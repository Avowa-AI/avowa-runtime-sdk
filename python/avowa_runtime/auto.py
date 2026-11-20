# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""Zero-code auto-instrumentation.

`instrument_openai(client)` asks the customer to find *where they construct their client*. In a
real codebase that is the hard part, not the typing: the client is built in a factory, in five
places, in a `@lru_cache` singleton, or inside LangChain / LlamaIndex / CrewAI where they cannot
edit it at all. An integration that only covers the client you remembered to wrap under-reports
coverage — and Avowa publishes coverage as a denominator, so under-instrumenting looks like low
traffic rather than a missed integration.

This module patches the CLIENT CLASSES instead, so every instance is instrumented no matter who
builds it or when. Three ways to switch it on, cheapest first:

  1. No code, no command change — install the startup hook once per environment:
         python -m avowa_runtime.auto --install
         export AVOWA_AUTO=1
     (Writes a .pth into site-packages. `--uninstall` removes it. It does nothing at all unless
     AVOWA_AUTO=1, so installing it can never silently start instrumenting an app.)

  2. No code change — prefix the process:
         avowa-run uvicorn app:main --host 0.0.0.0
     In Docker that is one line: `CMD ["avowa-run", "uvicorn", "app:main"]`. This is the option
     to recommend to most teams: containers own their CMD, and nothing in the app changes.

  3. One import, anywhere at start-up (Django settings, Lambda handler, main.py):
         import avowa_runtime.auto

All three end up in the same place. An auto-integration has nowhere to take arguments from, so
configuration is AVOWA_RUNTIME_KEY / AVOWA_RUNTIME_SECRET / AVOWA_BASE_URL / AVOWA_REGION, read from
the environment or from the `avowa.env` that `avowa init` writes — put that file in the
working directory and there is nothing to type. Real environment variables always win over the
file. Set AVOWA_SCAN=0 to disable the local injection/PII scan.

Providers patched, if installed: anthropic (Anthropic, AsyncAnthropic, AnthropicBedrock,
AnthropicVertex) and openai (OpenAI, AsyncOpenAI, AzureOpenAI, AsyncAzureOpenAI). Anything else
still needs an explicit `capture()` — see the README.
"""
import os
import sys
import importlib
import importlib.util

from . import AvowaRuntime, _warn_once, _autoload_env, _dbg, _disabled, _checked_base

__all__ = ["runtime", "install", "instrumented"]

_TRUE = ("1", "true", "yes", "on")

runtime = None

instrumented = []

_installed = False
_finding = set()


def _key():
    return os.getenv("AVOWA_RUNTIME_KEY")


def _patch_class(cls, instrument):
    if getattr(cls, "_avowa_patched", False):
        return False
    orig_init = cls.__init__

    def __init__(self, *args, **kwargs):
        orig_init(self, *args, **kwargs)
        try:
            instrument(self)
        except Exception as e:
            from . import _internal_error
            _internal_error("auto.instrument", e)

    try:
        cls.__init__ = __init__
        cls._avowa_patched = True
    except Exception:
        return False
    return True


def _patch_module(name, module):
    rt = runtime
    if rt is None:
        return
    if name == "anthropic":
        targets, how = ("Anthropic", "AsyncAnthropic", "AnthropicBedrock", "AnthropicVertex"), rt.instrument_anthropic
    elif name == "openai":
        targets, how = ("OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI"), rt.instrument_openai
    else:
        return
    scan = os.getenv("AVOWA_SCAN", "1").lower() in _TRUE
    for attr in targets:
        cls = getattr(module, attr, None)
        if isinstance(cls, type) and _patch_class(cls, lambda c: how(c, scan=scan)):
            instrumented.append(name + "." + attr)
            _dbg("patched " + name + "." + attr)


class _ImportHook:

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in ("anthropic", "openai") or fullname in _finding:
            return None
        _finding.add(fullname)
        try:
            spec = importlib.util.find_spec(fullname)
        except Exception:
            return None
        finally:
            _finding.discard(fullname)
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return None
        orig_exec = spec.loader.exec_module

        def exec_module(module):
            orig_exec(module)
            try:
                _patch_module(fullname, module)
            except Exception:
                pass
        try:
            spec.loader.exec_module = exec_module
        except Exception:
            return None
        return spec


def install():
    """Switch on auto-instrumentation. Idempotent; safe to call from anywhere."""
    global runtime, _installed
    if _installed:
        return runtime
    _installed = True
    if _disabled():
        _dbg("AVOWA_DISABLE is set — auto-instrumentation is off; nothing is patched")
        return None

    from . import __version__
    found = _autoload_env()
    _dbg("avowa_runtime %s active · key %s · base %s · env file %s"
         % (__version__,
            "set" if _key() else "MISSING",
            os.getenv("AVOWA_BASE_URL") or "NOT SET",
            found or "none"))
    _dbg("watching for `import anthropic` / `import openai` — a 'patched ...' line follows each. "
         "If none ever appears, this process does not use those SDKs and needs capture().")
    if _key() and not os.getenv("AVOWA_BASE_URL"):
        _warn_once("nobase",
                   "AVOWA_BASE_URL is not set, so no signals will be sent. It is already filled in "
                   "inside the AVOWA_TOKEN that `avowa init` writes to avowa.env.")
    if not _key():
        _warn_once("noauth",
                   "auto-instrumentation is loaded, but no credentials were found, so no signals "
                   "will be sent. Run `avowa init <setup-token>` in the working directory, "
                   "or export AVOWA_TOKEN (on macOS/Linux `export`, not `set`).")
    runtime = AvowaRuntime()

    for name in ("anthropic", "openai"):
        mod = sys.modules.get(name)
        if mod is not None:
            _patch_module(name, mod)
    sys.meta_path.insert(0, _ImportHook())
    return runtime


_PTH_NAME = "avowa_auto.pth"
_PTH_BODY = ("import os; exec(\"try:\\n import avowa_runtime.hook\\nexcept Exception:\\n pass\") "
             "if os.environ.get('AVOWA_DISABLE','').lower() not in ('1','true','yes','on') "
             "and os.environ.get('AVOWA_AUTO','').lower() not in ('0','false','no','off') "
             "and (os.environ.get('AVOWA_AUTO') or os.environ.get('AVOWA_TOKEN') or os.path.isfile('avowa.env')) "
             "else None\n")


def _pth_path():
    import site
    for d in (getattr(site, "getsitepackages", lambda: [])() or []) + [os.path.dirname(os.path.dirname(__file__))]:
        if os.path.isdir(d) and os.access(d, os.W_OK):
            return os.path.join(d, _PTH_NAME)
    return None


def _main(argv):
    if "--install" in argv:
        p = _pth_path()
        if not p:
            print("could not find a writable site-packages — are you in the venv your app uses?")
            return 1
        with open(p, "w") as f:
            f.write(_PTH_BODY)
        print("installed %s\nNow set AVOWA_AUTO=1 (plus AVOWA_RUNTIME_KEY / AVOWA_RUNTIME_SECRET) "
              "in the app's environment. Nothing is instrumented until AVOWA_AUTO=1." % p)
        return 0
    if "--uninstall" in argv:
        p = _pth_path()
        if p and os.path.exists(p):
            os.remove(p)
            print("removed " + p)
        else:
            print("nothing to remove")
        return 0
    from . import load_env, __version__
    found = load_env()
    from . import _apply_token
    _apply_token()
    if "--doctor" in argv:
        import json
        import time
        import hmac
        import hashlib
        import urllib.request
        base, problem = _checked_base(os.getenv("AVOWA_BASE_URL"))
        key = _key()
        secret = os.getenv("AVOWA_RUNTIME_SECRET")
        if problem:
            print("sdk        : avowa_runtime %s" % __version__)
            print("api        : " + problem)
            return 1
        print("sdk        : avowa_runtime %s" % __version__)
        print("env file   : " + (found or "not found"))
        print("api        : " + base)
        if not key:
            print("ingest key : MISSING — put avowa.env beside your app or export AVOWA_RUNTIME_KEY")
            return 1
        ts = str(int(time.time()))
        headers = {"X-Ingest-Key": key, "X-Avowa-Timestamp": ts,
                   "User-Agent": "avowa-runtime-python/%s (+https://avowa.ai)" % __version__}
        if secret:
            headers["X-Avowa-Signature"] = hmac.new(secret.encode(), ("%s." % ts).encode(), hashlib.sha256).hexdigest()
        try:
            r = urllib.request.urlopen(urllib.request.Request(base + "/ingest/whoami", headers=headers), timeout=8)
            who = json.loads(r.read() or b"{}")
        except Exception as e:
            code = getattr(e, "code", None)
            if code == 401:
                print("ingest key : REJECTED by %s — not a key this server knows (wrong AVOWA_BASE_URL, or rotated/revoked)" % base)
            elif code:
                print("api        : %s answered HTTP %s" % (base, code))
            else:
                print("api        : NOT reachable from this host (%s)" % type(e).__name__)
            return 1
        ok = True
        print("connection : %s · %s" % (who.get("label") or who.get("connection_id"), who.get("environment")))
        if not who.get("capture_allowed"):
            print("plan       : capture NOT allowed — the workspace is on Declare; signals will get 402")
            ok = False
        else:
            print("plan       : capture allowed")
        if secret:
            if who.get("signature_ok"):
                print("secret     : signs correctly")
            else:
                print("secret     : does NOT verify — wrong AVOWA_RUNTIME_SECRET, every signal would get 401")
                ok = False
        else:
            print("secret     : not set — signals would be sent UNSIGNED and refused")
            ok = False
        skew = who.get("clock_skew_s")
        if skew is not None:
            print("clock      : %+.0fs vs server%s" % (skew, "" if abs(skew) < 120 else " — over 5 minutes is rejected; fix NTP"))
            ok = ok and abs(skew) < 300
        print("last event : %s (%s total)" % (who.get("last_event_at") or "never", who.get("events_total", 0)))
        from . import _remote_on
        rf = who.get("sdk_fields")
        if not _remote_on():
            print("meta fields: OFF (AVOWA_REMOTE_FIELDS) — only the built-in metadata is read")
        elif isinstance(rf, list):
            print("meta fields: %s" % (", ".join("%s (%s %s.%s)" % (f.get("name"), f.get("provider"), f.get("from"), f.get("path"))
                                                for f in rf) or "none beyond the built-in metadata"))
        print("\nThis check sent no signal." + ("" if ok else " Fix the lines marked above, then run again."))
        return 0 if ok else 1
    if "--check" in argv:
        import urllib.request
        from . import __version__
        base, problem = _checked_base(os.getenv("AVOWA_BASE_URL"))
        print("sdk        : avowa_runtime %s at %s" % (__version__, os.path.dirname(__file__)))
        if _disabled():
            print("disabled   : YES — AVOWA_DISABLE is set; nothing is patched or sent")
        if problem:
            print("api        : " + problem)
            return 1
        for name in ("anthropic", "openai"):
            try:
                m = importlib.import_module(name)
                print("%-11s: installed (%s)" % (name, getattr(m, "__version__", "?")))
            except Exception:
                print("%-11s: NOT installed in this environment" % name)
        print("env file   : " + (found or "not found"))
        print("ingest key : " + ("set" if _key() else "MISSING"))
        print("ingest sec : " + ("set" if os.getenv("AVOWA_RUNTIME_SECRET") else "MISSING"))
        try:
            _req = urllib.request.Request(base, headers={
                "User-Agent": "avowa-runtime-python/%s (+https://avowa.ai)" % __version__})
            r = urllib.request.urlopen(_req, timeout=5)
            r.read(1)
            print("reachable  : yes — %s (HTTP %s)" % (base, getattr(r, "status", 200)))
        except Exception as e:
            code = getattr(e, "code", None)
            if code:
                print("reachable  : yes — %s answered HTTP %s" % (base, code))
            else:
                print("reachable  : NO — %s (%s). Check the URL, DNS and egress rules from THIS "
                      "host." % (base, type(e).__name__))
                return 1
        print("\nNo signal was sent — a synthetic event would show on your trust profile as "
              "inference that never happened.\nRun your app under avowa-run with AVOWA_DEBUG=1 to "
              "watch real calls.")
        return 0 if _key() else 1
    install()
    ok = bool(_key())
    print("avowa auto-instrumentation active")
    print("  env file   : " + (found or "not found (looked for avowa.env / .env here and above)"))
    print("  ingest key : " + ("set" if ok else "MISSING"))
    print("  ingest sec : " + ("set" if os.getenv("AVOWA_RUNTIME_SECRET") else "MISSING"))
    print("  base url   : " + (os.getenv("AVOWA_BASE_URL") or "NOT SET — nothing will be sent"))
    print("  patched    : " + (", ".join(instrumented) or "none (no provider SDK imported yet)"))
    print("  sdk        : avowa_runtime %s" % __version__)
    if not ok:
        print("\n  No credentials, so nothing would be sent. Run `avowa init <setup-token>` in this\n"
              "  directory, or `export AVOWA_TOKEN=...` (`export`, not `set`, which is Windows CMD\n"
              "  syntax and does nothing in bash/zsh).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
elif not getattr(sys.modules.get("avowa_runtime"), "_setup_tool", False):
    install()
