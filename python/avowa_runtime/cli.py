# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""`avowa` - set up, check and switch off the Runtime SDK. It is a setup tool, not a launcher:
after `avowa init` your app starts with the command it has always used.

    avowa init <setup-token>     connect this project (writes avowa.env, one line: AVOWA_TOKEN)
    avowa init --dry-run         show what init would do; changes nothing, uses no token
    avowa init --no-hook         connect, but do not install the start-up hook
    avowa status                 is the hook in place, what is covered, does the server know this key
    avowa doctor                 the server check only (sends no signal)
    avowa run <command>          start one command instrumented, without the start-up hook

In production set one variable, AVOWA_TOKEN, in your secret store. Nothing else changes.
AVOWA_DISABLE=1 switches everything off.
"""
import importlib.util
import os
import sys

_LIBS = (
    ("openai", "openai", "auto", "covered automatically (OpenAI, Azure OpenAI, OpenAI-compatible hosts)"),
    ("anthropic", "anthropic", "auto", "covered automatically (incl. Claude on Bedrock / Vertex clients)"),
    ("boto3", "boto3", "line", "Bedrock needs one line: instrument_bedrock(avowa, client)"),
    ("google.genai", "google-genai", "line", "Gemini needs one line: instrument_gemini(avowa, client)"),
    ("mistralai", "mistralai", "manual", "no wrapper yet: record calls with avowa.capture(...)"),
    ("cohere", "cohere", "manual", "no wrapper yet: record calls with avowa.capture(...)"),
)


def _has(module):
    try:
        return importlib.util.find_spec(module) is not None
    except Exception:
        return False


def _hook_file():
    import site
    from .auto import _PTH_NAME
    dirs = list(getattr(site, "getsitepackages", lambda: [])() or [])
    try:
        dirs.append(site.getusersitepackages())
    except Exception:
        pass
    for d in dirs:
        p = os.path.join(d, _PTH_NAME)
        if os.path.isfile(p):
            return p
    return None


def _ensure_hook(dry, skip=False):
    from .auto import _PTH_BODY, _pth_path
    if skip:
        return ("start-up hook : left alone (--no-hook). Start with `avowa run <command>` or add "
                "`import avowa_runtime.auto` to your entry file.")
    have = _hook_file()
    if have:
        try:
            if open(have).read() == _PTH_BODY:
                return "start-up hook : in place (%s)" % have
        except Exception:
            pass
    target = have or _pth_path()
    if not target:
        return ("start-up hook : NOT installed and site-packages is not writable. Start with "
                "`avowa run <command>` or add `import avowa_runtime.auto` to your entry file.")
    if dry:
        return "start-up hook : would write %s" % target
    try:
        with open(target, "w") as f:
            f.write(_PTH_BODY)
    except Exception as e:
        return ("start-up hook : could not write %s (%s). Start with `avowa run <command>` or add "
                "`import avowa_runtime.auto` to your entry file." % (target, type(e).__name__))
    return "start-up hook : written to %s" % target


def _gitignore(dry):
    here = os.getcwd()
    gi = os.path.join(here, ".gitignore")
    if not (os.path.isfile(gi) or os.path.exists(os.path.join(here, ".git"))):
        return None
    try:
        text = open(gi).read() if os.path.isfile(gi) else ""
    except Exception:
        return None
    lines = text.splitlines()
    if any(l.strip() in ("avowa.env", "/avowa.env", "*.env") for l in lines):
        return ".gitignore    : already ignores avowa.env"
    if dry:
        return ".gitignore    : would add avowa.env"
    try:
        with open(gi, "a") as f:
            f.write(("" if not text or text.endswith("\n") else "\n") + "avowa.env\n")
    except Exception:
        return ".gitignore    : could not be updated. Add the line avowa.env yourself; the file holds a secret."
    return ".gitignore    : added avowa.env (the file holds a secret)"


def _coverage_lines():
    out, any_auto = [], False
    for module, name, how, note in _LIBS:
        if _has(module):
            any_auto = any_auto or how == "auto"
            out.append("  %-13s: %s" % (name, note))
    if _has("langchain_core") and not any_auto:
        out.append("  %-13s: add callbacks=[AvowaCallbackHandler()] (from avowa_runtime.langchain)" % "langchain")
    if not out:
        out.append("  no AI provider library found in this Python environment. Run this in the "
                   "environment your app uses; calls made over raw HTTP need avowa.capture(...).")
    return out


def _dependency_hint():
    for name in ("requirements.txt", "pyproject.toml", "Pipfile"):
        try:
            if os.path.isfile(name) and "avowa-runtime" not in open(name).read() and "avowa_runtime" not in open(name).read():
                return "dependency    : add avowa-runtime to %s so your build installs it too" % name
        except Exception:
            pass
    return None


def _report_setup(key, secret, base, wired):
    import hashlib
    import hmac
    import json
    import time
    import urllib.request
    from . import __version__
    covered = [name for module, name, how, _ in _LIBS if how == "auto" and _has(module)]
    ts = str(int(time.time()))
    headers = {"X-Ingest-Key": key, "X-Avowa-Timestamp": ts,
               "X-Avowa-Signature": hmac.new((secret or "").encode(), ("%s." % ts).encode(), hashlib.sha256).hexdigest(),
               "X-Avowa-Setup": "wired=%s; covered=%s" % ("1" if wired else "0", ",".join(covered)),
               "User-Agent": "avowa-runtime-python/%s (+https://avowa.ai)" % __version__}
    try:
        r = urllib.request.urlopen(urllib.request.Request(base + "/ingest/whoami", headers=headers), timeout=8)
        who = json.loads(r.read() or b"{}")
    except Exception as e:
        return "server check  : could not confirm (%s). Run `avowa status` to see why." % (getattr(e, "code", None) or type(e).__name__)
    if not who.get("signature_ok"):
        return "server check  : the secret did NOT verify. Run `avowa status`."
    if not who.get("capture_allowed"):
        return "server check  : key accepted, but this workspace's plan does not allow capture yet"
    return "server check  : key and signature accepted (your console card now shows this step done)"


def _redeem(token, api):
    import json
    import urllib.request
    from . import _checked_base
    api, problem = _checked_base(api)
    if problem:
        return None, problem.replace("AVOWA_BASE_URL", "--api") + "."
    req = urllib.request.Request(api + "/public/sdk/setup", data=json.dumps({"token": token}).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "avowa-runtime-python (+https://avowa.ai)"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            creds = json.loads(r.read())
    except Exception as e:
        if getattr(e, "code", None) == 404:
            return None, "That setup token is invalid, expired (24h) or already used. Generate a new one in the console."
        return None, "Could not reach %s (%s). Pass --api with your Avowa API URL." % (api, e)
    if creds.get("connector_id") != "runtime_sdk":
        return None, "That token belongs to a Collector connection, not the Runtime SDK. Use avowa-collector.pyz init."
    base, problem = _checked_base(creds.get("base_url") or api)
    if problem:
        return None, "The server returned an unsafe API URL (%s); nothing was written." % problem
    creds["base_url"] = base
    return creds, None


def init(args):
    import stat
    from . import make_token
    dry = "--dry-run" in args
    no_hook = "--no-hook" in args
    api = (os.getenv("AVOWA_BASE_URL") or "https://api.avowa.ai").rstrip("/")
    if "--api" in args:
        i = args.index("--api")
        if i + 1 >= len(args):
            sys.stderr.write("--api needs a URL\n")
            return 2
        api = args[i + 1].rstrip("/")
        args = args[:i] + args[i + 2:]
    words = [a for a in args if not a.startswith("-")]
    path = os.path.join(os.getcwd(), "avowa.env")

    if dry:
        print("avowa init --dry-run: nothing is changed and no setup token is used.\n")
        print("credentials   : would write %s (mode 0600, one line: AVOWA_TOKEN)" % path)
        for line in (_gitignore(True), _ensure_hook(True, no_hook), _dependency_hint()):
            if line:
                print(line)
        print("coverage in this environment:")
        print("\n".join(_coverage_lines()))
        print("\nYour start command and your code stay as they are.")
        return 0

    if not words:
        sys.stderr.write("usage: avowa init <setup-token> [--api https://api.avowa.ai] [--dry-run] [--no-hook]\n"
                         "Generate the setup token in the Avowa console: Connections, Runtime SDK.\n")
        return 2
    from . import _checked_base
    _, unsafe = _checked_base(api)
    if unsafe:
        sys.stderr.write(unsafe.replace("AVOWA_BASE_URL", "--api") + ".\n")
        return 2
    creds, problem = _redeem(words[0], api)
    if problem:
        sys.stderr.write(problem + "\n")
        return 1
    token = make_token(creds["ingest_token"], creds.get("ingest_secret") or "", creds["base_url"])
    text = ("# Avowa Runtime SDK: the credential for this connection. Keep private, server-side only.\n"
            "# Written by `avowa init`. Read from the directory you start your app in.\n"
            "# In production, put this one value in your secret store as AVOWA_TOKEN instead.\n"
            "AVOWA_TOKEN=%s\n" % token)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    print("connected     : %s (%s)" % (creds.get("label") or "Avowa Runtime SDK", creds.get("environment", "prod")))
    print("credentials   : %s (mode 0600, one line: AVOWA_TOKEN)" % path)
    for line in (_gitignore(False), _ensure_hook(False, no_hook), _dependency_hint()):
        if line:
            print(line)
    print("coverage in this environment:")
    print("\n".join(_coverage_lines()))
    print(_report_setup(creds["ingest_token"], creds.get("ingest_secret") or "", creds["base_url"],
                        wired=bool(_hook_file()) and not no_hook))
    print("\nDone. Start your app the way you always do, then send one real request that calls the model.\n"
          "  check      : avowa status\n"
          "  production : set AVOWA_TOKEN (the value in avowa.env) in your secret store. Nothing else changes.\n"
          "  off switch : AVOWA_DISABLE=1")
    return 0


def status(args):
    from . import __version__, load_env, _apply_token, auto_wanted, _disabled
    found = None
    try:
        found = load_env()
    except Exception:
        pass
    _apply_token()
    print("sdk           : avowa_runtime %s" % __version__)
    hook = _hook_file()
    print("start-up hook : %s" % (hook or "NOT installed (run `avowa init`, or start with `avowa run <command>`)"))
    if _disabled():
        print("instrumenting : OFF, AVOWA_DISABLE is set")
    elif auto_wanted():
        print("instrumenting : ON for processes started here (credential from %s)"
              % (found or "the environment"))
    elif os.getenv("AVOWA_RUNTIME_KEY"):
        print("instrumenting : not automatic. This connection uses the three separate variables; "
              "set AVOWA_AUTO=1, or use AVOWA_TOKEN.")
    else:
        print("instrumenting : OFF, no credential found (run `avowa init <setup-token>`)")
    print("coverage in this environment:")
    print("\n".join(_coverage_lines()))
    key, secret = os.getenv("AVOWA_RUNTIME_KEY"), os.getenv("AVOWA_RUNTIME_SECRET")
    from . import _checked_base
    base, problem = _checked_base(os.getenv("AVOWA_BASE_URL"))
    if key and secret and base and not problem and not _disabled():
        _report_setup(key, secret, base, wired=bool(hook) and auto_wanted())
    print("server check:")
    from .auto import _main as _auto_main
    return _auto_main(["--doctor"])


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    import avowa_runtime
    avowa_runtime._setup_tool = True
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stderr.write(__doc__.strip() + "\n")
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "init":
        return init(rest)
    if cmd == "status":
        return status(rest)
    if cmd == "doctor":
        from .auto import _main as _auto_main
        return _auto_main(["--doctor"])
    if cmd == "run":
        from .run import main as _run
        return _run(rest)
    if cmd in ("--version", "version"):
        from . import __version__
        print(__version__)
        return 0
    sys.stderr.write("unknown command: %s\n\n%s\n" % (cmd, __doc__.strip()))
    return 2


if __name__ == "__main__":
    sys.exit(main())
