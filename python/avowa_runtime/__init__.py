# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""
Avowa Runtime SDK — emit live AI-inference signals to Avowa as evidence.

Drop this into your inference path. Every call records the signal that PROVES
your AI-trust claims at runtime: which model, which region, whether customer data
is used for training, guardrail outcomes — the evidence posture tools can't see.

Stdlib-only (urllib) so it adds no dependencies to your app. Sends are
non-blocking by default (a background worker), so it adds ~0ms to inference.

    from avowa_runtime import AvowaRuntime
    avowa = AvowaRuntime(ingest_key="avk_runtime_...", region="us-east-1")

    # Option A — auto-instrument the Anthropic client (captures every call):
    avowa.instrument_anthropic(client)

    # Option B — wrap a block:
    with avowa.track(model="claude-opus-4-8"):
        resp = client.messages.create(...)

    # Option C — record explicitly:
    avowa.capture(model="claude-opus-4-8", region="us-east-1", train_on_data=False)
"""
import os
import re
import sys
import json
import time
import hmac
import hashlib
import queue
import atexit
import inspect
import threading
import contextvars
import urllib.request
from contextlib import contextmanager
from urllib.parse import urlsplit

__version__ = "0.13.0"
__all__ = ["AvowaRuntime", "agent_context", "approval", "tool_outcome", "call_ref"]


_CARD_RX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

_PII_PATTERNS = (
    re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{2,63}"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    _CARD_RX,
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}\."),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{20,200}\b"),
)

SCAN_LIMIT = 32 * 1024

DEFERRED_SCAN_MAX = 256


def _cap(text, keep="head"):
    if not isinstance(text, str) or len(text) <= SCAN_LIMIT:
        return text
    return text[-SCAN_LIMIT:] if keep == "tail" else text[:SCAN_LIMIT]


_TRUE = ("1", "true", "yes", "on")


def _disabled():
    return os.getenv("AVOWA_DISABLE", "").strip().lower() in _TRUE


_TOKEN_PREFIX = "avw1_"
_TOKEN_VARS = ("AVOWA_RUNTIME_KEY", "AVOWA_RUNTIME_SECRET", "AVOWA_BASE_URL")


def make_token(key, secret, base_url):
    """Pack a connection's key, signing secret and API URL into one AVOWA_TOKEN value."""
    import base64
    raw = "\n".join((key or "", secret or "", (base_url or "").rstrip("/")))
    return _TOKEN_PREFIX + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def read_token(token):
    """(key, secret, base_url) from an AVOWA_TOKEN value, or None when it is not one."""
    import base64
    token = (token or "").strip()
    if not token.startswith(_TOKEN_PREFIX):
        return None
    body = token[len(_TOKEN_PREFIX):]
    try:
        parts = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode().split("\n")
    except Exception:
        return None
    if len(parts) != 3 or not parts[0]:
        return None
    return tuple(parts)


def _apply_token():
    token = os.getenv("AVOWA_TOKEN")
    if not token:
        return False
    parts = read_token(token)
    if not parts:
        _warn_once("token", "AVOWA_TOKEN is set but is not a valid Avowa token (one starts with "
                            "avw1_), so no signals will be sent. Copy it again from avowa.env or the console.")
        return False
    for name, value in zip(_TOKEN_VARS, parts):
        if value:
            os.environ.setdefault(name, value)
    return True


def auto_wanted():
    """Should the start-up hook instrument this process? AVOWA_AUTO decides when it is set; when it
    is not, having a token (in the environment or in avowa.env) is the opt-in. Installing the
    package alone never switches anything on."""
    if _disabled():
        return False
    flag = os.getenv("AVOWA_AUTO", "").strip().lower()
    if flag:
        return flag in _TRUE
    return bool(os.getenv("AVOWA_TOKEN"))


def _private_host(host):
    h = (host or "").strip("[]").lower()
    if not h:
        return False
    if h in ("localhost",) or h.endswith(".localhost") or "." not in h and ":" not in h:
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def _checked_base(url):
    if not url:
        return None, "AVOWA_BASE_URL is not set"
    u = str(url).strip()
    try:
        parts = urlsplit(u if "://" in u else "https://" + u)
    except Exception:
        return None, "AVOWA_BASE_URL is not a valid URL"
    if parts.scheme == "https":
        return u.rstrip("/"), None
    if parts.scheme == "http" and (_private_host(parts.hostname)
                                   or os.getenv("AVOWA_ALLOW_HTTP", "").strip().lower() in _TRUE):
        return u.rstrip("/"), None
    return None, ("AVOWA_BASE_URL uses %s:// to %s — signals carry your ingest key, so only https:// "
                  "is accepted (plain http only to localhost or a private network)"
                  % (parts.scheme or "?", parts.hostname or "?"))

_INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.I),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|rules?)", re.I),
    re.compile(r"(?:reveal|print|repeat|show)\s+(?:me\s+)?(?:your\s+)?system\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+(?:a|an|in)\b", re.I),
    re.compile(r"\bdeveloper\s+mode\b|\bDAN\s+mode\b", re.I),
    re.compile(r"</?(?:system|instructions?)>", re.I),
    re.compile(r"pretend\s+(?:that\s+)?you\s+(?:are|have)\b", re.I),
)


def _luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _looks_like_card(text):
    for m in _CARD_RX.finditer(text or ""):
        digits = re.sub(r"[^0-9]", "", m.group(0))
        if 13 <= len(digits) <= 16 and _luhn_ok(digits):
            return True
    return False


_DIGIT = re.compile(r"\d")
_INJECTION_GATES = (
    lambda f: "ignore" in f, lambda f: "disregard" in f, lambda f: "system" in f, lambda f: "now" in f,
    lambda f: "mode" in f, lambda f: "system>" in f or "instruction" in f, lambda f: "pretend" in f,
)
_PII_GATES = (
    lambda t, d: "@" in t, lambda t, d: d and "-" in t, lambda t, d: d, lambda t, d: "AKIA" in t,
    lambda t, d: "-----BEGIN" in t, lambda t, d: "eyJ" in t, lambda t, d: "sk-" in t or "rk-" in t,
)


def _count_matches(text, patterns):
    if not text or not isinstance(text, str):
        return 0
    n = 0
    for rx in patterns:
        if rx is _CARD_RX:
            n += 1 if _looks_like_card(text) else 0
        elif rx.search(text):
            n += 1
    return n


_PII_NAMES = ("email", "us_ssn", "payment_card", "aws_access_key", "private_key", "jwt", "provider_secret_key")
_INJECTION_NAMES = ("ignore_instructions", "disregard_rules", "reveal_system_prompt", "role_override",
                    "developer_mode", "delimiter_injection", "pretend")


def _apply_scan(evt, scan):
    if not scan:
        return
    prompt, output = scan
    if prompt is not None and "injection_suspected" not in evt:
        fam = injection_families(prompt)
        evt["injection_suspected"], evt["injection_families"] = len(fam), fam
    if output is not None and "pii_detected" not in evt:
        fam = pii_families(output)
        evt["pii_detected"], evt["pii_families"] = len(fam), fam


def pii_families(text):
    """Names of the PII/secret pattern families present in `text`. Runs locally; text is never sent."""
    if not text or not isinstance(text, str):
        return []
    d = any(c in text for c in "0123456789") or (not text.isascii() and bool(_DIGIT.search(text)))
    return [name for name, gate, rx in zip(_PII_NAMES, _PII_GATES, _PII_PATTERNS)
            if gate(text, d) and (_looks_like_card(text) if rx is _CARD_RX else rx.search(text))]


def injection_families(text):
    """Names of the prompt-injection pattern families present in `text`. Runs locally; never sent."""
    if not text or not isinstance(text, str):
        return []
    f = text.casefold()
    return [name for name, gate, rx in zip(_INJECTION_NAMES, _INJECTION_GATES, _INJECTION_PATTERNS)
            if gate(f) and rx.search(text)]


def scan_pii(text):
    """Distinct PII/secret pattern families present in `text`. Runs locally; text is never sent."""
    return len(pii_families(text))


def scan_injection(text):
    """Distinct prompt-injection pattern families present in `text`. Runs locally; text is never sent."""
    return len(injection_families(text))


_SCHEMA = "avowa.signal/1"
_BATCH_MAX = 100

_ENV_NAMES = ("avowa.env", ".env")
_env_loaded = False


def load_env(path=None, _search_up=3):
    """Fill in missing AVOWA_* variables from the `avowa.env` that `avowa init` writes.

    The file already holds the credential, so requiring people to re-type it into the
    shell is a step that buys nothing — and it is the step where integrations die (`set` instead
    of `export`, a var exported in one terminal and the app started in another, a Compose file
    that never passed it through).

    Two rules make this safe to do automatically:
      • **Only `AVOWA_*` keys are read.** Applications keep database passwords and API keys in
        the same `.env`; a telemetry SDK has no business parsing them, so it doesn't.
      • **The real environment always wins.** Anything already exported is left alone, so a
        Kubernetes Secret or Secrets Manager injection is never silently overridden by a file
        someone forgot to delete.

    Set AVOWA_ENV_FILE to point at a specific file, or AVOWA_NO_ENV_FILE=1 to switch this off.
    Returns the path actually loaded, or None.
    """
    if os.getenv("AVOWA_NO_ENV_FILE", "").lower() in ("1", "true", "yes", "on"):
        return None
    candidates = []
    explicit = path or os.getenv("AVOWA_ENV_FILE")
    if explicit:
        candidates.append(explicit)
    else:
        d = os.getcwd()
        for _ in range(max(1, _search_up)):
            candidates.extend(os.path.join(d, n) for n in _ENV_NAMES)
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    for cand in candidates:
        try:
            if not os.path.isfile(cand):
                continue
            with open(cand) as fh:
                lines = fh.readlines()
        except Exception:
            continue
        found = False
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            key, sep, val = line.partition("=")
            key = key.strip()
            if not sep or not key.startswith("AVOWA_"):
                continue
            val = val.strip().strip('"').strip("'")
            found = True
            os.environ.setdefault(key, val)
        if found:
            return cand
    return None


def _autoload_env():
    global _env_loaded
    found = None
    if not _env_loaded:
        _env_loaded = True
        try:
            found = load_env()
        except Exception:
            found = None
    _apply_token()
    return found


_warned = set()


def _debug_on():
    return os.getenv("AVOWA_DEBUG", "").lower() in ("1", "true", "yes", "on")


def _dbg(msg):
    if _debug_on():
        try:
            sys.stderr.write("[avowa:debug] " + msg + "\n")
        except Exception:
            pass


def _evt_summary(evt):
    seen = evt.get("_sdk_observed") or []
    return "%s via %s (%sms)%s" % (evt.get("model") or "?", evt.get("endpoint") or "?",
                                   evt.get("latency_ms"),
                                   (" · derived " + ",".join(seen)) if seen else "")


def _warn_once(key, msg):
    if key not in _warned:
        _warned.add(key)
        try:
            sys.stderr.write("[avowa] " + msg + "\n")
        except Exception:
            pass


INTERNAL_ERRORS = {}


def _strict():
    return os.environ.get("AVOWA_STRICT", "").strip().lower() in _TRUE


def _internal_error(where, exc, fatal_in_strict=True):
    key = f"{where}:{type(exc).__name__}"
    INTERNAL_ERRORS[key] = INTERNAL_ERRORS.get(key, 0) + 1
    if fatal_in_strict and _strict():
        raise exc
    _warn_once("internal:" + key, f"internal error in {where} ({type(exc).__name__}: {str(exc)[:120]}) — "
                                  "this signal was skipped; your app is unaffected. Please tell security@avowa.ai.")


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _StreamWatch:
    def __init__(self, record, kwargs, start, label):
        self._record, self._kwargs, self._start, self._label = record, kwargs, start, label
        self._model, self._stop, self._text, self._size, self._done = None, None, [], 0, False
        self._ttft = None

    def see(self, c):
        if self._ttft is None:
            self._ttft = int((time.time() - self._start) * 1000)
        try:
            t = getattr(c, "type", None) or ""
            msg = getattr(c, "message", None)
            if t == "message_start" and getattr(msg, "model", None):
                self._model = msg.model
            delta = getattr(c, "delta", None)
            if t == "message_delta" and getattr(delta, "stop_reason", None):
                self._stop = delta.stop_reason
            if t == "content_block_delta" and getattr(delta, "text", None):
                self._keep(delta.text)
            if t.endswith("output_text.delta") and isinstance(delta, str):
                self._keep(delta)
            if t == "response.completed" and getattr(getattr(c, "response", None), "model", None):
                self._model = c.response.model
            if getattr(c, "model", None) and not t:
                self._model = c.model
            choices = getattr(c, "choices", None) or []
            if choices:
                ch = choices[0]
                fr = getattr(ch, "finish_reason", None)
                if fr:
                    self._stop = fr
                content = getattr(getattr(ch, "delta", None), "content", None)
                if isinstance(content, str) and content:
                    self._keep(content)
        except Exception:
            pass

    def _keep(self, s):
        if self._size < SCAN_LIMIT:
            self._text.append(s)
            self._size += len(s)

    def finish(self, err):
        if self._done:
            return
        self._done = True
        text = "".join(self._text)
        if self._label.startswith("anthropic"):
            summary = _Obj(model=self._model, stop_reason=self._stop, content=[_Obj(type="text", text=text)])
        else:
            summary = _Obj(model=self._model, output_text=text,
                           choices=[_Obj(finish_reason=self._stop, message=_Obj(content=text, tool_calls=None))])
        try:
            self._record(summary, err, int((time.time() - self._start) * 1000), self._kwargs, ttft_ms=self._ttft)
        except Exception as e:
            _internal_error("stream.finish", e)


def _observe_stream(resp, watch):
    it = getattr(resp, "_iterator", None)
    if it is None:
        return _StreamProxy(resp, watch)
    try:
        if hasattr(it, "__anext__"):
            async def _agen():
                try:
                    async for c in it:
                        watch.see(c)
                        yield c
                except Exception as e:
                    watch.finish(e)
                    raise
                finally:
                    watch.finish(None)
            resp._iterator = _agen()
        else:
            def _gen():
                try:
                    for c in it:
                        watch.see(c)
                        yield c
                except Exception as e:
                    watch.finish(e)
                    raise
                finally:
                    watch.finish(None)
            resp._iterator = _gen()
        close = getattr(resp, "close", None)
        if callable(close):
            def _close(*a, **k):
                watch.finish(None)
                return close(*a, **k)
            resp.close = _close
        return resp
    except Exception:
        return _StreamProxy(resp, watch)


class _StreamProxy:
    def __init__(self, inner, watch):
        self._inner, self._watch, self._it = inner, watch, None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __enter__(self):
        getattr(self._inner, "__enter__", lambda: None)()
        return self

    def __exit__(self, *exc):
        self._watch.finish(exc[1] if exc and exc[1] else None)
        return getattr(self._inner, "__exit__", lambda *a: None)(*exc)

    async def __aenter__(self):
        ae = getattr(self._inner, "__aenter__", None)
        if ae:
            await ae()
        return self

    async def __aexit__(self, *exc):
        self._watch.finish(exc[1] if exc and exc[1] else None)
        ax = getattr(self._inner, "__aexit__", None)
        return await ax(*exc) if ax else None

    def close(self):
        self._watch.finish(None)
        c = getattr(self._inner, "close", None)
        if c:
            return c()

    def __iter__(self):
        return self

    def __next__(self):
        try:
            if self._it is None:
                self._it = self._inner if hasattr(self._inner, "__next__") else iter(self._inner)
            chunk = next(self._it)
        except StopIteration:
            self._watch.finish(None)
            raise
        except Exception as e:
            self._watch.finish(e)
            raise
        self._watch.see(chunk)
        return chunk

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            chunk = await self._inner.__anext__()
        except StopAsyncIteration:
            self._watch.finish(None)
            raise
        except Exception as e:
            self._watch.finish(e)
            raise
        self._watch.see(chunk)
        return chunk


def _wrap_call(original, record, label):
    record = _with_call_facts(record, label)

    def wrapped(*args, **kwargs):
        if kwargs.get("stream"):
            start = time.time()
            try:
                resp = original(*args, **kwargs)
            except Exception as e:
                record(None, e, int((time.time() - start) * 1000), kwargs)
                raise
            if inspect.isawaitable(resp):
                async def _awaited_stream():
                    try:
                        real = await resp
                    except Exception as e:
                        record(None, e, int((time.time() - start) * 1000), kwargs)
                        raise
                    return _observe_stream(real, _StreamWatch(record, kwargs, start, label))
                return _awaited_stream()
            return _observe_stream(resp, _StreamWatch(record, kwargs, start, label))

        start = time.time()
        try:
            resp = original(*args, **kwargs)
        except Exception as e:
            record(None, e, int((time.time() - start) * 1000), kwargs)
            raise

        if inspect.isawaitable(resp):
            async def _awaited():
                try:
                    real = await resp
                except Exception as e:
                    record(None, e, int((time.time() - start) * 1000), kwargs)
                    raise
                record(real, None, int((time.time() - start) * 1000), kwargs)
                return real
            return _awaited()

        record(resp, None, int((time.time() - start) * 1000), kwargs)
        return resp

    wrapped._avowa_wrapped = True
    return wrapped


_CEILING_KEYS = ("max_tokens", "max_completion_tokens", "max_output_tokens")


_IMAGE_PARTS = ("image", "image_url", "input_image")
_FILE_PARTS = ("document", "file", "input_file")
_AUDIO_PARTS = ("input_audio", "audio")


def _part_kind(b):
    t = b.get("type") if isinstance(b, dict) else getattr(b, "type", None)
    if t is None and isinstance(b, dict):
        t = next((k for k in ("image", "document", "audio", "text") if k in b), None)
    return t


def _facts_from_request(kwargs):
    kw = kwargs or {}
    out = {}
    for k in _CEILING_KEYS:
        v = kw.get(k)
        if isinstance(v, int) and not isinstance(v, bool) and v > 0:
            out["token_ceiling"] = v
            break
    msgs = kw.get("messages")
    if msgs is None and isinstance(kw.get("input"), list):
        msgs = kw.get("input")
    roles = {"user": 0, "assistant": 0, "tool": 0}
    kinds = {"image": 0, "file": 0, "audio": 0}
    chars, system = 0, bool(kw.get("system") or kw.get("instructions"))
    if isinstance(msgs, list):
        for m in msgs:
            role = m.get("role") if isinstance(m, dict) else getattr(m, "role", None)
            content = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
            if role in ("system", "developer"):
                system = True
            elif role in roles:
                roles[role] += 1
            if isinstance(content, str):
                chars += len(content)
            elif isinstance(content, list):
                for b in content:
                    k = _part_kind(b)
                    if k in _IMAGE_PARTS:
                        kinds["image"] += 1
                    elif k in _FILE_PARTS:
                        kinds["file"] += 1
                    elif k in _AUDIO_PARTS:
                        kinds["audio"] += 1
                    elif k == "tool_result":
                        roles["tool"] += 1
                    txt = b.get("text") if isinstance(b, dict) else getattr(b, "text", None)
                    if isinstance(txt, str):
                        chars += len(txt)
        out.update({"messages_user": roles["user"], "messages_assistant": roles["assistant"],
                    "messages_tool": roles["tool"], "input_images": kinds["image"],
                    "input_files": kinds["file"], "input_audio": kinds["audio"], "prompt_chars": chars})
    if msgs is not None or system:
        out["system_prompt_present"] = system
    tc = kw.get("tool_choice")
    if tc is not None:
        if isinstance(tc, str):
            out["tool_choice"] = tc[:20]
        else:
            t = tc.get("type") if isinstance(tc, dict) else getattr(tc, "type", None)
            out["tool_choice"] = str(t or "specific")[:20]
    if kw.get("stream") is not None:
        out["streaming"] = bool(kw.get("stream"))
    rf = kw.get("response_format") or kw.get("output_format")
    if rf is not None:
        t = rf.get("type") if isinstance(rf, dict) else getattr(rf, "type", None)
        out["response_format_type"] = str(t or getattr(rf, "__name__", "schema"))[:30]
    return out, list(out)


def _client_facts(client):
    out = {}
    r = getattr(client, "max_retries", None)
    if isinstance(r, int) and not isinstance(r, bool):
        out["client_max_retries"] = r
    t = getattr(client, "timeout", None)
    t = getattr(t, "read", None) if t is not None and not isinstance(t, (int, float)) else t
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        out["client_timeout_s"] = float(t)
    return out


_USAGE_KEYS = {
    "input_tokens": ("input_tokens", "prompt_tokens", "inputTokens", "prompt_token_count"),
    "output_tokens": ("output_tokens", "completion_tokens", "outputTokens", "candidates_token_count"),
    "cache_read_tokens": ("cache_read_input_tokens", "cacheReadInputTokens", "cached_content_token_count"),
    "cache_write_tokens": ("cache_creation_input_tokens", "cacheWriteInputTokens"),
}


_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,60}$")
_REGION = re.compile(r"^[A-Za-z0-9 _-]{2,30}$")


def _g(obj, *path):
    for k in path:
        if obj is None:
            return None
        try:
            if isinstance(obj, (list, tuple)) and k.isdigit():
                obj = obj[int(k)] if int(k) < len(obj) else None
            else:
                obj = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
        except Exception:
            return None
    return obj


def _num_or_none(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v else None


def _label(v, n=30):
    return v[:n] if isinstance(v, str) and v and _CODE.match(v[:n]) else None


def _param_facts(kwargs):
    kw = kwargs or {}
    cfg = kw.get("config")
    inf = kw.get("inferenceConfig") if isinstance(kw.get("inferenceConfig"), dict) else {}
    out = {}
    for fact, val in (("temperature", kw["temperature"] if "temperature" in kw else _g(cfg, "temperature") if cfg is not None else inf.get("temperature")),
                      ("top_p", kw["top_p"] if "top_p" in kw else _g(cfg, "top_p") if cfg is not None else inf.get("topP")),
                      ("seed", kw["seed"] if "seed" in kw else _g(cfg, "seed") if cfg is not None else None),
                      ("choices_n", kw["n"] if "n" in kw else _g(cfg, "candidate_count") if cfg is not None else None)):
        v = _num_or_none(val)
        if v is not None:
            out[fact] = v
    stops = kw.get("stop_sequences", kw.get("stop", inf.get("stopSequences")))
    if isinstance(stops, str):
        stops = [stops]
    if isinstance(stops, (list, tuple)):
        out["stop_sequences"] = len(stops)
    for fact, key in (("parallel_tool_calls", "parallel_tool_calls"), ("store_requested", "store"),
                      ("logprobs", "logprobs")):
        if isinstance(kw.get(key), bool):
            out[fact] = kw[key]
    tier = _label(kw.get("service_tier"), 20)
    if tier:
        out["service_tier_requested"] = tier
    meta = kw.get("metadata")
    if meta is not None:
        out["metadata_present"] = bool(meta)
    if kw.get("user") or kw.get("safety_identifier") or _g(meta, "user_id"):
        out["end_user_id_present"] = True
    elif "user" in kw or "safety_identifier" in kw or meta is not None:
        out["end_user_id_present"] = False
    effort = _label(kw.get("reasoning_effort") or _g(kw.get("reasoning"), "effort"), 20)
    if effort:
        out["reasoning_effort"] = effort
    th = kw.get("thinking")
    if isinstance(th, bool):
        out["thinking_enabled"] = th
    elif th is not None:
        out["thinking_enabled"] = _g(th, "type") not in (None, "disabled")
    if kw.get("guardrailConfig") is not None:
        out["guardrail_configured"] = True
    ss = _g(cfg, "safety_settings") if cfg is not None else None
    if isinstance(ss, (list, tuple)):
        out["safety_settings"] = len(ss)
    return out


def _filter_categories(results):
    out = []
    for r in (results if isinstance(results, list) else [results]):
        inner = _g(r, "content_filter_results")
        r = inner if inner is not None else r
        if isinstance(r, dict):
            out += [k for k, v in r.items() if isinstance(v, dict) and v.get("filtered") is True and _CODE.match(k)]
    return out


def _response_meta_facts(resp):
    if resp is None:
        return {}
    out = {}
    extra = getattr(resp, "model_extra", None)
    extra = extra if isinstance(extra, dict) else {}
    fp = _label(_g(resp, "system_fingerprint") or extra.get("system_fingerprint"), 60)
    if fp:
        out["system_fingerprint"] = fp
    tier = _label(_g(resp, "service_tier") or _g(resp, "usage", "service_tier") or extra.get("service_tier"), 20)
    if tier:
        out["service_tier"] = tier
    cats, present = [], False
    pf = _g(resp, "prompt_filter_results") or extra.get("prompt_filter_results")
    if pf is not None:
        present = True
        cats += _filter_categories(pf)
    choices = _g(resp, "choices")
    for c in (choices if isinstance(choices, (list, tuple)) else [])[:4]:
        cextra = getattr(c, "model_extra", None)
        cf = _g(c, "content_filter_results") or (cextra.get("content_filter_results") if isinstance(cextra, dict) else None)
        if cf is not None:
            present = True
            cats += _filter_categories(cf)
    block = _g(resp, "prompt_feedback", "block_reason")
    if block is not None:
        present = True
        out["provider_block_reason"] = _label(str(getattr(block, "name", block)), 40) or "blocked"
    if isinstance(resp, dict) and _g(resp, "trace", "guardrail") is not None:
        present = True
    if present:
        out["provider_filtered"] = bool(cats) or "provider_block_reason" in out
        if cats:
            out["provider_filter_categories"] = sorted(set(cats))[:10]
    return out


def _error_facts(e):
    out = {}
    resp = getattr(e, "response", None)
    status = next((v for v in (_num_or_none(getattr(e, "status_code", None)),
                               _num_or_none(_g(resp, "status_code")),
                               _num_or_none(_g(resp, "ResponseMetadata", "HTTPStatusCode")),
                               _num_or_none(getattr(e, "code", None))) if v is not None), None)
    if status is not None and 100 <= status <= 599:
        out["http_status"] = int(status)
    body = getattr(e, "body", None)
    code = None
    if isinstance(body, dict):
        code = _g(body, "error", "type") or (body.get("type") if body.get("type") != "error" else None) \
            or _g(body, "code")
    for cand in (code, getattr(e, "code", None), _g(resp, "Error", "Code"), getattr(e, "status", None)):
        c = _label(cand if isinstance(cand, str) else None, 60)
        if c:
            out["provider_error_code"] = c
            break
    try:
        headers = _g(resp, "headers")
        ra = headers.get("retry-after") if headers is not None else None
        if ra is not None:
            out["retry_after_s"] = float(ra)
    except (TypeError, ValueError, AttributeError):
        pass
    return out


_PROVIDER_LIBS = {"openai": "openai", "anthropic": "anthropic", "bedrock": "boto3", "gemini": "google-genai"}
_LIB_VERSIONS = {}


def _provider_lib_facts(label):
    lib = _PROVIDER_LIBS.get((label or "").split(".", 1)[0])
    if not lib:
        return {}
    if lib not in _LIB_VERSIONS:
        try:
            from importlib.metadata import version
            _LIB_VERSIONS[lib] = version(lib)[:30]
        except Exception:
            _LIB_VERSIONS[lib] = None
    out = {"provider_lib": lib}
    if _LIB_VERSIONS[lib]:
        out["provider_lib_version"] = _LIB_VERSIONS[lib]
    return out


_REGION_VARS = ("AWS_REGION", "AWS_DEFAULT_REGION", "GOOGLE_CLOUD_REGION", "FUNCTION_REGION", "CLOUD_RUN_REGION",
                "REGION_NAME", "AZURE_REGION", "FLY_REGION", "VERCEL_REGION", "RAILWAY_REPLICA_REGION", "RENDER_REGION")
_FRAMEWORKS = ("langchain", "langgraph", "llama_index", "crewai", "autogen", "haystack", "semantic_kernel", "dspy")
_ENV_FACTS = None


def _env_facts():
    global _ENV_FACTS
    if _ENV_FACTS is None:
        import platform
        out = {"python_version": platform.python_version()}
        for var in _REGION_VARS:
            v = os.getenv(var)
            if v and _REGION.match(v):
                out["app_region"], out["app_region_source"] = v, var
                break
        _ENV_FACTS = out
    fw = [f for f in _FRAMEWORKS if f in sys.modules]
    return {**_ENV_FACTS, **({"app_frameworks": fw} if fw else {})}


_RF_DENY = frozenset({
    "content", "contents", "text", "texts", "message", "messages", "input", "inputs", "output", "outputs",
    "output_text", "prompt", "prompts", "system", "instructions", "arguments", "args", "delta", "parts",
    "part", "body", "data", "completion", "completions", "document", "documents", "query", "queries",
    "value", "values", "raw", "html", "markdown", "transcript", "summary", "reasoning_content", "thinking",
})
_RF_NAME = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_RF_SEG = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]{0,40}|\d{1,2})$")
_RF_PROVIDERS = ("*", "openai", "anthropic", "bedrock", "gemini")
_RF_MAX = 20
_REMOTE = {"v": None, "fields": ()}


def _remote_on():
    return (os.getenv("AVOWA_REMOTE_FIELDS") or "on").strip().lower() not in ("off", "0", "false", "no")


def _rf_ok(f):
    if not isinstance(f, dict):
        return False
    name, prov, src, path = f.get("name"), f.get("provider"), f.get("from"), f.get("path")
    if not (isinstance(name, str) and _RF_NAME.match(name) and prov in _RF_PROVIDERS
            and src in ("request", "response", "error") and isinstance(path, str)):
        return False
    segs = path.split(".")
    return 1 <= len(segs) <= 6 and all(
        _RF_SEG.match(x) and not x.startswith("_") and x.lower() not in _RF_DENY for x in segs)


def _rf_value(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v if v == v and v not in (float("inf"), float("-inf")) else None
    return _label(v, 40) if isinstance(v, str) else None


def _accept_fields(block, secret):
    try:
        doc, mac = block.get("doc"), block.get("mac")
        if not (isinstance(doc, str) and isinstance(mac, str) and secret):
            return
        want = hmac.new(secret.encode(), b"avowa-fields." + doc.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, mac):
            _warn_once("rf-mac", "ignored a metadata-field list that did not verify under this connection's secret.")
            return
        d = json.loads(doc)
        fields = tuple(f for f in (d.get("fields") or [])[:_RF_MAX] if _rf_ok(f))
        _REMOTE["v"], _REMOTE["fields"] = str(d.get("v") or "")[:32] or None, fields
        _dbg("metadata-field list %s: %d field(s)" % (_REMOTE["v"], len(fields)))
    except Exception as e:
        _internal_error("remote_fields", e)


def remote_fields():
    """The server-defined metadata fields this process is currently reading (empty when off)."""
    return [dict(f) for f in _REMOTE["fields"]] if _remote_on() else []


def _remote_facts(label, resp, kwargs, exc):
    if not _REMOTE["fields"] or not _remote_on():
        return {}
    prov = (label or "").split(".", 1)[0]
    src = {"request": kwargs, "response": resp, "error": exc}
    out = {}
    for f in _REMOTE["fields"]:
        if f["provider"] in ("*", prov) and src.get(f["from"]) is not None:
            v = _rf_value(_g(src[f["from"]], *f["path"].split(".")))
            if v is not None:
                out["rf_" + f["name"]] = v
    return out


_CALL_FACTS = contextvars.ContextVar("avowa_call_facts", default=None)


def _with_call_facts(record, label):
    def rec(resp, err, ms, kwargs, ttft_ms=None):
        facts = {}
        try:
            if isinstance(err, BaseException):
                facts.update(_error_facts(err))
            facts.update(_param_facts(kwargs))
            facts.update(_response_meta_facts(resp))
            facts.update(_provider_lib_facts(label))
            if ttft_ms is not None:
                facts["ttft_ms"] = ttft_ms
            facts.update(_remote_facts(label, resp, kwargs, err if isinstance(err, BaseException) else None))
        except Exception as e:
            _internal_error("call_facts", e)
        if isinstance(err, BaseException):
            err = type(err).__name__
        tok = _CALL_FACTS.set(facts)
        try:
            return record(resp, err, ms, kwargs)
        finally:
            _CALL_FACTS.reset(tok)
    return rec


def _usage_facts(resp):
    u = getattr(resp, "usage", None) or getattr(resp, "usage_metadata", None)
    if u is None and isinstance(resp, dict):
        u = resp.get("usage")
    if u is None:
        return {}
    get = (lambda k: u.get(k)) if isinstance(u, dict) else (lambda k: getattr(u, k, None))
    out = {}
    for fact, names in _USAGE_KEYS.items():
        for n in names:
            v = get(n)
            if isinstance(v, int) and not isinstance(v, bool):
                out[fact] = v
                break
    if "cache_read_tokens" not in out:
        for d in ("prompt_tokens_details", "input_tokens_details"):
            det = get(d)
            v = (det.get("cached_tokens") if isinstance(det, dict) else getattr(det, "cached_tokens", None)) if det else None
            if isinstance(v, int) and not isinstance(v, bool):
                out["cache_read_tokens"] = v
                break
    return out


def _output_chars(resp):
    n = 0
    try:
        txt = getattr(resp, "output_text", None)
        if isinstance(txt, str):
            return len(txt)
        for b in (getattr(resp, "content", None) or []):
            t = getattr(b, "text", None)
            if isinstance(t, str):
                n += len(t)
        for c in (getattr(resp, "choices", None) or []):
            t = getattr(getattr(c, "message", None), "content", None)
            if isinstance(t, str):
                n += len(t)
    except Exception:
        return None
    return n


def _facts_from_response(resp, kwargs, salt=None):
    out, seen = {}, []
    if resp is None:
        return out, seen
    asked = kwargs.get("model")
    if asked:
        out["requested_model"] = str(asked)[:120]
        seen.append("requested_model")
    stop = getattr(resp, "stop_reason", None)
    if stop is None:
        try:
            stop = getattr(resp.choices[0], "finish_reason", None)
        except Exception:
            stop = None
    if stop is None and getattr(resp, "status", None) is not None and hasattr(resp, "output"):
        stop = getattr(getattr(resp, "incomplete_details", None), "reason", None) or resp.status
        part_types = {getattr(part, "type", None) for item in (getattr(resp, "output", None) or [])
                      for part in (getattr(item, "content", None) or [])}
        if "refusal" in part_types:
            out["refusal_part"] = True
            seen.append("refusal_part")
    if stop is not None:
        out["stop_reason"] = str(stop)[:40]
        seen.append("stop_reason")
    usage = _usage_facts(resp)
    out.update(usage)
    seen.extend(usage)
    size = _output_chars(resp)
    if size is not None:
        out["output_chars"] = size
        seen.append("output_chars")
    offered = _tool_names(kwargs.get("tools"))
    if offered:
        out["tools_offered"] = offered
        seen.append("tools_offered")
    invoked = _tools_invoked(resp)
    if offered or invoked:
        out["tools_invoked"] = invoked
        seen.append("tools_invoked")
    calls = _tool_calls(resp)
    if calls:
        out["tool_calls"] = calls
        seen.append("tool_calls")
    history = kwargs.get("messages") or kwargs.get("input")
    results = _tool_results(history)
    if results:
        out["tool_results"] = results
        seen.append("tool_results")
    mcp = _mcp_facts(kwargs, resp)
    out.update(mcp)
    seen.extend(mcp)
    if offered:
        depth = _autonomy_depth(history)
        if depth is not None:
            out["autonomy_depth"] = depth
            seen.append("autonomy_depth")
        key = _run_key(history, salt)
        if key:
            out["agent_run_key"] = key
            seen.append("agent_run_key")
    return out, seen


_TOOL_CAP = 60


def _tool_names(tools):
    out = []
    for t in (tools or []):
        n = None
        if isinstance(t, dict):
            n = t.get("name") or (t.get("function") or {}).get("name")
        else:
            n = getattr(t, "name", None) or getattr(getattr(t, "function", None), "name", None)
        if n:
            out.append(str(n)[:64])
    return sorted(set(out))[:_TOOL_CAP]


def _tools_invoked(resp):
    names = []
    try:
        for b in (getattr(resp, "content", None) or []):
            if getattr(b, "type", None) == "tool_use" and getattr(b, "name", None):
                names.append(str(b.name)[:64])
    except Exception:
        pass
    try:
        for tc in (getattr(resp.choices[0].message, "tool_calls", None) or []):
            fn = getattr(getattr(tc, "function", None), "name", None) or getattr(tc, "name", None)
            if fn:
                names.append(str(fn)[:64])
    except Exception:
        pass
    try:
        for item in (getattr(resp, "output", None) or []):
            if getattr(item, "type", None) in ("function_call", "custom_tool_call"):
                fn = getattr(item, "name", None)
                if fn:
                    names.append(str(fn)[:64])
    except Exception:
        pass
    return sorted(set(names))[:_TOOL_CAP]


def _run_key(messages, salt=None):
    if not isinstance(messages, list):
        return None
    for m in messages:
        if not isinstance(m, dict):
            try:
                m = {"role": getattr(m, "role", None), "content": getattr(m, "content", None)}
            except Exception:
                continue
        if m.get("role") != "user":
            continue
        c = m.get("content")
        if isinstance(c, list):
            parts = []
            for b in c:
                if isinstance(b, dict):
                    parts.append(str(b.get("text") or b.get("content") or ""))
                else:
                    parts.append(str(getattr(b, "text", "") or ""))
            c = "".join(parts)
        c = str(c or "").strip()
        if not c:
            continue
        data = c.encode("utf-8", "replace")
        if salt:
            return hmac.new(str(salt).encode("utf-8"), data, hashlib.sha256).hexdigest()[:12]
        return hashlib.sha256(data).hexdigest()[:12]
    return None


def _autonomy_depth(messages):
    if not isinstance(messages, list):
        return None
    depth = 0
    for m in messages:
        if not isinstance(m, dict):
            try:
                m = {"role": getattr(m, "role", None), "content": getattr(m, "content", None),
                     "tool_calls": getattr(m, "tool_calls", None)}
            except Exception:
                continue
        if m.get("role") != "assistant":
            continue
        if m.get("tool_calls"):
            depth += 1
            continue
        c = m.get("content")
        if isinstance(c, list) and any(
                (b.get("type") if isinstance(b, dict) else getattr(b, "type", None)) == "tool_use"
                for b in c):
            depth += 1
    return depth


TOOL_OUTCOMES = ("ok", "error", "denied", "timeout")
APPROVER_TYPES = ("human", "policy", "system", "unknown")
CALL_REF_LEN = 20


def call_ref(call_id):
    """The reference Avowa uses for one tool call: 20 hex characters of SHA-256 over the provider's id.
    A correlation pseudonym, not anonymisation: anyone who has the id can compute it."""
    if call_id is None or call_id == "":
        return None
    return hashlib.sha256(("avowa-call:" + str(call_id)).encode("utf-8", "replace")).hexdigest()[:CALL_REF_LEN]


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _tool_calls(resp):
    out = []

    def add(cid, name):
        ref = call_ref(cid)
        if ref and name:
            out.append(ref + ":" + str(name)[:64])
    try:
        for b in (_get(resp, "content") or []):
            if _get(b, "type") == "tool_use":
                add(_get(b, "id"), _get(b, "name"))
    except Exception:
        pass
    try:
        for tc in (_get(_get(resp.choices[0], "message"), "tool_calls") or []):
            add(_get(tc, "id"), _get(_get(tc, "function"), "name") or _get(tc, "name"))
    except Exception:
        pass
    try:
        for item in (_get(resp, "output") or []):
            if _get(item, "type") in ("function_call", "custom_tool_call"):
                add(_get(item, "call_id") or _get(item, "id"), _get(item, "name"))
    except Exception:
        pass
    return out[:_TOOL_CAP]


def _tool_results(history):
    if not isinstance(history, list):
        return []
    fresh = []
    for m in history:
        role, typ = _get(m, "role"), _get(m, "type")
        if role == "assistant" or typ in ("function_call", "custom_tool_call"):
            fresh = []
            continue
        if role == "tool":
            ref = call_ref(_get(m, "tool_call_id"))
            if ref:
                fresh.append(ref + ":returned")
            continue
        if typ in ("function_call_output", "custom_tool_call_output"):
            ref = call_ref(_get(m, "call_id"))
            if ref:
                fresh.append(ref + ":returned")
            continue
        c = _get(m, "content")
        if isinstance(c, list):
            for b in c:
                if _get(b, "type") == "tool_result":
                    ref = call_ref(_get(b, "tool_use_id"))
                    if ref:
                        fresh.append(ref + (":error" if _get(b, "is_error") is True else ":returned"))
    return fresh[:_TOOL_CAP]


def _mcp_facts(kwargs, resp):
    out, labels, hosts, ran, host_of = {}, [], [], [], {}
    try:
        for s in (kwargs.get("mcp_servers") or []):
            lb, h = _get(s, "name"), _host_of(_get(s, "url"))
            if lb:
                labels.append(str(lb)[:64])
            if h:
                hosts.append(h)
                if lb:
                    host_of[str(lb)[:64]] = h
        for t in (kwargs.get("tools") or []):
            if _get(t, "type") == "mcp":
                lb, h = _get(t, "server_label"), _host_of(_get(t, "server_url"))
                if lb:
                    labels.append(str(lb)[:64])
                if h:
                    hosts.append(h)
                    if lb:
                        host_of[str(lb)[:64]] = h
    except Exception:
        pass
    try:
        for b in (_get(resp, "content") or []):
            if _get(b, "type") == "mcp_tool_use" and _get(b, "name"):
                ran.append(str(_get(b, "server_name") or "?")[:64] + "/" + str(_get(b, "name"))[:64])
        for item in (_get(resp, "output") or []):
            if _get(item, "type") == "mcp_call" and _get(item, "name"):
                ran.append(str(_get(item, "server_label") or "?")[:64] + "/" + str(_get(item, "name"))[:64])
    except Exception:
        pass
    if labels:
        out["mcp_servers_offered"] = sorted(set(labels))[:_TOOL_CAP]
    if hosts:
        out["mcp_hosts"] = sorted(set(hosts))[:_TOOL_CAP]
    if labels or ran:
        out["mcp_tools_invoked"] = sorted(set(ran))[:_TOOL_CAP]
        used = sorted({host_of[r.split("/", 1)[0]] for r in ran if r.split("/", 1)[0] in host_of})
        out["mcp_hosts_invoked"] = used[:_TOOL_CAP]
    return out


_AGENT = contextvars.ContextVar("avowa_agent", default=None)
_LABEL_RX = re.compile(r"^[A-Za-z0-9 _.:/-]{1,64}$")


@contextmanager
def agent_context(name=None, customer=None):
    """Every model call inside this block is recorded as made by agent `name` for `customer`.

        with avowa_runtime.agent_context("triage", customer=account.id):
            run_agent(...)

    `name` is sent as written (64 characters, letters, digits and `_ . : / -`); `customer` is sent
    only as a keyed hash. Works across threads started inside the block only if they copy the
    context (contextvars), and across asyncio tasks automatically."""
    nm = str(name)[:64] if name is not None else None
    if nm is not None and not _LABEL_RX.match(nm):
        _warn_once("agentname", "agent_context name must be letters, digits and _ . : / - (64 at most); "
                                "the name was not recorded.")
        nm = None
    tok = _AGENT.set({"name": nm, "customer": None if customer is None else str(customer)})
    try:
        yield
    finally:
        _AGENT.reset(tok)


def _customer_ref(secret, customer):
    if customer is None or customer == "":
        return None
    key = os.getenv("AVOWA_REF_KEY") or secret
    if not key:
        return None
    return hmac.new(str(key).encode("utf-8"), ("avowa-customer:" + str(customer)).encode("utf-8", "replace"),
                    hashlib.sha256).hexdigest()[:12]


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


_DEFAULT = None


def approval(call_id, approved, approver_role=None, approver_type="unknown", policy_ref=None):
    """Record an approval decision on one tool call. See `AvowaRuntime.approval`."""
    if _DEFAULT is None:
        _warn_once("noruntime", "approval() was called but no Avowa runtime is running; nothing was recorded.")
        return
    _DEFAULT.approval(call_id, approved, approver_role, approver_type, policy_ref)


def tool_outcome(call_id, outcome):
    """Record how one tool call ended. See `AvowaRuntime.tool_outcome`."""
    if _DEFAULT is None:
        _warn_once("noruntime", "tool_outcome() was called but no Avowa runtime is running; nothing was recorded.")
        return
    _DEFAULT.tool_outcome(call_id, outcome)


def _host_of(url):
    if not url:
        return None
    try:
        u = str(url)
        return (urlsplit(u if "://" in u else "https://" + u).hostname or None)
    except Exception:
        return None


class AvowaRuntime:
    def __init__(self, ingest_key=None, ingest_secret=None, base_url=None, region=None,
                 default_model=None, async_send=True, timeout=5):
        self.disabled = _disabled()
        if self.disabled:
            self.key = self.secret = self.base = self.region = self.default_model = None
            self.timeout, self.async_send, self._q, self._worker, self._pid = timeout, False, None, None, None
            return
        if not (ingest_key and ingest_secret):
            _autoload_env()
        self.key = ingest_key or os.getenv("AVOWA_RUNTIME_KEY")
        self.secret = ingest_secret or os.getenv("AVOWA_RUNTIME_SECRET")
        self.base, problem = _checked_base(base_url or os.getenv("AVOWA_BASE_URL"))
        if problem and self.key:
            _warn_once("base", problem + " — no signals will be sent. Your app is unaffected.")
        self.region = region or os.getenv("AVOWA_REGION")
        self.default_model = default_model
        self.timeout = timeout
        self.async_send = async_send
        global _DEFAULT
        if _DEFAULT is None and self.key:
            _DEFAULT = self
        self._q = queue.Queue(maxsize=10000) if async_send else None
        self._worker = None
        self._pid = None
        if async_send:
            self._start_worker()
            atexit.register(self.flush)
            if hasattr(os, "register_at_fork"):
                try:
                    os.register_at_fork(after_in_child=self._reset_after_fork)
                except Exception:
                    pass

    def _start_worker(self):
        self._pid = os.getpid()
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def _reset_after_fork(self):
        self._q = queue.Queue(maxsize=10000)
        self._start_worker()

    def _ensure_worker(self):
        if self._pid != os.getpid() or self._worker is None or not self._worker.is_alive():
            self._reset_after_fork()

    def capture(self, model=None, region=None, train_on_data=None,
                guardrail_blocked=None, latency_ms=None, guardrail=None,
                decision_logged=None, human_reviewed=None, rationale_present=None,
                ai_disclosed=None, uncertainty_flagged=None, fairness_checked=None,
                blocked_category=None, pii_redacted=None, grounded=None, refused=None,
                injection_blocked=None, output_validated=None, system_prompt_protected=None,
                rate_limited=None, tool_authorized=None, action_authorized=None,
                model_pinned=None, eval_score=None,
                agent_run=None, tool_called=None, autonomy_depth=None, action_class=None,
                tools_offered=None, tools_invoked=None, agent_run_key=None,
                approval_required=None, approved_by_human=None, action_blocked=None,
                action_logged=None,
                endpoint=None, scan_prompt=None, scan_output=None,
                error=None, fallback_model=None, retries=None,
                injection_suspected=None, pii_detected=None,
                token_ceiling=None, provider_throttled=None,
                requested_model=None, stop_reason=None, structured_output=None, refusal_part=None,
                input_tokens=None, output_tokens=None, cache_read_tokens=None, cache_write_tokens=None,
                system_prompt_present=None, tool_choice=None, messages_user=None, messages_assistant=None,
                messages_tool=None, input_images=None, input_files=None, input_audio=None, streaming=None,
                response_format_type=None, prompt_chars=None, output_chars=None, client_max_retries=None,
                client_timeout_s=None, pii_families=None, injection_families=None,
                tool_calls=None, tool_results=None, mcp_servers_offered=None, mcp_tools_invoked=None,
                mcp_hosts=None, mcp_hosts_invoked=None, agent_name=None, customer=None,
                _sdk_observed=None,
                **unknown):
        """Record one inference signal (fire-and-forget).

        Basic fields (model/region/train_on_data/guardrail_blocked) prove model provenance,
        inference region, no-train and monitoring. The optional behavioural flags below are the
        Responsible-AI moat — pass the ones your app enforces and Avowa live-verifies that principle:
          guardrail          str  — guardrail type applied (e.g. "pii-redact", "prompt-injection")
          decision_logged    bool — this decision + inputs + user action were logged  (Accountability)
          human_reviewed     bool — output was routed for human approval/override      (Human Oversight)
          rationale_present  bool — the response carried rationale / citations          (Explainability)
          ai_disclosed       bool — the response disclosed it is AI                     (Transparency)
          uncertainty_flagged bool — the model flagged uncertainty / fell back          (Reliability)
          fairness_checked   bool — a fairness / bias check ran on this call            (Fairness)
          blocked_category   str  — WHAT a guardrail caught: "prompt_injection" | "jailbreak" |
                                    "pii" | "toxic" | "off_topic" …    (feeds live red-teaming + guardrail depth)
          pii_redacted       bool — PII was detected & redacted on this call            (Privacy)
          grounded           bool — the answer was grounded in retrieved context (RAG)  (hallucination resistance)
          refused            bool — the model refused an unsafe / out-of-policy request (abuse resistance)

        AI SECURITY — OWASP LLM Top 10 + agentic. Each is proven live from the call path; a static
        pentest or posture tool cannot show these. Pass the ones your inference path enforces:
          injection_blocked      bool — a prompt-injection attempt was blocked on this call   (LLM01)
          pii_redacted           bool — sensitive data redacted before egress                 (LLM02)
          model_pinned           bool — model version pinned / provider integrity verified     (LLM03)
          output_validated       bool — output was schema-validated / encoded before use       (LLM05)
          tool_authorized        bool — an agent tool call was within its allowed scope         (LLM06)
          action_authorized      bool — a high-impact / irreversible action was gated/approved  (agentic)
          system_prompt_protected bool — system-prompt-leak attempt blocked / protection on     (LLM07)
          grounded               bool — answer grounded in retrieved context (also LLM09)
          rate_limited           bool — a rate / token-cost ceiling was enforced on this call    (LLM10)
          eval_score             number — a continuous quality-eval score for this sampled call  (model eval)
        AGENTIC OVERSIGHT — for products that ship agents, not just a chat box. This answers the
        questions a buyer asks about autonomy: what can it DO, under whose authority, bounded how,
        and who watched. Nothing here can be captured by a questionnaire or a posture scanner.
          agent_run          bool  — this call was part of an agentic run
          tool_called        str   — the tool actually invoked ("send_email", "post_invoice")
          autonomy_depth     int   — steps taken in this run without human input
          action_class       str   — consequence tier: "read" | "write" | "external" | "financial".
                                     Anything above "read" counts as consequential, and the human-
                                     approval rate is measured over those ONLY (approving read-only
                                     calls would inflate the number and prove nothing).
          approval_required  bool  — policy required a human before this action
          approved_by_human  bool  — a human actually approved it
          action_blocked     bool  — the action was blocked by policy in the execution path
          action_logged      bool  — the action was written to an attributable audit trail
          agent_name         str   — which of your agents made the call (or use `agent_context`)
          customer           str   — which of YOUR customers it ran for; sent only as a keyed hash
        A human approval or a tool's outcome happens AFTER the model call that proposed the tool, so
        it is recorded on its own with `approval(call_id, …)` / `tool_outcome(call_id, …)`, joined
        to the call by the provider's tool-call id.

        OBSERVED fields — these are the ones Avowa grades as evidence it saw for itself (L3), rather
        than a claim your application made about itself (L2 "runtime-asserted"). Prefer these:
          endpoint       str — the host you called ("api.anthropic.com"). Becomes your OBSERVED
                               sub-processor list and, where the host encodes one, your observed
                               inference region. Pass a host or a URL; only the hostname is sent.
          scan_prompt    str — prompt text to scan LOCALLY for injection patterns. NEVER transmitted;
                               only the integer count of matched pattern families is sent.
          scan_output    str — output text to scan LOCALLY for PII/secrets, after your own redaction
                               has run. NEVER transmitted; only the count is sent.
          error          str — error class if the call failed
          fallback_model str — the model that actually served the request when the primary failed
          retries        int — retry attempts made for this call
        The two scan_* arguments are read, matched, and dropped inside your process. Avowa receives
        `pii_detected` / `injection_suspected` counts and nothing else — which is what lets a leak or
        an attack be evidenced without Avowa ever processing your prompts.

        Fields you don't pass are NOT sent — so you only ever claim what you actually instrument.
        A product with no agents simply never passes these, and its agentic claims stay
        "not applicable" rather than showing a hollow pass.
        Adversarial blocks (injection_blocked / blocked_category prompt_injection|jailbreak) + refusals
        become LIVE red-teaming + attack-surface evidence — proven on real traffic, not a report.
        """
        if unknown:
            _warn_once("unknown:" + ",".join(sorted(unknown)),
                       "capture() ignored unknown field(s): %s — the rest of the signal was sent." % ", ".join(sorted(unknown)))
        if not (self.key and self.base):
            return
        evt = {"model": model or self.default_model,
               "region": region or self.region,
               "latency_ms": latency_ms}
        if train_on_data is not None:
            evt["train_on_data"] = bool(train_on_data)
        for k, v in (("guardrail_blocked", guardrail_blocked),
                     ("guardrail", guardrail), ("decision_logged", decision_logged),
                     ("human_reviewed", human_reviewed), ("rationale_present", rationale_present),
                     ("ai_disclosed", ai_disclosed), ("uncertainty_flagged", uncertainty_flagged),
                     ("fairness_checked", fairness_checked), ("blocked_category", blocked_category),
                     ("pii_redacted", pii_redacted), ("grounded", grounded), ("refused", refused),
                     ("injection_blocked", injection_blocked), ("output_validated", output_validated),
                     ("system_prompt_protected", system_prompt_protected), ("rate_limited", rate_limited),
                     ("tool_authorized", tool_authorized), ("action_authorized", action_authorized),
                     ("model_pinned", model_pinned), ("eval_score", eval_score),
                     ("agent_run", agent_run), ("tool_called", tool_called),
                     ("autonomy_depth", autonomy_depth), ("action_class", action_class),
                     ("tools_offered", tools_offered), ("tools_invoked", tools_invoked),
                     ("agent_run_key", agent_run_key),
                     ("approval_required", approval_required), ("approved_by_human", approved_by_human),
                     ("action_blocked", action_blocked), ("action_logged", action_logged),
                     ("endpoint", _host_of(endpoint)), ("error", error),
                     ("fallback_model", fallback_model), ("retries", retries),
                     ("token_ceiling", token_ceiling), ("provider_throttled", provider_throttled),
                     ("requested_model", requested_model), ("stop_reason", stop_reason),
                     ("structured_output", structured_output), ("refusal_part", refusal_part),
                     ("input_tokens", input_tokens), ("output_tokens", output_tokens),
                     ("cache_read_tokens", cache_read_tokens), ("cache_write_tokens", cache_write_tokens),
                     ("system_prompt_present", system_prompt_present), ("tool_choice", tool_choice),
                     ("messages_user", messages_user), ("messages_assistant", messages_assistant),
                     ("messages_tool", messages_tool), ("input_images", input_images),
                     ("input_files", input_files), ("input_audio", input_audio), ("streaming", streaming),
                     ("response_format_type", response_format_type), ("prompt_chars", prompt_chars),
                     ("output_chars", output_chars), ("client_max_retries", client_max_retries),
                     ("client_timeout_s", client_timeout_s), ("pii_families", pii_families),
                     ("injection_families", injection_families),
                     ("tool_calls", tool_calls), ("tool_results", tool_results),
                     ("mcp_servers_offered", mcp_servers_offered), ("mcp_tools_invoked", mcp_tools_invoked),
                     ("mcp_hosts", mcp_hosts), ("mcp_hosts_invoked", mcp_hosts_invoked)):
            if v is not None:
                evt[k] = v
        ctx = _AGENT.get() or {}
        name = agent_name if agent_name is not None else ctx.get("name")
        if name is not None:
            evt["agent_name"] = str(name)[:64]
        cref = _customer_ref(self.secret, customer if customer is not None else ctx.get("customer"))
        if cref:
            evt["customer_ref"] = cref
        call = _CALL_FACTS.get() or {}
        more = {**_env_facts(), **call}
        for k, v in more.items():
            evt.setdefault(k, v)
        if call or _sdk_observed:
            _sdk_observed = list(_sdk_observed or []) + list(more)
        scan = None
        if scan_prompt is not None or scan_output is not None:
            scan = (_cap(scan_prompt, "tail") if scan_prompt is not None else None,
                    _cap(scan_output, "head") if scan_output is not None else None)
        if injection_suspected is not None:
            evt["injection_suspected"] = int(injection_suspected)
        if pii_detected is not None:
            evt["pii_detected"] = int(pii_detected)
        if _sdk_observed:
            evt["_sdk_observed"] = sorted(set(_sdk_observed))
        if INTERNAL_ERRORS:
            evt["sdk_errors"] = sum(INTERNAL_ERRORS.values())
            evt["sdk_error_kinds"] = sorted(INTERNAL_ERRORS)[:10]
        if self.async_send:
            self._ensure_worker()
            if scan is not None and self._q.qsize() >= DEFERRED_SCAN_MAX:
                _apply_scan(evt, scan)
                scan = None
            try:
                self._q.put_nowait((evt, scan))
                _dbg("captured " + _evt_summary(evt))
            except queue.Full:
                _warn_once("qfull", "signal queue is full — signals are being dropped. The "
                                    "backend is unreachable or far slower than your traffic.")
        else:
            _apply_scan(evt, scan)
            self._post(evt)

    def approval(self, call_id, approved, approver_role=None, approver_type="unknown", policy_ref=None):
        """Record an approval decision on one tool call: approved (`approved=True`) or refused.

        `call_id` is the provider's id for the call (`tool_use.id`, `tool_calls[i].id`, or a
        Responses `call_id`); only its hash is sent, and the server joins it to the model call that
        proposed it.

        `approver_type` says WHO decided: "human", "policy" (a policy engine or rule), "system"
        (another automated component) or "unknown". Only "human" counts as human oversight, so pass
        it when a person made the call. `approver_role` is a short label such as "finance_ops",
        never a person's name; `policy_ref` a short label naming the rule that decided.
        This is your app's statement about itself and is graded as one: Avowa cannot see the
        decision, and does not claim it came before the tool ran."""
        ref = call_ref(call_id)
        if ref is None:
            return
        kind = approver_type if approver_type in APPROVER_TYPES else "unknown"
        if approver_type not in APPROVER_TYPES:
            _warn_once("approvertype", "approval() approver_type must be one of %s; recorded as unknown." % ", ".join(APPROVER_TYPES))
        ann = {"type": "approval", "tool_call_ref": ref, "approved": bool(approved),
               "approver_type": kind, "at": _now_iso()}
        role = None if approver_role is None else str(approver_role)[:40]
        if role and _LABEL_RX.match(role):
            ann["approver_role"] = role
        pol = None if policy_ref is None else str(policy_ref)[:64]
        if pol and _LABEL_RX.match(pol):
            ann["policy_ref"] = pol
        self._annotate(ann)

    def tool_outcome(self, call_id, outcome):
        """Record how one tool call ended: "ok", "error", "denied" (a policy or a person stopped it)
        or "timeout". Your app's statement, joined to the proposing call by the provider's id."""
        ref = call_ref(call_id)
        if ref is None:
            return
        if outcome not in TOOL_OUTCOMES:
            _warn_once("outcome", "tool_outcome() takes one of %s; that outcome was not recorded." % ", ".join(TOOL_OUTCOMES))
            return
        self._annotate({"type": "outcome", "tool_call_ref": ref, "outcome": outcome, "at": _now_iso()})

    def _annotate(self, ann):
        if self.disabled or not (self.key and self.base):
            return
        if self.async_send:
            self._ensure_worker()
            try:
                self._q.put_nowait(({"_annotation": ann}, None))
            except queue.Full:
                _warn_once("qfull", "signal queue is full — signals are being dropped. The "
                                    "backend is unreachable or far slower than your traffic.")
        else:
            self._post_many([], [ann])

    @contextmanager
    def track(self, model=None, region=None, train_on_data=None, **asserts):
        """Time a block and capture a signal when it exits. An exception inside the block is
        recorded as `error=<ExceptionType>` — it used to be recorded as `guardrail_blocked=True`,
        which turned every timeout and bad API key into evidence of a working guardrail. Pass
        `guardrail_blocked=True` yourself when your guardrail actually blocked the call."""
        start = time.time()
        err = None
        try:
            yield
        except Exception as e:
            err = type(e).__name__
            raise
        finally:
            self.capture(model=model, region=region, train_on_data=train_on_data, error=err,
                         latency_ms=int((time.time() - start) * 1000), **asserts)

    def instrument_openai(self, client, region=None, scan=True, asserts=None):
        """Monkey-patch an OpenAI (or Azure OpenAI) client so every model call is captured.

        Same contract as `instrument_anthropic`: everything recorded is OBSERVED — the model the
        API actually returned, the host reached, latency and errors — plus, with `scan=True`, an
        in-process injection/PII scan that transmits counts only.

        Covers all three call shapes, because a vendor rarely uses only one:
          • `chat.completions.create`  — the common path
          • `chat.completions.parse`   — structured output (beta namespace on some versions)
          • `responses.create`         — the newer Responses API
        Wrapping only `chat.completions.create` would silently miss the others and under-report
        coverage, which is the same trap `parse()` set on the Anthropic side.

        AZURE OPENAI works through this call too: it is the same client class with a different
        `base_url`, so the host recorded is the Azure endpoint — which is exactly what proves the
        inference region rather than assuming it.

        Streaming (`stream=True`) is captured when the stream ends, on the provider's own stream
        object — the app receives exactly what it would without Avowa.
        """
        if self.disabled:
            return client
        rt = self
        host = _host_of(getattr(client, "base_url", None)) or "api.openai.com"
        client_facts = _client_facts(client)

        def _text_of(msgs):
            parts = []
            for m in (msgs or []):
                c = m.get("content") if isinstance(m, dict) else None
                if isinstance(c, str):
                    parts.append(c)
                elif isinstance(c, list):
                    parts.extend(b.get("text", "") for b in c if isinstance(b, dict))
            return "\n".join(p for p in parts if p)

        def _out_of(resp):
            try:
                txt = getattr(resp, "output_text", None)
                if txt:
                    return txt
                choices = getattr(resp, "choices", None) or []
                return "\n".join((getattr(c.message, "content", "") or "") for c in choices)
            except Exception:
                return None

        def _wrap(original, kind):
            def record(resp, err, ms, kwargs):
                try:
                    model = getattr(resp, "model", None) or kwargs.get("model")
                    extra = dict(asserts or {})
                    facts, seen = _facts_from_response(resp, kwargs, rt.secret)
                    extra.update(facts)
                    req, req_seen = _facts_from_request(kwargs)
                    extra.update(req); seen += req_seen
                    extra.update(client_facts); seen += list(client_facts)
                    if kind == "parse" or kwargs.get("response_format") is not None:
                        extra["structured_output"] = True
                        seen.append("structured_output")
                    seen += ["model", "endpoint", "latency_ms"] + (["error"] if err else [])
                    if scan:
                        seen += ["pii_detected", "injection_suspected", "pii_families", "injection_families"]
                    extra["_sdk_observed"] = seen
                    prompt = kwargs.get("messages")
                    if prompt is None and isinstance(kwargs.get("input"), list):
                        prompt = kwargs.get("input")
                    rt.capture(model=model, region=region or rt.region,
                               latency_ms=ms, endpoint=host, error=err,
                               scan_prompt=_text_of(prompt) if scan else None,
                               scan_output=_out_of(resp) if (scan and resp is not None) else None,
                               **extra)
                except Exception as e:
                    _internal_error("openai.record", e)
            return _wrap_call(original, record, "openai." + kind)

        targets = []
        chat = getattr(getattr(client, "chat", None), "completions", None)
        if chat is not None:
            targets += [(chat, "create", "create"), (chat, "parse", "parse")]
        beta_chat = getattr(getattr(getattr(client, "beta", None), "chat", None), "completions", None)
        if beta_chat is not None:
            targets.append((beta_chat, "parse", "parse"))
        responses = getattr(client, "responses", None)
        if responses is not None:
            targets += [(responses, "create", "create"), (responses, "parse", "parse")]

        for holder, name, kind in targets:
            fn = getattr(holder, name, None)
            if callable(fn) and not getattr(fn, "_avowa_wrapped", False):
                try:
                    setattr(holder, name, _wrap(fn, kind))
                except Exception as e:
                    _internal_error(f"openai.patch.{name}", e, fatal_in_strict=False)
        return client

    def instrument_anthropic(self, client, region=None, scan=True, asserts=None):
        """Monkey-patch an Anthropic client so every message call is captured.

        Wraps BOTH `messages.create` and `messages.parse`. This matters: `parse()` does not route
        through `create()` — it posts directly — so wrapping only `create` would silently miss every
        structured-output call and quietly under-report your coverage.

        Everything recorded here is OBSERVED by the SDK — the model the API actually returned, the
        host it was reached on, latency, errors and retries. With `scan=True` (default) the prompt
        and response are also scanned in-process for injection and PII patterns; only the counts are
        sent. Pass `scan=False` to disable the local scan entirely.

        `asserts` is a dict of behavioural flags your app genuinely enforces on EVERY call through
        this client (e.g. {"model_pinned": True} when the model id is a pinned constant). They are
        recorded as self-reported, not observed — pass only what is true unconditionally.

        A `parse()` call that supplies an `output_format` is recorded as structured output (a fact
        about the call); Avowa grades output validation from it.

        Streaming: `messages.create(stream=True)` is captured when the stream ends, on the provider's
        own stream object (nothing is swapped in front of it). The `messages.stream()` helper is not
        wrapped — call `avowa.capture(...)` after it closes if you use it.
        """
        if self.disabled:
            return client
        rt = self
        host = _host_of(getattr(client, "base_url", None)) or "api.anthropic.com"
        client_facts = _client_facts(client)

        def _text_of(msgs):
            parts = []
            for m in (msgs or []):
                c = m.get("content") if isinstance(m, dict) else None
                if isinstance(c, str):
                    parts.append(c)
                elif isinstance(c, list):
                    parts.extend(b.get("text", "") for b in c if isinstance(b, dict))
            return "\n".join(parts)

        def _wrap(original, method_name):
            def record(resp, err, ms, kwargs):
                try:
                    model = getattr(resp, "model", None) or kwargs.get("model")
                    out_text = None
                    if scan and resp is not None:
                        try:
                            out_text = "\n".join(getattr(b, "text", "") or ""
                                                 for b in (getattr(resp, "content", None) or []))
                        except Exception:
                            out_text = None
                    extra = dict(asserts or {})
                    facts, seen = _facts_from_response(resp, kwargs, rt.secret)
                    extra.update(facts)
                    req, req_seen = _facts_from_request(kwargs)
                    extra.update(req); seen += req_seen
                    extra.update(client_facts); seen += list(client_facts)
                    if method_name == "parse" and kwargs.get("output_format") is not None:
                        extra["structured_output"] = True
                        seen.append("structured_output")
                    seen += ["model", "endpoint", "latency_ms"] + (["error"] if err else [])
                    if scan:
                        seen += ["pii_detected", "injection_suspected", "pii_families", "injection_families"]
                    extra["_sdk_observed"] = seen
                    rt.capture(model=model, region=region or rt.region,
                               latency_ms=ms, endpoint=host, error=err,
                               scan_prompt=_text_of(kwargs.get("messages")) if scan else None,
                               scan_output=out_text, **extra)
                except Exception as e:
                    _internal_error("anthropic.record", e)
            return _wrap_call(original, record, "anthropic." + method_name)

        for name in ("create", "parse"):
            fn = getattr(getattr(client, "messages", None), name, None)
            if callable(fn) and not getattr(fn, "_avowa_wrapped", False):
                try:
                    setattr(client.messages, name, _wrap(fn, name))
                except Exception as e:
                    _internal_error(f"anthropic.patch.{name}", e, fatal_in_strict=False)
        return client

    def flush(self, timeout=5):
        """Block until queued signals are sent, or until `timeout` seconds pass — whichever is
        first. Called automatically at exit. The timeout used to be ignored and `q.join()` has no
        bound of its own, so a process exiting with egress blackholed and a full queue could hang
        for up to 10,000 × the request timeout. Evidence is never worth holding an exit hostage."""
        if not (self.async_send and self._q is not None):
            return
        deadline = time.time() + max(0.0, float(timeout or 0))
        try:
            while self._q.unfinished_tasks and time.time() < deadline:
                time.sleep(0.05)
        except Exception:
            pass

    def _run(self):
        while True:
            item = self._q.get()
            batch, stop = [item], item is None
            while not stop and len(batch) < _BATCH_MAX:
                try:
                    nxt = self._q.get_nowait()
                except queue.Empty:
                    break
                batch.append(nxt)
                stop = nxt is None
            try:
                events, anns = [], []
                for it in batch:
                    if it is None:
                        continue
                    evt, scan = it
                    if "_annotation" in evt:
                        anns.append(evt["_annotation"])
                        continue
                    _apply_scan(evt, scan)
                    events.append(evt)
                if anns:
                    self._post_many(events, anns)
                elif events:
                    self._post_many(events)
            except Exception as e:
                _internal_error("sender", e, fatal_in_strict=False)
            finally:
                for _ in batch:
                    self._q.task_done()
            if stop:
                return

    def _post(self, evt):
        self._post_many([evt])

    def _post_many(self, events, annotations=()):
        envelope = {"schema": _SCHEMA, "source": {"kind": "runtime", "client": "avowa-runtime-python",
                                                  "version": __version__},
                    "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "nonce": os.urandom(12).hex(), "events": list(events)}
        if annotations:
            envelope["annotations"] = list(annotations)
        body = json.dumps(envelope, separators=(",", ":"))
        headers = {"Content-Type": "application/json", "X-Ingest-Key": self.key,
                   "User-Agent": f"avowa-runtime-python/{__version__} (+https://avowa.ai)"}
        if self.secret:
            ts = str(int(time.time()))
            sig = hmac.new(self.secret.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
            headers["X-Avowa-Timestamp"] = ts
            headers["X-Avowa-Signature"] = sig
        if self.secret and _remote_on():
            headers["X-Avowa-Fields"] = _REMOTE["v"] or "none"
        url = self.base + "/ingest/v1"
        req = urllib.request.Request(url, data=body.encode(), method="POST", headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            raw = resp.read()
            reply = None
            if raw[:1] == b"{":
                try:
                    reply = json.loads(raw)
                except Exception:
                    reply = None
            if isinstance(reply, dict):
                block = reply.get("sdk_fields")
                if self.secret and _remote_on() and isinstance(block, dict):
                    _accept_fields(block, self.secret)
                latest = reply.get("sdk_latest")
                if isinstance(latest, str) and re.match(r"^\d+\.\d+\.\d+$", latest):
                    _warn_once("latest", "avowa_runtime %s is available (this is %s). Nothing is wrong — "
                                         "upgrade when convenient (your Avowa Connections page has the download)." % (latest, __version__))
            what = _evt_summary(events[0]) if len(events) == 1 else "%d events" % len(events)
            _dbg("sent %s → HTTP %s" % (what, getattr(resp, "status", None) or resp.getcode()))
        except Exception as e:
            detail = type(e).__name__
            code = getattr(e, "code", None)
            if code:
                hint = {401: "the ingest key or secret is wrong for this connection",
                        403: "this key is not permitted to write signals",
                        404: "no /ingest/v1 at this AVOWA_BASE_URL — check the URL",
                        422: "the server rejected the signal's shape"}.get(
                            code, "the server rejected the signal")
                if code == 401 and self.secret:
                    hint += " (or the clock is off — signatures expire after 5 minutes)"
                detail = "HTTP %s — %s" % (code, hint)
            elif isinstance(e, (OSError,)):
                detail = "%s — cannot reach %s (DNS, egress rules or the wrong host)" % (
                    type(e).__name__, self.base)
            _warn_once("post:" + str(code or type(e).__name__),
                       "signal NOT delivered: %s. Your app is unaffected; evidence is not being "
                       "recorded. Set AVOWA_DEBUG=1 for per-call detail." % detail)
            _dbg("POST %s failed: %r" % (url, e))
