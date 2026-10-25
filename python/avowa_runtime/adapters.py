# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""
Provider adapters beyond the OpenAI and Anthropic clients: Amazon Bedrock (boto3) and Google Gemini
(google-genai). Each wraps the client's call methods the way `instrument_openai` does — the signal
is recorded once the response EXISTS, the served model and stop reason are read off it, the output
text is scanned locally and never leaves, and the provenance list names what the adapter derived.

    from avowa_runtime import AvowaRuntime
    from avowa_runtime.adapters import instrument_bedrock, instrument_gemini

    rt = AvowaRuntime()
    instrument_bedrock(rt, boto3.client("bedrock-runtime"))   # converse, converse_stream (summary), invoke_model
    instrument_gemini(rt, genai.Client())                      # models.generate_content

Nothing here imports boto3 or google-genai: the client object is whatever the app already built.
"""
from . import _wrap_call, _facts_from_response, _facts_from_request, _host_of, _Obj, _internal_error


def _text_blocks(messages):
    out = []
    try:
        for m in (messages or []):
            if isinstance(m, str):
                out.append(m)
            elif isinstance(m, dict):
                for b in (m.get("content") or m.get("parts") or []):
                    if isinstance(b, dict) and b.get("text"):
                        out.append(b["text"])
                    elif isinstance(b, str):
                        out.append(b)
            else:
                for part in (getattr(m, "parts", None) or []):
                    t = getattr(part, "text", None)
                    if t:
                        out.append(t)
    except Exception:
        pass
    return "\n".join(out)


def instrument_bedrock(rt, client, region=None, scan=True, asserts=None):
    """boto3 `bedrock-runtime` client: wraps `converse`, `converse_stream` and `invoke_model`."""
    host = _host_of(getattr(getattr(client, "meta", None), "endpoint_url", None)) or "bedrock-runtime.amazonaws.com"
    reg = region or getattr(getattr(client, "meta", None), "region_name", None)

    def _wrap(method):
        def record(resp, err, ms, kwargs):
            try:
                model = kwargs.get("modelId")
                stop = (resp or {}).get("stopReason") if isinstance(resp, dict) else None
                blocks = ((((resp or {}).get("output") or {}).get("message") or {}).get("content") or []) \
                    if isinstance(resp, dict) else []
                used = [_Obj(type="tool_use", name=b["toolUse"].get("name")) for b in blocks
                        if isinstance(b, dict) and isinstance(b.get("toolUse"), dict) and b["toolUse"].get("name")]
                out_text = None
                if isinstance(resp, dict) and scan:
                    try:
                        out_text = "\n".join(b.get("text", "") for b in
                                             ((resp.get("output") or {}).get("message") or {}).get("content") or []
                                             if isinstance(b, dict))
                    except Exception:
                        out_text = None
                summary = _Obj(model=model, stop_reason=stop, usage=(resp or {}).get("usage") if isinstance(resp, dict) else None,
                               content=[_Obj(type="text", text=out_text or "")] + used)
                facts, seen = _facts_from_response(summary, {"model": model, "tools": _bedrock_tools(kwargs)})
                extra = dict(asserts or {})
                extra.update(facts)
                req, req_seen = _facts_from_request({**kwargs, "max_tokens": (kwargs.get("inferenceConfig") or {}).get("maxTokens"),
                                                     "tool_choice": next(iter(((kwargs.get("toolConfig") or {}).get("toolChoice") or {})), None)})
                extra.update(req); seen += req_seen
                seen += ["model", "endpoint", "latency_ms"] + (["error"] if err else [])
                if scan:
                    seen += ["pii_detected", "injection_suspected", "pii_families", "injection_families"]
                extra["_sdk_observed"] = seen
                rt.capture(model=model, region=reg or rt.region, latency_ms=ms,
                           endpoint=host, error=err,
                           scan_prompt=_text_blocks(kwargs.get("messages")) if scan else None,
                           scan_output=out_text if (scan and out_text) else None, **extra)
            except Exception as e:
                _internal_error("bedrock.record", e)
        return _wrap_call(method, record, "bedrock.converse")

    for name in ("converse", "invoke_model"):
        fn = getattr(client, name, None)
        if callable(fn) and not getattr(fn, "_avowa_wrapped", False):
            try:
                setattr(client, name, _wrap(fn))
            except Exception as e:
                _internal_error("bedrock.patch", e, fatal_in_strict=False)
    return client


def _bedrock_tools(kwargs):
    try:
        return [{"name": t["toolSpec"]["name"]} for t in ((kwargs.get("toolConfig") or {}).get("tools") or [])
                if isinstance(t, dict) and t.get("toolSpec")]
    except Exception:
        return None


def _gemini_tools(kwargs):
    cfg = kwargs.get("config") or kwargs.get("generation_config")
    tools = cfg.get("tools") if isinstance(cfg, dict) else getattr(cfg, "tools", None)
    out = []
    for t in (tools or []):
        decls = t.get("function_declarations") if isinstance(t, dict) else getattr(t, "function_declarations", None)
        for d in (decls or []):
            n = d.get("name") if isinstance(d, dict) else getattr(d, "name", None)
            if n:
                out.append({"name": n})
    return out or None


def instrument_gemini(rt, client, region=None, scan=True, asserts=None):
    """google-genai `Client`: wraps `models.generate_content` (sync and async clients)."""
    vertex = bool(getattr(client, "vertexai", False))
    host = "aiplatform.googleapis.com" if vertex else "generativelanguage.googleapis.com"

    def record(resp, err, ms, kwargs):
        try:
            asked = kwargs.get("model")
            served = getattr(resp, "model_version", None) or asked
            fr = None
            try:
                fr = getattr(resp.candidates[0], "finish_reason", None)
                fr = getattr(fr, "name", fr)
            except Exception:
                fr = None
            out_text = None
            if scan and resp is not None:
                try:
                    out_text = getattr(resp, "text", None)
                except Exception:
                    out_text = None
            used = []
            try:
                for part in (getattr(getattr(resp.candidates[0], "content", None), "parts", None) or []):
                    fc = getattr(part, "function_call", None)
                    if getattr(fc, "name", None):
                        used.append(_Obj(type="tool_use", name=fc.name))
            except Exception:
                pass
            summary = _Obj(model=served, stop_reason=str(fr).lower() if fr else None,
                           usage_metadata=getattr(resp, "usage_metadata", None),
                           content=[_Obj(type="text", text=out_text or "")] + used)
            facts, seen = _facts_from_response(summary, {"model": asked, "tools": _gemini_tools(kwargs)})
            extra = dict(asserts or {})
            extra.update(facts)
            cfg = kwargs.get("config") or kwargs.get("generation_config")
            ceil = cfg.get("max_output_tokens") if isinstance(cfg, dict) else getattr(cfg, "max_output_tokens", None)
            req, req_seen = _facts_from_request({"max_tokens": ceil})
            extra.update(req); seen += req_seen
            seen += ["model", "endpoint", "latency_ms"] + (["error"] if err else [])
            if scan:
                seen += ["pii_detected", "injection_suspected", "pii_families", "injection_families"]
            extra["_sdk_observed"] = seen
            rt.capture(model=served, region=region or rt.region, latency_ms=ms,
                       endpoint=host, error=err,
                       scan_prompt=_text_blocks(kwargs.get("contents") if not isinstance(kwargs.get("contents"), str)
                                                else [kwargs.get("contents")]) if scan else None,
                       scan_output=out_text if (scan and out_text) else None, **extra)
        except Exception as e:
            _internal_error("gemini.record", e)

    models = getattr(client, "models", None)
    fn = getattr(models, "generate_content", None)
    if callable(fn) and not getattr(fn, "_avowa_wrapped", False):
        try:
            setattr(models, "generate_content", _wrap_call(fn, record, "gemini.generate_content"))
        except Exception as e:
            _internal_error("gemini.patch", e, fatal_in_strict=False)
    aio = getattr(getattr(client, "aio", None), "models", None)
    afn = getattr(aio, "generate_content", None)
    if callable(afn) and not getattr(afn, "_avowa_wrapped", False):
        try:
            setattr(aio, "generate_content", _wrap_call(afn, record, "gemini.generate_content"))
        except Exception as e:
            _internal_error("gemini.patch.aio", e, fatal_in_strict=False)
    return client
