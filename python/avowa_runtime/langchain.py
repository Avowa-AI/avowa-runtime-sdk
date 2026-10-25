# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""
LangChain / LangGraph callback handler — one signal per model call, from the framework's own events.

    from avowa_runtime.langchain import AvowaCallbackHandler
    llm = ChatOpenAI(callbacks=[AvowaCallbackHandler()])        # or pass in `config={"callbacks": [...]}`

What it reads: the model name LangChain reports on `on_llm_end` (`llm_output["model_name"]`, or
the serialized class's `model` kwarg), the generation's `finish_reason`, the tool names LangChain
starts, and the latency between start and end of the same run id. The prompt and completion text
are scanned locally and never leave. Everything is marked as derived by the handler.

If the app already instruments the underlying `openai`/`anthropic` client, do not also add this
handler: the same call would be recorded twice.
"""
import time

try:
    from langchain_core.callbacks import BaseCallbackHandler as _Base
except Exception:
    class _Base:
        pass

from . import AvowaRuntime, _facts_from_response, _Obj, _internal_error

_HOSTS = {"openai": "api.openai.com", "anthropic": "api.anthropic.com", "google": "generativelanguage.googleapis.com",
          "bedrock": "bedrock-runtime.amazonaws.com", "mistral": "api.mistral.ai", "cohere": "api.cohere.com"}


class AvowaCallbackHandler(_Base):
    def __init__(self, runtime=None, scan=True, asserts=None):
        super().__init__()
        self.rt = runtime or AvowaRuntime()
        self.scan = scan
        self.asserts = dict(asserts or {})
        self._runs = {}

    def on_llm_start(self, serialized, prompts, *, run_id=None, **kw):
        self._start(serialized, "\n".join(prompts or []), run_id)

    def on_chat_model_start(self, serialized, messages, *, run_id=None, **kw):
        text = []
        for batch in (messages or []):
            for m in batch:
                c = getattr(m, "content", None)
                if isinstance(c, str):
                    text.append(c)
        self._start(serialized, "\n".join(text), run_id)

    def _start(self, serialized, prompt, run_id):
        s = serialized or {}
        kwargs = s.get("kwargs") or {}
        model = kwargs.get("model") or kwargs.get("model_name")
        ids = s.get("id") or []
        provider = next((h for k, h in _HOSTS.items() if any(k in str(x).lower() for x in ids)), None)
        self._runs[run_id] = (time.time(), model, prompt, provider)

    def on_llm_end(self, response, *, run_id=None, **kw):
        start, asked, prompt, provider = self._runs.pop(run_id, (time.time(), None, "", None))
        try:
            llm_output = getattr(response, "llm_output", None) or {}
            served = llm_output.get("model_name") or llm_output.get("model") or asked
            gens = getattr(response, "generations", None) or []
            gen = gens[0][0] if gens and gens[0] else None
            info = getattr(gen, "generation_info", None) or {}
            fr = info.get("finish_reason") or info.get("stop_reason")
            text = getattr(gen, "text", "") or ""
            self._emit(served, asked, fr, text, prompt, provider, None, start,
                       usage=llm_output.get("token_usage") or llm_output.get("usage"))
        except Exception as e:
            _internal_error("langchain.llm_end", e)

    def on_llm_error(self, error, *, run_id=None, **kw):
        start, asked, prompt, provider = self._runs.pop(run_id, (time.time(), None, "", None))
        self._emit(asked, asked, None, "", prompt, provider, type(error).__name__, start)

    def on_tool_start(self, serialized, input_str, *, run_id=None, **kw):
        try:
            name = (serialized or {}).get("name")
            if name:
                self.rt.capture(model=None, tool_called=str(name)[:64], agent_run=True,
                                _sdk_observed=["tool_called", "agent_run"])
        except Exception as e:
            _internal_error("langchain.tool_start", e)

    def _emit(self, served, asked, fr, text, prompt, provider, err, start, usage=None):
        try:
            summary = _Obj(model=served, stop_reason=fr, usage=usage, content=[_Obj(type="text", text=text)])
            facts, seen = _facts_from_response(summary, {"model": asked})
            extra = dict(self.asserts)
            extra.update(facts)
            seen += ["model", "latency_ms"] + (["endpoint"] if provider else []) + (["error"] if err else [])
            if self.scan:
                seen += ["pii_detected", "injection_suspected", "pii_families", "injection_families"]
            extra["_sdk_observed"] = seen
            self.rt.capture(model=served, latency_ms=int((time.time() - start) * 1000),
                            endpoint=provider, error=err,
                            scan_prompt=prompt if self.scan else None,
                            scan_output=text if (self.scan and text) else None, **extra)
        except Exception as e:
            _internal_error("langchain.emit", e)
