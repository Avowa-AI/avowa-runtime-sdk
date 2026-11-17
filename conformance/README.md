# Runtime evidence conformance

`runtime-scenarios.json` describes provider calls and the Avowa runtime event each one must produce
(the contract: `docs/RUNTIME_EVIDENCE_CONTRACT.md` in the Avowa repository, version `avowa.signal/1`).

Every collector runs the same file:

- the Python SDK and the OpenTelemetry parser: `backend/test_evidence_contract.py`
- the Node SDK: `js/conformance.test.mjs`

A collector for another language (a Java agent extension, a Go middleware) is finished when it
passes every scenario here. Each scenario lists:

| Key | Meaning |
|---|---|
| `request`, `response` or `raise` | the provider call, as the provider's own client sees it |
| `expect` | fields the event must carry, with these exact values |
| `observed` | fields the collector must mark as read off the call (`_sdk_observed`) |
| `absent` | fields that must not be sent |
| `graded` | what the server must derive from the event |
| `otel` | the same call as an OpenTelemetry span, and which facts it must yield |

Text containing `SECRET` must never appear in any event.
