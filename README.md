# Avowa Runtime SDK

**Evidence from the call path, not from a questionnaire.**

This SDK runs inside your application and records what actually happened when your AI made a call:
which model answered, which host served it, from where, how long it took, and whether your
guardrails fired. Avowa grades those observations as evidence. Nothing here asks you what your
policy says — that is the point.

It is open source because it runs in your production system. You should be able to read every line
that does, and your security reviewer should be able to check the claim below for themselves rather
than take our word for it.

Two lines, and your code and start command stay as they are:

```bash
pip install avowa-runtime                 # Python
avowa init <setup-token>
```

```bash
npm install @avowa/runtime                # Node.js
npx @avowa/runtime init <setup-token>
```

Then start your app the way you always do. In production it is one variable, `AVOWA_TOKEN`.
`AVOWA_DISABLE=1` switches everything off.

- **[`python/`](python/)** — the Python SDK: a start-up hook that covers the `anthropic` and `openai`
  libraries with no code or start-command change, client wrappers, and explicit capture.
- **[`js/`](js/)** — the JavaScript/TypeScript SDK for Node 18+, server-side only (the signing
  secret must never reach a browser): a preload that covers `openai` and `@anthropic-ai/sdk`
  with no code change, client wrappers, and explicit capture.

## What it sends, and what it never sends

Every signal is **metadata only**:

| Sent | Never sent |
|---|---|
| Model id the provider returned | Prompts |
| Host that answered (`api.anthropic.com`) | Completions |
| Region (if you configure it), latency, token usage and the output-token ceiling | Tool-call arguments |
| Flags you pass (`train_on_data=False`, guardrail outcomes) | Customer data of any kind |

`AVOWA_DEBUG=1` prints each signal as it goes, so you can watch this hold on your own traffic.

## The rule this SDK is built on

**Observed, never asserted.** The SDK records only what it can see happen in the call path. If your
application *says* it uses one model and the call path shows another, Avowa reports the difference
rather than hiding it — including when that makes your own score worse. A wrapper that recorded an
application's claim about itself would defeat the purpose, so contributions that do it are declined
(see [CONTRIBUTING.md](CONTRIBUTING.md)).

Grading, scoring and the trust profile happen server-side in Avowa and are not part of this repo.

## Safety in your request path

- **Fire and forget.** A capture failure never raises into your code.
- **No dependencies.** The Python package is standard library only.
- **Silent by default.** No output unless you ask for it.

## Licence

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Security reports: [SECURITY.md](SECURITY.md).
