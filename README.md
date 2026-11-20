# Avowa Runtime SDK

**Evidence from the call path, not from a questionnaire.**

This SDK runs inside your application and records what happened when your AI made a call: which model
answered, which host served it, how long it took, which tools your agents called, and who approved them.
Avowa grades that record and you share it with buyers.

It is open source because it runs in your production system. You should be able to read every line that
does, and your security reviewer should be able to check the claims below for themselves.

**Documentation: [avowa.ai/docs](https://avowa.ai/docs/)**

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

- **[`python/`](python/)**: the Python SDK. A start-up hook covers the `anthropic` and `openai` libraries
  with no code or start-command change; adapters cover Bedrock, Gemini and LangChain.
- **[`js/`](js/)**: the Node.js SDK (18.18+ or 20.6+, server-side only). A preload covers `openai` and
  `@anthropic-ai/sdk` with no code change.
- **[`conformance/`](conformance/)**: the scenarios every collector must pass.

## What it sends, and what it never sends

| Sent | Never sent |
|---|---|
| Model requested and model the provider returned | Prompts and system prompts |
| Hostname that answered (`api.anthropic.com`), latency, errors, token counts | Completions |
| Tool names, and a hash of each tool call id | Tool arguments and tool output |
| Counts (never matches) from a local personal-data and injection scan | Customer ids (sent only as a keyed hash) |
| Approvals and outcomes you record, and flags you pass | Customer data of any kind |

Every field by name: [avowa.ai/docs/data.html](https://avowa.ai/docs/data.html). `AVOWA_DEBUG=1` prints
each signal as it goes, so you can watch this hold on your own traffic.

## Observed and asserted are never mixed

The SDK records two kinds of fact. What it reads off the call itself (the model the provider returned,
the host, the tools the model called) is marked **observed**. What your application tells it (a
`train_on_data` flag, an approval) is your application's **word**: signed in transit, never upgraded to
an observation. Avowa grades the two differently and buyers see which is which. If your application says it uses one model and the call path shows another,
Avowa reports the difference, including when that makes your own record worse. Contributions that record
an application's claim as an observation are declined (see [CONTRIBUTING.md](CONTRIBUTING.md)).

Grading and the trust profile happen server-side in Avowa and are not part of this repo:
[avowa.ai/grading.html](https://avowa.ai/grading.html).

## Safety in your request path

- **Fire and forget.** A send failure never raises into your code; uploads run on a background thread.
- **HTTPS only**, each request signed with HMAC-SHA256 and a single-use nonce.
- **No dependencies.** Standard library only in Python; none in Node.
- **Silent by default.** No output unless you ask for it.

## Licence

Apache-2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). Changes: [CHANGELOG.md](CHANGELOG.md).
Security reports: [SECURITY.md](SECURITY.md).
