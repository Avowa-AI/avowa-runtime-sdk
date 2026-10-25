# @avowa/runtime

The JavaScript/TypeScript half of the [Avowa Runtime SDK](https://github.com/Avowa-AI/avowa-runtime-sdk) — emits live AI-inference
signals to Avowa as **observed** evidence. Node 18+, server-side only — the signing secret must never ship to a browser, and the ingest API does not accept browser origins.

```bash
npm install @avowa/runtime
```

One dependency-free file, Apache-2.0. (It is also in your Avowa SDK download, if you would rather vendor it.)

```js
import createAvowa from '@avowa/runtime'

const avowa = createAvowa({
  ingestKey: process.env.AVOWA_RUNTIME_KEY,
  ingestSecret: process.env.AVOWA_RUNTIME_SECRET,   // signs each signal (tamper-evident)
  baseUrl: process.env.AVOWA_BASE_URL,
  region: 'us-east-1',
})

// record a call you already made
avowa.capture({ model: 'claude-opus-4-8', train_on_data: false })

// or wrap one — times it, and records whether it was blocked
const resp = await avowa.track({ model: 'claude-opus-4-8' }, () => client.messages.create(...))
```

**Metadata only.** Model id, host, region, latency, counts and the flags you pass. Never prompts,
completions, tool arguments or customer data.

**Never in your way.** Capture is fire-and-forget and never rejects: if Avowa is unreachable your
call still returns, uploads time out after 5 s, and at most 64 are in flight (past that they are
dropped, with one warning). The wrappers hand back the provider's own promise and stream objects
(`.withResponse()`, `.tee()` and `instanceof` all behave as without Avowa). HTTPS only, every
request signed and single-use, and `AVOWA_DISABLE=1` turns it off entirely.
`track()` re-throws whatever your function threw, after recording that it was blocked.

Licence: Apache-2.0.

## Wrap your client (observed, not asserted)

```js
import OpenAI from 'openai'
import { createAvowa } from '@avowa/runtime'

const avowa = createAvowa()                       // AVOWA_RUNTIME_KEY / _SECRET / AVOWA_BASE_URL from the env
const openai = avowa.instrumentOpenAI(new OpenAI())      // chat.completions.create, responses.create — streams included
// const anthropic = avowa.instrumentAnthropic(new Anthropic())   // messages.create — streams included
```

The wrapper reads the requested and served model, the provider's finish/stop code, the tools
offered and the tools the model invoked, and scans the prompt and output text locally; only counts
leave. It sends those facts as they are — Avowa evaluates them on its side — and each signal names
the fields the wrapper read, so they grade as observed rather than as your app's word. `capture()` and `track()` remain for anything else,
graded as self-reported.
