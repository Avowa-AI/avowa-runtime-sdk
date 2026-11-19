# @avowa/runtime

The JavaScript/TypeScript half of the [Avowa Runtime SDK](https://github.com/Avowa-AI/avowa-runtime-sdk) — emits live AI-inference
signals to Avowa as **observed** evidence. Node 18+, server-side only — the signing secret must never ship to a browser, and the ingest API does not accept browser origins.

## Install

**Two lines, in your project folder.** Your code stays as it is. (The setup token comes from
Connections → Runtime SDK → *Generate setup token*.)

```bash
npm install @avowa/runtime
npx @avowa/runtime init <setup-token>     # writes avowa.env with one value: AVOWA_TOKEN
```

`init` also offers to add the preload to your `start` script, and shows the change before it makes
it (`init --dry-run` changes nothing at all):

```
from: node server.js
to:   node --import @avowa/runtime/register server.js
```

Then start your app the way you always do and send one real request that calls the model.
`npx @avowa/runtime status` shows what is covered and asks the server whether it knows this key. It
sends no signal.

**In production** set two environment variables and change nothing else:

```bash
AVOWA_TOKEN=avw1_...                                   # the value in avowa.env
NODE_OPTIONS=--import @avowa/runtime/register          # any start command, Docker, Kubernetes
```

`AVOWA_DISABLE=1` switches everything off. One dependency-free package, Apache-2.0.

### What the preload covers

`@avowa/runtime/register` patches the provider SDKs' own classes as your app loads, so every client
is covered whoever builds it: your code, a framework, or a dependency. ES modules and CommonJS both
work.

| Library | Covered |
|---|---|
| `openai` (OpenAI, Azure OpenAI, any OpenAI-compatible host) | `chat.completions.create`, `responses.create`, streams included |
| `@anthropic-ai/sdk` | `messages.create`, streams included |
| anything else (Bedrock, Gemini, Vercel AI SDK, raw `fetch`) | not yet: use `capture()` / `track()` below |

Two limits to know about:

- **Bundled server code.** A bundler (Next.js, esbuild, webpack) that compiles the provider SDK into
  its own output file carries a private copy the preload never meets. Keep the provider SDK external
  to the bundle (Next.js: `serverExternalPackages`), or wrap the client once as shown below.
- **Node version.** `--import` needs Node 18.18+ or 20.6+.

## Use it in code instead

Nothing below is needed when the preload is on. It is for the cases above, and for recording what
your app enforces.

```js
import createAvowa from '@avowa/runtime'

const avowa = createAvowa()        // reads AVOWA_TOKEN from the environment

// record a call you already made
avowa.capture({ model: 'claude-opus-4-8', train_on_data: false })

// or wrap one: times it, and records whether it was blocked
const resp = await avowa.track({ model: 'claude-opus-4-8' }, () => client.messages.create(...))
```

`createAvowa({ ingestKey, ingestSecret, baseUrl, region })` takes the values explicitly if you would
rather not use the token, and the three separate variables (`AVOWA_RUNTIME_KEY`,
`AVOWA_RUNTIME_SECRET`, `AVOWA_BASE_URL`) still work. To read `avowa.env` without the preload:
`import { loadEnv } from '@avowa/runtime/env'; loadEnv()`.

**Metadata only.** Model id, host, region, latency, counts and the flags you pass. Never prompts,
completions, tool arguments or customer data.

**Never in your way.** Capture is fire-and-forget and never rejects: if Avowa is unreachable your
call still returns, uploads time out after 5 s, and at most 64 are in flight (past that they are
dropped, with one warning). The wrappers hand back the provider's own promise and stream objects
(`.withResponse()`, `.tee()` and `instanceof` all behave as without Avowa). HTTPS only, every
request signed and single-use, and `AVOWA_DISABLE=1` turns it off entirely.
`track()` re-throws whatever your function threw, after recording that it was blocked.

Licence: Apache-2.0.

## Agents: approvals, outcomes and who ran it (0.13)

The wrappers read each tool call the model proposed and each result your app handed back, by a hash
of the provider's call id (the id never leaves your process), plus the run key and step depth, the
same as the Python SDK. A human approval or a tool's outcome happens after the call, so record it on
its own:

```js
import { approval, toolOutcome, agentContext } from '@avowa/runtime'

await agentContext({ name: 'triage', customer: account.id }, async () => {
  const resp = await client.messages.create({ ... })
  for (const b of resp.content) {
    if (b.type === 'tool_use' && needsSignOff(b)) {
      approval(b.id, await askAHuman(b), 'finance_ops', { approverType: 'human' })   // a role label, never a name
      toolOutcome(b.id, 'ok')                             // or 'error', 'denied', 'timeout'
    }
  }
})
```

`approverType` is `'human'`, `'policy'` (with `policyRef`), `'system'` or `'unknown'` (the default); only
`'human'` counts as human approval, and Avowa does not claim the decision came before the tool ran.
Call references are 20 hex characters of a hash of the provider's id: a correlation label, not
anonymisation. The customer id is sent only as a keyed hash; set `AVOWA_REF_KEY` (read only in your
process, never sent) and nobody else can test a guess. Rotating it starts a new correlation period.

## Wrap your client (observed, not asserted)

```js
import OpenAI from 'openai'
import { createAvowa } from '@avowa/runtime'

const avowa = createAvowa()                       // AVOWA_TOKEN from the env
const openai = avowa.instrumentOpenAI(new OpenAI())      // chat.completions.create, responses.create — streams included
// const anthropic = avowa.instrumentAnthropic(new Anthropic())   // messages.create — streams included
```

The wrapper reads the requested and served model, the provider's finish/stop code, the tools
offered and the tools the model invoked, and scans the prompt and output text locally; only counts
leave. It sends those facts as they are — Avowa evaluates them on its side — and each signal names
the fields the wrapper read, so they grade as observed rather than as your app's word. `capture()` and `track()` remain for anything else,
graded as self-reported.
