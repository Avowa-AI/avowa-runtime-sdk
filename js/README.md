# @avowa/runtime

The Node.js half of the [Avowa Runtime SDK](https://github.com/Avowa-AI/avowa-runtime-sdk). Keeps an
independent record of what your AI does in production: which model answered, where it ran, which tools
your agents called, and who approved them.

It reads **metadata only**. It never sends prompts, completions, tool arguments or tool output, never
changes a request or response, and never blocks a call. If Avowa is unreachable your app carries on.
`AVOWA_DISABLE=1` turns it off. Node 18.18+ or 20.6+, server-side only. Apache-2.0, no dependencies.

**Documentation: [avowa.ai/docs](https://avowa.ai/docs/)**

## Install

In your project folder. Generate the setup token in the Avowa console under **Connections, Runtime
SDK**; it works once.

```bash
npm install @avowa/runtime
npx @avowa/runtime init <setup-token>
```

`init` writes `avowa.env` (one line, `AVOWA_TOKEN`), adds it to `.gitignore`, and offers to add the
preload to your `start` script, showing the change first (`init --dry-run` changes nothing):

```
from: node server.js
to:   node --import @avowa/runtime/register server.js
```

Start your app the way you always do and send one request that calls the model. Then
`npx @avowa/runtime status` shows what is covered and whether the server knows this key. It sends no
signal.

**In production** set two variables and change nothing else:

```bash
AVOWA_TOKEN=<the value in avowa.env>
NODE_OPTIONS=--import @avowa/runtime/register
```

## What the preload covers

| Library | Coverage |
|---|---|
| `openai` (OpenAI, Azure OpenAI, any OpenAI-compatible host) | `chat.completions.create`, `responses.create`, streams included |
| `@anthropic-ai/sdk` | `messages.create`, streams included |
| Bedrock, Gemini, Vercel AI SDK, raw `fetch` | not yet: use `capture()` or `track()` |

ES modules and CommonJS both work. The wrappers hand back the provider's own promise and stream objects,
so `.withResponse()`, `.tee()` and `instanceof` behave as without Avowa.

**Bundled server code.** A bundler (Next.js, esbuild, webpack) that compiles the provider SDK into its
own output carries a private copy the preload never meets. Keep the provider SDK external to the bundle
(Next.js: `serverExternalPackages`), or wrap the client once:

```js
import OpenAI from 'openai'
import { createAvowa } from '@avowa/runtime'

const avowa = createAvowa()                            // reads AVOWA_TOKEN
const openai = avowa.instrumentOpenAI(new OpenAI())
// const anthropic = avowa.instrumentAnthropic(new Anthropic())
```

## Agents: runs, approvals, outcomes

The wrappers record each tool call the model proposed and each result your app handed back, by a hash
of the provider's call id, with the step depth and a run key. Three calls add what they cannot see:

```js
import { agentContext, approval, toolOutcome } from '@avowa/runtime'

await agentContext({ name: 'incident-agent', customer: account.id }, async () => {
  const resp = await client.messages.create({ ... })
  for (const b of resp.content) {
    if (b.type === 'tool_use') {
      const ok = await askOnCall(b)                                    // your approval step
      approval(b.id, ok, 'on-call SRE', { approverType: 'human' })    // a role, never a name
      // a rule instead: approval(b.id, true, null, { approverType: 'policy', policyRef: 'read-only-tools' })
      toolOutcome(b.id, ok ? 'ok' : 'denied')                         // or 'error', 'timeout'
    }
  }
})
```

`approverType` is `'human'`, `'policy'`, `'system'` or `'unknown'` (the default); only `'human'` counts
as human approval. The customer id is sent only as a keyed hash. Findings name the run, step and a call
reference; `npx @avowa/runtime ref --find <ref> <logfile>` finds that call in your own logs.

Guide: [avowa.ai/docs/agents.html](https://avowa.ai/docs/agents.html).

## Recording what your app enforces

```js
avowa.capture({ model: 'claude-opus-4-8', train_on_data: false })

// or wrap a call: times it and records whether it was blocked
const resp = await avowa.track({ model: 'claude-opus-4-8' }, () => client.messages.create(...))
```

These are signed in transit and graded as your application's word, never as observed. `track()`
re-throws whatever your function threw. Uploads time out after 5 seconds and at most 64 are in flight;
past that they are dropped, with one warning.

## More

- What leaves your process, field by field: [avowa.ai/docs/data.html](https://avowa.ai/docs/data.html)
- Security review: [avowa.ai/docs/security.html](https://avowa.ai/docs/security.html)
- Commands and environment variables: [avowa.ai/docs/reference.html](https://avowa.ai/docs/reference.html)
- Troubleshooting: [avowa.ai/docs/troubleshooting.html](https://avowa.ai/docs/troubleshooting.html)
- Changelog: [avowa.ai/docs/changelog.html](https://avowa.ai/docs/changelog.html)

Support: support@avowa.ai. Licence: Apache-2.0.
