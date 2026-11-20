# Avowa Runtime SDK (Python)

Keeps an independent record of what your AI does in production: which model answered, where it ran,
which tools your agents called, and who approved them. Avowa grades that record and you share it with
buyers instead of answering their security questionnaire from memory.

It runs inside your process and reads **metadata only**. It never sends prompts, completions, tool
arguments or tool output, never changes a request or response, and never blocks or slows a call. If
Avowa is unreachable your app carries on. `AVOWA_DISABLE=1` turns it off. Apache-2.0, no runtime
dependencies.

**Documentation: [avowa.ai/docs](https://avowa.ai/docs/)**

## Install

In the environment your app runs in. Generate the setup token in the Avowa console under
**Connections, Runtime SDK**; it works once.

```bash
pip install avowa-runtime
avowa init <setup-token>
```

`init` writes `avowa.env` (one line, `AVOWA_TOKEN`), adds it to `.gitignore`, installs the start-up
hook and checks that the server knows the key. `avowa init --dry-run` shows what it would do first.

Start your app the way you always do and send one request that calls the model. Then:

```bash
avowa status
```

It lists what is covered and asks the server whether it has heard from this key. It sends no signal.

**In production** set `AVOWA_TOKEN` from your secret store. Nothing else changes. In Docker, install the
package in the image and pass `AVOWA_TOKEN` at run time; never run `init` in a Dockerfile.

## What is covered

| Library | Coverage |
|---|---|
| `openai` | `OpenAI`, `AsyncOpenAI`, `AzureOpenAI`, `AsyncAzureOpenAI`, any OpenAI-compatible host. Chat Completions and Responses, streams included. |
| `anthropic` | `Anthropic`, `AsyncAnthropic`, `AnthropicBedrock`, `AnthropicVertex`. Streams included. |
| `boto3` (Bedrock) | One line: `instrument_bedrock(avowa, client)` |
| `google-genai` | One line: `instrument_gemini(avowa, client)` |
| LangChain, LangGraph | Clients built inside the framework are covered; a callback handler covers the rest. |
| anything else | Record the call with `capture()`, below. |

Clients built in your own factory or in a dependency are covered too, and gunicorn and uvicorn workers
inherit the hook.

## Agents: runs, approvals, outcomes

The SDK already records each tool call the model proposed and each result your app handed back, by a
hash of the provider's call id, with the step depth and a run key. Three calls add what it cannot see:

```python
import avowa_runtime

# 1. Name the run and the customer it is for (the customer id is sent only as a keyed hash).
with avowa_runtime.agent_context(name="incident-agent", customer=account.id):
    run_agent(alert)

# 2. Where a person or a rule approves a tool call, record it against the provider's call id.
avowa_runtime.approval(call_id, approved, approver_type="human", approver_role="on-call SRE")
avowa_runtime.approval(call_id, True, approver_type="policy", policy_ref="read-only-tools")

# 3. After each tool call runs: "ok", "error", "denied" or "timeout".
avowa_runtime.tool_outcome(call_id, "ok")
```

`approver_type` is `human`, `policy`, `system` or `unknown` (the default); only `human` counts as human
approval. The role is a label, never a person's name. Findings name the run, step and a call reference;
`avowa ref --find <ref> <logfile>` finds that call in your own logs, on your machine.

Guide: [avowa.ai/docs/agents.html](https://avowa.ai/docs/agents.html). Classify what each tool does once,
in the console: [avowa.ai/docs/tools.html](https://avowa.ai/docs/tools.html).

## Recording what your app enforces

Facts only your app knows, such as a training opt-out or a guardrail decision:

```python
avowa = avowa_runtime.AvowaRuntime()          # reads AVOWA_TOKEN
avowa.capture(model="mistral-large-latest", train_on_data=False)
```

These are signed in transit and graded as your application's word, never as observed. What the SDK
reads off the call itself is graded as observed. Buyers see which is which.

## What leaves your process

Model requested and served, endpoint hostname, latency, errors, token counts, tool names, hashed tool
call references, and counts (never matches) from a local scan for personal data, secrets and prompt
injection. Every field, by name: [avowa.ai/docs/data.html](https://avowa.ai/docs/data.html).

Each upload goes over HTTPS only, signed with HMAC-SHA256 and a single-use nonce, from a background
queue. Security review: [avowa.ai/docs/security.html](https://avowa.ai/docs/security.html).

## Commands and settings

`avowa init`, `status`, `doctor`, `run`, `ref`. Every command and environment variable:
[avowa.ai/docs/reference.html](https://avowa.ai/docs/reference.html). Troubleshooting:
[avowa.ai/docs/troubleshooting.html](https://avowa.ai/docs/troubleshooting.html). Changes:
[avowa.ai/docs/changelog.html](https://avowa.ai/docs/changelog.html).

## Remove it

`AVOWA_DISABLE=1` switches everything off. `pip uninstall avowa-runtime` removes the package and its
hook; delete `avowa.env`.

Support: support@avowa.ai. Licence: Apache-2.0.
