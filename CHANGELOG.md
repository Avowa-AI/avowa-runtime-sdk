# Changelog

Python (`avowa-runtime`) and Node (`@avowa/runtime`) share version numbers.
Also at https://avowa.ai/docs/changelog.html

## 0.13.2 (unreleased)

- Python: a short-lived process that exits with signals still queued now says how many were not sent, on stderr. `AVOWA_FLUSH_TIMEOUT` sets how long it waits (default 5 seconds).
- The upgrade notice names the package manager command (`pip install -U avowa-runtime`, `npm install @avowa/runtime@latest`).

## 0.13.1 (2026-11-20)

- Agents on the OpenAI Responses API, including chained responses and the OpenAI Agents SDK, are now grouped into runs and their steps counted correctly.
- Streamed and raw responses keep their tool calls and token usage.
- More accurate model reporting for refused calls and for streams that never name their model.
- New: `avowa ref` and `avowa ref --find` turn a reference in a finding back into the tool call in your own logs.

## 0.13.0 (2026-11-19)

- Agents: `agent_context` names the agent and the customer a run is for (the customer id is sent only as a keyed hash).
- `approval()` and `tool_outcome()` record who approved a tool call and how it ended, against the provider's tool call id.
- Each tool the model called and each result handed back is recorded by a hash of the call id, with the run key and the step depth.

## 0.12.0 (2026-11-17)

- One value, `AVOWA_TOKEN`, replaces the key, secret and address.
- `avowa init` connects a project in one command. The Python start-up hook ships in the package, so the start command stays as it is.
- Node: the `@avowa/runtime/register` preload covers `openai` and `@anthropic-ai/sdk` with no code change.

## 0.11.0 (2026-10-27)

- First open-source release under Apache-2.0: npm `@avowa/runtime`, then PyPI `avowa-runtime`.
