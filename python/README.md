# Avowa Runtime SDK (Python)

Emit **live AI-inference signals** to Avowa so your AI-trust claims are backed by
runtime evidence — which model ran, in which region, whether customer data is used
for training, and guardrail outcomes. This is the evidence posture tools (Vanta/Drata)
can't capture: *how your AI actually behaves in production.*

- **Stdlib-only** — no dependencies added to your app.
- **Non-blocking** — a background worker sends signals; ~0ms added to inference.

## Install

**Two lines, in the environment your app runs in.** Your code and your start command stay as they
are. (The setup token comes from Connections → Runtime SDK → *Generate setup token*.)

```bash
pip install avowa-runtime        # standard library only, nothing else is installed
avowa init <setup-token>         # writes avowa.env with one value: AVOWA_TOKEN
```

Then start your app the way you always do and send one real request that calls the model.

- `avowa init --dry-run` shows what init would do and changes nothing.
- `avowa status` shows what is covered and asks the server whether it knows this key. It sends no signal.
- **In production** put one variable in your secret store: `AVOWA_TOKEN` (the value in `avowa.env`). Nothing else changes: not the Dockerfile `CMD`, not the code.
- `AVOWA_DISABLE=1` switches everything off.

How it works: the package installs a small start-up hook (`avowa_auto.pth`). The hook does nothing
unless the process has opted in, which means `AVOWA_TOKEN` is set, or an `avowa.env` is in the
directory the process starts from, or `AVOWA_AUTO=1`. Installing the package alone never switches
anything on, and `pip uninstall avowa-runtime` removes the hook.

No route to PyPI? Mirror `avowa-runtime` through your own index like any other dependency: it is
pure Python with no dependencies of its own. From a checkout of this repository it is
`pip install ./python`.

## Configure
`avowa init` does this for you. By hand, it is one variable (or the same line in `avowa.env`):

```bash
export AVOWA_TOKEN="avw1_..."        # the connection's key, signing secret and API URL in one value
export AVOWA_REGION="us-east-1"      # optional
```

The three separate variables the token replaces still work, and one that is set wins over the
token: `AVOWA_RUNTIME_KEY`, `AVOWA_RUNTIME_SECRET`, `AVOWA_BASE_URL`. With those instead of a
token, set `AVOWA_AUTO=1` to switch the start-up hook on.

> **Tamper-evident and single-use (0.9+):** every request is HMAC-SHA256-signed over
> `"<unix-timestamp>.<nonce>.<body>"` (headers `X-Avowa-Timestamp` / `X-Avowa-Nonce` /
> `X-Avowa-Signature`). The server rejects bad signatures, requests outside a 5-minute window,
> and any nonce it has already seen — so a signal can't be forged, altered or replayed.
> **HTTPS only:** the SDK refuses a plain `http://` base URL unless it is localhost or a private
> network (override with `AVOWA_ALLOW_HTTP=1`), and sends nothing when no URL is set.
> **Off switch:** `AVOWA_DISABLE=1` — nothing is patched and nothing is sent, in every mode.
> Keep the secret server-side — never ship it to a browser.

## Usage

```python
from avowa_runtime import AvowaRuntime
avowa = AvowaRuntime(region="us-east-1")   # reads AVOWA_RUNTIME_KEY / AVOWA_BASE_URL

# A) Wrap one client explicitly. Everything it records is OBSERVED (model, endpoint, latency,
#    errors) and it runs the local injection/PII scans for you. Pass scan=False to disable them.
import anthropic, openai
client = avowa.instrument_anthropic(anthropic.Anthropic(), region="us-east-1")
client.messages.create(model="claude-opus-4-8", max_tokens=512, messages=[...])

client = avowa.instrument_openai(openai.OpenAI(), region="us-east-1")
client.chat.completions.create(model="gpt-4o", messages=[...])

# ...but prefer zero-code auto-instrumentation (next section) — it covers clients you can't
# reach by hand, which is where coverage is actually lost.

# B) Wrap a block (times it + records the model/region):
with avowa.track(model="claude-opus-4-8", region="us-east-1"):
    resp = client.messages.create(...)

# C) Record explicitly (e.g. after a guardrail check):
avowa.capture(model="claude-opus-4-8", region="us-east-1",
              train_on_data=False, guardrail_blocked=blocked, latency_ms=842)
```

Each signal feeds the **runtime_sdk** connector. Run a capture/sync (or the Change Feed)
in Avowa and the signals become evidence. You only ever claim what you instrument — a field
you don't pass is not sent, so it proves nothing.

## Zero-code auto-instrumentation (recommended)

`instrument_openai(client)` asks you to find *where the client is constructed*. In a real
codebase that's the hard part — it may be a factory, five call sites, or inside LangChain /
LlamaIndex / CrewAI where you can't edit it at all. Anything you miss shows up as **low traffic**
rather than a missed integration, because Avowa publishes instrumentation coverage as a
denominator. Auto-instrumentation patches the client **classes**, so every instance is covered
no matter who builds it.

**Credentials first, and there is nothing to type.** `avowa init` writes `avowa.env` into the
directory you start your app from. The SDK reads **only
`AVOWA_*` keys** out of it and a real environment variable **always wins**, so Kubernetes Secrets
or Secrets Manager injection keeps working unchanged. (`AVOWA_ENV_FILE` points at a specific file;
`AVOWA_NO_ENV_FILE=1` switches it off.) Setting them by hand on macOS/Linux is `export VAR=value` —
plain `set VAR=value` is Windows CMD syntax and silently does nothing in bash/zsh.

```bash
# 1. Nothing. With a token in place the start-up hook covers the app as it starts:
uvicorn app:main --host 0.0.0.0
gunicorn -w 4 app:main

# 2. One process only, without the hook: prefix its command.
avowa run uvicorn app:main --host 0.0.0.0      # `avowa-run <command>` is the same, older name

# 3. See what it patched.
python -m avowa_runtime.auto
```

```python
# 4. Or one import at your entry point (main.py, Django settings, Lambda handler):
import avowa_runtime.auto
```

All of them read config from the environment only: `AVOWA_TOKEN`, `AVOWA_REGION`, and
`AVOWA_SCAN=0` to disable the local scan. Import order
doesn't matter — an import hook patches provider SDKs whenever they load. Gunicorn/uvicorn
workers inherit the environment, so workers are instrumented and Avowa sums their signals.

The start-up hook does nothing at all without a token (or `AVOWA_AUTO=1`), so installing the SDK
can never silently start instrumenting something. `AVOWA_AUTO=0` keeps it off even with a token.

### Nothing showing up?

```bash
python -m avowa_runtime.auto --check       # credentials + reachability. Sends NO signal:
                                           # a synthetic event would show on your trust
                                           # profile as inference that never happened.
AVOWA_DEBUG=1 <your usual start command>   # trace patch → capture → send, metadata only
```

```
[avowa:debug] patched openai.OpenAI
[avowa:debug] captured gpt-4o-2026-05-13 via api.openai.com (32ms)
[avowa:debug] sent gpt-4o-2026-05-13 via api.openai.com (32ms) → HTTP 200
```

In order of likelihood: **no inference has run yet** (starting the app proves nothing — send a
request that calls the model); **the app doesn't use the `anthropic`/`openai` Python SDKs** (raw
`requests`/`httpx`, or a provider with no wrapper — use `capture()`); or **delivery is failing**.
The first failed send prints one line naming the cause — a wrong key, a wrong base URL, a blocked
host — and then stays quiet. Silence on that line means signals are being delivered.

`AVOWA_DEBUG` output is metadata-only, like the wire format. It never prints prompts or responses;
there's a test asserting that, because debug output is what people paste into tickets.

### What the SDK reads off each call

Controls that would otherwise be self-reported are visible in the call itself. The SDK reads the
facts and sends them as they are; Avowa evaluates them on its side and grades the result as
**observed (L3)** rather than asserted (L2). The SDK draws no conclusions of its own.

| Fact sent | Read from | Evidence it feeds |
|---|---|---|
| `requested_model` + `model` | the model id on the request, and the one in the response | AI supply-chain integrity |
| `stop_reason` | the provider's own stop / finish code | Guardrails / content filtering |
| `structured_output` | the call used `parse()` or supplied a schema | Output handling |
| `token_ceiling`, `error` | the request's output-token limit; the exception type on a failed call | Rate & cost limits |
| token usage (`input_tokens`, `output_tokens`, cache reads and writes) | the provider's own usage report on the response | Rate & cost limits · volume |
| `system_prompt_present`, `tool_choice`, `response_format_type`, `streaming` | the request's settings — whether a system prompt was set, never what it says | System-prompt protection · agency · output handling |
| `messages_user` / `_assistant` / `_tool`, `input_images` / `_files` / `_audio`, `prompt_chars`, `output_chars` | counts and sizes only | Autonomy · data types processed |
| `client_max_retries`, `client_timeout_s` | how your client is configured | AI-path resilience |
| `pii_families`, `injection_families` | which named pattern families the local scan matched (never the text) | Sensitive-data leakage · prompt injection |
| `temperature`, `top_p`, `seed`, `choices_n`, `stop_sequences` (a count), `reasoning_effort`, `thinking_enabled` | the request's sampling and reasoning settings | Reproducibility · output handling |
| `store_requested`, `service_tier_requested` / `service_tier` | whether the app asked the provider to store the output; the tier requested and served | Data retention · no-training |
| `end_user_id_present`, `metadata_present` | **whether** an end-user id or metadata travelled with the call — never the id | Accountability · per-user attribution |
| `provider_filtered`, `provider_filter_categories`, `provider_block_reason`, `guardrail_configured`, `safety_settings` (a count) | the provider's **own** safety verdict (Azure content filters, Gemini block reasons, a Bedrock guardrail) — category names only | Guardrails / content filtering |
| `system_fingerprint` | the provider's backend configuration id | AI supply-chain integrity · model change |
| `http_status`, `provider_error_code`, `retry_after_s` | a failed call's status and the provider's error **code** — never the error message, which can echo the request | Rate & cost limits · AI-path resilience |
| `ttft_ms` | time to the first streamed chunk | Availability · performance |
| `provider_lib` / `provider_lib_version`, `python_version`, `app_frameworks` | which provider library, Python and agent frameworks the app runs | AI bill of materials |
| `app_region` + `app_region_source` | the region code from your platform's own variable (`AWS_REGION`, `FLY_REGION` …) | Where processing happens — cross-border transfers |

### New metadata without a redeploy

Providers add metadata fields over time (a new safety verdict, a new service tier). Rather than ask
you to upgrade for each one, Avowa can ask the SDK to read a further **metadata** field by name. The
list arrives on the response to a signal the SDK already sends, authenticated with your connection's
secret, and only when your copy is out of date.

- **Data, never code.** An entry is a name, a provider and an attribute path. The SDK reads that path
  and nothing else; no code is downloaded or run.
- **The guard is in the SDK, not in the list.** A path through any content-bearing name (`content`,
  `text`, `messages`, `input`, `output`, `arguments`, `system` …) or a private attribute is refused,
  and only a number, true/false or a short code (letters, digits, `_.:-`, at most 40 characters) can
  come back. No list Avowa sends can widen what leaves your process.
- **See it, or switch it off.** `python -m avowa_runtime.auto` prints the active list.
  `AVOWA_REMOTE_FIELDS=off` turns it off; only the built-in metadata above is then read.

**If your app gives the model tools, the agentic evidence comes free too.** Nobody else can produce
this, because it isn't in a log or a config file — it only exists in the call:

| Flag | How it is derived | Claim it proves |
|---|---|---|
| `tools_offered` | the tool definitions supplied on this call — the grant, as it really was | Agent tool inventory |
| `tools_invoked` | the tool-use blocks the model actually returned (parallel calls included) | Agent tool inventory · tool-permission scoping |
| `autonomy_depth` | prior assistant turns that requested tools — steps taken before returning to a human | Autonomy bounds |

**Tool names only.** Schemas, descriptions and arguments are read for the name and dropped
in-process: they carry business logic and sometimes examples containing real data, so they are
treated exactly like prompt text.

Unused grants are the point. A tool handed to the model on every call and never invoked is standing
authority nobody is watching — OWASP LLM06 — and Avowa reports it as a finding. Scoping is only
*proven* when every granted tool is exercised; an unused one is never called proof of over-scoping
either, because a short window can't tell a rarely-used tool from an unnecessary one.

Nothing here defaults to `True`, and a flag is **omitted entirely** when the call does not answer
the question — a field the SDK cannot see is never filled in on your behalf. `autonomy_depth` is
reported as unknown rather than `0` when the message history isn't a shape it recognises, because
`0` would read as "fully attended".

Everything else (`human_reviewed`, `decision_logged`, `ai_disclosed`, `grounded`,
`rationale_present`, `fairness_checked`, `uncertainty_flagged`, `rate_limited`,
`system_prompt_protected`, `eval_score`) is genuinely invisible from the call, so it stays an
explicit `capture(...)` argument and is graded self-reported. **Pass only what your app actually
enforces** — asserting a control you don't have is the thing Avowa exists to catch.

Where a signal is built from ONE field, calls the SDK observed are graded on their own and the
app-reported ones are named and excluded — an assertion can neither inflate an observation nor
suppress it. Where a signal blends several fields (guardrails combines your guardrail names and PII
counts with the block outcome) it stays as strong as its weakest field, so every call must be
observed for it to be graded observed.

**Since 0.13, each tool call is tracked by reference, and approvals join the right call.**

| Field | How it is derived |
|---|---|
| `tool_calls` | each call the model proposed, as `<ref>:<tool>`. `ref` is 20 hex characters of a hash of the provider's id (`toolu_…`, `call_…`); the id itself never leaves your process. It is a correlation label, not anonymisation: anyone with the id can compute it |
| `tool_results` | each result your app handed back to the model on the next call, as `<ref>:returned` or `<ref>:error` (`error` only where your app flagged it, such as Anthropic `is_error`) |
| `mcp_servers_offered`, `mcp_hosts`, `mcp_tools_invoked` | hosted MCP servers handed to the provider (labels and hostnames only) and the MCP tools it ran there |

A human approval, or how a tool call ended, happens after the model call that proposed it, so you
record it on its own. Pass the provider's id; only its hash is sent:

```python
import avowa_runtime

for block in resp.content:
    if block.type == "tool_use" and needs_sign_off(block):
        ok = ask_a_human(block)
        avowa_runtime.approval(block.id, approved=ok, approver_role="finance_ops", approver_type="human")
        ...
        avowa_runtime.tool_outcome(block.id, "ok")      # or "error", "denied", "timeout"
```

`approver_type` says who decided: `"human"`, `"policy"` (pass `policy_ref="refunds-under-100"`),
`"system"`, or `"unknown"` (the default). Only `"human"` counts as human approval; a policy or system
authorisation is counted separately. `approver_role` is a short label, never a person's name. The
human-approval claim is then counted per consequential call, from what your app reported. Avowa does
not see the decision and does not claim it came before the tool ran.

Which agent ran, and for which of **your** customers:

```python
with avowa_runtime.agent_context("triage", customer=account.id):
    run_agent(...)
```

The name is sent as written; the customer id is sent only as a keyed hash. Set `AVOWA_REF_KEY` to a
secret of your own (it is read only inside your process and never sent) and nobody, Avowa included,
can test a guessed customer id against it. Rotating that key starts a new correlation period: the
same customer gets a new reference from then on. Avowa never holds a mapping back to your customers.
A run whose calls carry two different customers is shown to you as a finding.

`action_class` (read / write / external / financial) is **not** derived. The SDK sees a tool's name,
not its consequence, and guessing would put a judgement in your mouth — pass it explicitly if you
want human-approval coverage measured over consequential actions only.

### Which providers auto-instrument

| Provider | Classes patched | Notes |
|---|---|---|
| Anthropic | `Anthropic`, `AsyncAnthropic` | covers `messages.create` and `messages.parse` |
| Claude on Bedrock / Vertex | `AnthropicBedrock`, `AnthropicVertex` | covered when you use the `anthropic` SDK's own clients |
| OpenAI | `OpenAI`, `AsyncOpenAI` | covers `chat.completions.create` / `.parse` (incl. the `beta` namespace) and `responses.create` / `.parse` |
| Azure OpenAI | `AzureOpenAI`, `AsyncAzureOpenAI` | the Azure host is recorded, which is what evidences the inference region instead of assuming it |
| Any OpenAI-compatible endpoint (Together, Groq, Fireworks, vLLM, OpenRouter, local) | via the `openai` classes | the real host is recorded, not `api.openai.com` |
| Amazon Bedrock (boto3 `bedrock-runtime`) | `from avowa_runtime.adapters import instrument_bedrock` → `instrument_bedrock(avowa, client)` | `converse` and `invoke_model`; the Bedrock endpoint host and region, `stopReason` (a `guardrail_intervened` stop is the guardrail firing, observed), tool grants from `toolConfig` |
| Google Gemini (`google-genai`) | `instrument_gemini(avowa, client)` | `models.generate_content` (sync and `aio`); served `model_version`, `finish_reason` (SAFETY / PROHIBITED_CONTENT = blocked), Vertex vs AI Studio host |
| LangChain / LangGraph | `from avowa_runtime.langchain import AvowaCallbackHandler` → `callbacks=[AvowaCallbackHandler()]` | one signal per model call from the framework's own events, tool names from `on_tool_start`. Do not combine with a wrapped client — the call would count twice |
| `mistralai`, `cohere` | — | no wrapper yet: `avowa.track(...)` / `avowa.capture(...)`, graded as self-reported |

**Async clients are fully supported** — the signal is recorded after the `await`, not when the
coroutine is created, so `latency_ms` is the real call duration and a failure is recorded as a
failure.

**Streaming is captured when the stream ends.** With `stream=True` the wrapper returns a proxy
over the provider's iterator (sync or async, context manager included) that watches the chunks go
by — the served model, the stop/finish reason, the output text for the local scan — and records
once, with latency measured to the last chunk, when the stream is exhausted or closed. Nothing is
recorded before that, because nothing is known before that. Anthropic's `messages.stream()` helper
is not wrapped yet; call `capture(...)` after it closes.

**Check the install without sending anything:** `python -m avowa_runtime.auto --doctor` asks the
server who this key is — connection, environment, whether the plan allows capture, whether your
secret signs correctly, your clock skew, and when it last heard from you.

Nothing about your provider changes how evidence is graded. What matters is observed vs
asserted, below — a manual `capture()` with observed fields outranks a wrapped call carrying
only self-reported booleans.

## Observed vs asserted — how Avowa grades what you send

Not every field is worth the same, and Avowa will not pretend otherwise.

| | What it is | Grade |
|---|---|---|
| **Observed** | The SDK worked it out itself — the model the API returned, the host it dialled, latency, errors, and the counts its own local detectors produced. | **L3 · live-verified** |
| **Asserted** | A boolean your application passed about itself (`output_validated=True`). The HMAC proves the transport wasn't tampered with; it proves nothing about whether the claim is true. | **L2 · runtime-asserted** |

An assertion is still worth more than a questionnaire answer — it's continuous, timestamped and
signed — but it is a self-report, and a buyer is told so. **Prefer the observed fields.** They cost
you nothing extra and they're the only ones that read as independently verified.

Avowa also reports **instrumentation coverage**: if a flag rides on 5 of your 1,000 calls, the
evidence says `5/1000 (0.5% of traffic)`, not `5/5`.

**Core**

| Field | Proves | Graded |
|---|---|---|
| `model` | `ai_components.models` | observed |
| `endpoint` | `subprocessors` (observed egress) + `data.data_residency_jurisdiction` where the host encodes a region | observed |
| `scan_prompt` → `injection_suspected` | `ai_security.prompt_injection` | observed |
| `scan_output` → `pii_detected` | `ai_security.sensitive_disclosure` | observed |
| `error` / `retries` / `fallback_model` | `resilience.ai_path` | observed |
| `region` | `data.data_residency_jurisdiction` | observed if derivable from `endpoint`, else asserted |
| `train_on_data=false` | `training_posture.trains_model_weights_on_customer_data` | asserted |
| `guardrail_blocked` / `guardrail` / `blocked_category` | `responsible_ai.model_monitoring` + `guardrails` (+ live red-teaming) | asserted |

### Local detection, metadata egress

`scan_prompt` and `scan_output` are matched **inside your process** and dropped. Avowa receives an
integer count and nothing else — never the text. That is what lets a leak or an attack be evidenced
without Avowa ever processing your prompts.

A detection is evidence an attack *arrived*, not that it was *stopped*: injection patterns your app
doesn't report blocking, or PII still present in egress after your redaction ran, are reported as
**unresolved exposure** rather than a passing control.

**Responsible AI** (pass the flags your app enforces)

| Field | Proves |
|---|---|
| `decision_logged` | `responsible_ai.decision_audit` + `prompt_output_logging` |
| `human_reviewed` | `ai_components.human_oversight` |
| `rationale_present` | `responsible_ai.decision_logic` (explainability) |
| `ai_disclosed` | `responsible_ai.ai_disclosure` |
| `uncertainty_flagged` | `responsible_ai.uncertainty_handling` |
| `fairness_checked` | `responsible_ai.bias_detection` |

**AI security — OWASP LLM Top 10 + agentic** (the moat: proven live from the call path, which no posture tool or static pentest can show)

| Field | Proves | OWASP |
|---|---|---|
| `injection_blocked` | `ai_security.prompt_injection` | LLM01 |
| `pii_redacted` | `ai_security.sensitive_disclosure` | LLM02 |
| `model_pinned` | `ai_security.model_supply_chain` | LLM03 |
| `output_validated` | `ai_security.output_handling` | LLM05 |
| `tool_authorized` | `ai_security.excessive_agency` (agent tool-scoping) | LLM06 |
| `action_authorized` | `ai_security.action_authorization` (high-impact action gating) | agentic |
| `system_prompt_protected` | `ai_security.system_prompt_protection` | LLM07 |
| `grounded` | `ai_security.groundedness` (hallucination resistance) | LLM09 |
| `rate_limited` | `ai_security.rate_limiting` (abuse / DoS) | LLM10 |
| `eval_score` (number) | `ai_governance.model_evaluation` | — |

```python
# prove AI-security controls live — pass what your inference path enforces on each call:
avowa.capture(model="claude-opus-4-8", region="us-east-1", train_on_data=False,
              injection_blocked=False, pii_redacted=True, output_validated=True,
              system_prompt_protected=True, grounded=True, tool_authorized=True,
              action_authorized=True, model_pinned=True, rate_limited=False, eval_score=0.94)
```

## Notes
- Sends are best-effort and never raise into your request path.
- `avowa.flush()` is registered at process exit; call it manually before a short-lived job ends.
- Only metadata is sent — never prompts, outputs, or customer data.
