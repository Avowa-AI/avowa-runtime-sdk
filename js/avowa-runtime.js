// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avowa, Inc.
import { createHash, createHmac } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
const env = typeof process !== 'undefined' && process.env || {};
const VERSION = '0.13.2';
const SCHEMA = 'avowa.signal/1';
export const SDK_VERSION = VERSION;
let _subtle = null;
async function subtle() {
  if (_subtle) return _subtle;
  if (globalThis.crypto && globalThis.crypto.subtle) return _subtle = globalThis.crypto.subtle;
  const m = await import('node:crypto');
  return _subtle = m.webcrypto.subtle;
}
async function hmacHex(secret, msg) {
  const enc = new TextEncoder();
  const st = await subtle();
  const k = await st.importKey('raw', enc.encode(secret), {
    name: 'HMAC',
    hash: 'SHA-256'
  }, false, ['sign']);
  const sig = await st.sign('HMAC', k, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
const RF_DENY = new Set(['content', 'contents', 'text', 'texts', 'message', 'messages', 'input', 'inputs', 'output', 'outputs', 'output_text', 'prompt', 'prompts', 'system', 'instructions', 'arguments', 'args', 'delta', 'parts', 'part', 'body', 'data', 'completion', 'completions', 'document', 'documents', 'query', 'queries', 'value', 'values', 'raw', 'html', 'markdown', 'transcript', 'summary', 'reasoning_content', 'thinking']);
const RF_NAME = /^[a-z][a-z0-9_]{1,40}$/;
const RF_SEG = /^(?:[A-Za-z_][A-Za-z0-9_]{0,40}|\d{1,2})$/;
const RF_PROVIDERS = ['*', 'openai', 'anthropic', 'bedrock', 'gemini'];
const REMOTE = {
  v: null,
  fields: []
};
const remoteOn = () => !['off', '0', 'false', 'no'].includes(String(env.AVOWA_REMOTE_FIELDS || 'on').trim().toLowerCase());
export function rfOk(f) {
  if (!f || typeof f !== 'object') return false;
  const {
    name,
    provider,
    path
  } = f;
  if (!(typeof name === 'string' && RF_NAME.test(name) && RF_PROVIDERS.includes(provider) && ['request', 'response', 'error'].includes(f.from) && typeof path === 'string')) return false;
  const segs = path.split('.');
  return segs.length >= 1 && segs.length <= 6 && segs.every(x => RF_SEG.test(x) && !x.startsWith('_') && !RF_DENY.has(x.toLowerCase()));
}
function rfValue(v) {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  return typeof v === 'string' && v && /^[A-Za-z0-9_.:-]{1,40}$/.test(v.slice(0, 40)) ? v.slice(0, 40) : null;
}
function rfGet(obj, path) {
  for (const k of path.split('.')) {
    if (obj == null) return null;
    try {
      obj = Array.isArray(obj) && /^\d+$/.test(k) ? obj[Number(k)] : obj[k];
    } catch {
      return null;
    }
  }
  return obj;
}
async function acceptFields(block, secret) {
  try {
    if (!block || typeof block.doc !== 'string' || typeof block.mac !== 'string' || !secret) return;
    if ((await hmacHex(secret, 'avowa-fields.' + block.doc)) !== block.mac) {
      warnOnce('rf-mac', 'ignored a metadata-field list that did not verify under this connection\'s secret.');
      return;
    }
    const d = JSON.parse(block.doc);
    REMOTE.v = String(d.v || '').slice(0, 32) || null;
    REMOTE.fields = (Array.isArray(d.fields) ? d.fields : []).slice(0, 20).filter(rfOk);
  } catch (e) {
    internalError('remote_fields', e);
  }
}
export const _resetRemoteFields = () => {
  REMOTE.v = null;
  REMOTE.fields = [];
};
export const remoteFields = () => remoteOn() ? REMOTE.fields.map(f => ({
  ...f
})) : [];
function remoteFacts(kind, resp, params, errObj) {
  const out = {};
  if (!REMOTE.fields.length || !remoteOn()) return out;
  const src = {
    request: params,
    response: resp,
    error: errObj
  };
  for (const f of REMOTE.fields) {
    if ((f.provider === '*' || f.provider === kind) && src[f.from] != null) {
      const v = rfValue(rfGet(src[f.from], f.path));
      if (v != null) out['rf_' + f.name] = v;
    }
  }
  return out;
}
const _warned = new Set();
function warnOnce(kind, msg) {
  if (_warned.has(kind)) return;
  _warned.add(kind);
  try {
    console.error(`[avowa] ${msg}`);
  } catch {}
}
export const INTERNAL_ERRORS = {};
function internalError(where, e) {
  const key = `${where}:${e && e.name || 'Error'}`;
  INTERNAL_ERRORS[key] = (INTERNAL_ERRORS[key] || 0) + 1;
  if (['1', 'true', 'yes', 'on'].includes(String(typeof process !== 'undefined' && process.env && process.env.AVOWA_STRICT || '').trim().toLowerCase())) throw e;
  warnOnce('internal:' + key, `internal error in ${where} (${key.split(':')[1]}) — this signal was skipped; your app is unaffected`);
}
const CARD_RX = /\b(?:\d[ -]*?){13,16}\b/;
function luhnOk(digits) {
  let total = 0,
    alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
    alt = !alt;
  }
  return total % 10 === 0;
}
function looksLikeCard(text) {
  const rx = new RegExp(CARD_RX.source, 'g');
  let m;
  while ((m = rx.exec(text)) !== null) {
    const digits = m[0].replace(/[^0-9]/g, '');
    if (digits.length >= 13 && digits.length <= 16 && luhnOk(digits)) return true;
  }
  return false;
}
const PII_PATTERNS = [/(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{2,63}/, /\b\d{3}-\d{2}-\d{4}\b/, CARD_RX, /\bAKIA[0-9A-Z]{16}\b/, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, /\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}\./, /\b(?:sk|rk)-[A-Za-z0-9]{20,200}\b/];
export const SCAN_LIMIT = 32 * 1024;
const cap = (t, keep) => typeof t === 'string' && t.length > SCAN_LIMIT ? keep === 'tail' ? t.slice(-SCAN_LIMIT) : t.slice(0, SCAN_LIMIT) : t;
const TRUE = new Set(['1', 'true', 'yes', 'on']);
const isOn = v => TRUE.has(String(v || '').trim().toLowerCase());
function privateHost(h) {
  h = String(h || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost') || !h.includes('.') && !h.includes(':')) return true;
  if (/^127\./.test(h) || h === '::1' || /^10\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  const m = h.match(/^172\.(\d+)\./);
  return !!(m && +m[1] >= 16 && +m[1] <= 31);
}
export function checkedBase(url) {
  if (!url) return [null, 'AVOWA_BASE_URL is not set'];
  let u;
  try {
    u = new URL(String(url).includes('://') ? String(url) : `https://${url}`);
  } catch {
    return [null, 'AVOWA_BASE_URL is not a valid URL'];
  }
  const base = String(url).replace(/\/+$/, '');
  if (u.protocol === 'https:') return [base, null];
  if (u.protocol === 'http:' && (privateHost(u.hostname) || isOn(env.AVOWA_ALLOW_HTTP))) return [base, null];
  return [null, `AVOWA_BASE_URL uses ${u.protocol}// to ${u.hostname} — signals carry your ingest key, so only https:// is accepted (plain http only to localhost or a private network)`];
}
const INJECTION_PATTERNS = [/ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i, /disregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|rules?)/i, /(?:reveal|print|repeat|show)\s+(?:me\s+)?(?:your\s+)?system\s+prompt/i, /you\s+are\s+now\s+(?:a|an|in)\b/i, /\bdeveloper\s+mode\b|\bDAN\s+mode\b/i, /<\/?(?:system|instructions?)>/i, /pretend\s+(?:that\s+)?you\s+(?:are|have)\b/i];
const countMatches = (text, pats) => typeof text === 'string' && text ? pats.reduce((n, rx) => n + ((rx === CARD_RX ? looksLikeCard(text) : rx.test(text)) ? 1 : 0), 0) : 0;
const PII_GATES = [(t, d) => t.includes('@'), (t, d) => d && t.includes('-'), (t, d) => d, t => t.includes('AKIA'), t => t.includes('-----BEGIN'), t => t.includes('eyJ'), t => t.includes('sk-') || t.includes('rk-')];
const PII_NAMES = ['email', 'us_ssn', 'payment_card', 'aws_access_key', 'private_key', 'jwt', 'provider_secret_key'];
const INJECTION_NAMES = ['ignore_instructions', 'disregard_rules', 'reveal_system_prompt', 'role_override', 'developer_mode', 'delimiter_injection', 'pretend'];
export function piiFamilies(text) {
  if (typeof text !== 'string' || !text) return [];
  const d = /\d/.test(text);
  return PII_PATTERNS.flatMap((rx, i) => PII_GATES[i](text, d) && (rx === CARD_RX ? looksLikeCard(text) : rx.test(text)) ? [PII_NAMES[i]] : []);
}
export function injectionFamilies(text) {
  if (typeof text !== 'string' || !text) return [];
  return INJECTION_PATTERNS.flatMap((rx, i) => rx.test(text) ? [INJECTION_NAMES[i]] : []);
}
export const scanPii = text => piiFamilies(text).length;
export const scanInjection = text => injectionFamilies(text).length;
export const _ungated = {
  pii: t => countMatches(t, PII_PATTERNS),
  injection: t => countMatches(t, INJECTION_PATTERNS)
};
export function hostOf(url) {
  if (!url) return null;
  try {
    return new URL(String(url).includes('://') ? url : `https://${url}`).hostname || null;
  } catch {
    return null;
  }
}
const TOKEN_PREFIX = 'avw1_';
export function makeToken(key, secret, baseUrl) {
  const raw = [key || '', secret || '', String(baseUrl || '').replace(/\/+$/, '')].join('\n');
  return TOKEN_PREFIX + btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function readToken(token) {
  token = String(token || '').trim();
  if (!token.startsWith(TOKEN_PREFIX)) return null;
  try {
    const parts = atob(token.slice(TOKEN_PREFIX.length).replace(/-/g, '+').replace(/_/g, '/')).split('\n');
    return parts.length === 3 && parts[0] ? parts : null;
  } catch {
    return null;
  }
}
export const TOOL_OUTCOMES = ['ok', 'error', 'denied', 'timeout'];
export const APPROVER_TYPES = ['human', 'policy', 'system', 'unknown'];
const CALL_REF_LEN = 20;
const TOOL_CAP = 60;
const LABEL_RX = /^[A-Za-z0-9 _.:/-]{1,64}$/;
export function callRef(id) {
  if (id === undefined || id === null || id === '') return null;
  return createHash('sha256').update('avowa-call:' + String(id)).digest('hex').slice(0, CALL_REF_LEN);
}
const g = (o, k) => o === null || o === undefined ? undefined : o[k];
function toolCalls(resp) {
  const out = [];
  const add = (id, name) => {
    const r = callRef(id);
    if (r && name) out.push(r + ':' + String(name).slice(0, 64));
  };
  try {
    for (const b of g(resp, 'content') || []) if (g(b, 'type') === 'tool_use') add(g(b, 'id'), g(b, 'name'));
    const msg = g(g(g(resp, 'choices'), 0), 'message');
    for (const tc of g(msg, 'tool_calls') || []) add(g(tc, 'id'), g(g(tc, 'function'), 'name') || g(tc, 'name'));
    for (const it of Array.isArray(g(resp, 'output')) ? resp.output : []) {
      if (['function_call', 'custom_tool_call'].includes(g(it, 'type'))) add(g(it, 'call_id') || g(it, 'id'), g(it, 'name'));
    }
  } catch {}
  return out.slice(0, TOOL_CAP);
}
function toolResults(history) {
  if (!Array.isArray(history)) return [];
  let fresh = [];
  for (const m of history) {
    const role = g(m, 'role'),
      typ = g(m, 'type');
    if (role === 'assistant' || MODEL_ITEMS.has(typ)) {
      fresh = [];
      continue;
    }
    if (role === 'tool') {
      const r = callRef(g(m, 'tool_call_id'));
      if (r) fresh.push(r + ':returned');
      continue;
    }
    if (typ === 'function_call_output' || typ === 'custom_tool_call_output') {
      const r = callRef(g(m, 'call_id'));
      if (r) fresh.push(r + ':returned');
      continue;
    }
    const c = g(m, 'content');
    if (Array.isArray(c)) {
      for (const b of c) {
        if (g(b, 'type') === 'tool_result') {
          const r = callRef(g(b, 'tool_use_id'));
          if (r) fresh.push(r + (g(b, 'is_error') === true ? ':error' : ':returned'));
        }
      }
    }
  }
  return fresh.slice(0, TOOL_CAP);
}
function mcpFacts(params, resp) {
  const f = {},
    labels = [],
    hosts = [],
    ran = [],
    hostOfLabel = {};
  const note = (lb, h) => {
    if (lb) labels.push(String(lb).slice(0, 64));
    if (h) {
      hosts.push(h);
      if (lb) hostOfLabel[String(lb).slice(0, 64)] = h;
    }
  };
  try {
    for (const s of g(params, 'mcp_servers') || []) note(g(s, 'name'), hostOf(g(s, 'url')));
    for (const t of g(params, 'tools') || []) {
      if (g(t, 'type') === 'mcp') note(g(t, 'server_label'), hostOf(g(t, 'server_url')));
    }
    for (const b of g(resp, 'content') || []) {
      if (g(b, 'type') === 'mcp_tool_use' && g(b, 'name')) ran.push(String(g(b, 'server_name') || '?').slice(0, 64) + '/' + String(b.name).slice(0, 64));
    }
    for (const it of Array.isArray(g(resp, 'output')) ? resp.output : []) {
      if (g(it, 'type') === 'mcp_call' && g(it, 'name')) ran.push(String(g(it, 'server_label') || '?').slice(0, 64) + '/' + String(it.name).slice(0, 64));
    }
  } catch {}
  const uniq = a => [...new Set(a)].sort().slice(0, TOOL_CAP);
  if (labels.length) f.mcp_servers_offered = uniq(labels);
  if (hosts.length) f.mcp_hosts = uniq(hosts);
  if (labels.length || ran.length) {
    f.mcp_tools_invoked = uniq(ran);
    f.mcp_hosts_invoked = uniq(ran.map(r => hostOfLabel[r.split('/')[0]]).filter(Boolean));
  }
  return f;
}
function runKey(messages, secret) {
  if (typeof messages === 'string') messages = [{
    role: 'user',
    content: messages
  }];
  if (!Array.isArray(messages)) return null;
  for (const m of messages) {
    if (g(m, 'role') !== 'user') continue;
    let c = g(m, 'content');
    if (Array.isArray(c)) c = c.map(b => b && typeof b === 'object' ? String(b.text || b.content || '') : '').join('');
    c = String(c || '').trim();
    if (!c) continue;
    return (secret ? createHmac('sha256', String(secret)).update(c) : createHash('sha256').update(c)).digest('hex').slice(0, 12);
  }
  return null;
}
const MODEL_ITEMS = new Set(['function_call', 'custom_tool_call', 'mcp_call', 'computer_call', 'web_search_call', 'file_search_call', 'code_interpreter_call', 'local_shell_call', 'reasoning']);
const CALL_ITEMS = new Set(['function_call', 'custom_tool_call', 'mcp_call', 'computer_call', 'local_shell_call']);
const RESULT_ITEMS = new Set(['function_call_output', 'custom_tool_call_output', 'computer_call_output', 'local_shell_call_output', 'mcp_approval_response']);
function modelTurns(messages) {
  const turns = [];
  let cur = null;
  for (const m of messages) {
    const role = g(m, 'role'),
      typ = g(m, 'type');
    if (!(MODEL_ITEMS.has(typ) || role === 'assistant')) {
      cur = null;
      turns.push([false, false]);
      continue;
    }
    let tools = CALL_ITEMS.has(typ);
    if (role === 'assistant') {
      if (Array.isArray(g(m, 'tool_calls')) && m.tool_calls.length) tools = true;
      const c = g(m, 'content');
      if (Array.isArray(c) && c.some(b => g(b, 'type') === 'tool_use')) tools = true;
    }
    if (role === 'assistant' && typ === undefined) {
      cur = null;
      turns.push([true, tools]);
      continue;
    }
    if (!cur) {
      cur = [true, false];
      turns.push(cur);
    }
    cur[1] = cur[1] || tools;
  }
  return turns;
}
function autonomyDepth(messages) {
  if (typeof messages === 'string') return 0;
  if (!Array.isArray(messages)) return null;
  try {
    return modelTurns(messages).filter(([m, t]) => m && t).length;
  } catch {
    return null;
  }
}
const CHAIN = new Map();
function chainPut(id, key, next) {
  CHAIN.set(String(id), [key, next]);
  while (CHAIN.size > 4096) CHAIN.delete(CHAIN.keys().next().value);
}
const AGENT = new AsyncLocalStorage();
export function agentContext({
  name,
  customer
} = {}, fn) {
  let nm = name === undefined || name === null ? null : String(name).slice(0, 64);
  if (nm !== null && !LABEL_RX.test(nm)) {
    warnOnce('agentname', 'agentContext name must be letters, digits and _ . : / - (64 at most); the name was not recorded.');
    nm = null;
  }
  return AGENT.run({
    name: nm,
    customer: customer === undefined || customer === null ? null : String(customer)
  }, fn);
}
function customerRef(secret, customer) {
  if (customer === undefined || customer === null || customer === '') return null;
  const key = env.AVOWA_REF_KEY || secret;
  if (!key) return null;
  return createHmac('sha256', String(key)).update('avowa-customer:' + String(customer)).digest('hex').slice(0, 12);
}
let DEFAULT = null;
export function approval(callId, approved, approverRole, opts = {}) {
  if (!DEFAULT) {
    warnOnce('noruntime', 'approval() was called but no Avowa runtime is running; nothing was recorded.');
    return Promise.resolve(null);
  }
  return DEFAULT.approval(callId, approved, approverRole, opts);
}
export function toolOutcome(callId, outcome) {
  if (!DEFAULT) {
    warnOnce('noruntime', 'toolOutcome() was called but no Avowa runtime is running; nothing was recorded.');
    return Promise.resolve(null);
  }
  return DEFAULT.toolOutcome(callId, outcome);
}
export function createAvowa({
  ingestKey,
  ingestSecret,
  baseUrl,
  region
} = {}) {
  if (isOn(env.AVOWA_DISABLE)) {
    const noop = async () => undefined;
    return {
      capture: noop,
      track: (meta, fn) => fn(),
      instrumentOpenAI: c => c,
      instrumentAnthropic: c => c,
      _wrapResource: () => undefined,
      approval: noop,
      toolOutcome: noop,
      disabled: true
    };
  }
  const tok = env.AVOWA_TOKEN ? readToken(env.AVOWA_TOKEN) : null;
  if (env.AVOWA_TOKEN && !tok) warnOnce('token', 'AVOWA_TOKEN is set but is not a valid Avowa token (one starts with avw1_), so no signals will be sent. Copy it again from avowa.env or the console.');
  const key = ingestKey || env.AVOWA_RUNTIME_KEY || tok && tok[0] || undefined;
  const secret = ingestSecret || env.AVOWA_RUNTIME_SECRET || tok && tok[1] || undefined;
  const [base, baseProblem] = checkedBase(baseUrl || env.AVOWA_BASE_URL || tok && tok[2] || undefined);
  if (!key) warnOnce('nokey', 'no credentials. Set AVOWA_TOKEN (from `npx @avowa/runtime init`) or pass ingestKey. No signals will be sent.');else if (baseProblem) warnOnce('nobase', `${baseProblem} — no signals will be sent. Your app is unaffected.`);
  const MAX_INFLIGHT = 64;
  const TIMEOUT_MS = 5000;
  let inflight = 0;
  async function capture(evt = {}) {
    try {
      return await _capture(evt);
    } catch (e) {
      internalError('capture', e);
      return null;
    }
  }
  async function _capture(evt = {}) {
    if (!key || !base) return;
    const payload = {
      model: evt.model || null,
      region: evt.region || region || null,
      latency_ms: evt.latency_ms ?? null
    };
    if (evt.train_on_data !== undefined && evt.train_on_data !== null) payload.train_on_data = !!evt.train_on_data;
    if (evt.guardrail_blocked !== undefined && evt.guardrail_blocked !== null) {
      payload.guardrail_blocked = !!evt.guardrail_blocked;
    }
    for (const k of ['guardrail', 'decision_logged', 'human_reviewed', 'rationale_present', 'ai_disclosed', 'uncertainty_flagged', 'fairness_checked', 'blocked_category', 'pii_redacted', 'grounded', 'refused', 'injection_blocked', 'output_validated', 'system_prompt_protected', 'rate_limited', 'tool_authorized', 'action_authorized', 'model_pinned', 'eval_score', 'agent_run', 'tool_called', 'autonomy_depth', 'action_class', 'approval_required', 'approved_by_human', 'action_blocked', 'action_logged', 'agent_run_key', 'tools_offered', 'tools_invoked', 'injection_suspected', 'pii_detected', 'error', 'fallback_model', 'retries', 'token_ceiling', 'provider_throttled', 'requested_model', 'stop_reason', 'structured_output', 'refusal_part', 'input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_write_tokens', 'system_prompt_present', 'tool_choice', 'messages_user', 'messages_assistant', 'messages_tool', 'input_images', 'input_files', 'input_audio', 'streaming', 'response_format_type', 'prompt_chars', 'output_chars', 'client_max_retries', 'client_timeout_s', 'pii_families', 'injection_families', 'temperature', 'top_p', 'seed', 'choices_n', 'stop_sequences', 'parallel_tool_calls', 'store_requested', 'logprobs', 'service_tier_requested', 'metadata_present', 'end_user_id_present', 'reasoning_effort', 'thinking_enabled', 'system_fingerprint', 'service_tier', 'provider_filtered', 'provider_filter_categories', 'ttft_ms', 'http_status', 'provider_error_code', 'retry_after_s', 'provider_lib', 'node_version', 'app_region', 'app_region_source', 'tool_calls', 'tool_results', 'mcp_servers_offered', 'mcp_tools_invoked', 'mcp_hosts', 'mcp_hosts_invoked']) {
      if (evt[k] !== undefined && evt[k] !== null) payload[k] = evt[k];
    }
    const ctx = AGENT.getStore() || {};
    const name = evt.agent_name !== undefined && evt.agent_name !== null ? String(evt.agent_name).slice(0, 64) : ctx.name;
    if (name) payload.agent_name = name;
    const cref = customerRef(secret, evt.customer !== undefined && evt.customer !== null ? evt.customer : ctx.customer);
    if (cref) payload.customer_ref = cref;
    if (evt.endpoint) payload.endpoint = hostOf(evt.endpoint);
    const scanP = evt.scanPrompt !== undefined && evt.scanPrompt !== null ? cap(evt.scanPrompt, 'tail') : null;
    const scanO = evt.scanOutput !== undefined && evt.scanOutput !== null ? cap(evt.scanOutput, 'head') : null;
    if (scanP !== null || scanO !== null) {
      await new Promise(r => typeof setImmediate === 'function' ? setImmediate(r) : setTimeout(r, 0));
      if (scanP !== null) {
        const fam = injectionFamilies(scanP);
        payload.injection_suspected = fam.length;
        payload.injection_families = fam;
      }
      if (scanO !== null) {
        const fam = piiFamilies(scanO);
        payload.pii_detected = fam.length;
        payload.pii_families = fam;
      }
    }
    for (const k of Object.keys(evt)) if (/^rf_[a-z][a-z0-9_]{1,40}$/.test(k) && evt[k] != null) payload[k] = evt[k];
    if (Array.isArray(evt._sdk_observed) && evt._sdk_observed.length) payload._sdk_observed = [...new Set(evt._sdk_observed)];
    const kinds = Object.keys(INTERNAL_ERRORS);
    if (kinds.length) {
      payload.sdk_errors = kinds.reduce((n, k) => n + INTERNAL_ERRORS[k], 0);
      payload.sdk_error_kinds = kinds.sort().slice(0, 10);
    }
    return enqueue(payload);
  }
  const BATCH_MAX = 100;
  const BATCH_WAIT_MS = 20;
  let pending = [];
  let pendingTimer = null;
  function enqueue(payload) {
    return new Promise((resolve, reject) => {
      pending.push({
        payload,
        resolve,
        reject
      });
      if (pending.length >= BATCH_MAX) flushPending();else if (!pendingTimer) pendingTimer = setTimeout(flushPending, BATCH_WAIT_MS);
    });
  }
  function flushPending() {
    if (pendingTimer) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }
    const batch = pending.splice(0, BATCH_MAX);
    if (pending.length) pendingTimer = setTimeout(flushPending, BATCH_WAIT_MS);
    if (!batch.length) return;
    sendEnvelope(batch.filter(b => !b.payload._annotation).map(b => b.payload), batch.filter(b => b.payload._annotation).map(b => b.payload._annotation)).then(r => batch.forEach(b => b.resolve(r)), e => batch.forEach(b => b.reject(e)));
  }
  function annotate(ann) {
    if (!key || !base) return Promise.resolve(null);
    return enqueue({
      _annotation: ann
    }).catch(e => {
      internalError('annotate', e);
      return null;
    });
  }
  const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  function approval(callId, approved, approverRole, {
    approverType = 'unknown',
    policyRef
  } = {}) {
    const ref = callRef(callId);
    if (!ref) return Promise.resolve(null);
    if (!APPROVER_TYPES.includes(approverType)) {
      warnOnce('approvertype', `approval() approverType must be one of ${APPROVER_TYPES.join(', ')}; recorded as unknown.`);
      approverType = 'unknown';
    }
    const ann = {
      type: 'approval',
      tool_call_ref: ref,
      approved: !!approved,
      approver_type: approverType,
      at: nowIso()
    };
    const role = approverRole === undefined || approverRole === null ? null : String(approverRole).slice(0, 40);
    if (role && LABEL_RX.test(role)) ann.approver_role = role;
    const pol = policyRef === undefined || policyRef === null ? null : String(policyRef).slice(0, 64);
    if (pol && LABEL_RX.test(pol)) ann.policy_ref = pol;
    return annotate(ann);
  }
  function toolOutcome(callId, outcome) {
    const ref = callRef(callId);
    if (!ref) return Promise.resolve(null);
    if (!TOOL_OUTCOMES.includes(outcome)) {
      warnOnce('outcome', `toolOutcome() takes one of ${TOOL_OUTCOMES.join(', ')}; that outcome was not recorded.`);
      return Promise.resolve(null);
    }
    return annotate({
      type: 'outcome',
      tool_call_ref: ref,
      outcome,
      at: nowIso()
    });
  }
  async function sendEnvelope(events, annotations = []) {
    const nonce = [...(globalThis.crypto && globalThis.crypto.getRandomValues ? globalThis.crypto.getRandomValues(new Uint8Array(12)) : (await import('node:crypto')).randomBytes(12))].map(b => b.toString(16).padStart(2, '0')).join('');
    const envelope = {
      schema: SCHEMA,
      source: {
        kind: 'runtime',
        client: 'avowa-runtime-js',
        version: VERSION
      },
      sent_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      nonce,
      events
    };
    if (annotations.length) envelope.annotations = annotations;
    const body = JSON.stringify(envelope);
    const headers = {
      'Content-Type': 'application/json',
      'X-Ingest-Key': key,
      'X-Avowa-Client': `avowa-runtime-js/${VERSION}`
    };
    if (secret) {
      const ts = String(Math.floor(Date.now() / 1000));
      headers['X-Avowa-Timestamp'] = ts;
      headers['X-Avowa-Signature'] = await hmacHex(secret, `${ts}.${body}`);
      if (remoteOn()) headers['X-Avowa-Fields'] = REMOTE.v || 'none';
    }
    if (inflight >= MAX_INFLIGHT) {
      warnOnce('inflight', `${MAX_INFLIGHT} uploads already in flight — Avowa is slow or unreachable, so signals are being dropped. Your app is unaffected.`);
      return null;
    }
    inflight++;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    if (timer && typeof timer.unref === 'function') timer.unref();
    try {
      const r = await fetch(base + '/ingest/v1', {
        method: 'POST',
        headers,
        body,
        signal: ctl.signal
      });
      if (r.ok) {
        try {
          const j = await r.clone().json();
          if (j && j.sdk_fields && secret && remoteOn()) await acceptFields(j.sdk_fields, secret);
          if (j && typeof j.sdk_latest === 'string' && /^\d+\.\d+\.\d+$/.test(j.sdk_latest)) {
            warnOnce('latest', `@avowa/runtime ${j.sdk_latest} is available (this is ${VERSION}). Nothing is wrong — upgrade when convenient: npm install @avowa/runtime@latest.`);
          }
        } catch {}
      }
      if (!r.ok) {
        const hint = {
          401: 'the key or secret is wrong, or this host\'s clock is off (signatures expire after 5 minutes)',
          402: 'the workspace is on the Declare plan — live capture needs Prove',
          403: 'blocked before reaching Avowa (a proxy or WAF?)',
          404: `${base} is not an Avowa API — check AVOWA_BASE_URL`,
          429: 'rate limited — the SDK does not retry; reduce volume or sample'
        }[r.status];
        warnOnce(`http${r.status}`, `signal rejected: HTTP ${r.status}${hint ? ' — ' + hint : ''}`);
      }
      return r;
    } catch (e) {
      warnOnce('net', `could not reach ${base} (${e && e.name ? e.name : 'error'}) — check the URL, DNS and egress from this host`);
      return null;
    } finally {
      clearTimeout(timer);
      inflight--;
    }
  }
  async function track(meta, fn) {
    const start = Date.now();
    let err = null;
    try {
      return await fn();
    } catch (e) {
      err = errName(e);
      throw e;
    } finally {
      Promise.resolve().then(() => capture({
        ...meta,
        error: err,
        latency_ms: Date.now() - start
      })).catch(() => {});
    }
  }
  const textOfMessages = msgs => {
    const out = [];
    for (const m of msgs || []) {
      if (typeof m === 'string') out.push(m);else if (m && typeof m.content === 'string') out.push(m.content);else if (m && Array.isArray(m.content)) for (const b of m.content) if (b && typeof b.text === 'string') out.push(b.text);
    }
    return out.join('\n');
  };
  const toolNames = tools => (tools || []).map(t => t && (t.name || t.function && t.function.name) || null).filter(Boolean).slice(0, 60);
  const errName = e => e && (e.status === 429 || e.statusCode === 429) ? 'RateLimitError' : e && e.name || 'Error';
  const KIND = {
    image: 'image',
    image_url: 'image',
    input_image: 'image',
    document: 'file',
    file: 'file',
    input_file: 'file',
    input_audio: 'audio',
    audio: 'audio'
  };
  function requestFacts(params) {
    const p = params || {},
      f = {};
    for (const k of ['max_tokens', 'max_completion_tokens', 'max_output_tokens']) {
      if (Number.isInteger(p[k]) && p[k] > 0) {
        f.token_ceiling = p[k];
        break;
      }
    }
    const msgs = Array.isArray(p.messages) ? p.messages : Array.isArray(p.input) ? p.input : null;
    let system = !!(p.system || p.instructions);
    if (msgs) {
      const roles = {
          user: 0,
          assistant: 0,
          tool: 0
        },
        kinds = {
          image: 0,
          file: 0,
          audio: 0
        };
      let chars = 0;
      try {
        roles.assistant += modelTurns(msgs).filter(([mt]) => mt).length - msgs.filter(m => g(m, 'role') === 'assistant').length;
      } catch {}
      for (const m of msgs) {
        if (!m) continue;
        if (RESULT_ITEMS.has(m.type)) roles.tool++;
        if (m.role === 'system' || m.role === 'developer') system = true;else if (m.role in roles) roles[m.role]++;
        if (typeof m.content === 'string') chars += m.content.length;else if (Array.isArray(m.content)) {
          for (const b of m.content) {
            const k = b && KIND[b.type];
            if (k) kinds[k]++;else if (b && b.type === 'tool_result') roles.tool++;
            if (b && typeof b.text === 'string') chars += b.text.length;
          }
        }
      }
      Object.assign(f, {
        messages_user: roles.user,
        messages_assistant: roles.assistant,
        messages_tool: roles.tool,
        input_images: kinds.image,
        input_files: kinds.file,
        input_audio: kinds.audio,
        prompt_chars: chars
      });
    }
    if (msgs || system) f.system_prompt_present = system;
    if (p.tool_choice != null) f.tool_choice = String(typeof p.tool_choice === 'string' ? p.tool_choice : p.tool_choice.type || 'specific').slice(0, 20);
    if (p.stream != null) f.streaming = !!p.stream;
    const rf = p.response_format || p.output_format;
    if (rf != null) f.response_format_type = String(rf && rf.type || 'schema').slice(0, 30);
    return [f, Object.keys(f)];
  }
  const USAGE = {
    input_tokens: ['input_tokens', 'prompt_tokens'],
    output_tokens: ['output_tokens', 'completion_tokens'],
    cache_read_tokens: ['cache_read_input_tokens'],
    cache_write_tokens: ['cache_creation_input_tokens']
  };
  function usageFacts(resp) {
    const u = resp && resp.usage,
      f = {};
    if (!u) return f;
    for (const [fact, names] of Object.entries(USAGE)) {
      for (const n of names) if (Number.isInteger(u[n])) {
        f[fact] = u[n];
        break;
      }
    }
    if (f.cache_read_tokens == null) {
      for (const d of ['prompt_tokens_details', 'input_tokens_details']) {
        if (u[d] && Number.isInteger(u[d].cached_tokens)) {
          f.cache_read_tokens = u[d].cached_tokens;
          break;
        }
      }
    }
    return f;
  }
  function clientFacts(client) {
    const f = {};
    if (client && Number.isInteger(client.maxRetries)) f.client_max_retries = client.maxRetries;
    if (client && typeof client.timeout === 'number') f.client_timeout_s = client.timeout / 1000;
    return f;
  }
  const CODE = /^[A-Za-z0-9_.:-]{1,60}$/;
  const label = (v, n = 30) => typeof v === 'string' && v && CODE.test(v.slice(0, n)) ? v.slice(0, n) : null;
  const num = v => typeof v === 'number' && Number.isFinite(v) ? v : null;
  function paramFacts(params) {
    const p = params || {},
      f = {};
    for (const [fact, key] of [['temperature', 'temperature'], ['top_p', 'top_p'], ['seed', 'seed'], ['choices_n', 'n']]) {
      const v = num(p[key]);
      if (v != null) f[fact] = v;
    }
    let stops = p.stop_sequences != null ? p.stop_sequences : p.stop;
    if (typeof stops === 'string') stops = [stops];
    if (Array.isArray(stops)) f.stop_sequences = stops.length;
    for (const [fact, key] of [['parallel_tool_calls', 'parallel_tool_calls'], ['store_requested', 'store'], ['logprobs', 'logprobs']]) {
      if (typeof p[key] === 'boolean') f[fact] = p[key];
    }
    const tier = label(p.service_tier, 20);
    if (tier) f.service_tier_requested = tier;
    if (p.metadata != null) f.metadata_present = !!p.metadata && Object.keys(p.metadata).length > 0;
    if (p.user || p.safety_identifier || p.metadata && p.metadata.user_id) f.end_user_id_present = true;else if ('user' in p || 'safety_identifier' in p || p.metadata != null) f.end_user_id_present = false;
    const effort = label(p.reasoning_effort || p.reasoning && p.reasoning.effort, 20);
    if (effort) f.reasoning_effort = effort;
    if (typeof p.thinking === 'boolean') f.thinking_enabled = p.thinking;else if (p.thinking != null) f.thinking_enabled = p.thinking.type != null && p.thinking.type !== 'disabled';
    return f;
  }
  const filtered = r => {
    const inner = r && r.content_filter_results ? r.content_filter_results : r;
    return inner && typeof inner === 'object' ? Object.entries(inner).filter(([k, v]) => v && v.filtered === true && CODE.test(k)).map(([k]) => k) : [];
  };
  function responseMetaFacts(resp) {
    const f = {};
    if (!resp) return f;
    const fp = label(resp.system_fingerprint, 60);
    if (fp) f.system_fingerprint = fp;
    const tier = label(resp.service_tier || resp.usage && resp.usage.service_tier, 20);
    if (tier) f.service_tier = tier;
    let present = false,
      cats = [];
    if (resp.prompt_filter_results != null) {
      present = true;
      for (const r of [].concat(resp.prompt_filter_results)) cats.push(...filtered(r));
    }
    for (const c of Array.isArray(resp.choices) ? resp.choices.slice(0, 4) : []) {
      if (c && c.content_filter_results != null) {
        present = true;
        cats.push(...filtered(c));
      }
    }
    if (present) {
      f.provider_filtered = cats.length > 0;
      if (cats.length) f.provider_filter_categories = [...new Set(cats)].sort().slice(0, 10);
    }
    return f;
  }
  function errorFacts(e) {
    const f = {};
    if (!e || typeof e !== 'object') return f;
    const st = num(e.status) != null ? e.status : num(e.statusCode);
    if (st != null && st >= 100 && st <= 599) f.http_status = st;
    const body = e.error;
    const code = [body && body.error && body.error.type, body && body.type !== 'error' ? body.type : null, e.code, e.type].map(c => label(typeof c === 'string' ? c : null, 60)).find(Boolean);
    if (code) f.provider_error_code = code;
    try {
      const h = e.headers;
      const ra = h && (typeof h.get === 'function' ? h.get('retry-after') : h['retry-after']);
      if (ra != null && Number.isFinite(Number(ra))) f.retry_after_s = Number(ra);
    } catch {}
    return f;
  }
  const REGION_VARS = ['AWS_REGION', 'AWS_DEFAULT_REGION', 'GOOGLE_CLOUD_REGION', 'FUNCTION_REGION', 'CLOUD_RUN_REGION', 'REGION_NAME', 'AZURE_REGION', 'FLY_REGION', 'VERCEL_REGION', 'RAILWAY_REPLICA_REGION', 'RENDER_REGION'];
  function envFacts() {
    const f = {};
    if (typeof process !== 'undefined' && process.versions && process.versions.node) f.node_version = process.versions.node;
    for (const v of REGION_VARS) {
      const val = env[v];
      if (val && /^[A-Za-z0-9 _-]{2,30}$/.test(val)) {
        f.app_region = val;
        f.app_region_source = v;
        break;
      }
    }
    return f;
  }
  function responseFacts(resp, params, kind) {
    const f = {},
      seen = [];
    if (!resp) return [f, seen];
    const asked = params && params.model;
    if (asked) {
      f.requested_model = String(asked).slice(0, 120);
      seen.push('requested_model');
    }
    let stop = resp.stop_reason;
    if (stop == null && resp.choices && resp.choices[0]) stop = resp.choices[0].finish_reason;
    if (stop == null && resp.status != null && Array.isArray(resp.output)) {
      stop = resp.incomplete_details && resp.incomplete_details.reason || resp.status;
      const types = new Set(resp.output.flatMap(it => (Array.isArray(it && it.content) ? it.content : []).map(c => c && c.type)));
      if (types.has('refusal')) {
        f.refusal_part = true;
        seen.push('refusal_part');
      }
    }
    if (stop != null) {
      f.stop_reason = String(stop).slice(0, 40);
      seen.push('stop_reason');
    }
    const offered = toolNames(params && params.tools);
    if (offered.length) {
      f.tools_offered = offered;
      seen.push('tools_offered');
    }
    const invoked = [];
    try {
      if (kind === 'anthropic') {
        for (const b of resp.content || []) {
          if (b && b.type === 'tool_use' && b.name) invoked.push(String(b.name).slice(0, 64));
        }
      } else {
        for (const tc of resp.choices && resp.choices[0] && resp.choices[0].message && resp.choices[0].message.tool_calls || []) {
          const n = tc.function && tc.function.name || tc.name;
          if (n) invoked.push(String(n).slice(0, 64));
        }
        for (const it of resp.output || []) {
          if (it && (it.type === 'function_call' || it.type === 'custom_tool_call') && it.name) invoked.push(String(it.name).slice(0, 64));
        }
      }
    } catch {}
    if (offered.length || invoked.length) {
      f.tools_invoked = invoked;
      seen.push('tools_invoked');
    }
    const calls = toolCalls(resp);
    if (calls.length) {
      f.tool_calls = calls;
      seen.push('tool_calls');
    }
    const history = params && (Array.isArray(params.messages) ? params.messages : Array.isArray(params.input) || typeof params.input === 'string' ? params.input : null);
    const results = toolResults(history);
    if (results.length) {
      f.tool_results = results;
      seen.push('tool_results');
    }
    const mcp = mcpFacts(params, resp);
    Object.assign(f, mcp);
    seen.push(...Object.keys(mcp));
    if (offered.length) {
      let depth = autonomyDepth(history);
      let rk = runKey(history, secret);
      if (params.previous_response_id) {
        const parent = CHAIN.get(String(params.previous_response_id));
        if (!parent) {
          depth = null;
          rk = null;
        } else {
          rk = parent[0];
          depth = parent[1] === null || depth === null ? null : parent[1] + depth;
        }
      } else if (params.conversation) {
        depth = null;
        rk = null;
      }
      if (depth !== null) {
        f.autonomy_depth = depth;
        seen.push('autonomy_depth');
      }
      if (rk) {
        Object.assign(f, {
          agent_run_key: rk
        });
        seen.push('agent_run_key');
      }
      if (resp.id && Array.isArray(resp.output)) chainPut(resp.id, rk, depth === null ? null : depth + (calls.length ? 1 : 0));
    }
    return [f, seen];
  }
  function outputText(resp, kind) {
    try {
      if (kind === 'anthropic') return (resp.content || []).map(b => b && b.text || '').join('\n');
      if (typeof resp.output_text === 'string') return resp.output_text;
      return (resp.choices || []).map(c => c.message && c.message.content || '').join('\n');
    } catch {
      return '';
    }
  }
  function streamWatch(onEnd, kind) {
    let model = null,
      stop = null,
      size = 0,
      ttft = null;
    let completed = null,
      usage = null;
    const chatCalls = new Map(),
      blocks = [];
    const started = Date.now();
    const text = [];
    const keep = t => {
      if (size < SCAN_LIMIT) {
        text.push(t);
        size += t.length;
      }
    };
    const see = c => {
      if (ttft === null) ttft = Date.now() - started;
      try {
        const t = c.type || '';
        if (t === 'message_start' && c.message && c.message.model) model = c.message.model;
        if (t === 'message_delta' && c.delta && c.delta.stop_reason) stop = c.delta.stop_reason;
        if (t === 'content_block_delta' && c.delta && c.delta.text) keep(c.delta.text);
        if (t.endsWith('output_text.delta') && typeof c.delta === 'string') keep(c.delta);
        if (t === 'response.completed' && c.response) {
          completed = c.response;
          if (c.response.model) model = c.response.model;
        }
        if (t === 'content_block_start' && c.content_block && c.content_block.type === 'tool_use') blocks.push({
          type: 'tool_use',
          id: c.content_block.id,
          name: c.content_block.name
        });
        if (t === 'message_start' && c.message && c.message.usage) usage = {
          ...(usage || {}),
          input_tokens: c.message.usage.input_tokens
        };
        if (t === 'message_delta' && c.usage && c.usage.output_tokens != null) usage = {
          ...(usage || {}),
          output_tokens: c.usage.output_tokens
        };
        if (!t && c.model) model = c.model;
        if (!t && c.usage && c.usage.prompt_tokens != null) usage = {
          prompt_tokens: c.usage.prompt_tokens,
          completion_tokens: c.usage.completion_tokens
        };
        const ch = c.choices && c.choices[0];
        if (ch) {
          if (ch.finish_reason) stop = ch.finish_reason;
          if (ch.delta && typeof ch.delta.content === 'string') keep(ch.delta.content);
          for (const tc of ch.delta && ch.delta.tool_calls || []) {
            const slot = chatCalls.get(tc.index || 0) || [null, null];
            if (tc.id) slot[0] = tc.id;
            if (tc.function && tc.function.name) slot[1] = tc.function.name;
            chatCalls.set(tc.index || 0, slot);
          }
        }
      } catch {}
    };
    let done = false;
    const finish = err => {
      if (done) return;
      done = true;
      const all = text.join('');
      const calls = [...chatCalls.entries()].sort((a, b) => a[0] - b[0]).filter(([, [, n]]) => n).map(([, [id, name]]) => ({
        id,
        type: 'function',
        function: {
          name
        }
      }));
      const summary = completed ? completed : kind === 'anthropic' ? {
        model,
        stop_reason: stop,
        usage,
        content: [{
          type: 'text',
          text: all
        }, ...blocks]
      } : {
        model,
        output_text: all,
        usage,
        choices: [{
          finish_reason: stop,
          message: {
            content: all,
            tool_calls: calls.length ? calls : undefined
          }
        }]
      };
      try {
        onEnd(summary, err, ttft);
      } catch (e) {
        internalError('stream.finish', e);
      }
    };
    return {
      see,
      finish
    };
  }
  function observeStream(stream, onEnd, kind) {
    const w = streamWatch(onEnd, kind);
    const watched = makeIt => async function* () {
      try {
        for await (const c of {
          [Symbol.asyncIterator]: makeIt
        }) {
          w.see(c);
          yield c;
        }
      } catch (e) {
        w.finish(e);
        throw e;
      } finally {
        w.finish(null);
      }
    }();
    try {
      if (typeof stream.iterator === 'function') {
        const orig = stream.iterator.bind(stream);
        stream.iterator = () => watched(orig);
      } else if (typeof stream[Symbol.asyncIterator] === 'function') {
        const orig = stream[Symbol.asyncIterator].bind(stream);
        stream[Symbol.asyncIterator] = () => watched(orig);
      }
    } catch {}
    return stream;
  }
  function wrapMethod(holder, name, kind, host, opts, given) {
    if (typeof holder[name] !== 'function' || holder[name]._avowa_wrapped) return;
    const original = given || holder[name].bind(holder);
    const wrapped = function (params = {}, ...rest) {
      const start = Date.now();
      const emit = (resp, err, ttft) => {
        try {
          const more = {
            ...envFacts(),
            ...paramFacts(params),
            ...responseMetaFacts(resp),
            provider_lib: kind === 'anthropic' ? '@anthropic-ai/sdk' : 'openai'
          };
          Object.assign(more, remoteFacts(kind, resp, params, err && typeof err === 'object' ? err : null));
          if (err && typeof err === 'object') {
            Object.assign(more, errorFacts(err));
            err = errName(err);
          }
          if (ttft != null) more.ttft_ms = ttft;
          const [facts, seen] = responseFacts(resp, params, kind);
          for (const [k, v] of Object.entries(more)) if (!(k in facts)) facts[k] = v;
          seen.push(...Object.keys(more));
          const [req, reqSeen] = requestFacts(params);
          Object.assign(facts, req);
          seen.push(...reqSeen);
          const usage = usageFacts(resp);
          Object.assign(facts, usage, opts.clientFacts || {});
          seen.push(...Object.keys(usage), ...Object.keys(opts.clientFacts || {}));
          const out = resp ? outputText(resp, kind) : '';
          if (resp) {
            facts.output_chars = out.length;
            seen.push('output_chars');
          }
          if (resp && typeof resp.model === 'string' && resp.model) seen.push('model');
          seen.push('endpoint', 'latency_ms');
          if (err) seen.push('error');
          if (opts.scan !== false) seen.push('pii_detected', 'injection_suspected', 'pii_families', 'injection_families');
          const prompt = kind === 'anthropic' ? textOfMessages(params.messages) : textOfMessages(params.messages || (Array.isArray(params.input) ? params.input : [params.input]));
          capture({
            ...(opts.asserts || {}),
            ...facts,
            model: resp && resp.model || params.model,
            region: opts.region,
            endpoint: host,
            latency_ms: Date.now() - start,
            error: err,
            scanPrompt: opts.scan !== false ? prompt : undefined,
            scanOutput: opts.scan !== false && out ? out : undefined,
            _sdk_observed: seen
          });
        } catch (e) {
          internalError('emit', e);
        }
      };
      let p;
      try {
        p = original(params, ...rest);
      } catch (e) {
        emit(null, e);
        throw e;
      }
      try {
        if (p && typeof p.then === 'function') {
          p.then(resp => {
            if (params && params.stream && resp && (typeof resp.iterator === 'function' || typeof resp[Symbol.asyncIterator] === 'function')) observeStream(resp, emit, kind);else emit(resp, null);
          }, e => emit(null, e));
        } else {
          emit(p, null);
        }
      } catch (e) {
        internalError('wrap', e);
      }
      return p;
    };
    wrapped._avowa_wrapped = true;
    holder[name] = wrapped;
  }
  function instrumentOpenAI(client, opts = {}) {
    const host = hostOf(client && client.baseURL) || 'api.openai.com';
    opts = {
      ...opts,
      clientFacts: clientFacts(client)
    };
    const chat = client && client.chat && client.chat.completions;
    if (chat) wrapMethod(chat, 'create', 'openai', host, opts);
    if (client && client.responses) wrapMethod(client.responses, 'create', 'openai', host, opts);
    return client;
  }
  function instrumentAnthropic(client, opts = {}) {
    const host = hostOf(client && client.baseURL) || 'api.anthropic.com';
    opts = {
      ...opts,
      clientFacts: clientFacts(client)
    };
    if (client && client.messages) wrapMethod(client.messages, 'create', 'anthropic', host, opts);
    return client;
  }
  function _wrapResource(resource, name, kind, original) {
    const client = resource && resource._client;
    const host = hostOf(client && client.baseURL) || (kind === 'anthropic' ? 'api.anthropic.com' : 'api.openai.com');
    const scan = !['0', 'false', 'no', 'off'].includes(String(env.AVOWA_SCAN || '').trim().toLowerCase());
    wrapMethod(resource, name, kind, host, {
      clientFacts: clientFacts(client),
      scan,
      region
    }, original.bind(resource));
  }
  const api = {
    capture,
    track,
    instrumentOpenAI,
    instrumentAnthropic,
    _wrapResource,
    approval,
    toolOutcome
  };
  if (!DEFAULT && key) DEFAULT = api;
  return api;
}
export default createAvowa;
