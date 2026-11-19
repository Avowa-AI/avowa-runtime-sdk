#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avowa, Inc.
/**
 * `npx @avowa/runtime <command>` - set up and check the Runtime SDK. A setup tool, not a launcher:
 * after `init` your app starts the way it always has.
 *
 *   init <setup-token>     connect this project: writes avowa.env (one line: AVOWA_TOKEN)
 *   init --dry-run         show what init would do; changes nothing, uses no token
 *   status                 what is wired, what is covered, does the server know this key
 *   doctor                 the server check only (sends no signal)
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import readline from 'node:readline'
import { checkedBase, makeToken, readToken, SDK_VERSION as VERSION } from './avowa-runtime.js'
import { loadEnv } from './env.js'

const REGISTER = '@avowa/runtime/register'
const USAGE = `usage: npx @avowa/runtime <command>

  init <setup-token> [--api https://api.avowa.ai] [--dry-run] [--yes]
  status
  doctor

Generate the setup token in the Avowa console: Connections, Runtime SDK.
In production set two variables and change nothing else:
  AVOWA_TOKEN=<the value in avowa.env>
  NODE_OPTIONS=--import ${REGISTER}
AVOWA_DISABLE=1 switches everything off.`

// How each library is covered: "auto" needs nothing; the rest say what they need.
const LIBS = [
  ['openai', 'covered automatically (OpenAI, Azure OpenAI, OpenAI-compatible hosts)'],
  ['@anthropic-ai/sdk', 'covered automatically'],
  ['@aws-sdk/client-bedrock-runtime', 'no wrapper yet: record calls with avowa.capture(...)'],
  ['@google/genai', 'no wrapper yet: record calls with avowa.capture(...)'],
  ['@google/generative-ai', 'no wrapper yet: record calls with avowa.capture(...)'],
  ['ai', 'Vercel AI SDK calls providers over its own HTTP client: record calls with avowa.track(...)'],
]
const BUNDLED = ['next', 'nuxt', '@remix-run/dev', '@sveltejs/kit']

const readPkg = () => { try { return JSON.parse(fs.readFileSync('package.json', 'utf8')) } catch { return null } }
const deps = (pkg) => ({ ...(pkg && pkg.dependencies), ...(pkg && pkg.devDependencies) })

function coverage(pkg) {
  const d = deps(pkg)
  const out = LIBS.filter(([n]) => n in d).map(([n, note]) => `  ${n.padEnd(18)}: ${note}`)
  if (!out.length) out.push('  no AI provider library in package.json. Calls made over fetch need avowa.capture(...).')
  const b = BUNDLED.filter((n) => n in d)
  if (b.length) out.push(`  ${b.join(', ')} bundles server code, so the preload may not see the provider SDK.\n` +
    '                      Keep it external to the bundle (Next.js: serverExternalPackages), or wrap the\n' +
    '                      client once with avowa.instrumentOpenAI(client).')
  return out
}

function nodeOk() {
  const [maj, min] = process.versions.node.split('.').map(Number)
  return maj > 20 || (maj === 20 && min >= 6) || (maj === 18 && min >= 18) || maj === 19
}

function gitignore(dry) {
  if (!fs.existsSync('.gitignore') && !fs.existsSync('.git')) return null
  let lines = []
  try { lines = fs.readFileSync('.gitignore', 'utf8').split(/\r?\n/) } catch { /* no file yet */ }
  if (lines.some((l) => ['avowa.env', '/avowa.env', '*.env'].includes(l.trim()))) return '.gitignore    : already ignores avowa.env'
  if (dry) return '.gitignore    : would add avowa.env'
  try {
    const sep = lines.length && lines[lines.length - 1] !== '' ? '\n' : ''
    fs.appendFileSync('.gitignore', sep + 'avowa.env\n')
  } catch { return '.gitignore    : could not be updated. Add the line avowa.env yourself; the file holds a secret.' }
  return '.gitignore    : added avowa.env (the file holds a secret)'
}

// The scripts that start the app with plain `node`, and what each would become.
function startScripts(pkg) {
  const out = []
  for (const name of ['start', 'dev', 'serve']) {
    const cmd = pkg && pkg.scripts && pkg.scripts[name]
    if (typeof cmd !== 'string' || cmd.includes(REGISTER)) continue
    const m = cmd.match(/^(\s*(?:[A-Z_]+=\S+\s+)*node\s)(.*)$/)
    if (m) out.push({ name, from: cmd, to: `${m[1]}--import ${REGISTER} ${m[2]}` })
  }
  return out
}
const wired = (pkg) => (process.env.NODE_OPTIONS || '').includes(REGISTER) ||
  Object.values((pkg && pkg.scripts) || {}).some((c) => typeof c === 'string' && c.includes(REGISTER))

function ask(question) {
  if (!process.stdin.isTTY) return Promise.resolve(false)
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  return new Promise((ok) => rl.question(question + ' [y/N] ', (a) => { rl.close(); ok(/^y(es)?$/i.test(a.trim())) }))
}

async function redeem(token, api) {
  const [base, problem] = checkedBase(api)
  if (problem) return [null, problem.replace('AVOWA_BASE_URL', '--api') + '.']
  // One retry: in a container that has just started, the very first connection can fail once
  // (seen 2026-11-17 in a fresh node:22-slim) and succeed a second later. The token is spent only
  // by a request the server answers, so retrying a request that never arrived is safe.
  let r
  for (let attempt = 1; ; attempt++) {
    try {
      r = await fetch(base + '/public/sdk/setup', { method: 'POST', body: JSON.stringify({ token }),
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'avowa-runtime-js (+https://avowa.ai)' },
        signal: AbortSignal.timeout(15000) })
      break
    } catch (e) {
      if (attempt < 2) { await new Promise((ok) => setTimeout(ok, 1500)); continue }
      const why = (e.cause && (e.cause.code || e.cause.message)) || e.name
      return [null, `Could not reach ${base} (${why}). Check the address and that this machine can reach it, or pass --api with your Avowa API URL. The setup token was not used.`]
    }
  }
  if (r.status === 404) return [null, 'That setup token is invalid, expired (24h) or already used. Generate a new one in the console.']
  if (!r.ok) return [null, `${base} answered HTTP ${r.status}.`]
  const creds = await r.json()
  if (creds.connector_id !== 'runtime_sdk') return [null, 'That token belongs to a Collector connection, not the Runtime SDK.']
  const [b, p] = checkedBase(creds.base_url || base)
  if (p) return [null, `The server returned an unsafe API URL (${p}); nothing was written.`]
  return [{ ...creds, base_url: b }, null]
}

async function init(args) {
  const dry = args.includes('--dry-run')
  const yes = args.includes('--yes')
  let api = (process.env.AVOWA_BASE_URL || 'https://api.avowa.ai').replace(/\/+$/, '')
  const i = args.indexOf('--api')
  if (i >= 0) {
    if (!args[i + 1]) { console.error('--api needs a URL'); return 2 }
    api = args[i + 1].replace(/\/+$/, ''); args = [...args.slice(0, i), ...args.slice(i + 2)]
  }
  const words = args.filter((a) => !a.startsWith('-'))
  const file = path.join(process.cwd(), 'avowa.env')
  const pkg = readPkg()
  const scripts = startScripts(pkg)
  const dep = pkg && !('@avowa/runtime' in deps(pkg)) ? 'dependency    : run `npm install @avowa/runtime` so your build installs it too' : null
  const node = nodeOk() ? null : `node          : ${process.versions.node} has no --import flag (needs 18.18+ or 20.6+). Wrap the client with avowa.instrumentOpenAI(client) instead.`

  if (dry) {
    console.log('npx @avowa/runtime init --dry-run: nothing is changed and no setup token is used.\n')
    console.log(`credentials   : would write ${file} (mode 0600, one line: AVOWA_TOKEN)`)
    for (const l of [gitignore(true), dep, node]) if (l) console.log(l)
    for (const s of scripts) console.log(`package.json  : would offer to change "${s.name}"\n                  from: ${s.from}\n                  to:   ${s.to}`)
    console.log('coverage from package.json:'); console.log(coverage(pkg).join('\n'))
    return 0
  }
  if (!words.length) { console.error(USAGE); return 2 }
  const [, unsafe] = checkedBase(api)
  if (unsafe) { console.error(unsafe.replace('AVOWA_BASE_URL', '--api') + '.'); return 2 }
  const [creds, problem] = await redeem(words[0], api)
  if (problem) { console.error(problem); return 1 }
  const token = makeToken(creds.ingest_token, creds.ingest_secret || '', creds.base_url)
  fs.writeFileSync(file,
    '# Avowa Runtime SDK: the credential for this connection. Keep private, server-side only.\n' +
    '# Written by `npx @avowa/runtime init`. Read from the directory you start your app in.\n' +
    '# In production, put this one value in your secret store as AVOWA_TOKEN instead.\n' +
    `AVOWA_TOKEN=${token}\n`, { mode: 0o600 })
  try { fs.chmodSync(file, 0o600) } catch { /* Windows */ }
  console.log(`connected     : ${creds.label || 'Avowa Runtime SDK'} (${creds.environment || 'prod'})`)
  console.log(`credentials   : ${file} (mode 0600, one line: AVOWA_TOKEN)`)
  for (const l of [gitignore(false), dep, node]) if (l) console.log(l)

  let changed = false
  for (const s of scripts) {
    console.log(`package.json  : "${s.name}" can load Avowa before your app:\n                  from: ${s.from}\n                  to:   ${s.to}`)
    if (yes || await ask('                Make this change?')) {
      const raw = fs.readFileSync('package.json', 'utf8')
      const next = raw.replace(JSON.stringify(s.from), JSON.stringify(s.to))
      if (next !== raw) { fs.writeFileSync('package.json', next); changed = true; console.log('                changed') }
    } else console.log('                left as it is')
  }
  console.log('coverage from package.json:'); console.log(coverage(pkg).join('\n'))
  console.log(await reportSetup(creds.ingest_token, creds.ingest_secret || '', creds.base_url, readPkg(), wired(readPkg())))
  console.log('\nDone.' + (changed ? ' Start your app the way you always do' : ` Start your app with NODE_OPTIONS="--import ${REGISTER}" set`) +
    ', then send one real request that calls the model.\n' +
    '  check      : npx @avowa/runtime status\n' +
    `  production : set AVOWA_TOKEN (the value in avowa.env) and NODE_OPTIONS=--import ${REGISTER}. Nothing else changes.\n` +
    '  off switch : AVOWA_DISABLE=1')
  return 0
}

// Tell the server how the install stands, so the console's checklist can tick: the key and secret
// verify, which covered libraries package.json names, whether the preload is wired. The same
// signed whoami the doctor makes, with one extra header. No signal is sent.
async function reportSetup(key, secret, base, pkg, isWired) {
  const d = deps(pkg)
  const covered = ['openai', '@anthropic-ai/sdk'].filter((n) => n in d)
  const ts = String(Math.floor(Date.now() / 1000))
  const headers = { 'X-Ingest-Key': key, 'X-Avowa-Timestamp': ts,
    'X-Avowa-Signature': crypto.createHmac('sha256', secret || '').update(ts + '.').digest('hex'),
    'X-Avowa-Setup': `wired=${isWired ? 1 : 0}; covered=${covered.join(',')}`,
    'User-Agent': `avowa-runtime-js/${VERSION} (+https://avowa.ai)` }
  try {
    const r = await fetch(base + '/ingest/whoami', { headers, signal: AbortSignal.timeout(8000) })
    if (!r.ok) return `server check  : could not confirm (HTTP ${r.status}). Run \`npx @avowa/runtime status\` to see why.`
    const who = await r.json()
    if (!who.signature_ok) return 'server check  : the secret did NOT verify. Run `npx @avowa/runtime status`.'
    if (!who.capture_allowed) return "server check  : key accepted, but this workspace's plan does not allow capture yet"
    return 'server check  : key and signature accepted (your console card now shows this step done)'
  } catch (e) { return `server check  : could not confirm (${e.name}). Run \`npx @avowa/runtime status\` to see why.` }
}

// Asks the server who this key is. Sends no signal: a synthetic one would show on the trust
// profile as inference that never happened.
async function doctor() {
  const found = loadEnv()
  const tok = process.env.AVOWA_TOKEN ? readToken(process.env.AVOWA_TOKEN) : null
  const key = process.env.AVOWA_RUNTIME_KEY || (tok && tok[0])
  const secret = process.env.AVOWA_RUNTIME_SECRET || (tok && tok[1])
  const [base, problem] = checkedBase(process.env.AVOWA_BASE_URL || (tok && tok[2]) || undefined)
  console.log(`env file   : ${found || 'not found'}`)
  if (process.env.AVOWA_TOKEN && !tok) { console.log('token      : AVOWA_TOKEN is not a valid Avowa token (one starts with avw1_)'); return 1 }
  if (problem) { console.log('api        : ' + problem); return 1 }
  console.log('api        : ' + base)
  if (!key) { console.log('credential : MISSING. Run `npx @avowa/runtime init <setup-token>` or set AVOWA_TOKEN'); return 1 }
  const ts = String(Math.floor(Date.now() / 1000))
  const headers = { 'X-Ingest-Key': key, 'X-Avowa-Timestamp': ts, 'User-Agent': `avowa-runtime-js/${VERSION} (+https://avowa.ai)` }
  if (secret) headers['X-Avowa-Signature'] = crypto.createHmac('sha256', secret).update(ts + '.').digest('hex')
  let who
  try {
    const r = await fetch(base + '/ingest/whoami', { headers, signal: AbortSignal.timeout(8000) })
    if (r.status === 401) { console.log(`credential : REJECTED by ${base}. Not a key this server knows (rotated or revoked?)`); return 1 }
    if (!r.ok) { console.log(`api        : ${base} answered HTTP ${r.status}`); return 1 }
    who = await r.json()
  } catch (e) { console.log(`api        : NOT reachable from this host (${e.name})`); return 1 }
  let ok = true
  console.log(`connection : ${who.label || who.connection_id} · ${who.environment}`)
  if (who.capture_allowed) console.log('plan       : capture allowed')
  else { console.log('plan       : capture NOT allowed. The workspace is on Declare; signals will get 402'); ok = false }
  if (!secret) { console.log('secret     : not set. Signals would be sent unsigned and refused'); ok = false }
  else if (who.signature_ok) console.log('secret     : signs correctly')
  else { console.log('secret     : does NOT verify. Every signal would get 401'); ok = false }
  if (typeof who.clock_skew_s === 'number') {
    const s = who.clock_skew_s
    console.log(`clock      : ${s >= 0 ? '+' : ''}${Math.round(s)}s vs server${Math.abs(s) < 120 ? '' : '. Over 5 minutes is rejected; fix NTP'}`)
    ok = ok && Math.abs(s) < 300
  }
  console.log(`last event : ${who.last_event_at || 'never'} (${who.events_total || 0} total)`)
  console.log('\nNo signal was sent.' + (ok ? '' : ' Fix the lines marked above, then run again.'))
  return ok ? 0 : 1
}

async function status() {
  const pkg = readPkg()
  console.log(`node          : ${process.versions.node}${nodeOk() ? '' : ' (no --import flag: needs 18.18+ or 20.6+)'}`)
  console.log(`preload       : ${wired(pkg) ? 'wired (' + REGISTER + ')' : 'NOT wired. Set NODE_OPTIONS="--import ' + REGISTER + '" or run init'}`)
  console.log('coverage from package.json:'); console.log(coverage(pkg).join('\n'))
  loadEnv()
  const tok = process.env.AVOWA_TOKEN ? readToken(process.env.AVOWA_TOKEN) : null
  const key = process.env.AVOWA_RUNTIME_KEY || (tok && tok[0])
  const secret = process.env.AVOWA_RUNTIME_SECRET || (tok && tok[1])
  const [base] = checkedBase(process.env.AVOWA_BASE_URL || (tok && tok[2]) || undefined)
  if (key && secret && base) await reportSetup(key, secret, base, pkg, wired(pkg))     // refreshes the console checklist
  console.log('server check:')
  return doctor()
}

const [cmd, ...rest] = process.argv.slice(2)
let code
if (cmd === 'init') code = await init(rest)
else if (cmd === 'status') code = await status()
else if (cmd === 'doctor') code = await doctor()
else { console.error(USAGE); code = cmd && !['-h', '--help', 'help'].includes(cmd) ? 2 : (cmd ? 0 : 2) }
process.exitCode = code
