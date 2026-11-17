// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avowa, Inc.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { makeToken, readToken } from './avowa-runtime.js';
import { loadEnv } from './env.js';
const here = path.dirname(fileURLToPath(import.meta.url));
const REGISTER = pathToFileURL(path.join(here, 'register.js')).href;
const RUNTIME = pathToFileURL(path.join(here, 'avowa-runtime.js')).href;
const servers = [];
const dirs = [];
after(() => {
  for (const s of servers) {
    if (s.closeAllConnections) s.closeAllConnections();
    s.close();
  }
  for (const d of dirs) fs.rmSync(d, {
    recursive: true,
    force: true
  });
});
function avowaServer() {
  const got = [];
  const srv = http.createServer((req, res) => {
    if (req.method === 'GET') {
      res.writeHead(200);
      res.end(String(got.length));
      return;
    }
    let body = '';
    req.on('data', c => {
      body += c;
    });
    req.on('end', () => {
      const parsed = JSON.parse(body || '{}');
      for (const ev of parsed.events || []) got.push({
        headers: req.headers,
        body: ev,
        envelope: parsed
      });
      res.writeHead(200);
      res.end('{}');
    });
  });
  servers.push(srv);
  return new Promise(ok => srv.listen(0, '127.0.0.1', () => ok({
    got,
    url: `http://127.0.0.1:${srv.address().port}`
  })));
}
const PROVIDER = exportLine => `
class Completions {
  constructor(client) { this._client = client }
  create(params) { return Promise.resolve({ model: params.model + '-served', choices: [{ finish_reason: 'stop', message: { content: 'hi' } }], usage: { prompt_tokens: 3, completion_tokens: 1 } }) }
}
class Chat { constructor(client) { this.completions = new Completions(client) } }
Chat.Completions = Completions
class OpenAI {
  constructor(o = {}) { this.baseURL = o.baseURL || 'https://api.openai.com/v1'; this.maxRetries = 2; this.chat = new Chat(this) }
}
OpenAI.Chat = Chat
${exportLine}
`;
function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'avowa-register-'));
  dirs.push(dir);
  const pkg = path.join(dir, 'node_modules', 'openai');
  fs.mkdirSync(pkg, {
    recursive: true
  });
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({
    name: 'openai',
    version: '9.9.9',
    exports: {
      '.': {
        require: {
          default: './index.js'
        },
        default: './index.mjs'
      }
    }
  }));
  fs.writeFileSync(path.join(pkg, 'index.js'), PROVIDER('module.exports = OpenAI; module.exports.OpenAI = OpenAI; module.exports.default = OpenAI'));
  fs.writeFileSync(path.join(pkg, 'index.mjs'), PROVIDER('export { OpenAI }; export default OpenAI'));
  for (const [name, text] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), text);
  return dir;
}
function run(dir, script, env, preload = true) {
  const args = preload ? ['--import', REGISTER, script] : [script];
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('AVOWA_')));
  return new Promise(ok => {
    const child = spawn(process.execPath, args, {
      cwd: dir,
      env: {
        ...clean,
        AVOWA_STRICT: '1',
        ...env
      }
    });
    let out = '',
      err = '';
    child.stdout.on('data', c => {
      out += c;
    });
    child.stderr.on('data', c => {
      err += c;
    });
    child.on('close', code => ok({
      code,
      out,
      err
    }));
  });
}
const WAIT = `{
  const want = Number(process.env.TEST_EXPECT || 0), url = process.env.TEST_AVOWA
  const until = Date.now() + (want ? 5000 : 300)
  while (Date.now() < until) {
    if (want && Number(await (await fetch(url)).text()) >= want) break
    await new Promise((ok) => setTimeout(ok, 25))
  }
}`;
const ESM_APP = `import OpenAI from 'openai'
const c = new OpenAI({ baseURL: 'https://eu.example.test/v1' })
const r = await c.chat.completions.create({ model: 'gpt-x', messages: [{ role: 'user', content: 'hello' }] })
await c.chat.completions.create({ model: 'gpt-x', messages: [{ role: 'user', content: 'again' }] })
console.log('app:' + r.choices[0].message.content)
${WAIT}
`;
const CJS_APP = `const OpenAI = require('openai')
;(async () => {
  const c = new OpenAI()
  const r = await c.chat.completions.create({ model: 'gpt-x', messages: [{ role: 'user', content: 'hello' }] })
  console.log('app:' + r.choices[0].message.content)
  ${WAIT}
})()
`;
const BOTH_APP = `import OpenAI from 'openai'
import { createAvowa } from ${JSON.stringify(RUNTIME)}
const c = createAvowa().instrumentOpenAI(new OpenAI())
await c.chat.completions.create({ model: 'gpt-x', messages: [{ role: 'user', content: 'hello' }] })
console.log('app:done')
${WAIT}
await new Promise((ok) => setTimeout(ok, 300))    // long enough for a second, wrong, signal to land
`;
test('AVOWA_TOKEN round-trips, and a wrong value is not a token', () => {
  const t = makeToken('ik_1', 'avs_2', 'https://api.example.test/');
  assert.ok(t.startsWith('avw1_') && !t.includes('='));
  assert.deepEqual(readToken(t), ['ik_1', 'avs_2', 'https://api.example.test']);
  assert.equal(readToken('nope'), null);
  assert.equal(readToken('avw1_!!!'), null);
  assert.equal(readToken(''), null);
});
test('loadEnv reads only AVOWA_* keys, and a real environment variable wins', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'avowa-env-'));
  dirs.push(dir);
  const file = path.join(dir, 'avowa.env');
  fs.writeFileSync(file, '# note\nDATABASE_URL=postgres://secret\nexport AVOWA_TEST_ONE="from-file"\nAVOWA_TEST_TWO=from-file\n');
  process.env.AVOWA_TEST_TWO = 'from-env';
  try {
    assert.equal(loadEnv(file), file);
    assert.equal(process.env.AVOWA_TEST_ONE, 'from-file');
    assert.equal(process.env.AVOWA_TEST_TWO, 'from-env');
    assert.equal(process.env.DATABASE_URL, undefined);
  } finally {
    delete process.env.AVOWA_TEST_ONE;
    delete process.env.AVOWA_TEST_TWO;
  }
});
test('the preload covers an ES-module app with no code change, reading the token from avowa.env', async () => {
  const {
    got,
    url
  } = await avowaServer();
  const dir = project({
    'app.mjs': ESM_APP,
    'avowa.env': `AVOWA_TOKEN=${makeToken('ik_esm', 'avs_secret', url)}\n`
  });
  const r = await run(dir, 'app.mjs', {
    TEST_EXPECT: '2',
    TEST_AVOWA: url
  });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /app:hi/);
  assert.equal(got.length, 2, 'one signal per call');
  assert.equal(got[0].headers['x-ingest-key'], 'ik_esm');
  assert.ok(got[0].headers['x-avowa-signature'], 'signed with the secret inside the token');
  assert.equal(got[0].body.model, 'gpt-x-served');
  assert.equal(got[0].body.requested_model, 'gpt-x');
  assert.equal(got[0].body.endpoint, 'eu.example.test');
  assert.ok(!JSON.stringify(got[0].body).includes('hello'), 'no prompt text leaves the process');
});
test('the preload covers a CommonJS app, with the token in the environment', async () => {
  const {
    got,
    url
  } = await avowaServer();
  const dir = project({
    'app.cjs': CJS_APP
  });
  const r = await run(dir, 'app.cjs', {
    AVOWA_TOKEN: makeToken('ik_cjs', 'avs_secret', url),
    TEST_EXPECT: '1',
    TEST_AVOWA: url
  });
  assert.equal(r.code, 0, r.err);
  assert.equal(got.length, 1);
  assert.equal(got[0].headers['x-ingest-key'], 'ik_cjs');
  assert.equal(got[0].body.endpoint, 'api.openai.com');
});
test('a client that is also wrapped by hand is counted once', async () => {
  const {
    got,
    url
  } = await avowaServer();
  const dir = project({
    'app.mjs': BOTH_APP
  });
  const r = await run(dir, 'app.mjs', {
    AVOWA_TOKEN: makeToken('ik_both', 'avs_secret', url),
    TEST_EXPECT: '1',
    TEST_AVOWA: url
  });
  assert.equal(r.code, 0, r.err);
  assert.equal(got.length, 1);
});
test('AVOWA_DISABLE=1 patches nothing and sends nothing; so does running without the preload', async () => {
  const {
    got,
    url
  } = await avowaServer();
  const dir = project({
    'app.mjs': ESM_APP
  });
  const token = makeToken('ik_off', 'avs_secret', url);
  const off = await run(dir, 'app.mjs', {
    AVOWA_TOKEN: token,
    AVOWA_DISABLE: '1'
  });
  assert.equal(off.code, 0, off.err);
  assert.match(off.out, /app:hi/);
  const plain = await run(dir, 'app.mjs', {
    AVOWA_TOKEN: token
  }, false);
  assert.equal(plain.code, 0, plain.err);
  assert.equal(got.length, 0);
});
test('with no credentials and no provider package the app still starts and runs', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'avowa-bare-'));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, 'app.mjs'), "console.log('app:ok')\n");
  const r = await run(dir, 'app.mjs', {
    AVOWA_STRICT: ''
  });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /app:ok/);
});
