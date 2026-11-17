// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avowa, Inc.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAvowa } from './avowa-runtime.js';
const here = path.dirname(fileURLToPath(import.meta.url));
const {
  scenarios
} = JSON.parse(fs.readFileSync(path.join(here, '..', 'conformance', 'runtime-scenarios.json'), 'utf8'));
const servers = [];
after(() => servers.forEach(s => {
  if (s.closeAllConnections) s.closeAllConnections();
  s.close();
}));
function avowa() {
  const got = [];
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => {
      body += c;
    });
    req.on('end', () => {
      for (const ev of JSON.parse(body).events || []) got.push(ev);
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
async function arrived(got, n, ms = 3000) {
  const until = Date.now() + ms;
  while (got.length < n && Date.now() < until) await new Promise(r => setTimeout(r, 10));
}
const sorted = v => Array.isArray(v) ? [...v].sort() : v;
for (const sc of scenarios) {
  test(`contract: ${sc.name}`, async () => {
    const {
      got,
      url
    } = await avowa();
    const sdk = createAvowa({
      ingestKey: 'k',
      ingestSecret: 's',
      baseUrl: url
    });
    const call = async () => {
      if (sc.raise) {
        const e = new Error(sc.raise.message);
        e.status = sc.raise.status;
        e.name = sc.raise.class;
        throw e;
      }
      return JSON.parse(JSON.stringify(sc.response));
    };
    const client = sc.provider === 'anthropic' ? {
      baseURL: sc.base_url,
      messages: {
        create: call
      }
    } : {
      baseURL: sc.base_url,
      chat: {
        completions: {
          create: call
        }
      },
      responses: {
        create: call
      }
    };
    sc.provider === 'anthropic' ? sdk.instrumentAnthropic(client) : sdk.instrumentOpenAI(client);
    const target = sc.provider === 'anthropic' ? client.messages : sc.api === 'responses' ? client.responses : client.chat.completions;
    const req = JSON.parse(JSON.stringify(sc.request));
    if (sc.raise) await assert.rejects(target.create(req));else await target.create(req);
    await arrived(got, 1);
    assert.equal(got.length, 1, 'one event per model call');
    const ev = got[0];
    for (const [k, v] of Object.entries(sc.expect)) {
      assert.deepEqual(sorted(ev[k]), sorted(v), `${k} = ${JSON.stringify(ev[k])}, expected ${JSON.stringify(v)}`);
    }
    const missing = (sc.observed || []).filter(k => !(ev._sdk_observed || []).includes(k));
    assert.deepEqual(missing, [], 'not marked observed');
    for (const k of sc.absent || []) assert.equal(ev[k], undefined, `${k} must not be sent`);
    assert.ok(!JSON.stringify(ev).includes('SECRET'), 'text left the process');
  });
}
