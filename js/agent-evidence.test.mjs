// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avowa, Inc.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
process.env.AVOWA_STRICT = '1';
import { createAvowa, callRef, agentContext, approval, toolOutcome } from './avowa-runtime.js';
const servers = [];
let firstEnvelopes = null;
after(() => servers.forEach(s => {
  if (s.closeAllConnections) s.closeAllConnections();
  s.close();
}));
function avowa() {
  const envelopes = [];
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => {
      body += c;
    });
    req.on('end', () => {
      envelopes.push(JSON.parse(body));
      res.writeHead(200);
      res.end('{}');
    });
  });
  servers.push(srv);
  return new Promise(ok => srv.listen(0, '127.0.0.1', () => ok({
    envelopes,
    url: `http://127.0.0.1:${srv.address().port}`
  })));
}
test('callRef is the same 20-hex hash the Python SDK computes', () => {
  assert.equal(callRef('toolu_9'), 'bb2a67311d6c3d467761');
  assert.equal(callRef(''), null);
});
test('an approval and an outcome travel as annotations, never as events, and never carry the id', async () => {
  const {
    envelopes,
    url
  } = await avowa();
  const sdk = createAvowa({
    ingestKey: 'k',
    ingestSecret: 's',
    baseUrl: url
  });
  firstEnvelopes = envelopes;
  await sdk.approval('toolu_9', true, 'finance_ops', {
    approverType: 'human'
  });
  await sdk.toolOutcome('toolu_9', 'denied');
  await sdk.approval('toolu_9', false, 'Jane Smith <jane@example.com>', {
    approverType: 'policy',
    policyRef: 'refund-limit'
  });
  const anns = envelopes.flatMap(e => e.annotations || []);
  assert.deepEqual(envelopes.flatMap(e => e.events), []);
  assert.deepEqual(anns.map(a => [a.type, a.tool_call_ref, a.approved ?? a.outcome, a.approver_role, a.approver_type, a.policy_ref]), [['approval', 'bb2a67311d6c3d467761', true, 'finance_ops', 'human', undefined], ['outcome', 'bb2a67311d6c3d467761', 'denied', undefined, undefined, undefined], ['approval', 'bb2a67311d6c3d467761', false, undefined, 'policy', 'refund-limit']]);
  assert.ok(!JSON.stringify(envelopes).includes('toolu_9') && !JSON.stringify(envelopes).includes('jane'));
});
test('an approval that does not say who decided is unknown, never human', async () => {
  const {
    envelopes,
    url
  } = await avowa();
  const sdk = createAvowa({
    ingestKey: 'k',
    ingestSecret: 's',
    baseUrl: url
  });
  const err = console.error;
  console.error = () => {};
  try {
    await sdk.approval('t1', true);
    await sdk.approval('t2', true, null, {
      approverType: 'a manager probably'
    });
  } finally {
    console.error = err;
  }
  assert.deepEqual(envelopes.flatMap(e => e.annotations || []).map(a => a.approver_type), ['unknown', 'unknown']);
});
test('an unknown outcome is not recorded', async () => {
  const {
    envelopes,
    url
  } = await avowa();
  const sdk = createAvowa({
    ingestKey: 'k',
    ingestSecret: 's',
    baseUrl: url
  });
  const err = console.error;
  console.error = () => {};
  try {
    await sdk.toolOutcome('call_1', 'succeeded-ish');
  } finally {
    console.error = err;
  }
  assert.equal(envelopes.length, 0);
});
test('agentContext names the agent and sends the customer only as a keyed hash', async () => {
  const {
    envelopes,
    url
  } = await avowa();
  delete process.env.AVOWA_REF_KEY;
  const sdk = createAvowa({
    ingestKey: 'k',
    ingestSecret: 's',
    baseUrl: url
  });
  await agentContext({
    name: 'billing-agent',
    customer: 'acme-42'
  }, () => sdk.capture({
    model: 'm'
  }));
  await sdk.capture({
    model: 'outside'
  });
  const [inside, outside] = envelopes.flatMap(e => e.events);
  assert.equal(inside.agent_name, 'billing-agent');
  assert.equal(inside.customer_ref, crypto.createHmac('sha256', 's').update('avowa-customer:acme-42').digest('hex').slice(0, 12));
  assert.ok(!JSON.stringify(inside).includes('acme-42'));
  assert.equal(outside.agent_name, undefined, 'the context does not leak out of the block');
});
test('the module-level helpers send through the first runtime created with credentials', async () => {
  await approval('toolu_mod', true);
  await toolOutcome('toolu_mod', 'ok');
  const mine = firstEnvelopes.flatMap(e => e.annotations || []).filter(a => a.tool_call_ref === callRef('toolu_mod'));
  assert.deepEqual(mine.map(a => a.type), ['approval', 'outcome']);
});
