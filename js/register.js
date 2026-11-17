// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avowa, Inc.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { createAvowa } from './avowa-runtime.js';
import { loadEnv } from './env.js';
const on = v => ['1', 'true', 'yes', 'on'].includes(String(v || '').trim().toLowerCase());
const debug = msg => {
  if (on(process.env.AVOWA_DEBUG)) console.error('[avowa:debug] ' + msg);
};
const TARGETS = {
  'openai': {
    kind: 'openai',
    root: 'OpenAI',
    methods: [['Chat', 'Completions', 'create'], ['Responses', 'create']]
  },
  '@anthropic-ai/sdk': {
    kind: 'anthropic',
    root: 'Anthropic',
    methods: [['Messages', 'create']]
  }
};
export const instrumented = [];
let avowa = null;
function patchModule(name, mod, flavour) {
  const t = TARGETS[name];
  if (!t || !mod || !avowa) return;
  const root = mod[t.root] || mod.default && (mod.default[t.root] || mod.default);
  if (typeof root !== 'function') return;
  for (const p of t.methods) {
    const method = p[p.length - 1];
    let cls = root;
    for (const seg of p.slice(0, -1)) cls = cls && cls[seg];
    const proto = cls && cls.prototype;
    if (!proto || typeof proto[method] !== 'function' || proto[method]._avowa_class_patch) continue;
    const original = proto[method];
    const shim = function (...args) {
      try {
        const own = Object.prototype.hasOwnProperty.call(this, method) ? this[method] : null;
        if (own && own._avowa_wrapped) return original.apply(this, args);
        avowa._wrapResource(this, method, t.kind, original);
        const wrapped = Object.prototype.hasOwnProperty.call(this, method) ? this[method] : null;
        if (wrapped && wrapped._avowa_wrapped) return wrapped.apply(this, args);
      } catch {}
      return original.apply(this, args);
    };
    shim._avowa_class_patch = true;
    try {
      proto[method] = shim;
      const label = `${name} ${p.join('.')} (${flavour})`;
      instrumented.push(label);
      debug('patched ' + label);
    } catch {}
  }
}
function esmEntry(cjsEntry, name) {
  let dir = path.dirname(cjsEntry);
  for (let i = 0; i < 6; i++) {
    const pj = path.join(dir, 'package.json');
    if (fs.existsSync(pj)) {
      let pkg;
      try {
        pkg = JSON.parse(fs.readFileSync(pj, 'utf8'));
      } catch {
        return null;
      }
      if (pkg.name !== name) {
        dir = path.dirname(dir);
        continue;
      }
      const pick = e => {
        if (typeof e === 'string') return e;
        if (!e || typeof e !== 'object') return null;
        return pick(e.import) || pick(e.default);
      };
      const dot = pkg.exports && (pkg.exports['.'] !== undefined ? pkg.exports['.'] : pkg.exports);
      const rel = pick(dot) || pkg.module;
      return rel ? path.join(dir, rel) : null;
    }
    dir = path.dirname(dir);
  }
  return null;
}
async function install() {
  if (on(process.env.AVOWA_DISABLE)) {
    debug('AVOWA_DISABLE is set: nothing is patched');
    return;
  }
  const found = loadEnv();
  avowa = createAvowa({
    region: process.env.AVOWA_REGION
  });
  debug(`@avowa/runtime/register active · env file ${found || 'none'}`);
  const nodeModule = createRequire(import.meta.url)('node:module');
  const load = nodeModule._load;
  nodeModule._load = function (request) {
    const exp = load.apply(this, arguments);
    if (Object.prototype.hasOwnProperty.call(TARGETS, request)) {
      try {
        patchModule(request, exp, 'require');
      } catch {}
    }
    return exp;
  };
  const roots = [];
  if (process.argv[1]) roots.push(path.dirname(path.resolve(process.argv[1])));
  roots.push(process.cwd());
  for (const name of Object.keys(TARGETS)) {
    for (const root of roots) {
      let cjs;
      try {
        cjs = createRequire(path.join(root, 'noop.js')).resolve(name);
      } catch {
        continue;
      }
      const esm = esmEntry(cjs, name);
      if (esm && esm !== cjs && fs.existsSync(esm)) {
        try {
          patchModule(name, await import(pathToFileURL(esm).href), 'import');
        } catch {}
      }
      break;
    }
  }
}
try {
  await install();
} catch {}
