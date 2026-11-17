// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avowa, Inc.
import fs from 'node:fs';
import path from 'node:path';
const on = v => ['1', 'true', 'yes', 'on'].includes(String(v || '').trim().toLowerCase());
export function loadEnv(file) {
  if (on(process.env.AVOWA_NO_ENV_FILE)) return null;
  const candidates = [];
  const explicit = file || process.env.AVOWA_ENV_FILE;
  if (explicit) candidates.push(explicit);else {
    let d = process.cwd();
    for (let i = 0; i < 3; i++) {
      candidates.push(path.join(d, 'avowa.env'), path.join(d, '.env'));
      const parent = path.dirname(d);
      if (parent === d) break;
      d = parent;
    }
  }
  for (const cand of candidates) {
    let text;
    try {
      text = fs.readFileSync(cand, 'utf8');
    } catch {
      continue;
    }
    let found = false;
    for (let line of text.split(/\r?\n/)) {
      line = line.trim();
      if (!line || line.startsWith('#')) continue;
      if (line.startsWith('export ')) line = line.slice(7).trimStart();
      const i = line.indexOf('=');
      if (i < 1) continue;
      const key = line.slice(0, i).trim();
      if (!key.startsWith('AVOWA_')) continue;
      const val = line.slice(i + 1).trim().replace(/^["']|["']$/g, '');
      found = true;
      if (process.env[key] === undefined) process.env[key] = val;
    }
    if (found) return cand;
  }
  return null;
}
