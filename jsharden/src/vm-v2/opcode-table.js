import { mulberry32 } from './keygen.js';
import { BASE_OPCODES, SIMPLE_OPS, FUSED_OPS, ARG_WIDTHS } from './opcodes.js';
function hash32(...parts) {
  let h = 0x811c9dc5 >>> 0;
  for (const p of parts) {
    const s = String(p);
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    h ^= 0x2c;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}
export function buildOpcodeTable(key) {
  if (!key || typeof key.permSeed !== 'number') {
    throw new TypeError('buildOpcodeTable: key.permSeed must be a number (got ' + (key ? typeof key.permSeed : 'no key') + ')');
  }
  const rng = mulberry32(key.permSeed >>> 0);
  const pool = new Array(256);
  for (let i = 0; i < 256; i++) pool[i] = i;
  for (let i = 255; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = pool[i];
    pool[i] = pool[j];
    pool[j] = tmp;
  }
  const aliasCount = Object.create(null);
  let total = 0;
  for (const name of SIMPLE_OPS) {
    const n = 2 + Math.floor(rng() * 3);
    aliasCount[name] = n;
    total += n;
  }
  for (const name of FUSED_OPS) {
    aliasCount[name] = 1;
    total += 1;
  }
  while (total > 256) {
    let reduced = false;
    for (const name of SIMPLE_OPS) {
      if (aliasCount[name] > 2) {
        aliasCount[name]--;
        total--;
        reduced = true;
        if (total <= 256) break;
      }
    }
    if (!reduced) break;
  }
  const encodeMap = Object.create(null);
  const decodeMap = Object.create(null);
  let cursor = 0;
  const takeByte = () => {
    if (cursor >= 256) {
      return pool[cursor++ % 256];
    }
    return pool[cursor++];
  };
  for (const name of SIMPLE_OPS) {
    const n = aliasCount[name];
    const aliases = new Array(n);
    for (let i = 0; i < n; i++) {
      const b = takeByte();
      aliases[i] = b;
      decodeMap[b] = name;
    }
    encodeMap[name] = aliases;
  }
  const fused = Object.create(null);
  for (const name of FUSED_OPS) {
    const b = takeByte();
    encodeMap[name] = [b];
    decodeMap[b] = name;
    fused[b] = name;
  }
  const decoys = [];
  const decoyMap = Object.create(null);
  while (cursor < 256) {
    const b = pool[cursor++];
    const argWidth = Math.floor(rng() * 4);
    decoys.push({
      byte: b,
      argWidth
    });
    decoyMap[b] = argWidth;
  }
  const argWidthMap = Object.create(null);
  for (const name of Object.keys(encodeMap)) {
    const argSpec = BASE_OPCODES[name] && BASE_OPCODES[name].arg;
    const w = ARG_WIDTHS[argSpec] != null ? ARG_WIDTHS[argSpec] : 0;
    for (const b of encodeMap[name]) argWidthMap[b] = w;
  }
  for (const d of decoys) argWidthMap[d.byte] = d.argWidth;
  return {
    encodeMap,
    decodeMap,
    decoys,
    aliasCount,
    fused,
    _argWidthMap: argWidthMap,
    _decoyMap: decoyMap
  };
}
export function pickAlias(table, logicalName, ip, key) {
  const aliases = table.encodeMap[logicalName];
  if (!aliases || aliases.length === 0) {
    throw new Error(`pickAlias: unknown logical opcode: ${logicalName}`);
  }
  if (aliases.length === 1) return aliases[0];
  const seed = hash32(logicalName, ip, key && key.seed != null ? key.seed : 0);
  const r = mulberry32(seed >>> 0);
  const idx = Math.floor(r() * aliases.length) % aliases.length;
  return aliases[idx];
}
export function decodeByte(table, byteValue) {
  const name = table.decodeMap[byteValue];
  return name === undefined ? null : name;
}
export function argWidthFor(table, byteValue) {
  if (table._argWidthMap) {
    const w = table._argWidthMap[byteValue];
    if (w !== undefined) return w;
  }
  const name = table.decodeMap[byteValue];
  if (name !== undefined) {
    const argSpec = BASE_OPCODES[name] && BASE_OPCODES[name].arg;
    return ARG_WIDTHS && ARG_WIDTHS[argSpec] != null ? ARG_WIDTHS[argSpec] : 0;
  }
  if (table._decoyMap && table._decoyMap[byteValue] !== undefined) {
    return table._decoyMap[byteValue];
  }
  if (Array.isArray(table.decoys)) {
    for (const d of table.decoys) {
      if (d.byte === byteValue) return d.argWidth;
    }
  }
  return 0;
}