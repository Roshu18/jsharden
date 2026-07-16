import { mulberry32 } from '../vm-v2/keygen.js';
import { keystreamByte } from './encrypt.js';
const BROWSER_VALUES = {
  canvas: 255,
  chrome: 255,
  userAgent: 255,
  plugins: 255,
  performanceNow: 87,
  raf: 9,
  documentMode: 87,
  outerWidth: 1,
  screen: 16,
  webgl: 255,
  fonts: 114,
  storage: 98,
  indexedDB: 115,
  crypto: 118,
  pointer: 255,
  hardwareConcurrency: 17
};
const GATE_SEED_XOR = 0xCAFEBABE;
const CANARY_PLAINTEXT = 'canary';
function assertV2Key(key, fnName) {
  const seed = key && key.seed;
  if (typeof seed !== 'number' || !Number.isInteger(seed) || seed < 0 || seed > 0xFFFFFFFF) {
    throw new TypeError(`${fnName}: key.seed must be a uint32 (0 to 4294967295); got ${String(seed)}`);
  }
}
export function generateGateKey(key, selectedProbes) {
  assertV2Key(key, 'generateGateKey');
  if (!Array.isArray(selectedProbes) || selectedProbes.length === 0) {
    throw new TypeError('generateGateKey: selectedProbes must be a non-empty array');
  }
  const baseSeed = key.seed >>> 0;
  const rng = mulberry32((baseSeed ^ GATE_SEED_XOR) >>> 0);
  const storedParts = new Uint8Array(32);
  for (let i = 0; i < 32; i++) storedParts[i] = Math.floor(rng() * 256) & 0xFF;
  const probeCount = selectedProbes.length;
  const expectedResults = new Array(probeCount);
  for (let i = 0; i < probeCount; i++) {
    const name = selectedProbes[i] && selectedProbes[i].name;
    const val = BROWSER_VALUES[name];
    if (val === undefined) {
      expectedResults[i] = 1;
    } else {
      expectedResults[i] = val;
    }
  }
  const gateKey = kdf(storedParts, expectedResults);
  return {
    gateKey,
    storedParts,
    expectedResults
  };
}
export function kdf(SP, probes) {
  const probeCount = probes.length;
  if (probeCount === 0) {
    throw new TypeError('kdf: probes must be non-empty');
  }
  let h = 0x811c9dc5 >>> 0;
  for (let round = 0; round < 4; round++) {
    for (let i = 0; i < 32; i++) {
      h = (h ^ (SP[i] ^ probes[i % probeCount] << round * 2)) >>> 0;
      h = Math.imul(h, 0x01000193) >>> 0;
    }
  }
  const K = new Uint8Array(32);
  let s = h >>> 0;
  for (let i = 0; i < 32; i++) {
    s = s + 0x6D2B79F5 >>> 0;
    let t = s;
    t = Math.imul(t ^ t >>> 15, t | 1);
    t ^= t + Math.imul(t ^ t >>> 7, t | 61);
    K[i] = (t ^ t >>> 14) >>> 24 & 0xFF;
  }
  return K;
}
export function deriveKey(storedParts, actualResults) {
  const probeCount = actualResults.length;
  if (probeCount === 0) {
    throw new TypeError('deriveKey: actualResults must be non-empty');
  }
  return kdf(storedParts, actualResults);
}
export function presenceProbe(checkFn, perBuildConstant = 1) {
  const c = perBuildConstant & 0xFF;
  return () => {
    try {
      return checkFn() ? c : 0;
    } catch (_) {
      return 0;
    }
  };
}
export function generateCanary(gateKey, plaintext = CANARY_PLAINTEXT) {
  if (!(gateKey instanceof Uint8Array) || gateKey.length !== 32) {
    throw new TypeError('generateCanary: gateKey must be a Uint8Array of length 32');
  }
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new TypeError('generateCanary: plaintext must be a non-empty string');
  }
  const plainBytes = new TextEncoder().encode(plaintext);
  const encBytes = new Uint8Array(plainBytes.length);
  for (let i = 0; i < plainBytes.length; i++) {
    encBytes[i] = plainBytes[i] ^ keystreamByte(gateKey, i);
  }
  const encryptedB64 = Buffer.from(encBytes).toString('base64');
  return {
    encryptedB64,
    plaintext
  };
}