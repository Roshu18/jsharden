import { mulberry32 } from './keygen.js';
function fnv1aStr(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}
export function canarySource(key) {
  const nonce = (key.seed >>> 0 ^ 0x5A5A5A5A) & 0xFFFF;
  return 'function __canary(){return ' + nonce + ';}';
}
export function computeSelfHash(key) {
  return fnv1aStr(canarySource(key));
}
function getSelfHash(key) {
  const seed = key.seed >>> 0;
  if (key._selfHash !== undefined && key._selfHashSeed === seed) {
    return key._selfHash;
  }
  const h = computeSelfHash(key);
  key._selfHash = h;
  key._selfHashSeed = seed;
  return h;
}
function deriveStreamKey(streamSeed) {
  const rng = mulberry32(streamSeed);
  const key = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const v = rng();
    const t = v * 0x100000000 | 0;
    key[i] = (t ^ t >>> 16) & 0xFF;
  }
  return key;
}
function getStreamKey(key) {
  const seed = key.streamSeed >>> 0;
  if (key._streamKey && key._streamKeySeed === seed) return key._streamKey;
  const sk = deriveStreamKey(seed);
  key._streamKey = sk;
  key._streamKeySeed = seed;
  return sk;
}
export function streamByte(key, ip, selfHash) {
  const sbox = key.permKey;
  const streamKey = getStreamKey(key);
  if (selfHash === undefined) selfHash = getSelfHash(key);
  const a = key.streamSeed + ip >>> 0;
  const innerIdx = a >>> 8 & 0xFF;
  const inner = (sbox[innerIdx] ^ selfHash >>> (innerIdx & 3) * 8 & 0xFF) & 0xFF;
  const outerIdx = (a & 0xFF ^ inner) & 0xFF;
  const sboxOut = (sbox[outerIdx] ^ selfHash >>> (outerIdx & 3) * 8 & 0xFF) & 0xFF;
  const rotByte = streamKey[ip & 63];
  return (sboxOut ^ rotByte ^ ip >>> 3 & 0xFF) & 0xFF;
}
export function encryptBytecode(bytes, key, selfHash) {
  if (!bytes) return new Uint8Array(0);
  if (!(bytes instanceof Uint8Array) && !Array.isArray(bytes)) {
    throw new TypeError('encryptBytecode: bytes must be Uint8Array or number[]');
  }
  const n = bytes.length;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = bytes[i] ^ streamByte(key, i, selfHash);
  }
  return out;
}
export function decryptBytecode(bytes, key, selfHash) {
  return encryptBytecode(bytes, key, selfHash);
}
export function fnv1aBytes(bytes) {
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}
export function keyedIntegrityHash(bytes, key) {
  const seed = key && typeof key.antidebugSeed === 'number' ? key.antidebugSeed >>> 0 : 0;
  let h = 0x811c9dc5 ^ seed;
  const len = bytes.length;
  h = Math.imul(h ^ len, 0x01000193);
  const pk = key && key.permKey ? key.permKey : null;
  for (let i = 0; i < len; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193);
    if ((i & 15) === 15) {
      h ^= pk ? pk[i & 255] : 0;
      h = Math.imul(h, 0x01000193);
    }
  }
  return h >>> 0;
}