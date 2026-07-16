export function mulberry32(seed) {
  let s = seed >>> 0;
  return function () {
    s = s + 0x6d2b79f5 >>> 0;
    let t = s;
    t = Math.imul(t ^ t >>> 15, t | 1);
    t ^= t + Math.imul(t ^ t >>> 7, t | 61);
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}
function murmur3Finish(h) {
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}
export function shuffledBytes(seed) {
  const rng = mulberry32(seed >>> 0);
  const arr = new Uint8Array(256);
  for (let i = 0; i < 256; i++) arr[i] = i;
  for (let i = 255; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = arr[i];
    arr[i] = arr[j];
    arr[j] = t;
  }
  return arr;
}
const MIX_PERM = {
  mul: 0xcc9e2d51,
  xor: 0x9E3779B9
};
const MIX_STREAM = {
  mul: 0x1b873593,
  xor: 0xBB67AE85
};
const MIX_STRING = {
  mul: 0x85ebca6b,
  xor: 0x3C6EF372
};
const MIX_ANTIDEBUG = {
  mul: 0xc2b2ae35,
  xor: 0xA54FF53A
};
function mixSub(seed, mix) {
  return murmur3Finish((Math.imul(seed, mix.mul) ^ mix.xor) >>> 0);
}
export function generateKey(seed) {
  if (seed === undefined) {
    seed = Math.random() * 0x100000000 >>> 0;
  }
  if (!Number.isInteger(seed) || seed < 0 || seed > 0xFFFFFFFF) {
    throw new TypeError('generateKey: seed must be a uint32 (0 to 4294967295); got ' + String(seed));
  }
  seed = seed >>> 0;
  return {
    seed,
    permSeed: mixSub(seed, MIX_PERM),
    streamSeed: mixSub(seed, MIX_STREAM),
    stringSeed: mixSub(seed, MIX_STRING),
    antidebugSeed: mixSub(seed, MIX_ANTIDEBUG),
    permKey: shuffledBytes(seed)
  };
}
export function validateKey(key) {
  if (!key || typeof key !== 'object') {
    throw new TypeError('validateKey: key must be an object');
  }
  const fields = ['seed', 'permSeed', 'streamSeed', 'stringSeed', 'antidebugSeed'];
  for (const f of fields) {
    const v = key[f];
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 0xFFFFFFFF) {
      throw new TypeError(`validateKey: key.${f} must be a uint32; got ${String(v)}`);
    }
  }
  if (!(key.permKey instanceof Uint8Array) || key.permKey.length !== 256) {
    throw new TypeError('validateKey: key.permKey must be a Uint8Array of length 256');
  }
  const seen = new Uint8Array(256);
  for (let i = 0; i < 256; i++) seen[key.permKey[i]] = 1;
  for (let i = 0; i < 256; i++) {
    if (!seen[i]) {
      throw new TypeError(`validateKey: permKey is not a permutation (missing byte ${i})`);
    }
  }
  return true;
}
export function deriveSubkeys(key) {
  return {
    permKey: key.permKey,
    streamKey: shuffledBytes(key.streamSeed).subarray(0, 64),
    stringKey: shuffledBytes(key.stringSeed).subarray(0, 32),
    antidebugKey: shuffledBytes(key.antidebugSeed).subarray(0, 16)
  };
}