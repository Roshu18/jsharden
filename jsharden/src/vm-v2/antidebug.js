import { mulberry32 } from './keygen.js';
import { fnv1aBytes, keyedIntegrityHash } from './cipher.js';
export { keyedIntegrityHash };
const BASE_TRIP_CODE = 100;
function deriveTripCode(antidebugSeed) {
  const seed = antidebugSeed >>> 0 || 0;
  const rng = mulberry32(seed ^ 0x5a5a5a5a);
  const bits = Math.floor(rng() * 32) & 0x1f;
  return BASE_TRIP_CODE + bits >>> 0;
}
export function keyedFnv1a(bytes, key) {
  let h = 0x811c9dc5;
  const seed = key && typeof key.antidebugSeed === 'number' ? key.antidebugSeed >>> 0 : 0;
  h ^= seed;
  h = Math.imul(h, 0x01000193);
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}
export function makeIntegrityCheck(key) {
  const hasKey = !!(key && typeof key.antidebugSeed === 'number');
  const hasPermKey = !!(key && key.permKey instanceof Uint8Array);
  return function integrityCheck(bytes, expectedHash) {
    try {
      const expected = (expectedHash || 0) >>> 0;
      if (hasKey) {
        if (hasPermKey && keyedIntegrityHash(bytes, key) >>> 0 === expected) return true;
        if (keyedFnv1a(bytes, key) >>> 0 === expected) return true;
      }
      return fnv1aBytes(bytes) >>> 0 === expected;
    } catch (_) {
      return false;
    }
  };
}
const SUSPICIOUS_FRAME_RE = /devtools|injected/i;
export function makeStackCheck(opts) {
  const pattern = opts && opts.pattern instanceof RegExp ? opts.pattern : SUSPICIOUS_FRAME_RE;
  return function stackCheck() {
    try {
      const e = new Error();
      const s = e && e.stack;
      if (typeof s !== 'string') return true;
      if (pattern.test(s)) return false;
      return true;
    } catch (_) {
      return true;
    }
  };
}
export function makeClosureCheck(originalRef) {
  return function closureCheck(currentRef) {
    try {
      return currentRef === originalRef;
    } catch (_) {
      return true;
    }
  };
}
export function makeReplayCheck(opts) {
  const warmup = opts && typeof opts.warmup === 'number' && opts.warmup >= 0 ? Math.floor(opts.warmup) : 3;
  let ticks = 0;
  let lastTicks = 0;
  let checks = 0;
  function tick() {
    try {
      ticks = ticks + 1 >>> 0;
    } catch (_) {}
  }
  function check() {
    try {
      checks = checks + 1 >>> 0;
      if (checks <= warmup) {
        lastTicks = ticks;
        return true;
      }
      const advanced = ticks !== lastTicks;
      lastTicks = ticks;
      return advanced;
    } catch (_) {
      return true;
    }
  }
  return {
    tick,
    check
  };
}
export function makeAntidebugHooks(key, opts) {
  const antidebugSeed = key && typeof key.antidebugSeed === 'number' ? key.antidebugSeed : 0;
  const tripCode = opts && typeof opts.timingThreshold === 'number' && opts.timingThreshold > 0 ? opts.timingThreshold : deriveTripCode(antidebugSeed);
  const integrityCheck = makeIntegrityCheck(key);
  const stackCheck = makeStackCheck();
  const replayCheck = makeReplayCheck();
  function tick() {
    replayCheck.tick();
  }
  function check() {
    if (!stackCheck()) return false;
    if (!replayCheck.check()) return false;
    return true;
  }
  return {
    tick,
    check,
    timingCheck: check,
    integrityCheck,
    stackCheck,
    closureCheckFactory: makeClosureCheck,
    replayCheck,
    _tripCode: tripCode
  };
}