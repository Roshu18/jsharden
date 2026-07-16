import { mulberry32 } from '../vm-v2/keygen.js';
const PROBE_DEFS = [{
  name: 'canvas',
  check: () => typeof document !== 'undefined' && typeof document.createElement === 'function'
}, {
  name: 'chrome',
  check: () => typeof window !== 'undefined' && typeof window.chrome === 'object'
}, {
  name: 'userAgent',
  check: () => typeof navigator !== 'undefined' && typeof navigator.userAgent === 'string'
}, {
  name: 'plugins',
  check: () => typeof navigator !== 'undefined' && typeof navigator.plugins === 'object'
}, {
  name: 'performanceNow',
  check: () => typeof performance !== 'undefined' && typeof performance.now === 'function'
}, {
  name: 'raf',
  check: () => typeof requestAnimationFrame === 'function'
}, {
  name: 'documentMode',
  check: () => typeof document !== 'undefined' && typeof document.documentMode === 'number'
}, {
  name: 'outerWidth',
  check: () => typeof window !== 'undefined' && typeof window.outerWidth === 'number'
}, {
  name: 'screen',
  check: () => typeof screen !== 'undefined' && typeof screen.width === 'number'
}, {
  name: 'webgl',
  check: () => {
    if (typeof document === 'undefined' || typeof document.createElement !== 'function') return false;
    try {
      const c = document.createElement('canvas');
      return typeof c.getContext === 'function';
    } catch (_) {
      return false;
    }
  }
}, {
  name: 'fonts',
  check: () => typeof document !== 'undefined' && typeof document.fonts !== 'undefined'
}, {
  name: 'storage',
  check: () => {
    try {
      return typeof localStorage !== 'undefined';
    } catch (_) {
      return false;
    }
  }
}, {
  name: 'indexedDB',
  check: () => typeof indexedDB !== 'undefined'
}, {
  name: 'crypto',
  check: () => typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined'
}, {
  name: 'pointer',
  check: () => typeof window !== 'undefined' && typeof window.ontouchstart !== 'undefined'
}, {
  name: 'hardwareConcurrency',
  check: () => typeof navigator !== 'undefined' && typeof navigator.hardwareConcurrency === 'number'
}];
export const PROBES = Object.freeze(PROBE_DEFS.map(({
  name,
  check
}) => {
  const run = () => {
    try {
      return check() ? 1 : 0xFF;
    } catch (_) {
      return 0xFF;
    }
  };
  return Object.freeze({
    name,
    run
  });
}));
export const PROBE_POOL = PROBES;
export function selectProbes(seed, count = 8) {
  const s = seed >>> 0;
  const rng = mulberry32(s ^ 0xFEEDBEEF);
  const indices = PROBES.map((_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = indices[i];
    indices[i] = indices[j];
    indices[j] = t;
  }
  let n = Math.floor(count);
  if (!Number.isFinite(n) || n < 0) n = 0;
  if (n > PROBES.length) n = PROBES.length;
  return indices.slice(0, n).map(i => PROBES[i]);
}