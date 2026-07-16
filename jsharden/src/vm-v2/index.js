import { compileFunction as compileFunctionV2 } from './compiler.js';
import { runtimeSource as runtimeSourceV2 } from './runtime-source.js';
import { generateKey } from './keygen.js';
import { keyedIntegrityHash } from './cipher.js';
export { generateKey };
export function compileFunction(src, opts = {}) {
  const key = opts.key || generateKey(opts.seed);
  return compileFunctionV2(src, key);
}
export function runtimeSource(key, runtimeOpts) {
  return runtimeSourceV2(key, runtimeOpts);
}
export function compileAndRun(src, args = [], env = {}) {
  const key = env.key || generateKey(0xC0FFEE);
  const result = compileFunctionV2(src, key);
  if (!result.canCompile) throw new Error('bail: ' + result.error);
  const defaults = {
    Object,
    Array,
    RegExp,
    Math,
    JSON,
    Date,
    Error,
    Promise,
    Function
  };
  const captures = result.captures.map(n => {
    if (env.captures && n in env.captures) return env.captures[n];
    if (n in defaults) return defaults[n];
    if (n in globalThis) return globalThis[n];
    return undefined;
  });
  const integrityHash = keyedIntegrityHash(result.bytecode, key) >>> 0;
  const shippingCreateVM = new Function(runtimeSourceV2(key, {
    antidebug: env.antidebug !== false,
    integrityHash
  }) + '\n; return createVM;')();
  const vm = shippingCreateVM({
    strings: result.strings,
    captures,
    key,
    antidebug: env.antidebug !== false,
    integrityHash
  });
  return vm.execute(result.bytecode, args);
}