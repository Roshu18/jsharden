export const WASM_KDF_B64 = 'AGFzbQEAAAABBwFgA39/fwADAgEABQMBAAEHDQIDbWVtAgADa2RmAAAK0gEBzwEBBX9BxbvyiHghBUEAIQQCQANAIARBBE4NAUEAIQMCQANAIANBIE4NASAFIAAgA2otAAAgASADQQxwai0AACAEQQJsdHNzQZODgAhsIQUgA0EBaiEDDAALCyAEQQFqIQQMAAsLIAUhB0EAIQMCQANAIANBIE4NASAHQfXzrekGaiEHIAchBiAGIAZBD3ZzIAZBAXJsIQYgBiAGIAYgBkEHdnMgBkE9cmxqcyEGIAIgA2ogBiAGQQ52c0EYdkH/AXE6AAAgA0EBaiEDDAALCws=';
let _instance = null;
let _mem = null;
let _kdf = null;
export function getWasmKdfInstance() {
  if (_instance) return _instance;
  const bytes = Uint8Array.from(atob(WASM_KDF_B64), c => c.charCodeAt(0));
  const module = new WebAssembly.Module(bytes);
  _instance = new WebAssembly.Instance(module);
  _mem = new Uint8Array(_instance.exports.mem.buffer);
  _kdf = _instance.exports.kdf;
  return _instance;
}
export function wasmKdfSync(sp, probes) {
  if (!sp || sp.length < 32) {
    throw new TypeError('wasmKdfSync: sp must be at least 32 bytes');
  }
  if (!probes || probes.length === 0) {
    throw new TypeError('wasmKdfSync: probes must be non-empty');
  }
  getWasmKdfInstance();
  _mem.set(sp.subarray ? sp.subarray(0, 32) : sp.slice(0, 32), 0);
  const probeLen = Math.min(probes.length, 12);
  for (let i = 0; i < probeLen; i++) _mem[32 + i] = probes[i] & 0xFF;
  _kdf(0, 32, 64);
  return _mem.slice(64, 96);
}