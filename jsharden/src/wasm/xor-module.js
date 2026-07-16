export const WASM_BASE64 = 'AGFzbQEAAAABCAFgBH9/f38AAwIBAAUDAQABBxMCBm1lbW9yeQIABmRlY29kZQAACj8BPQECfwJAA0AgBCABTg0BIAAgBGogACAEai0AACACIAUgA29qLQAAczoAACAEQQFqIQQgBUEBaiEFDAALCws=';
let _instance = null;
let _mem = null;
let _decode = null;
let _instancePromise = null;
export function getXorModule() {
  if (_instancePromise) return _instancePromise;
  _instancePromise = (async () => {
    const bytes = Uint8Array.from(atob(WASM_BASE64), c => c.charCodeAt(0));
    const {
      instance
    } = await WebAssembly.instantiate(bytes, {});
    _instance = instance;
    _mem = instance.exports.memory;
    _decode = instance.exports.decode;
    return _instance;
  })().catch(err => {
    _instancePromise = null;
    throw err;
  });
  return _instancePromise;
}
export function xorDecodeSync(encryptedBytes, keyBytes) {
  if (!keyBytes || keyBytes.length === 0) {
    throw new Error('xorDecodeSync: key must be non-empty');
  }
  if (!encryptedBytes) {
    throw new Error('xorDecodeSync: encryptedBytes required');
  }
  if (!_decode) throw new Error('WASM module not loaded — call getXorModule() first');
  const needed = encryptedBytes.length + keyBytes.length + 16;
  const pagesNeeded = Math.max(0, Math.ceil(needed / 65536) - (_mem.buffer.byteLength / 65536 | 0));
  if (pagesNeeded > 0) _mem.grow(pagesNeeded);
  const buf = new Uint8Array(_mem.buffer);
  const dataPtr = 0;
  const keyPtr = encryptedBytes.length + 8;
  buf.set(encryptedBytes, dataPtr);
  buf.set(keyBytes, keyPtr);
  _decode(dataPtr, encryptedBytes.length, keyPtr, keyBytes.length);
  return buf.slice(dataPtr, dataPtr + encryptedBytes.length);
}
export function xorEncrypt(plainBytes, keyBytes) {
  return xorDecodeSync(plainBytes, keyBytes);
}