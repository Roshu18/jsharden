import { mulberry32 } from './keygen.js';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function encodeLen(len) {
  if (len < 0) throw new Error('string-pool: negative length');
  const out = [];
  let v = len;
  while (v >= 0x80) {
    out.push(v & 0x7f | 0x80);
    v >>>= 7;
  }
  out.push(v & 0x7f);
  return out;
}
function decodeLen(buf, off) {
  let v = 0;
  let shift = 0;
  let p = off;
  for (let i = 0; i < 7; i++) {
    const b = buf[p++];
    v |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return {
      len: v >>> 0,
      next: p
    };
    shift += 7;
  }
  throw new Error('string-pool: varint at offset ' + off + ' is malformed (no terminator)');
}
function nonceBytes(stringSeed, i, n) {
  const rng = mulberry32((stringSeed ^ i) >>> 0);
  const out = new Uint8Array(n);
  for (let k = 0; k < n; k++) out[k] = rng() * 256 | 0;
  return out;
}
function buildInverseSbox(permKey) {
  const inv = new Uint8Array(256);
  for (let i = 0; i < 256; i++) inv[permKey[i]] = i;
  return inv;
}
function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function encodeStringPool(strings, key) {
  const stringSeed = key.stringSeed >>> 0;
  const sbox = key.permKey;
  const parts = [];
  for (let i = 0; i < strings.length; i++) {
    const utf8 = encoder.encode(strings[i]);
    const nonce = nonceBytes(stringSeed, i, utf8.length);
    const lenBytes = encodeLen(utf8.length);
    for (let j = 0; j < lenBytes.length; j++) parts.push(lenBytes[j]);
    for (let j = 0; j < utf8.length; j++) {
      parts.push(sbox[(utf8[j] ^ nonce[j]) & 0xff]);
    }
  }
  return bytesToBase64(Uint8Array.from(parts));
}
export function makeDecoder(encodedBlob, key) {
  const stringSeed = key.stringSeed >>> 0;
  const buf = base64ToBytes(encodedBlob);
  const invSbox = buildInverseSbox(key.permKey);
  const offsets = [];
  const lengths = [];
  let pos = 0;
  while (pos < buf.length) {
    offsets.push(pos);
    const {
      len,
      next
    } = decodeLen(buf, pos);
    lengths.push(len);
    pos = next + len;
  }
  const length = offsets.length;
  const cache = new Array(length).fill(undefined);
  function get(i) {
    if (i < 0 || i >= length) {
      throw new RangeError('string-pool: index out of range ' + i);
    }
    if (cache[i] !== undefined) return cache[i];
    const start = offsets[i];
    const {
      next
    } = decodeLen(buf, start);
    const len = lengths[i];
    const slice = buf.subarray(next, next + len);
    const nonce = nonceBytes(stringSeed, i, len);
    const plain = new Uint8Array(len);
    for (let j = 0; j < len; j++) {
      plain[j] = (invSbox[slice[j]] ^ nonce[j]) & 0xff;
    }
    const str = decoder.decode(plain);
    cache[i] = str;
    return str;
  }
  return {
    get,
    length
  };
}
export function decodeAll(encodedBlob, key) {
  const dec = makeDecoder(encodedBlob, key);
  const out = new Array(dec.length);
  for (let i = 0; i < dec.length; i++) out[i] = dec.get(i);
  return out;
}