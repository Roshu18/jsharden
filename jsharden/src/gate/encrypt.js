export function keystreamByte(gateKey, i) {
  let h = i >>> 0;
  for (let j = 0; j < 32; j++) {
    h = Math.imul(h ^ gateKey[j], 0x01000193) >>> 0;
  }
  h = Math.imul(h ^ h >>> 15, 0x85ebca6b);
  h = Math.imul(h ^ h >>> 13, 0xc2b2ae35);
  h = (h ^ h >>> 16) >>> 0;
  return h & 0xFF;
}
export function encryptBody(body, gateKey) {
  if (!(gateKey instanceof Uint8Array) || gateKey.length !== 32) {
    throw new TypeError('encryptBody: gateKey must be a Uint8Array of length 32');
  }
  let plaintext;
  if (typeof body === 'string') {
    plaintext = new TextEncoder().encode(body);
  } else if (body instanceof Uint8Array) {
    plaintext = body;
  } else {
    throw new TypeError('encryptBody: body must be a string or Uint8Array');
  }
  const ciphertext = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) {
    ciphertext[i] = plaintext[i] ^ keystreamByte(gateKey, i);
  }
  const encryptedB64 = Buffer.from(ciphertext).toString('base64');
  return {
    encrypted: ciphertext,
    encryptedB64
  };
}
export function decryptBody(encrypted, gateKey) {
  if (!(gateKey instanceof Uint8Array) || gateKey.length !== 32) {
    throw new TypeError('decryptBody: gateKey must be a Uint8Array of length 32');
  }
  const ct = encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted);
  const plaintext = new Uint8Array(ct.length);
  for (let i = 0; i < ct.length; i++) {
    plaintext[i] = ct[i] ^ keystreamByte(gateKey, i);
  }
  return new TextDecoder().decode(plaintext);
}