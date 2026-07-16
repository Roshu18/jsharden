export function buildSelfHealSnippet({
  originalSource,
  key,
  brokenFnName,
  mask = 0xA5
}) {
  const srcBytes = new TextEncoder().encode(originalSource);
  const encoded = new Uint8Array(srcBytes.length);
  for (let i = 0; i < srcBytes.length; i++) {
    encoded[i] = srcBytes[i] ^ key[i % key.length];
  }
  const encodedBlob = base64FromBytes(encoded);
  const MASK = mask;
  const maskedKey = new Uint8Array(key.length);
  for (let i = 0; i < key.length; i++) maskedKey[i] = key[i] ^ MASK;
  const maskedKeyB64 = base64FromBytes(maskedKey);
  const fnAssignment = brokenFnName ? `try { ${brokenFnName} = (new Function(decodedSource + '\\n;return createVM;'))(); } catch(_) {}` : `try { (new Function(decodedSource))(); } catch(_) {}`;
  const snippet = `try {
      var _blob = ${JSON.stringify(encodedBlob)};
      var _mk = ${JSON.stringify(maskedKeyB64)};

      var _mkBytes = Uint8Array.from(atob(_mk), function(c){return c.charCodeAt(0);});
      var _k = new Uint8Array(_mkBytes.length);
      for (var _i = 0; _i < _mkBytes.length; _i++) _k[_i] = _mkBytes[_i] ^ __MASK;

      var _blobBytes = Uint8Array.from(atob(_blob), function(c){return c.charCodeAt(0);});
      var _dec;
      if (typeof __wasmXor === 'function') {
        _dec = __wasmXor(_blobBytes, _k);
      } else {
        _dec = new Uint8Array(_blobBytes.length);
        for (var _j = 0; _j < _blobBytes.length; _j++) _dec[_j] = _blobBytes[_j] ^ _k[_j % _k.length];
      }
      var decodedSource = (typeof TextDecoder !== 'undefined')
        ? new TextDecoder().decode(_dec)
        : Array.from(_dec).map(function(b){return String.fromCharCode(b);}).join('');
      ${fnAssignment}
    } catch(_) {}`;
  return {
    snippet,
    encodedBlob
  };
}
function base64FromBytes(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function btoa(s) {
  if (typeof globalThis.btoa === 'function') return globalThis.btoa(s);
  return Buffer.from(s, 'binary').toString('base64');
}