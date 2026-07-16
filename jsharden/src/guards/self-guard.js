export function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}
export function buildGuardSnippet(fnName, expectedHash, healSnippet = '') {
  const healBlock = healSnippet ? `try { ${healSnippet} } catch(_) {}` : '';
  return `(function(){
    var _g = ${expectedHash >>> 0};
    function _hash() {
      var _s = ${fnName}.toString();
      var _h = 0x811c9dc5;
      for (var _i = 0; _i < _s.length; _i++) {
        _h ^= _s.charCodeAt(_i);
        _h = Math.imul(_h, 0x01000193);
      }
      return _h >>> 0;
    }
    if (_hash() !== _g) {
${fnName}
      ${healBlock}
      if (_hash() !== _g) {
        throw new Error('integrity');
      }
    }
  })();`;
}
export function hashFunction(fn) {
  return fnv1a(fn.toString());
}