import { generateGateKey, deriveKey, generateCanary } from './key-derive.js';
import { selectProbes, PROBES } from './probes.js';
import { WASM_KDF_B64 } from './wasm-kdf.js';
const PROBE_CHECKS = {
  canvas: "C('#ff0000',0)",
  chrome: "C('#00ff00',1)",
  userAgent: "C('#0000ff',2)",
  plugins: "C('#ff0000',3)",
  performanceNow: "C('#570000',0)",
  raf: "C('#090000',0)",
  documentMode: "C('#570000',0)",
  outerWidth: "C('#010000',0)",
  screen: "C('#100000',0)",
  webgl: "C('#ffffff',0)",
  fonts: "Y('color:red','color').charCodeAt(0)",
  storage: "Y('','display').charCodeAt(0)",
  indexedDB: "Y('','position').charCodeAt(0)",
  crypto: "Y('','visibility').charCodeAt(0)",
  pointer: "C('#000000',3)",
  hardwareConcurrency: "C('#110000',0)"
};
function checkExpressionFor(probe) {
  const expr = probe && PROBE_CHECKS[probe.name];
  if (typeof expr === 'string' && expr.length > 0) {
    return expr.replace(/typeof (\w+)!=='undefined'/g, 'T($1)');
  }
  return 'T(window)';
}
function buildString({
  storedParts,
  perBuildConsts,
  selectedProbes,
  encryptedBody,
  gateKey
}) {
  void perBuildConsts;
  const spB64 = Buffer.from(storedParts).toString('base64');
  const probeSources = selectedProbes.map((probe, i) => {
    const expr = probe && PROBE_CHECKS[probe.name];
    if (!expr) {
      return '()=>{try{return cc[' + i + ']++?0:C("#ff0000",0)}catch(_){return 0}}';
    }
    return '()=>{try{return cc[' + i + ']++?0:' + expr + '}catch(_){return 0}}';
  });
  const probeFns = probeSources.map((src, i) => 'p' + i + '=' + src).join(',');
  const probeCalls = selectedProbes.map((_, i) => 'p' + i + '()').join(',');
  const probeRefs = selectedProbes.map((_, i) => 'p' + i).join(',');
  const probeHashes = probeSources.map(src => {
    let h = 0x811c9dc5;
    for (let i = src.length - 1; i >= 0; i--) {
      h ^= src.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return h | 0;
  });
  const probeHelpers = 'function C(fc,c){try{var d=document.createElement(\'canvas\');d.width=1;d.height=1;var x=d.getContext(\'2d\');x.fillStyle=fc;x.fillRect(0,0,1,1);return x.getImageData(0,0,1,1).data[c]}catch(_){return 0}}' + 'function Y(cs,p){try{var e=document.createElement(\'div\');if(cs)e.style.cssText=cs;var r=document.documentElement||document.body;r.appendChild(e);var v=getComputedStyle(e)[p];r.removeChild(e);return v}catch(_){return 0}}';
  const ksFn = 'function f(i){var M=Math.imul,h=i>>>0;' + 'for(var j=0;j<32;j++)h=M(h^k[j],16777619);' + 'h=M(h^(h>>>15),0x85ebca6b);' + 'h=M(h^(h>>>13),0xc2b2ae35);' + 'return(h^(h>>>16))&255;}';
  const decFn = 'function G(x){var e=u(x),d=new Uint8Array(e.length);' + 'for(var i=0;i<e.length;i++)d[i]=e[i]^f(i);' + 'return D.decode(d);}';
  const {
    encryptedB64: canaryB64,
    plaintext: canaryPlaintext
  } = generateCanary(gateKey);
  const jsKdfFn = 'function _jk(a,b){var c=b.length,h=2166136261;for(var r=0;r<4;r++)for(var i=0;i<32;i++){h=h^(a[i]^(b[i%c]<<(r*2)));h=Math.imul(h,16777619);}var K=new Uint8Array(32),s=h;for(var i=0;i<32;i++){s=s+1831565813;var t=s;t=Math.imul(t^(t>>>15),t|1);t^=t+Math.imul(t^(t>>>7),t|61);K[i]=((t^(t>>>14))>>>24)&255;}return K;}';
  return '(function(){' + 'function _N(x){var s="";try{s=""+x;}catch(_){}return s.indexOf("[native code]")<0;}' + 'var _F=Function,_b=_N(eval),_G=_N(_F);' + 'var u=s=>Uint8Array.from(atob(s),x=>x.charCodeAt()),' + 'D=new TextDecoder(),' + 'Q=null,m=null,' + 's=u("' + spB64 + '"),' + 'b="' + encryptedBody + '",' + 'cc=Array(' + selectedProbes.length + ').fill(0),' + 'N=_=>(performance||Date).now(),' + 'M=Math.imul,' + probeFns + ',' + 'P=[' + probeRefs + '],' + 'H=[' + probeHashes.join(',') + '],' + 'i,j,k;' + 'try{Q=new WebAssembly.Instance(new WebAssembly.Module(u("' + WASM_KDF_B64 + '")));m=new Uint8Array(Q.exports.mem.buffer);}catch(_){Q=null;m=null;}' + probeHelpers + jsKdfFn + 'var R=[' + probeCalls + '];' + 'if(Q&&m){m.set(s,0);m.set(R,32);Q.exports.kdf(0,32,64);k=m.slice(64,96);}else{k=_jk(s,R);}' + 'if(_b&&_G){for(j=32;j--;)k[j]^=170;}' + ksFn + decFn + 'var t0=N(),v=G("' + canaryB64 + '"),dt=N()-t0;' + 'if(v!=="' + canaryPlaintext + '")for(j=32;j--;)k[j]^=255;' + 'var src=G(b);' + 'if(_b){if(!_G){(0,_F)(src)();}}else{(0,eval)(src);}' + '})();';
}
export function buildGateCode(v2Key, encryptedBodyB64) {
  if (!v2Key || typeof v2Key.seed !== 'number' || !Number.isInteger(v2Key.seed) || v2Key.seed < 0 || v2Key.seed > 0xFFFFFFFF) {
    throw new TypeError('buildGateCode: v2Key.seed must be a uint32 (0 to 4294967295); got ' + String(v2Key && v2Key.seed));
  }
  if (typeof encryptedBodyB64 !== 'string') {
    throw new TypeError('buildGateCode: encryptedBodyB64 must be a base64 string');
  }
  const selected = selectProbes(v2Key.seed, 12);
  const {
    gateKey,
    storedParts,
    expectedResults
  } = generateGateKey(v2Key, selected);
  const gateCode = buildString({
    storedParts,
    perBuildConsts: expectedResults,
    selectedProbes: selected,
    encryptedBody: encryptedBodyB64,
    gateKey
  });
  if (typeof deriveKey === 'function') {
    const derived = deriveKey(storedParts, expectedResults);
    for (let i = 0; i < 32; i++) {
      if (derived[i] !== gateKey[i]) {
        throw new Error('buildGateCode: deriveKey invariant violated at byte ' + i + ' — gateKey would not be recoverable in a browser ' + '(key-derive.js regression?)');
      }
    }
  }
  const expectedProbeResults = new Uint8Array(expectedResults);
  return {
    gateCode,
    gateKey,
    expectedProbeResults,
    expectedResults
  };
}
export { PROBE_CHECKS, buildString, checkExpressionFor, PROBES, PROBES as PROBE_POOL };