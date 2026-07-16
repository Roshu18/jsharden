import { buildOpcodeTable } from './opcode-table.js';
import { mulberry32 } from './keygen.js';
import { canarySource } from './cipher.js';
const _cache = new Map();
const CACHE_LIMIT = 64;
const SEED_XOR = 0xCAFEBABE >>> 0;
const PERMSEED_XOR = 0xDEADBEEF >>> 0;
const STREAMSEED_XOR = 0x12345678 >>> 0;
const STRINGSEED_XOR = 0x9ABCDEF0 >>> 0;
const ANTIDEBUGSEED_XOR = 0x13579BDF >>> 0;
const MASK_MIX = [{
  mul: 0xcc9e2d51,
  xor: 0x9E3779B9
}, {
  mul: 0x1b873593,
  xor: 0xBB67AE85
}, {
  mul: 0x85ebca6b,
  xor: 0x3C6EF372
}, {
  mul: 0xc2b2ae35,
  xor: 0xA54FF53A
}];
function deriveChunkMask(seed, c) {
  const m = MASK_MIX[c];
  return (Math.imul(seed >>> 0, m.mul) ^ m.xor) >>> 0 & 0xFF;
}
const OP_ORDER = ['PUSH_NULL', 'PUSH_UNDEF', 'PUSH_TRUE', 'PUSH_FALSE', 'PUSH_INT', 'PUSH_FLOAT', 'PUSH_STR', 'POP', 'DUP', 'SWAP', 'LOAD_LOCAL', 'STORE_LOCAL', 'LOAD_CAPTURE', 'STORE_CAPTURE', 'GET_PROP', 'SET_PROP', 'GET_ELEM', 'SET_ELEM', 'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'NEG', 'POS', 'NOT', 'BIT_NOT', 'BIT_AND', 'BIT_OR', 'BIT_XOR', 'SHL', 'SHR', 'USHR', 'EQ', 'NEQ', 'SEQ', 'SNEQ', 'LT', 'LTE', 'GT', 'GTE', 'INSTANCEOF', 'IN', 'TYPEOF', 'VOID', 'DELETE_PROP', 'DELETE_ELEM', 'JMP', 'JZ', 'JNZ', 'CALL', 'CALL_METHOD', 'NEW', 'RET', 'RET_UNDEF', 'GET_ITER', 'ITER_NEXT', 'TRY_ENTER', 'TRY_EXIT', 'THROW', 'FUSED_LI_ADD', 'FUSED_LI_PUSH', 'FUSED_SI_PUSH', 'FUSED_GETP_LI', 'FUSED_LI_LT', 'FUSED_INC_STORE'];
const HANDLER_SOURCES = ['function(){stk[sp++]=null;}', 'function(){stk[sp++]=undefined;}', 'function(){stk[sp++]=true;}', 'function(){stk[sp++]=false;}', 'function(){stk[sp++]=fi32();}', 'function(){stk[sp++]=ff64();}', 'function(){stk[sp++]=S[fu16()];}', 'function(){sp--;}', 'function(){stk[sp]=stk[sp-1];sp++;}', 'function(){var t=stk[sp-1];stk[sp-1]=stk[sp-2];stk[sp-2]=t;}', 'function(){stk[sp++]=L[fu8()];}', 'function(){L[fu8()]=stk[--sp];}', 'function(){stk[sp++]=C[fu8()];}', 'function(){C[fu8()]=stk[--sp];}', "function(){var i=fu16();var o=stk[--sp];if(o==null)throw new TypeError('Cannot read properties of '+o+' (reading '+S[i]+')');stk[sp++]=o[S[i]];}", 'function(){var i=fu16();var v=stk[--sp];var o=stk[--sp];if(o!=null)o[S[i]]=v;}', "function(){var k=stk[--sp];var o=stk[--sp];if(o==null)throw new TypeError('Cannot read properties of '+o+' (reading '+k+')');stk[sp++]=o[k];}", 'function(){var v=stk[--sp];var k=stk[--sp];var o=stk[--sp];if(o!=null)o[k]=v;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a+b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a-b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a*b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a/b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a%b;}', 'function(){stk[sp-1]=-stk[sp-1];}', 'function(){stk[sp-1]=+stk[sp-1];}', 'function(){stk[sp-1]=!stk[sp-1];}', 'function(){stk[sp-1]=~stk[sp-1];}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a&b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a|b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a^b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a<<b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a>>b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a>>>b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a==b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a!=b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a===b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a!==b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a<b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a<=b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a>b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a>=b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a instanceof b;}', 'function(){var b=stk[--sp];var a=stk[--sp];stk[sp++]=a in b;}', 'function(){stk[sp-1]=typeof stk[sp-1];}', 'function(){stk[sp-1]=undefined;}', 'function(){var i=fu16();var o=stk[--sp];var r=true;try{if(o!=null)r=delete o[S[i]];}catch(e){}stk[sp++]=r;}', 'function(){var k=stk[--sp];var o=stk[--sp];var r=true;try{if(o!=null)r=delete o[k];}catch(e){}stk[sp++]=r;}', 'function(){ip=fu16();}', 'function(){var a=fu16();if(!stk[--sp])ip=a;}', 'function(){var a=fu16();if(stk[--sp])ip=a;}', 'function(){var argc=fu8();var base=sp-argc-1;var fn=stk[base];var arr=new Array(argc);for(var i=0;i<argc;i++)arr[i]=stk[base+1+i];sp=base;stk[sp++]=fn.apply(undefined,arr);}', "function(){var argc=fu8();var idx=fu16();var base=sp-argc-1;var o=stk[base];var arr=new Array(argc);for(var j=0;j<argc;j++)arr[j]=stk[base+1+j];sp=base;if(o==null)throw new TypeError('Cannot read properties of '+o+' (reading '+S[idx]+')');stk[sp++]=o[S[idx]].apply(o,arr);}", 'function(){var argc=fu8();var base=sp-argc-1;var fn=stk[base];var arr=new Array(argc);for(var i=0;i<argc;i++)arr[i]=stk[base+1+i];sp=base;stk[sp++]=Reflect.construct(fn,arr);}', 'function(){rv=stk[--sp];ip=len;}', 'function(){rv=undefined;ip=len;}', 'function(){var v=stk[--sp];if(v==null){stk[sp++]={next:function(){return {done:true};}};return;}if(Array.isArray(v)){stk[sp++]=v[Symbol.iterator]();return;}if(typeof v[Symbol.iterator]===\'function\'){stk[sp++]=v[Symbol.iterator]();return;}stk[sp++]=Object.keys(v)[Symbol.iterator]();}', 'function(){var it=stk[--sp];stk[sp++]=it.next();}', 'function(){ts.push(fu16());}', 'function(){ts.pop();}', 'function(){throw stk[--sp];}', 'function(){var li=fu8();var n=fi32();stk[sp++]=L[li]+n;}', 'function(){var li=fu8();var n=fi32();stk[sp++]=L[li];stk[sp++]=n;}', 'function(){var si=fu8();var n=fi32();L[si]=n;stk[sp++]=n;}', "function(){var pi=fu16();var li=fu8();var o=L[li];if(o==null)throw new TypeError('Cannot read properties of '+o+' (reading '+S[pi]+')');stk[sp++]=o[S[pi]];}", 'function(){var li=fu8();var n=fi32();stk[sp++]=L[li]<n;}', 'function(){var li=fu8();L[li]=L[li]+1;}'];
function shuffleIndices(n, seed) {
  const arr = Array.from({
    length: n
  }, (_, i) => i);
  const rng = mulberry32(seed >>> 0);
  for (let i = n - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = arr[i];
    arr[i] = arr[j];
    arr[j] = t;
  }
  return arr;
}
const DECOY = 255;
const BASE_TRIP_CODE = 100;
function deriveTripCode(antidebugSeed) {
  const seed = antidebugSeed >>> 0 || 0;
  const rng = mulberry32(seed ^ 0x5a5a5a5a);
  const bits = Math.floor(rng() * 32) & 0x1f;
  return BASE_TRIP_CODE + bits >>> 0;
}
function fnv1aStr(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}
function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  if (typeof Buffer !== 'undefined') return Buffer.from(bin, 'binary').toString('base64');
  return btoa(bin);
}
export function runtimeSource(key, opts) {
  opts = opts || {};
  const ad = opts.antidebug !== false;
  const ih = (opts.integrityHash || 0) >>> 0;
  const memoKey = (key.seed >>> 0) + '|' + (ad ? 1 : 0) + '|' + ih;
  if (_cache.has(memoKey)) return _cache.get(memoKey);
  if (_cache.size >= CACHE_LIMIT) _cache.clear();
  const raw = minify(buildSource(key, ad, ih));
  const src = _applySelfHash(raw);
  _cache.set(memoKey, src);
  return src;
}
function buildSource(key, ad, ih) {
  const table = buildOpcodeTable(key);
  const perm = shuffleIndices(OP_ORDER.length, key.permSeed);
  const invPerm = new Array(OP_ORDER.length);
  for (let i = 0; i < OP_ORDER.length; i++) invPerm[perm[i]] = i;
  const idMap = Object.create(null);
  OP_ORDER.forEach((name, i) => {
    idMap[name] = perm[i];
  });
  const dmBytes = new Uint8Array(256);
  const awBytes = new Uint8Array(256);
  for (let b = 0; b < 256; b++) {
    const name = table.decodeMap[b];
    dmBytes[b] = name !== undefined ? idMap[name] : DECOY;
    const w = table._argWidthMap ? table._argWidthMap[b] : undefined;
    awBytes[b] = w !== undefined ? w : 0;
  }
  const permKey = key.permKey;
  const pkChunks = new Array(4);
  for (let c = 0; c < 4; c++) {
    const mask = deriveChunkMask(key.seed, c);
    const chunk = new Uint8Array(64);
    for (let o = 0; o < 64; o++) {
      chunk[o] = permKey[c * 64 + o] ^ mask;
    }
    pkChunks[c] = chunk;
  }
  const seedEnc = (key.seed ^ SEED_XOR) >>> 0;
  const permSeedEnc = (key.permSeed ^ PERMSEED_XOR) >>> 0;
  const streamSeedEnc = (key.streamSeed ^ STREAMSEED_XOR) >>> 0;
  const stringSeedEnc = (key.stringSeed ^ STRINGSEED_XOR) >>> 0;
  const antidebugSeedEnc = (key.antidebugSeed ^ ANTIDEBUGSEED_XOR) >>> 0;
  void deriveTripCode(key.antidebugSeed);
  const pk0B64 = bytesToBase64(pkChunks[0]);
  const pk1B64 = bytesToBase64(pkChunks[1]);
  const pk2B64 = bytesToBase64(pkChunks[2]);
  const pk3B64 = bytesToBase64(pkChunks[3]);
  const dmB64 = bytesToBase64(dmBytes);
  const awB64 = bytesToBase64(awBytes);
  const streamKeyBytes = new Uint8Array(64);
  {
    const rng = mulberry32(key.streamSeed);
    for (let i = 0; i < 64; i++) {
      const v = rng();
      const t = v * 0x100000000 | 0;
      streamKeyBytes[i] = (t ^ t >>> 16) & 0xFF;
    }
  }
  const skB64 = bytesToBase64(streamKeyBytes);
  const canarySrc = canarySource(key);
  const expectedCanaryHash = fnv1aStr(canarySrc);
  const adVars = ad ? `var ic=0,br=B;` : ``;
  const adBlock = ad ? `if(ad&&(++ic&63)===0){try{if(B!==br)cr=true;var es=(new Error()).stack;if(es&&/devtools|injected/i.test(es))cr=true;}catch(_){}}` : ``;
  return `
var _ks=${seedEnc};
var _kp=${permSeedEnc};
var _kst=${streamSeedEnc};
var _ksr=${stringSeedEnc};
var _ka=${antidebugSeedEnc};
var _xs=3405691582,_xp=3735928559,_xst=305419896,_xsr=2596069104,_xa=324508639;
var _mk0=(Math.imul(_ks^_xs,3432918353)^2654435769)&255;
var _mk1=(Math.imul(_ks^_xs,461845907)^3144134277)&255;
var _mk2=(Math.imul(_ks^_xs,2246822507)^1013904242)&255;
var _mk3=(Math.imul(_ks^_xs,3266489909)^2773480762)&255;
var _pk0=atob("${pk0B64}");
var _pk1=atob("${pk1B64}");
var _pk2=atob("${pk2B64}");
var _pk3=atob("${pk3B64}");
var _sk=atob("${skB64}");
var DM=atob("${dmB64}");
var AW=atob("${awB64}");
var IH=${ih};
var AD=${ad};
${canarySrc}
var __ah=0;
try{var __cs=arguments.callee.toString();var __ci1=__cs.indexOf('function __canary');var __ci2=__cs.indexOf('}',__ci1);if(__ci1>=0&&__ci2>__ci1){var __csl=__cs.substring(__ci1,__ci2+1);var __ch=0x811c9dc5;for(var __ci=0;__ci<__csl.length;__ci++){__ch^=__csl.charCodeAt(__ci);__ch=Math.imul(__ch,0x01000193);}__ah=__ch>>>0;}}catch(_){}
var __ech=${expectedCanaryHash};
var __mix=__ah^__ech;
function sboxGet(i){var c=(i>>>6)&3,o=i&63;var b=c===0?_pk0.charCodeAt(o)^_mk0:c===1?_pk1.charCodeAt(o)^_mk1:c===2?_pk2.charCodeAt(o)^_mk2:_pk3.charCodeAt(o)^_mk3;return (b^((__ah>>>((i&3)*8))&255))&255;}
function sb(ip){var ss=_kst^_xst;var a=(ss+(ip>>>0))>>>0;var inn=sboxGet((a>>>8)&255);var so=sboxGet((a&255)^inn);var rb=_sk.charCodeAt(ip&63);return (so^rb^((ip>>>3)&255)^((__mix>>>((ip&3)*8))&255))&255;}

function pkGet(i){var c=(i>>>6)&3,o=i&63;return (c===0?_pk0.charCodeAt(o)^_mk0:c===1?_pk1.charCodeAt(o)^_mk1:c===2?_pk2.charCodeAt(o)^_mk2:_pk3.charCodeAt(o)^_mk3)&255;}

function kih(b){var h=(0x811c9dc5^(_ka^_xa))>>>0;var len=b.length;h=Math.imul(h^len,0x01000193);for(var i=0;i<len;i++){h^=b[i];h=Math.imul(h,0x01000193);if((i&15)===15){h^=pkGet(i&255);h=Math.imul(h,0x01000193);}}return h>>>0;}
function fnv(b){var h=0x811c9dc5;for(var i=0;i<b.length;i++){h^=b[i];h=Math.imul(h,0x01000193);}return h>>>0;}

var __eh=0;
var __M1=0;
var __sh=__eh;
try{var __s=arguments.callee.toString();var __i1=__s.indexOf('__M1');var __i2=__s.indexOf('__M2');if(__i1>=0&&__i2>__i1){var __sl=__s.substring(__i1,__i2);var __h=0x811c9dc5;for(var __i=0;__i<__sl.length;__i++){__h^=__sl.charCodeAt(__i);__h=Math.imul(__h,0x01000193);}__sh=__h>>>0;}}catch(_){}
var __M2=0;

function createVM(opts){
opts=opts||{};
var S=opts.strings||[];
var C=opts.captures||[];
var ad=opts.antidebug!==undefined?opts.antidebug:AD;
var ih=(opts.integrityHash!==undefined&&opts.integrityHash!==null)?(opts.integrityHash>>>0):IH;
function execute(code,args){
args=args||[];
var B=code instanceof Uint8Array?code:new Uint8Array(code);
var len=B.length;
var stk=[];
var sp=0;
var L=new Array(32);
for(var i=0;i<args.length;i++)L[i]=args[i];
var ip=0;
var ts=[];
var rv;
var cr=false;

var __db=[0,0,0,0,0,0,0,0];
${adVars}
if(ih!==0){try{if(kih(B)!==ih)cr=true;}catch(_){cr=true;}}
if(__sh!==__eh)cr=true;
function fb(){if(ip>=len)return 0;var d=B[ip]^sb(ip);if(cr)d^=0xff;ip++;return d&0xff;}
function fu8(){return fb();}
function fu16(){var a=fb();var b=fb();return a|(b<<8);}
function fi32(){var a=fb();var b=fb();var c=fb();var d=fb();return a|(b<<8)|(c<<16)|(d<<24);}
function ff64(){var tmp=new Uint8Array(8);for(var i=0;i<8;i++)tmp[i]=fb();return new Float64Array(tmp.buffer)[0];}
var H=[${invPerm.map(function (i) {
    return HANDLER_SOURCES[i];
  }).join(',')}];
while(ip<len){
var op=fb();
var id=DM.charCodeAt(op);
if(id===${DECOY}){var w=AW.charCodeAt(op);var decoyVal=op;for(var j=0;j<w;j++){var ab=fb();decoyVal=(decoyVal*31+ab)|0;}__db[op&7]=decoyVal;continue;}
${adBlock}
try{H[id]();}
catch(err){if(cr){if(ts.length>0){var ca=ts.pop();sp=0;stk[sp++]=err;ip=ca;continue;}throw err;}if(ts.length>0){ca=ts.pop();sp=0;stk[sp++]=err;ip=ca;continue;}throw err;}
}
return rv;
}
return {execute:execute};
}
`;
}
function minify(src) {
  let s = '';
  let i = 0;
  const len = src.length;
  while (i < len) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === '/' && c2 === '/') {
      i += 2;
      while (i < len && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && c2 === '*') {
      i += 2;
      while (i < len && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      s += c;
      i++;
      while (i < len) {
        if (src[i] === '\\') {
          s += src[i] + (src[i + 1] || '');
          i += 2;
          continue;
        }
        if (src[i] === quote) {
          s += src[i];
          i++;
          break;
        }
        s += src[i];
        i++;
      }
      continue;
    }
    s += c;
    i++;
  }
  const PUNCT = '{};()[],.=:+-*/%<>!&|^~?';
  let out = '';
  i = 0;
  const n = s.length;
  let inStr = null;
  while (i < n) {
    const c = s[i];
    if (inStr) {
      out += c;
      if (c === '\\') {
        out += s[i + 1] || '';
        i += 2;
        continue;
      }
      if (c === inStr) inStr = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      inStr = c;
      out += c;
      i++;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      let j = i;
      while (j < n && (s[j] === ' ' || s[j] === '\t' || s[j] === '\n' || s[j] === '\r')) j++;
      const prev = out[out.length - 1];
      const next = s[j];
      if (!prev || PUNCT.includes(prev) || !next || PUNCT.includes(next)) {} else {
        out += ' ';
      }
      i = j;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}
export function _applySelfHash(src) {
  const m1Idx = src.indexOf('__M1');
  const m2Idx = src.indexOf('__M2');
  let selfHash = 0;
  if (m1Idx >= 0 && m2Idx > m1Idx) {
    selfHash = fnv1aStr(src.substring(m1Idx, m2Idx));
  }
  return src.replace(/var __eh=0;/, 'var __eh=' + selfHash + ';');
}
export function _buildKeyEncoding(key) {
  const antidebugSeedEnc = (key.antidebugSeed ^ ANTIDEBUGSEED_XOR) >>> 0;
  const permKeyChunks = new Array(4);
  const permMasks = new Array(4);
  for (let c = 0; c < 4; c++) {
    permMasks[c] = deriveChunkMask(key.seed, c);
    const chunk = new Uint8Array(64);
    for (let o = 0; o < 64; o++) {
      chunk[o] = key.permKey[c * 64 + o] ^ permMasks[c];
    }
    permKeyChunks[c] = bytesToBase64(chunk);
  }
  return {
    antidebugSeedEnc,
    antidebugSeedXor: ANTIDEBUGSEED_XOR,
    permKeyChunks,
    permMasks
  };
}