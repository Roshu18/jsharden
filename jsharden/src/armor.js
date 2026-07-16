import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import _generate from '@babel/generator';
import * as t from '@babel/types';
import JavaScriptObfuscator from 'javascript-obfuscator';
import { minify } from 'terser';
import { compileFunction, runtimeSource, generateKey } from './vm-v2/index.js';
import { mulberry32 } from './vm-v2/keygen.js';
import { keyedIntegrityHash } from './vm-v2/cipher.js';
import { _buildKeyEncoding } from './vm-v2/runtime-source.js';
import { WASM_BASE64 } from './wasm/xor-module.js';
import { fnv1a } from './guards/self-guard.js';
import { buildSelfHealSnippet } from './guards/self-heal.js';
import { PROFILES } from './profiles.js';
import { splitUserscriptHeader, verifyParses } from './harden.js';
import { wrapWithGate } from './gate/index.js';
const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;
const ARMOR_RESERVED_NAMES = ['__vm', '__wasmXor', '__vmFuncs', '__vmCache', '__vmRuntime', '__vmRuntimeHash', '__vmCallCount', '__vmGuardHash', '__MASK', '__captureRegistry', '__blob', '__wasmOff', '__wasmEnd', '__wasmInstance', '__wasmMem', '__wasmDecode', '__initWasm', '__getFnKey', '__decodeBc', '__decodeStr', '__getVmForIndex', '__installVmRuntime'];
export const ARMOR_RESERVED_NAMES_READONLY = Object.freeze([...ARMOR_RESERVED_NAMES]);
const WELL_KNOWN_GLOBALS = new Set(['Object', 'Array', 'Math', 'JSON', 'Date', 'Error', 'Promise', 'Function', 'RegExp', 'Number', 'String', 'Boolean', 'Symbol', 'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'undefined', 'NaN', 'Infinity', 'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI', 'eval', 'globalThis', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'FinalizationRegistry', 'Reflect', 'Proxy', 'Iterator', 'Generator', 'AsyncIterator', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Uint16Array', 'Uint32Array', 'Uint8ClampedArray', 'Int8Array', 'Int16Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'BigInt', 'Bigint', 'TextEncoder', 'TextDecoder', 'console', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'setImmediate', 'clearImmediate', 'requestAnimationFrame', 'cancelAnimationFrame', 'requestIdleCallback', 'cancelIdleCallback', 'queueMicrotask', 'performance', 'document', 'window', 'self', 'navigator', 'location', 'history', 'localStorage', 'sessionStorage', 'indexedDB', 'customElements', 'CustomEvent', 'Event', 'EventTarget', 'MutationObserver', 'ResizeObserver', 'IntersectionObserver', 'HTMLElement', 'Element', 'Node', 'Document', 'Window', 'fetch', 'Headers', 'Request', 'Response', 'Blob', 'File', 'FileReader', 'URL', 'URLSearchParams', 'WebSocket', 'XMLHttpRequest', 'FormData', 'DOMParser', 'XMLSerializer', 'Image', 'Audio', 'MediaStream', 'MessageChannel', 'MessagePort', 'BroadcastChannel', 'Worker', 'SharedWorker', 'crypto', 'Crypto', 'SubtleCrypto', 'CryptoKey', 'AbortController', 'AbortSignal', 'ReadableStream', 'WritableStream', 'TransformStream', 'structuredClone', 'atob', 'btoa', 'alert', 'confirm', 'prompt', 'matchMedia', 'getComputedStyle', 'addEventListener', 'removeEventListener', 'postMessage', 'process', 'Buffer', 'global', 'module', 'exports', 'require', '__dirname', '__filename']);
function resolveConstAliasInit(init) {
  if (!init) return null;
  if (init.type === 'Identifier') {
    return WELL_KNOWN_GLOBALS.has(init.name) ? {
      root: init.name,
      chain: []
    } : null;
  }
  if (init.type !== 'MemberExpression') return null;
  const chain = [];
  let n = init;
  while (n && n.type === 'MemberExpression' && !n.computed) {
    if (!n.property || n.property.type !== 'Identifier') return null;
    chain.unshift(n.property.name);
    n = n.object;
  }
  if (!n || n.type !== 'Identifier') return null;
  if (!WELL_KNOWN_GLOBALS.has(n.name)) return null;
  return {
    root: n.name,
    chain
  };
}
function buildMemberExprNode(root, chain) {
  let expr = t.identifier(root);
  for (const prop of chain) {
    expr = t.memberExpression(expr, t.identifier(prop), false);
  }
  return expr;
}
function isReferencePosition(idNode, parent) {
  if (!parent) return false;
  switch (parent.type) {
    case 'MemberExpression':
      if (parent.property === idNode && !parent.computed) return false;
      return true;
    case 'ObjectProperty':
    case 'ObjectMethod':
    case 'Property':
      if (parent.key === idNode && !parent.computed) return false;
      if (parent.shorthand) return false;
      return true;
    case 'VariableDeclarator':
      if (parent.id === idNode) return false;
      return true;
    case 'FunctionDeclaration':
    case 'FunctionExpression':
      if (parent.id === idNode) return false;
      if (parent.params && parent.params.indexOf(idNode) !== -1) return false;
      return true;
    case 'ArrowFunctionExpression':
      if (parent.params && parent.params.indexOf(idNode) !== -1) return false;
      return true;
    case 'CatchClause':
      if (parent.param === idNode) return false;
      return true;
    case 'LabeledStatement':
      if (parent.label === idNode) return false;
      return true;
    case 'BreakStatement':
    case 'ContinueStatement':
      if (parent.label === idNode) return false;
      return true;
    case 'ImportSpecifier':
    case 'ImportDefaultSpecifier':
    case 'ImportNamespaceSpecifier':
    case 'ExportSpecifier':
    case 'ExportDefaultDeclaration':
      return false;
    case 'AssignmentPattern':
      if (parent.left === idNode) return false;
      return true;
    case 'AssignmentExpression':
      if (parent.left === idNode) return false;
      return true;
    case 'UpdateExpression':
      if (parent.argument === idNode) return false;
      return true;
    default:
      if (parent.type && parent.type.indexOf('JSX') === 0) return false;
      return true;
  }
}
function substituteConstAliasesInClone(node, constAliasMap) {
  if (!node || typeof node !== 'object' || constAliasMap.size === 0) return;
  const visit = (n, parent, parentKey, arrIdx) => {
    if (!n || typeof n !== 'object') return;
    if (Array.isArray(n)) {
      for (let i = 0; i < n.length; i++) visit(n[i], parent, parentKey, i);
      return;
    }
    if (n.type === 'Identifier' && constAliasMap.has(n.name)) {
      if (isReferencePosition(n, parent)) {
        const replacement = t.cloneDeep(constAliasMap.get(n.name));
        if (arrIdx !== undefined && arrIdx !== null && Array.isArray(parent[parentKey])) {
          parent[parentKey][arrIdx] = replacement;
        } else {
          parent[parentKey] = replacement;
        }
        return;
      }
    }
    for (const key of Object.keys(n)) {
      if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'extra' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') continue;
      const val = n[key];
      if (Array.isArray(val)) {
        for (let i = 0; i < val.length; i++) visit(val[i], n, key, i);
      } else if (val && typeof val === 'object' && val.type) {
        visit(val, n, key, null);
      }
    }
  };
  visit(node, null, null, null);
}
export async function hardenArmor({
  source,
  seed = 0,
  antiDebug = false,
  consoleOff = false,
  skipVm = false,
  vmSkipPatterns = [],
  vmSkipCallers = false,
  compact = false,
  gate = true
}) {
  const v2Key = generateKey(seed || 1);
  const report = {
    topLevelFunctions: 0,
    vmCompiled: 0,
    vmCompiledNames: [],
    vmBailed: 0,
    bailReasons: [],
    bytesBefore: source.length,
    bytesAfterObf: 0,
    bytesAfterTerser: 0,
    bytesAfterGate: 0,
    skipVm: skipVm,
    vmSkipPatterns: vmSkipPatterns,
    vmSkipCallers: vmSkipCallers,
    compact: compact,
    gate: gate
  };
  const skipRegexes = vmSkipPatterns.map(p => new RegExp(p, 'i'));
  const shouldSkip = name => skipRegexes.some(r => r.test(name));
  const {
    header,
    body
  } = splitUserscriptHeader(source);
  let ast;
  try {
    ast = parse(body, {
      sourceType: 'script',
      allowReturnOutsideFunction: true,
      plugins: ['objectRestSpread', 'optionalChaining', 'nullishCoalescingOperator']
    });
  } catch (err) {
    throw new Error(`armor: source does not parse: ${err.message}`);
  }
  const candidates = [];
  traverse(ast, {
    FunctionDeclaration(path) {
      const name = path.node.id?.name;
      if (!name) return;
      if (path.node.generator || path.node.async) return;
      candidates.push({
        path,
        name,
        kind: 'decl',
        node: path.node
      });
    },
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const init = path.node.init;
      if (!init) return;
      if (!t.isArrowFunctionExpression(init) && !t.isFunctionExpression(init)) return;
      if (init.async || init.generator) return;
      candidates.push({
        path,
        name: path.node.id.name,
        kind: 'var',
        node: path.node
      });
    },
    AssignmentExpression(path) {
      const left = path.node.left;
      const right = path.node.right;
      if (!t.isMemberExpression(left) || left.computed) return;
      if (!t.isIdentifier(left.property)) return;
      if (!t.isArrowFunctionExpression(right) && !t.isFunctionExpression(right)) return;
      if (right.async || right.generator) return;
      const propName = left.property.name;
      const objName = t.isIdentifier(left.object) ? left.object.name : '';
      const fullName = objName ? `${objName}.${propName}` : propName;
      candidates.push({
        path,
        name: propName,
        fullName,
        kind: 'assign',
        node: path.node
      });
    }
  });
  report.topLevelFunctions = candidates.length;
  const expandedSkipSet = new Set();
  if (vmSkipCallers && skipRegexes.length > 0) {
    const skipCandidates = candidates.filter(c => {
      const nameToCheck = c.fullName || c.name;
      return shouldSkip(nameToCheck) || shouldSkip(c.name);
    });
    const collectIdentifiers = (node, set) => {
      if (!node || typeof node !== 'object') return;
      if (Array.isArray(node)) {
        for (const n of node) collectIdentifiers(n, set);
        return;
      }
      if (node.type === 'CallExpression') {
        const callee = node.callee;
        if (callee.type === 'Identifier') {
          set.add(callee.name);
        } else if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
          set.add(callee.property.name);
        }
        for (const arg of node.arguments) collectIdentifiers(arg, set);
        return;
      }
      for (const key of Object.keys(node)) {
        if (key === 'type' || key === 'start' || key === 'end' || key === 'loc') continue;
        collectIdentifiers(node[key], set);
      }
    };
    for (const c of skipCandidates) {
      let fnNode;
      if (c.kind === 'decl') fnNode = c.path.node;else if (c.kind === 'assign') fnNode = c.path.node.right;else fnNode = c.path.node.init;
      if (!fnNode) continue;
      collectIdentifiers(fnNode, expandedSkipSet);
    }
  }
  const effectiveShouldSkip = (name, fullName) => {
    if (shouldSkip(name) || fullName && shouldSkip(fullName)) return true;
    if (vmSkipCallers && expandedSkipSet.has(name)) return true;
    return false;
  };
  const constAliasMap = new Map();
  if (!skipVm) {
    const bindingCount = new Map();
    const bump = name => {
      if (!name) return;
      bindingCount.set(name, (bindingCount.get(name) || 0) + 1);
    };
    const countPattern = p => {
      if (!p) return;
      if (p.type === 'Identifier') bump(p.name);else if (p.type === 'AssignmentPattern') countPattern(p.left);else if (p.type === 'RestElement') countPattern(p.argument);else if (p.type === 'ObjectPattern') {
        for (const prop of p.properties || []) {
          if (prop.type === 'ObjectProperty' || prop.type === 'Property') countPattern(prop.value);else if (prop.type === 'RestElement') countPattern(prop.argument);
        }
      } else if (p.type === 'ArrayPattern') {
        for (const el of p.elements || []) countPattern(el);
      }
    };
    const walkForCounting = n => {
      if (!n || typeof n !== 'object') return;
      if (Array.isArray(n)) {
        for (const c of n) walkForCounting(c);
        return;
      }
      switch (n.type) {
        case 'VariableDeclarator':
          if (n.id) countPattern(n.id);
          break;
        case 'FunctionDeclaration':
        case 'FunctionExpression':
        case 'ArrowFunctionExpression':
          if (n.id && n.id.name) bump(n.id.name);
          if (n.params) for (const p of n.params) countPattern(p);
          break;
        case 'ClassDeclaration':
          if (n.id && n.id.name) bump(n.id.name);
          break;
        case 'CatchClause':
          if (n.param) countPattern(n.param);
          break;
      }
      for (const key of Object.keys(n)) {
        if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'extra' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') continue;
        const v = n[key];
        if (Array.isArray(v)) for (const c of v) walkForCounting(c);else if (v && typeof v === 'object' && v.type) walkForCounting(v);
      }
    };
    walkForCounting(ast);
    const walkForCollecting = (n, parent) => {
      if (!n || typeof n !== 'object') return;
      if (Array.isArray(n)) {
        for (const c of n) walkForCollecting(c, parent);
        return;
      }
      if (n.type === 'VariableDeclarator' && n.id && n.id.type === 'Identifier') {
        const name = n.id.name;
        if ((bindingCount.get(name) || 0) === 1) {
          if (parent && parent.type === 'VariableDeclaration' && parent.kind === 'const') {
            const resolved = resolveConstAliasInit(n.init);
            if (resolved) {
              constAliasMap.set(name, buildMemberExprNode(resolved.root, resolved.chain));
            }
          }
        }
      }
      for (const key of Object.keys(n)) {
        if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'extra' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') continue;
        const v = n[key];
        if (Array.isArray(v)) for (const c of v) walkForCollecting(c, n);else if (v && typeof v === 'object' && v.type) walkForCollecting(v, n);
      }
    };
    walkForCollecting(ast, null);
  }
  const vmFunctions = [];
  const bailReasons = new Map();
  if (skipVm) {
    report.vmBailed = candidates.length;
    for (const c of candidates) {
      bailReasons.set(c.name, 'skipped (skipVm=true)');
    }
  } else {
    for (const c of candidates) {
      const nameToCheck = c.fullName || c.name;
      if (effectiveShouldSkip(c.name, c.fullName)) {
        report.vmBailed++;
        const reason = shouldSkip(c.name) || shouldSkip(nameToCheck) ? 'skipped (matches vmSkipPatterns)' : 'skipped (called by vmSkipPatterns function)';
        bailReasons.set(c.name, reason);
        continue;
      }
      let fnSrc;
      if (constAliasMap.size === 0) {
        if (c.kind === 'decl') {
          fnSrc = `(${generate(t.functionExpression(null, c.path.node.params, c.path.node.body), {
            compact: true
          }).code})`;
        } else if (c.kind === 'assign') {
          fnSrc = `(${generate(c.path.node.right, {
            compact: true
          }).code})`;
        } else {
          fnSrc = `(${generate(c.path.node.init, {
            compact: true
          }).code})`;
        }
      } else {
        if (c.kind === 'decl') {
          const cloned = t.cloneNode(c.path.node, true, true);
          substituteConstAliasesInClone(cloned, constAliasMap);
          fnSrc = `(${generate(t.functionExpression(null, cloned.params, cloned.body), {
            compact: true
          }).code})`;
        } else if (c.kind === 'assign') {
          const cloned = t.cloneNode(c.path.node.right, true, true);
          substituteConstAliasesInClone(cloned, constAliasMap);
          fnSrc = `(${generate(cloned, {
            compact: true
          }).code})`;
        } else {
          const cloned = t.cloneNode(c.path.node.init, true, true);
          substituteConstAliasesInClone(cloned, constAliasMap);
          fnSrc = `(${generate(cloned, {
            compact: true
          }).code})`;
        }
      }
      const r = compileFunction(fnSrc, {
        key: v2Key
      });
      if (!r.canCompile) {
        report.vmBailed++;
        bailReasons.set(c.name, r.error);
        continue;
      }
      const lexicalCaptures = r.captures.filter(name => {
        if (name === 'this') return true;
        try {
          const binding = c.path.scope.getBinding(name);
          return !!binding;
        } catch (_e) {
          return true;
        }
      });
      if (lexicalCaptures.length > 0) {
        report.vmBailed++;
        bailReasons.set(c.name, `has lexical captures: ${lexicalCaptures.join(', ')}`);
        continue;
      }
      const hasUnknownCapture = r.captures.some(name => !WELL_KNOWN_GLOBALS.has(name));
      if (hasUnknownCapture) {
        report.vmBailed++;
        bailReasons.set(c.name, `has captures: ${r.captures.filter(n => !WELL_KNOWN_GLOBALS.has(n)).join(', ')}`);
        continue;
      }
      const fnIdx = vmFunctions.length;
      const bcHash = r.meta && typeof r.meta.integrityHash === 'number' ? r.meta.integrityHash >>> 0 : keyedIntegrityHash(r.bytecode, v2Key) >>> 0;
      if (process.env.NODE_ENV !== 'production' && r.meta && typeof r.meta.integrityHash === 'number') {
        const check = keyedIntegrityHash(r.bytecode, v2Key) >>> 0;
        if (check !== r.meta.integrityHash >>> 0) {
          throw new Error(`armor: integrityHash mismatch (compiler=${r.meta.integrityHash >>> 0}, armor=${check}) for ${c.name}`);
        }
      }
      const vmCallExpr = t.callExpression(t.memberExpression(t.identifier('__vm'), t.identifier('run')), [t.numericLiteral(fnIdx), t.identifier('arguments'), t.numericLiteral(bcHash)]);
      const vmCallArrow = t.callExpression(t.memberExpression(t.identifier('__vm'), t.identifier('run')), [t.numericLiteral(fnIdx), t.identifier('args'), t.numericLiteral(bcHash)]);
      if (c.kind === 'decl') {
        c.path.node.body = t.blockStatement([t.returnStatement(vmCallExpr)]);
      } else if (c.kind === 'assign') {
        c.path.node.right = t.arrowFunctionExpression([t.restElement(t.identifier('args'))], vmCallArrow);
      } else {
        c.path.node.init = t.arrowFunctionExpression([t.restElement(t.identifier('args'))], vmCallArrow);
      }
      vmFunctions.push({
        name: c.name,
        bytecode: r.bytecode,
        strings: r.strings,
        captures: r.captures,
        bcHash: bcHash
      });
      report.vmCompiled++;
      report.vmCompiledNames.push(c.fullName || c.name);
    }
  }
  report.bailReasons = Array.from(bailReasons.entries()).map(([n, r]) => `${n}: ${r}`);
  const replacedCode = generate(ast, {
    compact: false,
    retainLines: false
  }).code;
  let obfOpts;
  if (compact) {
    obfOpts = {
      compact: true,
      renameGlobals: false,
      identifierNamesGenerator: 'hexadecimal',
      stringArray: true,
      stringArrayEncoding: ['base64'],
      stringArrayThreshold: 0.5,
      stringArrayWrappersCount: 1,
      stringArrayWrappersChainedCalls: false,
      stringArrayWrappersType: 'function',
      stringArrayRotate: true,
      stringArrayShuffle: true,
      controlFlowFlattening: true,
      controlFlowFlatteningThreshold: 0.25,
      deadCodeInjection: false,
      debugProtection: false,
      disableConsoleOutput: false,
      selfDefending: false,
      numbersToExpressions: false,
      splitStrings: false,
      seed: seed,
      sourceMap: false,
      ignoreImports: true,
      reservedNames: ARMOR_RESERVED_NAMES,
      reservedStrings: [],
      target: 'browser'
    };
  } else {
    obfOpts = {
      ...PROFILES.max.options,
      seed,
      reservedNames: ARMOR_RESERVED_NAMES,
      stringArrayEncoding: ['base64'],
      deadCodeInjectionThreshold: 0.15,
      stringArrayThreshold: 0.6,
      splitStrings: false,
      compact: true,
      numbersToExpressions: true,
      identifierNamesGenerator: 'mangled'
    };
  }
  if (antiDebug) {
    obfOpts.debugProtection = true;
    obfOpts.debugProtectionInterval = 2000;
  }
  if (consoleOff) obfOpts.disableConsoleOutput = true;
  obfOpts.selfDefending = false;
  const obfResult = JavaScriptObfuscator.obfuscate(replacedCode, obfOpts);
  const obfuscated = obfResult.getObfuscatedCode();
  report.bytesAfterObf = obfuscated.length;
  const wrapper = await buildArmorWrapper({
    vmFunctions,
    seed,
    v2Key,
    obfuscatedUserCode: obfuscated,
    compact,
    antiDebug
  });
  const terserOpts = compact ? {
    toplevel: true,
    mangle: {
      toplevel: true
    },
    format: {
      comments: false,
      ecma: 2020
    },
    compress: {
      dead_code: true,
      inline: 2,
      conditionals: true,
      sequences: true,
      reduce_vars: true,
      ecma: 2020,
      passes: 3,
      drop_console: consoleOff,
      drop_debugger: true,
      unused: true,
      toplevel: true,
      join_vars: true,
      collapse_vars: true,
      computed_props: true,
      hoist_props: true
    },
    ecma: 2020
  } : {
    toplevel: false,
    mangle: {
      toplevel: false
    },
    format: {
      comments: false,
      ecma: 2020
    },
    compress: {
      dead_code: true,
      inline: 1,
      conditionals: true,
      sequences: true,
      reduce_vars: true,
      ecma: 2020,
      passes: 1
    },
    ecma: 2020
  };
  const terserResult = await minify({
    'armor.js': wrapper
  }, terserOpts);
  if (terserResult.error) throw new Error('Terser: ' + terserResult.error);
  const minified = terserResult.code || wrapper;
  const preGate = header + minified;
  report.bytesAfterTerser = preGate.length;
  try {
    verifyParses(preGate);
  } catch (err) {
    throw new Error(`armor output does not parse: ${err.message}`);
  }
  let finalCode = minified;
  if (gate) {
    const gateResult = wrapWithGate(finalCode, v2Key);
    finalCode = gateResult.code;
    finalCode = finalCode.replace('(0,eval)(src);', 'eval(src);');
    try {
      verifyParses(header + finalCode);
    } catch (err) {
      throw new Error(`gate-wrapped output does not parse: ${err.message}`);
    }
  }
  const final = header + finalCode;
  report.bytesAfterGate = final.length;
  return {
    code: final,
    stats: report,
    report
  };
}
function deriveWasmKey(v2Key) {
  const wasmSeed = (v2Key.antidebugSeed ^ 0x517CC1B7) >>> 0;
  const rng = mulberry32(wasmSeed);
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = Math.floor(rng() * 256);
  return key;
}
async function buildArmorWrapper({
  vmFunctions,
  seed,
  v2Key,
  obfuscatedUserCode,
  compact = false,
  antiDebug = false
}) {
  let prngState = seed >>> 0 || 1;
  const rand = () => {
    prngState = Math.imul(prngState, 1664525) + 1013904223 >>> 0;
    return prngState;
  };
  const randByte = () => rand() & 0xff;
  const vmSrc = runtimeSource(v2Key, {
    antidebug: antiDebug,
    integrityHash: 0
  });
  const guardHash = fnv1a(vmSrc);
  const keyEnc = _buildKeyEncoding(v2Key);
  const MASK = (guardHash >>> 8 & 0x7F) + 0x40;
  const healKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) healKey[i] = randByte();
  const fnKeys = vmFunctions.map(() => {
    const k = new Uint8Array(32);
    for (let i = 0; i < 32; i++) k[i] = randByte();
    return k;
  });
  const vmFuncsEncoded = vmFunctions.map((f, fi) => {
    const fnKey = fnKeys[fi];
    const bcBytes = new Uint8Array(f.bytecode);
    const bcEnc = new Uint8Array(bcBytes.length);
    for (let i = 0; i < bcBytes.length; i++) {
      bcEnc[i] = bcBytes[i] ^ fnKey[i % fnKey.length];
    }
    const stringsEnc = f.strings.map((s, si) => {
      const sb = new TextEncoder().encode(s);
      const out = new Uint8Array(sb.length);
      const offset = si * 7 % fnKey.length;
      for (let i = 0; i < sb.length; i++) {
        out[i] = sb[i] ^ fnKey[(i + offset) % fnKey.length];
      }
      return b64(out);
    });
    const maskedKey = new Uint8Array(fnKey.length);
    for (let i = 0; i < fnKey.length; i++) maskedKey[i] = fnKey[i] ^ MASK;
    const keyHalf1 = b64(maskedKey.slice(0, 16));
    const keyHalf2 = b64(maskedKey.slice(16));
    return {
      bytecode: b64(bcEnc),
      strings: stringsEnc,
      captures: f.captures,
      k1: keyHalf1,
      k2: keyHalf2,
      n: f.strings.length,
      h: f.bcHash >>> 0
    };
  });
  const heal = buildSelfHealSnippet({
    originalSource: vmSrc,
    key: healKey,
    brokenFnName: '__vmRuntime',
    mask: MASK
  });
  const includeSelfHeal = !compact;
  const wasmBytes = Uint8Array.from(atob(WASM_BASE64), c => c.charCodeAt(0));
  const wasmKey = deriveWasmKey(v2Key);
  const wasmEncrypted = new Uint8Array(wasmBytes.length);
  for (let i = 0; i < wasmBytes.length; i++) {
    wasmEncrypted[i] = wasmBytes[i] ^ wasmKey[i % wasmKey.length];
  }
  const decoyLen = compact ? 20 + (randByte() & 0x1F) : 200 + (randByte() & 0x7F);
  const decoy = new Uint8Array(decoyLen + wasmEncrypted.length + (compact ? 10 : 50));
  for (let i = 0; i < decoy.length; i++) decoy[i] = randByte();
  const wasmOffset = compact ? 5 + (randByte() & 0x0F) : 30 + (randByte() & 0x3F);
  decoy.set(wasmEncrypted, wasmOffset);
  const wasmEnd = wasmOffset + wasmEncrypted.length;
  const fullBlobB64 = b64(decoy);
  const maskedWasmKey = new Uint8Array(wasmKey.length);
  for (let i = 0; i < wasmKey.length; i++) maskedWasmKey[i] = wasmKey[i] ^ MASK;
  const maskedWasmKeyB64 = b64(maskedWasmKey);
  const healSnippet = includeSelfHeal ? heal.snippet.replace(/;$/, '') : '';
  const wrapper = `(function(){
    var __blob = ${JSON.stringify(fullBlobB64)};
    var __wasmOff = ${wasmOffset};
    var __wasmEnd = ${wasmEnd};
    var __wasmEncKey = ${JSON.stringify(maskedWasmKeyB64)};
    var __wasmInstance = null;
    var __wasmMem = null;
    var __wasmDecode = null;
    function __initWasm() {
      if (__wasmInstance) return;
      var all = Uint8Array.from(atob(__blob), function(c){return c.charCodeAt(0);});
      var enc = all.slice(__wasmOff, __wasmEnd);

      var mk = Uint8Array.from(atob(__wasmEncKey), function(c){return c.charCodeAt(0);});
      var wk = new Uint8Array(mk.length);
      for (var ki = 0; ki < mk.length; ki++) wk[ki] = mk[ki] ^ __MASK;
      var wasmBytes = new Uint8Array(enc.length);
      for (var wi = 0; wi < enc.length; wi++) wasmBytes[wi] = enc[wi] ^ wk[wi % wk.length];
      __wasmInstance = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes), {});
      __wasmMem = __wasmInstance.exports.memory;
      __wasmDecode = __wasmInstance.exports.decode;
    }
    function __wasmXor(bytes, keyBytes) {
      __initWasm();
      var needed = bytes.length + keyBytes.length + 16;
      var pagesNeeded = Math.max(0, Math.ceil(needed / 65536) - ((__wasmMem.buffer.byteLength / 65536) | 0));
      if (pagesNeeded > 0) __wasmMem.grow(pagesNeeded);
      var buf = new Uint8Array(__wasmMem.buffer);
      buf.set(bytes, 0);
      buf.set(keyBytes, bytes.length + 8);
      __wasmDecode(0, bytes.length, bytes.length + 8, keyBytes.length);
      return buf.slice(0, bytes.length);
    }
    var __vmGuardHash = ${guardHash >>> 0};
    var __MASK = ((__vmGuardHash >>> 8) & 0x7F) + 0x40;

    var __aseed = ${keyEnc.antidebugSeedEnc >>> 0};
    var __ax = ${keyEnc.antidebugSeedXor >>> 0};
    var __pk0 = atob("${keyEnc.permKeyChunks[0]}");
    var __pk1 = atob("${keyEnc.permKeyChunks[1]}");
    var __pk2 = atob("${keyEnc.permKeyChunks[2]}");
    var __pk3 = atob("${keyEnc.permKeyChunks[3]}");
    var __mk0 = ${keyEnc.permMasks[0]};
    var __mk1 = ${keyEnc.permMasks[1]};
    var __mk2 = ${keyEnc.permMasks[2]};
    var __mk3 = ${keyEnc.permMasks[3]};
    function __pkGet(i){var c=(i>>>6)&3,o=i&63;return (c===0?__pk0.charCodeAt(o)^__mk0:c===1?__pk1.charCodeAt(o)^__mk1:c===2?__pk2.charCodeAt(o)^__mk2:__pk3.charCodeAt(o)^__mk3)&255;}
    function __kih(b){var h=(0x811c9dc5^(__aseed^__ax))>>>0;var len=b.length;h=Math.imul(h^len,0x01000193);for(var i=0;i<len;i++){h^=b[i];h=Math.imul(h,0x01000193);if((i&15)===15){h^=__pkGet(i&255);h=Math.imul(h,0x01000193);}}return h>>>0;}
    function __getFnKey(meta) {
      var m1 = Uint8Array.from(atob(meta.k1), function(c){return c.charCodeAt(0);});
      var m2 = Uint8Array.from(atob(meta.k2), function(c){return c.charCodeAt(0);});
      var k = new Uint8Array(m1.length + m2.length);
      for (var i = 0; i < m1.length; i++) k[i] = m1[i] ^ __MASK;
      for (var j = 0; j < m2.length; j++) k[m1.length + j] = m2[j] ^ __MASK;
      return k;
    }
    var __vmRuntime = null;

    function __installVmRuntime() {
      var src = ${JSON.stringify(vmSrc)};
      var h = 0x811c9dc5;
      for (var i = 0; i < src.length; i++) {
        h ^= src.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
      }
      h = h >>> 0;
      if (h !== __vmGuardHash) {
        ${healSnippet ? 'try{' + healSnippet + '}catch(_){}' : ''}
        if (!__vmRuntime) throw new Error('integrity');
      } else {
        __vmRuntime = (new Function(src + '\\n; return createVM;'))();
      }
    }
    var __vmFuncs = ${JSON.stringify(vmFuncsEncoded)};
    var __vmCache = [];

    function __decodeBc(meta, fnKey) {
      var enc = Uint8Array.from(atob(meta.bytecode), function(c){return c.charCodeAt(0);});
      var dec = __wasmXor(enc, fnKey);
      return dec;
    }
    function __decodeStr(meta, strB64, idx, fnKey) {
      var enc = Uint8Array.from(atob(strB64), function(c){return c.charCodeAt(0);});

      var offset = (idx * 7) % fnKey.length;

      var shiftedKey = new Uint8Array(fnKey.length);
      for (var i = 0; i < fnKey.length; i++) {
        shiftedKey[i] = fnKey[(i + offset) % fnKey.length];
      }
      var dec = __wasmXor(enc, shiftedKey);
      return new TextDecoder().decode(dec);
    }

    function __getVmForIndex(idx) {
      if (__vmCache[idx]) return __vmCache[idx];
      if (!__vmRuntime) __installVmRuntime();
      var meta = __vmFuncs[idx];
      var fnKey = __getFnKey(meta);
      var bytecode = __decodeBc(meta, fnKey);
      var strings = meta.strings.map(function(s, i){return __decodeStr(meta, s, i, fnKey);});
      var captures = meta.captures.map(function(){return undefined;});

      var vm = __vmRuntime({ strings: strings, captures: captures, antidebug: ${antiDebug ? 'true' : 'false'}, integrityHash: meta.h >>> 0 });
      var entry = { vm: vm, captures: captures, captureNames: meta.captures, vmBytecode: bytecode };
      __vmCache[idx] = entry;
      return entry;
    }

    var __captureRegistry = Object.create(null);
    var __vm = {
      run: function(idx, args, expectedHash) {
        var entry = __getVmForIndex(idx);

        var bc = entry.vmBytecode;
        var actualHash = __kih(bc);
        var meta = __vmFuncs[idx];
        var registryHash = meta ? (meta.h >>> 0) : 0;
        if (actualHash !== registryHash) {
          throw new Error('integrity');
        }
        for (var i = 0; i < entry.captureNames.length; i++) {
          var n = entry.captureNames[i];
          if (n in __captureRegistry) {
            entry.captures[i] = __captureRegistry[n];
          } else if (typeof globalThis !== 'undefined' && n in globalThis) {
            entry.captures[i] = globalThis[n];
          } else if (typeof window !== 'undefined' && n in window) {
            entry.captures[i] = window[n];
          }
        }
        return entry.vm.execute(entry.vmBytecode, args || []);
      },
      registerCapture: function(name, value) { __captureRegistry[name] = value; },
    };

    ${obfuscatedUserCode}
  })();`;
  return wrapper;
}
function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return typeof globalThis !== 'undefined' && globalThis.btoa ? globalThis.btoa(s) : Buffer.from(s, 'binary').toString('base64');
}