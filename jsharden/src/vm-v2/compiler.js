import { parse } from '@babel/parser';
import * as t from '@babel/types';
import { OP_META, ARG_WIDTHS } from './opcodes.js';
import { generateKey } from './keygen.js';
import { buildOpcodeTable, pickAlias } from './opcode-table.js';
import { encryptBytecode, keyedIntegrityHash } from './cipher.js';
import { applyFusion } from './fusion.js';
const BIN_OPS = {
  '+': 'ADD',
  '-': 'SUB',
  '*': 'MUL',
  '/': 'DIV',
  '%': 'MOD',
  '==': 'EQ',
  '!=': 'NEQ',
  '===': 'SEQ',
  '!==': 'SNEQ',
  '<': 'LT',
  '<=': 'LTE',
  '>': 'GT',
  '>=': 'GTE',
  'in': 'IN',
  'instanceof': 'INSTANCEOF',
  '&': 'BIT_AND',
  '|': 'BIT_OR',
  '^': 'BIT_XOR',
  '<<': 'SHL',
  '>>': 'SHR',
  '>>>': 'USHR'
};
const UN_OPS = {
  '-': 'NEG',
  '+': 'POS',
  '!': 'NOT',
  '~': 'BIT_NOT',
  'void': 'VOID',
  'typeof': 'TYPEOF'
};
const ASSIGN_COMPOUND = {
  '+=': 'ADD',
  '-=': 'SUB',
  '*=': 'MUL',
  '/=': 'DIV',
  '%=': 'MOD',
  '&=': 'BIT_AND',
  '|=': 'BIT_OR',
  '^=': 'BIT_XOR',
  '<<=': 'SHL',
  '>>=': 'SHR',
  '>>>=': 'USHR'
};
const LABEL_OP = '__LABEL';
export function compileFunction(src, key) {
  let ast;
  try {
    ast = parse(src, {
      sourceType: 'script',
      allowReturnOutsideFunction: true,
      plugins: ['objectRestSpread', 'optionalChaining', 'nullishCoalescingOperator']
    });
  } catch (err) {
    return bail(`parse: ${err.message}`);
  }
  const stmt = ast.program.body[0];
  let fnExpr;
  let isAsync = false;
  let isGenerator = false;
  if (t.isExpressionStatement(stmt) && (t.isArrowFunctionExpression(stmt.expression) || t.isFunctionExpression(stmt.expression))) {
    fnExpr = stmt.expression;
    isAsync = !!fnExpr.async;
    isGenerator = !!fnExpr.generator;
  } else if (t.isFunctionDeclaration(stmt)) {
    fnExpr = t.functionExpression(null, stmt.params, stmt.body);
    isAsync = !!stmt.async;
    isGenerator = !!stmt.generator;
  } else {
    return bail('not a function');
  }
  if (!key) key = generateKey();
  if (isAsync && bodyHasAwait(fnExpr.body)) {
    return bail('async function with await not supported');
  }
  if (isGenerator) return bail('generator function not supported');
  const ctx = new Ctx();
  try {
    compileFn(ctx, fnExpr);
  } catch (e) {
    if (e && e.code === 'BAIL') return bail(e.message);
    throw e;
  }
  const originalLen = ctx.instrs.length;
  let fusedInstrs = ctx.instrs;
  try {
    fusedInstrs = applyFusion(ctx.instrs);
  } catch (_e) {
    fusedInstrs = ctx.instrs;
  }
  if (!Array.isArray(fusedInstrs)) fusedInstrs = ctx.instrs;
  let plainBytes;
  try {
    const table = buildOpcodeTable(key);
    plainBytes = encodeToBytes(fusedInstrs, table, key);
  } catch (e) {
    return bail(`encode: ${e && e.message ? e.message : String(e)}`);
  }
  if (plainBytes.length > 0xFFFF) return bail('bytecode too large (>64KB)');
  if (ctx.strings.length > 0xFFFF) return bail('too many strings (>65535)');
  const encryptedBytes = encryptBytecode(plainBytes, key);
  const integrityHash = keyedIntegrityHash(encryptedBytes, key) >>> 0;
  return {
    canCompile: true,
    bytecode: encryptedBytes,
    strings: ctx.strings,
    captures: ctx.captureNames,
    maxLocals: ctx.maxLocals,
    error: null,
    meta: {
      key,
      integrityHash,
      opCount: ctx.instrs.filter(i => i.op !== LABEL_OP).length,
      fusedCount: Math.max(0, originalLen - fusedInstrs.length),
      plainBytes: plainBytes.length,
      encryptedBytes: encryptedBytes.length
    }
  };
}
function bail(msg) {
  return {
    canCompile: false,
    bytecode: new Uint8Array(0),
    strings: [],
    captures: [],
    maxLocals: 0,
    error: msg,
    meta: null
  };
}
function bailT(msg) {
  const e = new Error(msg);
  e.code = 'BAIL';
  throw e;
}
function bodyHasAwait(fnBody) {
  function walk(node) {
    if (!node || typeof node !== 'object') return false;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        if (walk(node[i])) return true;
      }
      return false;
    }
    if (t.isAwaitExpression(node)) return true;
    if (t.isFunction(node)) return false;
    const keys = t.VISITOR_KEYS[node.type];
    if (keys) {
      for (let i = 0; i < keys.length; i++) {
        if (walk(node[keys[i]])) return true;
      }
    }
    return false;
  }
  return walk(fnBody);
}
class Ctx {
  constructor() {
    this.instrs = [];
    this.strings = [];
    this.strIdx = new Map();
    this.captureNames = [];
    this.capIdx = new Map();
    this.scopes = [];
    this.functionScope = null;
    this.maxLocals = 0;
    this.loops = [];
    this.tryDepth = 0;
    this.labelCounter = 0;
  }
  internStr(s) {
    if (this.strIdx.has(s)) return this.strIdx.get(s);
    if (this.strings.length > 0xFFFF) bailT('too many strings (>65535)');
    const i = this.strings.length;
    this.strings.push(s);
    this.strIdx.set(s, i);
    return i;
  }
  internCap(name) {
    if (this.capIdx.has(name)) return this.capIdx.get(name);
    if (this.captureNames.length >= 255) bailT('too many captures (>255)');
    const i = this.captureNames.length;
    this.captureNames.push(name);
    this.capIdx.set(name, i);
    return i;
  }
  pushScope() {
    const parent = this.scopes.length ? this.peek() : null;
    this.scopes.push({
      locals: new Map(),
      next: parent ? parent.next : 0
    });
  }
  popScope() {
    this.scopes.pop();
  }
  peek() {
    return this.scopes[this.scopes.length - 1];
  }
  declare(name) {
    const s = this.peek();
    if (s.next >= 255) bailT('too many locals (>255)');
    const i = s.next++;
    s.locals.set(name, i);
    if (s.next > this.maxLocals) this.maxLocals = s.next;
    return i;
  }
  declareVar(name) {
    const s = this.functionScope;
    if (s.locals.has(name)) return s.locals.get(name);
    let i = 0;
    for (const scope of this.scopes) {
      if (scope.next > i) i = scope.next;
    }
    s.next = i + 1;
    s.locals.set(name, i);
    if (s.next > this.maxLocals) this.maxLocals = s.next;
    for (const scope of this.scopes) {
      if (scope.next < s.next) scope.next = s.next;
    }
    return i;
  }
  resolveLocal(name) {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const s = this.scopes[i];
      if (s.locals.has(name)) return s.locals.get(name);
    }
    return -1;
  }
  newLabel() {
    return 'L' + this.labelCounter++;
  }
  emitLabel(name) {
    this.instrs.push({
      op: LABEL_OP,
      args: [name]
    });
  }
  emit(op, arg) {
    if (arg === undefined || arg === null) this.instrs.push({
      op,
      args: []
    });else if (Array.isArray(arg)) this.instrs.push({
      op,
      args: arg
    });else this.instrs.push({
      op,
      args: [arg]
    });
  }
}
function compileFn(ctx, fn) {
  ctx.pushScope();
  ctx.functionScope = ctx.peek();
  const defaults = [];
  for (const p of fn.params) {
    if (t.isIdentifier(p)) {
      ctx.declare(p.name);
    } else if (t.isAssignmentPattern(p)) {
      if (!t.isIdentifier(p.left)) bailT('non-identifier param');
      const idx = ctx.declare(p.left.name);
      defaults.push({
        idx,
        default: p.right
      });
    } else {
      bailT('non-identifier param');
    }
  }
  for (const d of defaults) {
    ctx.emit('LOAD_LOCAL', d.idx);
    ctx.emit('PUSH_UNDEF');
    ctx.emit('SEQ');
    const skip = ctx.newLabel();
    ctx.emit('JZ', skip);
    compileExpr(ctx, d.default);
    ctx.emit('STORE_LOCAL', d.idx);
    ctx.emitLabel(skip);
  }
  if (t.isBlockStatement(fn.body)) {
    compileBlock(ctx, fn.body);
    ctx.emit('RET_UNDEF');
  } else {
    compileExpr(ctx, fn.body);
    ctx.emit('RET');
  }
  ctx.popScope();
}
function compileBlock(ctx, block) {
  ctx.pushScope();
  for (const s of block.body) compileStmt(ctx, s);
  ctx.popScope();
}
function compileStmt(ctx, s) {
  if (t.isReturnStatement(s)) {
    if (s.argument) {
      compileExpr(ctx, s.argument);
      ctx.emit('RET');
    } else ctx.emit('RET_UNDEF');
    return;
  }
  if (t.isExpressionStatement(s)) {
    compileExpr(ctx, s.expression);
    ctx.emit('POP');
    return;
  }
  if (t.isVariableDeclaration(s)) {
    for (const d of s.declarations) {
      if (!t.isIdentifier(d.id)) bailT('non-identifier var');
      const i = s.kind === 'var' ? ctx.declareVar(d.id.name) : ctx.declare(d.id.name);
      if (d.init) compileExpr(ctx, d.init);else ctx.emit('PUSH_UNDEF');
      ctx.emit('STORE_LOCAL', i);
    }
    return;
  }
  if (t.isIfStatement(s)) {
    compileExpr(ctx, s.test);
    const jzLabel = ctx.newLabel();
    ctx.emit('JZ', jzLabel);
    compileStmt(ctx, s.consequent);
    if (s.alternate) {
      const jmpLabel = ctx.newLabel();
      ctx.emit('JMP', jmpLabel);
      ctx.emitLabel(jzLabel);
      compileStmt(ctx, s.alternate);
      ctx.emitLabel(jmpLabel);
    } else {
      ctx.emitLabel(jzLabel);
    }
    return;
  }
  if (t.isBlockStatement(s)) {
    compileBlock(ctx, s);
    return;
  }
  if (t.isEmptyStatement(s)) return;
  if (t.isForStatement(s) || t.isWhileStatement(s) || t.isDoWhileStatement(s)) {
    compileLoop(ctx, s);
    return;
  }
  if (t.isForInStatement(s) || t.isForOfStatement(s)) {
    compileForInOrOf(ctx, s);
    return;
  }
  if (t.isSwitchStatement(s)) {
    compileSwitch(ctx, s);
    return;
  }
  if (t.isBreakStatement(s)) {
    const top = ctx.loops[ctx.loops.length - 1];
    if (!top) bailT('break outside loop');
    emitTryExitsForJump(ctx, top);
    ctx.emit('JMP', top.breakLabel);
    return;
  }
  if (t.isContinueStatement(s)) {
    const top = ctx.loops[ctx.loops.length - 1];
    if (!top) bailT('continue outside loop');
    emitTryExitsForJump(ctx, top);
    ctx.emit('JMP', top.continueLabel);
    return;
  }
  if (t.isThrowStatement(s)) {
    compileExpr(ctx, s.argument);
    ctx.emit('THROW');
    return;
  }
  if (t.isTryStatement(s)) {
    if (s.finalizer) bailT('try/finally');
    if (!s.handler) bailT('try without catch');
    if (s.handler.param && !t.isIdentifier(s.handler.param)) bailT('non-identifier catch');
    const catchLabel = ctx.newLabel();
    ctx.emit('TRY_ENTER', catchLabel);
    ctx.tryDepth++;
    compileStmt(ctx, s.block);
    ctx.emit('TRY_EXIT');
    ctx.tryDepth--;
    const afterLabel = ctx.newLabel();
    ctx.emit('JMP', afterLabel);
    ctx.emitLabel(catchLabel);
    ctx.pushScope();
    const catchIdx = s.handler.param ? ctx.declare(s.handler.param.name) : -1;
    if (catchIdx >= 0) ctx.emit('STORE_LOCAL', catchIdx);else ctx.emit('POP');
    compileStmt(ctx, s.handler.body);
    ctx.popScope();
    ctx.emitLabel(afterLabel);
    return;
  }
  bailT(`unsupported statement: ${s.type}`);
}
function emitTryExitsForJump(ctx, loopFrame) {
  const exits = ctx.tryDepth - loopFrame.tryDepth;
  for (let i = 0; i < exits; i++) ctx.emit('TRY_EXIT');
}
function compileLoop(ctx, s) {
  ctx.pushScope();
  if (t.isForStatement(s) && s.init) {
    if (t.isVariableDeclaration(s.init)) compileStmt(ctx, s.init);else {
      compileExpr(ctx, s.init);
      ctx.emit('POP');
    }
  }
  if (t.isDoWhileStatement(s)) {
    const loopStartLabel = ctx.newLabel();
    ctx.emitLabel(loopStartLabel);
    const breakLabel = ctx.newLabel();
    const continueLabel = ctx.newLabel();
    const frame = {
      breakLabel,
      continueLabel,
      isDoWhile: true,
      tryDepth: ctx.tryDepth
    };
    ctx.loops.push(frame);
    compileStmt(ctx, s.body);
    ctx.emitLabel(continueLabel);
    compileExpr(ctx, s.test);
    ctx.emit('JNZ', loopStartLabel);
    ctx.emitLabel(breakLabel);
    ctx.loops.pop();
    ctx.popScope();
    return;
  }
  const loopStartLabel = ctx.newLabel();
  ctx.emitLabel(loopStartLabel);
  const breakLabel = ctx.newLabel();
  const continueLabel = ctx.newLabel();
  const frame = {
    breakLabel,
    continueLabel,
    isDoWhile: false,
    tryDepth: ctx.tryDepth
  };
  ctx.loops.push(frame);
  if (t.isWhileStatement(s) || t.isForStatement(s)) {
    if (s.test) {
      compileExpr(ctx, s.test);
      ctx.emit('JZ', breakLabel);
    }
    compileStmt(ctx, s.body);
  }
  ctx.emitLabel(continueLabel);
  if (t.isForStatement(s) && s.update) {
    compileExpr(ctx, s.update);
    ctx.emit('POP');
  }
  ctx.emit('JMP', loopStartLabel);
  ctx.emitLabel(breakLabel);
  ctx.loops.pop();
  ctx.popScope();
}
function compileForInOrOf(ctx, s) {
  ctx.pushScope();
  let leftIdx;
  if (t.isVariableDeclaration(s.left)) {
    const decl = s.left.declarations[0];
    if (!t.isIdentifier(decl.id)) bailT('non-identifier loop var');
    leftIdx = ctx.declare(decl.id.name);
  } else if (t.isIdentifier(s.left)) {
    leftIdx = ctx.resolveLocal(s.left.name);
    if (leftIdx < 0) bailT('for-in/of with capture target not supported');
  } else {
    bailT('non-identifier loop var');
  }
  if (t.isForInStatement(s)) {
    ctx.emit('LOAD_CAPTURE', ctx.internCap('Object'));
    compileExpr(ctx, s.right);
    ctx.emit('CALL_METHOD', [1, ctx.internStr('keys')]);
    ctx.emit('GET_ITER');
  } else {
    compileExpr(ctx, s.right);
    ctx.emit('GET_ITER');
  }
  const iterIdx = ctx.declare('__iter');
  ctx.emit('STORE_LOCAL', iterIdx);
  const loopStartLabel = ctx.newLabel();
  const bodyLabel = ctx.newLabel();
  const breakLabel = ctx.newLabel();
  ctx.emitLabel(loopStartLabel);
  ctx.emit('LOAD_LOCAL', iterIdx);
  ctx.emit('ITER_NEXT');
  ctx.emit('DUP');
  ctx.emit('GET_PROP', ctx.internStr('done'));
  ctx.emit('JZ', bodyLabel);
  ctx.emit('POP');
  ctx.emit('JMP', breakLabel);
  ctx.emitLabel(bodyLabel);
  ctx.emit('GET_PROP', ctx.internStr('value'));
  ctx.emit('STORE_LOCAL', leftIdx);
  const frame = {
    breakLabel,
    continueLabel: loopStartLabel,
    isDoWhile: false,
    tryDepth: ctx.tryDepth
  };
  ctx.loops.push(frame);
  compileStmt(ctx, s.body);
  ctx.loops.pop();
  ctx.emit('JMP', loopStartLabel);
  ctx.emitLabel(breakLabel);
  ctx.popScope();
}
function compileSwitch(ctx, s) {
  ctx.pushScope();
  compileExpr(ctx, s.discriminant);
  const breakLabel = ctx.newLabel();
  const enclosing = ctx.loops[ctx.loops.length - 1];
  const continueLabel = enclosing ? ctx.newLabel() : breakLabel;
  const frame = {
    breakLabel,
    continueLabel,
    isDoWhile: false,
    tryDepth: ctx.tryDepth
  };
  ctx.loops.push(frame);
  const caseLabels = s.cases.map(() => ctx.newLabel());
  let defaultIdx = -1;
  for (let i = 0; i < s.cases.length; i++) {
    if (s.cases[i].test === null) {
      defaultIdx = i;
      break;
    }
  }
  for (let i = 0; i < s.cases.length; i++) {
    const c = s.cases[i];
    if (c.test === null) continue;
    ctx.emit('DUP');
    compileExpr(ctx, c.test);
    ctx.emit('SEQ');
    ctx.emit('JNZ', caseLabels[i]);
  }
  ctx.emit('JMP', defaultIdx >= 0 ? caseLabels[defaultIdx] : breakLabel);
  for (let i = 0; i < s.cases.length; i++) {
    ctx.emitLabel(caseLabels[i]);
    for (const stmt of s.cases[i].consequent) compileStmt(ctx, stmt);
  }
  ctx.emit('JMP', breakLabel);
  if (enclosing) {
    ctx.emitLabel(continueLabel);
    ctx.emit('POP');
    ctx.emit('JMP', enclosing.continueLabel);
  }
  ctx.emitLabel(breakLabel);
  ctx.emit('POP');
  ctx.loops.pop();
  ctx.popScope();
}
function compileExpr(ctx, e, chainEnd) {
  if (t.isNullLiteral(e)) {
    ctx.emit('PUSH_NULL');
    return;
  }
  if (t.isIdentifier(e)) {
    if (e.name === 'undefined') {
      ctx.emit('PUSH_UNDEF');
      return;
    }
    if (e.name === 'arguments') bailT('arguments object not supported in VM');
    const li = ctx.resolveLocal(e.name);
    if (li >= 0) {
      ctx.emit('LOAD_LOCAL', li);
      return;
    }
    ctx.emit('LOAD_CAPTURE', ctx.internCap(e.name));
    return;
  }
  if (t.isBigIntLiteral(e)) bailT('bigint not supported');
  if (t.isNumericLiteral(e)) {
    const n = Number(e.value);
    if (Object.is(n, -0)) {
      ctx.emit('PUSH_FLOAT', n);
      return;
    }
    if (Number.isInteger(n) && n >= -0x80000000 && n <= 0x7fffffff) ctx.emit('PUSH_INT', n | 0);else ctx.emit('PUSH_FLOAT', n);
    return;
  }
  if (t.isStringLiteral(e)) {
    ctx.emit('PUSH_STR', ctx.internStr(e.value));
    return;
  }
  if (t.isBooleanLiteral(e)) {
    ctx.emit(e.value ? 'PUSH_TRUE' : 'PUSH_FALSE');
    return;
  }
  if (t.isRegExpLiteral(e)) {
    ctx.emit('LOAD_CAPTURE', ctx.internCap('RegExp'));
    ctx.emit('PUSH_STR', ctx.internStr(e.pattern));
    ctx.emit('PUSH_STR', ctx.internStr(e.flags || ''));
    ctx.emit('NEW', 2);
    return;
  }
  if (t.isTemplateLiteral(e)) {
    if (e.expressions.length === 0) {
      ctx.emit('PUSH_STR', ctx.internStr(e.quasis[0].value.cooked));
      return;
    }
    ctx.emit('PUSH_STR', ctx.internStr(e.quasis[0].value.cooked));
    for (let i = 0; i < e.expressions.length; i++) {
      compileExpr(ctx, e.expressions[i]);
      ctx.emit('ADD');
      ctx.emit('PUSH_STR', ctx.internStr(e.quasis[i + 1].value.cooked));
      ctx.emit('ADD');
    }
    return;
  }
  if (t.isThisExpression(e)) {
    ctx.emit('LOAD_CAPTURE', ctx.internCap('this'));
    return;
  }
  if (t.isBinaryExpression(e)) {
    const op = BIN_OPS[e.operator];
    if (!op) bailT(`unsupported binary op: ${e.operator}`);
    compileExpr(ctx, e.left);
    compileExpr(ctx, e.right);
    ctx.emit(op);
    return;
  }
  if (t.isUnaryExpression(e)) {
    const op = UN_OPS[e.operator];
    if (!op) bailT(`unsupported unary op: ${e.operator}`);
    compileExpr(ctx, e.argument);
    ctx.emit(op);
    return;
  }
  if (t.isLogicalExpression(e)) {
    if (e.operator === '??') {
      compileExpr(ctx, e.left);
      ctx.emit('DUP');
      ctx.emit('PUSH_NULL');
      ctx.emit('EQ');
      const keepLabel = ctx.newLabel();
      ctx.emit('JZ', keepLabel);
      ctx.emit('POP');
      compileExpr(ctx, e.right);
      ctx.emitLabel(keepLabel);
      return;
    }
    compileExpr(ctx, e.left);
    ctx.emit('DUP');
    const skipLabel = ctx.newLabel();
    ctx.emit(e.operator === '&&' ? 'JZ' : 'JNZ', skipLabel);
    ctx.emit('POP');
    compileExpr(ctx, e.right);
    ctx.emitLabel(skipLabel);
    return;
  }
  if (t.isConditionalExpression(e)) {
    compileExpr(ctx, e.test);
    const jzLabel = ctx.newLabel();
    ctx.emit('JZ', jzLabel);
    compileExpr(ctx, e.consequent);
    const jmpLabel = ctx.newLabel();
    ctx.emit('JMP', jmpLabel);
    ctx.emitLabel(jzLabel);
    compileExpr(ctx, e.alternate);
    ctx.emitLabel(jmpLabel);
    return;
  }
  if (t.isAssignmentExpression(e)) {
    compileAssign(ctx, e);
    return;
  }
  if (t.isUpdateExpression(e)) {
    if (!t.isIdentifier(e.argument)) bailT('update on non-identifier');
    const li = ctx.resolveLocal(e.argument.name);
    if (li < 0) bailT('update on capture');
    ctx.emit('LOAD_LOCAL', li);
    if (!e.prefix) {
      ctx.emit('DUP');
      ctx.emit('PUSH_INT', 1);
      ctx.emit(e.operator === '++' ? 'ADD' : 'SUB');
      ctx.emit('STORE_LOCAL', li);
      return;
    }
    ctx.emit('PUSH_INT', 1);
    ctx.emit(e.operator === '++' ? 'ADD' : 'SUB');
    ctx.emit('DUP');
    ctx.emit('STORE_LOCAL', li);
    return;
  }
  if (t.isCallExpression(e)) {
    if (t.isMemberExpression(e.callee) && !e.callee.computed && t.isIdentifier(e.callee.property)) {
      compileExpr(ctx, e.callee.object);
      for (const a of e.arguments) {
        if (t.isSpreadElement(a)) bailT('spread in call');
        compileExpr(ctx, a);
      }
      ctx.emit('CALL_METHOD', [e.arguments.length, ctx.internStr(e.callee.property.name)]);
      return;
    }
    if (t.isMemberExpression(e.callee) && e.callee.computed) {
      compileExpr(ctx, e.callee.object);
      ctx.emit('DUP');
      compileExpr(ctx, e.callee.property);
      ctx.emit('GET_ELEM');
      ctx.emit('SWAP');
      for (const a of e.arguments) {
        if (t.isSpreadElement(a)) bailT('spread in call');
        compileExpr(ctx, a);
      }
      ctx.emit('CALL_METHOD', [e.arguments.length + 1, ctx.internStr('call')]);
      return;
    }
    compileExpr(ctx, e.callee);
    for (const a of e.arguments) {
      if (t.isSpreadElement(a)) bailT('spread in call');
      compileExpr(ctx, a);
    }
    ctx.emit('CALL', e.arguments.length);
    return;
  }
  if (t.isNewExpression(e)) {
    compileExpr(ctx, e.callee);
    for (const a of e.arguments) {
      if (t.isSpreadElement(a)) bailT('spread in new');
      compileExpr(ctx, a);
    }
    ctx.emit('NEW', e.arguments.length);
    return;
  }
  if (t.isMemberExpression(e)) {
    compileExpr(ctx, e.object);
    if (e.computed) {
      compileExpr(ctx, e.property);
      ctx.emit('GET_ELEM');
    } else if (t.isIdentifier(e.property)) {
      ctx.emit('GET_PROP', ctx.internStr(e.property.name));
    } else bailT('non-identifier member property');
    return;
  }
  if (t.isOptionalMemberExpression(e)) {
    const isInChain = chainEnd != null;
    const myChainEnd = chainEnd != null ? chainEnd : ctx.newLabel();
    compileExpr(ctx, e.object, myChainEnd);
    if (e.optional) {
      ctx.emit('DUP');
      ctx.emit('PUSH_NULL');
      ctx.emit('EQ');
      const skip = ctx.newLabel();
      ctx.emit('JZ', skip);
      ctx.emit('POP');
      ctx.emit('PUSH_UNDEF');
      ctx.emit('JMP', myChainEnd);
      ctx.emitLabel(skip);
    }
    if (e.computed) {
      compileExpr(ctx, e.property);
      ctx.emit('GET_ELEM');
    } else if (t.isIdentifier(e.property)) {
      ctx.emit('GET_PROP', ctx.internStr(e.property.name));
    } else {
      bailT('non-identifier optional member property');
    }
    if (!isInChain) ctx.emitLabel(myChainEnd);
    return;
  }
  if (t.isOptionalCallExpression(e)) {
    compileOptionalCall(ctx, e, chainEnd);
    return;
  }
  if (t.isObjectExpression(e)) {
    ctx.emit('LOAD_CAPTURE', ctx.internCap('Object'));
    ctx.emit('NEW', 0);
    for (const p of e.properties) {
      if (!t.isObjectProperty(p)) bailT('non-property in object');
      if (p.computed) bailT('computed property key');
      if (t.isSpreadElement(p)) bailT('spread in object');
      let name;
      if (t.isIdentifier(p.key)) name = p.key.name;else if (t.isStringLiteral(p.key)) name = p.key.value;else if (t.isNumericLiteral(p.key)) name = String(p.key.value);else bailT('unsupported key type');
      ctx.emit('DUP');
      compileExpr(ctx, p.value);
      ctx.emit('SET_PROP', ctx.internStr(name));
    }
    return;
  }
  if (t.isArrayExpression(e)) {
    ctx.emit('LOAD_CAPTURE', ctx.internCap('Array'));
    ctx.emit('NEW', 0);
    for (let i = 0; i < e.elements.length; i++) {
      const el = e.elements[i];
      if (t.isSpreadElement(el)) bailT('spread in array');
      if (el === null) continue;
      ctx.emit('DUP');
      ctx.emit('PUSH_INT', i);
      compileExpr(ctx, el);
      ctx.emit('SET_ELEM');
    }
    if (e.elements.length > 0) {
      ctx.emit('DUP');
      ctx.emit('PUSH_INT', e.elements.length);
      ctx.emit('SET_PROP', ctx.internStr('length'));
    }
    return;
  }
  if (t.isSequenceExpression(e)) {
    for (let i = 0; i < e.expressions.length; i++) {
      compileExpr(ctx, e.expressions[i]);
      if (i < e.expressions.length - 1) ctx.emit('POP');
    }
    return;
  }
  bailT(`unsupported expression: ${e.type}`);
}
function compileOptionalCall(ctx, e, chainEnd) {
  const isInChain = chainEnd != null;
  const myChainEnd = chainEnd != null ? chainEnd : ctx.newLabel();
  const callee = e.callee;
  const args = e.arguments;
  const isME = t.isMemberExpression(callee);
  const isOME = t.isOptionalMemberExpression(callee);
  const isMemberLike = isME || isOME;
  const computed = isMemberLike && callee.computed;
  const calleeOptional = isOME && callee.optional;
  const hasIdentProp = isMemberLike && !computed && t.isIdentifier(callee.property);
  function shortCircuitTop() {
    ctx.emit('DUP');
    ctx.emit('PUSH_NULL');
    ctx.emit('EQ');
    const skip = ctx.newLabel();
    ctx.emit('JZ', skip);
    ctx.emit('POP');
    ctx.emit('PUSH_UNDEF');
    ctx.emit('JMP', myChainEnd);
    ctx.emitLabel(skip);
  }
  if (isMemberLike) {
    if (!hasIdentProp && !computed) bailT('non-identifier member property in optional call');
    compileExpr(ctx, callee.object, myChainEnd);
    if (calleeOptional) {
      shortCircuitTop();
    }
    if (computed) {
      ctx.emit('DUP');
      compileExpr(ctx, callee.property);
      ctx.emit('GET_ELEM');
    } else if (e.optional) {
      ctx.emit('DUP');
      ctx.emit('GET_PROP', ctx.internStr(callee.property.name));
    }
    if (e.optional) {
      ctx.emit('DUP');
      ctx.emit('PUSH_NULL');
      ctx.emit('EQ');
      const skipMethod = ctx.newLabel();
      ctx.emit('JZ', skipMethod);
      ctx.emit('POP');
      ctx.emit('POP');
      ctx.emit('PUSH_UNDEF');
      ctx.emit('JMP', myChainEnd);
      ctx.emitLabel(skipMethod);
    }
    if (computed) {
      ctx.emit('SWAP');
      for (const a of args) {
        if (t.isSpreadElement(a)) bailT('spread in call');
        compileExpr(ctx, a);
      }
      ctx.emit('CALL_METHOD', [args.length + 1, ctx.internStr('call')]);
    } else {
      if (e.optional) {
        ctx.emit('POP');
      }
      for (const a of args) {
        if (t.isSpreadElement(a)) bailT('spread in call');
        compileExpr(ctx, a);
      }
      ctx.emit('CALL_METHOD', [args.length, ctx.internStr(callee.property.name)]);
    }
  } else {
    compileExpr(ctx, callee, myChainEnd);
    if (e.optional) {
      shortCircuitTop();
    }
    for (const a of args) {
      if (t.isSpreadElement(a)) bailT('spread in call');
      compileExpr(ctx, a);
    }
    ctx.emit('CALL', args.length);
  }
  if (!isInChain) ctx.emitLabel(myChainEnd);
}
function compileAssign(ctx, e) {
  if (e.operator === '=') {
    compileExpr(ctx, e.right);
    if (t.isIdentifier(e.left)) {
      const li = ctx.resolveLocal(e.left.name);
      if (li >= 0) {
        ctx.emit('DUP');
        ctx.emit('STORE_LOCAL', li);
      } else {
        const ci = ctx.internCap(e.left.name);
        ctx.emit('DUP');
        ctx.emit('STORE_CAPTURE', ci);
      }
      return;
    }
    if (t.isMemberExpression(e.left)) {
      const tempIdx = ctx.declare('__t');
      ctx.emit('STORE_LOCAL', tempIdx);
      compileExpr(ctx, e.left.object);
      if (e.left.computed) {
        compileExpr(ctx, e.left.property);
        ctx.emit('LOAD_LOCAL', tempIdx);
        ctx.emit('SET_ELEM');
      } else if (t.isIdentifier(e.left.property)) {
        const nameIdx = ctx.internStr(e.left.property.name);
        ctx.emit('LOAD_LOCAL', tempIdx);
        ctx.emit('SET_PROP', nameIdx);
      } else bailT('non-identifier assignment target prop');
      ctx.emit('LOAD_LOCAL', tempIdx);
      return;
    }
    bailT('unsupported assignment target');
  }
  if (ASSIGN_COMPOUND[e.operator]) {
    const op = ASSIGN_COMPOUND[e.operator];
    if (t.isIdentifier(e.left)) {
      const li = ctx.resolveLocal(e.left.name);
      if (li >= 0) {
        ctx.emit('LOAD_LOCAL', li);
        compileExpr(ctx, e.right);
        ctx.emit(op);
        ctx.emit('DUP');
        ctx.emit('STORE_LOCAL', li);
      } else {
        const ci = ctx.internCap(e.left.name);
        ctx.emit('LOAD_CAPTURE', ci);
        compileExpr(ctx, e.right);
        ctx.emit(op);
        ctx.emit('DUP');
        ctx.emit('STORE_CAPTURE', ci);
      }
      return;
    }
    if (t.isMemberExpression(e.left)) {
      if (e.left.computed) {
        const oIdx = ctx.declare('__co');
        const kIdx = ctx.declare('__ck');
        const tIdx = ctx.declare('__ct');
        compileExpr(ctx, e.left.object);
        compileExpr(ctx, e.left.property);
        ctx.emit('STORE_LOCAL', kIdx);
        ctx.emit('STORE_LOCAL', oIdx);
        ctx.emit('LOAD_LOCAL', oIdx);
        ctx.emit('LOAD_LOCAL', kIdx);
        ctx.emit('GET_ELEM');
        compileExpr(ctx, e.right);
        ctx.emit(op);
        ctx.emit('STORE_LOCAL', tIdx);
        ctx.emit('LOAD_LOCAL', oIdx);
        ctx.emit('LOAD_LOCAL', kIdx);
        ctx.emit('LOAD_LOCAL', tIdx);
        ctx.emit('SET_ELEM');
        ctx.emit('LOAD_LOCAL', tIdx);
      } else if (t.isIdentifier(e.left.property)) {
        const nameIdx = ctx.internStr(e.left.property.name);
        const tIdx = ctx.declare('__ct');
        compileExpr(ctx, e.left.object);
        ctx.emit('DUP');
        ctx.emit('GET_PROP', nameIdx);
        compileExpr(ctx, e.right);
        ctx.emit(op);
        ctx.emit('STORE_LOCAL', tIdx);
        ctx.emit('LOAD_LOCAL', tIdx);
        ctx.emit('SET_PROP', nameIdx);
        ctx.emit('LOAD_LOCAL', tIdx);
      } else {
        bailT('non-identifier compound assignment target prop');
      }
      return;
    }
    bailT('compound assignment to unsupported target');
  }
  if (e.operator === '||=' || e.operator === '&&=' || e.operator === '??=') {
    compileLogicalAssign(ctx, e);
    return;
  }
  bailT(`unsupported assignment op: ${e.operator}`);
}
function compileLogicalAssign(ctx, e) {
  const isOr = e.operator === '||=';
  const isAnd = e.operator === '&&=';
  if (t.isIdentifier(e.left)) {
    const li = ctx.resolveLocal(e.left.name);
    const skip = ctx.newLabel();
    if (li >= 0) {
      ctx.emit('LOAD_LOCAL', li);
    } else {
      ctx.emit('LOAD_CAPTURE', ctx.internCap(e.left.name));
    }
    ctx.emit('DUP');
    if (isOr) {
      ctx.emit('JNZ', skip);
    } else if (isAnd) {
      ctx.emit('JZ', skip);
    } else {
      ctx.emit('PUSH_NULL');
      ctx.emit('EQ');
      ctx.emit('JZ', skip);
    }
    ctx.emit('POP');
    compileExpr(ctx, e.right);
    ctx.emit('DUP');
    if (li >= 0) {
      ctx.emit('STORE_LOCAL', li);
    } else {
      ctx.emit('STORE_CAPTURE', ctx.internCap(e.left.name));
    }
    ctx.emitLabel(skip);
    return;
  }
  if (t.isMemberExpression(e.left)) {
    if (e.left.computed) {
      const oIdx = ctx.declare('__lo');
      const kIdx = ctx.declare('__lk');
      const tIdx = ctx.declare('__lt');
      compileExpr(ctx, e.left.object);
      compileExpr(ctx, e.left.property);
      ctx.emit('STORE_LOCAL', kIdx);
      ctx.emit('STORE_LOCAL', oIdx);
      ctx.emit('LOAD_LOCAL', oIdx);
      ctx.emit('LOAD_LOCAL', kIdx);
      ctx.emit('GET_ELEM');
      const skip = ctx.newLabel();
      ctx.emit('DUP');
      if (isOr) ctx.emit('JNZ', skip);else if (isAnd) ctx.emit('JZ', skip);else {
        ctx.emit('PUSH_NULL');
        ctx.emit('EQ');
        ctx.emit('JZ', skip);
      }
      ctx.emit('POP');
      compileExpr(ctx, e.right);
      ctx.emit('STORE_LOCAL', tIdx);
      ctx.emit('LOAD_LOCAL', oIdx);
      ctx.emit('LOAD_LOCAL', kIdx);
      ctx.emit('LOAD_LOCAL', tIdx);
      ctx.emit('SET_ELEM');
      ctx.emit('LOAD_LOCAL', tIdx);
      ctx.emitLabel(skip);
      return;
    }
    if (t.isIdentifier(e.left.property)) {
      const nameIdx = ctx.internStr(e.left.property.name);
      const oIdx = ctx.declare('__lo');
      const tIdx = ctx.declare('__lt');
      compileExpr(ctx, e.left.object);
      ctx.emit('STORE_LOCAL', oIdx);
      ctx.emit('LOAD_LOCAL', oIdx);
      ctx.emit('GET_PROP', nameIdx);
      const skip = ctx.newLabel();
      ctx.emit('DUP');
      if (isOr) ctx.emit('JNZ', skip);else if (isAnd) ctx.emit('JZ', skip);else {
        ctx.emit('PUSH_NULL');
        ctx.emit('EQ');
        ctx.emit('JZ', skip);
      }
      ctx.emit('POP');
      compileExpr(ctx, e.right);
      ctx.emit('STORE_LOCAL', tIdx);
      ctx.emit('LOAD_LOCAL', oIdx);
      ctx.emit('LOAD_LOCAL', tIdx);
      ctx.emit('SET_PROP', nameIdx);
      ctx.emit('LOAD_LOCAL', tIdx);
      ctx.emitLabel(skip);
      return;
    }
    bailT('non-identifier logical assignment target prop');
  }
  bailT('logical assignment to unsupported target');
}
function encodeToBytes(instrs, table, key) {
  const ips = new Array(instrs.length + 1);
  let ip = 0;
  for (let i = 0; i < instrs.length; i++) {
    ips[i] = ip;
    const op = instrs[i].op;
    if (op === LABEL_OP) continue;
    const meta = OP_META[op];
    if (!meta) throw new Error(`encode: unknown logical op: ${op}`);
    const w = ARG_WIDTHS[meta.arg];
    if (w == null) throw new Error(`encode: unknown arg spec for ${op}: ${meta.arg}`);
    ip += 1 + w;
  }
  ips[instrs.length] = ip;
  const labelIPs = new Map();
  for (let i = 0; i < instrs.length; i++) {
    if (instrs[i].op === LABEL_OP) {
      labelIPs.set(instrs[i].args[0], ips[i]);
    }
  }
  const out = [];
  for (let i = 0; i < instrs.length; i++) {
    const instr = instrs[i];
    if (instr.op === LABEL_OP) continue;
    const byteVal = pickAlias(table, instr.op, ips[i], key);
    out.push(byteVal & 0xff);
    encodeArgs(out, instr.op, instr.args, labelIPs);
  }
  return Uint8Array.from(out);
}
function normalizeArgs(op, args) {
  if (!args || Array.isArray(args) || typeof args !== 'object') return args;
  switch (OP_META[op].arg) {
    case 'u8_i32':
      return [args.localIdx, args.intVal];
    case 'u8_u16':
      return [args.argc, args.nameIdx];
    case 'u16_u8':
      return [args.nameIdx, args.localIdx];
    case 'u8':
      return [args.localIdx];
    default:
      return Object.values(args);
  }
}
function encodeArgs(out, op, args, labelIPs) {
  const a = normalizeArgs(op, args);
  const argSpec = OP_META[op].arg;
  switch (argSpec) {
    case 'none':
      return;
    case 'u8':
      out.push(a[0] & 0xff);
      return;
    case 'u16':
      out.push(...u16(resolveArg(a[0], labelIPs)));
      return;
    case 'i32':
      out.push(...i32(a[0] | 0));
      return;
    case 'f64':
      out.push(...f64(a[0]));
      return;
    case 'u8_i32':
      out.push(a[0] & 0xff);
      out.push(...i32(a[1] | 0));
      return;
    case 'u8_u16':
      out.push(a[0] & 0xff);
      out.push(...u16(resolveArg(a[1], labelIPs)));
      return;
    case 'u16_u8':
      out.push(...u16(resolveArg(a[0], labelIPs)));
      out.push(a[1] & 0xff);
      return;
    default:
      throw new Error(`encodeArgs: unknown arg spec: ${argSpec}`);
  }
}
function resolveArg(v, labelIPs) {
  if (typeof v === 'string') {
    const ip = labelIPs.get(v);
    if (ip === undefined) throw new Error(`encode: unresolved label: ${v}`);
    return ip;
  }
  return v;
}
function u16(v) {
  return [v & 0xff, v >> 8 & 0xff];
}
function i32(v) {
  return [v & 0xff, v >> 8 & 0xff, v >> 16 & 0xff, v >>> 24 & 0xff];
}
function f64(v) {
  const buf = new Float64Array([v]);
  const view = new Uint8Array(buf.buffer);
  const out = new Array(8);
  for (let i = 0; i < 8; i++) out[i] = view[i];
  return out;
}