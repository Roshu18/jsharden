import { buildOpcodeTable, decodeByte, argWidthFor } from './opcode-table.js';
import { streamByte } from './cipher.js';
import { makeAntidebugHooks } from './antidebug.js';
const TIMING_PERIOD = 64;
export function createVM(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new TypeError('createVM: opts object required');
  }
  const {
    strings,
    captures = [],
    key,
    antidebug = true,
    integrityHash
  } = opts;
  if (!key) throw new TypeError('createVM: key is required');
  const S = strings || [];
  const C = captures;
  const table = buildOpcodeTable(key);
  const wantIntegrity = integrityHash != null;
  const wantTiming = antidebug !== false;
  let integrityCheckFn = null;
  let timingCheckFn = null;
  if (wantIntegrity || wantTiming) {
    const ad = makeAntidebugHooks(key);
    if (wantIntegrity) integrityCheckFn = ad.integrityCheck;
    if (wantTiming) timingCheckFn = ad.timingCheck;
  }
  const handlers = buildHandlers(S, C);
  function execute(bytecode, args = []) {
    const B = bytecode instanceof Uint8Array ? bytecode : new Uint8Array(bytecode);
    const len = B.length;
    const stk = [];
    const locals = new Array(32);
    for (let i = 0; i < args.length; i++) locals[i] = args[i];
    const tryStack = [];
    let corruptionMask = 0;
    let instrCount = 0;
    const __db = new Array(8).fill(0);
    if (integrityCheckFn) {
      if (!integrityCheckFn(B, integrityHash)) corruptionMask = 0xff;
    }
    const vm = {
      B,
      len,
      stk,
      locals,
      tryStack,
      sp: 0,
      ip: 0,
      retVal: undefined,
      argsArr: [],
      fetchByte() {
        if (vm.ip >= vm.len) return 0;
        const enc = vm.B[vm.ip];
        const dec = enc ^ streamByte(key, vm.ip) ^ corruptionMask;
        vm.ip++;
        return dec & 0xff;
      },
      fetchU16() {
        const lo = vm.fetchByte();
        const hi = vm.fetchByte();
        return lo | hi << 8;
      },
      fetchI32() {
        const b0 = vm.fetchByte();
        const b1 = vm.fetchByte();
        const b2 = vm.fetchByte();
        const b3 = vm.fetchByte();
        return b0 | b1 << 8 | b2 << 16 | b3 << 24;
      }
    };
    while (vm.ip < vm.len) {
      const opByte = vm.fetchByte();
      const logicalName = decodeByte(table, opByte);
      if (logicalName === null) {
        const w = argWidthFor(table, opByte);
        let decoyVal = opByte;
        for (let i = 0; i < w; i++) {
          const ab = vm.fetchByte();
          decoyVal = decoyVal * 31 + ab | 0;
        }
        __db[opByte & 7] = decoyVal;
        continue;
      }
      if (timingCheckFn && (++instrCount & TIMING_PERIOD - 1) === 0) {
        if (!timingCheckFn()) corruptionMask = 0xff;
      }
      try {
        const h = handlers[logicalName];
        if (!h) throw new Error('VM v2: no handler for ' + logicalName);
        h(vm);
      } catch (err) {
        if (corruptionMask) return vm.retVal;
        if (vm.tryStack.length > 0) {
          const catchAddr = vm.tryStack.pop();
          vm.sp = 0;
          vm.stk[vm.sp++] = err;
          vm.ip = catchAddr;
          continue;
        }
        throw err;
      }
    }
    return vm.retVal;
  }
  return {
    execute
  };
}
function buildHandlers(S, C) {
  const h = {};
  h.PUSH_NULL = vm => {
    vm.stk[vm.sp++] = null;
  };
  h.PUSH_UNDEF = vm => {
    vm.stk[vm.sp++] = undefined;
  };
  h.PUSH_TRUE = vm => {
    vm.stk[vm.sp++] = true;
  };
  h.PUSH_FALSE = vm => {
    vm.stk[vm.sp++] = false;
  };
  h.PUSH_INT = vm => {
    vm.stk[vm.sp++] = vm.fetchI32();
  };
  h.PUSH_FLOAT = vm => {
    const tmp = new Uint8Array(8);
    for (let i = 0; i < 8; i++) tmp[i] = vm.fetchByte();
    vm.stk[vm.sp++] = new Float64Array(tmp.buffer)[0];
  };
  h.PUSH_STR = vm => {
    vm.stk[vm.sp++] = S[vm.fetchU16()];
  };
  h.POP = vm => {
    vm.sp--;
  };
  h.DUP = vm => {
    vm.stk[vm.sp] = vm.stk[vm.sp - 1];
    vm.sp++;
  };
  h.SWAP = vm => {
    const t = vm.stk[vm.sp - 1];
    vm.stk[vm.sp - 1] = vm.stk[vm.sp - 2];
    vm.stk[vm.sp - 2] = t;
  };
  h.LOAD_LOCAL = vm => {
    vm.stk[vm.sp++] = vm.locals[vm.fetchByte()];
  };
  h.STORE_LOCAL = vm => {
    vm.locals[vm.fetchByte()] = vm.stk[--vm.sp];
  };
  h.LOAD_CAPTURE = vm => {
    vm.stk[vm.sp++] = C[vm.fetchByte()];
  };
  h.STORE_CAPTURE = vm => {
    C[vm.fetchByte()] = vm.stk[--vm.sp];
  };
  h.GET_PROP = vm => {
    const idx = vm.fetchU16();
    const obj = vm.stk[--vm.sp];
    if (obj == null) throw new TypeError('Cannot read properties of ' + obj + ' (reading ' + S[idx] + ')');
    vm.stk[vm.sp++] = obj[S[idx]];
  };
  h.SET_PROP = vm => {
    const idx = vm.fetchU16();
    const val = vm.stk[--vm.sp];
    const obj = vm.stk[--vm.sp];
    if (obj != null) obj[S[idx]] = val;
  };
  h.GET_ELEM = vm => {
    const key = vm.stk[--vm.sp];
    const obj = vm.stk[--vm.sp];
    if (obj == null) throw new TypeError('Cannot read properties of ' + obj + ' (reading ' + key + ')');
    vm.stk[vm.sp++] = obj[key];
  };
  h.SET_ELEM = vm => {
    const seVal = vm.stk[--vm.sp];
    const seKey = vm.stk[--vm.sp];
    const seObj = vm.stk[--vm.sp];
    if (seObj != null) seObj[seKey] = seVal;
  };
  const bin = f => vm => {
    const b = vm.stk[--vm.sp];
    const a = vm.stk[--vm.sp];
    vm.stk[vm.sp++] = f(a, b);
  };
  h.ADD = bin((a, b) => a + b);
  h.SUB = bin((a, b) => a - b);
  h.MUL = bin((a, b) => a * b);
  h.DIV = bin((a, b) => a / b);
  h.MOD = bin((a, b) => a % b);
  h.BIT_AND = bin((a, b) => a & b);
  h.BIT_OR = bin((a, b) => a | b);
  h.BIT_XOR = bin((a, b) => a ^ b);
  h.SHL = bin((a, b) => a << b);
  h.SHR = bin((a, b) => a >> b);
  h.USHR = bin((a, b) => a >>> b);
  h.EQ = bin((a, b) => a == b);
  h.NEQ = bin((a, b) => a != b);
  h.SEQ = bin((a, b) => a === b);
  h.SNEQ = bin((a, b) => a !== b);
  h.LT = bin((a, b) => a < b);
  h.LTE = bin((a, b) => a <= b);
  h.GT = bin((a, b) => a > b);
  h.GTE = bin((a, b) => a >= b);
  h.INSTANCEOF = bin((a, b) => a instanceof b);
  h.IN = bin((a, b) => a in b);
  const un = f => vm => {
    vm.stk[vm.sp - 1] = f(vm.stk[vm.sp - 1]);
  };
  h.NEG = un(a => -a);
  h.POS = un(a => +a);
  h.NOT = un(a => !a);
  h.BIT_NOT = un(a => ~a);
  h.TYPEOF = un(a => typeof a);
  h.VOID = un(() => undefined);
  h.DELETE_PROP = vm => {
    const idx = vm.fetchU16();
    const obj = vm.stk[--vm.sp];
    let r = true;
    try {
      if (obj != null) r = delete obj[S[idx]];
    } catch (_) {}
    vm.stk[vm.sp++] = r;
  };
  h.DELETE_ELEM = vm => {
    const key = vm.stk[--vm.sp];
    const obj = vm.stk[--vm.sp];
    let r = true;
    try {
      if (obj != null) r = delete obj[key];
    } catch (_) {}
    vm.stk[vm.sp++] = r;
  };
  h.JMP = vm => {
    vm.ip = vm.fetchU16();
  };
  h.JZ = vm => {
    const a = vm.fetchU16();
    if (!vm.stk[--vm.sp]) vm.ip = a;
  };
  h.JNZ = vm => {
    const a = vm.fetchU16();
    if (vm.stk[--vm.sp]) vm.ip = a;
  };
  h.CALL = vm => {
    const argc = vm.fetchByte();
    const base = vm.sp - argc - 1;
    const fn = vm.stk[base];
    const argsArr = vm.argsArr;
    argsArr.length = argc;
    for (let i = 0; i < argc; i++) argsArr[i] = vm.stk[base + 1 + i];
    vm.sp = base;
    vm.stk[vm.sp++] = fn.apply(undefined, argsArr);
  };
  h.CALL_METHOD = vm => {
    const argc = vm.fetchByte();
    const idx = vm.fetchU16();
    const base = vm.sp - argc - 1;
    const obj = vm.stk[base];
    const argsArr = vm.argsArr;
    argsArr.length = argc;
    for (let i = 0; i < argc; i++) argsArr[i] = vm.stk[base + 1 + i];
    vm.sp = base;
    if (obj == null) throw new TypeError('Cannot read properties of ' + obj + ' (reading ' + S[idx] + ')');
    vm.stk[vm.sp++] = obj[S[idx]].apply(obj, argsArr);
  };
  h.NEW = vm => {
    const argc = vm.fetchByte();
    const base = vm.sp - argc - 1;
    const fn = vm.stk[base];
    const argsArr = vm.argsArr;
    argsArr.length = argc;
    for (let i = 0; i < argc; i++) argsArr[i] = vm.stk[base + 1 + i];
    vm.sp = base;
    vm.stk[vm.sp++] = Reflect.construct(fn, argsArr);
  };
  h.RET = vm => {
    vm.retVal = vm.stk[--vm.sp];
    vm.ip = vm.len;
  };
  h.RET_UNDEF = vm => {
    vm.retVal = undefined;
    vm.ip = vm.len;
  };
  h.GET_ITER = vm => {
    const v = vm.stk[--vm.sp];
    if (v == null) {
      vm.stk[vm.sp++] = {
        next: function () {
          return {
            done: true
          };
        }
      };
      return;
    }
    if (Array.isArray(v)) {
      vm.stk[vm.sp++] = v[Symbol.iterator]();
      return;
    }
    if (typeof v[Symbol.iterator] === 'function') {
      vm.stk[vm.sp++] = v[Symbol.iterator]();
      return;
    }
    vm.stk[vm.sp++] = Object.keys(v)[Symbol.iterator]();
  };
  h.ITER_NEXT = vm => {
    const it = vm.stk[--vm.sp];
    vm.stk[vm.sp++] = it.next();
  };
  h.TRY_ENTER = vm => {
    vm.tryStack.push(vm.fetchU16());
  };
  h.TRY_EXIT = vm => {
    vm.tryStack.pop();
  };
  h.THROW = vm => {
    throw vm.stk[--vm.sp];
  };
  h.FUSED_LI_ADD = vm => {
    const localIdx = vm.fetchByte();
    const intVal = vm.fetchI32();
    vm.stk[vm.sp++] = vm.locals[localIdx] + intVal;
  };
  h.FUSED_LI_PUSH = vm => {
    const localIdx = vm.fetchByte();
    const intVal = vm.fetchI32();
    vm.stk[vm.sp++] = vm.locals[localIdx];
    vm.stk[vm.sp++] = intVal;
  };
  h.FUSED_SI_PUSH = vm => {
    const localIdx = vm.fetchByte();
    const intVal = vm.fetchI32();
    vm.locals[localIdx] = intVal;
    vm.stk[vm.sp++] = intVal;
  };
  h.FUSED_GETP_LI = vm => {
    const nameIdx = vm.fetchU16();
    const localIdx = vm.fetchByte();
    const obj = vm.locals[localIdx];
    if (obj == null) throw new TypeError('Cannot read properties of ' + obj + ' (reading ' + S[nameIdx] + ')');
    vm.stk[vm.sp++] = obj[S[nameIdx]];
  };
  h.FUSED_LI_LT = vm => {
    const localIdx = vm.fetchByte();
    const intVal = vm.fetchI32();
    vm.stk[vm.sp++] = vm.locals[localIdx] < intVal;
  };
  h.FUSED_INC_STORE = vm => {
    const localIdx = vm.fetchByte();
    vm.locals[localIdx] = vm.locals[localIdx] + 1;
  };
  return h;
}