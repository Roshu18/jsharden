export const ARG_WIDTHS = {
  none: 0,
  u8: 1,
  u16: 2,
  i32: 4,
  f64: 8,
  u8_i32: 5,
  u8_u16: 3,
  u16_u8: 3
};
export const BASE_OPCODES = {
  PUSH_NULL: {
    id: 'PUSH_NULL',
    arg: 'none'
  },
  PUSH_UNDEF: {
    id: 'PUSH_UNDEF',
    arg: 'none'
  },
  PUSH_TRUE: {
    id: 'PUSH_TRUE',
    arg: 'none'
  },
  PUSH_FALSE: {
    id: 'PUSH_FALSE',
    arg: 'none'
  },
  PUSH_INT: {
    id: 'PUSH_INT',
    arg: 'i32'
  },
  PUSH_FLOAT: {
    id: 'PUSH_FLOAT',
    arg: 'f64'
  },
  PUSH_STR: {
    id: 'PUSH_STR',
    arg: 'u16'
  },
  POP: {
    id: 'POP',
    arg: 'none'
  },
  DUP: {
    id: 'DUP',
    arg: 'none'
  },
  SWAP: {
    id: 'SWAP',
    arg: 'none'
  },
  LOAD_LOCAL: {
    id: 'LOAD_LOCAL',
    arg: 'u8'
  },
  STORE_LOCAL: {
    id: 'STORE_LOCAL',
    arg: 'u8'
  },
  LOAD_CAPTURE: {
    id: 'LOAD_CAPTURE',
    arg: 'u8'
  },
  STORE_CAPTURE: {
    id: 'STORE_CAPTURE',
    arg: 'u8'
  },
  GET_PROP: {
    id: 'GET_PROP',
    arg: 'u16'
  },
  SET_PROP: {
    id: 'SET_PROP',
    arg: 'u16'
  },
  GET_ELEM: {
    id: 'GET_ELEM',
    arg: 'none'
  },
  SET_ELEM: {
    id: 'SET_ELEM',
    arg: 'none'
  },
  ADD: {
    id: 'ADD',
    arg: 'none'
  },
  SUB: {
    id: 'SUB',
    arg: 'none'
  },
  MUL: {
    id: 'MUL',
    arg: 'none'
  },
  DIV: {
    id: 'DIV',
    arg: 'none'
  },
  MOD: {
    id: 'MOD',
    arg: 'none'
  },
  NEG: {
    id: 'NEG',
    arg: 'none'
  },
  POS: {
    id: 'POS',
    arg: 'none'
  },
  NOT: {
    id: 'NOT',
    arg: 'none'
  },
  BIT_NOT: {
    id: 'BIT_NOT',
    arg: 'none'
  },
  BIT_AND: {
    id: 'BIT_AND',
    arg: 'none'
  },
  BIT_OR: {
    id: 'BIT_OR',
    arg: 'none'
  },
  BIT_XOR: {
    id: 'BIT_XOR',
    arg: 'none'
  },
  SHL: {
    id: 'SHL',
    arg: 'none'
  },
  SHR: {
    id: 'SHR',
    arg: 'none'
  },
  USHR: {
    id: 'USHR',
    arg: 'none'
  },
  EQ: {
    id: 'EQ',
    arg: 'none'
  },
  NEQ: {
    id: 'NEQ',
    arg: 'none'
  },
  SEQ: {
    id: 'SEQ',
    arg: 'none'
  },
  SNEQ: {
    id: 'SNEQ',
    arg: 'none'
  },
  LT: {
    id: 'LT',
    arg: 'none'
  },
  LTE: {
    id: 'LTE',
    arg: 'none'
  },
  GT: {
    id: 'GT',
    arg: 'none'
  },
  GTE: {
    id: 'GTE',
    arg: 'none'
  },
  INSTANCEOF: {
    id: 'INSTANCEOF',
    arg: 'none'
  },
  IN: {
    id: 'IN',
    arg: 'none'
  },
  TYPEOF: {
    id: 'TYPEOF',
    arg: 'none'
  },
  VOID: {
    id: 'VOID',
    arg: 'none'
  },
  DELETE_PROP: {
    id: 'DELETE_PROP',
    arg: 'u16'
  },
  DELETE_ELEM: {
    id: 'DELETE_ELEM',
    arg: 'none'
  },
  JMP: {
    id: 'JMP',
    arg: 'u16'
  },
  JZ: {
    id: 'JZ',
    arg: 'u16'
  },
  JNZ: {
    id: 'JNZ',
    arg: 'u16'
  },
  CALL: {
    id: 'CALL',
    arg: 'u8'
  },
  CALL_METHOD: {
    id: 'CALL_METHOD',
    arg: 'u8_u16'
  },
  NEW: {
    id: 'NEW',
    arg: 'u8'
  },
  RET: {
    id: 'RET',
    arg: 'none'
  },
  RET_UNDEF: {
    id: 'RET_UNDEF',
    arg: 'none'
  },
  GET_ITER: {
    id: 'GET_ITER',
    arg: 'none'
  },
  ITER_NEXT: {
    id: 'ITER_NEXT',
    arg: 'none'
  },
  TRY_ENTER: {
    id: 'TRY_ENTER',
    arg: 'u16'
  },
  TRY_EXIT: {
    id: 'TRY_EXIT',
    arg: 'none'
  },
  THROW: {
    id: 'THROW',
    arg: 'none'
  },
  FUSED_LI_ADD: {
    id: 'FUSED_LI_ADD',
    arg: 'u8_i32',
    fused: ['LOAD_LOCAL', 'PUSH_INT', 'ADD']
  },
  FUSED_LI_PUSH: {
    id: 'FUSED_LI_PUSH',
    arg: 'u8_i32',
    fused: ['LOAD_LOCAL', 'PUSH_INT']
  },
  FUSED_SI_PUSH: {
    id: 'FUSED_SI_PUSH',
    arg: 'u8_i32',
    fused: ['STORE_LOCAL', 'PUSH_INT']
  },
  FUSED_GETP_LI: {
    id: 'FUSED_GETP_LI',
    arg: 'u16_u8',
    fused: ['GET_PROP', 'LOAD_LOCAL']
  },
  FUSED_LI_LT: {
    id: 'FUSED_LI_LT',
    arg: 'u8_i32',
    fused: ['LOAD_LOCAL', 'PUSH_INT', 'LT']
  },
  FUSED_INC_STORE: {
    id: 'FUSED_INC_STORE',
    arg: 'u8',
    fused: ['LOAD_LOCAL', 'PUSH_INT', 'ADD', 'STORE_LOCAL']
  }
};
export const OP_META = BASE_OPCODES;
export const SIMPLE_OPS = Object.keys(BASE_OPCODES).filter(n => !BASE_OPCODES[n].fused);
export const FUSED_OPS = Object.keys(BASE_OPCODES).filter(n => BASE_OPCODES[n].fused);