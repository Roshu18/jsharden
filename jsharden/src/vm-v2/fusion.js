const LABEL_OP = '__LABEL';
const STMT_OP = '__STMT';
function isBoundary(instr) {
  return !!(instr && (instr.op === LABEL_OP || instr.op === STMT_OP));
}
export const FUSION_PATTERNS = [{
  fusedOp: 'FUSED_LI_ADD',
  match: [{
    op: 'LOAD_LOCAL'
  }, {
    op: 'PUSH_INT'
  }, {
    op: 'ADD'
  }],
  combine: m => ({
    localIdx: m[0].args[0],
    intVal: m[1].args[0]
  })
}, {
  fusedOp: 'FUSED_LI_LT',
  match: [{
    op: 'LOAD_LOCAL'
  }, {
    op: 'PUSH_INT'
  }, {
    op: 'LT'
  }],
  combine: m => ({
    localIdx: m[0].args[0],
    intVal: m[1].args[0]
  })
}, {
  fusedOp: 'FUSED_LI_PUSH',
  match: [{
    op: 'LOAD_LOCAL'
  }, {
    op: 'PUSH_INT'
  }],
  combine: m => ({
    localIdx: m[0].args[0],
    intVal: m[1].args[0]
  })
}];
FUSION_PATTERNS.sort((a, b) => b.match.length - a.match.length);
export function tryFuse(instrs, i) {
  if (!Array.isArray(instrs)) return null;
  if (i < 0 || i >= instrs.length) return null;
  for (const p of FUSION_PATTERNS) {
    if (i + p.match.length > instrs.length) continue;
    let ok = true;
    const matched = [];
    for (let k = 0; k < p.match.length; k++) {
      const ins = instrs[i + k];
      if (!ins || isBoundary(ins) || ins.op !== p.match[k].op) {
        ok = false;
        break;
      }
      matched.push(ins);
    }
    if (!ok) continue;
    return {
      fused: {
        op: p.fusedOp,
        args: p.combine(matched)
      },
      consumed: p.match.length
    };
  }
  return null;
}
export function expandFused(fused) {
  if (!fused || typeof fused.op !== 'string') {
    throw new Error('expandFused: invalid fused instruction');
  }
  const a = fused.args || {};
  switch (fused.op) {
    case 'FUSED_LI_ADD':
      return [{
        op: 'LOAD_LOCAL',
        args: [a.localIdx]
      }, {
        op: 'PUSH_INT',
        args: [a.intVal]
      }, {
        op: 'ADD',
        args: []
      }];
    case 'FUSED_LI_PUSH':
      return [{
        op: 'LOAD_LOCAL',
        args: [a.localIdx]
      }, {
        op: 'PUSH_INT',
        args: [a.intVal]
      }];
    case 'FUSED_LI_LT':
      return [{
        op: 'LOAD_LOCAL',
        args: [a.localIdx]
      }, {
        op: 'PUSH_INT',
        args: [a.intVal]
      }, {
        op: 'LT',
        args: []
      }];
    default:
      throw new Error(`expandFused: unknown fused op: ${fused.op}`);
  }
}
export function applyFusion(instrs) {
  if (!Array.isArray(instrs)) return instrs;
  const out = [];
  let i = 0;
  while (i < instrs.length) {
    const cur = instrs[i];
    if (isBoundary(cur)) {
      out.push(cur);
      i++;
      continue;
    }
    const r = tryFuse(instrs, i);
    if (r) {
      out.push(r.fused);
      i += r.consumed;
    } else {
      out.push(cur);
      i++;
    }
  }
  return out;
}