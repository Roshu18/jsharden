const VALUE_FLAGS = new Set(['--profile', '-p', '--out-file', '-o', '--out-dir', '-d', '--seed', '--config']);
export function parseArgs(argv) {
  const out = {
    inputs: [],
    profile: null,
    outFile: null,
    outDir: null,
    watch: false,
    antiDebug: false,
    consoleOff: false,
    seed: null,
    noTerser: false,
    gate: true,
    verify: false,
    config: null,
    help: false,
    version: false,
    obfuscatorOverrides: {}
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const [key, eqVal] = arg.split('=');
    const next = argv[i + 1];
    if (arg === '--help' || arg === '-h') {
      out.help = true;
      continue;
    }
    if (arg === '--version' || arg === '-v') {
      out.version = true;
      continue;
    }
    if (arg === '--no-watch') {
      out.watch = false;
      continue;
    }
    if (arg === '--no-anti-debug') {
      out.antiDebug = false;
      continue;
    }
    if (arg === '--no-console-off') {
      out.consoleOff = false;
      continue;
    }
    if (arg === '--no-gate') {
      out.gate = false;
      continue;
    }
    if (arg === '--no-verify') {
      out.verify = false;
      continue;
    }
    if (arg === '--watch' || arg === '-w') {
      out.watch = true;
      continue;
    }
    if (arg === '--anti-debug') {
      out.antiDebug = true;
      continue;
    }
    if (arg === '--console-off') {
      out.consoleOff = true;
      continue;
    }
    if (arg === '--no-terser') {
      out.noTerser = true;
      continue;
    }
    if (arg === '--gate') {
      out.gate = true;
      continue;
    }
    if (arg === '--verify') {
      out.verify = true;
      continue;
    }
    if (VALUE_FLAGS.has(key)) {
      const val = eqVal !== undefined ? eqVal : next;
      if (val === undefined || val.startsWith('--') && val.length > 2) {
        throw new Error(`Flag ${key} requires a value`);
      }
      if (eqVal === undefined) i++;
      switch (key) {
        case '--profile':
        case '-p':
          {
            if (!['light', 'balanced', 'max', 'armor'].includes(val)) {
              throw new Error(`Invalid --profile: ${val}. Choose from: light, balanced, max, armor`);
            }
            out.profile = val;
            break;
          }
        case '--out-file':
        case '-o':
          out.outFile = val;
          break;
        case '--out-dir':
        case '-d':
          out.outDir = val;
          break;
        case '--seed':
          {
            const n = Number(val);
            if (!Number.isInteger(n)) throw new Error(`--seed must be an integer, got: ${val}`);
            out.seed = n;
            break;
          }
        case '--config':
          out.config = val;
          break;
      }
      continue;
    }
    if (arg.startsWith('--') && arg.length > 2) {
      if (arg.startsWith('--obfuscator.')) {
        const rest = arg.slice('--obfuscator.'.length);
        const [k, v] = rest.split('=');
        if (v === undefined) throw new Error(`Override ${arg} must be in --obfuscator.KEY=VALUE form`);
        out.obfuscatorOverrides[k] = parseOverrideValue(v);
        continue;
      }
      throw new Error(`Unknown flag: ${arg}`);
    }
    if (arg.startsWith('-') && arg.length > 1 && !arg.startsWith('--')) {
      throw new Error(`Unknown flag: ${arg}`);
    }
    out.inputs.push(arg);
  }
  return out;
}
function parseOverrideValue(v) {
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^-?\d+$/.test(v)) return Number(v);
  if (v.startsWith('[') || v.startsWith('{')) {
    try {
      return JSON.parse(v);
    } catch {}
  }
  return v;
}