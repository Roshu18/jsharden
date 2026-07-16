export const PROFILES = {
  light: {
    label: 'light',
    blurb: 'Identifier renaming + basic string hiding. Fast, minimal breakage.',
    tradeoff: 'Size +5–15%. Runtime overhead <5%. Indistinguishable from a normal minified bundle to a casual reader; defeats naive string-grep and "search the source" attacks.',
    options: {
      compact: true,
      renameGlobals: false,
      identifierNamesGenerator: 'hexadecimal',
      stringArray: true,
      stringArrayEncoding: ['base64'],
      stringArrayThreshold: 0.85,
      stringArrayWrappersCount: 1,
      stringArrayWrappersChainedCalls: false,
      stringArrayWrappersType: 'function',
      controlFlowFlattening: false,
      deadCodeInjection: false,
      debugProtection: false,
      disableConsoleOutput: false,
      selfDefending: false,
      numbersToExpressions: false,
      splitStrings: false,
      seed: 0,
      sourceMap: false,
      ignoreImports: true,
      reservedNames: [],
      reservedStrings: [],
      target: 'browser'
    }
  },
  balanced: {
    label: 'balanced',
    blurb: 'Light + control-flow flattening + dead-code injection + self-defending.',
    tradeoff: 'Size +30–60%. Runtime overhead 5–20%. Defeats webcrack-style one-shot deobfuscators; an attacker has to manually trace flattened control flow and discard dead branches.',
    options: {
      compact: true,
      renameGlobals: false,
      identifierNamesGenerator: 'hexadecimal',
      stringArray: true,
      stringArrayEncoding: ['base64'],
      stringArrayThreshold: 0.85,
      stringArrayWrappersCount: 2,
      stringArrayWrappersChainedCalls: true,
      stringArrayWrappersType: 'function',
      controlFlowFlattening: true,
      controlFlowFlatteningThreshold: 0.5,
      deadCodeInjection: true,
      deadCodeInjectionThreshold: 0.25,
      debugProtection: false,
      disableConsoleOutput: false,
      selfDefending: true,
      numbersToExpressions: true,
      splitStrings: true,
      splitStringsChunkLength: 8,
      seed: 0,
      sourceMap: false,
      ignoreImports: true,
      reservedNames: [],
      reservedStrings: [],
      target: 'browser',
      stringArrayRotate: true,
      stringArrayShuffle: true,
      deadCodeInjectionExclude: []
    }
  },
  max: {
    label: 'max',
    blurb: 'Balanced + RC4 string encoding + aggressive CFF + chained wrappers.',
    tradeoff: 'Size +80–200%. Runtime overhead 20–80% (still usable). An attacker who wants to recover readable source needs to defeat RC4 + chained wrappers + heavy CFF + dead code in combination — realistically 1–2 weeks of focused work, not a 30-second pass with webcrack.',
    options: {
      compact: true,
      renameGlobals: false,
      identifierNamesGenerator: 'mangled',
      stringArray: true,
      stringArrayEncoding: ['rc4'],
      stringArrayThreshold: 0.9,
      stringArrayWrappersCount: 4,
      stringArrayWrappersChainedCalls: true,
      stringArrayWrappersType: 'function',
      controlFlowFlattening: true,
      controlFlowFlatteningThreshold: 0.85,
      deadCodeInjection: true,
      deadCodeInjectionThreshold: 0.5,
      debugProtection: false,
      disableConsoleOutput: false,
      selfDefending: true,
      numbersToExpressions: true,
      splitStrings: true,
      splitStringsChunkLength: 6,
      seed: 0,
      sourceMap: false,
      ignoreImports: true,
      reservedNames: [],
      reservedStrings: [],
      target: 'browser',
      stringArrayRotate: true,
      stringArrayShuffle: true,
      wrapIIFE: true
    }
  }
};
export function applyFlagOverrides(base, flags) {
  const out = {
    ...base
  };
  if (flags.antiDebug) {
    out.debugProtection = true;
    out.debugProtectionInterval = 2000;
  }
  if (flags.consoleOff) {
    out.disableConsoleOutput = true;
  }
  if (typeof flags.seed === 'number') {
    out.seed = flags.seed;
  }
  return out;
}
export function describeProfile(name) {
  const p = PROFILES[name];
  if (!p) return null;
  return `${p.label.toUpperCase()}\n  ${p.blurb}\n  Trade-off: ${p.tradeoff}`;
}