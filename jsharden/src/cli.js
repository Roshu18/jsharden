#!/usr/bin/env node
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve, relative } from 'node:path';
import { watch } from 'node:fs';
import { parseArgs } from './args.js';
import { resolveConfig } from './config.js';
import { PROFILES, applyFlagOverrides } from './profiles.js';
import { discoverFiles, computeOutputPath } from './discover.js';
import { harden, smokeTest } from './harden.js';
import { hardenArmor } from './armor.js';
const BANNER = `
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ░░░░░░  ░░░░░░░  ░░░    ░░░  ░░░░░░    ░░░░░░░  ░░░    ░░░     ║
║   ░     ░  ░     ░  ░░ ░░  ░░  ░     ░  ░     ░  ░░ ░░  ░░      ║
║   ░░░░░░   ░░░░░░   ░░  ░░ ░░  ░░░░░░   ░░░░░░   ░░  ░░ ░░      ║
║   ░   ░    ░     ░  ░   ░░ ░░  ░   ░    ░     ░  ░   ░░ ░░      ║
║   ░    ░░  ░░░░░░░  ░    ░░░░  ░    ░░  ░░░░░░░  ░    ░░░░      ║
║                                                                  ║
║            J S   H A R D E N   —   v2.0.0                        ║
║                                                                  ║
║   "Anything that runs can be reverse-engineered. We raise the    ║
║    cost." — Deterrence, not security.                            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`;
const HELP = `${BANNER}
jsharden — harden JavaScript against reverse engineering.

USAGE
  jsharden <input.js> [options]
  jsharden <input1.js> <input2.js> ... [options]
  jsharden ./src --out-dir ./dist        # folder, recursive
  jsharden 'src*.js' --out-dir ./dist  # glob

PROFILES (default: balanced)
  --profile light       Renaming + basic string hiding. Fast, minimal breakage.
                        Size +5-15%, runtime overhead <5%.
  --profile balanced    + control-flow flattening, dead-code injection,
                        self-defending. Size +30-60%, overhead 5-20%.
  --profile max         + RC4 string encoding, aggressive CFF, chained
                        wrappers. Size +80-200%, overhead 20-80%.
                        Defeats webcrack-class one-shot deobfuscators; pushes
                        a focused reverse-engineer into 1-2 weeks of work.
  --profile armor       THE FULL ARSENAL. max + custom VM bytecode for
                        leaf functions + WASM-encrypted string pool +
                        self-guard (integrity hash) + self-healing
                        (XOR-encoded recovery blob). Bytes shrink because
                        VM-compiled functions lose their original source.
                        Defeat requires browser DevTools runtime inspection;
                        Node CLI tools (webcrack, etc.) cannot recover the
                        VM-compiled portions. Strongest practical protection.

OPTIONS
  -o, --out-file <f>    Output path (single input only). NEVER overwrites input.
  -d, --out-dir <dir>   Output directory (batch mode).
  -w, --watch           Re-harden on change (debounced 250ms).
      --anti-debug      Enable debugProtection (OFF by default — would freeze
                        a console-pasted script).
      --console-off     Strip console output (OFF by default).
      --seed <n>        Deterministic seed for the obfuscation maze.
      --no-terser       Skip the Terser compression pass (debugging only).
      --no-gate         Skip the Browser-Gate wrapping (armor profile only).
                        The gate encrypts the armor body with a key derived
                        from browser-only API probes; in Node (no browser
                        APIs) the body stays encrypted and the script won't
                        run. Default: gate ON.
      --verify          Smoke-test the output in a sandbox after writing.
      --config <path>   Explicit .jshardenrc.json path (default: walk up).
      --obfuscator.K=V  Raw override passthrough (e.g. --obfuscator.target=node).
  -h, --help            Show this help.
  -v, --version         Show version.

PRECEDENCE
  profile defaults  <  .jshardenrc.json  <  CLI flags

EXAMPLES
  jsharden app.js -o dist/app.hardened.js --profile max
  jsharden fallen.user.js --profile armor --verify
  jsharden ./src --out-dir ./dist --profile balanced --anti-debug
  jsharden 'lib*.js' --out-dir ./dist --watch

HONESTY
  Client-side obfuscation is DETERRENCE, not security. Anything that runs
  in a browser can be reverse-engineered by a determined attacker. Keep
  real secrets on a server behind an authenticated API.
`;
const argv = process.argv.slice(2);
const args = parseArgs(argv);
if (args.help) {
  process.stdout.write(HELP);
  process.exit(0);
}
if (args.version) {
  const pkgUrl = new URL('../package.json', import.meta.url);
  const pkg = JSON.parse(await readFile(pkgUrl, 'utf8'));
  process.stdout.write(`jsharden ${pkg.version}\n`);
  process.exit(0);
}
if (args.inputs.length === 0) {
  process.stderr.write(BANNER + '\n');
  process.stderr.write('Error: no input given. Run `jsharden --help`.\n');
  process.exit(2);
}
if (args.outFile && args.inputs.length > 1) {
  process.stderr.write('Error: --out-file can only be used with a single input.\n');
  process.exit(2);
}
if (args.outFile && args.outDir) {
  process.stderr.write('Error: --out-file and --out-dir are mutually exclusive.\n');
  process.exit(2);
}
const cwd = process.cwd();
let resolved, configPath, profileName;
try {
  ({
    resolved,
    configPath,
    profileName
  } = await resolveConfig(args, cwd));
} catch (err) {
  fail(err.message);
}
if (process.stdout.isTTY || args.inputs.length > 0) {
  process.stdout.write(BANNER);
  process.stdout.write(`  profile : ${profileName}\n`);
  process.stdout.write(`  inputs  : ${args.inputs.join(' ')}\n`);
  if (configPath) process.stdout.write(`  config  : ${relative(cwd, configPath)}\n`);
  process.stdout.write(`  flags   : ${[resolved.antiDebug && '--anti-debug', resolved.consoleOff && '--console-off', args.gate === false && '--no-gate', args.verify && '--verify', args.watch && '--watch'].filter(Boolean).join(' ') || '(none)'}\n\n`);
}
let files;
try {
  files = await discoverFiles(args.inputs, cwd);
} catch (err) {
  fail(`File discovery failed: ${err.message}`);
}
if (files.length === 0) {
  fail(`No JavaScript files matched input: ${args.inputs.join(' ')}`);
}
if (args.outDir) {
  await mkdir(resolve(cwd, args.outDir), {
    recursive: true
  });
}
await runOnce({
  files,
  resolved,
  profileName,
  configPath,
  noTerser: args.noTerser,
  gate: args.gate,
  verify: args.verify,
  seed: resolved.seed
});
if (!args.watch) {
  process.exit(0);
}
console.log(`\n[watch] watching ${files.length} file(s) for changes (Ctrl-C to exit)...`);
const debounceTimers = new Map();
for (const f of files) {
  watch(f, () => {
    if (debounceTimers.has(f)) clearTimeout(debounceTimers.get(f));
    debounceTimers.set(f, setTimeout(() => {
      debounceTimers.delete(f);
      console.log(`[watch] ${relative(cwd, f)} changed — re-hardening...`);
      runOnce({
        files: [f],
        resolved,
        profileName,
        configPath,
        noTerser: args.noTerser,
        gate: args.gate,
        verify: args.verify,
        seed: resolved.seed,
        quiet: true
      }).catch(err => console.error(`[watch] error: ${err.message}`));
    }, 250));
  });
}
async function runOnce({
  files,
  resolved,
  profileName,
  noTerser,
  gate,
  verify,
  seed,
  quiet
}) {
  const profile = PROFILES[profileName];
  if (!quiet) {
    if (profile) {
      console.log(`  trade-off: ${profile.tradeoff}\n`);
    } else if (profileName === 'armor') {
      console.log(`  trade-off: VM bytecode + WASM + self-guard + self-heal. Bytes shrink.\n`);
    }
  }
  let totalBefore = 0;
  let totalAfter = 0;
  let failed = 0;
  for (const file of files) {
    const outPath = computeOutputPath(file, resolved.outFile, resolved.outDir);
    if (resolve(outPath) === resolve(file)) {
      console.error(`  ✗ ${relative(cwd, file)} → refusing to overwrite input`);
      failed++;
      continue;
    }
    try {
      const source = await readFile(file, 'utf8');
      const t0 = Date.now();
      let code, stats, report;
      if (profileName === 'armor') {
        const armorResult = await hardenArmor({
          source,
          seed,
          antiDebug: resolved.antiDebug,
          consoleOff: resolved.consoleOff,
          gate
        });
        code = armorResult.code;
        stats = {
          before: armorResult.stats.bytesBefore,
          afterTerser: armorResult.stats.bytesAfterGate
        };
        report = armorResult.report;
      } else {
        const obfuscatorOptions = applyFlagOverrides(profile.options, {
          antiDebug: resolved.antiDebug,
          consoleOff: resolved.consoleOff,
          seed
        });
        const finalOpts = {
          ...obfuscatorOptions,
          ...resolved.obfuscatorOverrides
        };
        const result = await harden({
          source,
          obfuscatorOptions: finalOpts,
          skipTerser: noTerser
        });
        code = result.code;
        stats = result.stats;
      }
      if (verify) {
        const result = await smokeTest(code);
        if (!result.ok) {
          console.error(`  ✗ ${relative(cwd, file)} → smoke test failed: ${result.error}`);
          failed++;
          continue;
        }
      }
      await mkdir(dirname(outPath), {
        recursive: true
      });
      await writeFile(outPath, code, 'utf8');
      const ratio = ((1 - stats.afterTerser / stats.before) * 100).toFixed(1);
      const sign = stats.afterTerser < stats.before ? '-' : '+';
      totalBefore += stats.before;
      totalAfter += stats.afterTerser;
      const timeStr = `${Date.now() - t0}ms`;
      console.log(`  ✓ ${relative(cwd, file)} → ${relative(cwd, outPath)}  ` + `${formatBytes(stats.before)} → ${formatBytes(stats.afterTerser)}  ` + `(${sign}${Math.abs(ratio)}%)  ${timeStr}`);
      if (report && (report.vmCompiled > 0 || report.vmBailed > 0)) {
        console.log(`    VM: ${report.vmCompiled}/${report.topLevelFunctions} functions compiled to bytecode, ${report.vmBailed} bailed`);
      }
    } catch (err) {
      console.error(`  ✗ ${relative(cwd, file)} → ${err.message}`);
      console.error(err.stack);
      failed++;
    }
  }
  if (!quiet && files.length > 1) {
    const r = ((1 - totalAfter / totalBefore) * 100).toFixed(1);
    const sign = totalAfter < totalBefore ? '-' : '+';
    console.log(`\n  total: ${formatBytes(totalBefore)} → ${formatBytes(totalAfter)} (${sign}${Math.abs(r)}%)`);
  }
  if (failed > 0 && !quiet) {
    process.exitCode = 1;
  }
}
function fail(msg) {
  process.stderr.write(BANNER + '\n');
  process.stderr.write(`Error: ${msg}\n`);
  process.exit(2);
}
function formatBytes(n) {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1024 / 1024).toFixed(2)}MB`;
}