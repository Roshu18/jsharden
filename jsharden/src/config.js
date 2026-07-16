import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { PROFILES } from './profiles.js';
const CONFIG_FILENAMES = ['.jshardenrc.json', '.jshardenrc'];
export async function findConfig(startDir) {
  let dir = resolve(startDir);
  for (;;) {
    for (const name of CONFIG_FILENAMES) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) {
        try {
          const raw = await readFile(candidate, 'utf8');
          const parsed = JSON.parse(raw);
          return {
            config: parsed,
            path: candidate
          };
        } catch (err) {
          throw new Error(`Failed to parse ${candidate}: ${err.message}`);
        }
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return {
    config: null,
    path: null
  };
}
export async function resolveConfig(args, cwd) {
  const {
    config: fileConfig,
    path: configPath
  } = await findConfig(cwd);
  const profileName = args.profile || fileConfig?.profile || 'balanced';
  if (!PROFILES[profileName] && profileName !== 'armor') {
    throw new Error(`Unknown profile: ${profileName}. Choose from: light, balanced, max, armor.`);
  }
  const resolved = {
    profile: profileName,
    outFile: args.outFile || fileConfig?.outFile || null,
    outDir: args.outDir || fileConfig?.outDir || null,
    antiDebug: args.antiDebug ?? fileConfig?.antiDebug ?? false,
    consoleOff: args.consoleOff ?? fileConfig?.consoleOff ?? false,
    watch: args.watch ?? fileConfig?.watch ?? false,
    seed: typeof args.seed === 'number' ? args.seed : fileConfig?.seed ?? 0,
    obfuscatorOverrides: {
      ...(fileConfig?.obfuscatorOverrides || {}),
      ...(args.obfuscatorOverrides || {})
    }
  };
  return {
    resolved,
    configPath,
    profileName
  };
}