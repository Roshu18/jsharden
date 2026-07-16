import { glob } from 'tinyglobby';
import { resolve, extname, basename, join } from 'node:path';
import { statSync } from 'node:fs';
const JS_EXTS = new Set(['.js', '.mjs', '.cjs']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo', 'out']);
export async function discoverFiles(inputs, cwd) {
  const found = new Set();
  for (const input of inputs) {
    const abs = resolve(cwd, input);
    let st;
    try {
      st = statSync(abs);
    } catch {
      st = null;
    }
    if (st && st.isFile()) {
      found.add(abs);
      continue;
    }
    if (st && st.isDirectory()) {
      const matches = await glob(join(abs, '**/*'), {
        onlyFiles: true,
        dot: false,
        ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.next/**', '**/.cache/**', '**/.turbo/**', '**/out/**', '**/*.hardened.js']
      });
      for (const m of matches) {
        const p = resolve(m);
        if (JS_EXTS.has(extname(p))) {
          found.add(p);
        }
      }
      continue;
    }
    const matches = await glob(input, {
      onlyFiles: true,
      dot: false,
      cwd,
      ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/*.hardened.js']
    });
    for (const m of matches) {
      const p = resolve(cwd, m);
      if (JS_EXTS.has(extname(p))) {
        found.add(p);
      }
    }
  }
  const cleaned = [];
  for (const p of found) {
    const parts = p.split(/[/\\]/);
    if (parts.some(seg => SKIP_DIRS.has(seg))) continue;
    if (basename(p).endsWith('.hardened.js')) continue;
    cleaned.push(p);
  }
  cleaned.sort();
  return cleaned;
}
export function computeOutputPath(inputFile, outFile, outDir) {
  if (outFile) return resolve(outFile);
  const dir = outDir ? resolve(outDir) : resolve(inputFile, '..');
  const base = basename(inputFile);
  return join(dir, `${base}.hardened.js`);
}