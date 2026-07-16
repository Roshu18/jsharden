# jsharden

A powerful, production-grade JavaScript obfuscator for Node.js and browsers that hardens code against reverse engineering. Built on `javascript-obfuscator`, `Terser`, a custom VM, and `WASM`.

* **Version:** 2.0.0
* **License:** MIT
* **Node.js:** >= 18.0.0

---

## Overview

jsharden is an enterprise-grade code obfuscation tool with four configurable security profiles. It transforms readable JavaScript into protected, hardened code that deters casual reverse engineering while maintaining functionality.

### Why jsharden?

* Four protection levels: `light`, `balanced`, `max`, and `armor`
* Production-ready for real-world applications and games
* CLI and programmatic API support
* Deterministic builds with `--seed`
* Watch mode for automatic hardening
* Batch processing support
* Project-level configuration via `.jshardencrc.json`

---

## Security Disclaimer

Client-side obfuscation is a deterrent, not security.

Anything that runs in a browser can be reverse-engineered by a determined attacker. Real secrets should always remain server-side behind authenticated APIs.

Use jsharden to raise the barrier to reverse engineering, not to store cryptographic keys or sensitive information.

---

## Features

| Feature                 | Details                                   |
| ----------------------- | ----------------------------------------- |
| String Encoding         | RC4 and Base64 string encoding            |
| Control Flow Flattening | Makes code harder to analyze              |
| Dead Code Injection     | Adds unreachable code paths               |
| Identifier Renaming     | Renames variables and functions           |
| Self Defending          | Detects common tampering attempts         |
| Custom VM               | Compiles selected functions into bytecode |
| WASM Encryption         | Encrypts string pools using WebAssembly   |
| Minification            | Compresses output using Terser            |
| Watch Mode              | Automatically hardens files on changes    |
| Smoke Testing           | Verifies generated output                 |

---

## Installation

### Global Installation

```bash
npm install -g jsharden

jsharden --version
```

### Local Installation

```bash
npm install --save-dev jsharden
```

Example `package.json` script:

```json
{
  "scripts": {
    "harden": "jsharden src/app.js -o dist/app.js --profile balanced"
  }
}
```

Run:

```bash
npm run harden
```

---

## Quick Start

### Single File

```bash
jsharden input.js -o dist/output.js --profile balanced
```

### Entire Directory

```bash
jsharden ./src --out-dir ./dist --profile max
```

### Watch Mode

```bash
jsharden ./src --out-dir ./dist --watch
```

### Maximum Protection

```bash
jsharden app.js -o dist/app.js --profile armor --verify
```

---

## Protection Profiles

### light

```bash
jsharden app.js -o dist/app.js --profile light
```

| Property             | Value                                       |
| -------------------- | ------------------------------------------- |
| Protection           | Basic identifier renaming and string hiding |
| Size Increase        | 5%–15%                                      |
| Performance Overhead | Less than 5%                                |
| Recommended For      | Public APIs and utilities                   |

---

### balanced (Recommended)

```bash
jsharden app.js -o dist/app.js --profile balanced
```

| Property             | Value                                                        |
| -------------------- | ------------------------------------------------------------ |
| Protection           | Control flow flattening, dead code injection, self-defending |
| Size Increase        | 30%–60%                                                      |
| Performance Overhead | 5%–20%                                                       |
| Recommended For      | Web applications and SaaS frontends                          |

---

### max

```bash
jsharden app.js -o dist/app.js --profile max
```

| Property                             | Value                                                 |
| ------------------------------------ | ----------------------------------------------------- |
| Protection                           | RC4 encoding, aggressive flattening, chained wrappers |
| Size Increase                        | 80%–200%                                              |
| Performance Overhead                 | 20%–80%                                               |
| Estimated Reverse Engineering Effort | 1–2 weeks                                             |
| Recommended For                      | Game clients and premium software                     |

---

### armor

```bash
jsharden app.js -o dist/app.js --profile armor --verify
```

| Property             | Value                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------- |
| Protection           | All max features plus VM bytecode, WASM encryption, integrity checks, and self-healing |
| Size Increase        | Similar to max                                                                         |
| Performance Overhead | 20%–80%+                                                                               |
| Recommended For      | Financial tools and highly sensitive applications                                      |

> Note: VM-compiled functions are significantly harder to recover but should not be considered impossible to reverse engineer.

---

## CLI Reference

### Syntax

```bash
jsharden <input> [options]
jsharden <file1.js> <file2.js> ...
jsharden ./src [options]
```

### Output Options

```bash
-o, --out-file <file>
-d, --out-dir <directory>
```

### Profiles

```bash
--profile light
--profile balanced
--profile max
--profile armor
```

### Development Options

```bash
-w, --watch
--verify
--seed <number>
```

### Security Options

```bash
--anti-debug
--console-off
--no-terser
--no-gate
```

### Advanced Options

```bash
--config <path>
--obfuscator.K=V
```

### Information

```bash
-h, --help
-v, --version
```

---

## Programmatic API

```javascript
import { harden } from "jsharden";

const result = await harden({
  code: 'const secret = "api-key"; console.log(secret);',
  profile: "max",
  seed: 12345,
  verify: true,
  terser: true,
  gate: true,
  antiDebug: false,
  consoleOff: false
});

console.log(result.code);
console.log(result.warnings);
```

---

## Configuration File

Create a `.jshardencrc.json` file:

```json
{
  "profile": "balanced",
  "seed": 42,
  "terser": true,
  "consoleOff": false,
  "antiDebug": false,
  "gate": true
}
```

CLI flags always take precedence over configuration values.

---

## Real-World Examples

### React Application

```bash
npm run build

jsharden dist/index.js \
  -o dist/index.hardened.js \
  --profile max \
  --verify

mv dist/index.hardened.js dist/index.js
```

### Game Client

```bash
jsharden src/game-logic.js \
  -o dist/game-logic.js \
  --profile armor \
  --verify \
  --seed 9001
```

### Development Workflow

```bash
jsharden src/app.js \
  -o dist/app.js \
  --watch \
  --profile balanced
```

### Monorepo Projects

```bash
jsharden packages/*/src \
  --out-dir dist \
  --profile balanced
```

### Reproducible Builds

```bash
jsharden src/app.js \
  -o dist/app.js \
  --profile max \
  --seed 12345 \
  --verify
```

---

## Recommended Profiles

| Use Case                          | Profile              |
| --------------------------------- | -------------------- |
| Public Libraries                  | light                |
| Internal Web Apps                 | balanced             |
| Premium SaaS                      | max                  |
| Game Clients                      | armor                |
| Performance-Critical Applications | light                |
| CI/CD Pipelines                   | balanced with --seed |

---

## Troubleshooting

### Code Breaks After Obfuscation

1. Ensure Node.js 18 or later is installed.
2. Try a lighter profile.
3. Use `--no-terser` for debugging.
4. Use `--verify` to validate the generated output.
5. Avoid fragile dynamic property access when possible.

---

### Large Output Files

* Ensure Terser is enabled.
* Switch to a lighter profile if necessary.
* Use deterministic builds with `--seed`.

---

### Performance Issues

* Use the `light` profile for performance-sensitive applications.
* Disable Browser Gate using `--no-gate` if applicable.
* Profile your application using browser developer tools.

---

### Debugging Hardened Code

* Keep source maps during development.
* Use the `light` profile while actively developing.
* Switch to `max` or `armor` for production builds.

---

## Architecture

jsharden is built on the following technologies:

* javascript-obfuscator
* Terser
* Babel
* Custom VM (Armor Profile)
* WebAssembly (Armor Profile)

---

## License

MIT License

Copyright (c) Roshu18

---

## Contributing

Contributions are welcome. Feel free to open issues or submit pull requests.

---

## Notes

No client-side protection mechanism is unbreakable. Obfuscation increases the time and effort required for reverse engineering, but it does not replace proper application security practices.

Always keep sensitive data and business logic on trusted servers whenever possible.
