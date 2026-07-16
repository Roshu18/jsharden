# jsharden 🔒

A powerful, production-grade JavaScript obfuscator for Node.js and browsers that hardens code against reverse engineering. Built on `javascript-obfuscator` + `Terser` + custom VM + `WASM`.

**Version:** 2.0.0 | **License:** MIT | **Node.js:** >= 18.0.0

---

## 📋 Overview

jsharden is an enterprise-grade code obfuscation tool with four configurable security profiles. It transforms readable JavaScript into protected, hardened code that deters casual reverse engineering while maintaining functionality.

### Why jsharden?

- ✅ **Four Protection Levels:** Choose between `light`, `balanced`, `max`, and `armor`
- - ✅ **Production Ready:** Used in real-world apps and games
  - - ✅ **CLI + API:** Command-line and programmatic interfaces
    - - ✅ **Deterministic Mode:** Reproducible builds with `--seed`
      - - ✅ **Watch Mode:** Auto-harden files on change
        - - ✅ **Batch Processing:** Obfuscate entire directories
          - - ✅ **Config Files:** Project-level `.jshardencrc.json` support
           
            - ### ⚠️ Security Disclaimer
           
            - **Client-side obfuscation is DETERRENCE, not security.** Anything in a browser can be reverse-engineered by a determined attacker. **Keep real secrets server-side behind an authenticated API.** Use jsharden to raise the barrier to entry, not for cryptographic keys.
           
            - ---

            ## ✨ Features

            | Feature | Details |
            |---------|---------|
            | **String Encoding** | RC4/Base64 string encryption |
            | **Control-Flow Flattening** | Flatten logic to confuse analyzers |
            | **Dead-Code Injection** | Add unreachable code |
            | **Identifier Renaming** | Rename variables & functions |
            | **Self-Defending** | Detect tampering attempts |
            | **Custom VM** | Compile functions to bytecode |
            | **WASM Encryption** | Encrypt strings with WebAssembly |
            | **Minification** | Compress with Terser |
            | **Watch Mode** | Re-harden on file change |
            | **Smoke Testing** | Verify output works |

            ---

            ## 🚀 Installation

            ### Global (Recommended for CLI)

            ```bash
            npm install -g jsharden
            jsharden --version  # Verify
            ```

            ### Local (For Projects)

            ```bash
            npm install jsharden --save-dev
            ```

            Add to `package.json`:
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

            ## ⚡ Quick Start

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

            ## 🛡️ Obfuscation Profiles

            ### light — Fast & Minimal
            ```bash
            jsharden app.js -o dist/app.js --profile light
            ```
            - **Protection:** Basic identifier renaming + string hiding
            - - **Size:** +5–15%
              - - **Speed:** <5% overhead
                - - **Best for:** Public APIs, utilities
                 
                  - ### balanced — Industry Standard (Recommended)
                  - ```bash
                    jsharden app.js -o dist/app.js --profile balanced
                    ```
                    - **Protection:** Control-flow flattening, dead-code, self-defending
                    - - **Size:** +30–60%
                      - - **Speed:** 5–20% overhead
                        - - **Best for:** Web apps, SaaS frontends
                         
                          - ### max — High Security
                          - ```bash
                            jsharden app.js -o dist/app.js --profile max
                            ```
                            - **Protection:** RC4 encoding, aggressive flattening, chained wrappers
                            - - **Size:** +80–200%
                              - - **Speed:** 20–80% overhead
                                - - **Effort to reverse:** 1–2 weeks
                                  - - **Best for:** Game clients, premium tools
                                   
                                    - ### armor — Maximum Protection
                                    - ```bash
                                      jsharden app.js -o dist/app.js --profile armor --verify
                                      ```
                                      - **Protection:** All of `max` + VM bytecode + WASM encryption + integrity hash + self-healing
                                      - - **Size:** Similar to `max`
                                        - - **Speed:** 20–80%+ overhead
                                          - - **Effort to reverse:** Near-impossible
                                            - - **Note:** VM-compiled functions are unrecoverable
                                              - - **Best for:** Ultra-sensitive apps, financial tools
                                               
                                                - ---

                                                ## 🖥️ CLI Reference

                                                ### Syntax
                                                ```bash
                                                jsharden <input> [options]
                                                jsharden <file1.js> <file2.js> ...
                                                jsharden ./src [options]
                                                ```

                                                ### Output Options
                                                ```bash
                                                -o, --out-file <f>    # Single output file
                                                -d, --out-dir <dir>   # Output directory (batch)
                                                ```

                                                ### Profiles
                                                ```bash
                                                --profile light       # Default: balanced
                                                --profile balanced
                                                --profile max
                                                --profile armor
                                                ```

                                                ### Development
                                                ```bash
                                                -w, --watch           # Re-harden on change
                                                --verify              # Test output in sandbox
                                                --seed <n>            # Deterministic output
                                                ```

                                                ### Security
                                                ```bash
                                                --anti-debug          # Enable debug protection
                                                --console-off         # Strip console.* calls
                                                --no-terser           # Skip compression
                                                --no-gate             # Skip Browser-Gate (armor only)
                                                ```

                                                ### Advanced
                                                ```bash
                                                --config <path>       # Config file path
                                                --obfuscator.K=V      # Pass to javascript-obfuscator
                                                ```

                                                ### Info
                                                ```bash
                                                -h, --help            # Show help
                                                -v, --version         # Show version
                                                ```

                                                ---

                                                ## 💻 Programmatic API

                                                Use jsharden in your build pipeline:

                                                ```javascript
                                                import { harden } from 'jsharden';

                                                const result = await harden({
                                                  code: 'const secret = "api-key"; console.log(secret);',
                                                  profile: 'max',       // 'light', 'balanced', 'max', 'armor'
                                                  seed: 12345,          // Optional: reproducible output
                                                  verify: true,         // Optional: test output
                                                  terser: true,         // Optional: minify (default: true)
                                                  gate: true,           // Optional: use browser-gate (armor only)
                                                  antiDebug: false,     // Optional: debug protection
                                                  consoleOff: false,    // Optional: strip console calls
                                                });

                                                console.log(result.code);      // Obfuscated code
                                                console.log(result.warnings);  // Any warnings
                                                ```

                                                ---

                                                ## 📝 Configuration File

                                                Create `.jshardencrc.json` in your project:

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

                                                CLI flags override config file settings.

                                                ---

                                                ## 🎯 Real-World Examples

                                                ### React App Protection
                                                ```bash
                                                npm run build
                                                jsharden dist/index.js -o dist/index.hardened.js --profile max --verify
                                                mv dist/index.hardened.js dist/index.js
                                                ```

                                                ### Game Client (Maximum Protection)
                                                ```bash
                                                jsharden src/game-logic.js -o dist/game-logic.js \
                                                  --profile armor \
                                                  --verify \
                                                  --seed 9001
                                                ```

                                                ### Development with Watch Mode
                                                ```bash
                                                jsharden src/app.js -o dist/app.js --watch --profile balanced
                                                ```

                                                ### Monorepo Batch Protection
                                                ```bash
                                                jsharden packages/*/src --out-dir dist --profile balanced
                                                ```

                                                ### Reproducible CI/CD Builds
                                                ```bash
                                                jsharden src/app.js -o dist/app.js --profile max --seed 12345 --verify
                                                ```

                                                ---

                                                ## 📊 Use Cases

                                                | Scenario | Profile | Reason |
                                                |----------|---------|--------|
                                                | Public library | `light` | Minimal overhead |
                                                | Internal web app | `balanced` | Industry standard |
                                                | Premium SaaS | `max` | High security |
                                                | Game/financial tool | `armor` | Maximum protection |
                                                | Real-time app | `light` | Performance critical |
                                                | Production CI/CD | `balanced` with `--seed` | Reproducible builds |

                                                ---

                                                ## 🐛 Troubleshooting

                                                ### Code Breaks After Obfuscation
                                                1. Ensure Node.js >= 18.0.0
                                                2. 2. Try lighter profile (`light` or `balanced`)
                                                   3. 3. Use `--no-terser` to isolate the issue
                                                      4. 4. Use `--verify` to catch errors early
                                                         5. 5. Avoid dynamic property access: `obj[variableName]`
                                                           
                                                            6. ### File Size Too Large
                                                            7. - Ensure `--no-terser=false` (Terser should run)
                                                               - - Switch to lighter profile
                                                                 - - Use `--seed` for consistent sizes
                                                                  
                                                                   - ### Performance Degraded
                                                                   - - Consider `light` profile for time-critical code
                                                                     - - Use `--no-gate` for armor profile
                                                                       - - Profile with browser DevTools
                                                                        
                                                                         - ### Debugging Obfuscated Code
                                                                         - - Keep source maps during development
                                                                           - - Use `light` profile during active dev
                                                                             - - Switch to `max`/`armor` for production
                                                                              
                                                                               - ---

                                                                               ## 🏗️ Architecture

                                                                               Built on industry-standard tools:
                                                                               - **javascript-obfuscator:** Core obfuscation engine
                                                                               - - **terser:** Minification & compression
                                                                                 - - **Custom VM:** Bytecode interpreter (armor)
                                                                                   - - **WASM:** String pool encryption (armor)
                                                                                     - - **Babel:** AST parsing & transformation
                                                                                      
                                                                                       - ---

                                                                                       ## 📄 License

                                                                                       MIT © Roshu18

                                                                                       ---

                                                                                       ## 🤝 Contributing

                                                                                       Contributions welcome! Open issues and PRs on GitHub.

                                                                                       ---

                                                                                       **Made with ❤️ for code protection**
