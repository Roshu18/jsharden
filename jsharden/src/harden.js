import JavaScriptObfuscator from 'javascript-obfuscator';
import { minify } from 'terser';
export function splitUserscriptHeader(src) {
  const headerStart = src.indexOf('// ==UserScript==');
  if (headerStart === -1) return {
    header: '',
    body: src
  };
  const headerEnd = src.indexOf('// ==/UserScript==', headerStart);
  if (headerEnd === -1) return {
    header: '',
    body: src
  };
  const headerEndFull = headerEnd + '// ==/UserScript=='.length;
  const wsMatch = src.slice(headerEndFull).match(/^[ \t\r\n]*/);
  const headerEndWithWs = headerEndFull + (wsMatch ? wsMatch[0].length : 0);
  return {
    header: src.slice(0, headerEndWithWs),
    body: src.slice(headerEndWithWs)
  };
}
export function verifyParses(code) {
  const wrapped = `(function(){${code}\n})`;
  try {
    new Function(wrapped);
  } catch (err) {
    throw new Error(`Output does not parse: ${err.message}`);
  }
}
export async function smokeTest(code, sandboxExtras = {}) {
  const document = {
    body: {
      appendChild: () => {},
      removeChild: () => {}
    },
    documentElement: {
      appendChild: () => {},
      removeChild: () => {}
    },
    addEventListener: () => {},
    createElement: tag => {
      const el = {
        tagName: String(tag).toUpperCase(),
        nodeName: String(tag).toUpperCase(),
        style: {
          cssText: ''
        },
        setAttribute: () => {},
        appendChild: () => {},
        removeChild: () => {},
        querySelector: () => null,
        querySelectorAll: () => [],
        classList: {
          add: () => {},
          remove: () => {},
          toggle: () => {}
        },
        dataset: {}
      };
      if (tag === 'canvas') {
        el.width = 0;
        el.height = 0;
        el.getContext = type => {
          if (type === '2d') {
            const ctx = {
              _fillStyle: '#000000',
              set fillStyle(v) {
                this._fillStyle = String(v);
              },
              get fillStyle() {
                return this._fillStyle;
              },
              fillRect: () => {},
              getImageData: (x, y, w, h) => {
                const fs = ctx._fillStyle || '#000000';
                let r = 0,
                  g = 0,
                  b = 0;
                let m = fs.match(/^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i);
                if (m) {
                  r = parseInt(m[1], 16);
                  g = parseInt(m[2], 16);
                  b = parseInt(m[3], 16);
                } else {
                  m = fs.match(/^#([0-9a-f])([0-9a-f])([0-9a-f])$/i);
                  if (m) {
                    r = parseInt(m[1] + m[1], 16);
                    g = parseInt(m[2] + m[2], 16);
                    b = parseInt(m[3] + m[3], 16);
                  }
                }
                const size = w * h * 4;
                const data = new Array(size);
                for (let i = 0; i < size; i += 4) {
                  data[i] = r;
                  data[i + 1] = g;
                  data[i + 2] = b;
                  data[i + 3] = 255;
                }
                return {
                  data
                };
              }
            };
            ctx.canvas = el;
            return ctx;
          }
          if (type === 'webgl' || type === 'experimental-webgl') {
            return {
              getParameter: p => {
                if (p === 7936) return 'WebGL 1.0';
                if (p === 35724) return 'WebGL GLSL ES 1.0';
                if (p === 3379) return 16384;
                if (p === 34921) return 16;
                return 0;
              }
            };
          }
          return null;
        };
        el.toDataURL = () => 'data:image/png;base64,AAAA';
      }
      return el;
    },
    toString: () => '[object HTMLDocument]',
    documentMode: 11,
    fonts: {
      size: 5,
      ready: Promise.resolve()
    }
  };
  const navigator = {
    userAgent: 'Mozilla/5.0 (smokeTest)',
    plugins: {
      length: 3
    },
    hardwareConcurrency: 8
  };
  const screen = {
    width: 1920,
    height: 1080
  };
  const performance = {
    now: () => 123.456
  };
  const crypto = {
    subtle: {},
    getRandomValues: arr => arr
  };
  const history = {
    length: 1
  };
  const location = {
    href: 'https://example.com',
    toString: () => 'https://example.com'
  };
  const getComputedStyle = () => ({
    color: 'rgb(255, 0, 0)',
    display: 'block',
    position: 'static',
    visibility: 'visible'
  });
  const window = {
    console: {
      log: () => {},
      warn: () => {},
      error: () => {},
      table: () => {},
      info: () => {}
    },
    document,
    navigator,
    screen,
    performance,
    crypto,
    history,
    location,
    getComputedStyle,
    toString: () => '[object Window]',
    chrome: {
      runtime: {}
    },
    outerWidth: 1920,
    ontouchstart: null,
    addEventListener: () => {},
    localStorage: {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {}
    },
    indexedDB: {},
    Object,
    Function,
    Array,
    Math,
    Date,
    JSON,
    Promise,
    setTimeout: () => 0,
    setInterval: () => 0,
    clearInterval: () => {},
    clearTimeout: () => {},
    requestAnimationFrame: () => 0,
    ...sandboxExtras
  };
  window.window = window;
  window.self = window;
  window.globalThis = window;
  const sandbox = {
    window,
    self: window,
    globalThis: window,
    document,
    navigator,
    screen,
    performance,
    crypto,
    history,
    location,
    getComputedStyle,
    ...window
  };
  try {
    const keys = Object.keys(sandbox);
    const values = Object.values(sandbox);
    const fn = new Function(...keys, `"use strict";${code}`);
    fn(...values);
    return {
      ok: true,
      window
    };
  } catch (err) {
    return {
      ok: false,
      error: err.message,
      window
    };
  }
}
export async function harden({
  source,
  obfuscatorOptions,
  skipTerser = false
}) {
  const before = source.length;
  const {
    header,
    body
  } = splitUserscriptHeader(source);
  const obfResult = JavaScriptObfuscator.obfuscate(body, obfuscatorOptions);
  const obfuscated = obfResult.getObfuscatedCode();
  const after = (header + obfuscated).length;
  let final = header + obfuscated;
  if (!skipTerser) {
    const terserResult = await minify({
      'input.js': obfuscated
    }, {
      toplevel: false,
      mangle: {
        toplevel: false,
        reserved: []
      },
      format: {
        comments: false,
        ecma: 2020
      },
      compress: {
        dead_code: true,
        inline: 1,
        conditionals: true,
        sequences: true,
        reduce_vars: true,
        ecma: 2020,
        passes: 2
      },
      ecma: 2020
    });
    if (terserResult.code) {
      final = header + terserResult.code;
    }
  }
  const afterTerser = final.length;
  verifyParses(final);
  return {
    code: final,
    stats: {
      before,
      after,
      afterTerser
    }
  };
}