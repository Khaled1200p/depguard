'use strict';
/**
 * DepGuard Tier-A Node.js interceptor. Zero application changes:
 *
 *   DEPGUARD_BASELINE=/app/depguard.baseline.json DEPGUARD_MODE=enforce \
 *   node --require /opt/depguard/agents/node/loader.js app.js
 *   # or: NODE_OPTIONS="--require /opt/depguard/agents/node/loader.js"
 *
 * Hooks (all run BEFORE the file is read/compiled/dlopen'ed):
 *   - Module._extensions['.js'|'.node']  every CommonJS file, incl. .cjs and require(esm)
 *   - process.dlopen                     every native addon, however it was located
 *   - module.register(esm-hooks.mjs)     every ESM import()/import (load hook)
 */
const Module = require('module');
const path = require('path');
const { pathToFileURL } = require('url');
const core = require('./core.cjs');

if (core.enabled) {
  for (const ext of ['.js', '.node']) {
    const original = Module._extensions[ext];
    if (typeof original !== 'function') continue;
    Module._extensions[ext] = function depguardExtension(module, filename) {
      core.check(filename);
      return original.call(this, module, filename);
    };
  }

  const originalDlopen = process.dlopen;
  process.dlopen = function depguardDlopen(module, filename, ...rest) {
    core.check(filename);
    return originalDlopen.call(this, module, filename, ...rest);
  };

  try {
    if (typeof Module.register === 'function') { // Node >= 18.19 / 20.6
      Module.register('./esm-hooks.mjs', pathToFileURL(path.join(__dirname, 'loader.js')));
    }
  } catch (err) {
    process.emitWarning(`DepGuard: ESM hooks unavailable (${err.message})`);
  }
}
