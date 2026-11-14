// DepGuard ESM hooks (run on Node's loader thread via module.register()).
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const core = createRequire(import.meta.url)('./core.cjs');

export async function load(url, context, nextLoad) {
  if (url.startsWith('file:') && !url.endsWith('.json') && !url.endsWith('.wasm')) {
    core.check(fileURLToPath(url)); // throws in enforce mode => import() rejects
  }
  return nextLoad(url, context);
}
