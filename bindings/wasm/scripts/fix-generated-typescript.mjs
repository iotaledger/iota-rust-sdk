// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const bindingsFile = resolve(process.cwd(), 'src/ts/iota_sdk_ffi.ts');

const source = readFileSync(bindingsFile, 'utf8');
let fixed = source.replaceAll('async public ', 'public async ');
// Replace standalone Object. references (built-in Object methods like
// Object.freeze, Object.create) with globalThis.Object. to avoid conflict
// with the generated `export class Object`.  Must NOT replace compound names
// like GenesisObject., FfiConverterTypeObject., UniffiAbstractObject. etc.
fixed = fixed.replace(/(?<![.\w])Object\./g, 'globalThis.Object.');

// The broad regex above is too eager: the IOTA Object class's factory does
// `Object.create(Object.prototype)` — the first `Object.create` is the
// BUILT-IN, but the second `Object.prototype` is the IOTA Object class's
// prototype. Without it, instances returned from `client.object(...)` would
// be plain `{}` literals without the IOTA Object's methods. Restore the
// second `Object.prototype` so the prototype chain points at the IOTA class.
fixed = fixed.replace(
  /globalThis\.Object\.create\(globalThis\.Object\.prototype\)/g,
  'globalThis.Object.create(Object.prototype)',
);

// Rename the reserved `arguments` parameter to `moveArguments` everywhere.
// Catches declarations (with optional default), interface signatures, and
// usage sites like `FfiConverter*.lower(arguments)`.
fixed = fixed.replace(/(?<=[\(,]\s*)arguments(?=\s*[:,\)])/g, 'moveArguments');
fixed = fixed.replace(/\.lower\(arguments\)/g, '.lower(moveArguments)');

// Redirect the wasm-bindgen import from index.js to index_bg.js.
// index.js (bundler target) does `import * from "./index_bg.wasm"` which
// esbuild can't handle.  index_bg.js is the pure JS glue without WASM imports.
// The WASM loading is handled by index.web.ts instead.
fixed = fixed.replace(
  /from ['"]\.\/wasm-bindgen\/index\.js['"]/g,
  'from "./wasm-bindgen/index_bg.js"'
);

if (source !== fixed) {
  writeFileSync(bindingsFile, fixed);
  console.log('Normalized generated TypeScript bindings.');
} else {
  console.log('Generated TypeScript bindings already normalized.');
}
