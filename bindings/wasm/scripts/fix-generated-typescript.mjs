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

// Rename the reserved `arguments` parameter to `moveArguments` everywhere.
// Catches declarations (with optional default), interface signatures, and
// usage sites like `FfiConverter*.lower(arguments)`.
fixed = fixed.replace(/(?<=[\(,]\s*)arguments(?=\s*[:,\)])/g, 'moveArguments');
fixed = fixed.replace(/\.lower\(arguments\)/g, '.lower(moveArguments)');

if (source !== fixed) {
  writeFileSync(bindingsFile, fixed);
  console.log('Normalized generated TypeScript bindings.');
} else {
  console.log('Generated TypeScript bindings already normalized.');
}