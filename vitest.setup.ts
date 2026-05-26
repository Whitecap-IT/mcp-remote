import { File } from 'node:buffer'

if (typeof globalThis.File === 'undefined') {
  globalThis.File = File as unknown as typeof globalThis.File
}
