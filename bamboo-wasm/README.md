# @bamboo-logs/bamboo-wasm

`publish`, `verify` and `decode` bamboo entries from javascript / typescript.

## About

This is a low level module. It's unlikely you want this. See [@bamboo-logs/bamboo-log](https://www.npmjs.com/package/@bamboo-logs/bamboo-log) for a module that wraps these functions and provides an easier to use API.

## Example

Publish and verify our first entry!

```js
const {publish, verify, decode, KeyPair} = require('@bamboo-logs/bamboo-wasm')

// Create a new cryptographic keypair for signing our entries
const keyPair = new KeyPair()

// The payload for our first entry
const payload = Buffer.from("Hello World!")

// The bamboo log id that we'll publish to. See the bamboo spec for more.
// Note that logId is a BigInt because it can be up to 2^64 -1.
const logId = 0n

// Is this the entry the last entry for this logId?
const isEndOfFeed = false

// Publish our first entry!
const entryBytes = publish(keyPair.publicKeyBytes(), keyPair.secretKeyBytes(), logId, payload, isEndOfFeed)

// Decode the entry bytes as an `Entry` 
const entry = decode(entryBytes)

console.log(entry)

try {
  // verify throws (with a useful exception) if the entry is invalid
  verify(entryBytes, payload)
  console.log("Entry was valid")
}catch(e){ }

```

Outputs:

( Array contents omitted for clarity )

```
{
  entryHash: Uint8Array(66) [ ... ],
  payloadHash: Uint8Array(66) [ ... ],
  lipmaaLinkHash: undefined,
  backLinkHash: undefined,
  signature: Uint8Array(64) [ ... ],
  author: Uint8Array(32) [ ... ],
  isEndOfFeed: false,
  logId: 0n,
  payloadSize: 12n,
  sequence: 1n
}
Entry was valid
```

## Api

See the Typescript types in `index.d.ts`

### NPM

[Published on npm](https://www.npmjs.com/package/@bamboo-logs/bamboo-wasm)

### 🛠️ Build with `wasm-pack build`

```
wasm-pack build  -t nodejs --scope bamboo-logs --release --out-name index -- --no-default-features --features u32_backend
wasm-opt index_bg.wasm --enable-mutable-globals -O4 -o ./index_bg.wasm
```

### 🔬 Test in Headless Browsers with `wasm-pack test`

```
wasm-pack test --headless --firefox
```

### 🎁 Publish to NPM with `wasm-pack publish`

```
wasm-pack publish
```

## 🔋 Batteries Included

* [`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen) for communicating
  between WebAssembly and JavaScript.
* [`console_error_panic_hook`](https://github.com/rustwasm/console_error_panic_hook)
  for logging panic messages to the developer console.
* [`wee_alloc`](https://github.com/rustwasm/wee_alloc), an allocator optimized
  for small code size.
