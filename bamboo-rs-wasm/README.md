# bamboo-wasm

** Note this readme does not reflect the state of the code. The code is nowhere near having all this working **

** All that "works" at the moment is that you can publish a message **


> [bamboo](https://github.com/AljoschaMeyer/bamboo) compiled to wasm from [rust](https://github.com/pietgeursen/bamboo-rs)

The goal of this module is to allow you to `publish` new entries or `add` valid exisiting entries to a bamboo `Log`. 

Conceptually, a `Log` is a collection of `Entries` published by a single author.
Bamboo supports [partial replication](https://github.com/AljoschaMeyer/bamboo#partial-replication-and-log-verification). Partial replication means a `Log` may not contain all `Entries` ever published by an author. 

This module has no opinions about _where_ you store the log. You could use leveldb or sqlite or IndexedDB if this is used in the browser.
You could also just store entries in an object or array if you want to store in memory. When constructing a `Log` you must provide a `store` object that implements some required methods (see below.) 

Note that a `Log` does not store the `payload`, it only stores the hash the of the `payload` in the entry. This module has no opinions about where you store the `payload`. Ideally you'll want to be able to access payloads by their `hash`.

## Example

Publish a new `entry`.

```js
  import { Log, MemoryStore } from 'bamboo-wasm';

  const { public, secret } = // Get a keypair from somewhere.
  const store = new MemoryStore()

  const log = new Log({store, public, secret})

  const myMessage =  // what type here, need to see what wasm bindgen provides 

  log.publish(myMessage)
    .then(({payloadHash}) => {
      console.log(`Published payload successfully, payload had hash: ${payloadHash}`)
      
      // Here you would want to store the payload too. 
    })
    .catch(() => {})
```

Add existing `entries` that have already been published. Typically you'd do this when you've replicated messages from another author.

```js
  import { Log, MemoryStore } from 'bamboo-wasm';

  const { public } = // Get the public key of this `Log` 
  const store = new MemoryStore()

  const log = new Log({store, public})

  const messages = [..] // what type here, need to see what wasm bindgen provides 

  log.add(messages)
    .then(() => {
      console.log(`Added messages successfully`)
    })
    .catch(() => {})

```

## Api 

The `store` object:
You need to provide a `store` object that is an abstraction over an asynchronous datastore. 

```js
{
  // Must return a Promise of an Integer
  getLastSeq: function(){
  
  },

  // Must return a Promise of Uint8Array
  getEntry: function(sequenceNumber){
  
  },

  // `entry` is a Uint8Array  
  // `sequenceNumber` is an Integer
  // Must return a Promise of `null`.
  addEntry: function(entry, sequenceNumber){
  
  },
}
```

### 🛠️ Build with `wasm-pack build`

```
wasm-pack build
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
