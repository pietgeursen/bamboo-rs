# bamboo-rs

> WIP implementation of [bamboo](https://github.com/AljoschaMeyer/bamboo) in rust.

## About

`bamboo-rs` aspires to be portable, fast and correct.

### portable

`bamboo-core` supports compilation with `no_std` and uses crypto libraries that support this too. [Anywhere rust can go](https://forge.rust-lang.org/release/platform-support.html), bamboo can go too, including microcontrollers, mobile and in the browser via web assembly.

`bamboo-core` expose a c-friendly api so building bindings to other languages should be

### fast

The most likely bottleneck for applications is verification. Experience with scuttlebutt shows that once an application has to deal with a few years of data from a social network, onboarding a new user is painfully slow, and part of that slowness is due to verification.  

`bamboo-rs` verification is fast because it: 
  - uses batch verification of hashes and cryptographic signatures.
  - use multi cpus where available.
  - use SIMD instructions where available. 


### correct
  -  


[Test vectors](./test_vectors/test_vectors.md) for testing your implementation against this one.
