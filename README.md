# bamboo-rs

> Rust implementation of [bamboo](https://github.com/AljoschaMeyer/bamboo).

## Docs
[Rust docs](https://pietgeursen.github.io/bamboo-rs/bamboo_rs_core/)

## About

`bamboo-rs` aspires to be portable, fast and correct.

### Portable

`bamboo-rs-core` supports compilation with `no_std` and uses crypto libraries that support this too. [Anywhere rust can go](https://forge.rust-lang.org/release/platform-support.html), bamboo can go too, including microcontrollers, mobile and in the browser via web assembly.

Bamboo releases target 29 different architectures. Releases of the bamboo_core library expose a c api so you can build bindings to many other languages.

### Fast

The most likely bottleneck for applications is verification. Experience with scuttlebutt shows that once an application has to deal with a few years of data from a social network, onboarding a new user is painfully slow, and part of that slowness is due to verification. 

`bamboo-rs` exports a batch verification function that uses [rayon](https://docs.rs/rayon) and signature batch verification that uses SIMD instructions for ~3-4 * speed up.

### Correct

There are [Test vectors](./test_vectors/test_vectors.md) so that you can test your implementation against this one. As people build their own implementations of bamboo we can work together to check each other's work.

## CLI

Check out [bamboo-rs-cli](./bamboo-rs-cli), a command line tool for working with bamboo entries. Download it for your architecture from the [releases](https://github.com/pietgeursen/bamboo-rs/releases)
