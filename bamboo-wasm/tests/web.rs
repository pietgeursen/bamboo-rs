//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use bamboo_wasm::*;

#[wasm_bindgen_test]
fn pass() {
    let keypair = KeyPair::new();
    assert_eq!(1 + 1, 2);
}
