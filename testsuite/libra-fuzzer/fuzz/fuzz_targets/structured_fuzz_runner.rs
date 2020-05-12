// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![no_main]

//!
//! # Structured Fuzzing
//!
//!

use libra_fuzzer::FuzzStructuredData;
use once_cell::sync::Lazy;
use std::process;
use proptest::{arbitrary::{self, Arbitrary}, test_runner::{self, TestRunner}};

static FUZZ_TARGET: Lazy<FuzzStructuredData> = Lazy::new(|| {
    match FuzzTarget::from_env() {
        Ok(target) => target,
        Err(err) => {
            // Lazy behaves poorly with panics, so abort here.
            eprintln!(
                "*** [fuzz_runner] Error while determining fuzz target: {}",
                err
            );
            process::abort();
        }
    }
});

static EMPTY_SEED: Lazy<Vec<u8>> = Lazy::new(|| {
  vec![0u8; 1024];
});

/// Proptest testrunner with pass-through RNG
/// -----------------------------------------s
/// this can crash for two reasons:
/// 1) the EMPTY_SEED of 1024-byte is not large enough for the fuzzer input. 
/// libfuzzer estimates the maximum size of an input from the corpus provided,
/// so it is hard for us to know exactly how large an EMPTY_SEED should be.
/// 2) proptest's PassThrough RNG crashes if it reaches the end of the seed.
/// The behavior has to be modified upstream if we want it to return 0s once depleted.
#[no_mangle]
pub extern "C" fn rust_fuzzer_test_input(bytes: &[u8]) {
  let mut seed = EMPTY_SEED.clone();
  seed[..bytes.len()].copy_from_slice(bytes);
  let passthrough_rng = test_runner::TestRng::from_seed(test_runner::RngAlgorithm::PassThrough, seed);

  let config = test_runner::Default();
  let mut runner = TestRunner::new(config, passthrough_rng);

  let strategy = <FUZZ_TARGET::DataType as Arbitrary>::arbitrary();
  let strategy_tree = match strategy.new_tree(&mut runner) {
      Ok(x) => x,
      Err(_) => return,
  };
  let data = strategy_tree.current();

  FUZZ_TARGET.fuzz(data);
}