// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! # Libra-Fuzz
//!
//! There are two kinds of targets we can fuzz:
//! - ByteArrayTarget. A function that takes a bytearray as input.
//! - StructedDataTarget. A function that takes a struct as input.
//!

use libra_proptest_helpers::ValueGenerator;
use std::{fmt, ops::Deref, str::FromStr};
use proptest::arbitrary::Arbitrary;
use anyhow::{format_err, Result};
use once_cell::sync::Lazy;
use std::{collections::BTreeMap, env};

mod fuzz_targets;
mod commands;
#[cfg(test)]
mod coverage;

use fuzz_targets::ALL_TARGETS;

//
// Fuzz Targets
// ------------
//
// There are two kinds of targets we can fuzz:
// - ByteArrayTarget. A function that takes a bytearray as input.
// - StructedDataTarget. A function that takes a struct as input.
//
//

/// A fuzzer can target a function taking a bytearray or a struct as input
#[derive(Clone)]
pub enum FuzzTarget<B, S> where B: FuzzByteArray, S: FuzzStructuredData {
    ByteArray(B),
    StructuredData(S),
}

impl<B, S> FuzzTarget<B, S> {
    /// The environment variable used for passing fuzz targets to child processes.
    pub(crate) const ENV_VAR: &'static str = "FUZZ_TARGET";

    /// get name
    pub fn name(&self) -> &'static str {
        match self {
            FuzzTarget::ByteArray(x) => x.name(),
            FuzzTarget::StructuredData(x) => x.name(),
        }
    }

    /// get description
    pub fn description(&self) -> &'static str {
        match self {
            FuzzTarget::ByteArray(x) => x.description(),
            FuzzTarget::StructuredData(x) => x.description(),
        }
    }

    /// Get the current fuzz target from the environment.
    pub fn from_env() -> Result<Self> {
        let name = env::var(Self::ENV_VAR)?;
        Self::by_name(&name).ok_or_else(|| format_err!("Unknown fuzz target '{}'", name))
    }

    /// Get a fuzz target by name.
    pub fn by_name(name: &str) -> Option<Self> {
        ALL_TARGETS.get(name)
    }

    /// A list of all fuzz targets.
    pub fn all_targets() -> impl Iterator<Item = Self> {
        ALL_TARGETS.values()
    }
}

impl<B, S> FromStr for FuzzTarget<B, S> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FuzzTarget::by_name(s).ok_or_else(|| format!("Fuzz target '{}' not found (run `list`)", s))
    }
}

//
// The different types of `FuzzTarget`
// -----------------------------------
//

/// Implementation for a particular target of a fuzz operation.
pub trait FuzzByteArray {
    /// The name of the fuzz target.
    fn name() -> &'static str;

    /// A description for this target.
    fn description() -> &'static str;

    /// Generates a new example for this target to store in the corpus. `idx` is the current index
    /// of the item being generated, starting from 0.
    ///
    /// Returns `Some(bytes)` if a value was generated, or `None` if no value can be generated.
    fn generate(idx: usize, gen: &mut ValueGenerator) -> Option<Vec<u8>>;

    /// Fuzz the target with this data. The fuzzer tests for panics or OOMs with this method.
    fn fuzz(data: &[u8]);
}

/// Implementation for a particular target of a fuzz operation.
pub trait FuzzStructuredData {
    ///
    type DataType: Arbitrary;

    /// The name of the fuzz target.
    fn name() -> &'static str;

    /// A description for this target.
    fn description() -> &'static str;

    /// Generation is just about generating a seed large enough for proptest to generate a `DataType`
    fn generate() -> Vec<u8> {
        let mut output = vec![0u8; 1024];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut output);
        output
    }

    /// Fuzz the target with this data. The fuzzer tests for panics or OOMs with this method.
    fn fuzz(data: Self::DataType);
}

//
// Convenience macros
// ------------------
//

/// Convenience macro to return the module name.
macro_rules! module_name {
    () => {
        module_path!()
            .rsplit("::")
            .next()
            .expect("module path must have at least one component")
    };
}

/// A fuzz target implementation for protobuf-compiled targets.
macro_rules! proto_fuzz_target {
    ($target:ident => $ty:ty, $prototy:ty) => {
        #[derive(Clone, Debug, Default)]
        pub struct $target;

        impl $crate::FuzzByteArray for $target {
            fn name() -> &'static str {
                module_name!()
            }

            fn description() -> &'static str {
                concat!(stringify!($ty), " (protobuf)")
            }

            fn generate(
                _idx: usize,
                gen: &mut ::libra_proptest_helpers::ValueGenerator,
            ) -> Option<Vec<u8>> {
                use libra_prost_ext::MessageExt;

                let value: $prototy = gen.generate(::proptest::arbitrary::any::<$ty>()).into();

                Some(value.to_vec().expect("failed to convert to bytes"))
            }

            fn fuzz(data: &[u8]) {
                use prost::Message;
                use std::convert::TryFrom;

                // Errors are OK -- the fuzzer cares about panics and OOMs.
                let _ = <$prototy>::decode(data).map(<$ty>::try_from);
            }
        }
    };
}
