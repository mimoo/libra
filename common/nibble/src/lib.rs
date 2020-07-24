// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `Nibble` represents a four-bit unsigned integer.

#[cfg(feature = "fuzzing")]
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Nibble(u8);

impl TryFrom<u8> for Nibble {
    type Error = ();

    fn try_from(nibble: u8) -> Result<Self, ()> {
        if !(nibble < 16) {
            return Err(());
        } // "Nibble out of range: {}", nibble);
        Ok(Self(nibble))
    }
}

impl From<Nibble> for u8 {
    fn from(nibble: Nibble) -> Self {
        nibble.0
    }
}

impl fmt::LowerHex for Nibble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[cfg(feature = "fuzzing")]
impl Arbitrary for Nibble {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (0..16u8).prop_map(Self::from).boxed()
    }
}
