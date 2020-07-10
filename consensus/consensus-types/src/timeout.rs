// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common::Epoch;
use crate::common::Round;
use libra_crypto::ed25519::Ed25519Signature;
use libra_crypto_derive::{CryptoHasher, LCSCryptoHash};
use libra_types::validator_signer::ValidatorSigner;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// This structure contains all the information necessary to construct a signature
/// on the equivalent of a timeout message
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, CryptoHasher, LCSCryptoHash)]
pub struct Timeout {
    /// Epoch number corresponds to the set of validators that are active for this round.
    epoch: Epoch,
    /// The consensus protocol executes proposals (blocks) in rounds, which monotically increase per epoch.
    round: Round,
}

impl Timeout {
    pub fn new(epoch: Epoch, round: Round) -> Self {
        Self { epoch, round }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn sign(&self, signer: &ValidatorSigner) -> Ed25519Signature {
        signer.sign(self)
    }
}

impl Display for Timeout {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Timeout: [epoch: {}, round: {}]", self.epoch, self.round,)
    }
}
