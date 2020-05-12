
// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::FuzzTarget;
use std::{collections::BTreeMap, env};

// Adding a fuzzer
// ---------------
//
// To add a fuzzer:
// 1. expose its module
// 2. add it to the ALL_TARGETS list
//

// 1. List fuzz target modules here.
mod accumulator_merkle_proof;
mod compiled_module;
mod consensus_proposal;
mod inbound_rpc_protocol;
mod inner_signed_transaction;
mod json_rpc_service;
mod network_noise_initiator;
mod storage_save_blocks;
mod signed_transaction;
mod sparse_merkle_proof;
mod vm_value;

// 2. Map of all targets
static ALL_TARGETS: Lazy<BTreeMap<&'static str, FuzzTarget>> = Lazy::new(|| {
    let targets: Vec<FuzzType> = vec![
        // byte-array targets
        FuzzTarget::ByteArray(compiled_module::CompiledModuleTarget::default()),
        FuzzTarget::ByteArray(signed_transaction::SignedTransactionTarget::default()),
        FuzzTarget::ByteArray(inner_signed_transaction::SignedTransactionTarget::default()),
        FuzzTarget::ByteArray(sparse_merkle_proof::SparseMerkleProofTarget::default()),
        FuzzTarget::ByteArray(vm_value::ValueTarget::default()),
        FuzzTarget::ByteArray(consensus_proposal::ConsensusProposal::default()),
        FuzzTarget::ByteArray(json_rpc_service::JsonRpcSubmitTransactionRequest::default()),
        FuzzTarget::ByteArray(inbound_rpc_protocol::RpcInboundRequest::default()),
        FuzzTarget::ByteArray(network_noise_initiator::NetworkNoiseInitiator::default()),
        FuzzTarget::ByteArray(network_noise_responder::NetworkNoiseResponder::default()),

        // structured-data targets
        FuzzTarget::StructuredData(storage_save_blocks::NetworkNoiseResponder::default()),
    ];

    // we use a B tree to sort the map by keys
    targets
        .into_iter()
        .map(|target| (target.name(), target))
        .collect()
});