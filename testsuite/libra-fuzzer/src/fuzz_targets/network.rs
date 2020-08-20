// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{corpus_from_strategy, fuzz_data_to_value, FuzzTargetImpl};
use libra_proptest_helpers::ValueGenerator;

//
// Noise wrapper
//

use network::noise::fuzzing::{
    fuzz_initiator, fuzz_post_handshake, fuzz_responder, generate_corpus,
};

#[derive(Clone, Debug, Default)]
pub struct NetworkNoiseInitiator;
impl FuzzTargetImpl for NetworkNoiseInitiator {
    fn description(&self) -> &'static str {
        "Network Noise crate initiator side"
    }

    fn generate(&self, _idx: usize, gen: &mut ValueGenerator) -> Option<Vec<u8>> {
        Some(generate_corpus(gen))
    }

    fn fuzz(&self, data: &[u8]) {
        fuzz_initiator(data);
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetworkNoiseResponder;
impl FuzzTargetImpl for NetworkNoiseResponder {
    fn description(&self) -> &'static str {
        "Network Noise crate responder side"
    }

    fn generate(&self, _idx: usize, gen: &mut ValueGenerator) -> Option<Vec<u8>> {
        Some(generate_corpus(gen))
    }

    fn fuzz(&self, data: &[u8]) {
        fuzz_responder(data);
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetworkNoiseStream;
impl FuzzTargetImpl for NetworkNoiseStream {
    fn description(&self) -> &'static str {
        "Network Noise crate stream"
    }

    fn generate(&self, _idx: usize, gen: &mut ValueGenerator) -> Option<Vec<u8>> {
        Some(generate_corpus(gen))
    }

    fn fuzz(&self, data: &[u8]) {
        fuzz_post_handshake(data);
    }
}

//
// RPC protocol
//

use network::protocols::rpc;

#[derive(Clone, Debug, Default)]
pub struct RpcInboundRequest;
impl FuzzTargetImpl for RpcInboundRequest {
    fn description(&self) -> &'static str {
        "P2P Network Inbound RPC Request"
    }

    fn generate(&self, _idx: usize, gen: &mut ValueGenerator) -> Option<Vec<u8>> {
        Some(rpc::fuzzing::generate_corpus(gen))
    }

    fn fuzz(&self, data: &[u8]) {
        rpc::fuzzing::fuzzer(data);
    }
}

//
// Handshake protocol
//

use network::fuzzing::{
    build_perform_handshake_input, fuzz_network_handshake_protocol_negotiation,
};

#[derive(Clone, Debug, Default)]
pub struct NetworkHandshakeProtocol;
impl FuzzTargetImpl for NetworkHandshakeProtocol {
    fn description(&self) -> &'static str {
        "network handshake protocol"
    }

    fn generate(&self, _idx: usize, _gen: &mut ValueGenerator) -> Option<Vec<u8>> {
        Some(corpus_from_strategy(build_perform_handshake_input()))
    }

    fn fuzz(&self, data: &[u8]) {
        let (own_handshake, their_handshake) =
            fuzz_data_to_value(data, build_perform_handshake_input());
        fuzz_network_handshake_protocol_negotiation(&own_handshake, their_handshake);
    }
}
