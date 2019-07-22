#![no_main]
#![feature(async_await)]
#[macro_use]
extern crate libfuzzer_sys;
extern crate consensus;

use consensus::chained_bft::{
    common::Author,
    consensus_types::proposal_info::ProposalInfo,
    event_processor::ProcessProposalResult,
    event_processor_test::NodeSetup,
    test_utils::{consensus_runtime, TestPayload},
};
use futures::executor::block_on;
use lazy_static::lazy_static;
use network::proto::ConsensusMsg;
use proto_conv::FromProto;
use protobuf::Message as proto;
use tokio::runtime;
use types::validator_verifier::ValidatorVerifier;

lazy_static! {
    static ref STATIC_RUNTIME: runtime::Runtime = consensus_runtime();
}

fuzz_target!(|data: &[u8]| {
    //
    let node = NodeSetup::create_node_fuzzing(STATIC_RUNTIME.executor());

    // proto parse
    let mut msg: ConsensusMsg = match protobuf::parse_from_bytes(data) {
        Ok(xx) => xx,
        Err(_) => {
            // println!("{:?}", x);
            return;
        }
    };

    // extract proposal
    let proposal = match msg.has_proposal() {
        true => match ProposalInfo::<TestPayload, Author>::from_proto(msg.take_proposal()) {
            Ok(xx) => xx,
            Err(_) => return,
        },
        false => return,
    };

    // process proposal (network.rs)
    let validator = ValidatorVerifier::new_empty();
    match proposal.verify(&validator) {
        Err(_) => {
            // println!("{:?}", x);
            return;
        }
        _ => (),
    }

    block_on(async move {
        // process proposal (event_process)
        match node
            .event_processor
            .process_proposal(proposal.clone())
            .await
        {
            ProcessProposalResult::Done(true) => (),
            _ => return,
        };

        // process winning proposal (event_process)
        node.event_processor
            .process_winning_proposal(proposal)
            .await;
    });
});
