#![no_main]
#![feature(async_await)]
#[macro_use]
extern crate libfuzzer_sys;
extern crate consensus;

use consensus::chained_bft::{
    common::Author,
    event_processor::ProcessProposalResult,
    event_processor_test::NodeSetup,
    liveness::{
        pacemaker::{NewRoundEvent, NewRoundReason},
        proposer_election::ProposalInfo,
        rotating_proposer_election::winning_received_for_fuzzing,
    },
    network_tests::NetworkPlayground,
    test_utils::{consensus_runtime, TestPayload},
};
use futures::{executor::block_on, stream::StreamExt};
use network::proto::ConsensusMsg;
use proto_conv::FromProto;
use protobuf::Message as proto;
use std::{
    fs::File,
    io::prelude::*,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use types::validator_verifier::ValidatorVerifier;

#[allow(dead_code)]
fn create_corpus() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.executor());
    let nodes = NodeSetup::create_nodes(&mut playground, runtime.executor(), 2);
    let node = &nodes[0];

    block_on(async move {
        node.event_processor
            .process_new_round_event(NewRoundEvent {
                round: 1,
                reason: NewRoundReason::QCReady,
                timeout: Duration::new(5, 0),
            })
            .await;
        let mut proposals = playground
            .wait_for_messages(1, NetworkPlayground::proposals_only)
            .await;
        let proposal = proposals.pop().unwrap();
        // save it to a file
        let dir = env!("CARGO_MANIFEST_DIR");
        let path = format!("{}/corpus/proposal.bin", dir);
        println!("saving file at {}", path);
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(&proposal.1.write_to_bytes().unwrap())
            .unwrap();
    });
}

fuzz_target!(|data: &[u8]| {
    // setup non-proposer node
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.executor());
    let mut node = NodeSetup::create_nodes(&mut playground, runtime.executor(), 1)
        .pop()
        .unwrap();

    // proto parse
    let mut msg: ConsensusMsg = match protobuf::parse_from_bytes(&data) {
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
        // dumb channel set to false
        winning_received_for_fuzzing.store(false, Ordering::Relaxed);

        // process proposal (event_process)
        match node.event_processor.process_proposal(proposal).await {
            ProcessProposalResult::Done => (),
            _ => return,
        };

        // only continue if dumb channel is true, and set it to false
        match winning_received_for_fuzzing.compare_exchange(
            true,
            false,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(true) => (),
            _ => return,
        };

        // process winning proposal (event_process)
        let winning = match node.winning_proposals_receiver.next().await {
            Some(xx) => xx,
            _ => return,
        };
        node.event_processor.process_winning_proposal(winning).await;
    });
});
