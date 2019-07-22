#![feature(async_await)]

//#[macro_use]
//extern crate afl;

use consensus::chained_bft::{
    common::Author,
    event_processor::ProcessProposalResult,
    event_processor_test::NodeSetup,
    liveness::{
        pacemaker::{NewRoundEvent, NewRoundReason},
        proposer_election::ProposalInfo,
    },
    network_tests::NetworkPlayground,
    test_utils::{consensus_runtime, TestPayload},
};
use futures::{executor::block_on};
use network::proto::ConsensusMsg;
use proto_conv::FromProto;
use protobuf::Message as proto;
use std::{
    fs::File,
    fs,
    io::prelude::*,
    time::Duration,
};
use types::validator_verifier::ValidatorVerifier;

#[allow(dead_code)]
fn create_corpus() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.executor());
    let nodes = NodeSetup::create_nodes(&mut playground, runtime.executor(), 2, true);
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

fn main() {
    fuzz_artifacts();
}

fn fuzz_single_file() {
    // fuzz input
    let mut buf = [0; 1000];
    let mut f =
        File::open("/Users/davidwg/libra_internal/libra/consensus/fuzz/corpus/proposal.bin").unwrap();
    let n = f.read(&mut buf[..]).unwrap();
    fuzz(&buf[..n])
}

fn fuzz_corpus() {

    let paths = fs::read_dir("/Users/davidwg/libra_internal/libra/consensus/fuzz/corpus/").unwrap();

    for path in paths {
        // fuzz input
        let mut buf = [0; 1000];
        let mut f = File::open(path.unwrap().path()).unwrap();
        let n = f.read(&mut buf[..]).unwrap();
        fuzz(&buf[..n])
    }
}

fn fuzz_artifacts() {
    let paths = fs::read_dir("/Users/davidwg/libra_internal/libra/consensus/fuzz/artifacts/fuzz_consensus_proposal/").unwrap();

    for path in paths {
        // fuzz input
        let mut buf = [0; 1000];
        let mut f = File::open(path.unwrap().path()).unwrap();
        let n = f.read(&mut buf[..]).unwrap();
        fuzz(&buf[..n])
    }
}

fn fuzz(data: &[u8]) {
    // setup non-proposer node
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.executor());
    let mut node = NodeSetup::create_nodes(&mut playground, runtime.executor(), 1, false)
        .pop()
        .unwrap();

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
        match node.event_processor.process_proposal(proposal.clone()).await {
            ProcessProposalResult::Done(true) => (),
            _ => return,
        };

        // process winning proposal (event_process)
        node.event_processor.process_winning_proposal(proposal).await;
    });
}
