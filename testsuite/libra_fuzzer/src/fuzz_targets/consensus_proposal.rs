#![feature(async_await)]

use crate::FuzzTargetImpl;
use config::config::ConsensusProposerType::FixedProposer;
use consensus::chained_bft::{
    chained_bft_smr_test::{fuzzing_corpus, FuzzingWhat},
    consensus_types::proposal_msg::ProposalMsg,
    event_processor::ProcessProposalResult,
    event_processor_test::fuzz_proposal,
    test_utils::{consensus_runtime, EmptyStateComputer, MockStorage, TestPayload},
    EventProcessor,
};
use futures::executor::block_on;
use lazy_static::lazy_static;
use network::proto::ConsensusMsg;
use proptest_helpers::ValueGenerator;
use proto_conv::FromProto;
use protobuf::Message as proto;
use tokio::runtime;
use types::{validator_signer::ValidatorSigner, validator_verifier::ValidatorVerifier};

#[derive(Clone, Debug, Default)]
pub struct ConsensusProposal;

impl FuzzTargetImpl for ConsensusProposal {
    fn name(&self) -> &'static str {
        module_name!()
    }

    fn description(&self) -> &'static str {
        "Consensus proposal messages"
    }

    fn generate(&self, _gen: &mut ValueGenerator) -> Vec<u8> {
        fuzzing_corpus(FuzzingWhat::Proposal)
    }

    fn fuzz(&self, data: &[u8]) {
        fuzz_proposal(data);
    }
}

//
// Fuzzer
// ======
// * should I put this behind a (public) module?
// * it should run
// * it should be callable from testsuite
// * generation of corpus should be callable from testsuite as well

#[cfg(any(test, fuzzing))]
lazy_static! {
    static ref STATIC_RUNTIME: runtime::Runtime = Runtime::new().unwrap();
    static ref FUZZING_SIGNER: ValidatorSigner = ValidatorSigner::random(None);
}

#[cfg(any(test, fuzzing))]
fn create_node_for_fuzzing() -> EventProcessor<TestPayload> {
    // GOOD
    let signer = FUZZING_SIGNER.clone();
    let mut peers = vec![];
    peers.push(signer.author());
    let proposer_author = peers[0];
    let peers = std::sync::Arc::new(peers);

    // I PROBABLY DONT NEED THIS
    let validator = ValidatorVerifier::new_single(signer.author(), signer.public_key());

    //? ?
    let epoch_mgr = Arc::new(EpochManager::new(0, validator));

    // I NEED EMPTYSTORAGE HERE?
    let (storage, initial_data) = MockStorage::<TestPayload>::start_for_fuzzing();

    let consensus_state = initial_data.state();
    let safety_rules = SafetyRules::new(consensus_state);

    // SOME CHANNELS ARE USELESS
    let (network_reqs_tx, network_reqs_rx) = channel::new_test(8);
    let (consensus_tx, consensus_rx) = channel::new_test(8);
    let network_sender = ConsensusNetworkSender::new(network_reqs_tx);
    let network_events = ConsensusNetworkEvents::new(consensus_rx);
    let author = signer.author();

    // I DONT CARE ABOUT NETWORK! NEED TO CREATE A FAKE ONE
    let network = ConsensusNetworkImpl::new(
        signer.author(),
        network_sender,
        network_events,
        Arc::clone(&epoch_mgr),
    );

    let block_store = NodeSetup::build_empty_store(signer.clone(), storage.clone(), initial_data);
    let time_service = Arc::new(ClockTimeService::new(STATIC_RUNTIME.executor().clone()));
    let proposal_generator = ProposalGenerator::new(
        block_store.clone(),
        Arc::new(MockTransactionManager::new()),
        time_service.clone(),
        1,
        true,
    );

    let pacemaker = NodeSetup::create_pacemaker(time_service.clone());

    let proposer_election = NodeSetup::create_proposer_election(proposer_author);
    let (commit_cb_sender, _commit_cb_receiver) = mpsc::unbounded::<LedgerInfoWithSignatures>();

    // empty state computer!
    let empty_state_computer = Arc::new(EmptyStateComputer);

    // event processor
    let mut event_processor = EventProcessor::new(
        author,
        Arc::clone(&block_store),
        pacemaker,
        proposer_election,
        proposal_generator,
        safety_rules,
        empty_state_computer,
        Arc::new(MockTransactionManager::new()),
        network,
        storage.clone(),
        time_service,
        true,
        Arc::clone(&epoch_mgr),
    );
    block_on(event_processor.start());
    event_processor
}

#[cfg(any(test, fuzzing))]
pub fn fuzz_proposal(data: &[u8]) {
    // create node
    let event_processor = create_node_for_fuzzing();

    // proto parse
    let mut msg: ConsensusMsg = match protobuf::parse_from_bytes(data) {
        Ok(xx) => xx,
        Err(_) => {
            if cfg!(test) {
                println!("1");
                assert!(false);
            }
            return;
        }
    };

    // extract proposal
    let proposal = match msg.has_proposal() {
        true => match ProposalMsg::<TestPayload>::from_proto(msg.take_proposal()) {
            Ok(xx) => xx,
            Err(_) => {
                if cfg!(test) {
                    println!("2");
                    assert!(false);
                }
                return;
            }
        },
        false => {
            if cfg!(test) {
                println!("3");
                assert!(false);
            }
            return;
        }
    };

    block_on(async move {
        // process proposal (event_process)
        event_processor.process_proposal_msg(proposal).await;
    });
}

#[test]
fn test_consensus_proposal_fuzzer() {
    let proposal = fuzzing_corpus(FuzzingWhat::Proposal);
    fuzz_proposal(&proposal);
}
