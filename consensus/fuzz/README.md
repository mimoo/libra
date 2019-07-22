problems:

* does cargo fuzz compiles with ASAN? https://github.com/japaric/rust-san
* running nothing exec/s: 26214
* I have this msg from libfuzzer: 

> INFO: libFuzzer disabled leak detection after every mutation.
      Most likely the target function accumulates allocated
      memory in a global state w/o actually leaking it.
      You may try running this binary with -trace_malloc=[12]      to get a trace of mallocs and frees.
      If LeakSanitizer is enabled in this process it will still
      run on the process shutdown.

* and this one as well:

> WARNING: The binary has too many instrumented PCs.
         You may want to reduce the size of the binary
         for more efficient fuzzing and precise coverage data

* cargo fuzz run fuzz_consensus_vote -- fuzz/corpus/vote
* cargo fuzz run fuzz_consensus_proposal -- fuzz/corpus/proposal
* cargo fuzz run fuzz_consensus_timeout -- fuzz/corpus/timeout


TODO: 

* create corpus for timeout_msg and vote_msg
* create different state before fuzzing

mkdir NEW_CORPUS_DIR  # Store minimized corpus here.
./my_fuzzer -merge=1 NEW_CORPUS_DIR FULL_CORPUS_DIR

