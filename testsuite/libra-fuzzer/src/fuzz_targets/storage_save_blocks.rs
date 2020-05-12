// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::FuzzStructuredData;
use libra_json_rpc::fuzzing::{fuzzer, generate_corpus};
use libra_proptest_helpers::ValueGenerator;

#[derive(Clone, Debug, Default)]
pub struct StorageSaveBlocks;

impl FuzzStructuredData for StorageSaveBlocks {
  fn name(&self) -> &'static str {
    module_name!()
  }

  fn description(&self) -> &'static str {
    "JSON RPC submit transaction request"
  }

  fn fuzz(&self, data: &[u8]) {
    fuzzer(data);
  }
}
