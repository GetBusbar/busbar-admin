// SPDX-License-Identifier: Apache-2.0

//! Pure CLI-argument mappings shared by the binary and its tests.
//!
//! These carry contract meaning (the tri-state `allowed_pools`, the first-`=`-wins label split),
//! so they live in the library rather than in `main.rs`: a test that imports the REAL function
//! catches a regression, a test against a copy of it cannot.

use anyhow::Result;

/// Resolve the three distinct `allowed_pools` states the server understands: omitted (`None`) =
/// ALL pools; an explicit empty list (`--no-pools`) = NO pools; a non-empty list = exactly those.
/// A shared function so `cmd_keys_create` and its test exercise the SAME mapping. Collapsing
/// `--no-pools` into `None` would mint an all-pools key when no-pools was asked for (fail-open on
/// privilege).
pub fn resolve_allowed_pools(no_pools: bool, pools: &[String]) -> Option<Vec<String>> {
    if no_pools {
        Some(Vec::new())
    } else if pools.is_empty() {
        None
    } else {
        Some(pools.to_vec())
    }
}

/// Parse repeated `--label KEY=VALUE` arguments into the map the mint body carries. The split is
/// on the FIRST `=` only, so a value that itself contains `=` (a URL query string, base64 padding)
/// survives intact.
pub fn parse_labels(pairs: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow::anyhow!("--label must be KEY=VALUE, got {p:?}"))
        })
        .collect()
}
