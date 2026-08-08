// SPDX-License-Identifier: Apache-2.0

//! Pure CLI-argument mapping tests. These call the REAL functions `cmd_keys_create` uses (via
//! `busbar_admin::argmap`), not a copy, so a regression in the actual mapping fails here.

use busbar_admin::argmap::{parse_labels, resolve_allowed_pools};

#[test]
fn parse_labels_splits_on_first_equals_only() {
    // A value containing '=' (a URL query string, base64 padding) must survive intact: the split
    // is on the FIRST '=', not all of them.
    let m = parse_labels(&["url=http://x?a=b".into(), "team=platform".into()]).unwrap();
    assert_eq!(m.get("url").map(String::as_str), Some("http://x?a=b"));
    assert_eq!(m.get("team").map(String::as_str), Some("platform"));
}

#[test]
fn parse_labels_rejects_a_pair_with_no_equals() {
    assert!(parse_labels(&["novalue".into()]).is_err());
}

#[test]
fn parse_labels_allows_empty_value() {
    let m = parse_labels(&["k=".into()]).unwrap();
    assert_eq!(m.get("k").map(String::as_str), Some(""));
}

#[test]
fn allowed_pools_tristate_no_pools_is_empty_not_none() {
    assert_eq!(
        resolve_allowed_pools(true, &[]),
        Some(Vec::new()),
        "--no-pools => NO pools"
    );
    assert_eq!(
        resolve_allowed_pools(false, &[]),
        None,
        "omitted => ALL pools"
    );
    assert_eq!(
        resolve_allowed_pools(false, &["p1".into()]),
        Some(vec!["p1".into()]),
        "a list => exactly those pools"
    );
}
