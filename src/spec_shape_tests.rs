// These lock wire SEMANTICS that a field-name comparison cannot express. `spec_contract_tests`
// above proves the field NAMES match the spec; these prove the meanings do — that a null
// `allowed_pools` is all-pools rather than none, that the once-shown credential is the signed
// `token` and not the 1.4.x `secret`, that an all-defaults `CreateKeyReq` serializes to exactly
// `{name}` against a server that rejects unknown fields. A rebase reintroducing a 1.4.x field,
// or flipping `allowed_pools` back to a non-Option Vec, compiles clean and ships without these.
use super::*;

#[test]
fn key_view_allowed_pools_null_is_all_pools() {
    // null (or omitted) allowed_pools => None => "all pools". A regression to `Vec<String>`
    // would fail to deserialize null, or silently decode it as an empty (== NO pools) list.
    let k: KeyView = serde_json::from_str(
        r#"{"id":"vk_1","name":"n","allowed_pools":null,"state":"active","enabled":true}"#,
    )
    .expect("null allowed_pools must decode");
    assert_eq!(
        k.allowed_pools, None,
        "null must mean all-pools (None), not []"
    );
}

#[test]
fn key_view_allowed_pools_empty_is_no_pools() {
    let k: KeyView =
        serde_json::from_str(r#"{"id":"vk_1","name":"n","allowed_pools":[]}"#).unwrap();
    assert_eq!(
        k.allowed_pools,
        Some(Vec::new()),
        "explicit [] must stay a distinct empty list (NO pools), never collapse to None"
    );
}

#[test]
fn created_key_view_carries_signed_token_not_secret() {
    // 1.5.0 credential is `token` (+ expires_at), NOT the 1.4.x `secret`. A revert to a
    // required `secret` field would fail to decode this real-shaped response.
    let c: CreatedKeyView = serde_json::from_str(
        r#"{"id":"vk_1","name":"n","token":"bbk_abc","expires_at":1785772871,"state":"active"}"#,
    )
    .expect("token-shaped CreatedKeyView must decode");
    assert_eq!(c.token.expose(), "bbk_abc");
    assert_eq!(c.expires_at, 1785772871_u64);
}

#[test]
fn create_key_req_omits_none_fields_and_never_sends_legacy_budget() {
    // deny_unknown_fields on the server rejects any stray field. This pins the exact minimal
    // body and fails if a 1.4.x budget/rpm/tpm field is ever reintroduced onto the struct.
    let req = CreateKeyReq {
        name: "svc".into(),
        allowed_pools: None,
        group: None,
        parent: None,
        expires_in: None,
        expires_at: None,
        labels: Default::default(),
        issue_aws_credential: false,
    };
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.keys().collect::<Vec<_>>(),
        vec!["name"],
        "an all-defaults CreateKeyReq must serialize to exactly {{name}} — any extra key is \
         either a leaked None or a reintroduced legacy field the server will 400 on"
    );
    for banned in [
        "budget",
        "budget_period",
        "rpm_limit",
        "tpm_limit",
        "max_budget_cents",
    ] {
        assert!(
            !obj.contains_key(banned),
            "legacy field {banned} must never serialize"
        );
    }
}

#[test]
fn create_key_req_empty_allowed_pools_serializes_as_empty_array() {
    // The --no-pools path sets Some(vec![]); it must reach the wire as `[]`, not be dropped.
    let req = CreateKeyReq {
        name: "svc".into(),
        allowed_pools: Some(Vec::new()),
        group: None,
        parent: None,
        expires_in: None,
        expires_at: None,
        labels: Default::default(),
        issue_aws_credential: false,
    };
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert_eq!(v["allowed_pools"], serde_json::json!([]));
}

#[test]
fn rotated_key_view_token_and_secret_are_both_optional() {
    // The doc invariant is "exactly one of token or secret"; the type models both as optional
    // so a token-only rotate decodes without a phantom `secret`.
    let r: RotatedKeyView =
        serde_json::from_str(r#"{"id":"vk_1","name":"n","token":"bbk_new"}"#).unwrap();
    assert_eq!(r.token.as_ref().map(Secret::expose), Some("bbk_new"));
    assert_eq!(r.secret, None);
}

#[test]
fn inspect_view_carries_manifest_preview_shape() {
    // 1.5.2 added POST /plugins/inspect — a stateless preview whose body is the PluginSchemaView
    // shape plus version/kind. This pins the fields busbar-admin renders so a future spec resync
    // that drops/renames one (e.g. `trust`, `schema_error`, or the new `version`) fails loudly.
    let v: InspectView = serde_json::from_str(
        r#"{"name":"acme-store","version":"1.2.3","kind":"store","trust":"unverified",
            "source":"manifest","restart_required_default":true,
            "schema":{"type":"object"},"schema_error":null}"#,
    )
    .expect("inspect preview must decode");
    assert_eq!(v.name, "acme-store");
    assert_eq!(v.version.as_deref(), Some("1.2.3"));
    assert_eq!(v.kind.as_deref(), Some("store"));
    assert_eq!(v.trust, "unverified");
    assert_eq!(v.restart_required_default, Some(true));
    assert!(v.schema.is_some());
    assert_eq!(v.schema_error, None);
}

#[test]
fn inspect_view_tolerates_null_kind_and_absent_version() {
    // An unresolvable candidate reports kind/version/restart_required_default as null; the CLI
    // must still decode (never refuse) so it can render the `trust`/`schema_error` verdict.
    let v: InspectView = serde_json::from_str(
        r#"{"name":"bad","kind":null,"trust":"rejected","source":"manifest","schema":null,
            "schema_error":"settings_schema is not valid JSON"}"#,
    )
    .expect("a rejected/unresolvable candidate must still decode");
    assert_eq!(v.kind, None);
    assert_eq!(v.version, None);
    assert_eq!(v.trust, "rejected");
    assert_eq!(
        v.schema_error.as_deref(),
        Some("settings_schema is not valid JSON")
    );
}

#[test]
fn info_view_preserves_process_identity_and_reads_older_servers() {
    let base = serde_json::json!({
        "version": "1.6.0", "build": {},
        "topology": {"pools": 0, "models": 0, "providers": 0}
    });
    let old: InfoView = serde_json::from_value(base.clone()).expect("older info still decodes");
    assert_eq!(old.process_boot_nonce, None);
    let mut current = base;
    let nonce = "0123456789abcdef0123456789abcdef";
    current["process_boot_nonce"] = serde_json::json!(nonce);
    let view: InfoView = serde_json::from_value(current).expect("process identity decodes");
    assert_eq!(view.process_boot_nonce.as_deref(), Some(nonce));
    assert_eq!(
        serde_json::to_value(view).unwrap()["process_boot_nonce"],
        nonce
    );
}

#[test]
fn plugin_readback_preserves_archive_identity_without_inventing_it() {
    let digest = "a".repeat(64);
    let plugin: PluginView = serde_json::from_value(serde_json::json!({
        "name": "p", "type": "hook", "loader": "plugin", "archive_sha256": digest
    }))
    .unwrap();
    assert_eq!(plugin.archive_sha256.as_deref(), Some(digest.as_str()));
    assert_eq!(
        serde_json::to_value(plugin).unwrap()["archive_sha256"],
        digest
    );
    let old: PluginView =
        serde_json::from_str(r#"{"name":"p","type":"hook","loader":"plugin"}"#).unwrap();
    assert!(serde_json::to_value(old)
        .unwrap()
        .get("archive_sha256")
        .is_none());
    let inspected: InspectView = serde_json::from_value(serde_json::json!({
        "name": "p", "trust": "trusted", "source": "installed_archive",
        "file": "p.tar.gz", "archive_sha256": digest, "schema_state": "absent",
        "schema": null, "schema_error": null
    }))
    .unwrap();
    let wire = serde_json::to_value(inspected).unwrap();
    assert_eq!(wire["file"], "p.tar.gz");
    assert_eq!(wire["archive_sha256"], digest);
    assert_eq!(wire["schema_state"], "absent");
}
