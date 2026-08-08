// SPDX-License-Identifier: Apache-2.0

//! Cross-repo SHAPE conformance: every serde type in `busbar_admin::client` checked against the
//! REAL committed `openapi.json` at the repo root.
//!
//! Why this file exists. busbar-admin is a hand-rolled client for another repo's API, so its
//! structs are a mirror of wire shapes that live somewhere else. The `spec-drift` CI job compares
//! `jq -r .info.version openapi.json` against the latest busbar release tag: a VERSION STRING. It
//! says nothing about whether `src/client.rs` still matches the schemas inside that document, and
//! it degrades to a warning when the GitHub API is unreachable. So a struct could drift arbitrarily
//! from the spec sitting in the same commit and every gate stayed green.
//!
//! What is asserted, per mapped type:
//!   1. Rust field set (the WIRE keys, taken from a real serialize) vs the schema's `properties`.
//!      A Rust field with no schema property fails. A schema property with no Rust field fails
//!      unless it is listed in that case's `unmodelled` allowlist, which is itself checked for
//!      staleness. Adding a property to the schema therefore fails this suite until someone
//!      either models it or consciously records the omission.
//!   2. Optionality. A property the schema marks required and NOT nullable must reject an explicit
//!      `null`, which is only true if the Rust field is not an `Option`. A property the schema
//!      marks nullable must ACCEPT `null`, which is only true if it is an `Option`. The two
//!      directions together pin every field's optionality to the document.
//!   3. Round-trip. A schema-shaped value is deserialized, re-serialized, and both the wire keys
//!      and the per-property values are compared.
//!   4. Endpoint wiring: every path the client calls exists in `paths` with that method, and its
//!      success response points at the schema the corresponding client method decodes into.
//!
//! The spec is loaded with `include_str!` from the actual committed file, not a copy, so there is
//! nothing to keep in sync by hand.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};

use busbar_admin::client::{
    BuildInfo, ConfigApplyView, CreateKeyReq, CreatedKeyView, ErrorEnvelope, HookPage,
    HookTransportView, HookView, InfoView, InspectPluginReq, InspectView, InstallPluginReq,
    KeyPage, KeyView, PluginInstallView, PluginPage, PluginReloadView, PluginView, RevokeView,
    RotatedKeyView, TopologyInfo,
};

/// The ACTUAL committed spec, compiled into the test binary. `include_str!` is relative to this
/// source file, so this is `<repo root>/openapi.json` and cannot silently become a stale copy.
const OPENAPI_JSON: &str = include_str!("../openapi.json");

fn spec() -> &'static Value {
    static SPEC: OnceLock<Value> = OnceLock::new();
    SPEC.get_or_init(|| {
        serde_json::from_str(OPENAPI_JSON).expect("openapi.json must be valid JSON")
    })
}

fn schema(name: &str) -> &'static Value {
    spec()
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.get(name))
        .unwrap_or_else(|| {
            panic!("openapi.json has no components.schemas.{name}: the spec was resynced and this schema was renamed or removed")
        })
}

fn properties(sch: &'static Value) -> &'static Map<String, Value> {
    sch.get("properties")
        .and_then(Value::as_object)
        .expect("schema must carry properties")
}

fn required_of(sch: &Value) -> BTreeSet<String> {
    sch.get("required")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Is this property allowed to carry `null` on the wire? A `$ref` to another object schema is
/// not. A `type` array containing `"null"` is. A property with NO `type` at all (the spec emits
/// that for a free-form JSON value, e.g. `PluginSchemaView.schema`) can be anything, null
/// included.
fn nullable(prop: &Value) -> bool {
    if prop.get("$ref").is_some() {
        return false;
    }
    match prop.get("type") {
        None => true,
        Some(Value::String(_)) => false,
        Some(Value::Array(types)) => types.iter().any(|t| t == "null"),
        Some(other) => panic!("unexpected `type` encoding in the spec: {other}"),
    }
}

fn keys_of(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .expect("expected a JSON object")
        .keys()
        .cloned()
        .collect()
}

/// One response type under test: the schema it mirrors, a fully schema-shaped sample payload, and
/// the schema properties the Rust type deliberately does not carry.
struct Case<'a> {
    /// `components.schemas` entry name.
    schema: &'a str,
    /// A value shaped per that schema, carrying every property the Rust type models.
    sample: Value,
    /// Schema properties the client knowingly does not model (the contract is additive-only and
    /// the CLI renders a subset). Every entry must still be a real property that is still absent
    /// from the Rust type, so this list cannot rot into a blanket excuse.
    unmodelled: &'a [&'a str],
}

/// Run every check for a response type the client DESERIALIZES.
fn check_response<T: DeserializeOwned + Serialize>(case: Case<'_>) {
    let sch = schema(case.schema);
    let props = properties(sch);
    let required = required_of(sch);
    let schema_props: BTreeSet<String> = props.keys().cloned().collect();

    // The Rust field set, taken from a real serialize of a real deserialize: these are the WIRE
    // keys, so a `#[serde(rename)]` is honoured and a renamed Rust field shows up here.
    let decoded: T = serde_json::from_value(case.sample.clone()).unwrap_or_else(|e| {
        panic!(
            "{}: a schema-shaped payload must deserialize into the Rust type, got: {e}",
            case.schema
        )
    });
    let round = serde_json::to_value(&decoded).expect("re-serializing must succeed");
    let rust_keys = keys_of(&round);

    // 1a. A Rust field with no schema property: the client is inventing wire keys.
    let invented: Vec<_> = rust_keys.difference(&schema_props).collect();
    assert!(
        invented.is_empty(),
        "{}: Rust field(s) {invented:?} have no property in the committed openapi.json schema \
         (renamed field, or a field the spec never had)",
        case.schema
    );

    // 1b. Allowlist hygiene: a name listed as unmodelled must still be a real schema property,
    // and must still be genuinely absent from the Rust type.
    for u in case.unmodelled {
        assert!(
            schema_props.contains(*u),
            "{}: `{u}` is on the unmodelled allowlist but is no longer a property of the schema; \
             drop the stale entry",
            case.schema
        );
        assert!(
            !rust_keys.contains(*u),
            "{}: `{u}` is on the unmodelled allowlist but the Rust type DOES carry it; drop the \
             entry so the field is checked like every other",
            case.schema
        );
    }

    // 1c. A schema property with no Rust field. This is the check that fires when busbar adds a
    // property: modelling it or recording it in `unmodelled` is then a deliberate act.
    let allow: BTreeSet<String> = case.unmodelled.iter().map(|s| (*s).to_string()).collect();
    let unread: Vec<_> = schema_props
        .difference(&rust_keys)
        .filter(|p| !allow.contains(*p))
        .collect();
    assert!(
        unread.is_empty(),
        "{}: schema propert(ies) {unread:?} have no Rust field. The client reads this response, \
         so either model them or add them to this case's `unmodelled` list with a reason",
        case.schema
    );

    // 2. Optionality, driven off `required` + nullability, proven by behaviour: an `Option` field
    // accepts an explicit null and a non-`Option` field rejects it.
    for (name, prop) in props {
        if allow.contains(name) {
            continue;
        }
        let mut nulled = case.sample.as_object().cloned().expect("object sample");
        nulled.insert(name.clone(), Value::Null);
        let attempt = serde_json::from_value::<T>(Value::Object(nulled));
        if nullable(prop) {
            assert!(
                attempt.is_ok(),
                "{}.{name}: the schema types this property as nullable, so the Rust field must be \
                 an Option and accept an explicit null, but decoding failed: {:?}",
                case.schema,
                attempt.err()
            );
        } else if required.contains(name) {
            assert!(
                attempt.is_err(),
                "{}.{name}: the schema marks this property REQUIRED and non-nullable, but the \
                 Rust type accepted an explicit null, which means the field is an Option (or \
                 otherwise nullable). A required non-nullable property must be a plain field",
                case.schema
            );
        }
    }

    // 3. Round-trip: every modelled property survives decode + encode with its value intact.
    for (name, value) in case.sample.as_object().expect("object sample") {
        if allow.contains(name) || !schema_props.contains(name) {
            continue;
        }
        assert_eq!(
            round.get(name),
            Some(value),
            "{}.{name}: value did not survive the deserialize/serialize round trip",
            case.schema
        );
    }
}

/// Run the field-set checks for a request type the client only SERIALIZES.
///
/// `full` is a fully populated instance (every optional set) so the complete Rust field set shows
/// up on the wire; `minimal` is an all-defaults instance, which must still emit every property the
/// schema marks required.
fn check_request(schema_name: &str, full: &Value, minimal: &Value, unmodelled: &[&str]) {
    let sch = schema(schema_name);
    let props = properties(sch);
    let required = required_of(sch);
    let schema_props: BTreeSet<String> = props.keys().cloned().collect();
    let rust_keys = keys_of(full);

    let invented: Vec<_> = rust_keys.difference(&schema_props).collect();
    assert!(
        invented.is_empty(),
        "{schema_name}: request field(s) {invented:?} are not properties of the committed schema. \
         The server sets `deny_unknown_fields` on its request bodies, so sending one is a 400"
    );

    let allow: BTreeSet<String> = unmodelled.iter().map(|s| (*s).to_string()).collect();
    for u in unmodelled {
        assert!(
            schema_props.contains(*u),
            "{schema_name}: stale `unmodelled` entry `{u}` is no longer a schema property"
        );
        assert!(
            !rust_keys.contains(*u),
            "{schema_name}: `{u}` is listed as unmodelled but the Rust type carries it"
        );
    }
    let missing: Vec<_> = schema_props
        .difference(&rust_keys)
        .filter(|p| !allow.contains(*p))
        .collect();
    assert!(
        missing.is_empty(),
        "{schema_name}: schema propert(ies) {missing:?} cannot be sent by this client. A new \
         request property means a capability the CLI silently cannot use"
    );

    let minimal_keys = keys_of(minimal);
    for req in &required {
        assert!(
            minimal_keys.contains(req),
            "{schema_name}: `{req}` is required by the schema but an all-defaults instance does \
             not serialize it (a `skip_serializing_if` on a required field is a guaranteed 400)"
        );
    }
}

// Sample fragments reused across cases.

fn key_meta_sample() -> Map<String, Value> {
    json!({
        "id": "vk_0123456789abcdef",
        "name": "svc-checkout",
        "allowed_pools": ["fast", "cheap"],
        "group": "team:payments",
        "labels": {"team": "payments"},
        "state": "active",
        "enabled": true,
        "created_at": 1785772871_u64
    })
    .as_object()
    .cloned()
    .unwrap()
}

/// Properties `PluginView` carries in the spec but not in Rust. Named once here so the case
/// declaration and the sample-reduction helper below cannot disagree.
const PLUGIN_VIEW_UNMODELLED: &[&str] = &[
    // The manifest NAME of a dynamic-library plugin. The CLI renders `file`, which is the handle
    // the sibling endpoints key off; `target` adds nothing to any rendered row.
    "target",
    // The store C-ABI number: an engine-internal compatibility detail with no CLI column.
    "interface_version",
    // A relative URL the CLI never follows: it prints `has_schema` (which mirrors
    // `schema_url.is_some()`) instead of fetching a per-row schema.
    "schema_url",
    // The list-row copy of the inspect verdict. `busbar-admin plugins inspect` surfaces it from
    // PluginSchemaView, where the CLI actually renders it.
    "schema_error",
];

/// A `PluginView` row carrying ONLY the properties the Rust type models: what a nested item must
/// be for a value-level round-trip comparison to be meaningful.
fn plugin_view_sample_modelled() -> Value {
    let mut row = plugin_view_sample().as_object().cloned().unwrap();
    for k in PLUGIN_VIEW_UNMODELLED {
        row.remove(*k);
    }
    Value::Object(row)
}

fn plugin_view_sample() -> Value {
    // Includes the properties the client does NOT model, so the "unknown fields are ignored"
    // tolerance the client documents is exercised on a realistic row.
    json!({
        "name": "acme-store",
        "type": "store",
        "loader": "plugin",
        "active": true,
        "target": "acme-store",
        "file": "acme_store.tar.gz",
        "version": "1.2.3",
        "publisher": "acme",
        "trust": "trusted",
        "valid": true,
        "error": null,
        "has_schema": true,
        "interface_version": 1,
        "schema_url": "/api/v1/admin/plugins/acme_store.tar.gz/schema",
        "schema_error": null
    })
}

#[test]
fn info_view_matches_schema() {
    check_response::<InfoView>(Case {
        schema: "InfoView",
        sample: json!({
            "version": "1.5.3",
            "build": {"auth_modules": ["tokens"], "hook_plugins": ["ranking"], "weighted_floor": true},
            "uptime_seconds": 3661_u64,
            "started_at": 1785772871_u64,
            "topology": {"pools": 2, "models": 9, "providers": 3},
            "config_persistence": true,
            "config_version": 7_u64
        }),
        unmodelled: &[],
    });
}

#[test]
fn build_info_matches_schema() {
    check_response::<BuildInfo>(Case {
        schema: "BuildInfo",
        sample: json!({
            "auth_modules": ["tokens"],
            "hook_plugins": ["ranking"],
            "weighted_floor": true
        }),
        unmodelled: &[],
    });
}

#[test]
fn topology_info_matches_schema() {
    check_response::<TopologyInfo>(Case {
        schema: "TopologyInfo",
        sample: json!({"pools": 2, "models": 9, "providers": 3}),
        unmodelled: &[],
    });
}

#[test]
fn key_view_matches_schema() {
    check_response::<KeyView>(Case {
        schema: "KeyView",
        sample: Value::Object(key_meta_sample()),
        unmodelled: &[],
    });
}

#[test]
fn key_page_matches_key_page_view_schema() {
    check_response::<KeyPage>(Case {
        schema: "KeyPageView",
        sample: json!({"items": [Value::Object(key_meta_sample())], "next_cursor": "eyJvIjoyMDB9"}),
        unmodelled: &[],
    });
}

#[test]
fn created_key_view_matches_schema() {
    let mut sample = key_meta_sample();
    sample.insert("token".into(), json!("bbk_live_abc"));
    sample.insert("expires_at".into(), json!(1785772871_u64));
    sample.insert("group_provisioned".into(), json!(true));
    sample.insert("aws_access_key_id".into(), json!("AKIAEXAMPLE"));
    sample.insert("aws_secret_access_key".into(), json!("s3cr3t"));
    check_response::<CreatedKeyView>(Case {
        schema: "CreatedKeyView",
        sample: Value::Object(sample),
        unmodelled: &[],
    });
}

#[test]
fn rotated_key_view_matches_schema() {
    let mut sample = key_meta_sample();
    sample.insert("token".into(), json!("bbk_live_new"));
    sample.insert("expires_at".into(), json!(1785772871_u64));
    sample.insert("secret".into(), Value::Null);
    check_response::<RotatedKeyView>(Case {
        schema: "RotatedKeyView",
        sample: Value::Object(sample),
        unmodelled: &[],
    });
}

#[test]
fn revoke_view_matches_schema() {
    check_response::<RevokeView>(Case {
        schema: "RevokeView",
        sample: json!({"revoked": "vk_0123456789abcdef"}),
        unmodelled: &[],
    });
}

#[test]
fn plugin_view_matches_schema() {
    check_response::<PluginView>(Case {
        schema: "PluginView",
        sample: plugin_view_sample(),
        unmodelled: PLUGIN_VIEW_UNMODELLED,
    });
}

#[test]
fn plugin_page_matches_page_plugin_view_schema() {
    check_response::<PluginPage>(Case {
        schema: "Page_PluginView",
        sample: json!({"items": [plugin_view_sample_modelled()], "next_cursor": Value::Null}),
        unmodelled: &[],
    });
}

#[test]
fn plugin_install_view_matches_schema() {
    check_response::<PluginInstallView>(Case {
        schema: "PluginInstallView",
        sample: json!({
            "file": "acme_store.tar.gz",
            "name": "acme-store",
            "version": "1.2.3",
            "publisher": "acme",
            "trust": "trusted",
            "note": "takes effect on the next store reload",
            "interface_version": 1
        }),
        // The validated store C-ABI number; the install line renders file/name/version/trust.
        unmodelled: &["interface_version"],
    });
}

#[test]
fn inspect_view_matches_plugin_schema_view_schema() {
    check_response::<InspectView>(Case {
        schema: "PluginSchemaView",
        sample: json!({
            "name": "acme-store",
            "version": "1.2.3",
            "kind": "store",
            "trust": "unverified",
            "source": "manifest",
            "restart_required_default": true,
            "schema": {"type": "object"},
            "schema_error": Value::Null
        }),
        unmodelled: &[],
    });
}

#[test]
fn plugin_reload_view_matches_schema() {
    check_response::<PluginReloadView>(Case {
        schema: "PluginReloadView",
        sample: json!({
            "plugins": [plugin_view_sample_modelled()],
            "note": "a store change applies on the next store reload"
        }),
        unmodelled: &[],
    });
}

#[test]
fn hook_view_matches_schema() {
    check_response::<HookView>(Case {
        schema: "HookView",
        sample: json!({
            "name": "pii-gate",
            "kind": "gate",
            "transport": {"kind": "plugin", "target": "pii"},
            "prompt": "ro",
            "user": "no",
            "priority": 10,
            "at": "request",
            "on_error": "reject",
            "timeout_ms": 250_u64,
            "global": true,
            "settings_keys": ["endpoint"]
        }),
        // Key NAMES only (values redacted server-side). The `hooks list` table has no column for
        // them; they are a config-surface concern, not a registry-row one.
        unmodelled: &["settings_keys"],
    });
}

#[test]
fn hook_transport_view_matches_schema() {
    check_response::<HookTransportView>(Case {
        schema: "HookTransportView",
        sample: json!({"kind": "plugin", "target": "pii"}),
        unmodelled: &[],
    });
}

#[test]
fn hook_page_matches_page_hook_view_schema() {
    check_response::<HookPage>(Case {
        schema: "Page_HookView",
        sample: json!({
            "items": [{
                "name": "pii-gate",
                "kind": "gate",
                "transport": {"kind": "plugin", "target": "pii"},
                "prompt": "ro",
                "user": "no",
                "priority": 10,
                "at": Value::Null,
                "on_error": "reject",
                "timeout_ms": 250_u64,
                "global": false
            }],
            "next_cursor": Value::Null
        }),
        unmodelled: &[],
    });
}

#[test]
fn config_apply_view_matches_schema() {
    check_response::<ConfigApplyView>(Case {
        schema: "ConfigApplyView",
        sample: json!({"applied": true, "config_version": 8_u64, "note": "live, not persisted"}),
        unmodelled: &[],
    });
}

#[test]
fn error_envelope_matches_schema() {
    check_response::<ErrorEnvelope>(Case {
        schema: "Error",
        sample: json!({"error": {"code": "unauthorized", "message": "admin token rejected"}}),
        unmodelled: &[],
    });
}

#[test]
fn create_key_req_matches_schema() {
    let full = serde_json::to_value(CreateKeyReq {
        name: "svc-checkout".into(),
        allowed_pools: Some(vec!["fast".into()]),
        group: Some("team:payments".into()),
        parent: Some("team".into()),
        expires_in: Some("7d".into()),
        expires_at: Some(1785772871),
        labels: [("team".to_string(), "payments".to_string())]
            .into_iter()
            .collect(),
        issue_aws_credential: true,
    })
    .unwrap();
    let minimal = serde_json::to_value(CreateKeyReq {
        name: "svc-checkout".into(),
        allowed_pools: None,
        group: None,
        parent: None,
        expires_in: None,
        expires_at: None,
        labels: Default::default(),
        issue_aws_credential: false,
    })
    .unwrap();

    // The schema sets `additionalProperties: false` (the server derives `deny_unknown_fields`),
    // so an extra Rust field here is not a cosmetic drift, it is a guaranteed 400 on every mint.
    assert_eq!(
        schema("CreateKeyReq").get("additionalProperties"),
        Some(&Value::Bool(false)),
        "CreateKeyReq stopped forbidding unknown fields; the strictness this case relies on moved"
    );
    check_request("CreateKeyReq", &full, &minimal, &[]);
}

#[test]
fn install_plugin_req_matches_schema() {
    let body = serde_json::to_value(InstallPluginReq {
        file: "acme_store.tar.gz".into(),
        tarball_b64: "H4sIAA==".into(),
    })
    .unwrap();
    check_request("InstallPluginReq", &body, &body, &[]);
}

#[test]
fn inspect_plugin_req_matches_schema() {
    let body = serde_json::to_value(InspectPluginReq {
        file: "acme_store.tar.gz".into(),
        tarball_b64: "H4sIAA==".into(),
    })
    .unwrap();
    check_request("InspectPluginReq", &body, &body, &[]);
}

/// The spec's ONLY closed `enum` on any shape this client touches is the error `code` vocabulary.
/// The client models it as a `String` (it renders `code: message` verbatim), so there is no Rust
/// variant set to compare; what IS load-bearing is that the two codes the CLI branches its 401 and
/// 403 hints on still exist, and that every documented code decodes.
#[test]
fn error_code_enum_vocabulary_matches_schema() {
    let codes = schema("Error")["properties"]["error"]["properties"]["code"]["enum"]
        .as_array()
        .expect("Error.error.code must stay a closed enum")
        .iter()
        .map(|v| v.as_str().expect("enum members are strings").to_string())
        .collect::<BTreeSet<_>>();

    let expected: BTreeSet<String> = [
        "not_found",
        "unauthorized",
        "method_not_allowed",
        "forbidden",
        "invalid_request",
        "version_conflict",
        "conflict",
        "rate_limited",
        "internal",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        codes, expected,
        "the error-code vocabulary changed in the spec; re-check the 401/403 hint branches in \
         Client::check_status before updating this list"
    );

    for code in &codes {
        let env: ErrorEnvelope =
            serde_json::from_value(json!({"error": {"code": code, "message": "m"}}))
                .unwrap_or_else(|e| panic!("error code {code} must decode: {e}"));
        assert_eq!(&env.error.code, code);
        assert_eq!(env.error.message, "m");
    }
}

/// Every endpoint the client calls must exist in the spec with that method, and its success
/// response must point at the schema the client's method decodes into. This is the wiring half of
/// conformance: the cases above prove the STRUCTS match their schemas, this proves each struct is
/// still pointed at the right endpoint.
#[test]
fn client_endpoints_exist_with_the_expected_response_schema() {
    // (path, method, success schema the client decodes, or None for a 204/untyped body)
    let calls: &[(&str, &str, Option<&str>)] = &[
        ("/info", "get", Some("InfoView")),
        ("/keys", "get", Some("KeyPageView")),
        ("/keys", "post", Some("CreatedKeyView")),
        ("/keys/{id}", "get", Some("KeyView")),
        ("/keys/{id}", "delete", None),
        ("/keys/{id}/revoke", "post", Some("RevokeView")),
        ("/keys/{id}/rotate", "post", Some("RotatedKeyView")),
        ("/plugins", "get", Some("Page_PluginView")),
        ("/plugins", "post", Some("PluginInstallView")),
        ("/plugins/inspect", "post", Some("PluginSchemaView")),
        ("/plugins/reload", "post", Some("PluginReloadView")),
        ("/hooks", "get", Some("Page_HookView")),
        // The CLI passes the effective config through as a raw serde_json::Value: there is no Rust
        // type mirroring EffectiveConfigView, by design (it is a rich nested config document that
        // the CLI only pretty-prints).
        ("/config", "get", Some("EffectiveConfigView")),
        ("/config/apply", "post", Some("ConfigApplyView")),
    ];

    let paths = spec()["paths"]
        .as_object()
        .expect("the spec must carry paths");
    for (rel, method, want) in calls {
        let full = format!("/api/v1/admin{rel}");
        let item = paths.get(&full).unwrap_or_else(|| {
            panic!("the client calls {method} {full} but the committed spec has no such path")
        });
        let op = item.get(method).unwrap_or_else(|| {
            panic!("the client calls {method} {full} but the spec defines no {method} on that path")
        });
        let responses = op["responses"].as_object().expect("responses object");
        let success = responses
            .iter()
            .find(|(code, _)| code.starts_with('2'))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("{method} {full} declares no 2xx response"));

        match want {
            None => assert!(
                success.get("content").is_none(),
                "{method} {full}: the client expects an empty body but the spec now returns one"
            ),
            Some(name) => {
                let got = success["content"]["application/json"]["schema"]["$ref"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("{method} {full}: the 2xx response no longer names a schema by $ref")
                    });
                assert_eq!(
                    got,
                    format!("#/components/schemas/{name}"),
                    "{method} {full}: the success response schema moved; the client decodes it as \
                     {name}"
                );
            }
        }
    }
}

/// `busbar-admin config apply` sends the JSON file verbatim as a `serde_json::Value`: there is no
/// Rust type for this body, so nothing else in this crate notices if its shape changes. Pin the
/// two facts the CLI's help text and error messages promise: `config` is required, and unknown
/// top-level keys are refused (so a typo'd file fails at the gateway, not silently).
#[test]
fn config_apply_request_body_shape_is_what_the_cli_documents() {
    let body = &spec()["paths"]["/api/v1/admin/config/apply"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert_eq!(
        body.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "POST /config/apply stopped refusing unknown top-level keys"
    );
    let required = required_of(body);
    assert!(
        required.contains("config"),
        "POST /config/apply no longer requires a `config` key, but the CLI's --help still tells \
         operators to write {{\"config\": ..., \"providers\": ...}}"
    );
    let props: BTreeSet<String> = body["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .cloned()
        .collect();
    let expected: BTreeSet<String> = ["config", "providers"]
        .into_iter()
        .map(str::to_string)
        .collect();
    assert_eq!(
        props, expected,
        "the config-apply body gained or lost a top-level key; the CLI passes the file through \
         untyped, so this assertion is the only thing that notices"
    );
}
