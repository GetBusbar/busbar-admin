use super::*;
use std::collections::BTreeSet;

/// Fields a schema marks REQUIRED that this CLI deliberately does not model, each with the
/// reason it is safe to ignore. Entries are `(schema, field, why)`. Anything not listed here
/// that core marks required will fail the test — the point is that dropping a required field
/// becomes a recorded decision instead of a silent one.
const DELIBERATELY_UNRENDERED: &[(&str, &str, &str)] = &[
    // `GET /hooks` is a definition listing; the live desired-vs-reported settings comparison is
    // `GET /hooks/{name}/status`, a separate endpoint this CLI does not surface yet. The key
    // NAMES are modelled anyway (cheap, and it keeps the rename arm honest), so this entry is
    // currently empty — kept as the documented seam for the next one.
];

fn spec() -> serde_json::Value {
    let path = std::env::var("BUSBAR_SPEC")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json").to_string());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading the OpenAPI document at {path}: {e}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parsing the OpenAPI document at {path}: {e}"))
}

/// The field names a struct actually puts on (or reads off) the wire, taken from its own
/// `Serialize` impl rather than from a list someone has to remember to update.
fn modelled<T: Serialize>(v: &T) -> BTreeSet<String> {
    serde_json::to_value(v)
        .expect("a contract struct must serialize")
        .as_object()
        .expect("a contract struct must serialize to a JSON object")
        .keys()
        .cloned()
        .collect()
}

fn schema_fields(spec: &serde_json::Value, name: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let s = spec
        .pointer(&format!("/components/schemas/{name}"))
        .unwrap_or_else(|| panic!("schema {name} is absent from the OpenAPI document"));
    let props = s
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let required = s
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    (props, required)
}

fn schema_accepts(
    spec: &serde_json::Value,
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> bool {
    use serde_json::Value;
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return schema_accepts(
            spec,
            spec.pointer(reference.strip_prefix('#').expect("local ref"))
                .expect("schema"),
            value,
        );
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(variants) = schema.get(keyword).and_then(Value::as_array) {
            return variants
                .iter()
                .any(|variant| schema_accepts(spec, variant, value));
        }
    }
    if let Some(variants) = schema.get("allOf").and_then(Value::as_array) {
        return variants
            .iter()
            .all(|variant| schema_accepts(spec, variant, value));
    }
    if let Some(types) = schema.get("type").and_then(Value::as_array) {
        return types.iter().any(|kind| {
            let mut variant = schema.clone();
            variant["type"] = kind.clone();
            schema_accepts(spec, &variant, value)
        });
    }
    match schema.get("type").and_then(Value::as_str) {
        None => true,
        Some("null") => value.is_null(),
        Some("boolean") => value.is_boolean(),
        Some("string") => value.is_string(),
        Some("integer") => value.is_i64() || value.is_u64(),
        Some("number") => value.is_number(),
        Some("array") => value.as_array().is_some_and(|values| {
            values.iter().all(|v| {
                schema
                    .get("items")
                    .is_none_or(|items| schema_accepts(spec, items, v))
            })
        }),
        Some("object") => value.as_object().is_some_and(|values| {
            values.iter().all(|(key, v)| {
                schema
                    .get("properties")
                    .and_then(|properties| properties.get(key))
                    .or_else(|| schema.get("additionalProperties").filter(|s| s.is_object()))
                    .is_none_or(|property| schema_accepts(spec, property, v))
            })
        }),
        Some(kind) => panic!("unhandled schema type {kind}"),
    }
}

fn assert_request_matches<T: Serialize>(spec: &serde_json::Value, schema: &str, instance: &T) {
    assert_fields_match(spec, schema, instance);
    let wire = serde_json::to_value(instance).unwrap();
    assert!(
        schema_accepts(spec, &spec["components"]["schemas"][schema], &wire),
        "{schema}: serialized field types do not match the contract"
    );
}

/// Assert one struct against one schema, in both directions.
fn assert_fields_match<T: Serialize>(spec: &serde_json::Value, schema: &str, instance: &T) {
    let modelled = modelled(instance);
    let (props, required) = schema_fields(spec, schema);

    let phantom: Vec<_> = modelled.difference(&props).cloned().collect();
    assert!(
        phantom.is_empty(),
        "{schema}: this client models {phantom:?}, which the spec does NOT have — a renamed \
         or removed field. The client is speaking a language the gateway no longer accepts."
    );

    let ignored: Vec<_> = required
        .difference(&modelled)
        .filter(|f| {
            !DELIBERATELY_UNRENDERED
                .iter()
                .any(|(s, field, _)| *s == schema && field == &f.as_str())
        })
        .cloned()
        .collect();
    assert!(
        ignored.is_empty(),
        "{schema}: the spec marks {ignored:?} REQUIRED but this client does not model them. \
         Either model them or record why not in DELIBERATELY_UNRENDERED."
    );
}

/// Exercise every advertised JSON type (including nullable alternatives) against the real
/// response deserializer. Each object probe varies one field at a time to avoid a Cartesian product.
fn schema_probes(
    spec: &serde_json::Value,
    schema: &serde_json::Value,
    depth: usize,
) -> Vec<serde_json::Value> {
    use serde_json::{json, Value};
    assert!(
        depth < 32,
        "recursive schema requires an explicit bounded fixture"
    );
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return schema_probes(
            spec,
            spec.pointer(reference.strip_prefix('#').expect("local schema ref"))
                .expect("referenced schema"),
            depth + 1,
        );
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(variants) = schema.get(keyword).and_then(Value::as_array) {
            return variants
                .iter()
                .flat_map(|variant| schema_probes(spec, variant, depth + 1))
                .collect();
        }
    }
    if let Some(variants) = schema.get("allOf").and_then(Value::as_array) {
        assert_eq!(
            variants.len(),
            1,
            "multi-part allOf requires a dedicated fixture"
        );
        return schema_probes(spec, &variants[0], depth + 1);
    }
    if let Some(types) = schema.get("type").and_then(Value::as_array) {
        return types
            .iter()
            .flat_map(|kind| {
                let mut variant = schema.clone();
                variant["type"] = kind.clone();
                schema_probes(spec, &variant, depth + 1)
            })
            .collect();
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values.clone();
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("null") | None => vec![Value::Null],
        Some("boolean") => vec![json!(true), json!(false)],
        Some("string") => vec![json!("sample")],
        Some("integer") => vec![json!(0)],
        Some("number") => vec![json!(0.5)],
        Some("array") => {
            let mut values = vec![json!([])];
            if let Some(items) = schema.get("items") {
                values.extend(
                    schema_probes(spec, items, depth + 1)
                        .into_iter()
                        .map(|item| json!([item])),
                );
            }
            values
        }
        Some("object") => {
            let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
                return match schema.get("additionalProperties").filter(|s| s.is_object()) {
                    Some(property) => schema_probes(spec, property, depth + 1)
                        .into_iter()
                        .map(|v| json!({"sample":v}))
                        .collect(),
                    None => vec![json!({})],
                };
            };
            let fields: Vec<_> = properties
                .iter()
                .map(|(name, property)| (name, schema_probes(spec, property, depth + 1)))
                .collect();
            let base: serde_json::Map<String, Value> = fields
                .iter()
                .map(|(name, values)| {
                    (
                        (*name).clone(),
                        values.first().expect("schema probe").clone(),
                    )
                })
                .collect();
            let mut values = vec![Value::Object(base.clone())];
            for (name, probes) in fields {
                for probe in probes {
                    let mut object = base.clone();
                    object.insert(name.clone(), probe);
                    values.push(Value::Object(object));
                }
            }
            values
        }
        Some(kind) => panic!("unhandled schema type {kind}"),
    }
}

fn assert_matches<T: Serialize + DeserializeOwned>(
    spec: &serde_json::Value,
    schema: &str,
    instance: &T,
) {
    assert_fields_match(spec, schema, instance);
    let document = &spec["components"]["schemas"][schema];
    for value in schema_probes(spec, document, 0) {
        assert!(serde_json::from_value::<T>(value).is_ok(), "{schema}: an advertised JSON type or nullable alternative cannot decode in this client");
    }
}

#[test]
fn spec_contract_rejects_changed_type_and_nullability() {
    for property in [
        serde_json::json!({"type":"string"}),
        serde_json::json!({"type":["boolean","null"]}),
    ] {
        let mut document = spec();
        document["components"]["schemas"]["ConfigApplyView"]["properties"]["applied"] = property;
        let value = ConfigApplyView {
            applied: true,
            config_version: 0,
            note: String::new(),
            reload_to_apply: vec!["admin".into()],
        };
        assert!(
            std::panic::catch_unwind(|| assert_matches(&document, "ConfigApplyView", &value))
                .is_err()
        );
    }
}

// ── Instances. Every field is populated so nothing is `skip_serializing_if`-omitted; the
//    compiler forces this list to track the structs, which is the point.

fn sample_key_view() -> KeyView {
    KeyView {
        id: "vk_1".into(),
        name: "n".into(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
        state: "active".into(),
        enabled: true,
        created_at: 0,
    }
}

#[test]
fn info_shapes_match_the_spec() {
    let spec = spec();
    assert_matches(
        &spec,
        "InfoView",
        &InfoView {
            version: "1.5.2".into(),
            build: BuildInfo {
                auth_modules: vec![],
                hook_plugins: vec![],
                weighted_floor: false,
            },
            uptime_seconds: Some(0),
            started_at: Some(0),
            process_boot_nonce: Some("0123456789abcdef0123456789abcdef".into()),
            topology: TopologyInfo {
                pools: 0,
                models: 0,
                providers: 0,
            },
            config_persistence: false,
            config_version: 0,
        },
    );
    assert_matches(
        &spec,
        "BuildInfo",
        &BuildInfo {
            auth_modules: vec![],
            hook_plugins: vec![],
            weighted_floor: false,
        },
    );
    assert_matches(
        &spec,
        "TopologyInfo",
        &TopologyInfo {
            pools: 0,
            models: 0,
            providers: 0,
        },
    );
}

#[test]
fn key_shapes_match_the_spec() {
    let spec = spec();
    assert_matches(&spec, "KeyView", &sample_key_view());
    assert_matches(
        &spec,
        "KeyPageView",
        &KeyPage {
            items: vec![],
            next_cursor: None,
        },
    );
    assert_request_matches(
        &spec,
        "CreateKeyReq",
        &CreateKeyReq {
            name: "svc".into(),
            allowed_pools: Some(vec![]),
            group: Some("g".into()),
            parent: Some("p".into()),
            expires_in: Some("7d".into()),
            expires_at: Some(0),
            labels: [("k".to_string(), "v".to_string())].into_iter().collect(),
            issue_aws_credential: true,
        },
    );
    assert_matches(
        &spec,
        "CreatedKeyView",
        &CreatedKeyView {
            id: "vk_1".into(),
            name: "n".into(),
            allowed_pools: None,
            group: None,
            labels: Default::default(),
            state: "active".into(),
            enabled: true,
            created_at: 0,
            token: "bbk".into(),
            expires_at: 0,
            group_provisioned: false,
            aws_access_key_id: None,
            aws_secret_access_key: None,
        },
    );
    assert_matches(
        &spec,
        "RotatedKeyView",
        &RotatedKeyView {
            id: "vk_1".into(),
            name: "n".into(),
            allowed_pools: None,
            group: None,
            labels: Default::default(),
            state: "active".into(),
            enabled: true,
            created_at: 0,
            token: None,
            expires_at: None,
            secret: None,
        },
    );
    assert_matches(
        &spec,
        "RevokeView",
        &RevokeView {
            revoked: "vk_1".into(),
        },
    );
}

fn sample_plugin_view() -> PluginView {
    PluginView {
        name: "p".into(),
        plugin_type: "hooks".into(),
        loader: "plugin".into(),
        active: Some(true),
        target: Some("p".into()),
        file: Some("p.tar.gz".into()),
        archive_sha256: Some("a".repeat(64)),
        interface_version: Some(1),
        version: Some("1.0.0".into()),
        publisher: Some("acme".into()),
        trust: Some("trusted".into()),
        valid: Some(true),
        error: None,
        has_schema: true,
    }
}

#[test]
fn plugin_shapes_match_the_spec() {
    let spec = spec();
    assert_matches(&spec, "PluginView", &sample_plugin_view());
    assert_matches(
        &spec,
        "Page_PluginView",
        &PluginPage {
            items: vec![],
            next_cursor: None,
        },
    );
    assert_request_matches(
        &spec,
        "InstallPluginReq",
        &InstallPluginReq {
            file: "p.tar.gz".into(),
            tarball_b64: "AA==".into(),
        },
    );
    assert_request_matches(
        &spec,
        "InspectPluginReq",
        &InspectPluginReq {
            file: "p.tar.gz".into(),
            tarball_b64: "AA==".into(),
        },
    );
    assert_matches(
        &spec,
        "PluginInstallView",
        &PluginInstallView {
            file: "p.tar.gz".into(),
            name: "p".into(),
            interface_version: Some(1),
            version: Some("1.0.0".into()),
            publisher: Some("acme".into()),
            trust: "trusted".into(),
            note: String::new(),
        },
    );
    assert_matches(
        &spec,
        "PluginSchemaView",
        &InspectView {
            name: "p".into(),
            version: Some("1.0.0".into()),
            kind: Some("store".into()),
            trust: "trusted".into(),
            source: "installed_archive".into(),
            file: Some("p.tar.gz".into()),
            archive_sha256: Some("a".repeat(64)),
            schema_state: Some("absent".into()),
            restart_required_default: Some(true),
            schema: None,
            schema_error: None,
        },
    );
    assert_matches(
        &spec,
        "PluginReloadView",
        &PluginReloadView {
            plugins: vec![],
            note: String::new(),
        },
    );
}

#[test]
fn hook_shapes_match_the_spec() {
    let spec = spec();
    assert_matches(
        &spec,
        "HookView",
        &HookView {
            name: "h".into(),
            kind: "gate".into(),
            transport: HookTransportView {
                kind: "plugin".into(),
                target: Some("t".into()),
            },
            prompt: "ro".into(),
            user: "no".into(),
            priority: 0,
            at: Some("request".into()),
            on_error: "reject".into(),
            timeout_ms: 0,
            settings_keys: vec!["api_key".into()],
            global: false,
            phase: vec![],
            fires_at: vec!["request".into()],
            groups: vec![],
        },
    );
    assert_matches(
        &spec,
        "HookTransportView",
        &HookTransportView {
            kind: "plugin".into(),
            target: Some("t".into()),
        },
    );
    assert_matches(
        &spec,
        "Page_HookView",
        &HookPage {
            items: vec![],
            next_cursor: None,
        },
    );
}

#[test]
fn config_shapes_match_the_spec() {
    assert_matches(
        &spec(),
        "ConfigApplyView",
        &ConfigApplyView {
            reload_to_apply: vec!["admin".into()],
            applied: true,
            config_version: 0,
            note: String::new(),
        },
    );
}
