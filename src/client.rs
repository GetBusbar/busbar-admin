//! A thin, hand-rolled admin client for the busbar gateway's `/api/v1/admin` surface.
//!
//! The request/response structs below mirror the frozen v1 contract
//! (`crates/busbar/src/admin/v1/contract`; the committed `openapi.json` at the repo root is the
//! canonical spec this client was audited against — busbar 1.5.0). Only the fields busbar-admin actually renders are
//! modelled; unknown fields are ignored (the contract is additive-only), so a newer gateway never
//! breaks an older CLI. To add an endpoint: add a typed response struct and a method on
//! [`Client`] that calls [`Client::get`] / [`Client::send`] with the relative path — every method
//! funnels through those two seams for uniform auth, TLS, and error mapping.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Header the admin plane authenticates on (the API also accepts `Authorization: Bearer <token>`).
const X_ADMIN_TOKEN: &str = "x-admin-token";
const ADMIN_PREFIX: &str = "/api/v1/admin";

/// TLS / transport knobs, mirroring the Terraform provider (`insecure`, `ca_cert_pem`,
/// `client_cert_pem` + `client_key_pem`) for parity — here the cert inputs are file paths.
#[derive(Default)]
pub struct Tls {
    pub insecure: bool,
    pub ca_cert: Option<std::path::PathBuf>,
    pub client_cert: Option<std::path::PathBuf>,
    pub client_key: Option<std::path::PathBuf>,
}

/// The admin client: an endpoint base URL, an admin token, and a configured HTTP client.
pub struct Client {
    base: String,
    http: HttpClient,
    endpoint: String,
}

impl Client {
    /// Build a client. `endpoint` is the gateway base (e.g. `http://localhost:8081`); `token` is
    /// the admin token sent as `x-admin-token`. TLS knobs mirror the Terraform provider.
    pub fn new(endpoint: &str, token: &str, tls: Tls) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let base = format!("{endpoint}{ADMIN_PREFIX}");

        let mut headers = HeaderMap::new();
        let mut tok = HeaderValue::from_str(token)
            .context("admin token contains characters invalid for an HTTP header")?;
        tok.set_sensitive(true);
        headers.insert(X_ADMIN_TOKEN, tok.clone());
        // Send both carriers; the gateway accepts either.
        let mut bearer = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("admin token contains characters invalid for an HTTP header")?;
        bearer.set_sensitive(true);
        headers.insert(AUTHORIZATION, bearer);

        let mut builder = HttpClient::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("busbar-admin/", env!("CARGO_PKG_VERSION")));

        if tls.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(ca) = &tls.ca_cert {
            let pem =
                std::fs::read(ca).with_context(|| format!("reading --ca-cert {}", ca.display()))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .with_context(|| format!("parsing --ca-cert {} as PEM", ca.display()))?;
            builder = builder.add_root_certificate(cert);
        }
        match (&tls.client_cert, &tls.client_key) {
            (Some(cert), Some(key)) => {
                let mut pem = std::fs::read(cert)
                    .with_context(|| format!("reading --client-cert {}", cert.display()))?;
                let mut keypem = std::fs::read(key)
                    .with_context(|| format!("reading --client-key {}", key.display()))?;
                pem.push(b'\n');
                pem.append(&mut keypem);
                let identity = reqwest::Identity::from_pem(&pem)
                    .context("parsing --client-cert / --client-key as a PEM identity")?;
                builder = builder.identity(identity);
            }
            (None, None) => {}
            _ => {
                return Err(anyhow!(
                    "--client-cert and --client-key must be provided together (mTLS)"
                ))
            }
        }

        let http = builder.build().context("building the HTTP client")?;
        Ok(Self {
            base,
            http,
            endpoint,
        })
    }

    fn url(&self, rel: &str) -> String {
        format!("{}{}", self.base, rel)
    }

    /// Execute a prepared request, mapping transport + HTTP errors onto helpful messages.
    fn execute(&self, req: RequestBuilder) -> Result<Response> {
        let resp = req.send().map_err(|e| self.transport_error(e))?;
        self.check_status(resp)
    }

    /// Turn a reqwest transport error into an actionable message (connection refused, DNS, TLS…).
    fn transport_error(&self, e: reqwest::Error) -> anyhow::Error {
        if e.is_connect() {
            return anyhow!(
                "no gateway reachable at {} (connection failed): {e}",
                self.endpoint
            );
        }
        if e.is_timeout() {
            return anyhow!("request to {} timed out", self.endpoint);
        }
        anyhow!("request to {} failed: {e}", self.endpoint)
    }

    /// Map an HTTP status onto an error carrying the gateway's `{"error":{"code","message"}}`
    /// envelope when present. 401/403 get dedicated hints.
    fn check_status(&self, resp: Response) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().unwrap_or_default();
        let envelope: Option<ErrorEnvelope> = serde_json::from_str(&body).ok();
        let detail = envelope
            .as_ref()
            .map(|e| format!("{}: {}", e.error.code, e.error.message));

        let msg = match status {
            StatusCode::UNAUTHORIZED => format!(
                "admin token rejected ({}){}",
                status,
                detail.map(|d| format!(" — {d}")).unwrap_or_default()
            ),
            StatusCode::FORBIDDEN => format!(
                "admin token lacks the required scope ({}){}",
                status,
                detail.map(|d| format!(" — {d}")).unwrap_or_default()
            ),
            _ => match detail {
                Some(d) => format!("gateway returned {status}: {d}"),
                None if body.is_empty() => format!("gateway returned {status}"),
                None => format!("gateway returned {status}: {body}"),
            },
        };
        Err(anyhow!(msg))
    }

    /// GET a relative admin path and decode the JSON body into `T`.
    pub fn get<T: DeserializeOwned>(&self, rel: &str) -> Result<T> {
        let resp = self.execute(self.http.get(self.url(rel)))?;
        Self::decode(resp)
    }

    /// GET returning the raw JSON value (for `--json` passthrough and untyped shapes).
    pub fn get_raw(&self, rel: &str) -> Result<serde_json::Value> {
        let resp = self.execute(self.http.get(self.url(rel)))?;
        Self::decode(resp)
    }

    /// Send a request with a JSON body (or none) and decode into `T`.
    pub fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        rel: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let mut req = self.http.request(method, self.url(rel));
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = self.execute(req)?;
        Self::decode(resp)
    }

    /// Send a request expecting NO body back (204). Returns Ok(()) on success.
    pub fn send_no_content(&self, method: Method, rel: &str) -> Result<()> {
        let req = self.http.request(method, self.url(rel));
        self.execute(req)?;
        Ok(())
    }

    fn decode<T: DeserializeOwned>(resp: Response) -> Result<T> {
        let body = resp.text().context("reading the response body")?;
        serde_json::from_str(&body)
            .with_context(|| format!("decoding the gateway response: {body}"))
    }

    // ── Typed endpoint methods ───────────────────────────────────────────────────────────────

    /// `GET /api/v1/admin/info`.
    pub fn info(&self) -> Result<InfoView> {
        self.get("/info")
    }

    /// `GET /api/v1/admin/keys` — one page (default 200). busbar-admin surfaces the first page.
    pub fn list_keys(&self) -> Result<KeyPage> {
        self.get("/keys")
    }

    /// `POST /api/v1/admin/keys` — mint a key. Returns the once-shown secret.
    pub fn create_key(&self, req: &CreateKeyReq) -> Result<CreatedKeyView> {
        self.send(Method::POST, "/keys", Some(req))
    }

    /// `GET /api/v1/admin/keys/{id}` — one key's metadata (never the secret).
    pub fn get_key(&self, id: &str) -> Result<KeyView> {
        self.get(&format!("/keys/{id}"))
    }

    /// `POST /api/v1/admin/keys/{id}/revoke` — durably denylist a key WITHOUT deleting the
    /// binding (the record stays visible for audit/usage attribution). Idempotent.
    pub fn revoke_key(&self, id: &str) -> Result<RevokeView> {
        self.send(Method::POST, &format!("/keys/{id}/revoke"), None::<&()>)
    }

    /// `POST /api/v1/admin/keys/{id}/rotate` — mint a fresh credential in place (same id,
    /// budgets, usage). The new token/secret is shown once.
    pub fn rotate_key(&self, id: &str) -> Result<RotatedKeyView> {
        self.send(Method::POST, &format!("/keys/{id}/rotate"), None::<&()>)
    }

    /// `DELETE /api/v1/admin/keys/{id}` — revoke AND forget (tombstone) a key (204).
    pub fn delete_key(&self, id: &str) -> Result<()> {
        self.send_no_content(Method::DELETE, &format!("/keys/{id}"))
    }

    /// `GET /api/v1/admin/plugins?type=` — the plugin catalog for one plugin type
    /// (`auth` | `hooks` | `store`).
    pub fn list_plugins(&self, plugin_type: &str) -> Result<PluginPage> {
        self.get(&format!("/plugins?type={plugin_type}"))
    }

    /// `POST /api/v1/admin/plugins` — install a signed plugin tarball (bytes ride as base64;
    /// the engine re-verifies the signed manifest server-side).
    pub fn install_plugin(&self, req: &InstallPluginReq) -> Result<PluginInstallView> {
        self.send(Method::POST, "/plugins", Some(req))
    }

    /// `POST /api/v1/admin/plugins/reload` — re-scan the plugins directory and return the
    /// reconciled dynamic-library inventory.
    pub fn reload_plugins(&self) -> Result<PluginReloadView> {
        self.send(Method::POST, "/plugins/reload", None::<&()>)
    }

    /// `GET /api/v1/admin/hooks` — the hook registry (a `{items, next_cursor}` page).
    pub fn list_hooks(&self) -> Result<HookPage> {
        self.get("/hooks")
    }

    /// `GET /api/v1/admin/config` — the effective running config (carries `version`).
    pub fn config(&self) -> Result<serde_json::Value> {
        self.get_raw("/config")
    }

    /// `POST /api/v1/admin/config/apply` — apply a full config carried in the body.
    pub fn config_apply(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.send(Method::POST, "/config/apply", Some(body))
    }
}

// ── Contract-mirroring request/response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

/// `GET /info` — mirrors `contract::InfoView`.
#[derive(Debug, Deserialize, Serialize)]
pub struct InfoView {
    pub version: String,
    pub build: BuildInfo,
    #[serde(default)]
    pub uptime_seconds: Option<u64>,
    #[serde(default)]
    pub started_at: Option<u64>,
    pub topology: TopologyInfo,
    #[serde(default)]
    pub config_persistence: bool,
    #[serde(default)]
    pub config_version: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BuildInfo {
    #[serde(default)]
    pub auth_modules: Vec<String>,
    #[serde(default)]
    pub hook_plugins: Vec<String>,
    #[serde(default)]
    pub weighted_floor: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TopologyInfo {
    pub pools: usize,
    pub models: usize,
    pub providers: usize,
}

/// A virtual-key metadata row (`GET /keys` item, `GET /keys/{id}`; the `key_meta()` shape).
/// 1.5.0: keys are pure auth — no inline budget/rpm/tpm (enforcement flows through the bound
/// `group`). `allowed_pools` is `null` = all pools, `[]` = no pools.
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyView {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub allowed_pools: Option<Vec<String>>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    /// `active` | `disabled` | `revoked` | `tombstoned` (derived, additive).
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: u64,
}

/// `GET /keys` — the cursor-paginated envelope.
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyPage {
    #[serde(default)]
    pub items: Vec<KeyView>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// `POST /keys` request body (1.5.0 `CreateKeyReq`). The server rejects unknown fields
/// (`deny_unknown_fields`), so the removed 1.4.x budget/rpm/tpm fields must never be sent —
/// per-key enforcement moved onto the bound `group`. Omitted (`None`) fields are dropped.
#[derive(Debug, Serialize)]
pub struct CreateKeyReq {
    pub name: String,
    /// Omitted = ALL pools; an explicit `[]` = NO pools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_pools: Option<Vec<String>>,
    /// The `groups:` bucket this key binds to (at most one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Auto-provision target: create `group` as a leaf under this existing parent group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Token lifetime as a duration string (`7d`, `24h`, `30m`, `3600s`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<String>,
    /// Token expiry as absolute Unix seconds (mutually exclusive with `expires_in`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Mint-time labels echoed onto the key's metric series.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub issue_aws_credential: bool,
}

/// `POST /keys` response (`CreatedKeyView`): key metadata + the ONCE-shown signed `token`
/// (1.5.0 — the credential is a busbar-signed expiring token, not a `secret`) + AWS creds when
/// requested.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreatedKeyView {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub allowed_pools: Option<Vec<String>>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: u64,
    /// The busbar-signed token — shown exactly once.
    pub token: String,
    /// Unix-seconds expiry of the signed token.
    #[serde(default)]
    pub expires_at: u64,
    /// Whether this mint auto-provisioned its bound group leaf.
    #[serde(default)]
    pub group_provisioned: bool,
    #[serde(default)]
    pub aws_access_key_id: Option<String>,
    #[serde(default)]
    pub aws_secret_access_key: Option<String>,
}

/// `POST /keys/{id}/rotate` response: metadata + the once-shown fresh credential — exactly one
/// of `token` (+ `expires_at`; signed-token keys) or `secret` (legacy hashed-secret keys).
#[derive(Debug, Deserialize, Serialize)]
pub struct RotatedKeyView {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub allowed_pools: Option<Vec<String>>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub secret: Option<String>,
}

/// `POST /keys/{id}/revoke` response: the id, now durably denylisted.
#[derive(Debug, Deserialize, Serialize)]
pub struct RevokeView {
    pub revoked: String,
}

/// One plugin catalog row (`GET /plugins?type=` item; `contract::PluginView`). Only the fields
/// busbar-admin renders are modelled; the contract is additive-only.
#[derive(Debug, Deserialize, Serialize)]
pub struct PluginView {
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
    /// `compiled-in` or `plugin` (a dlopen'd dynamic-library plugin).
    pub loader: String,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    /// `trusted` | `unverified` | `rejected` (dynamic-library plugins only).
    #[serde(default)]
    pub trust: Option<String>,
    #[serde(default)]
    pub valid: Option<bool>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub has_schema: bool,
}

/// `GET /plugins?type=` — the cursor-paginated plugin-catalog envelope.
#[derive(Debug, Deserialize, Serialize)]
pub struct PluginPage {
    #[serde(default)]
    pub items: Vec<PluginView>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// `POST /plugins` request body: install a signed plugin tarball (bytes as base64).
#[derive(Debug, Serialize)]
pub struct InstallPluginReq {
    /// The bare `.tar.gz` filename to store the artifact under.
    pub file: String,
    pub tarball_b64: String,
}

/// `POST /plugins` response (`PluginInstallView`).
#[derive(Debug, Deserialize, Serialize)]
pub struct PluginInstallView {
    pub file: String,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub trust: String,
    #[serde(default)]
    pub note: String,
}

/// `POST /plugins/reload` response: the reconciled dynamic-library inventory.
#[derive(Debug, Deserialize, Serialize)]
pub struct PluginReloadView {
    #[serde(default)]
    pub plugins: Vec<PluginView>,
    #[serde(default)]
    pub note: String,
}

/// A hook definition row (`GET /hooks` item; `contract::HookView`).
#[derive(Debug, Deserialize, Serialize)]
pub struct HookView {
    pub name: String,
    pub kind: String,
    pub transport: HookTransportView,
    #[serde(default)]
    pub prompt: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub priority: u16,
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub on_error: String,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default)]
    pub global: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HookTransportView {
    pub kind: String,
    #[serde(default)]
    pub target: Option<String>,
}

/// `GET /hooks` — the cursor-paginated hook-registry envelope.
#[derive(Debug, Deserialize, Serialize)]
pub struct HookPage {
    #[serde(default)]
    pub items: Vec<HookView>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod spec_shape_tests {
    // These lock the 1.5.0 wire shapes this crate was realigned to (commit that repaired the
    // 1.4.x drift). The spec-drift CI job only checks the committed openapi.json's VERSION string;
    // it does NOT check that these structs still match the spec's schemas. Without these, a
    // rebase reintroducing a 1.4.x field, or flipping `allowed_pools` back to a non-Option Vec,
    // compiles clean and ships — exactly the regression class the realignment fixed.
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
        assert_eq!(c.token, "bbk_abc");
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
        assert_eq!(r.token.as_deref(), Some("bbk_new"));
        assert_eq!(r.secret, None);
    }
}
