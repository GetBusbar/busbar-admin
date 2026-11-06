//! A thin, hand-rolled admin client for the busbar gateway's `/api/v1/admin` surface.
//!
//! The request/response structs below mirror the frozen v1 contract
//! (`crates/busbar/src/admin/v1/contract`; the committed `openapi.json` at the repo root is the
//! canonical spec this client is audited against, refreshed from core's generated document). The
//! audit is not a one-off: `spec_contract_tests` below re-runs it on every `cargo test`, against
//! the committed spec locally and against core's PAIRED spec in CI, so a shape change made under
//! an unchanged version stamp cannot pass unnoticed. Only the fields busbar-admin renders are
//! modelled; unknown fields are ignored (the contract is additive-only), so a newer gateway never
//! breaks an older CLI. To add an endpoint: add a typed response struct and a method on
//! [`Client`] that calls [`Client::get`] / [`Client::send`] with the relative path — every method
//! funnels through those two seams for uniform auth, TLS, and error mapping.

use std::io::Read as _;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub(crate) fn read_local(
    path: &std::path::Path,
    limit: u64,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("opening {label} {}", path.display()))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    anyhow::ensure!(
        bytes.len() as u64 <= limit,
        "{label} exceeds its {limit}-byte limit"
    );
    Ok(bytes)
}

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
        let parsed = reqwest::Url::parse(endpoint)
            .map_err(|_| anyhow!("endpoint must be a valid HTTP(S) URL"))?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https")
                && parsed.host_str().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "endpoint must be HTTP(S), without userinfo, query or fragment"
        );
        anyhow::ensure!(
            !token.is_empty() && !token.chars().any(char::is_control),
            "admin token must be nonempty and contain no control characters"
        );
        let endpoint = parsed.as_str().trim_end_matches('/').to_string();
        let base = format!("{endpoint}{ADMIN_PREFIX}");

        let mut headers = HeaderMap::new();
        let mut tok = HeaderValue::from_str(token)
            .context("admin token contains characters invalid for an HTTP header")?;
        tok.set_sensitive(true);
        headers.insert(X_ADMIN_TOKEN, tok.clone());
        // Send both carriers; the gateway accepts either.
        let mut bearer = HeaderValue::from_str(&Zeroizing::new(format!("Bearer {token}")))
            .context("admin token contains characters invalid for an HTTP header")?;
        bearer.set_sensitive(true);
        headers.insert(AUTHORIZATION, bearer);

        let mut builder = HttpClient::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            // Never follow redirects. The admin token rides as the custom `x-admin-token` header,
            // and reqwest strips `Authorization` across a cross-origin redirect but NOT custom
            // headers — so a malicious or MITM'd 3xx to another host would exfiltrate the token.
            // A CLI talking to one admin endpoint has no legitimate reason to follow a redirect.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("busbar-admin/", env!("CARGO_PKG_VERSION")));

        if tls.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(ca) = &tls.ca_cert {
            let pem = read_local(ca, 1024 * 1024, "--ca-cert")?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .with_context(|| format!("parsing --ca-cert {} as PEM", ca.display()))?;
            builder = builder.add_root_certificate(cert);
        }
        match (&tls.client_cert, &tls.client_key) {
            (Some(cert), Some(key)) => {
                let mut pem = read_local(cert, 1024 * 1024, "--client-cert")?;
                let keypem = read_local(key, 1024 * 1024, "--client-key")?;
                pem.push(b'\n');
                pem.extend_from_slice(&keypem);
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
        let e = e.without_url();
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

    /// Report HTTP status without echoing untrusted response bodies; 401/403 get dedicated hints.
    fn check_status(&self, resp: Response) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let msg = match status {
            StatusCode::UNAUTHORIZED => format!("admin token rejected ({status})"),
            StatusCode::FORBIDDEN => format!("admin token lacks the required scope ({status})"),
            _ => format!("gateway returned {status}; response body withheld because it may contain credentials"),
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

    /// Decode a JSON body. The error NEVER carries the body or serde's own message: a mint or
    /// rotate body holds a once-shown credential, and serde quotes the offending value
    /// (`invalid type: string "…"`). Only the error class, its position and the body length are
    /// reported, which is enough to diagnose a version skew without printing a secret.
    fn decode<T: DeserializeOwned>(resp: Response) -> Result<T> {
        let body = Self::read_body(resp)?;
        serde_json::from_slice(&body).map_err(|e| {
            let class = match e.classify() {
                serde_json::error::Category::Io => "an I/O error",
                serde_json::error::Category::Syntax => "invalid JSON",
                serde_json::error::Category::Data => "an unexpected shape",
                serde_json::error::Category::Eof => "a truncated body",
            };
            anyhow!(
                "decoding the gateway response: {class} at line {} column {} ({} bytes; the body \
                 is withheld because it may carry a credential)",
                e.line(),
                e.column(),
                body.len()
            )
        })
    }

    fn read_body(resp: Response) -> Result<Zeroizing<Vec<u8>>> {
        const LIMIT: u64 = 32 * 1024 * 1024;
        anyhow::ensure!(
            resp.content_length().is_none_or(|n| n <= LIMIT),
            "gateway response exceeds the 32 MiB limit"
        );
        let mut body = Zeroizing::new(Vec::new());
        resp.take(LIMIT + 1)
            .read_to_end(&mut body)
            .map_err(|_| anyhow!("reading the gateway response body failed"))?;
        anyhow::ensure!(
            body.len() as u64 <= LIMIT,
            "gateway response exceeds the 32 MiB limit"
        );
        Ok(body)
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

    fn key_path(id: &str, suffix: &str) -> Result<String> {
        anyhow::ensure!(
            !id.is_empty() && !matches!(id, "." | ".."),
            "key id must be a nonempty identifier, not a dot path segment"
        );
        let mut url = reqwest::Url::parse("http://localhost/keys/")?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("cannot construct key path"))?
            .pop_if_empty()
            .push(id);
        Ok(format!("{}{suffix}", url.path()))
    }

    /// `GET /api/v1/admin/keys/{id}` — one key's metadata (never the secret).
    pub fn get_key(&self, id: &str) -> Result<KeyView> {
        self.get(&Self::key_path(id, "")?)
    }

    /// `POST /api/v1/admin/keys/{id}/revoke` — durably denylist a key WITHOUT deleting the
    /// binding (the record stays visible for audit/usage attribution). Idempotent.
    pub fn revoke_key(&self, id: &str) -> Result<RevokeView> {
        self.send(Method::POST, &Self::key_path(id, "/revoke")?, None::<&()>)
    }

    /// `POST /api/v1/admin/keys/{id}/rotate` — mint a fresh credential in place (same id,
    /// budgets, usage). The new token/secret is shown once.
    pub fn rotate_key(&self, id: &str) -> Result<RotatedKeyView> {
        self.send(Method::POST, &Self::key_path(id, "/rotate")?, None::<&()>)
    }

    /// `DELETE /api/v1/admin/keys/{id}` — revoke AND forget (tombstone) a key (204).
    pub fn delete_key(&self, id: &str) -> Result<()> {
        self.send_no_content(Method::DELETE, &Self::key_path(id, "")?)
    }

    /// `GET /api/v1/admin/plugins?type=` — the plugin catalog for one plugin type
    /// (`auth` | `hooks` | `store`).
    pub fn list_plugins(&self, plugin_type: &str) -> Result<PluginPage> {
        let resp = self.execute(
            self.http
                .get(self.url("/plugins"))
                .query(&[("type", plugin_type)]),
        )?;
        Self::decode(resp)
    }

    /// `POST /api/v1/admin/plugins` — install a signed plugin tarball (bytes ride as base64;
    /// the engine re-verifies the signed manifest server-side).
    pub fn install_plugin(&self, req: &InstallPluginReq) -> Result<PluginInstallView> {
        self.send(Method::POST, "/plugins", Some(req))
    }

    /// `POST /api/v1/admin/plugins/inspect` — STATELESS preview of a candidate plugin tarball
    /// (bytes ride as base64). The engine verifies the signature and parses the manifest WITHOUT
    /// installing anything, returning the manifest's settings schema plus name/version/kind/trust.
    /// An untrusted/rejected candidate is reported (via `trust`), never refused.
    pub fn inspect_plugin(&self, req: &InspectPluginReq) -> Result<InspectView> {
        self.send(Method::POST, "/plugins/inspect", Some(req))
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
    pub fn config_apply(&self, body: &serde_json::Value) -> Result<ConfigApplyView> {
        self.send(Method::POST, "/config/apply", Some(body))
    }
}

/// `POST /config/apply` response (`ConfigApplyView`). `applied` is REQUIRED by the 1.5.2 contract
/// and carries the in-band success signal: a 200 with `applied: false` is an ACCEPTED-BUT-NOT-
/// APPLIED soft failure (the HTTP status alone does not tell the whole story), so a scriptable
/// caller must branch on it rather than treat any 2xx as success.
#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigApplyView {
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reload_to_apply: Vec<String>,
    #[serde(default)]
    pub config_version: u64,
    #[serde(default)]
    pub note: String,
}

// ── Contract-mirroring request/response types ────────────────────────────────────────────────

/// A once-shown credential the gateway minted (a signed token, an AWS secret, a legacy secret).
///
/// It (de)serializes as the bare string, so `--json` output stays byte-identical, but its `Debug`
/// prints `<redacted>` and it has no `Display`: rendering it takes an explicit [`Secret::expose`].
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// The credential itself. Every call site is a deliberate print or write of the secret.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_string())
    }
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
    /// Opaque identity of this process, stable across reload and absent on older servers.
    #[serde(default)]
    pub process_boot_nonce: Option<String>,
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
    pub token: Secret,
    /// Unix-seconds expiry of the signed token.
    #[serde(default)]
    pub expires_at: u64,
    /// Whether this mint auto-provisioned its bound group leaf.
    #[serde(default)]
    pub group_provisioned: bool,
    #[serde(default)]
    pub aws_access_key_id: Option<String>,
    #[serde(default)]
    pub aws_secret_access_key: Option<Secret>,
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
    pub token: Option<Secret>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub secret: Option<Secret>,
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
    /// For a dynamic-library plugin, its NAME — NOT a socket path or URL (that was the retired
    /// 1.4.x transport target). `null` for a compiled-in row.
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    /// SHA-256 of the complete installed archive bytes, when supplied by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_sha256: Option<String>,
    /// The C-ABI version the manifest declares — the operator-facing name for the ABI the engine
    /// speaks. `null` for a compiled-in row or a plugin with no manifest.
    #[serde(default)]
    pub interface_version: Option<u32>,
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
    /// The C-ABI version the installed manifest declares (see [`PluginView::interface_version`]).
    #[serde(default)]
    pub interface_version: Option<u32>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub trust: String,
    #[serde(default)]
    pub note: String,
}

/// `POST /plugins/inspect` request body (`InspectPluginReq`): SAME shape as `InstallPluginReq`
/// (`file` + `tarball_b64`). Inspect never writes to disk, so `file` is accepted only for shape
/// parity with the install flow and is otherwise unused server-side.
#[derive(Debug, Serialize)]
pub struct InspectPluginReq {
    pub file: String,
    pub tarball_b64: String,
}

/// `POST /plugins/inspect` response (`PluginSchemaView`): a stateless preview of the candidate's
/// signed manifest — the same shape `GET /plugins/{file}/schema` carries, plus `version`/`kind`.
/// `schema_error` is set (distinctly from a bare `schema: null`) only when the manifest DID set a
/// `settings_schema` that failed to parse. Only the fields busbar-admin renders are modelled.
#[derive(Debug, Deserialize, Serialize)]
pub struct InspectView {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    /// The plugin's `kind` (`hook` | `secret` | `auth` | `store` | …); `null` when the candidate
    /// cannot be resolved to a manifest.
    #[serde(default)]
    pub kind: Option<String>,
    /// `trusted` | `unverified` | `rejected` (the plugin-catalog trust vocabulary).
    pub trust: String,
    /// Server-reported provenance: describe, statement, manifest, or installed_archive.
    #[serde(default)]
    pub source: String,
    /// Explicit installed-archive lookup identity; absent on ordinary inspection/loaded reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_state: Option<String>,
    /// The kind-derived restart-scoping default; `null` when there is no resolvable manifest/kind.
    #[serde(default)]
    pub restart_required_default: Option<bool>,
    /// The plugin's settings JSON Schema verbatim, or `null` (no schema, or one that failed to
    /// parse — see `schema_error`).
    #[serde(default)]
    pub schema: Option<serde_json::Value>,
    /// Set only when the manifest's `settings_schema` was present but failed to parse.
    #[serde(default)]
    pub schema_error: Option<String>,
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
    pub on_error: String,
    /// Authored empty-ranking policy; null preserves the omitted policy.
    #[serde(default)]
    pub on_empty: Option<String>,
    /// Authored signal names, preserving their configured order.
    #[serde(default)]
    pub signals: Vec<String>,
    /// Whether this hook is the configured default.
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub timeout_ms: u64,
    /// The KEY NAMES of the hook's opaque `settings:` bag, sorted, WITHOUT their values.
    ///
    /// This field USED to be the bag itself. A hook's settings bag is a secret-reference carrier
    /// by design and a literal credential in it is fully supported, while `GET /hooks` is served
    /// at READ-ONLY admin scope — so the gateway now projects key names only, and this client
    /// models the redacted projection. Reading the bag verbatim is not something a newer gateway
    /// will do, and this CLI must not model a shape that would invite it back.
    #[serde(default)]
    pub settings_keys: Vec<String>,
    #[serde(default)]
    pub global: bool,
    /// The `phase:` stage list as configured (empty selects the four fixed core stages).
    #[serde(default)]
    pub phase: Vec<String>,
    /// The stages the hook actually fires at, in pipeline order (the effective answer).
    #[serde(default)]
    pub fires_at: Vec<String>,
    /// The `groups:` caller scope as configured; empty means every caller.
    #[serde(default)]
    pub groups: Vec<String>,
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

/// STRUCTURAL spec-contract check — the thing the `spec-drift` CI job could not see.
///
/// `spec-drift` compares `openapi.json`'s `info.version` against the latest busbar release, so it
/// is blind to any shape change made under an UNCHANGED version stamp. That is not hypothetical:
/// core `dev` and this repo's committed copy are both stamped 1.5.2 while core has already renamed
/// the hook `settings` bag to `settings_keys` (a redaction fix) on `HookView`, `HookDesiredStatus`
/// and `HookReportedStatus`, and added `drift_keys` to `HookStatusView`. A version-only check can
/// never go red on that, and a check that cannot fail is not a check.
///
/// This module closes the gap by comparing the structs in this file against the SPEC DOCUMENT,
/// field by field, in both directions:
///
///   * **no phantom fields** — every field this client models must exist in the schema. This is
///     the anti-RENAME arm: `settings` → `settings_keys` goes red here.
///   * **no ignored REQUIRED fields** — every field the schema marks `required` must be modelled,
///     unless it is named in [`DELIBERATELY_UNRENDERED`] with a written reason. This is the
///     anti-BLIND-SPOT arm: core adding a required field this CLI silently drops goes red, and the
///     only way to quiet it is to record the decision.
///
/// The modelled field set is not a hand-maintained list — it is derived by SERIALIZING a real
/// instance of each struct, so the table cannot drift away from the types it claims to describe.
///
/// **Which document.** By default the committed `openapi.json`. Set `BUSBAR_SPEC` to a path and
/// the same assertions run against that document instead — which is how CI runs this, BLOCKING,
/// against core at the run's branch. That paired run is consumption-scoped, so core racing ahead
/// with new endpoints and new optional fields does NOT turn it red (the failure mode that forced
/// the whole-document diff to be non-blocking); only a REMOVAL, a RENAME, or a new REQUIRED field
/// this client ignores can fail it.
#[cfg(test)]
#[path = "spec_contract_tests.rs"]
mod spec_contract_tests;

#[cfg(test)]
#[path = "spec_shape_tests.rs"]
mod spec_shape_tests;

/// Credential-echo canaries (CREDENTIAL-LOCKDOWN H1, H11). Each plants a known credential where
/// the gateway would put a minted one and asserts it never reaches an error chain or a `Debug`
/// rendering — the two places a CLI's output ends up in CI logs and bug reports.
#[cfg(test)]
#[path = "credential_echo_tests.rs"]
mod credential_echo_tests;

#[cfg(test)]
#[path = "transport_tests.rs"]
mod transport_tests;
