//! A thin, hand-rolled admin client for the busbar gateway's `/api/v1/admin` surface.
//!
//! The request/response structs below mirror the frozen v1 contract
//! (`crates/busbar/src/admin/v1/contract`). Only the fields busbarctl actually renders are
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
            .user_agent(concat!("busbarctl/", env!("CARGO_PKG_VERSION")));

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

    /// `GET /api/v1/admin/keys` — one page (default 200). busbarctl surfaces the first page.
    pub fn list_keys(&self) -> Result<KeyPage> {
        self.get("/keys")
    }

    /// `POST /api/v1/admin/keys` — mint a key. Returns the once-shown secret.
    pub fn create_key(&self, req: &CreateKeyReq) -> Result<CreatedKeyView> {
        self.send(Method::POST, "/keys", Some(req))
    }

    /// `DELETE /api/v1/admin/keys/{id}` — revoke a key (204).
    pub fn delete_key(&self, id: &str) -> Result<()> {
        self.send_no_content(Method::DELETE, &format!("/keys/{id}"))
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

/// A virtual-key metadata row (`GET /keys` item; `key_meta()` shape).
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyView {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub allowed_pools: Vec<String>,
    #[serde(default)]
    pub max_budget_cents: Option<i64>,
    #[serde(default)]
    pub budget_period: Option<String>,
    #[serde(default)]
    pub rpm_limit: Option<u32>,
    #[serde(default)]
    pub tpm_limit: Option<u32>,
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

/// `POST /keys` request body (`CreateKeyReq`). Omitted (`None`) fields are dropped from the JSON.
#[derive(Debug, Serialize)]
pub struct CreateKeyReq {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_pools: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_budget_cents: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpm_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm_limit: Option<u32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub issue_aws_credential: bool,
}

/// `POST /keys` response (`CreatedKeyView`): key metadata + the once-shown secret (+ AWS creds).
#[derive(Debug, Deserialize, Serialize)]
pub struct CreatedKeyView {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub allowed_pools: Vec<String>,
    #[serde(default)]
    pub max_budget_cents: Option<i64>,
    #[serde(default)]
    pub budget_period: Option<String>,
    #[serde(default)]
    pub rpm_limit: Option<u32>,
    #[serde(default)]
    pub tpm_limit: Option<u32>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: u64,
    pub secret: String,
    #[serde(default)]
    pub aws_access_key_id: Option<String>,
    #[serde(default)]
    pub aws_secret_access_key: Option<String>,
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
