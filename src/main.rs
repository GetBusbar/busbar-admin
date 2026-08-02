// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! busbar-admin — a human-facing CLI for the busbar gateway's admin API (`/api/v1/admin`).
//!
//! Config resolution is CLI flag > env var > a clear error. The thin admin client lives in
//! [`client`]; this module is the clap surface + human/JSON rendering.

mod client;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use client::{Client, CreateKeyReq, InstallPluginReq, KeyView, PluginView, Tls};

/// Resolve the three distinct `allowed_pools` states the server understands: omitted (`None`) =
/// ALL pools; an explicit empty list (`--no-pools`) = NO pools; a non-empty list = exactly those.
/// A shared function so `cmd_keys_create` and its test exercise the SAME mapping — collapsing
/// `--no-pools` into `None` would mint an all-pools key when no-pools was asked for (fail-open on
/// privilege).
fn resolve_allowed_pools(no_pools: bool, pools: &[String]) -> Option<Vec<String>> {
    if no_pools {
        Some(Vec::new())
    } else if pools.is_empty() {
        None
    } else {
        Some(pools.to_vec())
    }
}

/// busbar-admin — talk to a busbar gateway's admin API.
#[derive(Parser)]
#[command(name = "busbar-admin", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: GlobalOpts,

    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct GlobalOpts {
    /// Gateway base URL, e.g. http://localhost:8081 (or $BUSBAR_ENDPOINT).
    #[arg(long, global = true, env = "BUSBAR_ENDPOINT")]
    endpoint: Option<String>,

    /// Admin token, sent as `x-admin-token` (or $BUSBAR_ADMIN_TOKEN).
    #[arg(
        long,
        global = true,
        env = "BUSBAR_ADMIN_TOKEN",
        hide_env_values = true
    )]
    token: Option<String>,

    /// Skip TLS certificate verification (DEV ONLY).
    #[arg(long, global = true)]
    insecure: bool,

    /// Trust a private admin CA (PEM file) for TLS verification.
    #[arg(long, global = true, value_name = "PATH")]
    ca_cert: Option<std::path::PathBuf>,

    /// Client certificate (PEM) for mTLS. Requires --client-key.
    #[arg(long, global = true, value_name = "PATH")]
    client_cert: Option<std::path::PathBuf>,

    /// Client private key (PEM) for mTLS. Requires --client-cert.
    #[arg(long, global = true, value_name = "PATH")]
    client_key: Option<std::path::PathBuf>,

    /// Emit raw JSON instead of a human table/summary.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Gateway version, uptime, topology, and build modules (GET /info).
    Info,

    /// Manage governance virtual keys.
    #[command(subcommand)]
    Keys(KeysCmd),

    /// Inspect registered hooks.
    #[command(subcommand)]
    Hooks(HooksCmd),

    /// Inspect / manage the running config.
    #[command(subcommand)]
    Config(ConfigCmd),

    /// Inspect and manage plugins (auth / hooks / store).
    #[command(subcommand)]
    Plugins(PluginsCmd),
}

#[derive(Subcommand)]
enum KeysCmd {
    /// List virtual keys (first page).
    List,
    /// Mint a new virtual key. The signed token is shown ONCE.
    Create(KeyCreateArgs),
    /// Show one key's metadata (never the secret).
    Get {
        /// The virtual-key id (e.g. vk_0123456789abcdef).
        id: String,
    },
    /// Rotate a key: mint a fresh credential in place (shown once); the old stops resolving.
    Rotate {
        /// The virtual-key id.
        id: String,
    },
    /// Revoke a key: denylist it durably WITHOUT deleting the record (POST /keys/{id}/revoke).
    Revoke {
        /// The virtual-key id (e.g. vk_0123456789abcdef).
        id: String,
    },
    /// Delete a key: revoke AND forget it (tombstone; DELETE /keys/{id}).
    Delete {
        /// The virtual-key id.
        id: String,
    },
}

#[derive(Args)]
struct KeyCreateArgs {
    /// Human-readable label for the key.
    name: String,
    /// Bind the key to this `groups:` bucket (budgets/limits flow through the group).
    #[arg(long)]
    group: Option<String>,
    /// Auto-provision --group as a leaf under this EXISTING parent group if it doesn't exist.
    #[arg(long, requires = "group")]
    parent: Option<String>,
    /// Token lifetime as a duration string (e.g. 7d, 24h, 30m, 3600s).
    #[arg(long, value_name = "DURATION", conflicts_with = "expires_at")]
    expires_in: Option<String>,
    /// Token expiry as an absolute Unix-seconds timestamp.
    #[arg(long, value_name = "EPOCH_SECS")]
    expires_at: Option<u64>,
    /// Mint-time metric label (repeatable): KEY=VALUE.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    labels: Vec<String>,
    /// Restrict the key to these pools (repeatable). Omit to allow all.
    #[arg(long = "allowed-pool", value_name = "POOL")]
    allowed_pools: Vec<String>,
    /// Mint a key allowed on NO pools (an explicit empty allow-list, distinct from omitting
    /// --allowed-pool which allows ALL pools). Use for a placeholder/audit-only credential.
    #[arg(long, conflicts_with = "allowed_pools")]
    no_pools: bool,
    /// Also issue an AWS SigV4 credential (AccessKeyId + secret, shown once).
    #[arg(long)]
    issue_aws_credential: bool,
}

#[derive(Subcommand)]
enum PluginsCmd {
    /// List the plugin catalog for one plugin type.
    List {
        /// Plugin type: auth | hooks | store.
        #[arg(long = "type", value_name = "TYPE", default_value = "store")]
        plugin_type: String,
    },
    /// Install a signed plugin tarball (.tar.gz). The engine re-verifies the signature.
    Install {
        /// Path to the signed plugin tarball.
        tarball: std::path::PathBuf,
        /// Filename to store the artifact under (defaults to the tarball's basename).
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Re-scan the plugins directory and show the reconciled inventory.
    Reload,
}

#[derive(Subcommand)]
enum HooksCmd {
    /// List registered hooks and their transports.
    List,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Show the current config version (and persistence flag).
    Version,
    /// Show the effective running config (GET /config).
    Show,
    /// Apply a full config from a JSON file (POST /config/apply).
    Apply {
        /// Path to a JSON file: {"config": {...}, "providers": {...}}.
        file: std::path::PathBuf,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let g = &cli.global;

    let endpoint = g.endpoint.clone().context(
        "no endpoint: pass --endpoint or set BUSBAR_ENDPOINT (e.g. http://localhost:8081)",
    )?;
    let token = g
        .token
        .clone()
        .context("no admin token: pass --token or set BUSBAR_ADMIN_TOKEN")?;

    let tls = Tls {
        insecure: g.insecure,
        ca_cert: g.ca_cert.clone(),
        client_cert: g.client_cert.clone(),
        client_key: g.client_key.clone(),
    };
    let c = Client::new(&endpoint, &token, tls)?;
    let json = g.json;

    match &cli.command {
        Command::Info => cmd_info(&c, json),
        Command::Keys(k) => match k {
            KeysCmd::List => cmd_keys_list(&c, json),
            KeysCmd::Create(a) => cmd_keys_create(&c, a, json),
            KeysCmd::Get { id } => cmd_keys_get(&c, id, json),
            KeysCmd::Rotate { id } => cmd_keys_rotate(&c, id, json),
            KeysCmd::Revoke { id } => cmd_keys_revoke(&c, id, json),
            KeysCmd::Delete { id } => cmd_keys_delete(&c, id, json),
        },
        Command::Hooks(h) => match h {
            HooksCmd::List => cmd_hooks_list(&c, json),
        },
        Command::Config(cfg) => match cfg {
            ConfigCmd::Version => cmd_config_version(&c, json),
            ConfigCmd::Show => cmd_config_show(&c, json),
            ConfigCmd::Apply { file } => cmd_config_apply(&c, file, json),
        },
        Command::Plugins(p) => match p {
            PluginsCmd::List { plugin_type } => cmd_plugins_list(&c, plugin_type, json),
            PluginsCmd::Install { tarball, file } => {
                cmd_plugins_install(&c, tarball, file.as_deref(), json)
            }
            PluginsCmd::Reload => cmd_plugins_reload(&c, json),
        },
    }
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn cmd_info(c: &Client, json: bool) -> Result<()> {
    let info = c.info()?;
    if json {
        return print_json(&info);
    }
    println!("busbar {}", info.version);
    match info.uptime_seconds {
        Some(s) => println!("  uptime:           {}", human_duration(s)),
        None => println!("  uptime:           (unknown)"),
    }
    println!("  config version:   {}", info.config_version);
    println!(
        "  config persist:   {}",
        if info.config_persistence {
            "on (durable)"
        } else {
            "off (live-only)"
        }
    );
    println!(
        "  topology:         {} pools, {} models, {} providers",
        info.topology.pools, info.topology.models, info.topology.providers
    );
    let am = if info.build.auth_modules.is_empty() {
        "(none)".to_string()
    } else {
        info.build.auth_modules.join(", ")
    };
    let hp = if info.build.hook_plugins.is_empty() {
        "(none)".to_string()
    } else {
        info.build.hook_plugins.join(", ")
    };
    println!("  auth modules:     {am}");
    println!("  hook plugins:     {hp}");
    println!("  weighted floor:   {}", info.build.weighted_floor);
    Ok(())
}

fn cmd_keys_list(c: &Client, json: bool) -> Result<()> {
    let page = c.list_keys()?;
    if json {
        return print_json(&page);
    }
    if page.items.is_empty() {
        println!("no virtual keys");
        return Ok(());
    }
    println!(
        "{:<22} {:<20} {:<16} {:<10} {:<12} ENABLED",
        "ID", "NAME", "GROUP", "STATE", "POOLS"
    );
    for k in &page.items {
        println!(
            "{:<22} {:<20} {:<16} {:<10} {:<12} {}",
            k.id,
            truncate(&k.name, 20),
            truncate(k.group.as_deref().unwrap_or("-"), 16),
            if k.state.is_empty() { "-" } else { &k.state },
            pools_summary(&k.allowed_pools),
            k.enabled,
        );
    }
    if page.next_cursor.is_some() {
        println!("(more keys available — showing the first page)");
    }
    Ok(())
}

fn parse_labels(pairs: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow::anyhow!("--label must be KEY=VALUE, got {p:?}"))
        })
        .collect()
}

fn pools_summary(pools: &Option<Vec<String>>) -> String {
    match pools {
        None => "(all)".into(),
        Some(p) if p.is_empty() => "(none)".into(),
        Some(p) => truncate(&p.join(","), 12),
    }
}

fn cmd_keys_create(c: &Client, a: &KeyCreateArgs, json: bool) -> Result<()> {
    let req = CreateKeyReq {
        name: a.name.clone(),
        // Three distinct states the server understands: omitted (None) = ALL pools;
        // explicit [] (--no-pools) = NO pools; a non-empty list = exactly those. Collapsing
        // --no-pools into None would silently mint an ALL-pools key when NO pools was asked for
        // (a fail-open on privilege), so the empty list must survive as Some(vec![]).
        allowed_pools: resolve_allowed_pools(a.no_pools, &a.allowed_pools),
        group: a.group.clone(),
        parent: a.parent.clone(),
        expires_in: a.expires_in.clone(),
        expires_at: a.expires_at,
        labels: parse_labels(&a.labels)?,
        issue_aws_credential: a.issue_aws_credential,
    };
    let created = c.create_key(&req)?;
    if json {
        return print_json(&created);
    }
    println!("created key {} ({})", created.id, created.name);
    if let Some(g) = &created.group {
        println!(
            "  group: {g}{}",
            if created.group_provisioned {
                "  (auto-provisioned)"
            } else {
                ""
            }
        );
    }
    println!("  expires_at: {} (unix seconds)", created.expires_at);
    println!();
    println!("  ┌─────────────────────────────────────────────────────────────┐");
    println!("  │  TOKEN (shown once — store it now, it cannot be retrieved)  │");
    println!("  └─────────────────────────────────────────────────────────────┘");
    println!("  token: {}", created.token);
    if let Some(id) = &created.aws_access_key_id {
        println!("  aws_access_key_id:     {id}");
    }
    if let Some(sk) = &created.aws_secret_access_key {
        println!("  aws_secret_access_key: {sk}  (shown once)");
    }
    Ok(())
}

fn cmd_keys_get(c: &Client, id: &str, json: bool) -> Result<()> {
    let k: KeyView = c.get_key(id)?;
    if json {
        return print_json(&k);
    }
    println!("key {} ({})", k.id, k.name);
    println!(
        "  state:      {}",
        if k.state.is_empty() { "-" } else { &k.state }
    );
    println!("  enabled:    {}", k.enabled);
    println!("  group:      {}", k.group.as_deref().unwrap_or("(none)"));
    println!(
        "  pools:      {}",
        match &k.allowed_pools {
            None => "(all)".to_string(),
            Some(p) if p.is_empty() => "(none)".to_string(),
            Some(p) => p.join(", "),
        }
    );
    println!("  created_at: {}", k.created_at);
    if !k.labels.is_empty() {
        let labels: Vec<String> = k.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!("  labels:     {}", labels.join(", "));
    }
    Ok(())
}

fn cmd_keys_rotate(c: &Client, id: &str, json: bool) -> Result<()> {
    let rotated = c.rotate_key(id)?;
    if json {
        return print_json(&rotated);
    }
    println!("rotated key {} ({})", rotated.id, rotated.name);
    println!();
    println!("  ┌─────────────────────────────────────────────────────────────────┐");
    println!("  │  NEW CREDENTIAL (shown once — the old one no longer resolves)  │");
    println!("  └─────────────────────────────────────────────────────────────────┘");
    if let Some(t) = &rotated.token {
        println!("  token: {t}");
        if let Some(exp) = rotated.expires_at {
            println!("  expires_at: {exp} (unix seconds)");
        }
    }
    if let Some(s) = &rotated.secret {
        println!("  secret: {s}");
    }
    Ok(())
}

fn cmd_keys_revoke(c: &Client, id: &str, json: bool) -> Result<()> {
    let v = c.revoke_key(id)?;
    if json {
        return print_json(&v);
    }
    println!(
        "revoked key {} (denylisted; the record remains for audit)",
        v.revoked
    );
    Ok(())
}

fn cmd_keys_delete(c: &Client, id: &str, json: bool) -> Result<()> {
    c.delete_key(id)?;
    if json {
        return print_json(&serde_json::json!({"deleted": id}));
    }
    println!("deleted key {id} (revoked and tombstoned)");
    Ok(())
}

fn cmd_plugins_list(c: &Client, plugin_type: &str, json: bool) -> Result<()> {
    let page = c.list_plugins(plugin_type)?;
    if json {
        return print_json(&page);
    }
    if page.items.is_empty() {
        println!("no {plugin_type} plugins");
        return Ok(());
    }
    print_plugin_rows(&page.items);
    if page.next_cursor.is_some() {
        println!("(more {plugin_type} plugins available — showing the first page)");
    }
    Ok(())
}

fn print_plugin_rows(items: &[PluginView]) {
    println!(
        "{:<20} {:<7} {:<12} {:<8} {:<10} {:<10} FILE",
        "NAME", "TYPE", "LOADER", "ACTIVE", "VERSION", "TRUST"
    );
    for p in items {
        println!(
            "{:<20} {:<7} {:<12} {:<8} {:<10} {:<10} {}",
            truncate(&p.name, 20),
            p.plugin_type,
            p.loader,
            opt(p.active),
            p.version.as_deref().unwrap_or("-"),
            p.trust.as_deref().unwrap_or("-"),
            p.file.as_deref().unwrap_or("-"),
        );
    }
}

fn cmd_plugins_install(
    c: &Client,
    tarball: &std::path::Path,
    file: Option<&str>,
    json: bool,
) -> Result<()> {
    use base64::Engine as _;
    let bytes = std::fs::read(tarball)
        .with_context(|| format!("reading plugin tarball {}", tarball.display()))?;
    let file = match file {
        Some(f) => f.to_string(),
        None => tarball
            .file_name()
            .and_then(|f| f.to_str())
            .context("tarball path has no usable filename; pass --file")?
            .to_string(),
    };
    let req = InstallPluginReq {
        file,
        tarball_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
    };
    let installed = c.install_plugin(&req)?;
    if json {
        return print_json(&installed);
    }
    println!(
        "installed {} (plugin {} v{}, trust: {})",
        installed.file,
        installed.name,
        installed.version.as_deref().unwrap_or("?"),
        installed.trust,
    );
    if !installed.note.is_empty() {
        println!("note: {}", installed.note);
    }
    Ok(())
}

fn cmd_plugins_reload(c: &Client, json: bool) -> Result<()> {
    let v = c.reload_plugins()?;
    if json {
        return print_json(&v);
    }
    if v.plugins.is_empty() {
        println!("no dynamic-library plugins in the plugins directory");
    } else {
        print_plugin_rows(&v.plugins);
    }
    if !v.note.is_empty() {
        println!("note: {}", v.note);
    }
    Ok(())
}

fn cmd_hooks_list(c: &Client, json: bool) -> Result<()> {
    let page = c.list_hooks()?;
    if json {
        return print_json(&page);
    }
    if page.items.is_empty() {
        println!("no hooks registered");
        return Ok(());
    }
    println!(
        "{:<20} {:<6} {:<8} {:<8} {:<7} TARGET",
        "NAME", "KIND", "TRANSPORT", "PROMPT", "GLOBAL"
    );
    for h in &page.items {
        println!(
            "{:<20} {:<6} {:<8} {:<8} {:<7} {}",
            truncate(&h.name, 20),
            h.kind,
            h.transport.kind,
            h.prompt,
            h.global,
            h.transport.target.as_deref().unwrap_or("-"),
        );
    }
    if page.next_cursor.is_some() {
        println!("(more hooks available — showing the first page)");
    }
    Ok(())
}

fn cmd_config_version(c: &Client, json: bool) -> Result<()> {
    // config_version + persistence come from /info (the drift-detection markers).
    let info = c.info()?;
    if json {
        return print_json(&serde_json::json!({
            "config_version": info.config_version,
            "config_persistence": info.config_persistence,
        }));
    }
    println!("config version: {}", info.config_version);
    println!(
        "persistence:    {}",
        if info.config_persistence {
            "on (durable across restart)"
        } else {
            "off (live-only)"
        }
    );
    Ok(())
}

fn cmd_config_show(c: &Client, json: bool) -> Result<()> {
    let cfg = c.config()?;
    if json {
        return print_json(&cfg);
    }
    // The effective config is a rich nested doc; pretty-print it (it carries no secrets).
    print_json(&cfg)
}

fn cmd_config_apply(c: &Client, file: &std::path::Path, json: bool) -> Result<()> {
    let raw = std::fs::read_to_string(file)
        .with_context(|| format!("reading config file {}", file.display()))?;
    let body: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as JSON", file.display()))?;
    let resp = c.config_apply(&body)?;
    if json {
        print_json(&resp)?;
    }
    // The server signals ACCEPTED-BUT-NOT-APPLIED in-band via `applied: false` on a 200 — a soft
    // failure the HTTP status alone doesn't convey. A scriptable caller (`... && echo ok`) must
    // see a nonzero exit here, not a "config applied" success line.
    if !resp.applied {
        anyhow::bail!(
            "gateway did NOT apply the config (applied=false){}",
            if resp.note.is_empty() {
                String::new()
            } else {
                format!(": {}", resp.note)
            }
        );
    }
    if !json {
        println!("config applied — now at version {}", resp.config_version);
        if !resp.note.is_empty() {
            println!("note: {}", resp.note);
        }
    }
    Ok(())
}

// ── small render helpers ─────────────────────────────────────────────────────────────────────

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn human_duration(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 {
        parts.push(format!("{m}m"));
    }
    parts.push(format!("{s}s"));
    parts.join(" ")
}

#[cfg(test)]
mod cli_logic_tests {
    use super::*;

    #[test]
    fn parse_labels_splits_on_first_equals_only() {
        // A value containing '=' (a URL query string, a base64 pad) must survive intact — the
        // split is on the FIRST '=', not all of them.
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

    // Calls the REAL `resolve_allowed_pools` that `cmd_keys_create` uses — not a copy — so a
    // regression in the actual fail-open-on-privilege mapping fails this test. (The round-1
    // version tested a duplicated helper and was tautological: it passed even if the real code
    // regressed.)
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
}
