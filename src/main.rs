// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! busbarctl — a human-facing CLI for the busbar gateway's admin API (`/api/v1/admin`).
//!
//! Config resolution is CLI flag > env var > a clear error. The thin admin client lives in
//! [`client`]; this module is the clap surface + human/JSON rendering.

mod client;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use client::{Client, CreateKeyReq, Tls};

/// busbarctl — talk to a busbar gateway's admin API.
#[derive(Parser)]
#[command(name = "busbarctl", version, about, long_about = None)]
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
}

#[derive(Subcommand)]
enum KeysCmd {
    /// List virtual keys (first page).
    List,
    /// Mint a new virtual key. The plaintext secret is shown ONCE.
    Create(KeyCreateArgs),
    /// Revoke (delete) a virtual key by id.
    Revoke {
        /// The virtual-key id (e.g. vk_0123456789abcdef).
        id: String,
    },
}

#[derive(Args)]
struct KeyCreateArgs {
    /// Human-readable label for the key.
    name: String,
    /// Budget cap in cents (omit for unlimited).
    #[arg(long)]
    budget_cents: Option<i64>,
    /// Budget period: total | daily | monthly.
    #[arg(long)]
    budget_period: Option<String>,
    /// Requests-per-minute limit (omit for unlimited).
    #[arg(long)]
    rpm: Option<u32>,
    /// Tokens-per-minute limit (omit for unlimited).
    #[arg(long)]
    tpm: Option<u32>,
    /// Restrict the key to these pools (repeatable). Omit to allow all.
    #[arg(long = "allowed-pool", value_name = "POOL")]
    allowed_pools: Vec<String>,
    /// Also issue an AWS SigV4 credential (AccessKeyId + secret, shown once).
    #[arg(long)]
    issue_aws_credential: bool,
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
            KeysCmd::Revoke { id } => cmd_keys_revoke(&c, id, json),
        },
        Command::Hooks(h) => match h {
            HooksCmd::List => cmd_hooks_list(&c, json),
        },
        Command::Config(cfg) => match cfg {
            ConfigCmd::Version => cmd_config_version(&c, json),
            ConfigCmd::Show => cmd_config_show(&c, json),
            ConfigCmd::Apply { file } => cmd_config_apply(&c, file, json),
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
        "{:<22} {:<20} {:>8} {:<8} {:>6} {:>6} ENABLED",
        "ID", "NAME", "BUDGET¢", "PERIOD", "RPM", "TPM"
    );
    for k in &page.items {
        println!(
            "{:<22} {:<20} {:>8} {:<8} {:>6} {:>6} {}",
            k.id,
            truncate(&k.name, 20),
            opt(k.max_budget_cents),
            k.budget_period.as_deref().unwrap_or("-"),
            opt(k.rpm_limit),
            opt(k.tpm_limit),
            k.enabled,
        );
    }
    if page.next_cursor.is_some() {
        println!("(more keys available — showing the first page)");
    }
    Ok(())
}

fn cmd_keys_create(c: &Client, a: &KeyCreateArgs, json: bool) -> Result<()> {
    let req = CreateKeyReq {
        name: a.name.clone(),
        allowed_pools: a.allowed_pools.clone(),
        max_budget_cents: a.budget_cents,
        budget_period: a.budget_period.clone(),
        rpm_limit: a.rpm,
        tpm_limit: a.tpm,
        issue_aws_credential: a.issue_aws_credential,
    };
    let created = c.create_key(&req)?;
    if json {
        return print_json(&created);
    }
    println!("created key {} ({})", created.id, created.name);
    println!();
    println!("  ┌────────────────────────────────────────────────────────────┐");
    println!("  │  SECRET (shown once — store it now, it cannot be retrieved)  │");
    println!("  └────────────────────────────────────────────────────────────┘");
    println!("  secret: {}", created.secret);
    if let Some(id) = &created.aws_access_key_id {
        println!("  aws_access_key_id:     {id}");
    }
    if let Some(sk) = &created.aws_secret_access_key {
        println!("  aws_secret_access_key: {sk}  (shown once)");
    }
    Ok(())
}

fn cmd_keys_revoke(c: &Client, id: &str, json: bool) -> Result<()> {
    c.delete_key(id)?;
    if json {
        return print_json(&serde_json::json!({"revoked": id}));
    }
    println!("revoked key {id}");
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
        return print_json(&resp);
    }
    let v = resp
        .get("config_version")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "?".into());
    println!("config applied — now at version {v}");
    if let Some(note) = resp.get("note").and_then(|n| n.as_str()) {
        println!("note: {note}");
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
