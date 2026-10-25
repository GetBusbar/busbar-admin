// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! busbar-admin — a human-facing CLI for the busbar gateway's admin API (`/api/v1/admin`).
//!
//! Config resolution is CLI flag > env var > a clear error. The thin admin client lives in
//! [`client`]; this module is the clap surface + human/JSON rendering.

mod client;

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};

use client::{
    Client, CreateKeyReq, CreatedKeyView, InspectPluginReq, InstallPluginReq, KeyView, PluginView,
    RotatedKeyView, Tls,
};

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

    /// Read the admin token from this file (trailing newline ignored). Keeps the token out of
    /// argv (`ps`, shell history); takes precedence over $BUSBAR_ADMIN_TOKEN.
    #[arg(long, global = true, value_name = "PATH")]
    token_file: Option<std::path::PathBuf>,

    /// Write a minted or rotated credential (keys create / keys rotate) to this file (mode 0600)
    /// instead of stdout, as the full JSON view. `/dev/fd/N` writes to an inherited descriptor.
    /// Stdout then shows where the credential went in place of its value.
    #[arg(long, global = true, value_name = "PATH")]
    output_secret_to: Option<std::path::PathBuf>,

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
    /// Preview a candidate plugin tarball WITHOUT installing it (stateless): verify its
    /// signature, parse its manifest, and report its name/version/kind/trust and settings schema.
    Inspect {
        /// Path to the candidate plugin tarball (.tar.gz).
        tarball: std::path::PathBuf,
        /// Filename to report the artifact under (defaults to the tarball's basename). Unused
        /// server-side — inspect never writes to disk — but sent for shape parity with install.
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

/// Warning printed (to stderr) when the admin token arrives on the command line.
const ARGV_TOKEN_WARNING: &str = "warning: --token puts the admin token in the process list and \
shell history; prefer --token-file or BUSBAR_ADMIN_TOKEN";

/// Resolve the admin token: `--token-file` > `--token` / $BUSBAR_ADMIN_TOKEN. Returns the token
/// and whether it came from argv (the caller warns). The token-file's contents never appear in an
/// error.
fn resolve_token(
    token: Option<&str>,
    source: Option<ValueSource>,
    token_file: Option<&Path>,
) -> Result<(String, bool)> {
    let from_argv = source == Some(ValueSource::CommandLine);
    if let Some(path) = token_file {
        if from_argv {
            anyhow::bail!("--token and --token-file are mutually exclusive");
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading --token-file {}", path.display()))?;
        let tok = raw.trim_end_matches(['\r', '\n']);
        if tok.is_empty() {
            anyhow::bail!("--token-file {} is empty", path.display());
        }
        return Ok((tok.to_string(), false));
    }
    let tok = token.context("no admin token: pass --token or set BUSBAR_ADMIN_TOKEN")?;
    Ok((tok.to_string(), from_argv))
}

fn run() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let g = &cli.global;

    let endpoint = g.endpoint.clone().context(
        "no endpoint: pass --endpoint or set BUSBAR_ENDPOINT (e.g. http://localhost:8081)",
    )?;
    let (token, from_argv) = resolve_token(
        g.token.as_deref(),
        matches.value_source("token"),
        g.token_file.as_deref(),
    )?;
    if from_argv {
        eprintln!("{ARGV_TOKEN_WARNING}");
    }
    let secret_to = g.output_secret_to.as_deref();

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
            KeysCmd::Create(a) => cmd_keys_create(&c, a, json, secret_to),
            KeysCmd::Get { id } => cmd_keys_get(&c, id, json),
            KeysCmd::Rotate { id } => cmd_keys_rotate(&c, id, json, secret_to),
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
            PluginsCmd::Inspect { tarball, file } => {
                cmd_plugins_inspect(&c, tarball, file.as_deref(), json)
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

fn cmd_keys_create(
    c: &Client,
    a: &KeyCreateArgs,
    json: bool,
    secret_to: Option<&Path>,
) -> Result<()> {
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
    render_created(&created, json, secret_to, &mut std::io::stdout().lock())
}

/// The JSON object names that carry a once-shown credential in a mint or rotate view.
const SECRET_FIELDS: [&str; 3] = ["token", "aws_secret_access_key", "secret"];

/// Write the full view to the secret sink (created mode 0600 on unix; truncated if it exists).
fn write_secret_sink<T: serde::Serialize>(path: &Path, view: &T) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .with_context(|| format!("opening --output-secret-to {}", path.display()))?;
    writeln!(f, "{}", serde_json::to_string_pretty(view)?)
        .with_context(|| format!("writing --output-secret-to {}", path.display()))?;
    Ok(())
}

/// The `--json` rendering with the credential fields dropped (they went to the secret sink).
fn json_without_secrets<T: serde::Serialize>(view: &T) -> Result<serde_json::Value> {
    let mut v = serde_json::to_value(view)?;
    if let Some(o) = v.as_object_mut() {
        for k in SECRET_FIELDS {
            o.remove(k);
        }
    }
    Ok(v)
}

fn render_created(
    created: &CreatedKeyView,
    json: bool,
    secret_to: Option<&Path>,
    out: &mut dyn Write,
) -> Result<()> {
    if let Some(p) = secret_to {
        write_secret_sink(p, created)?;
    }
    if json {
        let text = match secret_to {
            None => serde_json::to_string_pretty(created)?,
            Some(_) => serde_json::to_string_pretty(&json_without_secrets(created)?)?,
        };
        writeln!(out, "{text}")?;
        return Ok(());
    }
    let shown = |v: &str| match secret_to {
        None => v.to_string(),
        Some(p) => format!("(written to {})", p.display()),
    };
    writeln!(out, "created key {} ({})", created.id, created.name)?;
    if let Some(g) = &created.group {
        writeln!(
            out,
            "  group: {g}{}",
            if created.group_provisioned {
                "  (auto-provisioned)"
            } else {
                ""
            }
        )?;
    }
    writeln!(out, "  expires_at: {} (unix seconds)", created.expires_at)?;
    writeln!(out)?;
    writeln!(
        out,
        "  ┌─────────────────────────────────────────────────────────────┐"
    )?;
    writeln!(
        out,
        "  │  TOKEN (shown once — store it now, it cannot be retrieved)  │"
    )?;
    writeln!(
        out,
        "  └─────────────────────────────────────────────────────────────┘"
    )?;
    writeln!(out, "  token: {}", shown(created.token.expose()))?;
    if let Some(id) = &created.aws_access_key_id {
        writeln!(out, "  aws_access_key_id:     {id}")?;
    }
    if let Some(sk) = &created.aws_secret_access_key {
        writeln!(
            out,
            "  aws_secret_access_key: {}  (shown once)",
            shown(sk.expose())
        )?;
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

fn cmd_keys_rotate(c: &Client, id: &str, json: bool, secret_to: Option<&Path>) -> Result<()> {
    let rotated = c.rotate_key(id)?;
    render_rotated(&rotated, json, secret_to, &mut std::io::stdout().lock())
}

fn render_rotated(
    rotated: &RotatedKeyView,
    json: bool,
    secret_to: Option<&Path>,
    out: &mut dyn Write,
) -> Result<()> {
    if let Some(p) = secret_to {
        write_secret_sink(p, rotated)?;
    }
    if json {
        let text = match secret_to {
            None => serde_json::to_string_pretty(rotated)?,
            Some(_) => serde_json::to_string_pretty(&json_without_secrets(rotated)?)?,
        };
        writeln!(out, "{text}")?;
        return Ok(());
    }
    let shown = |v: &str| match secret_to {
        None => v.to_string(),
        Some(p) => format!("(written to {})", p.display()),
    };
    writeln!(out, "rotated key {} ({})", rotated.id, rotated.name)?;
    writeln!(out)?;
    writeln!(
        out,
        "  ┌─────────────────────────────────────────────────────────────────┐"
    )?;
    writeln!(
        out,
        "  │  NEW CREDENTIAL (shown once — the old one no longer resolves)  │"
    )?;
    writeln!(
        out,
        "  └─────────────────────────────────────────────────────────────────┘"
    )?;
    if let Some(t) = &rotated.token {
        writeln!(out, "  token: {}", shown(t.expose()))?;
        if let Some(exp) = rotated.expires_at {
            writeln!(out, "  expires_at: {exp} (unix seconds)")?;
        }
    }
    if let Some(s) = &rotated.secret {
        writeln!(out, "  secret: {}", shown(s.expose()))?;
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

fn cmd_plugins_inspect(
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
    let req = InspectPluginReq {
        file,
        tarball_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
    };
    let preview = c.inspect_plugin(&req)?;
    if json {
        return print_json(&preview);
    }
    println!(
        "plugin {} v{} (kind: {}, trust: {})",
        preview.name,
        preview.version.as_deref().unwrap_or("?"),
        preview.kind.as_deref().unwrap_or("-"),
        preview.trust,
    );
    println!(
        "  restart required (default): {}",
        opt(preview.restart_required_default)
    );
    println!(
        "  settings schema: {}",
        if preview.schema.is_some() {
            "present"
        } else {
            "(none)"
        }
    );
    if let Some(err) = &preview.schema_error {
        println!("  schema error: {err}");
    }
    println!("(preview only — nothing was installed)");
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

    // Calls the REAL `resolve_allowed_pools` that `cmd_keys_create` uses, never a copy of it: a
    // test against a duplicated helper is tautological and stays green even when the shipped
    // mapping regresses.
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

    // ── credential output (CREDENTIAL-LOCKDOWN H11) ──────────────────────────────────────────

    const CANARY: &str = "bbk_CANARY_9f3c1e_do_not_print";

    fn created() -> CreatedKeyView {
        serde_json::from_str(
            r#"{"id":"vk_1","name":"svc","token":"bbk_CANARY_9f3c1e_do_not_print","expires_at":7,
                "aws_access_key_id":"AKIA1","aws_secret_access_key":"bbk_CANARY_9f3c1e_do_not_print"}"#,
        )
        .unwrap()
    }

    fn rotated() -> RotatedKeyView {
        serde_json::from_str(
            r#"{"id":"vk_1","name":"svc","token":"bbk_CANARY_9f3c1e_do_not_print","expires_at":7}"#,
        )
        .unwrap()
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("busbar-admin-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn default_create_output_is_byte_identical() {
        let mut out = Vec::new();
        render_created(&created(), false, None, &mut out).unwrap();
        let want = [
            "created key vk_1 (svc)".to_string(),
            "  expires_at: 7 (unix seconds)".into(),
            String::new(),
            "  ┌─────────────────────────────────────────────────────────────┐".into(),
            "  │  TOKEN (shown once — store it now, it cannot be retrieved)  │".into(),
            "  └─────────────────────────────────────────────────────────────┘".into(),
            format!("  token: {CANARY}"),
            "  aws_access_key_id:     AKIA1".into(),
            format!("  aws_secret_access_key: {CANARY}  (shown once)"),
            String::new(),
        ]
        .join("\n");
        assert_eq!(String::from_utf8(out).unwrap(), want);

        let mut out = Vec::new();
        render_created(&created(), true, None, &mut out).unwrap();
        let want = format!("{}\n", serde_json::to_string_pretty(&created()).unwrap());
        assert_eq!(String::from_utf8(out).unwrap(), want);
    }

    #[test]
    fn default_rotate_output_is_byte_identical() {
        let mut out = Vec::new();
        render_rotated(&rotated(), false, None, &mut out).unwrap();
        let want = [
            "rotated key vk_1 (svc)".to_string(),
            String::new(),
            "  ┌─────────────────────────────────────────────────────────────────┐".into(),
            "  │  NEW CREDENTIAL (shown once — the old one no longer resolves)  │".into(),
            "  └─────────────────────────────────────────────────────────────────┘".into(),
            format!("  token: {CANARY}"),
            "  expires_at: 7 (unix seconds)".into(),
            String::new(),
        ]
        .join("\n");
        assert_eq!(String::from_utf8(out).unwrap(), want);
    }

    #[test]
    fn output_secret_to_keeps_every_credential_off_stdout() {
        for json in [false, true] {
            let sink = tmp(&format!("create-{json}.json"));
            let mut out = Vec::new();
            render_created(&created(), json, Some(&sink), &mut out).unwrap();
            let shown = String::from_utf8(out).unwrap();
            assert!(
                !shown.contains(CANARY),
                "stdout carried the credential: {shown}"
            );
            let file = std::fs::read_to_string(&sink).unwrap();
            let v: serde_json::Value = serde_json::from_str(&file).unwrap();
            assert_eq!(v["token"], CANARY);
            assert_eq!(v["aws_secret_access_key"], CANARY);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&sink).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "the secret sink must be owner-only");
            }

            let sink = tmp(&format!("rotate-{json}.json"));
            let mut out = Vec::new();
            render_rotated(&rotated(), json, Some(&sink), &mut out).unwrap();
            let shown = String::from_utf8(out).unwrap();
            assert!(
                !shown.contains(CANARY),
                "stdout carried the credential: {shown}"
            );
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&sink).unwrap()).unwrap();
            assert_eq!(v["token"], CANARY);
        }
    }

    #[test]
    fn token_file_is_read_and_its_contents_never_reach_an_error() {
        let f = tmp("token");
        std::fs::write(&f, format!("{CANARY}\n")).unwrap();
        let (t, argv) = resolve_token(None, None, Some(&f)).unwrap();
        assert_eq!(t, CANARY);
        assert!(!argv);

        let e = resolve_token(Some("x"), Some(ValueSource::CommandLine), Some(&f)).unwrap_err();
        assert!(!format!("{e:#}").contains(CANARY));

        let missing = tmp("absent-token");
        let e = resolve_token(None, None, Some(&missing)).unwrap_err();
        assert!(format!("{e:#}").contains("--token-file"));
    }

    #[test]
    fn token_file_wins_over_the_env_token() {
        let f = tmp("token-env");
        std::fs::write(&f, "from-file\r\n").unwrap();
        let (t, _) =
            resolve_token(Some("from-env"), Some(ValueSource::EnvVariable), Some(&f)).unwrap();
        assert_eq!(t, "from-file");
    }

    #[test]
    fn only_an_argv_token_is_flagged_for_the_warning() {
        let m = Cli::command()
            .try_get_matches_from(["busbar-admin", "--token", "t", "info"])
            .unwrap();
        let (_, argv) = resolve_token(Some("t"), m.value_source("token"), None).unwrap();
        assert!(argv, "--token on argv must warn");

        let m = Cli::command()
            .try_get_matches_from(["busbar-admin", "info", "--token", "t"])
            .unwrap();
        assert_eq!(m.value_source("token"), Some(ValueSource::CommandLine));

        let (_, argv) = resolve_token(Some("t"), Some(ValueSource::EnvVariable), None).unwrap();
        assert!(!argv, "the env token must not warn");
    }
}
