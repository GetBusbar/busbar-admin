// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! busbar-admin — a human-facing CLI for the busbar gateway's admin API (`/api/v1/admin`).
//!
//! Config resolution is CLI flag > env var > a clear error. The thin admin client lives in
//! [`client`]; this module is the clap surface + human/JSON rendering.

macro_rules! human_println {
    ($($arg:tt)*) => { writeln!(&mut std::io::stdout().lock(), "{}", terminal_text(&format!($($arg)*)))? };
}

fn terminal_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            output.extend(c.escape_default());
        } else {
            output.push(c);
        }
    }
    output
}

mod client;

use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

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

    /// Emit the modeled JSON view instead of a human table/summary.
    #[arg(long, global = true)]
    json: bool,
}

impl Drop for GlobalOpts {
    fn drop(&mut self) {
        self.token.zeroize();
    }
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
        let _ = writeln!(
            &mut std::io::stderr().lock(),
            "error: {}",
            terminal_text(&format!("{e:#}"))
        );
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
) -> Result<(Zeroizing<String>, bool)> {
    let from_argv = source == Some(ValueSource::CommandLine);
    if let Some(path) = token_file {
        if from_argv {
            anyhow::bail!("--token and --token-file are mutually exclusive");
        }
        let bytes = client::read_local(path, 64 * 1024, "--token-file")?;
        let raw = std::str::from_utf8(&bytes).context("--token-file must be UTF-8")?;
        let tok = raw.trim_end_matches(['\r', '\n']);
        if tok.is_empty() {
            anyhow::bail!("--token-file {} is empty", path.display());
        }
        return Ok((Zeroizing::new(tok.to_string()), false));
    }
    let tok = token.context("no admin token: pass --token or set BUSBAR_ADMIN_TOKEN")?;
    Ok((Zeroizing::new(tok.to_string()), from_argv))
}

fn wipe_arg_tokens(matches: &mut clap::ArgMatches) {
    if let Some(mut token) = matches.remove_one::<String>("token") {
        token.zeroize();
    }
    if let Some((_, mut child)) = matches.remove_subcommand() {
        wipe_arg_tokens(&mut child);
    }
}

fn run() -> Result<()> {
    let mut matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let token_source = matches.value_source("token");
    wipe_arg_tokens(&mut matches);
    let g = &cli.global;

    let endpoint = g.endpoint.clone().context(
        "no endpoint: pass --endpoint or set BUSBAR_ENDPOINT (e.g. http://localhost:8081)",
    )?;
    let (token, from_argv) =
        resolve_token(g.token.as_deref(), token_source, g.token_file.as_deref())?;
    if from_argv {
        writeln!(&mut std::io::stderr().lock(), "{ARGV_TOKEN_WARNING}")?;
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
    write_json(v, &mut std::io::stdout().lock())
}

fn write_json<T: serde::Serialize>(v: &T, out: &mut dyn Write) -> Result<()> {
    let text = Zeroizing::new(serde_json::to_string_pretty(v)?);
    writeln!(out, "{}", text.as_str())?;
    Ok(())
}

fn cmd_info(c: &Client, json: bool) -> Result<()> {
    let info = c.info()?;
    if json {
        return print_json(&info);
    }
    human_println!("busbar {}", info.version);
    match info.uptime_seconds {
        Some(s) => human_println!("  uptime:           {}", human_duration(s)),
        None => human_println!("  uptime:           (unknown)"),
    }
    human_println!("  config version:   {}", info.config_version);
    human_println!(
        "  config persist:   {}",
        if info.config_persistence {
            "on (durable)"
        } else {
            "off (mutations locked)"
        }
    );
    human_println!(
        "  topology:         {} pools, {} models, {} providers",
        info.topology.pools,
        info.topology.models,
        info.topology.providers
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
    human_println!("  auth modules:     {am}");
    human_println!("  hook plugins:     {hp}");
    human_println!("  weighted floor:   {}", info.build.weighted_floor);
    Ok(())
}

fn cmd_keys_list(c: &Client, json: bool) -> Result<()> {
    let page = c.list_keys()?;
    if json {
        return print_json(&page);
    }
    if page.items.is_empty() {
        human_println!("no virtual keys");
        return Ok(());
    }
    human_println!(
        "{:<22} {:<20} {:<16} {:<10} {:<12} ENABLED",
        "ID",
        "NAME",
        "GROUP",
        "STATE",
        "POOLS"
    );
    for k in &page.items {
        human_println!(
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
        human_println!("(more keys available — showing the first page)");
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
    let mut sink = secret_to.map(SecretSink::open).transpose()?;
    let created = c.create_key(&req)?;
    render_created(&created, json, sink.as_mut(), &mut std::io::stdout().lock())
}

/// The JSON object names that carry a once-shown credential in a mint or rotate view.
const SECRET_FIELDS: [&str; 3] = ["token", "aws_secret_access_key", "secret"];

/// A private destination prepared before a once-only credential is minted.
struct SinkLock(std::path::PathBuf);

impl Drop for SinkLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct SecretSink {
    path: std::path::PathBuf,
    file: std::fs::File,
    temporary: Option<std::path::PathBuf>,
    _lock: Option<SinkLock>,
}

impl SecretSink {
    fn open(path: &Path) -> Result<Self> {
        let inherited = path
            .strip_prefix("/dev/fd")
            .ok()
            .and_then(|p| p.to_str())
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if inherited {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .with_context(|| format!("opening --output-secret-to {}", path.display()))?;
            return Ok(Self {
                path: path.to_owned(),
                file,
                temporary: None,
                _lock: None,
            });
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => anyhow::ensure!(
                metadata.is_file(),
                "--output-secret-to must be a regular file or /dev/fd/N"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("checking --output-secret-to"),
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .context("--output-secret-to requires a filename")?;
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(name);
        lock_name.push(".busbar-lock");
        let lock_path = parent.join(lock_name);
        let mut lock_options = std::fs::OpenOptions::new();
        lock_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            lock_options.mode(0o600);
        }
        let mut lock_file = lock_options.open(&lock_path).with_context(|| {
            format!(
                "locking --output-secret-to {}; another writer or stale lock may exist",
                path.display()
            )
        })?;
        let lock = SinkLock(lock_path);
        writeln!(lock_file, "{}", std::process::id()).context("recording credential writer")?;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        for _ in 0..128 {
            let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let temporary = parent.join(format!(".busbar-secret-{}-{serial}", std::process::id()));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            match options.open(&temporary) {
                Ok(file) => {
                    return Ok(Self {
                        path: path.to_owned(),
                        file,
                        temporary: Some(temporary),
                        _lock: Some(lock),
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e).context("preparing --output-secret-to"),
            }
        }
        anyhow::bail!("cannot allocate a private --output-secret-to file")
    }

    fn write<T: serde::Serialize>(&mut self, view: &T) -> Result<()> {
        let temporary = self.temporary.take();
        let result = (|| -> Result<()> {
            serde_json::to_writer_pretty(&mut self.file, view)
                .context("writing credential JSON")?;
            self.file
                .write_all(b"\n")
                .context("writing credential newline")?;
            self.file.flush().context("flushing credential output")?;
            if let Some(temporary) = &temporary {
                self.file.sync_all().context("syncing credential output")?;
                std::fs::rename(temporary, &self.path).context("publishing --output-secret-to")?;
            }
            Ok(())
        })();
        match temporary {
            Some(path) => result.with_context(|| format!("credential output failed; private recovery file retained at {} (it may be incomplete)", path.display())),
            None => result,
        }
    }
}

impl Drop for SecretSink {
    fn drop(&mut self) {
        if let Some(temporary) = &self.temporary {
            let _ = std::fs::remove_file(temporary);
        }
    }
}

fn wipe_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(values) => values.iter_mut().for_each(wipe_json),
        serde_json::Value::Object(values) => values.values_mut().for_each(wipe_json),
        _ => {}
    }
}

/// The `--json` rendering with the credential fields dropped (they went to the secret sink).
fn json_without_secrets<T: serde::Serialize>(view: &T) -> Result<serde_json::Value> {
    let mut v = serde_json::to_value(view)?;
    if let Some(o) = v.as_object_mut() {
        for k in SECRET_FIELDS {
            if let Some(mut value) = o.remove(k) {
                wipe_json(&mut value);
            }
        }
    }
    Ok(v)
}

fn render_created(
    created: &CreatedKeyView,
    json: bool,
    mut secret_to: Option<&mut SecretSink>,
    out: &mut dyn Write,
) -> Result<()> {
    if let Some(p) = secret_to.as_mut() {
        p.write(created)?;
    }
    if json {
        let text = Zeroizing::new(match secret_to.as_ref() {
            None => serde_json::to_string_pretty(created)?,
            Some(_) => serde_json::to_string_pretty(&json_without_secrets(created)?)?,
        });
        writeln!(out, "{}", text.as_str())?;
        return Ok(());
    }
    let shown = |v: &str| {
        Zeroizing::new(match secret_to.as_ref() {
            None => terminal_text(v),
            Some(p) => terminal_text(&format!("(written to {})", p.path.display())),
        })
    };
    writeln!(
        out,
        "created key {} ({})",
        terminal_text(&created.id),
        terminal_text(&created.name)
    )?;
    if let Some(g) = &created.group {
        writeln!(
            out,
            "  group: {}{}",
            terminal_text(g),
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
    writeln!(out, "  token: {}", shown(created.token.expose()).as_str())?;
    if let Some(id) = &created.aws_access_key_id {
        writeln!(out, "  aws_access_key_id:     {}", terminal_text(id))?;
    }
    if let Some(sk) = &created.aws_secret_access_key {
        writeln!(
            out,
            "  aws_secret_access_key: {}  (shown once)",
            shown(sk.expose()).as_str()
        )?;
    }
    Ok(())
}

fn cmd_keys_get(c: &Client, id: &str, json: bool) -> Result<()> {
    let k: KeyView = c.get_key(id)?;
    if json {
        return print_json(&k);
    }
    human_println!("key {} ({})", k.id, k.name);
    human_println!(
        "  state:      {}",
        if k.state.is_empty() { "-" } else { &k.state }
    );
    human_println!("  enabled:    {}", k.enabled);
    human_println!("  group:      {}", k.group.as_deref().unwrap_or("(none)"));
    human_println!(
        "  pools:      {}",
        match &k.allowed_pools {
            None => "(all)".to_string(),
            Some(p) if p.is_empty() => "(none)".to_string(),
            Some(p) => p.join(", "),
        }
    );
    human_println!("  created_at: {}", k.created_at);
    if !k.labels.is_empty() {
        let labels: Vec<String> = k.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        human_println!("  labels:     {}", labels.join(", "));
    }
    Ok(())
}

fn cmd_keys_rotate(c: &Client, id: &str, json: bool, secret_to: Option<&Path>) -> Result<()> {
    let mut sink = secret_to.map(SecretSink::open).transpose()?;
    let rotated = c.rotate_key(id)?;
    render_rotated(&rotated, json, sink.as_mut(), &mut std::io::stdout().lock())
}

fn render_rotated(
    rotated: &RotatedKeyView,
    json: bool,
    mut secret_to: Option<&mut SecretSink>,
    out: &mut dyn Write,
) -> Result<()> {
    if let Some(p) = secret_to.as_mut() {
        p.write(rotated)?;
    }
    if json {
        let text = Zeroizing::new(match secret_to.as_ref() {
            None => serde_json::to_string_pretty(rotated)?,
            Some(_) => serde_json::to_string_pretty(&json_without_secrets(rotated)?)?,
        });
        writeln!(out, "{}", text.as_str())?;
        return Ok(());
    }
    let shown = |v: &str| {
        Zeroizing::new(match secret_to.as_ref() {
            None => terminal_text(v),
            Some(p) => terminal_text(&format!("(written to {})", p.path.display())),
        })
    };
    writeln!(
        out,
        "rotated key {} ({})",
        terminal_text(&rotated.id),
        terminal_text(&rotated.name)
    )?;
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
        writeln!(out, "  token: {}", shown(t.expose()).as_str())?;
        if let Some(exp) = rotated.expires_at {
            writeln!(out, "  expires_at: {exp} (unix seconds)")?;
        }
    }
    if let Some(s) = &rotated.secret {
        writeln!(out, "  secret: {}", shown(s.expose()).as_str())?;
    }
    Ok(())
}

fn cmd_keys_revoke(c: &Client, id: &str, json: bool) -> Result<()> {
    let v = c.revoke_key(id)?;
    if json {
        return print_json(&v);
    }
    human_println!(
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
    human_println!("deleted key {id} (revoked and tombstoned)");
    Ok(())
}

fn cmd_plugins_list(c: &Client, plugin_type: &str, json: bool) -> Result<()> {
    let page = c.list_plugins(plugin_type)?;
    if json {
        return print_json(&page);
    }
    if page.items.is_empty() {
        human_println!("no {plugin_type} plugins");
        return Ok(());
    }
    print_plugin_rows(&page.items)?;
    if page.next_cursor.is_some() {
        human_println!("(more {plugin_type} plugins available — showing the first page)");
    }
    Ok(())
}

fn print_plugin_rows(items: &[PluginView]) -> Result<()> {
    human_println!(
        "{:<20} {:<7} {:<12} {:<8} {:<10} {:<10} FILE",
        "NAME",
        "TYPE",
        "LOADER",
        "ACTIVE",
        "VERSION",
        "TRUST"
    );
    for p in items {
        human_println!(
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
    Ok(())
}

fn cmd_plugins_install(
    c: &Client,
    tarball: &std::path::Path,
    file: Option<&str>,
    json: bool,
) -> Result<()> {
    use base64::Engine as _;
    let bytes = client::read_local(tarball, 128 * 1024 * 1024, "plugin tarball")?;
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
    human_println!(
        "installed {} (plugin {} v{}, trust: {})",
        installed.file,
        installed.name,
        installed.version.as_deref().unwrap_or("?"),
        installed.trust,
    );
    if !installed.note.is_empty() {
        human_println!("note: {}", installed.note);
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
    let bytes = client::read_local(tarball, 128 * 1024 * 1024, "plugin tarball")?;
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
    human_println!(
        "plugin {} v{} (kind: {}, trust: {})",
        preview.name,
        preview.version.as_deref().unwrap_or("?"),
        preview.kind.as_deref().unwrap_or("-"),
        preview.trust,
    );
    human_println!(
        "  restart required (default): {}",
        opt(preview.restart_required_default)
    );
    human_println!(
        "  settings schema: {}",
        if preview.schema.is_some() {
            "present"
        } else {
            "(none)"
        }
    );
    if let Some(err) = &preview.schema_error {
        human_println!("  schema error: {err}");
    }
    human_println!("(preview only — nothing was installed)");
    Ok(())
}

fn cmd_plugins_reload(c: &Client, json: bool) -> Result<()> {
    let v = c.reload_plugins()?;
    if json {
        return print_json(&v);
    }
    if v.plugins.is_empty() {
        human_println!("no dynamic-library plugins in the plugins directory");
    } else {
        print_plugin_rows(&v.plugins)?;
    }
    if !v.note.is_empty() {
        human_println!("note: {}", v.note);
    }
    Ok(())
}

fn cmd_hooks_list(c: &Client, json: bool) -> Result<()> {
    let page = c.list_hooks()?;
    if json {
        return print_json(&page);
    }
    if page.items.is_empty() {
        human_println!("no hooks registered");
        return Ok(());
    }
    human_println!(
        "{:<20} {:<6} {:<8} {:<8} {:<7} TARGET",
        "NAME",
        "KIND",
        "TRANSPORT",
        "PROMPT",
        "GLOBAL"
    );
    for h in &page.items {
        human_println!(
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
        human_println!("(more hooks available — showing the first page)");
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
    human_println!("config version: {}", info.config_version);
    human_println!(
        "persistence:    {}",
        if info.config_persistence {
            "on (durable across restart)"
        } else {
            "off (mutations locked)"
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
    let raw = client::read_local(file, 32 * 1024 * 1024, "config file")?;
    let mut body: serde_json::Value = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing {} as JSON", file.display()))?;
    let result = c.config_apply(&body);
    wipe_json(&mut body);
    let resp = result?;
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
        human_println!("config applied — now at version {}", resp.config_version);
        if !resp.reload_to_apply.is_empty() {
            human_println!(
                "restart required to apply: {}",
                resp.reload_to_apply.join(", ")
            );
        }
        if !resp.note.is_empty() {
            human_println!("note: {}", resp.note);
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
#[path = "cli_logic_tests.rs"]
mod cli_logic_tests;
