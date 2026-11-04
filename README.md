# busbar-admin

[![Coverage](https://codecov.io/gh/GetBusbar/busbar-admin/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-admin)

A human-facing CLI for the [busbar](https://github.com/GetBusbar) gateway's **admin API**
(`/api/v1/admin`). It speaks the frozen v1 contract over HTTP/HTTPS with a thin, hand-rolled
client (no OpenAPI generator), so it's small and easy to extend.

The contract it targets is committed at [`openapi.json`](openapi.json) (busbar **1.6.0**, the core version pinned in [`.busbar-core`](.busbar-core)). Drift is
caught two ways: CI compares that spec's version against the latest busbar release, and a set of
contract tests compares the client's own structs against the spec's schemas field by field — locally
against the committed copy, and in CI against core's spec at the paired branch. The second check is
the one that sees a shape change made under an unchanged version stamp.

## Install

From source (published later on crates.io / as a GitHub release + Homebrew tap):

```sh
cargo install --path .
# or, once published:
# cargo install busbar-admin
```

Prebuilt binaries and a Homebrew formula can follow via a tagged GitHub release (see
`.github/workflows/release.yml`).

## Configuration

Every global flag has an environment-variable fallback. Resolution order is
**CLI flag → environment variable → a clear error**.

| Flag            | Env var               | Purpose                                                        |
| --------------- | --------------------- | -------------------------------------------------------------- |
| `--endpoint`    | `BUSBAR_ENDPOINT`     | Gateway base URL, e.g. `http://localhost:8081`                 |
| `--token`       | `BUSBAR_ADMIN_TOKEN`  | Admin token (sent as `x-admin-token` and `Authorization: Bearer`) |
| `--token-file` | —                     | Read the admin token from a file (keeps it out of `ps` and shell history; `--token` on argv prints a warning) |
| `--output-secret-to` | —               | `keys create` / `keys rotate`: write the minted credential (full JSON view, mode 0600) to this file or `/dev/fd/N` instead of stdout |
| `--insecure`    | —                     | Skip TLS certificate verification (**dev only**)               |
| `--ca-cert`     | —                     | Trust a private admin CA (PEM file)                            |
| `--client-cert` | —                     | Client certificate (PEM) for mTLS (with `--client-key`)        |
| `--client-key`  | —                     | Client private key (PEM) for mTLS (with `--client-cert`)       |
| `--json`        | —                     | Emit the modeled JSON view instead of the human table/summary               |

The TLS knobs mirror the busbar Terraform provider (`insecure`, `ca_cert_pem`,
`client_cert_pem`/`client_key_pem`) so the same trust setup works for both.

```sh
export BUSBAR_ENDPOINT=http://localhost:8081
export BUSBAR_ADMIN_TOKEN=your-admin-token
```

## Usage

### `info` — gateway status

```sh
busbar-admin info
```

```
busbar 1.5.2
  uptime:           1m 12s
  config version:   0
  config persist:   off (mutations locked)
  topology:         0 pools, 1 models, 1 providers
  auth modules:     tokens
  hook plugins:     (none)
  weighted floor:   true
```

### `keys` — governance virtual keys

```sh
busbar-admin keys list
busbar-admin keys create my-service \
  --group team-a --expires-in 30d \
  --label team=platform \
  --allowed-pool default --issue-aws-credential
busbar-admin keys get vk_0123456789abcdef       # metadata + state (never the secret)
busbar-admin keys rotate vk_0123456789abcdef    # fresh credential in place, shown once
busbar-admin keys revoke vk_0123456789abcdef    # denylist; the record stays for audit
busbar-admin keys delete vk_0123456789abcdef    # revoke AND forget (tombstone)
```

As of busbar 1.5.0, keys are **pure auth**: a minted key is a busbar-signed expiring
token, and budgets/rate limits flow through the bound `--group` (a `groups:` bucket)
rather than per-key `--budget-cents`/`--rpm`/`--tpm` flags. `keys create` prints the
signed token (and any AWS SigV4 secret) **once** — it is never retrievable again.
Store it immediately.

Pool access is three-state. Omitting `--allowed-pool` allows **all** pools; one or more
`--allowed-pool` flags restrict the key to exactly those; and `--no-pools` mints a key
allowed on **no** pool at all (an explicit empty allow-list — e.g. a placeholder or
audit-only credential). `--no-pools` and `--allowed-pool` are mutually exclusive.

### `hooks` — hook registry

```sh
busbar-admin hooks list
```

> `hooks create` / `hooks remove` are intentionally not implemented in v0.1: the register
> endpoint (`POST /api/v1/admin/hooks`) takes a full transport/grants definition better
> expressed in config.yaml or the Terraform provider. `hooks list` covers inspection.

### `plugins` — signed plugin catalog (1.5.2)

```sh
busbar-admin plugins list --type store    # auth | hooks | store (default: store)
busbar-admin plugins install ./my-store-plugin.tar.gz
busbar-admin plugins inspect ./my-store-plugin.tar.gz   # preview WITHOUT installing
busbar-admin plugins reload               # re-scan the plugins directory
```

`plugins install` uploads a **signed** plugin tarball; the gateway re-verifies the
signature against its running trust posture (the client is never trusted).

`plugins inspect` (added in busbar 1.5.2) is a **stateless** preview: the gateway verifies
the tarball's signature and parses its manifest **without installing anything**, reporting
the plugin's name/version/kind, trust verdict, restart-scoping default, and its settings
schema. An untrusted or rejected candidate is reported (never refused), so you can vet an
artifact before committing to `plugins install`.

### `config` — running config

```sh
busbar-admin config version          # current config_version + persistence flag
busbar-admin config show             # the effective running config (redacted, no secrets)
busbar-admin config apply cfg.json   # POST /api/v1/admin/config/apply
```

The apply file is JSON of the shape `{"config": {...}, "providers": {...}}` (the
`config.yaml` / `providers.yaml` shapes). An applied config is **live but not written to
disk** — the next reload/restart returns to disk truth.

### JSON output

Add `--json` to any command to get its modeled JSON view for scripting. Unknown additive
response fields are ignored by typed commands; `config show` preserves the gateway's JSON view:

```sh
busbar-admin --json info | jq .version
busbar-admin --json keys list | jq '.items[].id'
```

## Errors

busbar-admin turns the common failure modes into actionable messages:

- connection refused → `no gateway reachable at <endpoint>`
- `401` → `admin token rejected`
- `403` → `admin token lacks the required scope`
- other gateway errors report their HTTP status; response bodies are withheld because they can contain credentials.

## Credential handling and limits

`--output-secret-to` is prepared before minting or rotating a key. Regular files are
replaced atomically with a new private file, so existing readers cannot see the new
credential. Symlinks and nonregular paths are refused; inherited `/dev/fd/N` sinks
remain supported. A sibling `.NAME.busbar-lock` prevents simultaneous writers. If a
process is killed, remove that lock only after confirming its recorded PID is no
longer writing. A crash can also leave a private `.busbar-secret-PID-N` staging file.
Output errors retain that private recovery file and report its location; failed writes
can leave it incomplete, so verify it before using the credential.

Responses and config inputs are limited to 32 MiB, plugin tarballs to 128 MiB,
PEM inputs to 1 MiB each, and token files to 64 KiB. Endpoints must be HTTP(S)
without userinfo, query strings or fragments. Tokens cannot contain control characters.
Human output escapes terminal controls; JSON preserves values through JSON escaping.
Application-owned credential and private-key buffers are wiped when released; HTTP
and TLS library internals manage their own copies.

## Differences from 1.5.5

The key mint/rotate and admin response surfaces existed in core 1.5.5. The CLI now
bounds hostile or mistaken inputs, treats key IDs as literal URL segments, withholds
error bodies that might echo credentials, and escapes terminal controls. Credential
files are prepared before a mutation and replaced privately, preventing the old
open-after-rotation failure and disclosure through an existing public file. Valid
credential values and successful command behavior are preserved.

`config apply` also reports the newer `reload_to_apply` plane list when supplied by
the gateway. This field was absent from the 1.5.5 full-config apply response.

## License

Apache-2.0. See [LICENSE](LICENSE).
