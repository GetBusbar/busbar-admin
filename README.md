# busbar-admin

A human-facing CLI for the [busbar](https://github.com/GetBusbar) gateway's **admin API**
(`/api/v1/admin`). It speaks the frozen v1 contract over HTTP/HTTPS with a thin, hand-rolled
client (no OpenAPI generator), so it's small and easy to extend.

The contract it targets is committed at [`openapi.json`](openapi.json) (busbar **1.5.0**);
CI compares that spec's version against the latest busbar release so drift is visible.

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
| `--insecure`    | —                     | Skip TLS certificate verification (**dev only**)               |
| `--ca-cert`     | —                     | Trust a private admin CA (PEM file)                            |
| `--client-cert` | —                     | Client certificate (PEM) for mTLS (with `--client-key`)        |
| `--client-key`  | —                     | Client private key (PEM) for mTLS (with `--client-cert`)       |
| `--json`        | —                     | Emit raw JSON instead of the human table/summary               |

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
busbar 1.5.0
  uptime:           1m 12s
  config version:   0
  config persist:   off (live-only)
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

### `hooks` — hook registry

```sh
busbar-admin hooks list
```

> `hooks create` / `hooks remove` are intentionally not implemented in v0.1: the register
> endpoint (`POST /api/v1/admin/hooks`) takes a full transport/grants definition better
> expressed in config.yaml or the Terraform provider. `hooks list` covers inspection.

### `plugins` — signed plugin catalog (1.5.0)

```sh
busbar-admin plugins list --type store    # auth | hooks | store (default: store)
busbar-admin plugins install ./my-store-plugin.tar.gz
busbar-admin plugins reload               # re-scan the plugins directory
```

`plugins install` uploads a **signed** plugin tarball; the gateway re-verifies the
signature against its running trust posture (the client is never trusted).

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

Add `--json` to any command to get the gateway's raw JSON for scripting:

```sh
busbar-admin --json info | jq .version
busbar-admin --json keys list | jq '.items[].id'
```

## Errors

busbar-admin turns the common failure modes into actionable messages:

- connection refused → `no gateway reachable at <endpoint>`
- `401` → `admin token rejected`
- `403` → `admin token lacks the required scope`
- any other gateway error carries the `{code, message}` envelope verbatim.

## License

Apache-2.0. See [LICENSE](LICENSE).
