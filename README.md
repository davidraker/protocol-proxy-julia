# ProtocolProxy (Julia)

A Julia port of the [protocol-proxy](../protocol-proxy/PROTOCOL.md) package, both sides of the wire contract: the
library a proxy process uses to talk to a `ProtocolProxyManager`, with an **echo proxy** (`bin/echo-proxy`) that
answers the core methods (`PING`, `SET_LOG_LEVEL`, `LOG` batches) and `ECHO` and speaks TLS 1.3 toward the manager;
and the **manager** itself (`Manager`), which launches proxies written in any language from their manifests, with the
**conformance harness** (`bin/conformance`) built on it. The echo proxy passes every check of the Python, Go and Julia
harnesses; the Julia manager runs the Python, Go, C and Julia proxies.

## Layout

| Path | What |
|---|---|
| `Project.toml`, `Manifest.toml` | the `ProtocolProxy` package and its pinned dependencies |
| `src/headers.jl` | version 1 and 2 frame headers (§3): `Header`, `pack`, `unpack`, request-id limits |
| `src/codec.jl` | zlib compression (§4) and AEAD encryption (§5) through OpenSSL's EVP interface: `seal`, `open_payload`, `aead_encrypt`, `aead_decrypt` |
| `src/tls.jl` | TLS 1.3 (§1, §2, §6): the stdin material, SSL contexts with the manager's CA as the only trust anchor, the handshake and the common-name check |
| `src/connector.jl` | the transport (§2, §6): listener, dialer, per-message and persistent connections over TCP or TLS, authentication, dispatch, `send_message`, `wait_response` |
| `src/proxy.jl` | the proxy process (§1, §7, §8, §9): stdin handshake, registration, `PING`, `SET_LOG_LEVEL`, `LOG` batches, parent watch, clean stop |
| `src/signals.jl` | SIGTERM handling (see below) |
| `src/logging.jl` | JSON log records (§9) as a Julia `AbstractLogger`: stderr lines, or the bounded rate-limited `LogQueue` shipped in `LOG` batches |
| `src/cli.jl` | the `--name value` command line, `main`, `echo_main`, `--self-test` |
| `src/manifest.jl` | manifests (§1a): `proxy.toml` parsing and validation, identity keys and normalisation, `must_match`, placeholders, the search path, `py_tuple` |
| `src/records.jl` | a launched proxy's records as the manager handles them (§9): JSON lines, plain and `<N>` lines, `LOG` batches, the manager-side logger name |
| `src/authority.jl` | the manager's in-memory certificate authority (§11b): EC P-256 CA and leaf certificates through OpenSSL.jl |
| `src/manager.jl` | the `ProtocolProxyManager` (§1, §7, §10, §11b): launch with the stdin handshake, pipe readers, registration, heartbeat, `LOG`, `SET_LOG_LEVEL`, loss and relaunch, `stop!` |
| `src/conformance.jl` | the 26-check harness (§12) on the Julia manager, and its command line |
| `src/vectors.jl` | the self-test against `test/test_vectors.json` |
| `src/precompile.jl` | a PrecompileTools workload so a launched proxy starts fast |
| `bin/echo-proxy` | shell wrapper: `julia --project=<repo> --startup-file=no bin/echo-proxy.jl "$@"` |
| `bin/conformance` | shell wrapper for the harness: `julia --project=<repo> bin/conformance.jl "$@"` |
| `proxy.toml` | the manifest a manager reads to launch this proxy (§1a) |
| `test/runtests.jl` | Julia tests; `test/test_vectors.json` is a copy of the Python repository's vectors |

## Dependencies

All registered in General and pinned in `Manifest.toml`:

- `CodecZlib` (zlib framing, default level; the underlying library is `Zlib_jll`)
- `OpenSSL_jll` — libcrypto for both AEADs via `ccall` (`EVP_chacha20_poly1305`, `EVP_aes_256_gcm`), so AES-256-GCM
  is always advertised and never falls back; `--cipher auto` still prefers it only when `/proc/cpuinfo` lists `aes`
  (§11a). libssl for TLS.
- `OpenSSL` (OpenSSL.jl) — `SSLStream`, which runs TLS over a `TCPSocket` through memory BIOs, and the X509 and key
  parsers. MbedTLS.jl was ruled out: its pinned MbedTLS has no TLS 1.3.
- `JSON3` (payloads and log records)
- `PrecompileTools`
- stdlib `TOML` (manifests)
- stdlib: `Sockets`, `UUIDs`, `Dates`, `Random`, `Logging`

Julia 1.10 or later.

## Setup

```sh
cd protocol-proxy-julia
julia --project=. -e 'using Pkg; Pkg.instantiate(); Pkg.precompile()'
./bin/echo-proxy --self-test          # pack/unpack every vector in test/test_vectors.json; exit 1 on a mismatch
julia --project=. -e 'using Pkg; Pkg.test()'
```

Startup matters: a manager gives a proxy 20 s to register. With the package precompiled, `bin/echo-proxy` writes
its first log line about 1.5 s after launch and is listening within another 0.05 s (Julia 1.10.12, x86_64); the
conformance runs registered about 1.8 s after launch. Without precompilation the first launch takes longer while
the cache is built, so run `Pkg.precompile()` after any change to `src/`.

## Conformance check

Two harnesses apply, and a proxy or a manager is measured against both. From the Python repository (its manager
launches this proxy through the manifest):

```sh
cd ../protocol-proxy
python -m protocol_proxy.conformance ../protocol-proxy-julia/proxy.toml --echo ECHO --tls --manager-dials -v
```

And this repository's own, on the Julia manager, against any manifest:

```sh
./bin/conformance proxy.toml --echo ECHO --tls --manager-dials               # the Julia echo proxy
./bin/conformance ../protocol-proxy-go/proxy.toml --echo ECHO --tls --manager-dials
./bin/conformance ../protocol-proxy-c/proxy.toml --echo ECHO --tls --manager-dials
./bin/conformance ../protocol-proxy/tests/manifests/GeventDummy.toml --echo ECHO --tls --manager-dials --python /path/to/venv/bin/python
```

`conformance <manifest.toml | proxy name> [--echo METHOD] [--tls] [--manager-dials] [--option NAME=VALUE ...]
[--timeout S] [--python PATH] [--log FILE] [--json] [-v]`; exit 0 when every check passes or is skipped. The 26 checks,
their names and the report layout are the Python harness's (PROTOCOL.md §12), including the `LOG` check: the proxy's
records are held at INFO for the run and a record must arrive over the socket within 3 s when `log` is advertised. A
proxy name instead of a path is looked up through the manifest search path (see Manager). A manifest for a Python
proxy is one whose command is `["{python}", "-m", "protocol_proxy.proxy", ...]`; `--python` (or
`PROTOCOL_PROXY_PYTHON`) says which interpreter that is. The Python repository ships manifests for its two test
dummies in `tests/manifests/` (`GeventDummy.toml`, `AsyncioDummy.toml`); their `[environment]` sets
`PYTHONPATH = "{manifest_dir}/.."`, the `[environment]` table taking the same placeholders as `command` (§1a).

Expected, as of 2026-10-24: `all checks pass (26 passed, 0 failed, 0 skipped)` for the Julia, Go and C echo proxies
and the Python gevent and asyncio dummies under the Julia manager, and for the Julia echo proxy under the Python and
Go managers.

## Manager

`Manager` is the Julia `ProtocolProxyManager`: it reads a manifest, launches the proxy process, writes the tokens (and
key and TLS material) to its stdin, reads its stdout and stderr, accepts its registration, pings it, handles its `LOG`
batches, terminates it on `stop!` and relaunches it on the next `get_proxy` after a loss. It is a `Connector` like a
proxy (`m.connector`), so handlers for a proxy's unsolicited pushes are registered on it the same way.

```julia
using ProtocolProxy
mf = find_manifest("mqtt")                                  # or load_manifest("path/proxy.toml")
m = Manager(mf; encrypt=true, ipc_tls=true, persistent=true)
start!(m)                                                   # listens on localhost, first free port in 22801..22899
on_proxy_lost!(m, (p, reason) -> nothing)                   # re-run setup here: get_proxy + wait_registered
p = get_proxy(m, ("mqtt", "broker"); host="broker.example", port=1883, username="u")
wait_registered(m, p, 20.0)                                 # the process is terminated and forgotten on a timeout
reply = request(m, p, "READ_POINTS", payload; timeout=10.0) # or send_to(m, p, Message(...)) for no reply
set_proxy_log_level!(m, p, "DEBUG")                         # SET_LOG_LEVEL, and its records are gated here at that level
health(m)                                                   # state, last seen, misses, features, pid, last PING report
stop!(m)                                                    # SIGTERM every proxy, SIGKILL after 5 s
```

**Keywords of `Manager`**: `name`; `inbound_address` (proxies are told `--manager-address` this) and `inbound_port`;
`persistent`, `encrypt`, `cipher`, `ipc_tls` as defaults for every proxy, each overridable per launch through the
options `persistent`, `encrypt`, `cipher`, `ipc_tls`; `compress_threshold`; `heartbeat_interval` (10 s, 0 disables),
`heartbeat_timeout` (5 s), `heartbeat_misses` (3); `python`; `environment`; `records` (a function receiving each
launched proxy's `Record`); `proxy_log_level` (gates them and travels as `--log-level`, "INFO").

**`get_proxy` options** are the proxy's launch options in the Python kwargs spelling (`inbound_port`, not
`--inbound-port`), as keywords or a `Dict`; they select the process through the manifest's identity keys and are
checked against its `must_match`, then travel to the proxy as `--name value` (booleans as `true`/`false`), sorted by
name after the standard options. The manager-only ones are `dial` (`(host, port)` or `"host:port"`, where to reach a
`manager_dials` proxy; default its `inbound_address:inbound_port`), `ssh_host`, `ssh_options`, `ssh_forward`,
`remote_python`, `remote_env` (the SSH launcher prefix of PROTOCOL.md §1, composed as the Python manager composes it
but not exercised by the tests here) and `manager_callbacks` (ignored; register handlers on `m.connector` instead).

**Process keys and names.** The process key is `(manifest name, normalised identity options...)` when the manifest
names `keys`, else the caller's `unique_remote_id`; a proxy's name, as passed in `--proxy-name` and used in log lines,
is that key rendered as a Python tuple (`('mqtt', 'broker.example', 1883)`, `py_tuple`), which is what a Python
manager would call the same process. The proxy id for a key is kept across relaunches; token and key are fresh per
launch.

**Manifest discovery** (`search_path`) is the §1a list: the directories in `PROTOCOL_PROXY_MANIFESTS` (prepended),
`$XDG_CONFIG_HOME/protocol-proxy/manifests` (`~/.config`), `<prefix>/share/protocol-proxy/manifests`,
`$XDG_CONFIG_DIRS/protocol-proxy/manifests` (`/etc`), and `$XDG_DATA_DIRS/protocol-proxy/manifests`
(`/usr/local/share:/usr/share`). `<prefix>` is `PROTOCOL_PROXY_PREFIX` when set, else the directory of the active
project (`julia --project=<dir>`, so this checkout's own `share/protocol-proxy/manifests` is searched), else the
directory above Julia's `bin`. There is no Python entry-point fallback: Python proxies are found after
`protocol-proxy-manifests export` has copied their manifests into one of the directories. `find_manifest(name)`,
`load_manifest(path)` and `discover_manifests()` are the entry points.

**`{python}`** in a manifest command resolves to the `python` keyword, else `$PROTOCOL_PROXY_PYTHON`, else `python3`
(behind an SSH prefix: `remote_python`, default `python3`). `{manifest_dir}` is the manifest file's directory.

**Logging hooks.** The manager's own messages go through Julia's global logger (`@info`, `@warn`); a `ProxyLogger`
with `json=false` prints them as readable lines, as `bin/conformance` does. A launched proxy's records, whether read as
JSON lines from its stderr pipe, as plain lines from either pipe (stdout INFO, stderr WARNING, or the level of a `<N>`
syslog prefix) or received in `LOG` batches, are rebuilt as `Record` (level, message, the proxy's own logger name, the
channel `stdout`/`stderr`/`socket`, pid, proxy name, the raw fields) and handed to the `records` function; the default
`log_record` forwards them to the global logger under `protocol_proxy.proxies.<manifest name>.<proxy name>`. Records
below the proxy's level (`proxy_log_level`, changed by `set_proxy_log_level!`) are dropped before the handler sees
them. A `dropped` count in a batch becomes one WARNING.

**TLS.** Every manager creates an in-memory CA (`Authority`, EC P-256, 366 days) and issues itself a certificate; a
proxy launched with TLS is issued one naming its id (`issue`) and receives `{"ca", "cert", "key"}` on stdin. The
manager's listener accepts plain and TLS connections on one port (`Connector(...; tls_optional=true)`: the first byte
tells them apart), so TLS and plain proxies may share a manager.

**Liveness.** Registered proxies with a running process are pinged every `heartbeat_interval`; any reply counts, and
`heartbeat_misses` consecutive misses, a process exit, or no registration within `wait_registered`'s timeout lose the
proxy: it is forgotten, its process terminated, `on_proxy_lost!` callbacks run, and the next `get_proxy` for its key
relaunches it. A process the manager is itself terminating is not pinged. The manager is Task-based and needs no
threads; unlike a proxy process it may run with Julia's default signal handling.

The manager-side behaviours PROTOCOL.md leaves implicit are listed in its §11b; this port follows them as the Go
manager does. One more it needed: a Julia proxy owns SIGTERM only once `run!` has installed its handler, about 1.5 s
after launch, so a manager that stops a proxy it has not yet seen register may get exit code -15 from it.

## What is implemented

- Headers V1 and V2, request ids cycling from 1 within the version's field; responses are sent in the header
  version of the request they answer.
- Frames over TCP (`Sockets`), one `Task` per connection; per-message and persistent (keep-alive bit) connections in
  both directions, adoption of an authenticated keep-alive connection, redial after loss, frames above 256 KiB on a
  connection of their own, TCP keepalive on persistent sockets.
- Authentication by sender id and token; dispatch by `(method, remote_id)` then `method`; `RESPONSE` matched by
  request id; the `{"status": "error", ...}` reply for an unknown method, a handler without a response, a raising
  handler, or one that exceeds its timeout; an empty reply to an unauthenticated request.
- zlib compression toward peers that advertised `compress`, above 4096 bytes (`--compress-threshold`); AEAD
  encryption with the key from stdin, ChaCha20-Poly1305 by default or AES-256-GCM when the peer advertised it,
  12-byte random nonce, the header as sent as associated data, mode fixed per peer.
- Registration (`REGISTER_PEER`, two attempts, 5 s timeout, 20 s apart), `--manager-dials true`, `PING`,
  `SET_LOG_LEVEL`, parent-PID watch every second, SIGTERM -> exit 0.
- Logging (§9, §11a): JSON lines on stderr until registration; then, when launched by a manager with stderr a pipe and
  `--socket-logging true` (the default), the logger switches to a `LogQueue` (2000 records, 50/s with a burst of 200,
  drops counted) and a Task ships `LOG` batches every 0.2 s or at 64 records. On a persistent connection a batch waits
  up to half a second for ordinary frames to go first; on a per-message peer each batch dials its own connection, so
  priority is moot. The switch itself is the first record over the socket; at stop whatever is queued goes to stderr.
- TLS 1.3 toward the manager (`--ipc-tls true`): the material arrives as one JSON line on stdin after the tokens and
  key; the listener is then TLS-only and dialled connections to TLS peers are TLS. Each end presents its certificate and
  requires the other's to chain to the manager's CA (held in memory, no file); hostnames are not checked, a frame is
  accepted only when its sender id is the certificate's common name, and a peer marked TLS is refused in the clear.
  Both AEADs and TLS together are allowed, as in the Python reference.

## SIGTERM in Julia

With its default signal handlers Julia blocks SIGTERM on its threads and consumes it on an internal signal thread,
where it is fatal (a backtrace, then death by the signal, exit code -15 to a parent), so a libuv signal watcher never
fires. `src/signals.jl` installs a `sigaction` handler that only stores the signal number into pre-allocated memory
(a Task polls the word every 50 ms and stops the proxy) and unblocks SIGTERM on the main thread. Linux offers a
process-directed signal to the main thread first, but skips it when it is off-CPU with another signal pending, and then
Julia's own thread took the signal in about one session in twenty under the conformance harness. `bin/echo-proxy`
therefore runs Julia with `--handle-signals=no`: there is no signal thread and nothing is blocked, so the handler is
the only one. The cost is Julia's crash reporting and SIGINT handling, and the process must stay single-threaded (no
`-t`), since Julia's GC needs those handlers to stop threads. SIGPIPE, which Julia would have ignored, is ignored by
`install_signal_handlers`. The `sigaction` layout is Linux-specific (glibc, x86_64 and aarch64).
