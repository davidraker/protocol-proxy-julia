# ProtocolProxy (Julia)

A Julia port of the [protocol-proxy](../protocol-proxy/PROTOCOL.md) IPC wire contract: the library a proxy process
uses to talk to a `ProtocolProxyManager`, plus an **echo proxy** (`bin/echo-proxy`) that answers the core methods
(`PING`, `SET_LOG_LEVEL`) and `ECHO`, and passes the Python conformance harness.

## Layout

| Path | What |
|---|---|
| `Project.toml`, `Manifest.toml` | the `ProtocolProxy` package and its pinned dependencies |
| `src/headers.jl` | version 1 and 2 frame headers (§3): `Header`, `pack`, `unpack`, request-id limits |
| `src/codec.jl` | zlib compression (§4) and AEAD encryption (§5): `seal`, `open_payload`, `aead_encrypt`, `aead_decrypt` |
| `src/connector.jl` | the transport (§2, §6): listener, dialer, per-message and persistent connections, authentication, dispatch, `send_message`, `wait_response` |
| `src/proxy.jl` | the proxy process (§1, §7, §8): stdin handshake, registration, `PING`, `SET_LOG_LEVEL`, parent watch, clean stop |
| `src/signals.jl` | SIGTERM handling (see below) |
| `src/logging.jl` | JSON log records on stderr (§9) as a Julia `AbstractLogger` |
| `src/cli.jl` | the `--name value` command line, `main`, `echo_main`, `--self-test` |
| `src/vectors.jl` | the self-test against `test/test_vectors.json` |
| `src/precompile.jl` | a PrecompileTools workload so a launched proxy starts fast |
| `bin/echo-proxy` | shell wrapper: `julia --project=<repo> --startup-file=no bin/echo-proxy.jl "$@"` |
| `proxy.toml` | the manifest a manager reads to launch this proxy (§1a) |
| `test/runtests.jl` | Julia tests; `test/test_vectors.json` is a copy of the Python repository's vectors |

## Dependencies

All registered in General and pinned in `Manifest.toml`:

- `CodecZlib` (zlib framing, default level; the underlying library is `Zlib_jll`)
- `libsodium_jll` — the AEADs via `ccall`: `crypto_aead_chacha20poly1305_ietf_*` and `crypto_aead_aes256gcm_*`.
  libsodium only offers AES-256-GCM on a CPU with hardware AES; where it is unavailable the proxy omits
  `aead-aes256gcm` from its features and `--cipher aes-256-gcm` falls back to ChaCha20-Poly1305 with a warning.
- `JSON3` (payloads and log records)
- `PrecompileTools`
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

From the Python repository (the harness launches this proxy through the manifest):

```sh
cd ../protocol-proxy
python -m protocol_proxy.conformance ../protocol-proxy-julia/proxy.toml --echo ECHO --manager-dials -v
```

Expected: `echo-julia: all checks pass`, with `tls` skipped (this port has no TLS; do not pass `--tls`).

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
  `SET_LOG_LEVEL`, JSON log lines on stderr, parent-PID watch every second, SIGTERM -> exit 0.

Not implemented: TLS (`--ipc-tls`), `LOG` batches over the socket (`log` is not advertised; the manager reads
stderr), `--socket-logging` is accepted and ignored.

## SIGTERM in Julia

Julia blocks SIGTERM on its threads and consumes it on an internal signal thread, where it is fatal (exit code 143
with a backtrace), so a libuv signal watcher never fires. `src/signals.jl` unblocks SIGTERM on the main thread and
installs a `sigaction` handler there that only stores the signal number into pre-allocated memory; Linux delivers a
process-directed signal to the main thread first when that thread does not block it. A Task polls the word every
50 ms and stops the proxy. This is Linux-specific (glibc `struct sigaction` layout for x86_64 and aarch64).
