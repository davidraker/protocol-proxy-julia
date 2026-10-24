"""
ProtocolProxy: a Julia port of the protocol-proxy IPC wire contract (PROTOCOL.md), both sides of it: the proxy-side
process behaviour with an ECHO proxy as its entry point (`bin/echo-proxy`), and the `ProtocolProxyManager` that
launches proxies from manifests, with the conformance harness as its entry point (`bin/conformance`).
"""
module ProtocolProxy

using Sockets
using UUIDs
using Dates
using Random
using Logging
using JSON3
using CodecZlib
using OpenSSL
using OpenSSL_jll: libssl, libcrypto

export Header, pack, unpack, header_length, request_id_max, uuid_bytes, uuid_from_bytes
export compress, decompress, aead_encrypt, aead_decrypt, aes_gcm_available, seal, open_payload, AuthenticationError
export TlsMaterial, parse_tls_material, tls_material_line
export LogQueue, emit!, drain!, batch_payload, write_json_line
export Connector, Peer, Message, Pending, Callback, register_callback!, unregister_callback!, start_listener!, send_message,
       wait_response, stop!, ResponseTimeout
export Proxy, Handshake, read_handshake, run!, send_registration!, health_report
export ProxyLogger, install_logger!, set_level!
export parse_args, main, echo_main, self_test
# the manager side
export Manifest, ManifestError, Identity, Step, parse_manifest, load_manifest, find_manifest, locate_manifest,
       discover_manifests, search_path, launch_command, self_test_command, resolve_environment, process_key, py_tuple
export Record, record_from_line, record_from_fields, records_from_batch, proxy_logger_name, log_record
export Authority, issue
export Manager, ManagedProxy, start!, get_proxy, wait_registered, request, send_to, set_proxy_log_level!, on_proxy_lost!,
       health, terminate!, wait_exit, run_self_test, proxies, proxy_by_id
export run_conformance, conformance_main, Report, report_text, report_json, report_ok

include("headers.jl")
include("codec.jl")
include("tls.jl")
include("logging.jl")
include("connector.jl")
include("signals.jl")
include("proxy.jl")
include("vectors.jl")
include("cli.jl")
include("manifest.jl")
include("records.jl")
include("authority.jl")
include("manager.jl")
include("conformance.jl")

include("precompile.jl")

end # module
