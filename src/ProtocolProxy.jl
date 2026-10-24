"""
ProtocolProxy: a Julia port of the protocol-proxy IPC wire contract (PROTOCOL.md) and the proxy-side process
behaviour, with an ECHO proxy as its entry point (`bin/echo-proxy`).
"""
module ProtocolProxy

using Sockets
using UUIDs
using Dates
using Random
using Logging
using JSON3
using CodecZlib
using libsodium_jll

export Header, pack, unpack, header_length, request_id_max, uuid_bytes, uuid_from_bytes
export compress, decompress, aead_encrypt, aead_decrypt, aes_gcm_available, seal, open_payload, AuthenticationError
export Connector, Peer, Message, Pending, Callback, register_callback!, unregister_callback!, start_listener!, send_message,
       wait_response, stop!, ResponseTimeout
export Proxy, Handshake, read_handshake, run!, send_registration!, health_report
export ProxyLogger, install_logger!, set_level!
export parse_args, main, echo_main, self_test

include("headers.jl")
include("codec.jl")
include("logging.jl")
include("connector.jl")
include("signals.jl")
include("proxy.jl")
include("vectors.jl")
include("cli.jl")

function __init__()
    try
        sodium_init(; force=true)       # the Ref may be a precompiled true; libsodium must initialise in this process
    catch e
        @warn "libsodium failed to initialise: $e"
    end
end

include("precompile.jl")

end # module
