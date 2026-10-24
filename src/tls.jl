# TLS 1.3 toward the manager (PROTOCOL.md §1, §2, §6). The manager is an ephemeral certificate authority: with
# `--ipc-tls true` it writes one JSON line `{"ca", "cert", "key"}` of PEM material to stdin after the tokens (and the
# AEAD key). Every connection with a TLS peer is then TLS, each end presenting its certificate and requiring the other's
# to chain to that CA; hostnames are not checked, the certificate's common name carries the peer's id and a frame is
# accepted only when its sender id is that name. OpenSSL.jl's `SSLStream` wraps the `TCPSocket` through memory BIOs,
# so the connector's connections are plain `IO`.

"""The PEM material of one end: the issuing CA's certificate, this end's certificate and its private key."""
struct TlsMaterial
    ca::String
    cert::String
    key::String
end

"""Parse the JSON line a manager writes to stdin."""
function parse_tls_material(line::Union{AbstractString,AbstractVector{UInt8}})
    text = line isa AbstractString ? String(line) : String(Vector{UInt8}(line))
    fields = try
        JSON3.read(text)
    catch e
        throw(ArgumentError("TLS material is not a JSON object: $(sprint(showerror, e))"))
    end
    fields isa JSON3.Object || throw(ArgumentError("TLS material is not a JSON object"))
    ca, cert, key = get(fields, :ca, ""), get(fields, :cert, ""), get(fields, :key, "")
    (isempty(ca) || isempty(cert) || isempty(key)) && throw(ArgumentError("TLS material must carry ca, cert and key"))
    return TlsMaterial(String(ca), String(cert), String(key))
end

"""The JSON line form (what a manager writes)."""
tls_material_line(m::TlsMaterial) = JSON3.write(Dict("ca" => m.ca, "cert" => m.cert, "key" => m.key)) * "\n"

const SSL_VERIFY_PEER = Cint(0x01)
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = Cint(0x02)
const SSL_ERROR_WANT_READ = Cint(2)
const SSL_ERROR_WANT_WRITE = Cint(3)
const SSL_ERROR_ZERO_RETURN = Cint(6)
const SSL_CTRL_SET_TLSEXT_HOSTNAME = Cint(55)
const TLSEXT_NAMETYPE_host_name = Clong(0)
const NID_commonName = Cint(13)

"""
    ssl_context(material, server::Bool) -> OpenSSL.SSLContext

TLS 1.3 only, our certificate and key, the CA as the only trust anchor (in memory, no file), the peer's certificate
required and verified against it.
"""
function ssl_context(m::TlsMaterial, server::Bool)
    ctx = OpenSSL.SSLContext(server ? OpenSSL.TLSServerMethod() : OpenSSL.TLSClientMethod(), "")   # "": no default CA file
    OpenSSL.ssl_set_min_protocol_version(ctx, OpenSSL.TLS1_3_VERSION)
    OpenSSL.ssl_use_certificate(ctx, OpenSSL.X509Certificate(m.cert))
    OpenSSL.ssl_use_private_key(ctx, OpenSSL.EvpPKey(m.key))
    store = ccall((:SSL_CTX_get_cert_store, libssl), Ptr{Cvoid}, (OpenSSL.SSLContext,), ctx)
    store == C_NULL && error(openssl_error_text("SSL_CTX_get_cert_store failed"))
    ca = OpenSSL.X509Certificate(m.ca)
    ccall((:X509_STORE_add_cert, libcrypto), Cint, (Ptr{Cvoid}, OpenSSL.X509Certificate), store, ca) == 1 ||
        error(openssl_error_text("the CA certificate was refused"))
    ccall((:SSL_CTX_set_verify, libssl), Cvoid, (OpenSSL.SSLContext, Cint, Ptr{Cvoid}),
          ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, C_NULL)
    return ctx
end

"""The common name of a certificate's subject, or nothing."""
function common_name(cert::OpenSSL.X509Certificate)
    name = OpenSSL.get_subject_name(cert)
    buf = Vector{UInt8}(undef, 256)
    n = ccall((:X509_NAME_get_text_by_NID, libcrypto), Cint, (OpenSSL.X509Name, Cint, Ptr{UInt8}, Cint),
              name, NID_commonName, buf, length(buf))
    n < 0 && return nothing
    return String(buf[1:n])
end

struct TlsHandshakeError <: Exception
    msg::String
end
Base.showerror(io::IO, e::TlsHandshakeError) = print(io, "TlsHandshakeError: ", e.msg)

"""
    tls_handshake!(ssl::OpenSSL.SSLStream, server::Bool; expect=nothing) -> common name of the peer's certificate

Drive `SSL_accept`/`SSL_connect` to completion over the non-blocking BIOs, then require a verified peer certificate
and, when `expect` is given, that its common name is `expect` (the peer's id as 32 hex characters).
"""
function tls_handshake!(ssl::OpenSSL.SSLStream, server::Bool; expect::Union{Nothing,AbstractString}=nothing,
                        server_name::Union{Nothing,AbstractString}=nothing)
    raw = ssl.ssl.ssl
    if !server && server_name !== nothing
        ccall((:SSL_ctrl, libssl), Clong, (Ptr{Cvoid}, Cint, Clong, Cstring),
              raw, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, server_name)
    end
    while true
        ret = server ? ccall((:SSL_accept, libssl), Cint, (Ptr{Cvoid},), raw) :
                       ccall((:SSL_connect, libssl), Cint, (Ptr{Cvoid},), raw)
        ret == 1 && break
        err = ccall((:SSL_get_error, libssl), Cint, (Ptr{Cvoid}, Cint), raw, ret)
        if err == SSL_ERROR_WANT_READ
            eof(ssl.io) && throw(TlsHandshakeError("the peer closed the connection during the TLS handshake"))
        elseif err == SSL_ERROR_WANT_WRITE
            flush(ssl.io)
        elseif err == SSL_ERROR_ZERO_RETURN
            throw(TlsHandshakeError("the peer closed the connection during the TLS handshake"))
        else
            throw(TlsHandshakeError(openssl_error_text("TLS handshake failed")))
        end
    end
    ccall((:SSL_set_read_ahead, libssl), Cvoid, (Ptr{Cvoid}, Cint), raw, Cint(1))
    result = ccall((:SSL_get_verify_result, libssl), Clong, (Ptr{Cvoid},), raw)
    if result != 0
        text = unsafe_string(ccall((:X509_verify_cert_error_string, libcrypto), Ptr{UInt8}, (Clong,), result))
        throw(TlsHandshakeError("the peer's certificate does not chain to the manager's CA: $text"))
    end
    cert = OpenSSL.get_peer_certificate(ssl)
    cert === nothing && throw(TlsHandshakeError("the peer presented no certificate"))
    cn = common_name(cert)
    cn === nothing && throw(TlsHandshakeError("the peer's certificate has no common name"))
    if expect !== nothing && cn != expect
        throw(TlsHandshakeError("the peer's certificate names $(repr(cn)), expected $(repr(expect))"))
    end
    return cn
end
