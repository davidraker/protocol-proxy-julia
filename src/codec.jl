# Payload transforms (PROTOCOL.md §4 and §5): zlib compression behind bit 1, AEAD encryption behind bit 2
# (ChaCha20-Poly1305, or AES-256-GCM with bit 4). The AEADs come from libsodium (libsodium_jll).

const KEY_BYTES = 32
const NONCE_BYTES = 12
const TAG_BYTES = 16
const COMPRESS_THRESHOLD = 4096
const PERSISTENT_MAX_FRAME = 256 * 1024

const CIPHER_CHACHA = "chacha20-poly1305"
const CIPHER_AES_GCM = "aes-256-gcm"
const FEATURE_CHACHA = "aead-chacha20poly1305"
const FEATURE_AES_GCM = "aead-aes256gcm"
const FEATURE_COMPRESS = "compress"
#: cipher name => (feature a peer must advertise to receive it, whether the header's AES-GCM bit is set)
const CIPHERS = Dict(CIPHER_CHACHA => (FEATURE_CHACHA, false), CIPHER_AES_GCM => (FEATURE_AES_GCM, true))

struct AuthenticationError <: Exception
    msg::String
end
Base.showerror(io::IO, e::AuthenticationError) = print(io, "AuthenticationError: ", e.msg)

const _sodium_ready = Ref(false)

function sodium_init(; force::Bool=false)
    _sodium_ready[] && !force && return
    rc = ccall((:sodium_init, libsodium), Cint, ())
    rc >= 0 || error("sodium_init failed ($rc)")
    _sodium_ready[] = true
    return
end

"""Whether libsodium can do AES-256-GCM on this CPU (it needs hardware AES instructions)."""
function aes_gcm_available()
    sodium_init()
    return ccall((:crypto_aead_aes256gcm_is_available, libsodium), Cint, ()) == 1
end

compress(data::AbstractVector{UInt8}) = transcode(ZlibCompressor, Vector{UInt8}(data))
decompress(data::AbstractVector{UInt8}) = transcode(ZlibDecompressor, Vector{UInt8}(data))

"""
    aead_encrypt(key, nonce, plaintext, ad; aes_gcm=false) -> ciphertext || tag

Encrypt with ChaCha20-Poly1305 (IETF, 12-byte nonce) or AES-256-GCM; the result is `length(plaintext) + 16` bytes.
"""
function aead_encrypt(key::AbstractVector{UInt8}, nonce::AbstractVector{UInt8}, plaintext::AbstractVector{UInt8},
                      ad::AbstractVector{UInt8}; aes_gcm::Bool=false)
    sodium_init()
    length(key) == KEY_BYTES || throw(ArgumentError("the key must be $KEY_BYTES bytes"))
    length(nonce) == NONCE_BYTES || throw(ArgumentError("the nonce must be $NONCE_BYTES bytes"))
    key, nonce, plaintext, ad = Vector{UInt8}(key), Vector{UInt8}(nonce), Vector{UInt8}(plaintext), Vector{UInt8}(ad)
    out = Vector{UInt8}(undef, length(plaintext) + TAG_BYTES)
    outlen = Ref{Culonglong}(0)
    rc = if aes_gcm
        aes_gcm_available() || error("AES-256-GCM is not available on this CPU")
        ccall((:crypto_aead_aes256gcm_encrypt, libsodium), Cint,
              (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
              out, outlen, plaintext, length(plaintext), ad, length(ad), C_NULL, nonce, key)
    else
        ccall((:crypto_aead_chacha20poly1305_ietf_encrypt, libsodium), Cint,
              (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
              out, outlen, plaintext, length(plaintext), ad, length(ad), C_NULL, nonce, key)
    end
    rc == 0 || error("AEAD encryption failed ($rc)")
    resize!(out, Int(outlen[]))
    return out
end

"""
    aead_decrypt(key, nonce, ciphertext_and_tag, ad; aes_gcm=false) -> plaintext

Throws `AuthenticationError` when the tag does not verify.
"""
function aead_decrypt(key::AbstractVector{UInt8}, nonce::AbstractVector{UInt8}, ciphertext::AbstractVector{UInt8},
                      ad::AbstractVector{UInt8}; aes_gcm::Bool=false)
    sodium_init()
    length(key) == KEY_BYTES || throw(ArgumentError("the key must be $KEY_BYTES bytes"))
    length(nonce) == NONCE_BYTES || throw(ArgumentError("the nonce must be $NONCE_BYTES bytes"))
    length(ciphertext) >= TAG_BYTES || throw(AuthenticationError("ciphertext shorter than the tag"))
    key, nonce, ciphertext, ad = Vector{UInt8}(key), Vector{UInt8}(nonce), Vector{UInt8}(ciphertext), Vector{UInt8}(ad)
    out = Vector{UInt8}(undef, length(ciphertext) - TAG_BYTES)
    outlen = Ref{Culonglong}(0)
    rc = if aes_gcm
        aes_gcm_available() || throw(AuthenticationError("AES-256-GCM is not available on this CPU"))
        ccall((:crypto_aead_aes256gcm_decrypt, libsodium), Cint,
              (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Ptr{UInt8}),
              out, outlen, C_NULL, ciphertext, length(ciphertext), ad, length(ad), nonce, key)
    else
        ccall((:crypto_aead_chacha20poly1305_ietf_decrypt, libsodium), Cint,
              (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Ptr{UInt8}),
              out, outlen, C_NULL, ciphertext, length(ciphertext), ad, length(ad), nonce, key)
    end
    rc == 0 || throw(AuthenticationError("AEAD tag verification failed"))
    resize!(out, Int(outlen[]))
    return out
end

random_nonce() = rand(RandomDevice(), UInt8, NONCE_BYTES)

"""
    seal(header, payload; key=nothing, compress=false, aes_gcm=false, nonce=random_nonce()) -> (raw_header, wire_payload)

Apply the sender's transforms in order (compress, then encrypt) and return the header bytes as sent together with
the payload as it goes on the wire. The header passed in carries the message's identity (method, request id, sender,
remote, flags); its `data_length`, `compressed`, `encrypted` and `aes_gcm` fields are filled in here. For an
encrypted frame the returned header bytes are the associated data.
"""
function seal(h::Header, payload::AbstractVector{UInt8}; key::Union{Nothing,AbstractVector{UInt8}}=nothing,
              compress::Bool=false, aes_gcm::Bool=false, nonce::AbstractVector{UInt8}=random_nonce())
    body = Vector{UInt8}(payload)
    if compress
        body = ProtocolProxy.compress(body)
    end
    if key === nothing
        raw = pack(with(h; data_length=length(body), compressed=compress, encrypted=false, aes_gcm=false))
        return raw, body
    end
    raw = pack(with(h; data_length=length(body) + NONCE_BYTES + TAG_BYTES, compressed=compress, encrypted=true, aes_gcm))
    wire = vcat(Vector{UInt8}(nonce), aead_encrypt(key, nonce, body, raw; aes_gcm))
    return raw, wire
end

"""
    open_payload(header, raw_header, wire_payload; key=nothing) -> payload

Undo the sender's transforms: decrypt (authenticating against `raw_header`) when the header says encrypted, then
decompress when it says compressed. Refuses a clear-text frame when `key` is given and an encrypted one when it is
not (`AuthenticationError`), as the mode is fixed per peer.
"""
function open_payload(h::Header, raw_header::AbstractVector{UInt8}, wire::AbstractVector{UInt8};
                      key::Union{Nothing,AbstractVector{UInt8}}=nothing)
    body = Vector{UInt8}(wire)
    if h.encrypted
        key === nothing && throw(AuthenticationError("encrypted $(h.method_name) from $(h.sender_id), with whom no key is shared"))
        length(body) >= NONCE_BYTES + TAG_BYTES ||
            throw(AuthenticationError("encrypted $(h.method_name) from $(h.sender_id) is too short"))
        nonce = body[1:NONCE_BYTES]
        body = aead_decrypt(key, nonce, body[NONCE_BYTES+1:end], Vector{UInt8}(raw_header); aes_gcm=h.aes_gcm)
    elseif key !== nothing
        throw(AuthenticationError("clear-text $(h.method_name) from $(h.sender_id), who must encrypt"))
    end
    if h.compressed
        body = decompress(body)
    end
    return body
end
