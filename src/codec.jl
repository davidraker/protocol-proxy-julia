# Payload transforms (PROTOCOL.md §4 and §5): zlib compression behind bit 1, AEAD encryption behind bit 2
# (ChaCha20-Poly1305, or AES-256-GCM with bit 4). Both AEADs come from OpenSSL's EVP interface (OpenSSL_jll), so
# AES-256-GCM is available on every CPU (in software where there is no hardware AES).

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

"""Whether AES-256-GCM can be used here. Always true with OpenSSL (kept for callers written against libsodium)."""
aes_gcm_available() = true

# EVP_CIPHER_CTX_ctrl commands (openssl/evp.h)
const EVP_CTRL_AEAD_SET_IVLEN = Cint(0x9)
const EVP_CTRL_AEAD_GET_TAG = Cint(0x10)
const EVP_CTRL_AEAD_SET_TAG = Cint(0x11)

evp_aead(aes_gcm::Bool) = aes_gcm ? ccall((:EVP_aes_256_gcm, libcrypto), Ptr{Cvoid}, ()) :
                                    ccall((:EVP_chacha20_poly1305, libcrypto), Ptr{Cvoid}, ())

function openssl_error_text(what::AbstractString)
    code = ccall((:ERR_get_error, libcrypto), Culong, ())
    code == 0 && return what
    buf = Vector{UInt8}(undef, 256)
    ccall((:ERR_error_string_n, libcrypto), Cvoid, (Culong, Ptr{UInt8}, Csize_t), code, buf, length(buf))
    return what * ": " * unsafe_string(pointer(buf))
end

evp_init(ctx::Ptr{Cvoid}, encrypt::Bool, cipher::Ptr{Cvoid}, key, nonce) = encrypt ?
    ccall((:EVP_EncryptInit_ex, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, cipher, C_NULL, key, nonce) :
    ccall((:EVP_DecryptInit_ex, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, cipher, C_NULL, key, nonce)

"""Run `f(ctx)` with a fresh EVP_CIPHER_CTX initialised for the AEAD, key and nonce; the context is always freed."""
function with_aead_context(f, key::Vector{UInt8}, nonce::Vector{UInt8}, encrypt::Bool, aes_gcm::Bool)
    ctx = ccall((:EVP_CIPHER_CTX_new, libcrypto), Ptr{Cvoid}, ())
    ctx == C_NULL && error(openssl_error_text("EVP_CIPHER_CTX_new failed"))
    try
        evp_init(ctx, encrypt, evp_aead(aes_gcm), C_NULL, C_NULL) == 1 || error(openssl_error_text("AEAD init failed"))
        ccall((:EVP_CIPHER_CTX_ctrl, libcrypto), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}),
              ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, C_NULL) == 1 || error(openssl_error_text("AEAD nonce length refused"))
        evp_init(ctx, encrypt, C_NULL, key, nonce) == 1 || error(openssl_error_text("AEAD key/nonce refused"))
        return f(ctx)
    finally
        ccall((:EVP_CIPHER_CTX_free, libcrypto), Cvoid, (Ptr{Cvoid},), ctx)
    end
end

function check_aead_args(key, nonce)
    length(key) == KEY_BYTES || throw(ArgumentError("the key must be $KEY_BYTES bytes"))
    length(nonce) == NONCE_BYTES || throw(ArgumentError("the nonce must be $NONCE_BYTES bytes"))
    return Vector{UInt8}(key), Vector{UInt8}(nonce)
end

compress(data::AbstractVector{UInt8}) = transcode(ZlibCompressor, Vector{UInt8}(data))
decompress(data::AbstractVector{UInt8}) = transcode(ZlibDecompressor, Vector{UInt8}(data))

"""
    aead_encrypt(key, nonce, plaintext, ad; aes_gcm=false) -> ciphertext || tag

Encrypt with ChaCha20-Poly1305 (IETF, 12-byte nonce) or AES-256-GCM; the result is `length(plaintext) + 16` bytes.
"""
function aead_encrypt(key::AbstractVector{UInt8}, nonce::AbstractVector{UInt8}, plaintext::AbstractVector{UInt8},
                      ad::AbstractVector{UInt8}; aes_gcm::Bool=false)
    key, nonce = check_aead_args(key, nonce)
    plaintext, ad = Vector{UInt8}(plaintext), Vector{UInt8}(ad)
    out = Vector{UInt8}(undef, length(plaintext) + TAG_BYTES)
    outlen = Ref{Cint}(0)
    with_aead_context(key, nonce, true, aes_gcm) do ctx
        GC.@preserve out plaintext ad begin
            if !isempty(ad)
                ccall((:EVP_EncryptUpdate, libcrypto), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}, Ptr{UInt8}, Cint),
                      ctx, C_NULL, outlen, ad, length(ad)) == 1 || error(openssl_error_text("AEAD associated data refused"))
            end
            n = 0
            if !isempty(plaintext)
                ccall((:EVP_EncryptUpdate, libcrypto), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}, Ptr{UInt8}, Cint),
                      ctx, pointer(out), outlen, plaintext, length(plaintext)) == 1 || error(openssl_error_text("AEAD encryption failed"))
                n = Int(outlen[])
            end
            ccall((:EVP_EncryptFinal_ex, libcrypto), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}),
                  ctx, pointer(out) + n, outlen) == 1 || error(openssl_error_text("AEAD encryption failed"))
            n += Int(outlen[])
            n == length(plaintext) || error("AEAD produced $n bytes for $(length(plaintext)) of plaintext")
            ccall((:EVP_CIPHER_CTX_ctrl, libcrypto), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}),
                  ctx, EVP_CTRL_AEAD_GET_TAG, TAG_BYTES, pointer(out) + n) == 1 || error(openssl_error_text("AEAD tag unavailable"))
        end
    end
    return out
end

"""
    aead_decrypt(key, nonce, ciphertext_and_tag, ad; aes_gcm=false) -> plaintext

Throws `AuthenticationError` when the tag does not verify.
"""
function aead_decrypt(key::AbstractVector{UInt8}, nonce::AbstractVector{UInt8}, ciphertext::AbstractVector{UInt8},
                      ad::AbstractVector{UInt8}; aes_gcm::Bool=false)
    key, nonce = check_aead_args(key, nonce)
    length(ciphertext) >= TAG_BYTES || throw(AuthenticationError("ciphertext shorter than the tag"))
    ciphertext, ad = Vector{UInt8}(ciphertext), Vector{UInt8}(ad)
    body_len = length(ciphertext) - TAG_BYTES
    out = Vector{UInt8}(undef, body_len)
    outlen = Ref{Cint}(0)
    ok = with_aead_context(key, nonce, false, aes_gcm) do ctx
        GC.@preserve out ciphertext ad begin
            if !isempty(ad)
                ccall((:EVP_DecryptUpdate, libcrypto), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}, Ptr{UInt8}, Cint),
                      ctx, C_NULL, outlen, ad, length(ad)) == 1 || error(openssl_error_text("AEAD associated data refused"))
            end
            n = 0
            if body_len > 0
                ccall((:EVP_DecryptUpdate, libcrypto), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}, Ptr{UInt8}, Cint),
                      ctx, pointer(out), outlen, pointer(ciphertext), body_len) == 1 || error(openssl_error_text("AEAD decryption failed"))
                n = Int(outlen[])
            end
            ccall((:EVP_CIPHER_CTX_ctrl, libcrypto), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}),
                  ctx, EVP_CTRL_AEAD_SET_TAG, TAG_BYTES, pointer(ciphertext) + body_len) == 1 || error(openssl_error_text("AEAD tag refused"))
            rc = ccall((:EVP_DecryptFinal_ex, libcrypto), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}),
                       ctx, pointer(out) + n, outlen)
            rc == 1 || return false
            n += Int(outlen[])
            n == body_len || error("AEAD produced $n bytes for $body_len of ciphertext")
            true
        end
    end
    ok || throw(AuthenticationError("AEAD tag verification failed"))
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
