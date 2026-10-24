# Frame headers (PROTOCOL.md §3): a 2-byte big-endian version word, then the fixed header of that version.
#
#   version 1: >HQ32sH16s16sH      (76 bytes after the version word)
#   version 2: >HQ32sI16s16sH16s   (94 bytes after the version word)

const BIT_RESPONSE_EXPECTED = 0
const BIT_COMPRESSED = 1
const BIT_ENCRYPTED = 2
const BIT_KEEP_ALIVE = 3
const BIT_AES_GCM = 4

const HEADER_LENGTH_V1 = 76
const HEADER_LENGTH_V2 = 94
const VERSION_WORD_BYTES = 2
const METHOD_NAME_BYTES = 32
const REQUEST_ID_MAX_V1 = 0xFFFF
const REQUEST_ID_MAX_V2 = 0xFFFFFFFF
const NO_REMOTE = UUID(0)

"""
    Header(; version=2, data_length, method_name, request_id, sender_id, sender_token, response_expected=false,
             keep_alive=false, compressed=false, encrypted=false, aes_gcm=false, remote_id=nothing)

One frame header. `remote_id` is `nothing` when absent (all zeros on the wire; version 1 never carries one).
"""
struct Header
    version::UInt16
    data_length::UInt64
    method_name::String
    request_id::UInt32
    sender_id::UUID
    sender_token::UUID
    response_expected::Bool
    compressed::Bool
    encrypted::Bool
    keep_alive::Bool
    aes_gcm::Bool
    remote_id::Union{Nothing,UUID}

    function Header(; version::Integer=2, data_length::Integer=0, method_name::AbstractString, request_id::Integer,
                    sender_id::UUID, sender_token::UUID, response_expected::Bool=false, keep_alive::Bool=false,
                    compressed::Bool=false, encrypted::Bool=false, aes_gcm::Bool=false,
                    remote_id::Union{Nothing,UUID}=nothing)
        version in (1, 2) || throw(ArgumentError("unknown header version $version"))
        ncodeunits(method_name) <= METHOD_NAME_BYTES ||
            throw(ArgumentError("method name $(repr(method_name)) exceeds $METHOD_NAME_BYTES bytes"))
        0 <= request_id <= request_id_max(version) ||
            throw(ArgumentError("request id $request_id does not fit the version $version header (maximum $(request_id_max(version)))"))
        if version == 1 && remote_id !== nothing
            throw(ArgumentError("a version 1 header carries no remote id"))
        end
        remote = remote_id === NO_REMOTE ? nothing : remote_id
        new(version, data_length, String(method_name), request_id, sender_id, sender_token, response_expected,
            compressed, encrypted, keep_alive, aes_gcm, remote)
    end
end

"""Header bytes after the version word for a header version."""
header_length(version::Integer) = version == 1 ? HEADER_LENGTH_V1 : version == 2 ? HEADER_LENGTH_V2 :
    throw(ArgumentError("unknown header version $version"))

"""Largest request id the version's field holds."""
request_id_max(version::Integer) = version == 1 ? REQUEST_ID_MAX_V1 : REQUEST_ID_MAX_V2

"""The 16 bytes of a UUID, most significant first (the same bytes Python's `UUID.bytes` gives)."""
function uuid_bytes(u::UUID)
    out = Vector{UInt8}(undef, 16)
    v = u.value
    @inbounds for i in 1:16
        out[i] = UInt8((v >> (8 * (16 - i))) & 0xff)
    end
    return out
end

"""The UUID of 16 bytes, most significant first."""
function uuid_from_bytes(b::AbstractVector{UInt8})
    length(b) == 16 || throw(ArgumentError("a UUID has 16 bytes, got $(length(b))"))
    v = UInt128(0)
    @inbounds for i in 1:16
        v = (v << 8) | UInt128(b[i])
    end
    return UUID(v)
end

function bitflags(h::Header)
    flags = UInt16(0)
    h.response_expected && (flags |= UInt16(1) << BIT_RESPONSE_EXPECTED)
    h.compressed && (flags |= UInt16(1) << BIT_COMPRESSED)
    h.encrypted && (flags |= UInt16(1) << BIT_ENCRYPTED)
    h.keep_alive && (flags |= UInt16(1) << BIT_KEEP_ALIVE)
    h.aes_gcm && (flags |= UInt16(1) << BIT_AES_GCM)
    return flags
end

bit_set(flags::Integer, bit::Integer) = (flags >> bit) & 1 == 1

"""The header as sent: version word included (76 + 2 or 94 + 2 bytes)."""
function pack(h::Header)::Vector{UInt8}
    io = IOBuffer(; sizehint=VERSION_WORD_BYTES + header_length(h.version))
    write(io, hton(h.version))
    write(io, hton(h.data_length))
    name = codeunits(h.method_name)
    write(io, name)
    write(io, zeros(UInt8, METHOD_NAME_BYTES - length(name)))
    if h.version == 1
        write(io, hton(UInt16(h.request_id)))
    else
        write(io, hton(h.request_id))
    end
    write(io, uuid_bytes(h.sender_id))
    write(io, uuid_bytes(h.sender_token))
    write(io, hton(bitflags(h)))
    if h.version == 2
        write(io, uuid_bytes(something(h.remote_id, NO_REMOTE)))
    end
    return take!(io)
end

"""The header version named by the first two bytes of a frame."""
peek_version(raw::AbstractVector{UInt8}) = (UInt16(raw[1]) << 8) | UInt16(raw[2])

"""
    unpack(raw) -> Header

Parse a complete header, version word included, as it came off the wire.
"""
function unpack(raw::AbstractVector{UInt8})::Header
    length(raw) >= VERSION_WORD_BYTES || throw(ArgumentError("header shorter than the version word"))
    version = peek_version(raw)
    version in (1, 2) || throw(ArgumentError("unknown header version $version"))
    expected = VERSION_WORD_BYTES + header_length(version)
    length(raw) == expected || throw(ArgumentError("version $version header is $expected bytes, got $(length(raw))"))
    io = IOBuffer(raw)
    read(io, UInt16)
    data_length = ntoh(read(io, UInt64))
    name_bytes = read(io, METHOD_NAME_BYTES)
    stop = findlast(!=(0x00), name_bytes)
    method_name = stop === nothing ? "" : String(name_bytes[1:stop])
    request_id = version == 1 ? UInt32(ntoh(read(io, UInt16))) : ntoh(read(io, UInt32))
    sender_id = uuid_from_bytes(read(io, 16))
    sender_token = uuid_from_bytes(read(io, 16))
    flags = ntoh(read(io, UInt16))
    remote_id = version == 2 ? uuid_from_bytes(read(io, 16)) : nothing
    return Header(; version, data_length, method_name, request_id, sender_id, sender_token,
                  response_expected=bit_set(flags, BIT_RESPONSE_EXPECTED), compressed=bit_set(flags, BIT_COMPRESSED),
                  encrypted=bit_set(flags, BIT_ENCRYPTED), keep_alive=bit_set(flags, BIT_KEEP_ALIVE),
                  aes_gcm=bit_set(flags, BIT_AES_GCM), remote_id=remote_id)
end

"""A copy of `h` with some fields changed (headers are immutable)."""
function with(h::Header; data_length=h.data_length, compressed=h.compressed, encrypted=h.encrypted, aes_gcm=h.aes_gcm,
              keep_alive=h.keep_alive, request_id=h.request_id)
    Header(; version=h.version, data_length, method_name=h.method_name, request_id, sender_id=h.sender_id,
           sender_token=h.sender_token, response_expected=h.response_expected, keep_alive, compressed, encrypted,
           aes_gcm, remote_id=h.remote_id)
end

function Base.:(==)(a::Header, b::Header)
    a.version == b.version && a.data_length == b.data_length && a.method_name == b.method_name &&
        a.request_id == b.request_id && a.sender_id == b.sender_id && a.sender_token == b.sender_token &&
        a.response_expected == b.response_expected && a.compressed == b.compressed && a.encrypted == b.encrypted &&
        a.keep_alive == b.keep_alive && a.aes_gcm == b.aes_gcm && a.remote_id == b.remote_id
end
