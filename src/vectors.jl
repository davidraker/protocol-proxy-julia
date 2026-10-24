# Self-test against tests/test_vectors.json of the Python implementation: every frame vector is unpacked, repacked
# and rebuilt byte for byte (encrypted vectors with the fixed nonce), and the constants are compared.

struct VectorMismatch <: Exception
    msg::String
end
Base.showerror(io::IO, e::VectorMismatch) = print(io, "VectorMismatch: ", e.msg)

uuid_from_string(s::AbstractString) = uuid_from_hex(replace(String(s), "-" => ""))

"""Check one frame vector; throws `VectorMismatch` on the first disagreement."""
function check_frame_vector(name::AbstractString, v, ids)
    header_bytes = hex2bytes(String(v[:header_hex]))
    frame_bytes_ = hex2bytes(String(v[:frame_hex]))
    version = Int(v[:header_version])
    h = unpack(header_bytes)
    checks = [
        ("version", Int(h.version), version),
        ("method_name", h.method_name, String(v[:method_name])),
        ("request_id", Int(h.request_id), Int(v[:request_id])),
        ("response_expected", h.response_expected, Bool(v[:response_expected])),
        ("keep_alive", h.keep_alive, Bool(v[:keep_alive])),
        ("compressed", h.compressed, Bool(v[:compressed])),
        ("encrypted", h.encrypted, Bool(v[:encrypted])),
        ("aes_gcm", h.aes_gcm, Bool(v[:aes_gcm])),
        ("sender_id", h.sender_id, uuid_from_string(ids[:sender_id])),
        ("sender_token", h.sender_token, uuid_from_string(ids[:sender_token])),
        ("remote_id", h.remote_id, v[:remote_id] === nothing ? nothing : uuid_from_string(v[:remote_id])),
        ("data_length", Int(h.data_length), length(frame_bytes_) - length(header_bytes)),
    ]
    for (field, got, want) in checks
        got == want || throw(VectorMismatch("$name: $field is $(repr(got)), expected $(repr(want))"))
    end
    pack(h) == header_bytes || throw(VectorMismatch("$name: repacked header differs"))
    # Rebuild the whole frame from the plain payload. Compressed bytes are those of the zlib implementation that
    # produced them (the vectors come from zlib-ng; Julia's Zlib_jll is classic zlib), so for a compressed vector
    # the rebuilt frame is checked by opening it again and the vector's own payload by opening it, not byte for byte.
    payload = Vector{UInt8}(codeunits(String(v[:payload_utf8])))
    key = h.encrypted ? hex2bytes(String(ids[:key_hex])) : nothing
    nonce = hex2bytes(String(ids[:nonce_hex]))
    raw, wire = seal(h, payload; key, compress=h.compressed, aes_gcm=h.aes_gcm, nonce)
    if h.compressed
        rebuilt = unpack(raw)
        with(rebuilt; data_length=0) == with(h; data_length=0) || throw(VectorMismatch("$name: sealed header differs beyond data_length"))
        length(wire) == rebuilt.data_length || throw(VectorMismatch("$name: data_length does not count the wire payload"))
        open_payload(rebuilt, raw, wire; key) == payload || throw(VectorMismatch("$name: our compressed frame does not open"))
    else
        raw == header_bytes || throw(VectorMismatch("$name: sealed header differs"))
        vcat(raw, wire) == frame_bytes_ || throw(VectorMismatch("$name: rebuilt frame differs"))
    end
    # And open the vector's wire frame back to the plain payload.
    opened = open_payload(h, header_bytes, frame_bytes_[length(header_bytes)+1:end]; key)
    opened == payload || throw(VectorMismatch("$name: opened payload differs"))
    if h.encrypted
        tampered = copy(frame_bytes_[length(header_bytes)+1:end])
        tampered[end] ⊻= 0x01
        ok = try
            open_payload(h, header_bytes, tampered; key)
            false
        catch e
            e isa AuthenticationError
        end
        ok || throw(VectorMismatch("$name: a tampered tag was accepted"))
    end
    return true
end

function check_constants(constants)
    expected = Dict("header_length_v1" => HEADER_LENGTH_V1, "header_length_v2" => HEADER_LENGTH_V2,
                    "version_word_bytes" => VERSION_WORD_BYTES, "bit_response_expected" => BIT_RESPONSE_EXPECTED,
                    "bit_compressed" => BIT_COMPRESSED, "bit_encrypted" => BIT_ENCRYPTED, "bit_keep_alive" => BIT_KEEP_ALIVE,
                    "bit_aes_gcm" => BIT_AES_GCM, "request_id_max_v1" => REQUEST_ID_MAX_V1,
                    "request_id_max_v2" => REQUEST_ID_MAX_V2, "nonce_bytes" => NONCE_BYTES, "tag_bytes" => TAG_BYTES,
                    "key_bytes" => KEY_BYTES)
    for (k, want) in expected
        got = Int(constants[Symbol(k)])
        got == want || throw(VectorMismatch("constant $k is $got here, $want in the vectors"))
    end
    return true
end

function check_log_channel(log_channel)
    record = JSON3.read(String(log_channel[:json_line]))
    for field in ("name", "levelno", "levelname", "pathname", "lineno", "funcName", "created", "msecs", "process", "msg")
        haskey(record, Symbol(field)) || throw(VectorMismatch("log json_line lacks $field"))
    end
    ours = record_fields(Logging.Warn, "device d1 offline", Main, "/srv/proxy/example.py", 42)
    for field in ("name", "levelno", "levelname", "pathname", "lineno", "funcName", "created", "msecs", "process", "msg")
        haskey(ours, field) || throw(VectorMismatch("our log record lacks $field"))
    end
    ours["levelno"] == record[:levelno] || throw(VectorMismatch("WARNING levelno differs"))
    return true
end

"""
    self_test(path; verbose=false) -> Bool

Check every vector in `path` (tests/test_vectors.json of the Python implementation). Prints each failure.
"""
function self_test(path::AbstractString=default_vectors_path(); verbose::Bool=false)
    isfile(path) || (println(stderr, "self-test: vectors file not found: $path"); return false)
    vectors = JSON3.read(read(path, String))
    ok = true
    function run(name, f)
        try
            f()
            verbose && println("ok   $name")
        catch e
            ok = false
            println(stderr, "FAIL $name: $(sprint(showerror, e))")
        end
    end
    run("constants", () -> check_constants(vectors[:constants]))
    for (name, v) in vectors[:frames]
        if Bool(v[:aes_gcm]) && !aes_gcm_available()
            verbose && println("skip $name (AES-256-GCM is not available on this CPU)")
            continue
        end
        run(string(name), () -> check_frame_vector(string(name), v, vectors[:identities]))
    end
    run("log_channel", () -> check_log_channel(vectors[:log_channel]))
    verbose && println(ok ? "self-test: all vectors pass" : "self-test: FAILURES")
    return ok
end
