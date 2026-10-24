using Test
using ProtocolProxy
using ProtocolProxy: record_fields, error_payload, unanswerable, next_request_id!, str2bool, with, resolve_ipv4,
                     check_frame_vector, check_constants, check_log_channel, uuid_from_hex, uuid_hex, registration_message,
                     registration_accepted!, iso8601_utc, common_name, cpu_has_aes, resolve_cipher,
                     normalized, conflicts, manifest_dir, option_string, opt_bool, dial_target, is_running, exit_code_of
using UUIDs
using JSON3
using Logging
using Sockets
import OpenSSL
using OpenSSL_jll: libcrypto

# ---- a throwaway certificate authority for the TLS tests (what the Python manager's Authority does) ----------------
function pem_private_key(key::OpenSSL.EvpPKey)
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    ccall((:PEM_write_bio_PrivateKey, libcrypto), Cint, (OpenSSL.BIO, OpenSSL.EvpPKey, Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{Cvoid}, Ptr{Cvoid}),
          bio, key, C_NULL, C_NULL, 0, C_NULL, C_NULL) == 1 || error("PEM_write_bio_PrivateKey failed")
    return String(copy(OpenSSL.bio_get_mem_data(bio)))
end

"""A certificate (and its key) with common name `cn`, self-signed as a CA when `issuer` is nothing, else issued by it."""
function test_issue(cn::AbstractString; issuer=nothing)
    key = OpenSSL.EvpPKey(OpenSSL.rsa_generate_key())
    cert = OpenSSL.X509Certificate()
    cert.version = 2
    name = OpenSSL.X509Name()
    OpenSSL.add_entry(name, "CN", String(cn))
    cert.subject_name = name
    cert.issuer_name = issuer === nothing ? name : issuer.cert.subject_name
    now = round(Int, time())
    cert.time_not_before = OpenSSL.Asn1Time(now - 300)
    cert.time_not_after = OpenSSL.Asn1Time(now + 86400)
    cert.public_key = key
    serial = ccall((:X509_get_serialNumber, libcrypto), Ptr{Cvoid}, (OpenSSL.X509Certificate,), cert)
    ccall((:ASN1_INTEGER_set, libcrypto), Cint, (Ptr{Cvoid}, Clong), serial, rand(1:typemax(Int32)))
    OpenSSL.add_extension(cert, OpenSSL.X509Extension("basicConstraints", issuer === nothing ? "critical,CA:TRUE" : "critical,CA:FALSE"))
    OpenSSL.sign_certificate(cert, issuer === nothing ? key : issuer.key)
    io = IOBuffer()
    write(io, cert)
    return (cert=cert, key=key, cert_pem=String(take!(io)), key_pem=pem_private_key(key))
end

material(ca, leaf) = TlsMaterial(ca.cert_pem, leaf.cert_pem, leaf.key_pem)

const VECTORS = JSON3.read(read(joinpath(@__DIR__, "test_vectors.json"), String))
const SENDER = UUID("11111111-2222-3333-4444-555555555555")
const TOKEN = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
const REMOTE = UUID("99999999-8888-7777-6666-555555555555")
const KEY = collect(UInt8.(0:31))

@testset "ProtocolProxy" begin
    @testset "headers against the vectors" begin
        @test check_constants(VECTORS[:constants])
        @test aes_gcm_available()                 # OpenSSL: on every CPU, so no vector is skipped
        @test any(Bool(v[:aes_gcm]) for (_, v) in VECTORS[:frames])
        for (name, v) in VECTORS[:frames]
            @test check_frame_vector(string(name), v, VECTORS[:identities])
        end
        @test check_log_channel(VECTORS[:log_channel])
        @test self_test(joinpath(@__DIR__, "test_vectors.json"))
    end

    @testset "header layout and limits" begin
        h1 = Header(; version=1, method_name="PING", request_id=7, sender_id=SENDER, sender_token=TOKEN)
        h2 = Header(; version=2, method_name="PING", request_id=70000, sender_id=SENDER, sender_token=TOKEN, remote_id=REMOTE)
        @test length(pack(h1)) == 2 + 76
        @test length(pack(h2)) == 2 + 94
        @test unpack(pack(h1)) == h1
        @test unpack(pack(h2)) == h2
        @test header_length(1) == 76 && header_length(2) == 94
        @test request_id_max(1) == 0xFFFF && request_id_max(2) == 0xFFFFFFFF
        @test_throws ArgumentError Header(; version=1, method_name="PING", request_id=70000, sender_id=SENDER, sender_token=TOKEN)
        @test_throws ArgumentError Header(; method_name="M" ^ 33, request_id=1, sender_id=SENDER, sender_token=TOKEN)
        @test_throws ArgumentError Header(; version=1, method_name="PING", request_id=1, sender_id=SENDER, sender_token=TOKEN, remote_id=REMOTE)
        @test_throws ArgumentError unpack(UInt8[0x00, 0x03])
        @test uuid_from_bytes(uuid_bytes(REMOTE)) == REMOTE
        @test bytes2hex(uuid_bytes(REMOTE)) == "99999999888877776666555555555555"
        # The flag bits
        flagged = Header(; method_name="X", request_id=1, sender_id=SENDER, sender_token=TOKEN, response_expected=true,
                         compressed=true, encrypted=true, keep_alive=true, aes_gcm=true)
        raw = pack(flagged)
        @test raw[end-17:end-16] == UInt8[0x00, 0x1f]
        # Request ids cycle from 1 within the version's field
        c = Connector(SENDER, TOKEN; features=String[])
        @test next_request_id!(c, 2) == 1 && next_request_id!(c, 2) == 2
        c.request_ids[1] = UInt32(0xFFFE)
        @test next_request_id!(c, 1) == 0xFFFE
        @test next_request_id!(c, 1) == 1
    end

    @testset "compression" begin
        payload = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "x" ^ 10000))))
        packed = compress(payload)
        @test length(packed) < length(payload)
        @test decompress(packed) == payload
        @test packed[1] == 0x78          # zlib framing
        h = Header(; method_name="ECHO", request_id=1, sender_id=SENDER, sender_token=TOKEN)
        raw, wire = seal(h, payload; compress=true)
        hh = unpack(raw)
        @test hh.compressed && hh.data_length == length(wire) && length(wire) < length(payload)
        @test open_payload(hh, raw, wire) == payload
        raw, wire = seal(h, payload)
        @test !unpack(raw).compressed && wire == payload
    end

    @testset "AEAD round trips" begin
        h = Header(; method_name="WRITE_POINTS", request_id=9, sender_id=SENDER, sender_token=TOKEN, response_expected=true, remote_id=REMOTE)
        payload = Vector{UInt8}(codeunits("{\"values\": {\"a\": 1}}"))
        for aes_gcm in (false, true)
            raw, wire = seal(h, payload; key=KEY, aes_gcm)
            hh = unpack(raw)
            @test hh.encrypted && hh.aes_gcm == aes_gcm && hh.data_length == length(payload) + 12 + 16
            @test open_payload(hh, raw, wire; key=KEY) == payload
            # a different header (associated data) must fail authentication
            other = pack(with(hh; request_id=10))
            @test_throws AuthenticationError open_payload(unpack(other), other, wire; key=KEY)
            # a flipped ciphertext byte must fail
            bad = copy(wire); bad[20] ⊻= 0x01
            @test_throws AuthenticationError open_payload(hh, raw, bad; key=KEY)
            # the wrong key must fail
            @test_throws AuthenticationError open_payload(hh, raw, wire; key=reverse(KEY))
            # mode is fixed per peer
            @test_throws AuthenticationError open_payload(hh, raw, wire)
            clear_raw, clear_wire = seal(h, payload)
            @test_throws AuthenticationError open_payload(unpack(clear_raw), clear_raw, clear_wire; key=KEY)
            # compress then encrypt
            big = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "z" ^ 65536))))
            raw, wire = seal(h, big; key=KEY, compress=true, aes_gcm)
            @test length(wire) < length(big)
            @test open_payload(unpack(raw), raw, wire; key=KEY) == big
        end
        # random nonces differ between frames
        r1 = seal(h, payload; key=KEY)[2][1:12]
        r2 = seal(h, payload; key=KEY)[2][1:12]
        @test r1 != r2
        # the fixed vector
        v = VECTORS[:frames][:v2_encrypted]
        raw, wire = seal(h, payload; key=KEY, nonce=hex2bytes(String(VECTORS[:identities][:nonce_hex])))
        @test bytes2hex(vcat(raw, wire)) == String(v[:frame_hex])
        # AES-256-GCM known answer (NIST GCM test case 16: 60-byte plaintext, 20 bytes of AAD, 96-bit IV)
        k = hex2bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        iv = hex2bytes("cafebabefacedbaddecaf888")
        pt = hex2bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        aad = hex2bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        ct = aead_encrypt(k, iv, pt, aad; aes_gcm=true)
        @test bytes2hex(ct[1:end-16]) == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        @test bytes2hex(ct[end-15:end]) == "76fc6ece0f4e1768cddf8853bb2d551b"
        @test aead_decrypt(k, iv, ct, aad; aes_gcm=true) == pt
        # empty plaintext still authenticates its header
        empty_ct = aead_encrypt(KEY, iv, UInt8[], aad; aes_gcm=true)
        @test length(empty_ct) == 16 && aead_decrypt(KEY, iv, empty_ct, aad; aes_gcm=true) == UInt8[]
        @test_throws AuthenticationError aead_decrypt(KEY, iv, empty_ct, UInt8[]; aes_gcm=true)
        # --cipher auto follows the CPU flag; both names resolve without fallback
        @test resolve_cipher("auto") == (cpu_has_aes() ? "aes-256-gcm" : "chacha20-poly1305")
        @test resolve_cipher("aes-256-gcm") == "aes-256-gcm" && resolve_cipher("ChaCha20-Poly1305") == "chacha20-poly1305"
    end

    @testset "LOG queue" begin
        q = LogQueue(; max_len=10, rate=100.0, burst=5)
        rec(i) = Dict{String,Any}("msg" => "r$i", "levelno" => 20)
        @test all(emit!(q, rec(i)) for i in 1:5)      # the burst
        @test !emit!(q, rec(6))                        # beyond it: dropped and counted
        @test length(q) == 5 && q.total_dropped == 1
        taken, dropped = drain!(q, 2)
        @test [r["msg"] for r in taken] == ["r1", "r2"] && dropped == 1
        taken, dropped = drain!(q)
        @test length(taken) == 3 && dropped == 0 && isempty(q)
        sleep(0.1)                                     # tokens refill at 100/s, capped at the burst
        @test count(emit!(q, rec(i)) for i in 1:20) == 5
        # the queue is bounded independently of the rate
        big = LogQueue(; max_len=3, rate=1.0e6, burst=1000)
        @test count(emit!(big, rec(i)) for i in 1:10) == 3 && big.dropped == 7
        # the batch payload
        body = JSON3.read(batch_payload(drain!(big)...))
        @test length(body[:records]) == 3 && body[:dropped] == 7 && body[:records][1][:msg] == "r1"
        @test JSON3.read(batch_payload(Dict{String,Any}[], 0))[:records] == []
        # the logger routes to the queue while one is installed, and back to its stream when it is removed
        buf = IOBuffer()
        logger = ProxyLogger(; levelno=10, json=true, stream=buf)
        logger.queue = LogQueue()
        with_logger(logger) do
            @info "over the socket" tag=1
        end
        @test position(buf) == 0
        records, _ = drain!(logger.queue)
        @test length(records) == 1 && records[1]["msg"] == "over the socket" && records[1]["tag"] == 1 && records[1]["levelname"] == "INFO"
        logger.queue = nothing
        with_logger(logger) do
            @warn "back on stderr"
        end
        @test JSON3.read(String(take!(buf)))[:msg] == "back on stderr"
        # the defaults of §11a
        d = LogQueue()
        @test d.max_len == 2000 && d.rate == 50.0 && d.burst == 200
        @test ProtocolProxy.LOG_FLUSH_INTERVAL == 0.2 && ProtocolProxy.LOG_BATCH_SIZE == 64
        @test "log" in ProtocolProxy.default_proxy_features()
    end

    @testset "TLS" begin
        ca = test_issue("protocol-proxy test CA")
        a_id, a_token = UUID("aaaaaaaa-0000-0000-0000-00000000000a"), UUID("aaaaaaaa-1111-1111-1111-11111111111a")
        b_id, b_token = UUID("bbbbbbbb-0000-0000-0000-00000000000b"), UUID("bbbbbbbb-1111-1111-1111-11111111111b")
        a_mat = material(ca, test_issue(uuid_hex(a_id); issuer=ca))
        b_mat = material(ca, test_issue(uuid_hex(b_id); issuer=ca))
        # the stdin line
        parsed = parse_tls_material(tls_material_line(a_mat))
        @test parsed.ca == a_mat.ca && parsed.cert == a_mat.cert && parsed.key == a_mat.key
        @test_throws ArgumentError parse_tls_material("{\"ca\": \"x\"}")
        @test_throws ArgumentError parse_tls_material("not json")
        hs = read_handshake(IOBuffer("0123456789abcdef0123456789abcdef" * "fedcba9876543210fedcba9876543210" * tls_material_line(a_mat)); ipc_tls=true)
        @test hs.tls == a_mat && hs.key === nothing
        @test_throws ArgumentError read_handshake(IOBuffer("0123456789abcdef0123456789abcdef" * "fedcba9876543210fedcba9876543210\n"); ipc_tls=true)
        @test common_name(OpenSSL.X509Certificate(a_mat.cert)) == uuid_hex(a_id)
        # two TLS connectors: persistent and per-message requests, both directions, identity from the certificate
        a = Connector(a_id, a_token; name="a", inbound_address="127.0.0.1", tls=a_mat)
        b = Connector(b_id, b_token; name="b", inbound_address="127.0.0.1", tls=b_mat)
        seen = Ref{Any}(nothing)
        register_callback!(b, (c, h, p) -> p, "ECHO"; provides_response=true)
        register_callback!(a, (c, h, p) -> p, "ECHO"; provides_response=true)
        start_listener!(a); start_listener!(b)
        a.peers[b_id] = Peer(b_id, b_token; address=b.bound, tls=true)
        b.peers[a_id] = Peer(a_id, a_token; address=a.bound, tls=true)
        try
            small = Vector{UInt8}(codeunits("{\"n\": 1}"))
            @test wait_response(send_message(a, a.peers[b_id], Message("ECHO", small; response_expected=true)), 10.0) == small
            a.peers[b_id].persistent = true
            large = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "x" ^ 65536))))
            @test wait_response(send_message(a, a.peers[b_id], Message("ECHO", large; response_expected=true)), 10.0) == large
            link = a.peers[b_id].connection
            @test link !== nothing && link.sock isa OpenSSL.SSLStream && link.tls_peer == uuid_hex(b_id)
            sleep(0.1)
            adopted = b.peers[a_id].connection
            @test adopted !== nothing && adopted.tls_peer == uuid_hex(a_id)
            @test wait_response(send_message(b, b.peers[a_id], Message("ECHO", small; response_expected=true)), 10.0) == small
            # a plain connector cannot talk to a TLS listener
            plain = Connector(a_id, a_token; name="plain", inbound_address="127.0.0.1")
            plain.peers[b_id] = Peer(b_id, b_token; address=b.bound)
            @test_throws Exception wait_response(send_message(plain, plain.peers[b_id], Message("ECHO", small; response_expected=true)), 3.0)
            # a certificate from the right CA but naming someone else is refused by the dialler...
            imposter_mat = material(ca, test_issue(uuid_hex(UUID("cccccccc-0000-0000-0000-00000000000c")); issuer=ca))
            imposter = Connector(a_id, a_token; name="imposter", inbound_address="127.0.0.1", tls=imposter_mat)
            imposter.peers[b_id] = Peer(b_id, b_token; address=b.bound, tls=true)
            @test_throws Exception wait_response(send_message(imposter, imposter.peers[b_id], Message("ECHO", small; response_expected=true)), 3.0)
            # ...and by the listener: its frames claim a's id but the certificate says otherwise (checked by the other end)
            @test_throws ProtocolProxy.TlsHandshakeError begin
                sock = Sockets.connect(ip"127.0.0.1", b.bound[2])
                ssl = OpenSSL.SSLStream(ProtocolProxy.ssl_context(imposter_mat, false), sock)
                ProtocolProxy.tls_handshake!(ssl, false; expect=uuid_hex(a_id))
            end
            # a certificate from another CA fails the handshake
            other_ca = test_issue("another CA")
            stranger = Connector(a_id, a_token; name="stranger", inbound_address="127.0.0.1", tls=material(other_ca, test_issue(uuid_hex(a_id); issuer=other_ca)))
            stranger.peers[b_id] = Peer(b_id, b_token; address=b.bound, tls=true)
            @test_throws Exception wait_response(send_message(stranger, stranger.peers[b_id], Message("ECHO", small; response_expected=true)), 3.0)
            # a peer marked TLS must not be dialled without material
            nomat = Connector(a_id, a_token; name="nomat", inbound_address="127.0.0.1")
            nomat.peers[b_id] = Peer(b_id, b_token; address=b.bound, tls=true)
            @test_throws Exception wait_response(send_message(nomat, nomat.peers[b_id], Message("ECHO", small; response_expected=true)), 3.0)
            stop!(plain); stop!(imposter); stop!(stranger); stop!(nomat)
        finally
            stop!(a); stop!(b)
        end
        # bad material fails at construction
        @test_throws Exception Connector(a_id, a_token; tls=TlsMaterial("junk", a_mat.cert, a_mat.key))
    end

    @testset "loopback request/response" begin
        a = Connector(SENDER, TOKEN; name="a", inbound_address="127.0.0.1", features=["compress"])
        b_id, b_token = UUID("22222222-3333-4444-5555-666666666666"), UUID("bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
        b = Connector(b_id, b_token; name="b", inbound_address="127.0.0.1", features=["compress"])
        received = Ref{Any}(nothing)
        register_callback!(b, (c, h, p) -> (received[] = (h, p); p), "ECHO"; provides_response=true)
        register_callback!(b, (c, h, p) -> nothing, "FIRE_AND_FORGET")
        register_callback!(b, (c, h, p) -> error("boom"), "RAISES"; provides_response=true)
        register_callback!(b, (c, h, p) -> (sleep(2); p), "SLOW"; provides_response=true, timeout=0.2)
        register_callback!(b, (c, h, p) -> Vector{UInt8}(codeunits("remote")), "TAGGED"; provides_response=true, remote_id=REMOTE)
        register_callback!(b, (c, h, p) -> Vector{UInt8}(codeunits("plain")), "TAGGED"; provides_response=true)
        start_listener!(a); start_listener!(b)
        @test a.bound !== nothing && b.bound !== nothing
        a.peers[b_id] = Peer(b_id, b_token; address=b.bound, features=["compress"])
        b.peers[SENDER] = Peer(SENDER, TOKEN; address=a.bound, features=["compress"])
        try
            # per message, small and large (compressed on the wire)
            small = Vector{UInt8}(codeunits("{\"n\": 1}"))
            @test wait_response(send_message(a, a.peers[b_id], Message("ECHO", small; response_expected=true)), 5.0) == small
            large = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "x" ^ 65536))))
            @test wait_response(send_message(a, a.peers[b_id], Message("ECHO", large; response_expected=true)), 5.0) == large
            @test received[][1].compressed       # the receiver saw a compressed frame
            # version 1 request
            @test wait_response(send_message(a, a.peers[b_id], Message("ECHO", small; response_expected=true, protocol_version=1)), 5.0) == small
            # unknown method, handler without a response, raising handler, slow handler: all answered with errors
            for method in ("NOPE", "FIRE_AND_FORGET", "RAISES", "SLOW")
                reply = JSON3.read(wait_response(send_message(a, a.peers[b_id], Message(method, small; response_expected=true)), 5.0))
                @test reply[:status] == "error" && reply[:method] == method && haskey(reply, :error)
            end
            # dispatch by (method, remote_id) first, then method
            @test String(wait_response(send_message(a, a.peers[b_id], Message("TAGGED", small; response_expected=true, remote_id=REMOTE)), 5.0)) == "remote"
            @test String(wait_response(send_message(a, a.peers[b_id], Message("TAGGED", small; response_expected=true)), 5.0)) == "plain"
            # persistent: several requests on one connection, and the connection is adopted by the receiver
            a.peers[b_id].persistent = true
            pendings = [send_message(a, a.peers[b_id], Message("ECHO", Vector{UInt8}(codeunits("{\"i\": $i}")); response_expected=true)) for i in 1:5]
            @test [String(wait_response(p, 5.0)) for p in pendings] == ["{\"i\": $i}" for i in 1:5]
            @test a.peers[b_id].connection !== nothing
            sleep(0.1)
            @test b.peers[SENDER].connection !== nothing          # adopted: b can now send back to a on it
            # b sends back on the adopted connection without dialling
            b.peers[SENDER].address = nothing
            register_callback!(a, (c, h, p) -> p, "ECHO"; provides_response=true)
            @test wait_response(send_message(b, b.peers[SENDER], Message("ECHO", small; response_expected=true)), 5.0) == small
            # a frame above the persistent threshold takes its own connection and still round-trips
            huge = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "y" ^ 300000))))
            @test wait_response(send_message(a, a.peers[b_id], Message("ECHO", huge; response_expected=true)), 5.0) == huge
            # unauthenticated sender: empty reply
            a.peers[b_id].persistent = false
            a.peers[b_id].connection = nothing
            intruder = Connector(UUID("77777777-7777-7777-7777-777777777777"), TOKEN; name="intruder", inbound_address="127.0.0.1", features=String[])
            intruder.peers[b_id] = Peer(b_id, b_token; address=b.bound)
            @test wait_response(send_message(intruder, intruder.peers[b_id], Message("ECHO", small; response_expected=true)), 5.0) == UInt8[]
            # encryption between peers that share a key, and refusal of clear text
            a.peers[b_id].key = KEY
            b.peers[SENDER].key = KEY
            @test wait_response(send_message(a, a.peers[b_id], Message("ECHO", large; response_expected=true)), 5.0) == large
            @test received[][1].encrypted && received[][1].compressed
            b.peers[SENDER].key = nothing
            @test_throws Exception wait_response(send_message(a, a.peers[b_id], Message("ECHO", small; response_expected=true)), 2.0)
        finally
            stop!(a); stop!(b)
        end
    end

    @testset "proxy pieces" begin
        io = IOBuffer("0123456789abcdef0123456789abcdef" * "fedcba9876543210fedcba9876543210" * bytes2hex(KEY))
        hs = read_handshake(io; encrypt=true)
        @test hs.proxy_token == UUID("01234567-89ab-cdef-0123-456789abcdef")
        @test hs.manager_token == UUID("fedcba98-7654-3210-fedc-ba9876543210")
        @test hs.key == KEY
        @test_throws ArgumentError read_handshake(IOBuffer("short"))
        @test_throws ArgumentError read_handshake(IOBuffer("0123456789abcdef0123456789abcdef" * "fedcba9876543210fedcba9876543210"); encrypt=true)
        opts = parse_args(["--proxy-id", "11111111222233334444555555555555", "--proxy-name", "('x',)", "--manager-id",
                           "99999999888877776666555555555555", "--manager-port", "22801", "--persistent", "True",
                           "--encrypt", "false", "--my-option", "value", "--self-test"])
        @test opts["proxy-name"] == "('x',)" && opts["persistent"] == "True" && opts["self-test"] == "true"
        @test str2bool("True") && !str2bool("False") && str2bool("1")
        @test_throws ArgumentError str2bool("maybe")
        delete!(opts, "self-test")
        p = Proxy(opts, Handshake(hs.proxy_token, hs.manager_token, nothing))
        @test p.connector.persistent && p.socket_logging && !p.manager.tls
        @test_throws ArgumentError Proxy(merge(opts, Dict("ipc-tls" => "true")), Handshake(hs.proxy_token, hs.manager_token, nothing))
        @test p.manager.address == ("localhost", 22801)
        @test "ping" in p.connector.features && "set_log_level" in p.connector.features && "compress" in p.connector.features
        @test "aead-chacha20poly1305" in p.connector.features && "aead-aes256gcm" in p.connector.features && "log" in p.connector.features
        health = JSON3.read(ProtocolProxy.handle_ping(p, Header(; method_name="PING", request_id=1, sender_id=SENDER, sender_token=TOKEN), UInt8[]))
        @test health[:uptime] isa Real && health[:remotes] == 0 && health[:busy] == false && health[:last_activity] === nothing
        @test occursin(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00$", iso8601_utc(1.7600000005e9))
        start_listener!(p.connector)
        reg = registration_message(p)
        body = JSON3.read(reg.payload)
        @test body[:address] == "127.0.0.1" && body[:port] == p.connector.bound[2]
        @test body[:proxy_id] == "11111111222233334444555555555555" && body[:cipher] in ("aes-256-gcm", "chacha20-poly1305")
        @test registration_accepted!(p, Vector{UInt8}(codeunits("{\"registered\": true, \"features\": [\"compress\"]}")))
        @test p.manager.features == ["compress"]
        @test registration_accepted!(p, Vector{UInt8}(codeunits("true")))
        @test !registration_accepted!(p, Vector{UInt8}(codeunits("false")))
        @test !registration_accepted!(p, Vector{UInt8}(codeunits("{\"registered\": false}")))
        stop!(p.connector)
        # SET_LOG_LEVEL through the installed logger
        logger = ProxyLogger(; json=true, stream=IOBuffer())
        ProtocolProxy.PROXY_LOGGER[] = logger
        reply = JSON3.read(ProtocolProxy.handle_set_log_level(p, Header(; method_name="SET_LOG_LEVEL", request_id=1, sender_id=SENDER, sender_token=TOKEN), Vector{UInt8}(codeunits("{\"level\": \"DEBUG\"}"))))
        @test reply[:level] == "DEBUG" && logger.levelno == 10
        reply = JSON3.read(ProtocolProxy.handle_set_log_level(p, Header(; method_name="SET_LOG_LEVEL", request_id=1, sender_id=SENDER, sender_token=TOKEN), Vector{UInt8}(codeunits("{\"level\": \"NONSENSE\"}"))))
        @test reply[:status] == "error"
        ProtocolProxy.PROXY_LOGGER[] = nothing
        # error reply shape
        err = JSON3.read(error_payload("NOPE", "Unknown method NOPE"))
        @test err[:status] == "error" && err[:method] == "NOPE"
        @test unanswerable(Header(; method_name="NOPE", request_id=1, sender_id=SENDER, sender_token=TOKEN), nothing) === nothing
    end

    @testset "log records" begin
        buf = IOBuffer()
        logger = ProxyLogger(; levelno=20, json=true, stream=buf)
        with_logger(logger) do
            @debug "hidden"
            @info "device $(1) offline" extra=1
            @warn "careful"
        end
        lines = split(strip(String(take!(buf))), '\n')
        @test length(lines) == 2
        rec = JSON3.read(lines[1])
        for field in ("name", "levelno", "levelname", "pathname", "lineno", "funcName", "created", "msecs", "process", "msg")
            @test haskey(rec, Symbol(field))
        end
        @test rec[:levelno] == 20 && rec[:levelname] == "INFO" && rec[:msg] == "device 1 offline" && rec[:extra] == 1
        @test JSON3.read(lines[2])[:levelname] == "WARNING"
        @test set_level!(logger, "warning") == "WARNING" && logger.levelno == 30
        @test_throws ArgumentError set_level!(logger, "nonsense")
    end

    # ---- the manager side ------------------------------------------------------------------------------------------

    REPO = dirname(@__DIR__)
    ECHO_MANIFEST = joinpath(REPO, "proxy.toml")
    EXAMPLE_MANIFEST = """
        [proxy]
        name = "mqtt"
        command = ["{python}", "-m", "protocol_proxy.proxy", "--gevent", "protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy"]
        header_version = 2

        [identity]
        keys = ["host", "port"]
        must_match = ["username", "password"]

        [identity.normalize]
        host = ["strip", "lowercase"]
        port = [{ default = 1883 }]

        [environment]
        MQTT_LOG = "info"

        [self_test]
        command = ["{manifest_dir}/bin/mqtt-proxy", "--self-test"]
        """

    @testset "manifests" begin
        m = parse_manifest(EXAMPLE_MANIFEST; source="/opt/mqtt/proxy.toml")
        @test m.name == "mqtt" && m.header_version == 2 && m.environment == Dict("MQTT_LOG" => "info")
        @test m.identity.keys == ["host", "port"] && m.identity.must_match == ["username", "password"]
        @test manifest_dir(m) == "/opt/mqtt"
        @test launch_command(m, "/venv/bin/python", ["--proxy-id", "x"]) ==
              ["/venv/bin/python", "-m", "protocol_proxy.proxy", "--gevent", "protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy", "--proxy-id", "x"]
        @test self_test_command(m, "python3") == ["/opt/mqtt/bin/mqtt-proxy", "--self-test"]
        # [environment] values take the same placeholders as command (§1a), resolved with the manager's interpreter
        env_m = parse_manifest("[proxy]\nname = \"e\"\ncommand = [\"x\"]\n[environment]\nPYTHONPATH = \"{manifest_dir}/..\"\nPY = \"{python}\"\nPLAIN = \"v\"\n";
                               source="/opt/e/manifests/e.toml")
        @test resolve_environment(env_m, "/venv/bin/python") == Dict("PYTHONPATH" => "/opt/e/manifests/..", "PY" => "/venv/bin/python", "PLAIN" => "v")
        @test env_m.environment["PYTHONPATH"] == "{manifest_dir}/.."          # kept verbatim until launch
        # normalisation, keys and conflicts
        @test normalized(m.identity, "host", "  Broker.Example ") == "broker.example"
        @test normalized(m.identity, "port", nothing) == 1883 && normalized(m.identity, "port", 8883) == 8883
        @test process_key(m, ("ignored",), Dict("host" => " BROKER ", "username" => "u")) == ("mqtt", "broker", 1883)
        @test py_tuple(process_key(m, ("ignored",), Dict("host" => "b", "port" => 1883))) == "('mqtt', 'b', 1883)"
        @test py_tuple(("conformance",)) == "('conformance',)"
        @test py_tuple(("a", nothing, true, 1.5, "it's")) == "('a', None, True, 1.5, \"it's\")"
        @test conflicts(m.identity, Dict("username" => "u", "password" => "p"), Dict("username" => "u", "password" => "q")) == ["password"]
        @test isempty(conflicts(m.identity, Dict("username" => "u"), Dict("username" => "u")))
        # no identity keys: the caller's key as given, and a manifest built in memory
        plain = Manifest("echo", ["{manifest_dir}/bin/echo-proxy"])
        @test process_key(plain, ("device", 7), Dict{String,Any}()) == ("device", 7)
        @test launch_command(plain, "python3") == ["/bin/echo-proxy"] && self_test_command(plain, "python3") === nothing
        # validation
        bad(text) = @test_throws ManifestError parse_manifest(text)
        bad("not = [toml")
        bad("[identity]\nkeys = [\"a\"]")                                      # no [proxy]
        bad("[proxy]\nname = \"bad name\"\ncommand = [\"x\"]")
        bad("[proxy]\nname = \"ok\"\ncommand = []")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"{nope}/x\"]")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\nheader_version = 3")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\n[proxy.extra]\na = 1")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\n[identity]\nkeys = [\"h\"]\n[identity.normalize]\nother = [\"strip\"]")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\n[identity]\nkeys = [\"h\"]\n[identity.normalize]\nh = [\"upper\"]")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\n[environment]\nN = 1")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\n[environment]\nN = \"{nope}\"")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\n[self_test]\nnope = 1")
        bad("[proxy]\nname = \"ok\"\ncommand = [\"x\"]\n[unknown]\na = 1")
        # discovery through the search path
        mktempdir() do dir
            write(joinpath(dir, "alpha.toml"), "[proxy]\nname = \"alpha\"\ncommand = [\"{manifest_dir}/a\"]\n")
            mkdir(joinpath(dir, "beta"))
            write(joinpath(dir, "beta", "proxy.toml"), "[proxy]\nname = \"beta\"\ncommand = [\"b\"]\n")
            withenv("PROTOCOL_PROXY_MANIFESTS" => dir, "PROTOCOL_PROXY_PREFIX" => joinpath(dir, "prefix")) do
                path = search_path()
                @test path[1] == dir && joinpath(dir, "prefix", "share", "protocol-proxy", "manifests") in path
                @test locate_manifest("alpha") == joinpath(dir, "alpha.toml")
                @test locate_manifest("beta") == joinpath(dir, "beta", "proxy.toml")
                @test_throws ManifestError locate_manifest("gamma")
                found = discover_manifests()
                @test haskey(found, "alpha") && haskey(found, "beta")
                @test launch_command(find_manifest("alpha"), "python3") == [joinpath(dir, "a")]
            end
        end
        echo = load_manifest(ECHO_MANIFEST)
        @test echo.name == "echo-julia" && launch_command(echo, "python3") == [joinpath(REPO, "bin", "echo-proxy")]
    end

    @testset "proxy records" begin
        L = proxy_logger_name("echo-julia", "('conformance',)")
        @test L == "protocol_proxy.proxies.echo-julia.conformance"
        @test proxy_logger_name("x", "('mqtt', 'broker.example', 1883)") == "protocol_proxy.proxies.x.mqtt_broker_example_1883"
        @test proxy_logger_name("x", "...") == "protocol_proxy.proxies.x.proxy"
        json = "{\"name\": \"protocol_proxy.julia.x\", \"levelno\": 30, \"levelname\": \"WARNING\", \"msg\": \"careful\", \"process\": 4242}"
        r = record_from_line(json, L, "stderr", 7, "p")
        @test r.logger == L && r.remote_name == "protocol_proxy.julia.x" && r.channel == "stderr" && r.levelno == 30
        @test r.message == "careful" && r.pid == 4242 && r.fields["levelno"] == 30 && r.exc_text === nothing
        r = record_from_line("{\"levelname\": \"ERROR\", \"msg\": \"m\"}", L, "stderr", 7, "p")
        @test r.levelno == 40 && r.pid == 7
        r = record_from_line("plain line", L, "stderr", 7, "p")
        @test r.levelno == 30 && r.remote_name == "stderr" && r.channel == "stderr" && r.fields === nothing
        @test record_from_line("plain line", L, "stdout", 7, "p").levelno == 20
        r = record_from_line("<7>debugging", L, "stdout", 7, "p")
        @test r.levelno == 10 && r.message == "debugging"
        @test record_from_line("<3>bad\r\n", L, "stdout", 7, "p").levelno == 40
        @test record_from_line("{not json}", L, "stdout", 7, "p").message == "{not json}"
        @test record_from_line("{\"no\": \"msg\"}", L, "stdout", 7, "p").message == "{\"no\": \"msg\"}"
        @test record_from_line("   ", L, "stdout", 7, "p") === nothing
        batch = Vector{UInt8}(codeunits("{\"records\": [{\"name\": \"a\", \"levelno\": 20, \"msg\": \"one\"}, {\"name\": \"b\", \"levelno\": 40, \"msg\": \"two\", \"exc_text\": \"tb\"}], \"dropped\": 3}"))
        rs = records_from_batch(batch, L, 7, "p")
        @test length(rs) == 3 && all(r -> r.channel == "socket", rs)
        @test rs[1].message == "one" && rs[2].exc_text == "tb" && rs[3].levelno == 30 && occursin("dropped 3 log records", rs[3].message)
        @test_throws Exception records_from_batch(Vector{UInt8}(codeunits("nope")), L, 7, "p")
        # the default handler goes through the global logger under the manager-side name
        buf = IOBuffer()
        with_logger(ProxyLogger(; levelno=10, json=true, stream=buf)) do
            log_record(rs[1])
        end
        out = JSON3.read(String(take!(buf)))
        @test out[:name] == L && out[:msg] == "[a] one" && out[:levelno] == 20
        # launch option rendering
        @test option_string(true) == "true" && option_string(false) == "false" && option_string(22801) == "22801"
        @test opt_bool(nothing, true) && !opt_bool("False", true) && opt_bool("yes", false) && opt_bool(1, false)
        @test dial_target(Dict{String,Any}("manager_dials" => true, "inbound_port" => 5, "inbound_address" => "127.0.0.1")) == ("127.0.0.1", 5)
        @test dial_target(Dict{String,Any}("manager_dials" => "true", "dial" => "h:9")) == ("h", 9)
        @test dial_target(Dict{String,Any}("manager_dials" => true, "dial" => ("h", 9))) == ("h", 9)
        @test dial_target(Dict{String,Any}()) === nothing
        @test_throws Exception dial_target(Dict{String,Any}("manager_dials" => true))
    end

    @testset "authority" begin
        auth = Authority("test manager")
        leaf = issue(auth, "abc"; ip_addresses=["127.0.0.1", "localhost"])
        @test startswith(leaf.ca, "-----BEGIN CERTIFICATE-----") && startswith(leaf.cert, "-----BEGIN CERTIFICATE-----")
        @test startswith(leaf.key, "-----BEGIN PRIVATE KEY-----")
        cert = OpenSSL.X509Certificate(leaf.cert)
        @test common_name(cert) == "abc" && common_name(OpenSSL.X509Certificate(leaf.ca)) == "test manager"
        text = ProtocolProxy.certificate_text(cert)
        @test occursin("DNS:abc", text) && occursin("IP Address:127.0.0.1", text) && occursin("DNS:localhost", text)
        @test occursin("TLS Web Server Authentication", text) && occursin("TLS Web Client Authentication", text)
        @test occursin("CA:FALSE", text) && occursin("id-ecPublicKey", text) && occursin("prime256v1", text)
        ca_text = ProtocolProxy.certificate_text(leaf.ca)
        @test occursin("CA:TRUE, pathlen:0", ca_text) && occursin("Certificate Sign", ca_text)
        # a stdin line round trip, and a mutual handshake through the connectors with issued material
        @test parse_tls_material(tls_material_line(leaf)) == leaf
        a_id, b_id = UUID("aaaaaaaa-0000-0000-0000-00000000000a"), UUID("bbbbbbbb-0000-0000-0000-00000000000b")
        a = Connector(a_id, TOKEN; name="a", inbound_address="127.0.0.1", tls=issue(auth, uuid_hex(a_id)), tls_optional=true)
        b = Connector(b_id, TOKEN; name="b", inbound_address="127.0.0.1", tls=issue(auth, uuid_hex(b_id)))
        register_callback!(a, (c, h, p) -> p, "ECHO"; provides_response=true)
        start_listener!(a); start_listener!(b)
        b.peers[a_id] = Peer(a_id, TOKEN; address=a.bound, tls=true, persistent=true)
        a.peers[b_id] = Peer(b_id, TOKEN; address=b.bound, tls=true)
        plain_id = UUID("cccccccc-0000-0000-0000-00000000000c")
        plain = Connector(plain_id, TOKEN; name="plain", inbound_address="127.0.0.1")
        plain.peers[a_id] = Peer(a_id, TOKEN; address=a.bound)
        a.peers[plain_id] = Peer(plain_id, TOKEN)
        try
            small = Vector{UInt8}(codeunits("{\"n\": 1}"))
            @test wait_response(send_message(b, b.peers[a_id], Message("ECHO", small; response_expected=true)), 10.0) == small
            @test b.peers[a_id].connection.tls_peer == uuid_hex(a_id)
            # the optional-TLS listener serves a plain peer on the same port
            @test wait_response(send_message(plain, plain.peers[a_id], Message("ECHO", small; response_expected=true)), 10.0) == small
            # a stranger's CA is refused
            other = issue(Authority("other"), uuid_hex(b_id))
            stranger = Connector(b_id, TOKEN; name="stranger", inbound_address="127.0.0.1", tls=other)
            stranger.peers[a_id] = Peer(a_id, TOKEN; address=a.bound, tls=true)
            @test_throws Exception wait_response(send_message(stranger, stranger.peers[a_id], Message("ECHO", small; response_expected=true)), 3.0)
            stop!(stranger)
        finally
            stop!(a); stop!(b); stop!(plain)
        end
    end

    @testset "manager" begin
        echo = load_manifest(ECHO_MANIFEST)
        records = Record[]
        lost = Tuple{String,String}[]
        quiet = ProxyLogger(; levelno=50, json=false, stream=IOBuffer())
        with_logger(quiet) do
            m = Manager(echo; heartbeat_interval=0.3, heartbeat_timeout=1.0, heartbeat_misses=3, records=r -> push!(records, r))
            on_proxy_lost!(m, (p, reason) -> push!(lost, (p.name, reason)))
            @test_throws Exception get_proxy(m, ("too-early",))
            start!(m)
            @test m.connector.bound !== nothing
            p = get_proxy(m, ("device",); persistent=true)
            @test p.name == "('device',)" && p.state == "launching" && is_running(p)
            @test p.command[1] == joinpath(REPO, "bin", "echo-proxy") && "--persistent" in p.command && "--log-level" in p.command
            wait_registered(m, p, 30.0)
            @test p.registered && "log" in p.peer.features && p.cipher in ("aes-256-gcm", "chacha20-poly1305")
            @test get_proxy(m, ("device",)) === p                            # the same key shares the process
            health_reply = JSON3.read(request(m, p, "PING"; timeout=5.0))
            @test haskey(health_reply, :uptime)
            @test String(request(m, p, "ECHO", "{\"n\": 1}"; timeout=5.0)) == "{\"n\": 1}"
            @test set_proxy_log_level!(m, p, "DEBUG") == Dict("level" => "DEBUG") && p.log_levelno == 10
            @test request(m, p, "ECHO", "x"; protocol_version=1, timeout=5.0) == UInt8['x']
            @test timedwait(() -> any(r -> r.channel == "stderr" && occursin("Launching proxy", r.message), records), 5.0) === :ok
            @test timedwait(() -> any(r -> r.channel == "socket" && r.proxy == p.name && r.pid == p.pid, records), 5.0) === :ok
            @test timedwait(() -> p.state == "healthy", 5.0) === :ok
            h = health(m)[p.name]
            @test h["state"] == "healthy" && h["pid"] == p.pid && h["report"]["uptime"] isa Real && h["persistent"] && h["connected"]
            # a second process for a different key, plain while the first... both plain here; keys do not collide
            q = get_proxy(m, ("other",))
            @test q !== p && q.proxy_id != p.proxy_id
            wait_registered(m, q, 30.0)
            @test length(proxies(m)) == 2 && proxy_by_id(m, q.proxy_id) === q
            # the process dies: the proxy is lost, the callback runs, the next get_proxy relaunches with the same id
            kill(q.process, Base.SIGKILL)
            @test timedwait(() -> q.lost, 10.0) === :ok
            @test q.exit_code == -9 && any(l -> l[1] == q.name && occursin("exited with code -9", l[2]), lost)
            q2 = get_proxy(m, ("other",))
            @test q2 !== q && q2.proxy_id == q.proxy_id && q2.peer.token != q.peer.token
            wait_registered(m, q2, 30.0)
            # an unresponsive proxy is lost after the misses and then terminated
            ccall(:kill, Cint, (Cint, Cint), q2.pid, 19)                      # SIGSTOP
            @test timedwait(() -> q2.lost, 15.0) === :ok
            @test occursin("missed 3 heartbeats", q2.lost_reason)
            ccall(:kill, Cint, (Cint, Cint), q2.pid, 18)                      # SIGCONT: the terminate can proceed
            @test wait_exit(q2, 10.0) !== nothing
            # stop terminates what is left with exit code 0 and drains the proxy's queue to its stderr
            stop!(m)
            @test wait_exit(p, 10.0) == 0
            @test timedwait(() -> any(r -> r.channel == "stderr" && occursin("stopping", r.message), records), 5.0) === :ok
            @test_throws Exception get_proxy(m, ("device",))
        end
    end

    @testset "manager: TLS, encryption, dialling, keys, failures" begin
        echo = load_manifest(ECHO_MANIFEST)
        quiet = ProxyLogger(; levelno=50, json=false, stream=IOBuffer())
        with_logger(quiet) do
            # a TLS proxy and a plain proxy on one manager and one listener; an encrypted one too
            m = Manager(echo; heartbeat_interval=0, encrypt=true, cipher="chacha20-poly1305")
            start!(m)
            tls_p = get_proxy(m, ("tls",); ipc_tls=true, persistent=true)
            plain_p = get_proxy(m, ("plain",); encrypt=false)
            wait_registered(m, tls_p, 30.0); wait_registered(m, plain_p, 30.0)
            @test tls_p.peer.tls && tls_p.peer.key !== nothing && "--cipher" in tls_p.command && "--ipc-tls" in tls_p.command
            @test !plain_p.peer.tls && plain_p.peer.key === nothing && !("--encrypt" in plain_p.command[1:end-1] && plain_p.command[findfirst(==("--encrypt"), plain_p.command) + 1] == "true")
            @test String(request(m, tls_p, "ECHO", "a"; timeout=5.0)) == "a" && tls_p.peer.connection.tls_peer == uuid_hex(tls_p.proxy_id)
            @test String(request(m, plain_p, "ECHO", "b"; timeout=5.0)) == "b"
            # manager-initiated registration
            port = ProtocolProxy.free_port()
            d = get_proxy(m, ("dialled",); manager_dials=true, inbound_address="127.0.0.1", inbound_port=port)
            @test d.peer.address == ("127.0.0.1", port) && d.peer.persistent == true
            wait_registered(m, d, 30.0)
            @test String(request(m, d, "ECHO", "c"; timeout=5.0)) == "c"
            stop!(m)
            @test wait_exit(tls_p, 10.0) == 0 && wait_exit(plain_p, 10.0) == 0 && wait_exit(d, 10.0) == 0
            # process keying with must_match
            keyed = Manifest("keyed", echo.command; source=echo.source,
                             identity=Identity(; keys=["host"], must_match=["user"], normalize=Dict("host" => [Step("lowercase")])))
            m = Manager(keyed; heartbeat_interval=0)
            start!(m)
            a = get_proxy(m, ("r1",); host="H", user="u")
            @test a.name == "('keyed', 'h')" && get_proxy(m, ("r2",); host="h", user="u") === a
            @test_throws Exception get_proxy(m, ("r3",); host="h", user="v")
            b = get_proxy(m, ("r4",); host="other", user="u")
            @test b !== a
            wait_registered(m, a, 30.0); wait_registered(m, b, 30.0)       # a Julia proxy owns SIGTERM only once it runs
            stop!(m)
            @test wait_exit(a, 10.0) == 0 && wait_exit(b, 10.0) == 0
            # a proxy that never registers is lost on the registration timeout and its process terminated
            sleeper = Manifest("sleeper", ["sh", "-c", "exec sleep 60", "sleeper"])     # the standard options land in \$@
            m = Manager(sleeper; heartbeat_interval=0)
            start!(m)
            s = get_proxy(m, ("s",))
            @test_throws Exception wait_registered(m, s, 1.0)
            @test s.lost && occursin("did not register", s.lost_reason) && isempty(proxies(m))
            @test wait_exit(s, 10.0) == -15
            stop!(m)
            # a command that cannot be launched is an error at get_proxy, and leaves nothing behind
            m = Manager(Manifest("missing", ["/nonexistent/binary"]); heartbeat_interval=0)
            start!(m)
            @test_throws Exception get_proxy(m, ("x",))
            @test isempty(proxies(m)) && isempty(m.connector.peers)
            stop!(m)
            # the self test of the echo manifest passes
            m = Manager(echo; heartbeat_interval=0)
            @test run_self_test(m) === nothing
            @test run_self_test(Manager(Manifest("bad", ["x"]; self_test=["false"]); heartbeat_interval=0)) !== nothing
        end
    end

    @testset "conformance report" begin
        r = ProtocolProxy.Report(Manifest("x", ["x"]))
        ProtocolProxy.add!(r, "a", true, "ok")
        ProtocolProxy.skip!(r, "b", "not advertised")
        @test report_ok(r) && occursin("x: all checks pass (1 passed, 0 failed, 1 skipped)", report_text(r))
        ProtocolProxy.add!(r, "c", false, "boom")
        @test !report_ok(r) && occursin("FAILURES", report_text(r)) && occursin("  FAIL c", report_text(r))
        j = JSON3.read(report_json(r))
        @test j[:ok] == false && length(j[:checks]) == 3 && j[:checks][2][:status] == "skip"
        @test ProtocolProxy.py_like(Dict("a" => 1, "b" => nothing, "c" => true)) == "{'a': 1, 'b': None, 'c': True}"
    end
end
