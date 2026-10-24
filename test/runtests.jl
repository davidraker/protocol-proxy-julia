using Test
using ProtocolProxy
using ProtocolProxy: record_fields, error_payload, unanswerable, next_request_id!, str2bool, with, resolve_ipv4,
                     check_frame_vector, check_constants, check_log_channel, uuid_from_hex, registration_message,
                     registration_accepted!, iso8601_utc
using UUIDs
using JSON3
using Logging
using Sockets

const VECTORS = JSON3.read(read(joinpath(@__DIR__, "test_vectors.json"), String))
const SENDER = UUID("11111111-2222-3333-4444-555555555555")
const TOKEN = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
const REMOTE = UUID("99999999-8888-7777-6666-555555555555")
const KEY = collect(UInt8.(0:31))

@testset "ProtocolProxy" begin
    @testset "headers against the vectors" begin
        @test check_constants(VECTORS[:constants])
        for (name, v) in VECTORS[:frames]
            if Bool(v[:aes_gcm]) && !aes_gcm_available()
                @test_skip check_frame_vector(string(name), v, VECTORS[:identities])
            else
                @test check_frame_vector(string(name), v, VECTORS[:identities])
            end
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
            aes_gcm && !aes_gcm_available() && continue
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
        @test p.connector.persistent
        @test p.manager.address == ("localhost", 22801)
        @test "ping" in p.connector.features && "set_log_level" in p.connector.features && "compress" in p.connector.features
        @test "aead-chacha20poly1305" in p.connector.features
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
end
