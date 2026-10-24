# Precompile the hot paths so a launched proxy registers quickly: headers, codecs, JSON, the command line, and a
# loopback request/response through the connector.
using PrecompileTools

@setup_workload begin
    sender = UUID("11111111-2222-3333-4444-555555555555")
    token = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    key = collect(UInt8.(0:31))
    @compile_workload Logging.with_logger(Logging.NullLogger()) do
        h = Header(; method_name="PING", request_id=1, sender_id=sender, sender_token=token, response_expected=true)
        raw = pack(h)
        unpack(raw)
        h1 = Header(; version=1, method_name="PING", request_id=1, sender_id=sender, sender_token=token)
        unpack(pack(h1))
        payload = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "x" ^ 5000))))
        r, w = seal(h, payload; compress=true)
        open_payload(unpack(r), r, w)
        r, w = seal(h, payload; key, compress=true)
        open_payload(unpack(r), r, w; key)
        if aes_gcm_available()
            r, w = seal(h, payload; key, aes_gcm=true)
            open_payload(unpack(r), r, w; key)
        end
        parse_args(["--proxy-id", "abc", "--encrypt", "true", "--self-test"])
        record_fields(Logging.Info, "hello", Main, "x.jl", 1)
        JSON3.write(Dict{String,Any}("uptime" => 1.0, "remotes" => 0, "busy" => false, "last_activity" => nothing))
        JSON3.read("{\"registered\": true, \"features\": [\"compress\"]}")
        error_payload("NOPE", "Unknown method NOPE")
        try
            # Loopback: two connectors on 127.0.0.1, one per-message request and one persistent request.
            a = Connector(sender, token; name="a", inbound_address="127.0.0.1", features=["compress"])
            b = Connector(UUID("99999999-8888-7777-6666-555555555555"), UUID("12345678-1234-1234-1234-123456789abc");
                          name="b", inbound_address="127.0.0.1", features=["compress"])
            register_callback!(b, (c, hh, p) -> p, "ECHO"; provides_response=true)
            start_listener!(a); start_listener!(b)
            a.peers[b.proxy_id] = Peer(b.proxy_id, b.token; address=b.bound, features=["compress"])
            b.peers[a.proxy_id] = Peer(a.proxy_id, a.token; address=a.bound, features=["compress"])
            pending = send_message(a, a.peers[b.proxy_id], Message("ECHO", payload; response_expected=true))
            wait_response(pending, 10.0)
            a.peers[b.proxy_id].persistent = true
            pending = send_message(a, a.peers[b.proxy_id], Message("ECHO", "{}"; response_expected=true))
            wait_response(pending, 10.0)
            pending = send_message(a, a.peers[b.proxy_id], Message("NOPE", "{}"; response_expected=true))
            wait_response(pending, 10.0)
            stop!(a); stop!(b)
            sleep(0.05)
        catch
        end
    end
end
