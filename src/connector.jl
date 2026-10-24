# The IPC connector (PROTOCOL.md §2, §6): a TCP listener and dialer, authentication of frames by sender id and
# token, dispatch by (method, remote_id) then method, RESPONSE matching by request id, per-message and persistent
# connections in both directions, over TCP or TLS (tls.jl). One Task per connection.

mutable struct Connection
    sock::IO                      # a TCPSocket, or an OpenSSL.SSLStream over one
    persistent::Bool
    peer_id::Union{Nothing,UUID}
    write_lock::ReentrantLock
    pending::Set{UInt32}          # request ids awaiting responses on this connection
    closed::Bool
    #: the common name of the certificate the other end presented (its id as hex), nothing on a plain connection
    tls_peer::Union{Nothing,String}
    #: ordinary writers waiting for or holding the write lock; low-priority writers (LOG batches) yield to them
    urgent::Threads.Atomic{Int}
end

Connection(sock::IO; persistent::Bool=false, peer_id::Union{Nothing,UUID}=nothing, tls_peer::Union{Nothing,String}=nothing) =
    Connection(sock, persistent, peer_id, ReentrantLock(), Set{UInt32}(), false, tls_peer, Threads.Atomic{Int}(0))

alive(c::Connection) = !c.closed && isopen(c.sock)

"""The TCP socket under a connection (the SSLStream's, when TLS)."""
raw_socket(c::Connection) = c.sock isa OpenSSL.SSLStream ? c.sock.io : c.sock

function Base.close(c::Connection)
    c.closed && return
    c.closed = true
    try
        close(c.sock)
    catch
    end
    return
end

"""A known remote system: the manager, or another proxy."""
mutable struct Peer
    proxy_id::UUID
    token::UUID
    #: the address the peer advertised (or that we were told to dial), or nothing when it can only be reached on a
    #: connection it opened to us
    address::Union{Nothing,Tuple{String,Int}}
    name::String
    #: connection policy toward this peer: true persistent, false per message, nothing for the connector's default
    persistent::Union{Nothing,Bool}
    connection::Union{Nothing,Connection}
    features::Vector{String}
    #: the shared AEAD key, or nothing for clear text; fixed for the peer's lifetime
    key::Union{Nothing,Vector{UInt8}}
    connect_lock::ReentrantLock
    last_seen::Union{Nothing,Float64}
    #: every connection with this peer is TLS, mutually verified against the manager's CA
    tls::Bool
end

Peer(proxy_id::UUID, token::UUID; address=nothing, name=string(proxy_id), persistent=nothing, features=String[],
     key=nothing, tls::Bool=false) = Peer(proxy_id, token, address, String(name), persistent, nothing, Vector{String}(features),
                                          key === nothing ? nothing : Vector{UInt8}(key), ReentrantLock(), nothing, tls)

struct Callback
    f::Function                   # f(connector, header, payload::Vector{UInt8}) -> Nothing | Vector{UInt8} | String
    name::String
    provides_response::Bool
    timeout::Float64
end

"""A message to send. `request_id` is drawn at send time when nothing."""
mutable struct Message
    method_name::String
    payload::Vector{UInt8}
    request_id::Union{Nothing,UInt32}
    response_expected::Bool
    remote_id::Union{Nothing,UUID}
    protocol_version::Int
end

Message(method_name::AbstractString, payload=UInt8[]; request_id=nothing, response_expected::Bool=false,
        remote_id::Union{Nothing,UUID}=nothing, protocol_version::Integer=2) =
    Message(String(method_name), payload isa AbstractString ? Vector{UInt8}(codeunits(payload)) : Vector{UInt8}(payload),
            request_id === nothing ? nothing : UInt32(request_id), response_expected, remote_id, Int(protocol_version))

"""The awaited reply to a request: `wait_response` blocks for it."""
struct Pending
    request_id::UInt32
    result::Channel{Any}
end
Pending(request_id::Integer) = Pending(UInt32(request_id), Channel{Any}(1))

struct ResponseTimeout <: Exception
    msg::String
end
Base.showerror(io::IO, e::ResponseTimeout) = print(io, "ResponseTimeout: ", e.msg)

"""
    wait_response(p::Pending, timeout) -> Vector{UInt8}

The reply payload, or throws the error that failed the request (`ResponseTimeout`, connection loss).
"""
function wait_response(p::Pending, timeout::Real)
    status = timedwait(() -> isready(p.result), Float64(timeout); pollint=0.005)
    status === :ok || throw(ResponseTimeout("no response to request $(p.request_id) within $(timeout) s"))
    value = take!(p.result)
    value isa Exception && throw(value)
    return value::Vector{UInt8}
end

function settle!(p::Pending, value)
    isready(p.result) && return
    put!(p.result, value)
    return
end

mutable struct Connector
    proxy_id::UUID
    token::UUID
    name::String
    inbound_address::String
    inbound_port::Union{Nothing,Int}
    min_port::Int
    max_port::Int
    server::Union{Nothing,Sockets.TCPServer}
    bound::Union{Nothing,Tuple{String,Int}}
    peers::Dict{UUID,Peer}
    callbacks::Dict{String,Callback}
    remote_callbacks::Dict{Tuple{String,UUID},Callback}
    pending::Dict{UInt32,Pending}
    request_ids::Dict{Int,UInt32}
    connections::Set{Connection}
    persistent::Bool
    persistent_max_frame::Int
    compress_threshold::Int
    cipher::String
    features::Vector{String}
    started_at::Float64
    last_activity::Union{Nothing,Float64}
    stopping::Bool
    accept_task::Union{Nothing,Task}
    lock::ReentrantLock
    #: TLS material makes every accepted connection TLS and lets this end dial TLS peers; nothing for plain TCP
    tls::Union{Nothing,TlsMaterial}
    server_ctx::Union{Nothing,OpenSSL.SSLContext}
    client_ctx::Union{Nothing,OpenSSL.SSLContext}
    #: with material, also accept plain connections, telling them apart by the first byte (a manager's listener, §11b)
    tls_optional::Bool
end

const KEEPALIVE_DELAY = 15

"""
    Connector(proxy_id, token; name, inbound_address="localhost", inbound_port=nothing, persistent=false,
              compress_threshold=4096, persistent_max_frame=262144, cipher="auto", features=[...], tls=nothing,
              tls_optional=false)

With `tls`, accepted connections are TLS (and plain ones are refused) unless `tls_optional`, which serves plain and TLS
connections on the one port by their first byte (0x16 opens a TLS record; a frame's version word starts with 0x00),
as the Python manager's listener does. Dialled connections are TLS toward peers marked `tls` either way.
"""
function Connector(proxy_id::UUID, token::UUID; name::AbstractString=string(proxy_id), inbound_address::AbstractString="localhost",
                   inbound_port::Union{Nothing,Integer}=nothing, min_port::Integer=22801, max_port::Integer=22899,
                   persistent::Bool=false, compress_threshold::Integer=COMPRESS_THRESHOLD,
                   persistent_max_frame::Integer=PERSISTENT_MAX_FRAME, cipher::AbstractString="auto",
                   features::AbstractVector{<:AbstractString}=default_features(), tls::Union{Nothing,TlsMaterial}=nothing,
                   tls_optional::Bool=false)
    c = Connector(proxy_id, token, String(name), String(inbound_address), inbound_port === nothing ? nothing : Int(inbound_port),
                  Int(min_port), Int(max_port), nothing, nothing, Dict{UUID,Peer}(), Dict{String,Callback}(),
                  Dict{Tuple{String,UUID},Callback}(), Dict{UInt32,Pending}(), Dict(1 => UInt32(1), 2 => UInt32(1)),
                  Set{Connection}(), persistent, Int(persistent_max_frame), Int(compress_threshold),
                  resolve_cipher(cipher), Vector{String}(features), time(), nothing, false, nothing, ReentrantLock(),
                  tls, nothing, nothing, tls_optional)
    if tls !== nothing
        c.server_ctx = ssl_context(tls, true)       # fails now, not at the first connection, if the material is bad
        c.client_ctx = ssl_context(tls, false)
    end
    register_callback!(c, handle_response, "RESPONSE")
    return c
end

"""What this connector advertises: compression and both AEADs (OpenSSL has them on every CPU)."""
default_features() = [FEATURE_COMPRESS, FEATURE_CHACHA, FEATURE_AES_GCM]

"""
The cipher for a configuration value: a known name, or `auto` (§11a: AES-256-GCM when `/proc/cpuinfo` lists the
`aes` flag, so that hardware does the work, else ChaCha20-Poly1305; both are always available).
"""
function resolve_cipher(cipher::AbstractString)
    c = lowercase(strip(cipher))
    if c in ("", "auto")
        return cpu_has_aes() ? CIPHER_AES_GCM : CIPHER_CHACHA
    end
    haskey(CIPHERS, c) || throw(ArgumentError("Unknown cipher $(repr(cipher)); choose from $(join(keys(CIPHERS), ", ")) or auto."))
    return c
end

"""The cipher toward a peer: ours, unless the peer advertised features that do not include it (then the baseline)."""
function cipher_for(c::Connector, peer::Union{Nothing,Peer})
    if peer !== nothing && !isempty(peer.features) && !(CIPHERS[c.cipher][1] in peer.features)
        return CIPHER_CHACHA
    end
    return c.cipher
end

"""Whether `/proc/cpuinfo` lists the `aes` flag (false where there is no such file)."""
function cpu_has_aes()
    isfile("/proc/cpuinfo") || return false
    for line in eachline("/proc/cpuinfo")
        if startswith(line, "flags") || startswith(line, "Features")
            return occursin(r"\baes\b", line)
        end
    end
    return false
end

# ---- callbacks -----------------------------------------------------------------------------------------------------

"""
    register_callback!(c, f, method_name; provides_response=false, timeout=30.0, remote_id=nothing)

`f(connector, header, payload)` handles `method_name`; with a `remote_id` it serves only frames tagged with that
remote (and replaces an earlier handler for the pair); without one the first registration wins.
"""
function register_callback!(c::Connector, f::Function, method_name::AbstractString; provides_response::Bool=false,
                            timeout::Real=30.0, remote_id::Union{Nothing,UUID}=nothing)
    cb = Callback(f, String(method_name), provides_response, Float64(timeout))
    if remote_id !== nothing
        c.remote_callbacks[(String(method_name), remote_id)] = cb
    elseif !haskey(c.callbacks, method_name)
        c.callbacks[String(method_name)] = cb
    end
    return cb
end

function unregister_callback!(c::Connector, method_name::AbstractString; remote_id::Union{Nothing,UUID}=nothing)
    if remote_id !== nothing
        return pop!(c.remote_callbacks, (String(method_name), remote_id), nothing) !== nothing
    end
    return pop!(c.callbacks, String(method_name), nothing) !== nothing
end

"""The handler for a frame: the remote's own if the frame names one it has, else the method's. Records activity."""
function find_callback(c::Connector, h::Header)
    c.last_activity = time()
    peer = get(c.peers, h.sender_id, nothing)
    peer === nothing || (peer.last_seen = c.last_activity)
    if h.remote_id !== nothing
        cb = get(c.remote_callbacks, (h.method_name, h.remote_id), nothing)
        cb === nothing || return cb
    end
    return get(c.callbacks, h.method_name, nothing)
end

error_payload(method_name::AbstractString, error::AbstractString) =
    Vector{UInt8}(codeunits(JSON3.write(Dict("status" => "error", "error" => error, "method" => method_name))))

"""The error reply owed when a request expects a response nobody will give (§6), else nothing."""
function unanswerable(h::Header, cb::Union{Nothing,Callback})
    h.response_expected || return nothing
    cb === nothing && return error_payload(h.method_name, "Unknown method $(h.method_name)")
    cb.provides_response || return error_payload(h.method_name, "Method $(h.method_name) provides no response")
    return nothing
end

function handle_response(c::Connector, h::Header, payload::Vector{UInt8})
    p = lock(c.lock) do
        pop!(c.pending, h.request_id, nothing)
    end
    if p === nothing
        @warn "$(c.name): response $(h.request_id) from $(h.sender_id) arrived but nothing awaits it"
    else
        settle!(p, payload)
    end
    return nothing
end

function fail_pending!(c::Connector, ids, err::Exception)
    for id in collect(ids)
        p = lock(c.lock) do
            pop!(c.pending, UInt32(id), nothing)
        end
        p === nothing || settle!(p, err)
    end
    return
end

"""The next request id for a header version, cycling from 1 within the version's field."""
function next_request_id!(c::Connector, version::Integer)
    lock(c.lock) do
        id = c.request_ids[Int(version)]
        c.request_ids[Int(version)] = id >= request_id_max(version) - 1 ? UInt32(1) : id + UInt32(1)
        return id
    end
end

# ---- listener ------------------------------------------------------------------------------------------------------

"""The IPv4 address to bind or dial for a host string."""
function resolve_ipv4(host::AbstractString)::IPv4
    h = strip(host)
    (isempty(h) || h == "localhost") && return ip"127.0.0.1"
    parsed = try
        IPv4(h)
    catch
        nothing
    end
    parsed === nothing || return parsed
    for addr in getalladdrinfo(String(h))
        addr isa IPv4 && return addr
    end
    throw(ArgumentError("no IPv4 address for $(repr(host))"))
end

"""Bind the listener: the configured port, else the first free one in `min_port:max_port`."""
function start_listener!(c::Connector)
    c.server === nothing || return c.bound
    ip = resolve_ipv4(c.inbound_address)
    if c.inbound_port !== nothing
        try
            c.server = listen(ip, c.inbound_port)
        catch e
            @warn "$(c.name): unable to bind $(ip):$(c.inbound_port) ($e); trying the port range"
        end
    end
    if c.server === nothing
        for port in c.min_port:c.max_port
            try
                c.server = listen(ip, port)
                break
            catch e
                e isa Base.IOError || rethrow()
            end
        end
    end
    c.server === nothing && error("$(c.name): unable to bind $(ip) on any port in $(c.min_port)..$(c.max_port)")
    _, port = getsockname(c.server)
    c.bound = (string(ip), Int(port))
    c.accept_task = errormonitor(@async accept_loop(c))
    @info "$(c.name): listening on $(c.bound[1]):$(c.bound[2])"
    return c.bound
end

function accept_loop(c::Connector)
    server = c.server
    while !c.stopping && server !== nothing
        sock = try
            accept(server)
        catch e
            c.stopping && break
            @warn "$(c.name): error accepting a connection: $e"
            sleep(0.1)
            continue
        end
        conn = Connection(sock)
        push!(c.connections, conn)
        if c.tls === nothing
            @async serve(c, conn)
        elseif c.tls_optional
            @async serve_sniffed(c, conn)
        else
            @async tls_accept!(c, conn) && serve(c, conn)
        end
    end
end

"""
Serve an accepted connection that may be TLS or plain: wait for its first byte without consuming it (it stays in the
socket's buffer for OpenSSL or the frame reader), 0x16 being a TLS ClientHello record and 0x00 a frame's version word.
"""
function serve_sniffed(c::Connector, conn::Connection)
    sock = conn.sock::TCPSocket
    closed = try
        eof(sock)
    catch
        true
    end
    if closed
        connection_lost!(c, conn, "closed before any data")
        return
    end
    if Base.peek(sock.buffer) == 0x16
        tls_accept!(c, conn) || return
    end
    serve(c, conn)
end

"""Complete the TLS handshake on an accepted connection (the listener is TLS-only with material). False if dropped."""
function tls_accept!(c::Connector, conn::Connection)
    ssl = OpenSSL.SSLStream(c.server_ctx, conn.sock::TCPSocket)
    conn.sock = ssl
    try
        conn.tls_peer = tls_handshake!(ssl, true)
        return true
    catch e
        c.stopping || @warn "$(c.name): TLS handshake with an accepted connection failed: $(sprint(showerror, e))"
        connection_lost!(c, conn, "TLS handshake failed")
        return false
    end
end

# ---- receiving -----------------------------------------------------------------------------------------------------

"""Exactly `n` bytes from `io`, or nothing at EOF."""
function read_exact(io::IO, n::Integer)
    n == 0 && return UInt8[]
    data = Vector{UInt8}(undef, n)
    try
        GC.@preserve data unsafe_read(io, pointer(data), UInt(n))
    catch e
        e isa EOFError && return nothing
        rethrow()
    end
    return data
end

"""
    read_frame(io) -> (header, raw_header, wire_payload) or nothing at EOF
"""
function read_frame(sock::IO)
    version_bytes = read_exact(sock, VERSION_WORD_BYTES)
    version_bytes === nothing && return nothing
    version = peek_version(version_bytes)
    version in (1, 2) || throw(ArgumentError("unknown header version $version"))
    rest = read_exact(sock, header_length(version))
    rest === nothing && return nothing
    raw = vcat(version_bytes, rest)
    h = unpack(raw)
    payload = read_exact(sock, Int(h.data_length))
    payload === nothing && return nothing
    return h, raw, payload
end

"""Whether the frame's sender is a known peer presenting that peer's token (§6)."""
function authenticated(c::Connector, h::Header)
    peer = get(c.peers, h.sender_id, nothing)
    return peer !== nothing && peer.token == h.sender_token
end

"""A keep-alive frame arrived on an accepted connection from an authenticated peer: send to it on this connection."""
function adopt!(c::Connector, conn::Connection, h::Header)
    peer = get(c.peers, h.sender_id, nothing)
    (peer === nothing || peer.token != h.sender_token) && return
    make_persistent!(conn, peer.proxy_id)
    previous = peer.connection
    peer.connection = conn
    if previous !== nothing && previous !== conn && alive(previous)
        @info "$(c.name): $(peer.proxy_id) opened a new persistent connection; closing the earlier one"
        close(previous)
    end
    return
end

function make_persistent!(conn::Connection, peer_id::Union{Nothing,UUID})
    conn.persistent = true
    conn.peer_id = peer_id
    try
        ccall(:uv_tcp_keepalive, Cint, (Ptr{Cvoid}, Cint, Cuint), raw_socket(conn).handle, 1, KEEPALIVE_DELAY)
    catch
    end
    return
end

"""
A frame is accepted only if its transport identity matches its claimed identity (§6): over TLS the sender id must
be the certificate's common name; a peer marked TLS must not arrive in the clear.
"""
function frame_identity_ok(c::Connector, conn::Connection, h::Header)
    if conn.tls_peer !== nothing
        uuid_hex(h.sender_id) == conn.tls_peer && return true
        @warn "$(c.name): frame from $(h.sender_id) over a TLS connection authenticated as $(conn.tls_peer); dropped"
        return false
    end
    peer = get(c.peers, h.sender_id, nothing)
    if peer !== nothing && peer.tls
        @warn "$(c.name): clear-text frame from $(h.sender_id), who must use TLS; dropped"
        return false
    end
    return true
end

"""Serve frames on a connection until EOF (or until this side closes it)."""
function serve(c::Connector, conn::Connection)
    reason = "closed by the peer"
    try
        while !c.stopping
            frame = read_frame(conn.sock)
            frame === nothing && break
            keep_going = process_frame(c, conn, frame...)
            keep_going || break
        end
    catch e
        if conn.closed || c.stopping
            reason = "closed"
        else
            reason = sprint(showerror, e)
            e isa Union{Base.IOError,EOFError} || @warn "$(c.name): error serving a connection: $reason"
        end
    finally
        connection_lost!(c, conn, reason)
    end
end

"""
Handle one received frame. Returns whether the connection should go on being served (false: per-message
connection that has been answered, or a frame that had to be refused).
"""
function process_frame(c::Connector, conn::Connection, h::Header, raw::Vector{UInt8}, wire::Vector{UInt8})
    frame_identity_ok(c, conn, h) || return conn.persistent
    if !authenticated(c, h)
        @warn "$(c.name): dropping $(h.method_name) from unauthenticated sender $(h.sender_id)"
        h.response_expected && reply(c, conn, h, UInt8[])
        return conn.persistent
    end
    peer = get(c.peers, h.sender_id, nothing)
    payload = try
        open_payload(h, raw, wire; key=peer === nothing ? nothing : peer.key)
    catch e
        @warn "$(c.name): dropping $(h.method_name) from $(h.sender_id): $(sprint(showerror, e))"
        close(conn)
        return false
    end
    if h.keep_alive && !conn.persistent
        adopt!(c, conn, h)
    end
    if h.method_name == "RESPONSE"
        delete!(conn.pending, h.request_id)
    end
    if conn.persistent
        @async dispatch(c, conn, h, payload)
        return true
    end
    dispatch(c, conn, h, payload)
    return false
end

"""Run the handler for a frame and write its reply on the same connection."""
function dispatch(c::Connector, conn::Connection, h::Header, payload::Vector{UInt8})
    cb = find_callback(c, h)
    cb === nothing && @warn "$(c.name): no handler for method $(h.method_name) (request $(h.request_id))"
    owed = unanswerable(h, cb)
    owed === nothing || reply(c, conn, h, owed)
    cb === nothing && return
    result = run_callback(c, cb, h, payload)
    if cb.provides_response
        reply(c, conn, h, result)
    end
    return
end

function run_callback(c::Connector, cb::Callback, h::Header, payload::Vector{UInt8})
    task = @async Base.invokelatest(cb.f, c, h, payload)     # handlers may be registered after the serving Tasks started
    done = timedwait(() -> istaskdone(task), cb.timeout; pollint=0.002)
    if done !== :ok
        @warn "$(c.name): handler $(h.method_name) timed out after $(cb.timeout) s"
        return error_payload(h.method_name, "Operation timed out after $(cb.timeout) seconds")
    end
    if istaskfailed(task)
        e = task.result
        e = e isa TaskFailedException ? e.task.result : e
        @warn "$(c.name): handler $(h.method_name) raised: $(sprint(showerror, e))"
        return error_payload(h.method_name, sprint(showerror, e))
    end
    result = task.result
    result === nothing && return UInt8[]
    result isa AbstractString && return Vector{UInt8}(codeunits(result))
    return Vector{UInt8}(result)
end

"""Write the RESPONSE to a request on the connection it arrived on, in the request's header version."""
function reply(c::Connector, conn::Connection, h::Header, payload::AbstractVector{UInt8})
    msg = Message("RESPONSE", payload; request_id=h.request_id, protocol_version=Int(h.version))
    peer = get(c.peers, h.sender_id, nothing)
    try
        write_frame(conn, frame_bytes(c, msg, peer; keep_alive=conn.persistent))
    catch e
        c.stopping || @warn "$(c.name): unable to answer $(h.method_name) (request $(h.request_id)): $e"
    end
    return
end

function connection_lost!(c::Connector, conn::Connection, reason::String)
    delete!(c.connections, conn)
    close(conn)
    if !isempty(conn.pending)
        fail_pending!(c, conn.pending, ErrorException("connection to $(conn.peer_id) lost: $reason"))
        empty!(conn.pending)
    end
    if conn.peer_id !== nothing
        peer = get(c.peers, conn.peer_id, nothing)
        if peer !== nothing && peer.connection === conn
            peer.connection = nothing
            c.stopping || reason == "closed" || @info "$(c.name): persistent connection to $(conn.peer_id) $reason"
        end
    end
    return
end

# ---- sending -------------------------------------------------------------------------------------------------------

"""The wire bytes of a message toward a peer: compressed when the peer takes it, encrypted when a key is shared."""
function frame_bytes(c::Connector, msg::Message, peer::Union{Nothing,Peer}; keep_alive::Bool=false)
    compress = peer !== nothing && FEATURE_COMPRESS in peer.features && length(msg.payload) > c.compress_threshold
    key = peer === nothing ? nothing : peer.key
    aes_gcm = key !== nothing && CIPHERS[cipher_for(c, peer)][2]
    h = Header(; version=msg.protocol_version, method_name=msg.method_name, request_id=msg.request_id,
               sender_id=c.proxy_id, sender_token=c.token, response_expected=msg.response_expected, keep_alive,
               remote_id=msg.protocol_version >= 2 ? msg.remote_id : nothing)
    raw, wire = seal(h, msg.payload; key, compress, aes_gcm)
    return vcat(raw, wire)
end

"""
Write a frame. A `low_priority` frame (a LOG batch, §9) waits up to half a second for ordinary writers to finish
first, so logging rides in the gaps of protocol traffic on a persistent connection instead of ahead of it.
"""
function write_frame(conn::Connection, bytes::Vector{UInt8}; low_priority::Bool=false)
    if low_priority
        deadline = time() + 0.5
        while conn.urgent[] > 0 && alive(conn) && time() < deadline
            sleep(0.001)
        end
    else
        Threads.atomic_add!(conn.urgent, 1)
    end
    try
        lock(conn.write_lock) do
            alive(conn) || throw(Base.IOError("connection closed", 0))
            write(conn.sock, bytes)
            conn.sock isa OpenSSL.SSLStream && flush(conn.sock)
        end
    finally
        low_priority || Threads.atomic_sub!(conn.urgent, 1)
    end
    return
end

is_persistent(c::Connector, peer::Peer) = peer.persistent === nothing ? c.persistent : peer.persistent

"""
    send_message(c, peer, msg; low_priority=false) -> Pending | true | false

Send a message. Returns a `Pending` when a response is expected, `true` when the frame was handed to a connection
(or a dial Task), `false` when it cannot be attempted. An open persistent connection to the peer is used when
there is one; otherwise a persistent peer gets one dialled and any other peer gets a connection for this message
alone. A frame above `persistent_max_frame` takes its own connection when the peer's address is known.
"""
function send_message(c::Connector, peer::Peer, msg::Message; low_priority::Bool=false)
    address = peer.address
    link = peer.connection !== nothing && alive(peer.connection) ? peer.connection : nothing
    if address === nothing && link === nothing
        @error "$(c.name): refusing to send $(msg.method_name) to $(peer.proxy_id): no open connection and no address"
        return false
    end
    if msg.request_id === nothing
        msg.request_id = next_request_id!(c, msg.protocol_version)
    end
    result = true
    if msg.response_expected
        result = Pending(msg.request_id)
        lock(c.lock) do
            c.pending[msg.request_id] = result
        end
    end
    if link === nothing && !is_persistent(c, peer)
        @async deliver(c, address, msg, peer)
        return result
    end
    frame = frame_bytes(c, msg, peer; keep_alive=true)
    if address !== nothing && c.persistent_max_frame > 0 && length(frame) > c.persistent_max_frame
        @async deliver(c, address, msg, peer)          # its own connection
        return result
    end
    try
        conn = link_to(c, peer, address)
        msg.response_expected && push!(conn.pending, msg.request_id)
        write_frame(conn, frame; low_priority)
    catch e
        c.stopping || @warn "$(c.name): unable to send $(msg.method_name) (request $(msg.request_id)) to $(peer.proxy_id): $e"
        msg.response_expected && fail_pending!(c, [msg.request_id], ErrorException("$(msg.method_name) to $(peer.proxy_id): $e"))
    end
    return result
end

const CONNECT_TIMEOUT = 30.0

"""
Dial a peer: plain TCP, or TLS when the peer is a TLS peer (this end then needs material; the certificate must
chain to the CA and name the peer). Returns a `Connection` with `tls_peer` set when TLS.
"""
function dial(c::Connector, peer::Union{Nothing,Peer}, address::Tuple{String,Int}; persistent::Bool=false)
    ip = resolve_ipv4(address[1])
    sock = Sockets.connect(ip, address[2])
    (peer === nothing || !peer.tls) && return Connection(sock; persistent, peer_id=persistent ? peer.proxy_id : nothing)
    if c.tls === nothing
        close(sock)
        error("$(peer.proxy_id) requires TLS but this end has no TLS material")
    end
    ssl = OpenSSL.SSLStream(c.client_ctx, sock)
    expect = uuid_hex(peer.proxy_id)
    cn = try
        tls_handshake!(ssl, false; expect, server_name=expect)
    catch e
        close(ssl)
        rethrow()
    end
    return Connection(ssl; persistent, peer_id=persistent ? peer.proxy_id : nothing, tls_peer=cn)
end

"""Dial a connection for this message alone: write the frame, read the reply if one is expected, close."""
function deliver(c::Connector, address::Tuple{String,Int}, msg::Message, peer::Union{Nothing,Peer})
    conn = nothing
    attempts = 5
    while attempts > 0
        try
            conn = dial(c, peer, address)
            push!(c.connections, conn)
            write_frame(conn, frame_bytes(c, msg, peer; keep_alive=false))
            if msg.response_expected
                push!(conn.pending, msg.request_id)
                frame = read_frame(conn.sock)
                if frame === nothing
                    @warn "$(c.name): $(address) closed the connection without answering $(msg.method_name) (request $(msg.request_id))"
                    fail_pending!(c, [msg.request_id], ErrorException("$(address) closed the connection without answering $(msg.method_name)"))
                else
                    process_frame(c, conn, frame...)
                end
            end
            break
        catch e
            attempts -= 1
            if attempts > 0 && !c.stopping && e isa Base.IOError && conn === nothing
                sleep(1)
                continue
            end
            c.stopping || @warn "$(c.name): unable to send $(msg.method_name) (request $(msg.request_id)) to $(address): $(sprint(showerror, e))"
            msg.response_expected && fail_pending!(c, [msg.request_id], ErrorException("$(msg.method_name) to $(address): $(sprint(showerror, e))"))
            break
        finally
            if conn !== nothing
                delete!(c.connections, conn)
                close(conn)
            end
        end
    end
    return
end

"""The peer's open persistent connection, dialled now if it has none and its address is known."""
function link_to(c::Connector, peer::Peer, address::Union{Nothing,Tuple{String,Int}})
    lock(peer.connect_lock) do
        conn = peer.connection
        (conn !== nothing && alive(conn)) && return conn
        address === nothing && error("no open connection to $(peer.proxy_id) and no address to dial")
        conn = dial(c, peer, address; persistent=true)
        make_persistent!(conn, peer.proxy_id)
        push!(c.connections, conn)
        peer.connection = conn
        @async serve(c, conn)
        @info "$(c.name): opened a persistent connection to $(peer.proxy_id) @ $(address[1]):$(address[2])"
        return conn
    end
end

# ---- lifecycle -----------------------------------------------------------------------------------------------------

"""Stop accepting and close every connection; pending requests fail."""
function stop!(c::Connector)
    c.stopping = true
    server = c.server
    c.server = nothing
    server === nothing || close(server)
    for conn in collect(c.connections)
        connection_lost!(c, conn, "closed")
    end
    fail_pending!(c, collect(keys(c.pending)), ErrorException("connector stopped"))
    return
end
