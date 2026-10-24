# A proxy process (PROTOCOL.md §1, §7, §8, §9): the stdin handshake, registration with the manager, the core methods
# PING and SET_LOG_LEVEL, LOG batches over the socket, the parent watch and the clean stop on SIGTERM.

const TOKEN_HEX_LENGTH = 32
const KEY_HEX_LENGTH = 64
const REGISTRATION_ATTEMPTS = 2
const REGISTRATION_TIMEOUT = 5.0
const REGISTRATION_RETRY_DELAY = 20.0
const MANAGER_WATCH_INTERVAL = 1.0
const HARD_EXIT_GRACE = 15.0
const LOG_FLUSH_INTERVAL = 0.2
const LOG_BATCH_SIZE = 64

struct Handshake
    proxy_token::UUID
    manager_token::UUID
    key::Union{Nothing,Vector{UInt8}}
    tls::Union{Nothing,TlsMaterial}
end
Handshake(proxy_token::UUID, manager_token::UUID, key) = Handshake(proxy_token, manager_token, key, nothing)

"""Parse 32 hex characters as a UUID (the form the manager writes on stdin)."""
function uuid_from_hex(s::AbstractString)
    h = replace(strip(s), "-" => "")
    length(h) == 32 || throw(ArgumentError("expected 32 hex characters, got $(repr(s))"))
    return UUID(parse(UInt128, h; base=16))
end

uuid_hex(u::UUID) = string(u.value; base=16, pad=32)

"""
    read_handshake(io; encrypt=false, ipc_tls=false) -> Handshake

The proxy's token, the manager's token (32 hex characters each), with `--encrypt true` the 32-byte key as 64 hex
characters, and with `--ipc-tls true` one JSON line of TLS material (`{"ca", "cert", "key"}`, PEM).
"""
function read_handshake(io::IO; encrypt::Bool=false, ipc_tls::Bool=false)
    data = read(io, 2 * TOKEN_HEX_LENGTH)
    length(data) == 2 * TOKEN_HEX_LENGTH ||
        throw(ArgumentError("Expected $(2 * TOKEN_HEX_LENGTH) hex characters (proxy token + manager token) on stdin, got $(length(data)) bytes. Proxies are meant to be launched by a ProtocolProxyManager."))
    text = String(data)
    proxy_token = uuid_from_hex(text[1:TOKEN_HEX_LENGTH])
    manager_token = uuid_from_hex(text[TOKEN_HEX_LENGTH+1:end])
    key = nothing
    if encrypt
        key_hex = read(io, KEY_HEX_LENGTH)
        length(key_hex) == KEY_HEX_LENGTH ||
            throw(ArgumentError("--encrypt is set but no $(KEY_BYTES)-byte key followed the tokens on stdin (got $(length(key_hex)) bytes)."))
        key = hex2bytes(String(key_hex))
    end
    tls = nothing
    if ipc_tls
        line = strip(readline(io))
        isempty(line) && throw(ArgumentError("--ipc-tls is set but no TLS material (one JSON line) followed on stdin."))
        tls = parse_tls_material(line)
    end
    return Handshake(proxy_token, manager_token, key, tls)
end

"""
    Proxy(options::Dict{String,String}, handshake::Handshake; features=default_proxy_features())

A proxy built from the parsed `--name value` command line of §1 and the stdin handshake.
"""
mutable struct Proxy
    connector::Connector
    manager::Peer
    manager_dials::Bool
    registered::Bool
    stopping::Bool
    exit_code::Int
    parent::Int
    options::Dict{String,String}
    #: `--socket-logging` (default true): ship log records in LOG batches once registered (§9)
    socket_logging::Bool
    log_queue::Union{Nothing,LogQueue}
    log_task::Union{Nothing,Task}
end

str2bool(v::AbstractString) = lowercase(strip(v)) in ("1", "true", "t", "yes", "y", "on") ? true :
    lowercase(strip(v)) in ("0", "false", "f", "no", "n", "off", "") ? false :
    throw(ArgumentError("Expected a boolean value, got $(repr(v))."))
str2bool(v::Bool) = v

"""The features this proxy advertises in REGISTER_PEER: ping, log, set_log_level, compress and both AEADs."""
default_proxy_features() = vcat(["ping", "log", "set_log_level"], default_features())

const STANDARD_OPTIONS = ["proxy-id", "proxy-name", "manager-id", "manager-address", "manager-port", "inbound-address",
                          "inbound-port", "encrypt", "cipher", "ipc-tls", "manager-dials", "persistent",
                          "socket-logging", "compress-threshold", "log-level"]

function Proxy(options::Dict{String,String}, handshake::Handshake; features::Vector{String}=default_proxy_features())
    getopt(name, default=nothing) = get(options, name, default)
    require(name) = haskey(options, name) ? options[name] : throw(ArgumentError("--$name is required"))
    proxy_id = uuid_from_hex(require("proxy-id"))
    manager_id = uuid_from_hex(require("manager-id"))
    name = something(getopt("proxy-name"), string(proxy_id))
    manager_address = something(getopt("manager-address"), "localhost")
    manager_port = parse(Int, something(getopt("manager-port"), "22801"))
    encrypt = str2bool(something(getopt("encrypt"), "false"))
    ipc_tls = str2bool(something(getopt("ipc-tls"), "false"))
    socket_logging = str2bool(something(getopt("socket-logging"), "true"))
    manager_dials = str2bool(something(getopt("manager-dials"), "false"))
    persistent = str2bool(something(getopt("persistent"), "false"))
    inbound_port = getopt("inbound-port")
    threshold = getopt("compress-threshold")
    if encrypt && handshake.key === nothing
        throw(ArgumentError("$name: --encrypt is set but no key was provided on stdin."))
    end
    if ipc_tls && handshake.tls === nothing
        throw(ArgumentError("$name: --ipc-tls is set but no TLS material was provided on stdin."))
    end
    connector = Connector(proxy_id, handshake.proxy_token; name, inbound_address=something(getopt("inbound-address"), "localhost"),
                          inbound_port=inbound_port === nothing ? nothing : parse(Int, inbound_port), persistent,
                          compress_threshold=threshold === nothing ? COMPRESS_THRESHOLD : parse(Int, threshold),
                          cipher=something(getopt("cipher"), "auto"), features=default_features(),
                          tls=ipc_tls ? handshake.tls : nothing)
    manager = Peer(manager_id, handshake.manager_token; name="manager",
                   address=manager_dials ? nothing : (manager_address, manager_port), key=handshake.key, tls=ipc_tls)
    connector.peers[manager_id] = manager
    p = Proxy(connector, manager, manager_dials, false, false, 0, parent_pid(), options, socket_logging, nothing, nothing)
    p.connector.features = features
    register_callback!(connector, (c, h, payload) -> handle_ping(p, h, payload), "PING"; provides_response=true)
    register_callback!(connector, (c, h, payload) -> handle_set_log_level(p, h, payload), "SET_LOG_LEVEL"; provides_response=true)
    unknown = [k for k in keys(options) if !(k in STANDARD_OPTIONS)]
    isempty(unknown) || @info "$name: ignoring protocol options $(join(sort(unknown), ", "))"
    return p
end

# ---- core methods --------------------------------------------------------------------------------------------------

function iso8601_utc(t::Float64)
    dt = Dates.unix2datetime(t)
    return Dates.format(dt, dateformat"yyyy-mm-dd\THH:MM:SS.sss") * "+00:00"
end

"""What a PING reply carries (§8)."""
function health_report(p::Proxy)
    c = p.connector
    last = c.last_activity
    return Dict{String,Any}("uptime" => round(time() - c.started_at; digits=3),
                            "remotes" => length(Set(remote for (_, remote) in keys(c.remote_callbacks))),
                            "busy" => false,
                            "last_activity" => last === nothing ? nothing : iso8601_utc(last))
end

handle_ping(p::Proxy, h::Header, payload::Vector{UInt8}) = Vector{UInt8}(codeunits(JSON3.write(health_report(p))))

function handle_set_log_level(p::Proxy, h::Header, payload::Vector{UInt8})
    logger = PROXY_LOGGER[]
    logger === nothing && return error_payload("SET_LOG_LEVEL", "no logger installed")
    try
        body = JSON3.read(payload)
        level = get(body, :level, nothing)
        level === nothing && throw(ArgumentError("missing level"))
        name = set_level!(logger, level isa AbstractString ? String(level) : level)
        @info "$(p.connector.name): log level set to $name."
        return Vector{UInt8}(codeunits(JSON3.write(Dict("level" => name))))
    catch e
        return error_payload("SET_LOG_LEVEL", "Invalid log level: $(sprint(showerror, e))")
    end
end

# ---- registration --------------------------------------------------------------------------------------------------

function registration_message(p::Proxy)
    bound = p.connector.bound
    bound === nothing && error("$(p.connector.name): the listener must exist before registering")
    body = Dict{String,Any}("address" => bound[1], "port" => bound[2], "proxy_id" => uuid_hex(p.connector.proxy_id),
                            "token" => uuid_hex(p.connector.token), "features" => p.connector.features,
                            "cipher" => p.connector.cipher)
    return Message("REGISTER_PEER", JSON3.write(body); response_expected=true)
end

"""Read the manager's REGISTER_PEER reply: `{"registered": true, "features": [...]}`, or plain `true`/`false`."""
function registration_accepted!(p::Proxy, raw::Vector{UInt8})
    isempty(raw) && return false
    value = try
        JSON3.read(raw)
    catch
        return false
    end
    if value isa JSON3.Object
        features = get(value, :features, nothing)
        p.manager.features = features === nothing ? String[] : [string(f) for f in features]
        registered = get(value, :registered, nothing)
        registered === nothing && return get(value, :status, nothing) != "error"
        return registered == true
    end
    return value == true
end

manager_linked(p::Proxy) = p.manager.connection !== nothing && alive(p.manager.connection)

function wait_for_manager(p::Proxy)
    waited = 0.0
    while !p.stopping && !manager_linked(p)
        if waited % 30.0 < 0.1
            @info "$(p.connector.name): waiting for the manager to connect to $(p.connector.bound)."
        end
        sleep(0.1)
        waited += 0.1
    end
end

"""Two attempts, 5 s response timeout, 20 s between attempts (§7). Returns whether registration succeeded."""
function send_registration!(p::Proxy; attempts::Int=REGISTRATION_ATTEMPTS, timeout::Float64=REGISTRATION_TIMEOUT,
                            retry_delay::Float64=REGISTRATION_RETRY_DELAY)
    if p.manager_dials
        wait_for_manager(p)
        p.stopping && return false
    end
    for attempt in 1:attempts
        success = false
        try
            result = send_message(p.connector, p.manager, registration_message(p))
            if result isa Pending
                success = registration_accepted!(p, wait_response(result, timeout))
            end
        catch e
            @warn "$(p.connector.name): registration attempt $attempt failed: $(sprint(showerror, e))"
        end
        if success
            p.registered = true
            @info "$(p.connector.name): registered with the manager (features $(p.manager.features))."
            start_socket_logging!(p)
            return true
        end
        if attempt < attempts
            waited = 0.0
            while !p.stopping && waited < retry_delay
                sleep(0.1)
                waited += 0.1
            end
        end
        p.stopping && return false
    end
    @error "$(p.connector.name): unable to register with the manager after $attempts attempts."
    return false
end

# ---- logging over the socket (§9, §11a) ------------------------------------------------------------------------------

"""
Switch the process logger to a `LogQueue` and start the flushing Task, if this proxy was launched by a manager with
stderr a pipe and `--socket-logging` is on. The switch itself is the first record over the socket.
"""
function start_socket_logging!(p::Proxy)
    logger = PROXY_LOGGER[]
    (p.socket_logging && logger !== nothing && logger.json && logger.stream === stderr && use_json_channel()) || return false
    p.log_queue !== nothing && return true
    queue = LogQueue()
    p.log_queue = queue
    logger.queue = queue
    p.log_task = errormonitor(@async flush_loop(p))
    @info "$(p.connector.name): logging over the IPC socket from here on."
    return true
end

"""Ship a batch every `LOG_FLUSH_INTERVAL` seconds, or as soon as `LOG_BATCH_SIZE` records are waiting."""
function flush_loop(p::Proxy)
    queue = p.log_queue
    while !p.stopping && PROXY_LOGGER[] !== nothing && PROXY_LOGGER[].queue === queue
        deadline = time() + LOG_FLUSH_INTERVAL
        while !p.stopping && time() < deadline && length(queue) < LOG_BATCH_SIZE
            sleep(0.02)
        end
        flush_logs!(p)
    end
    return
end

"""Send one LOG batch (no response expected); records that cannot be sent go to stderr."""
function flush_logs!(p::Proxy)
    queue = p.log_queue
    queue === nothing && return
    records, dropped = drain!(queue, LOG_BATCH_SIZE)
    (isempty(records) && dropped == 0) && return
    sent = try
        send_message(p.connector, p.manager, Message("LOG", batch_payload(records, dropped)); low_priority=true) !== false
    catch
        false
    end
    sent || foreach(r -> write_json_line(stderr, r), records)
    return
end

"""Back to stderr: restore the logger's stream and write whatever is still queued as JSON lines (§9)."""
function stop_socket_logging!(p::Proxy)
    queue = p.log_queue
    queue === nothing && return
    logger = PROXY_LOGGER[]
    logger === nothing || logger.queue === queue && (logger.queue = nothing)
    p.log_queue = nothing
    task = p.log_task
    task === nothing || (timedwait(() -> istaskdone(task), 1.0; pollint=0.01); p.log_task = nothing)
    records, dropped = drain!(queue)
    foreach(r -> write_json_line(stderr, r), records)
    dropped == 0 || @warn "$(p.connector.name): dropped $dropped log records (rate or queue limit)."
    return
end

# ---- run loop ------------------------------------------------------------------------------------------------------

function stop!(p::Proxy; code::Int=0)
    p.stopping && return
    p.stopping = true
    p.exit_code = code
    stop_socket_logging!(p)
    stop!(p.connector)
    return
end

"""
    run!(p::Proxy) -> exit code

Start the listener, register, then serve until SIGTERM, the parent's disappearance, or `stop!`.
"""
function run!(p::Proxy)
    c = p.connector
    install_signal_handlers() || @warn "$(c.name): no SIGTERM handler installed"
    watchdog = errormonitor(@async watch(p))
    start_listener!(c)
    if !send_registration!(p)
        p.stopping || stop!(p; code=1)
        wait_stopped(p)
        return p.exit_code
    end
    wait_stopped(p)
    return p.exit_code
end

function wait_stopped(p::Proxy)
    while !p.stopping
        sleep(0.05)
    end
    sleep(0.05)     # let connection Tasks wind down
    return
end

"""Stop on SIGTERM (polled every 50 ms) or when the parent process changes (checked every second)."""
function watch(p::Proxy)
    c = p.connector
    last_watch = time()
    while !p.stopping
        sig = signal_received()
        if sig != 0
            @info "$(c.name): received signal $sig; stopping."
            arm_hard_exit("signal $sig")
            stop!(p; code=0)
            break
        end
        if time() - last_watch >= MANAGER_WATCH_INTERVAL
            last_watch = time()
            if parent_pid() != p.parent
                @warn "$(c.name): the manager process ($(p.parent)) is gone. Stopping."
                arm_hard_exit("the manager was lost")
                stop!(p; code=0)
                break
            end
        end
        sleep(0.05)
    end
    return
end

"""Guarantee the process ends after an orderly stop was begun."""
function arm_hard_exit(reason::String)
    @async begin
        sleep(HARD_EXIT_GRACE)
        @error "still running $(HARD_EXIT_GRACE) s after $reason; exiting now."
        exit(1)
    end
    return
end
