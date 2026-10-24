# A ProtocolProxyManager (PROTOCOL.md §1, §1a, §7, §9, §10, §11b): launches proxy processes described by manifests,
# hands each its tokens, key and TLS material on stdin, accepts their registration, reads their logs from the pipes and
# from LOG batches, keeps them alive with PING, terminates them on `stop!` and relaunches them on the next request after
# a loss. It is built on the same `Connector` as a proxy, so a Julia program can host proxies written in any language.
#
#     m = Manager(find_manifest("mqtt"); encrypt=true, ipc_tls=true, persistent=true)
#     start!(m)
#     p = get_proxy(m, ("mqtt", "broker"); host="broker.example", port=1883)
#     wait_registered(m, p, 20.0)
#     reply = request(m, p, "READ_POINTS", payload)
#     stop!(m)

const METHOD_REGISTER_PEER = "REGISTER_PEER"
const METHOD_PING = "PING"
const METHOD_LOG = "LOG"
const METHOD_SET_LOG_LEVEL = "SET_LOG_LEVEL"

const DEFAULT_HEARTBEAT_INTERVAL = 10.0
const DEFAULT_HEARTBEAT_TIMEOUT = 5.0
const DEFAULT_HEARTBEAT_MISSES = 3
const DEFAULT_TERMINATE_TIMEOUT = 5.0
const DIAL_RETRY_INTERVAL = 1.0
const ENV_PYTHON = "PROTOCOL_PROXY_PYTHON"

#: get_proxy options the manager consumes itself; everything else travels to the proxy as `--name value`.
const MANAGER_ONLY_OPTIONS = Set(["manager_callbacks", "dial", "ssh_host", "ssh_options", "ssh_forward", "remote_python", "remote_env"])

"""A launched proxy process as the manager sees it: its peer on the IPC, its process and its liveness."""
mutable struct ManagedProxy
    peer::Peer
    proxy_id::UUID
    #: the proxy name it was launched with (the process key as a Python tuple); `key` the process key itself
    name::String
    key::Tuple
    command::Vector{String}
    material::Union{Nothing,TlsMaterial}
    process::Union{Nothing,Base.Process}
    pid::Int
    #: launching, registered, healthy, unhealthy, lost
    state::String
    last_seen::Union{Nothing,Float64}
    missed::Int
    health::Union{Nothing,Dict{String,Any}}
    #: gates the proxy's records in this process (Python levelno)
    log_levelno::Int
    #: the AEAD the proxy said it encrypts with in REGISTER_PEER ("" when it does not)
    cipher::String
    registered::Bool
    lost::Bool
    lost_reason::Union{Nothing,String}
    exited::Bool
    exit_code::Union{Nothing,Int}
end

ManagedProxy(peer::Peer, proxy_id::UUID, name::String, key::Tuple, command::Vector{String}, material, levelno::Int) =
    ManagedProxy(peer, proxy_id, name, key, command, material, nothing, 0, "launching", nothing, 0, nothing, levelno, "",
                 false, false, nothing, false, nothing)

is_running(p::ManagedProxy) = p.process !== nothing && !p.exited && process_running(p.process)

"""
    Manager(manifest; kwargs...)

The manager of one manifest's proxies. Keywords: `name` (this end's name in log lines, "Manager"); `inbound_address`
("localhost"; proxies are told `--manager-address` this) and `inbound_port` (nothing: the first free port in
22801..22899); `persistent`, `encrypt`, `cipher` ("auto"), `ipc_tls` as defaults for every proxy, each overridable per
launch through the options `persistent`, `encrypt`, `cipher`, `ipc_tls`; `compress_threshold`; `heartbeat_interval`
(10 s; 0 disables the heartbeat), `heartbeat_timeout` (5 s), `heartbeat_misses` (3); `python` (what `{python}`
resolves to: this, else `\$PROTOCOL_PROXY_PYTHON`, else `python3`); `environment` (added to every proxy's after the
manifest's); `records` (a function receiving each launched proxy's `Record`; default `log_record`); `proxy_log_level`
(gates their records here and travels as `--log-level`; "INFO").
"""
mutable struct Manager
    manifest::Manifest
    connector::Connector
    name::String
    inbound_address::String
    persistent::Bool
    encrypt::Bool
    ipc_tls::Bool
    heartbeat_interval::Float64
    heartbeat_timeout::Float64
    heartbeat_misses::Int
    python::Union{Nothing,String}
    environment::Dict{String,String}
    records::Function
    proxy_levelno::Int
    authority::Authority
    material::TlsMaterial
    proxies::Dict{UUID,ManagedProxy}
    #: process key text -> proxy id, kept across relaunches
    ids::Dict{String,UUID}
    #: must_match options of the first remote of each process
    shared::Dict{String,Dict{String,Any}}
    lost_callbacks::Vector{Function}
    stopping_pids::Set{Int}
    started::Bool
    stopped::Bool
    heartbeat_task::Union{Nothing,Task}
    lock::ReentrantLock
end

function Manager(manifest::Manifest; name::AbstractString="Manager", inbound_address::AbstractString="localhost",
                 inbound_port::Union{Nothing,Integer}=nothing, persistent::Bool=false, encrypt::Bool=false,
                 cipher::AbstractString="auto", ipc_tls::Bool=false, compress_threshold::Integer=COMPRESS_THRESHOLD,
                 heartbeat_interval::Real=DEFAULT_HEARTBEAT_INTERVAL, heartbeat_timeout::Real=DEFAULT_HEARTBEAT_TIMEOUT,
                 heartbeat_misses::Integer=DEFAULT_HEARTBEAT_MISSES, python::Union{Nothing,AbstractString}=nothing,
                 environment=Dict{String,String}(), records::Function=log_record, proxy_log_level="INFO")
    proxy_id = uuid4()
    authority = Authority("protocol-proxy manager $proxy_id")
    material = issue(authority, uuid_hex(proxy_id); ip_addresses=[String(inbound_address)])
    connector = Connector(proxy_id, uuid4(); name, inbound_address, inbound_port, persistent, compress_threshold,
                          cipher, features=default_features(), tls=material, tls_optional=true)
    levelno = levelno_of(proxy_log_level)
    levelno === nothing && throw(ArgumentError("Unknown proxy_log_level $(repr(proxy_log_level))"))
    m = Manager(manifest, connector, String(name), String(inbound_address), persistent, encrypt, ipc_tls,
                Float64(heartbeat_interval), Float64(heartbeat_timeout), Int(heartbeat_misses),
                python === nothing ? nothing : String(python), Dict{String,String}(environment), records, levelno,
                authority, material, Dict{UUID,ManagedProxy}(), Dict{String,UUID}(), Dict{String,Dict{String,Any}}(),
                Function[], Set{Int}(), false, false, nothing, ReentrantLock())
    register_callback!(connector, (c, h, payload) -> handle_register_peer(m, h, payload), METHOD_REGISTER_PEER; provides_response=true)
    register_callback!(connector, (c, h, payload) -> handle_log(m, h, payload), METHOD_LOG)
    return m
end

manager_id(m::Manager) = m.connector.proxy_id
manager_token(m::Manager) = m.connector.token
manager_cipher(m::Manager) = m.connector.cipher

"""Bind the listener and begin accepting connections. Returns the bound (address, port)."""
function start!(m::Manager)
    bound = start_listener!(m.connector)
    m.started = true
    return bound
end

listen_address(m::Manager) = m.connector.bound

"""What `{python}` resolves to for this manager."""
function python_for(m::Manager)
    m.python === nothing || return m.python
    env = get(ENV, ENV_PYTHON, "")
    return isempty(env) ? "python3" : env
end

# ---- proxies ---------------------------------------------------------------------------------------------------------

"""The proxies this manager currently knows, by name."""
proxies(m::Manager) = sort(collect(values(m.proxies)); by=p -> p.name)

proxy_by_id(m::Manager, proxy_id::UUID) = get(m.proxies, proxy_id, nothing)

is_current(m::Manager, p::ManagedProxy) = get(m.proxies, p.proxy_id, nothing) === p

"""
    on_proxy_lost!(m, f)

Call `f(proxy, reason)` whenever a proxy this manager launched is lost: its process exited, it missed too many
heartbeats, or it never registered. By then the proxy is already removed, so the next `get_proxy` for its key launches
a fresh process; users typically re-run their setup from the callback.
"""
on_proxy_lost!(m::Manager, f::Function) = (push!(m.lost_callbacks, f); nothing)

function notify_lost(m::Manager, p::ManagedProxy, reason::String)
    for f in copy(m.lost_callbacks)
        try
            f(p, reason)
        catch e
            @warn "$(m.name): proxy-lost callback raised for $(p.proxy_id): $(sprint(showerror, e))"
        end
    end
end

"""Forget a proxy, stop its process if it is still running, and tell the listeners."""
function lose_proxy!(m::Manager, p::ManagedProxy, reason::String)
    current = lock(m.lock) do
        if is_current(m, p)
            delete!(m.proxies, p.proxy_id)
            true
        else
            false
        end
    end
    current || return
    remove_peer!(m.connector, p.proxy_id)
    p.state = "lost"
    p.lost_reason = reason
    p.lost = true
    is_running(p) && @async terminate_process(m, p, DEFAULT_TERMINATE_TIMEOUT)
    notify_lost(m, p, reason)
    return
end

function remove_peer!(c::Connector, proxy_id::UUID)
    peer = pop!(c.peers, proxy_id, nothing)
    peer === nothing && return
    conn = peer.connection
    conn === nothing || connection_lost!(c, conn, "closed")
    return
end

"""
    get_proxy(m, unique_remote_id::Tuple; options...) -> ManagedProxy
    get_proxy(m, unique_remote_id::Tuple, options::AbstractDict)

The proxy for `unique_remote_id`, launching its process when none runs for its key. The options are the proxy's launch
options in the Python kwargs spelling (`inbound_port`): they select the process through the manifest's identity, are
checked against its `must_match`, and travel to the proxy as `--name value`, except the manager-only ones
(`MANAGER_ONLY_OPTIONS`). `encrypt`, `cipher`, `ipc_tls`, `persistent` and `manager_dials` also configure this end's
side of the connection; `dial` (`(host, port)` or `"host:port"`) is where to reach a proxy launched with `manager_dials`.
"""
get_proxy(m::Manager, unique_remote_id::Tuple; options...) =
    get_proxy(m, unique_remote_id, Dict{String,Any}(string(k) => v for (k, v) in options))

function get_proxy(m::Manager, unique_remote_id::Tuple, options::AbstractDict)
    opts = Dict{String,Any}(string(k) => v for (k, v) in options)
    m.started || error("the manager has not been started")
    m.stopped && error("the manager is stopped")
    key = process_key(m.manifest, unique_remote_id, opts)
    key_text = py_tuple(key)
    p, fresh = lock(m.lock) do
        first = get(m.shared, key_text, nothing)
        if first !== nothing
            bad = conflicts(m.manifest.identity, first, opts)
            isempty(bad) || error("remote $(py_tuple(unique_remote_id)) would share proxy process $key_text but differs in " *
                                  "$(join(bad, ", ")), which the $(m.manifest.name) manifest requires to match")
        else
            m.shared[key_text] = Dict{String,Any}(k => get(opts, k, nothing) for k in m.manifest.identity.must_match)
        end
        proxy_id = get!(m.ids, key_text) do
            uuid4()
        end
        existing = get(m.proxies, proxy_id, nothing)
        existing === nothing || return existing, false
        p = prepare(m, proxy_id, key_text, key, opts)
        m.connector.peers[proxy_id] = p.peer
        m.proxies[proxy_id] = p
        return p, true
    end
    fresh || return p
    try
        launch!(m, p)
    catch
        lock(m.lock) do
            is_current(m, p) && delete!(m.proxies, p.proxy_id)
        end
        remove_peer!(m.connector, p.proxy_id)
        rethrow()
    end
    if p.peer.address !== nothing && opt_bool(get(opts, "manager_dials", nothing), false)
        errormonitor(@async dial_until_registered(m, p))
    end
    start_heartbeat!(m)
    @info "PPM: Proxy $(p.proxy_id) created, waiting for registration before sending."
    return p
end

"""Build the proxy's peer, launch command and handshake from its options (the manager lock is held)."""
function prepare(m::Manager, proxy_id::UUID, name::String, key::Tuple, options::Dict{String,Any})
    launch = Dict{String,Any}(k => v for (k, v) in options if v !== nothing && !(k in MANAGER_ONLY_OPTIONS))
    prefix, python = launcher_prefix(m, options)
    if !isempty(prefix) && opt_bool(get(options, "ssh_forward", nothing), true)
        get!(launch, "manager_address", "127.0.0.1")        # the forwarded port on the proxy's host
    end
    get!(launch, "log_level", python_level_name(m.proxy_levelno))
    m.encrypt && get!(launch, "encrypt", true)
    encrypt = opt_bool(get(launch, "encrypt", nothing), false)
    encrypt && get!(launch, "cipher", manager_cipher(m))      # one choice for both ends unless the caller says otherwise
    m.ipc_tls && get!(launch, "ipc_tls", true)
    use_tls = opt_bool(get(launch, "ipc_tls", nothing), false)
    manager_address = string(pop!(launch, "manager_address", m.inbound_address))
    persistent = haskey(launch, "persistent") ? opt_bool(launch["persistent"], false) : nothing
    dial = dial_target(options)
    dial === nothing || (persistent = true)
    bound = listen_address(m)
    bound === nothing && error("the manager has not been started")
    standard = ["--proxy-id", uuid_hex(proxy_id), "--proxy-name", name, "--manager-id", uuid_hex(manager_id(m)),
                "--manager-address", manager_address, "--manager-port", string(bound[2])]
    for k in sort(collect(keys(launch)))
        push!(standard, "--" * replace(k, "_" => "-"), option_string(launch[k]))
    end
    command = vcat(prefix, launch_command(m.manifest, python, standard))
    key_bytes = encrypt ? rand(RandomDevice(), UInt8, KEY_BYTES) : nothing
    peer = Peer(proxy_id, uuid4(); name, address=dial, persistent, key=key_bytes, tls=use_tls)
    material = use_tls ? issue(m.authority, uuid_hex(proxy_id)) : nothing
    return ManagedProxy(peer, proxy_id, name, key, command, material, m.proxy_levelno)
end

"""
How the proxy command is wrapped: locally nothing, `{python}` this manager's interpreter. With `ssh_host` the prefix
is `ssh -o BatchMode=yes [-R <manager port>:127.0.0.1:<manager port>] [ssh_options...] host env <marker>
[remote_env...]`, and `{python}` is `remote_python` (default `python3`).
"""
function launcher_prefix(m::Manager, options::Dict{String,Any})
    host = get(options, "ssh_host", nothing)
    (host === nothing || isempty(string(host))) && return String[], python_for(m)
    prefix = ["ssh", "-o", "BatchMode=yes"]
    if opt_bool(get(options, "ssh_forward", nothing), true)
        port = listen_address(m)[2]
        push!(prefix, "-R", "$port:127.0.0.1:$port")
    end
    ssh_options = get(options, "ssh_options", nothing)
    ssh_options === nothing || append!(prefix, [string(o) for o in ssh_options])
    push!(prefix, string(host), "env", LAUNCHED_BY_MANAGER_ENV * "=1")
    remote_env = get(options, "remote_env", nothing)
    if remote_env !== nothing
        for k in sort([string(k) for k in keys(remote_env)])
            push!(prefix, "$k=$(remote_env[k])")
        end
    end
    remote_python = get(options, "remote_python", nothing)
    return prefix, remote_python === nothing || isempty(string(remote_python)) ? "python3" : string(remote_python)
end

"""
Where the manager must dial a proxy launched with `manager_dials`: the `dial` option (`(host, port)` or `"host:port"`),
else the proxy's `inbound_address`/`inbound_port` launch options. Nothing for a proxy that dials in.
"""
function dial_target(options::Dict{String,Any})
    opt_bool(get(options, "manager_dials", nothing), false) || return nothing
    dial = get(options, "dial", nothing)
    if dial isa AbstractString && !isempty(dial)
        host, port = rsplit(dial, ':'; limit=2)
        return (String(host), parse(Int, port))
    elseif dial isa Union{Tuple,AbstractVector} && length(dial) == 2
        return (string(dial[1]), parse(Int, string(dial[2])))
    end
    port = get(options, "inbound_port", nothing)
    port === nothing && error("manager_dials=true needs the proxy's inbound_port (and inbound_address) or a dial=(host, port)")
    address = get(options, "inbound_address", nothing)
    return (address === nothing || isempty(string(address)) ? "localhost" : string(address), parse(Int, string(port)))
end

"""
    wait_registered(m, p, timeout)

Wait for the proxy to register. When it has not done so within `timeout` seconds it is removed (its process
terminated) and an error thrown; a proxy lost meanwhile throws its reason at once.
"""
function wait_registered(m::Manager, p::ManagedProxy, timeout::Real)
    timedwait(() -> p.registered || p.lost, Float64(timeout); pollint=0.01)
    p.registered && return nothing
    p.lost && error("proxy $(p.name) lost before registering: $(p.lost_reason)")
    @warn "Peer $(p.proxy_id) did not register within $timeout seconds. Removing peer."
    lose_proxy!(m, p, "did not register within $timeout seconds")
    error("proxy $(p.name) did not register within $timeout seconds")
end

"""
For a proxy that cannot dial in, open the persistent connection to it and PING until it has registered over that
connection (it adopts the connection once the frame authenticates as this manager).
"""
function dial_until_registered(m::Manager, p::ManagedProxy)
    while is_current(m, p) && !p.registered && !m.stopped
        if !reachable(p.peer.address)       # a probe first: the proxy is usually not listening yet, and that is no warning
            p.lost && return
            sleep(DIAL_RETRY_INTERVAL)
            continue
        end
        try
            request(m, p, METHOD_PING; timeout=m.heartbeat_timeout)
        catch e
            @debug "PPM: $(p.name) not reachable yet at $(p.peer.address): $(sprint(showerror, e))"
            p.lost && return
            sleep(DIAL_RETRY_INTERVAL)
            continue
        end
        timedwait(() -> p.registered || p.lost, DIAL_RETRY_INTERVAL; pollint=0.02)
    end
end

"""Whether something accepts TCP connections at `address` (the connection is closed at once)."""
function reachable(address::Tuple{String,Int})
    sock = try
        Sockets.connect(resolve_ipv4(address[1]), address[2])
    catch
        return false
    end
    close(sock)
    return true
end

# ---- requests ------------------------------------------------------------------------------------------------------

"""
    request(m, p, method, payload=UInt8[]; timeout=30.0, protocol_version=2, remote_id=nothing) -> Vector{UInt8}

Send a request to a proxy and wait for its reply; throws `ResponseTimeout` or the error that failed it.
"""
function request(m::Manager, p::ManagedProxy, method::AbstractString, payload=UInt8[]; timeout::Real=30.0,
                 protocol_version::Integer=2, remote_id::Union{Nothing,UUID}=nothing)
    msg = Message(method, payload; response_expected=true, protocol_version, remote_id)
    result = send_message(m.connector, p.peer, msg)
    result isa Pending || error("unable to send $method to $(p.name)")
    return wait_response(result, timeout)
end

"""Send a message to a proxy that expects no reply. Returns whether it was handed to a connection."""
send_to(m::Manager, p::ManagedProxy, msg::Message) = send_message(m.connector, p.peer, msg) !== false

"""
Change a running proxy's log level (SET_LOG_LEVEL) and gate its records here at the same level. Returns the proxy's
reply (`{"level": ...}`) as a Dict.
"""
function set_proxy_log_level!(m::Manager, p::ManagedProxy, level; timeout::Real=10.0)
    levelno = levelno_of(level)
    levelno === nothing && throw(ArgumentError("Unknown level $(repr(level))"))
    p.log_levelno = levelno
    reply = request(m, p, METHOD_SET_LOG_LEVEL, JSON3.write(Dict("level" => python_level_name(levelno))); timeout)
    return JSON3.read(reply, Dict{String,Any})
end

# ---- registration and logs -----------------------------------------------------------------------------------------

function handle_register_peer(m::Manager, h::Header, payload::Vector{UInt8})
    p = proxy_by_id(m, h.sender_id)
    if p === nothing
        @error "PPM: Received registration message from unknown peer: $(h.sender_id)."
        return "false"
    end
    body = try
        JSON3.read(payload, Dict{String,Any})
    catch
        nothing
    end
    address = body === nothing ? nothing : get(body, "address", nothing)
    port = body === nothing ? nothing : get(body, "port", nothing)
    if !(address isa AbstractString) || !(port isa Integer) || port == 0
        @error "PPM: Failed to register peer: $(p.proxy_id) with message: $(String(copy(payload)))."
        return "false"
    end
    features = [string(f) for f in get(body, "features", Any[])]
    p.peer.address = (String(address), Int(port))
    p.peer.features = features
    cipher = get(body, "cipher", nothing)
    p.cipher = cipher isa AbstractString ? String(cipher) : ""
    p.state = "registered"
    p.last_seen = time()
    p.registered = true
    encrypts = !isempty(p.cipher) && p.peer.key !== nothing ? "; encrypts with $(p.cipher)" : ""
    @info "PPM: Successfully registered peer: $(p.proxy_id) @ $(address):$(port) (features: $(join(features, ", "))$encrypts)"
    return JSON3.write(Dict{String,Any}("registered" => true, "features" => m.connector.features))
end

function handle_log(m::Manager, h::Header, payload::Vector{UInt8})
    p = proxy_by_id(m, h.sender_id)
    if p === nothing
        @warn "PPM: LOG batch from unknown peer $(h.sender_id) ignored."
        return nothing
    end
    records = try
        records_from_batch(payload, proxy_logger_name(m.manifest.name, p.name), p.pid, p.name)
    catch e
        @warn "PPM: Undecodable LOG batch from $(p.name): $(sprint(showerror, e))"
        return nothing
    end
    for r in records
        r.levelno >= p.log_levelno && handle_record(m, r)
    end
    return nothing
end

function handle_record(m::Manager, r::Record)
    try
        m.records(r)
    catch e
        @warn "PPM: record handler raised: $(sprint(showerror, e))"
    end
end

# ---- process -------------------------------------------------------------------------------------------------------

"""
A launched proxy's environment: the manager's, the manifest's (its placeholders resolved, `{python}` to this manager's
interpreter), this manager's, and the launch marker.
"""
function proxy_environment(m::Manager)
    env = Dict{String,String}(k => v for (k, v) in ENV)
    merge!(env, resolve_environment(m.manifest, python_for(m)), m.environment)
    env[LAUNCHED_BY_MANAGER_ENV] = "1"
    return env
end

"""Start the proxy's process, write the stdin handshake (§1) and start the pipe readers and the watcher."""
function launch!(m::Manager, p::ManagedProxy)
    isempty(p.command) && error("$(m.manifest.name): empty launch command")
    input, out, err = Pipe(), Pipe(), Pipe()
    cmd = setenv(Cmd(p.command), proxy_environment(m))
    process = try
        run(pipeline(cmd; stdin=input, stdout=out, stderr=err); wait=false)
    catch e
        for pipe in (input, out, err)
            close(pipe)
        end
        error("$(m.manifest.name): unable to launch $(p.command): $(sprint(showerror, e))")
    end
    close(out.in)
    close(err.in)
    close(input.out)
    p.process = process
    p.pid = getpid(process)
    @info "proxy $(p.name) has PID $(p.pid)"
    logger_name = proxy_logger_name(m.manifest.name, p.name)
    errormonitor(@async read_records(m, p, out, "stdout", logger_name))
    errormonitor(@async read_records(m, p, err, "stderr", logger_name))
    @info "PPM: Created new ProtocolProxy $(p.name) with ID $(p.proxy_id), pid: $(p.pid)"
    handshake = uuid_hex(p.peer.token) * uuid_hex(manager_token(m))
    p.peer.key === nothing || (handshake *= bytes2hex(p.peer.key))
    p.material === nothing || (handshake *= tls_material_line(p.material))
    try
        write(input, handshake)
    catch e
        @warn "PPM: unable to write the handshake to $(p.name) (pid $(p.pid)): $(sprint(showerror, e))"
    finally
        close(input)
    end
    errormonitor(@async watch_process(m, p, process))
    return
end

"""Read a proxy's pipe line by line until EOF and handle each record at or above the proxy's level."""
function read_records(m::Manager, p::ManagedProxy, pipe::IO, stream::String, logger_name::String)
    try
        for line in eachline(pipe)
            r = try
                record_from_line(line, logger_name, stream, p.pid, p.name)
            catch e
                @error "Unable to parse a log line from $logger_name $stream: $(sprint(showerror, e))"
                continue
            end
            r === nothing && continue
            r.levelno >= p.log_levelno && handle_record(m, r)
        end
    catch e
        e isa Base.IOError || @warn "PPM: reader of $(p.name) $stream stopped: $(sprint(showerror, e))"
    end
end

"""The exit code the manager reports: the process's, or minus the signal that killed it."""
exit_code_of(process::Base.Process) = process.termsignal != 0 ? -Int(process.termsignal) : Int(process.exitcode)

"""
Wait for the process to exit; when it does, the proxy is dropped (if it is still the current one for its id) so the
next `get_proxy` relaunches, and the listeners are told so they can re-register.
"""
function watch_process(m::Manager, p::ManagedProxy, process::Base.Process)
    wait(process)
    code = exit_code_of(process)
    p.exit_code = code
    p.exited = true
    if is_current(m, p)
        @warn "PPM: $(m.manifest.name) process $(p.pid) (proxy $(p.proxy_id)) exited with code $code. It will be relaunched on the next request for it."
        lose_proxy!(m, p, "process exited with code $code")
    else
        @debug "PPM: $(m.manifest.name) process $(p.pid) (proxy $(p.proxy_id)) exited with code $code after its peer was already replaced or removed."
    end
end

"""Stop a proxy's process: SIGTERM, then SIGKILL after `timeout` seconds. While it runs the process is not pinged."""
function terminate_process(m::Manager, p::ManagedProxy, timeout::Real)
    process = p.process
    (process === nothing || p.exited || !process_running(process)) && return
    push!(m.stopping_pids, p.pid)
    try
        @info "Terminating $(m.manifest.name) with PID: $(p.pid)"
        try
            kill(process, Base.SIGTERM)
        catch e
            @warn "Exception encountered attempting to terminate proxy process ($(p.pid)): $(sprint(showerror, e))"
        end
        timedwait(() -> p.exited, Float64(timeout); pollint=0.02) === :ok && return
        @info "Killing $(m.manifest.name) with PID: $(p.pid)"
        try
            kill(process, Base.SIGKILL)
        catch
        end
        timedwait(() -> p.exited, Float64(timeout); pollint=0.02) === :ok ||
            @warn "Failed to stop $(m.manifest.name) with PID: $(p.pid)"
    finally
        delete!(m.stopping_pids, p.pid)
    end
    return
end

"""
    terminate!(m, p; timeout=5.0)

Stop a proxy's process (SIGTERM, SIGKILL after `timeout`) without forgetting the proxy: the watcher then loses it and
the next `get_proxy` relaunches.
"""
terminate!(m::Manager, p::ManagedProxy; timeout::Real=DEFAULT_TERMINATE_TIMEOUT) = terminate_process(m, p, timeout)

"""Wait up to `timeout` seconds for the process to exit; returns its exit code, or nothing if it has not."""
function wait_exit(p::ManagedProxy, timeout::Real)
    p.process === nothing && return nothing
    timedwait(() -> p.exited, Float64(timeout); pollint=0.02)
    return p.exited ? p.exit_code : nothing
end

"""Run the manifest's self-test command, if it has one. Returns nothing when it passes or there is none, else the failure text."""
function run_self_test(m::Manager)
    argv = self_test_command(m.manifest, python_for(m))
    argv === nothing && return nothing
    cmd = setenv(Cmd(argv), proxy_environment(m))
    out = IOBuffer()
    process = run(pipeline(ignorestatus(cmd); stdout=out, stderr=out))
    success(process) && return nothing
    return "$(m.manifest.name) self test $argv failed with exit code $(exit_code_of(process))\n$(String(take!(out)))"
end

# ---- heartbeat -----------------------------------------------------------------------------------------------------

function start_heartbeat!(m::Manager)
    m.heartbeat_interval > 0 || return
    m.heartbeat_task === nothing || return
    m.heartbeat_task = errormonitor(@async heartbeat_loop(m))
    return
end

function heartbeat_loop(m::Manager)
    while !m.stopped
        timedwait(() -> m.stopped, m.heartbeat_interval; pollint=0.05)
        m.stopped && break
        for p in proxies_to_ping(m)
            errormonitor(@async ping(m, p))
        end
    end
end

"""Registered proxies with a running process that this manager is not stopping (a stopping proxy refuses connections, which is not a miss)."""
proxies_to_ping(m::Manager) = [p for p in values(m.proxies) if p.registered && p.pid != 0 && !(p.pid in m.stopping_pids)]

function ping(m::Manager, p::ManagedProxy)
    reply = try
        request(m, p, METHOD_PING; timeout=m.heartbeat_timeout)
    catch e
        why = e isa ResponseTimeout ? "no reply within $(m.heartbeat_timeout) s" : sprint(showerror, e)
        is_current(m, p) || return
        p.missed += 1
        if p.missed >= m.heartbeat_misses
            p.state = "lost"
            @warn "PPM: $(p.name) missed heartbeat $(p.missed) of $(m.heartbeat_misses) ($why)."
            lose_proxy!(m, p, "missed $(p.missed) heartbeats")
        else
            p.state = "unhealthy"
            @info "PPM: $(p.name) missed heartbeat $(p.missed) of $(m.heartbeat_misses) ($why)."
        end
        return
    end
    heartbeat_answered!(p, reply)
end

"""Any reply counts (an old proxy answers with an unknown-method error, which still proves it alive)."""
function heartbeat_answered!(p::ManagedProxy, reply::Vector{UInt8})
    p.last_seen = time()
    p.missed = 0
    p.state = "healthy"
    report = try
        JSON3.read(reply, Dict{String,Any})
    catch
        nothing
    end
    report isa Dict && get(report, "status", nothing) != "error" && (p.health = report)
    return
end

"""
The liveness of every proxy this manager knows, by proxy name: the state machine (launching, registered, healthy,
unhealthy, lost), when it was last heard from, consecutive misses, features, pid and last PING report.
"""
function health(m::Manager)
    out = Dict{String,Dict{String,Any}}()
    for p in proxies(m)
        out[p.name] = Dict{String,Any}(
            "proxy_id" => string(p.proxy_id), "state" => p.state, "last_seen" => p.last_seen, "missed" => p.missed,
            "features" => copy(p.peer.features), "persistent" => is_persistent(m.connector, p.peer),
            "connected" => p.peer.connection !== nothing && alive(p.peer.connection), "pid" => p.pid, "report" => p.health)
    end
    return out
end

# ---- stopping ------------------------------------------------------------------------------------------------------

"""
    stop!(m; terminate_proxies=true, timeout=5.0)

Stop the manager and, with `terminate_proxies`, the proxies it launched: SIGTERM each process, SIGKILL after
`timeout`, so a stopped manager leaves no orphans. A caller that hands its processes over passes false.
"""
function stop!(m::Manager; terminate_proxies::Bool=true, timeout::Real=DEFAULT_TERMINATE_TIMEOUT)
    m.stopped && return
    m.stopped = true
    stop!(m.connector)
    terminate_proxies || return
    tasks = [(@async terminate_process(m, p, timeout)) for p in proxies(m) if is_running(p)]
    timedwait(() -> all(istaskdone, tasks), 2 * Float64(timeout) + 1; pollint=0.02)
    return
end

# ---- helpers -------------------------------------------------------------------------------------------------------

"""A boolean launch option as the Python manager's str2bool reads it (a Bool, or its command-line spelling)."""
function opt_bool(value, fallback::Bool)
    value === nothing && return fallback
    value isa Bool && return value
    if value isa AbstractString
        v = lowercase(strip(value))
        v in ("1", "true", "t", "yes", "y", "on") && return true
        v in ("0", "false", "f", "no", "n", "off", "") && return false
    end
    value isa Integer && return value != 0
    return fallback
end

"""A launch option's command-line value: booleans as true/false, everything else as printed."""
option_string(value) = value isa Bool ? (value ? "true" : "false") : string(value)
