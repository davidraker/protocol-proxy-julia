# Conformance checks for a proxy executable through the Julia manager (PROTOCOL.md §12), the counterpart of the Python
# harness (`protocol_proxy.conformance`): the proxy under test is whatever a manifest launches, in any language. Each
# check launches it with one combination of options and exercises the core contract: registration with its feature
# list, PING, the error reply for an unknown method, SET_LOG_LEVEL when advertised, a LOG batch over the socket when
# advertised, header version 1, per-message and persistent connections, encryption with each AEAD the proxy advertises,
# optionally TLS and manager-initiated registration, and a clean exit on SIGTERM. An echo method, if the proxy has one,
# round-trips payloads large enough to be compressed. The check names and the report format are the Python harness's.

#: Seconds a proxy that advertises `log` has to deliver a record over the socket once it has something to say.
const LOG_BATCH_WAIT = 3.0

struct Check
    name::String
    passed::Bool
    detail::String
    skipped::Bool
end
status(c::Check) = c.skipped ? "skip" : c.passed ? "pass" : "FAIL"

mutable struct Report
    manifest::Manifest
    checks::Vector{Check}
    features::Vector{String}
end
Report(manifest::Manifest) = Report(manifest, Check[], String[])

report_ok(r::Report) = all(c -> c.passed || c.skipped, r.checks)
add!(r::Report, name::AbstractString, passed::Bool, detail::AbstractString="") = push!(r.checks, Check(String(name), passed, String(detail), false))
skip!(r::Report, name::AbstractString, detail::AbstractString) = push!(r.checks, Check(String(name), true, String(detail), true))

"""The report in the Python harness's layout."""
function report_text(r::Report)
    width = max(10, maximum((length(c.name) for c in r.checks); init=0))
    passed = count(c -> c.passed && !c.skipped, r.checks)
    failed = count(c -> !c.passed, r.checks)
    skipped = count(c -> c.skipped, r.checks)
    lines = ["$(r.manifest.name): $(report_ok(r) ? "all checks pass" : "FAILURES") ($passed passed, $failed failed, $skipped skipped)"]
    for c in r.checks
        push!(lines, "  $(rpad(status(c), 4)) $(rpad(c.name, width))  $(c.detail)")
    end
    return join(lines, "\n")
end

report_json(r::Report) = JSON3.write(Dict{String,Any}(
    "proxy" => r.manifest.name, "ok" => report_ok(r), "features" => r.features,
    "checks" => [Dict("name" => c.name, "status" => status(c), "detail" => c.detail) for c in r.checks]))

"""One launched proxy under one manager configuration; `records` keeps every record the manager handled for it."""
mutable struct Session
    manager::Manager
    proxy::Union{Nothing,ManagedProxy}
    timeout::Float64
    records::Vector{Record}
end

by_channel(s::Session, channel::AbstractString) = [r for r in s.records if r.channel == channel]

"""Records that arrived by `channel` (`socket` or `stderr`), waiting up to `timeout` for the first."""
function wait_for_records(s::Session, channel::AbstractString, timeout::Real=LOG_BATCH_WAIT)
    timedwait(() -> !isempty(by_channel(s, channel)), Float64(timeout); pollint=0.05)
    return by_channel(s, channel)
end

session_request(s::Session, method::AbstractString, payload=UInt8[]; protocol_version::Integer=2) =
    request(s.manager, s.proxy, method, payload; timeout=s.timeout, protocol_version)

function request_json(s::Session, method::AbstractString, body=nothing)
    reply = session_request(s, method, body === nothing ? UInt8[] : JSON3.write(body))
    isempty(reply) && return nothing
    return JSON3.read(reply, Any)
end

"""Stop the manager (SIGTERM to the proxy) and return the proxy's exit code, nothing if it did not exit."""
function exit_code(s::Session)
    stop!(s.manager; timeout=5.0)
    return wait_exit(s.proxy, 10.0)
end

close_session(s::Session) = s.manager.stopped || stop!(s.manager; timeout=5.0)

detail(v) = v === nothing ? "None" : py_like(v)

"""JSON values rendered the way Python prints a dict, so reports read alike across harnesses."""
function py_like(v)
    v === nothing && return "None"
    v isa Bool && return v ? "True" : "False"
    v isa AbstractString && return "'" * v * "'"
    v isa AbstractDict && return "{" * join(["$(py_like(string(k))): $(py_like(v[k]))" for k in sort(collect(keys(v)); by=string)], ", ") * "}"
    v isa AbstractVector && return "[" * join(py_like.(v), ", ") * "]"
    v isa AbstractFloat && isinteger(v) && return string(Int(v)) * ".0"
    return string(v)
end

py_list(items) = "[" * join(["'" * string(i) * "'" for i in items], ", ") * "]"

exception_text(e) = "$(nameof(typeof(e))): $(sprint(showerror, e))"

is_health(v) = v isa AbstractDict && get(v, "uptime", nothing) isa Real && get(v, "remotes", nothing) isa Integer &&
    get(v, "busy", nothing) isa Bool && haskey(v, "last_activity")
has_uptime(v) = v isa AbstractDict && haskey(v, "uptime")

"""
    run_conformance(manifest; launch_options=Dict(), echo_method=nothing, tls=false, manager_dials=false,
                    timeout=20.0, python=nothing) -> Report

Run every check against the proxy the manifest launches.
"""
function run_conformance(manifest::Manifest; launch_options::AbstractDict=Dict{String,Any}(), echo_method=nothing,
                         tls::Bool=false, manager_dials::Bool=false, timeout::Real=20.0, python=nothing)
    report = Report(manifest)
    timeout = Float64(timeout)

    # Launch a session with a manager configured by `manager_options` and the launch options; records the registration
    # check and returns nothing when the proxy did not register. The proxy's logger is held at INFO for the run so its
    # switch to the socket and SET_LOG_LEVEL's confirmation are records it must ship.
    function open_session(name::String, manager_options::NamedTuple, launch::Dict{String,Any})
        records = Record[]
        local s
        try
            m = Manager(manifest; heartbeat_interval=0, python, proxy_log_level="INFO",
                        records=r -> (push!(records, r); log_record(r)), manager_options...)
            start!(m)
            s = Session(m, nothing, timeout, records)
        catch e
            add!(report, "$name: registration", false, exception_text(e))
            return nothing
        end
        options = merge(Dict{String,Any}(string(k) => v for (k, v) in launch_options), launch)
        try
            s.proxy = get_proxy(s.manager, ("conformance",), options)
            wait_registered(s.manager, s.proxy, timeout)
        catch e
            add!(report, "$name: registration", false, s.proxy === nothing ? exception_text(e) : "no registration within $(timeout)s")
            close_session(s)
            return nothing
        end
        add!(report, "$name: registration", true, "features " * py_list(s.proxy.peer.features))
        return s
    end
    function exit!(s::Session, name::String)
        code = exit_code(s)
        add!(report, name, code == 0, "exit code $(code === nothing ? "None" : code)")
        close_session(s)
    end
    function echo(s::Session, payloads...)
        for payload in payloads
            reply = session_request(s, echo_method, payload)
            reply == Vector{UInt8}(payload) || error("echo of $(length(payload)) bytes came back as $(length(reply)) bytes")
        end
    end

    # ---- 1. per-message connections: the core contract ------------------------------------------------------------
    s = open_session("per-message", (;), Dict{String,Any}("persistent" => false))
    if s !== nothing
        report.features = copy(s.proxy.peer.features)
        try
            health = request_json(s, "PING")
            add!(report, "ping reply", is_health(health), detail(health))
        catch e
            add!(report, "ping reply", false, exception_text(e))
        end
        try
            reply = request_json(s, "NO_SUCH_METHOD_CONFORMANCE", Dict("x" => 1))
            ok = reply isa AbstractDict && get(reply, "status", nothing) == "error" && haskey(reply, "method") && haskey(reply, "error")
            add!(report, "unknown method answered with an error reply", ok, detail(reply))
        catch e
            add!(report, "unknown method answered with an error reply", false, exception_text(e))
        end
        if "set_log_level" in report.features
            try
                reply = request_json(s, "SET_LOG_LEVEL", Dict("level" => "DEBUG"))
                add!(report, "SET_LOG_LEVEL", reply isa AbstractDict && get(reply, "level", nothing) == "DEBUG", detail(reply))
                request_json(s, "SET_LOG_LEVEL", Dict("level" => "INFO"))
            catch e
                add!(report, "SET_LOG_LEVEL", false, exception_text(e))
            end
        else
            skip!(report, "SET_LOG_LEVEL", "not advertised")
        end
        if "log" in report.features
            # The proxy has had something to say since it registered (its switch to the socket, SET_LOG_LEVEL's
            # confirmation), so a batch must have been shipped by now or very soon.
            records = wait_for_records(s, "socket")
            if isempty(records)
                add!(report, "LOG batch over the socket", false,
                     "no record over the socket within $(LOG_BATCH_WAIT)s ($(length(by_channel(s, "stderr"))) by stderr)")
            else
                add!(report, "LOG batch over the socket", true, "$(length(records)) record(s), first: $(repr(records[1].message))")
            end
        else
            skip!(report, "LOG batch over the socket", "not advertised")
        end
        try
            raw = session_request(s, "PING"; protocol_version=1)
            health = isempty(raw) ? nothing : JSON3.read(raw, Any)
            add!(report, "header version 1 accepted", has_uptime(health), detail(health))
        catch e
            add!(report, "header version 1 accepted", false, exception_text(e))
        end
        if echo_method !== nothing
            try
                small = Vector{UInt8}(codeunits(JSON3.write(Dict("n" => 1, "text" => "héllo"))))
                large = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "x" ^ 65536))))       # above the compression threshold
                echo(s, small, large)
                via = "compress" in report.features ? "compressed on the wire" : "uncompressed (compress not advertised)"
                add!(report, "echo round trip, small and 64 KiB", true, via)
            catch e
                add!(report, "echo round trip, small and 64 KiB", false, exception_text(e))
            end
        else
            skip!(report, "echo round trip, small and 64 KiB", "no echo method given")
        end
        exit!(s, "clean exit on SIGTERM")
    end

    # ---- 2. persistent connection ---------------------------------------------------------------------------------
    s = open_session("persistent", (;), Dict{String,Any}("persistent" => true))
    if s !== nothing
        name = "persistent: five pings on one connection"
        try
            replies = [request_json(s, "PING") for _ in 1:5]
            ok = all(has_uptime, replies) && s.proxy.peer.connection !== nothing
            add!(report, name, ok, ok ? "connection held" : detail(replies[end]))
        catch e
            add!(report, name, false, exception_text(e))
        end
        if echo_method !== nothing
            try
                large = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "y" ^ 300000))))    # above persistent_max_frame
                echo(s, large)
                add!(report, "persistent: 300 KB frame takes its own connection", true, "")
            catch e
                add!(report, "persistent: 300 KB frame takes its own connection", false, exception_text(e))
            end
        end
        exit!(s, "persistent: clean exit on SIGTERM")
    end

    # ---- 3. encryption, each AEAD the proxy advertises --------------------------------------------------------------
    for (cipher, feature) in ((CIPHER_CHACHA, FEATURE_CHACHA), (CIPHER_AES_GCM, FEATURE_AES_GCM))
        name = "encrypted ($cipher)"
        if !(feature in report.features)
            skip!(report, name, "$feature not advertised")
            continue
        end
        s = open_session(name, (; encrypt=true, cipher), Dict{String,Any}("persistent" => true))
        s === nothing && continue
        try
            health = request_json(s, "PING")
            add!(report, "$name: ping", has_uptime(health) && s.proxy.peer.key !== nothing, detail(health))
            if echo_method !== nothing
                large = Vector{UInt8}(codeunits(JSON3.write(Dict("blob" => "z" ^ 65536))))
                try
                    echo(s, large)
                    add!(report, "$name: 64 KiB echo (compress then encrypt)", true, "")
                catch e
                    add!(report, "$name: 64 KiB echo (compress then encrypt)", false, exception_text(e))
                end
            end
        catch e
            add!(report, "$name: ping", false, exception_text(e))
        end
        exit!(s, "$name: clean exit")
    end

    # ---- 4. optional transports -----------------------------------------------------------------------------------
    if tls
        s = open_session("tls", (; ipc_tls=true), Dict{String,Any}("persistent" => true))
        if s !== nothing
            try
                health = request_json(s, "PING")
                add!(report, "tls: ping", has_uptime(health) && s.proxy.peer.tls, detail(health))
            catch e
                add!(report, "tls: ping", false, exception_text(e))
            end
            exit!(s, "tls: clean exit")
        end
    else
        skip!(report, "tls", "not requested (--tls)")
    end
    if manager_dials
        port = free_port()
        s = open_session("manager-dials", (;), Dict{String,Any}("manager_dials" => true, "inbound_address" => "127.0.0.1", "inbound_port" => port))
        if s !== nothing
            try
                health = request_json(s, "PING")
                add!(report, "manager-dials: ping over the manager-initiated connection", has_uptime(health), detail(health))
            catch e
                add!(report, "manager-dials: ping over the manager-initiated connection", false, exception_text(e))
            end
            exit!(s, "manager-dials: clean exit")
        end
    else
        skip!(report, "manager-dials", "not requested (--manager-dials)")
    end
    return report
end

function free_port()
    server = listen(ip"127.0.0.1", 0)
    port = Int(getsockname(server)[2])
    close(server)
    return port
end

# ---- command line ----------------------------------------------------------------------------------------------------

const CONFORMANCE_USAGE = "usage: conformance <manifest.toml | proxy name> [--echo METHOD] [--tls] [--manager-dials] " *
                          "[--option NAME=VALUE ...] [--timeout S] [--python PATH] [--log FILE] [--json] [-v]"

"""
    conformance_main(argv) -> exit code

Launch the proxy a manifest describes through the Julia manager and check it against PROTOCOL.md; exit 0 when every
check passes or is skipped.
"""
function conformance_main(argv::AbstractVector{<:AbstractString}=ARGS)
    target = nothing
    echo_method = nothing
    tls = manager_dials = as_json = verbose = false
    options = Dict{String,Any}()
    timeout = 20.0
    python = nothing
    log_file = nothing
    i = 1
    try
        while i <= length(argv)
            a = argv[i]
            value() = (i < length(argv) || throw(ArgumentError("$a needs a value")); i += 1; argv[i])
            if a == "--echo"
                echo_method = value()
            elseif a == "--tls"
                tls = true
            elseif a == "--manager-dials"
                manager_dials = true
            elseif a == "--option"
                item = value()
                occursin('=', item) || throw(ArgumentError("--option needs NAME=VALUE, got $(repr(item))"))
                k, v = split(item, '='; limit=2)
                options[String(k)] = String(v)
            elseif a == "--timeout"
                timeout = parse(Float64, value())
            elseif a == "--python"
                python = value()
            elseif a == "--log"
                log_file = value()
            elseif a == "--json"
                as_json = true
            elseif a in ("-v", "--verbose")
                verbose = true
            elseif a in ("-h", "--help")
                println(CONFORMANCE_USAGE)
                return 0
            elseif startswith(a, "-")
                throw(ArgumentError("unknown option $a"))
            elseif target === nothing
                target = a
            else
                throw(ArgumentError("one proxy at a time, got $(repr(target)) and $(repr(a))"))
            end
            i += 1
        end
        target === nothing && throw(ArgumentError("a manifest file or proxy name is required"))
    catch e
        println(stderr, CONFORMANCE_USAGE)
        println(stderr, sprint(showerror, e))
        return 2
    end
    stream = log_file === nothing ? stderr : open(log_file, "a")
    levelno = log_file !== nothing || verbose ? 10 : 30
    Logging.global_logger(ProxyLogger(; levelno, json=false, stream))
    manifest = try
        endswith(target, ".toml") || occursin('/', target) ? load_manifest(target) : find_manifest(target)
    catch e
        println(stderr, "conformance: ", sprint(showerror, e))
        return 2
    end
    report = run_conformance(manifest; launch_options=options, echo_method, tls, manager_dials, timeout, python)
    println(as_json ? report_json(report) : report_text(report))
    log_file === nothing || close(stream)
    return report_ok(report) ? 0 : 1
end
