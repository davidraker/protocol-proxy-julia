# The command line of PROTOCOL.md §1: every option is `--name value`, booleans as true/false; unknown protocol
# options are accepted (and logged by the Proxy). `--self-test [vectors.json]` checks the wire vectors instead.

"""
    parse_args(argv) -> Dict{String,String}

`--name value` pairs keyed without the dashes. A `--flag` followed by another option or by nothing is `"true"`.
"""
function parse_args(argv::AbstractVector{<:AbstractString})
    options = Dict{String,String}()
    i = 1
    while i <= length(argv)
        arg = argv[i]
        if startswith(arg, "--")
            name = arg[3:end]
            if occursin('=', name)
                k, v = split(name, '='; limit=2)
                options[String(k)] = String(v)
                i += 1
            elseif i < length(argv) && !startswith(argv[i+1], "--")
                options[name] = String(argv[i+1])
                i += 2
            else
                options[name] = "true"
                i += 1
            end
        else
            throw(ArgumentError("unexpected argument $(repr(arg)); options are --name value"))
        end
    end
    return options
end

const SENSITIVE = ("password", "token", "secret", "credential")
redact(options::Dict{String,String}) = Dict(k => (any(occursin(s, lowercase(k)) for s in SENSITIVE) && !isempty(v) ? "***" : v)
                                            for (k, v) in options)

"""
    main(argv; setup=nothing, stdin=stdin) -> exit code

Run a proxy from the standard command line: parse options, install the logger, read the handshake, build the
`Proxy`, call `setup(proxy)` (which registers the protocol's handlers), then `run!`. With `--self-test` the wire
vectors are checked instead.
"""
function main(argv::AbstractVector{<:AbstractString}=ARGS; setup=nothing, input::IO=stdin)
    options = try
        parse_args(argv)
    catch e
        println(stderr, "usage: echo-proxy --proxy-id <hex> --proxy-name <str> --manager-id <hex> [--name value ...] | --self-test [vectors.json]")
        println(stderr, sprint(showerror, e))
        return 2
    end
    if haskey(options, "self-test")
        path = options["self-test"] == "true" ? default_vectors_path() : options["self-test"]
        return self_test(path; verbose=true) ? 0 : 1
    end
    level = get(options, "log-level", get(ENV, "PROTOCOL_PROXY_LOG_LEVEL", "INFO"))
    logger = install_logger!()
    try
        set_level!(logger, level)
    catch
        @warn "unknown --log-level $(repr(level)); using INFO"
    end
    @info "Launching proxy with parameters: $(redact(options))"
    proxy = try
        encrypt = str2bool(get(options, "encrypt", "false"))
        ipc_tls = str2bool(get(options, "ipc-tls", "false"))
        handshake = read_handshake(input; encrypt, ipc_tls)
        p = Proxy(options, handshake)
        setup === nothing || setup(p)
        p
    catch e
        @error "Proxy launch: cannot start" exception=(e, catch_backtrace())
        return 1
    end
    code = try
        run!(proxy)
    catch e
        e isa InterruptException && return 0
        @error "Proxy launch: proxy terminated with an unhandled exception" exception=(e, catch_backtrace())
        1
    end
    return code
end

default_vectors_path() = joinpath(dirname(@__DIR__), "test", "test_vectors.json")

"""ECHO: the payload comes straight back."""
handle_echo(c::Connector, h::Header, payload::Vector{UInt8}) = payload

"""Entry point of `bin/echo-proxy`: the core methods plus ECHO."""
function echo_main(argv::AbstractVector{<:AbstractString}=ARGS; input::IO=stdin)
    return main(argv; input, setup=p -> register_callback!(p.connector, handle_echo, "ECHO"; provides_response=true))
end
