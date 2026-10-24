# Log records (PROTOCOL.md §9, §11a): one JSON object per line on stderr with the Python LogRecord attribute names
# when launched by a manager (`_LAUNCHED_BY_PROXY_MANAGER=1`), else readable text for a terminal. After registration
# a proxy launched with stderr a pipe switches the logger to a bounded, rate-limited `LogQueue`, which the proxy ships
# in `LOG` batches over the socket (see `start_socket_logging!` in proxy.jl); at exit the queue is drained to stderr.

const LAUNCHED_BY_MANAGER_ENV = "_LAUNCHED_BY_PROXY_MANAGER"

const Critical = Logging.LogLevel(3000)

#: Python levelno for a Julia log level.
function python_levelno(level::Logging.LogLevel)
    level >= Critical && return 50
    level >= Logging.Error && return 40
    level >= Logging.Warn && return 30
    level >= Logging.Info && return 20
    return 10
end

const PYTHON_LEVEL_NAMES = Dict(10 => "DEBUG", 20 => "INFO", 30 => "WARNING", 40 => "ERROR", 50 => "CRITICAL")
const PYTHON_LEVELS = Dict("DEBUG" => 10, "INFO" => 20, "WARNING" => 30, "WARN" => 30, "ERROR" => 40,
                           "CRITICAL" => 50, "FATAL" => 50, "NOTSET" => 0)

python_level_name(levelno::Integer) = get(PYTHON_LEVEL_NAMES, levelno, "Level $levelno")

function julia_level(levelno::Integer)
    levelno >= 50 && return Critical
    levelno >= 40 && return Logging.Error
    levelno >= 30 && return Logging.Warn
    levelno >= 20 && return Logging.Info
    return Logging.Debug
end

"""
    LogQueue(; max_len=2000, rate=50.0, burst=200)

Records waiting to be shipped in `LOG` batches (§9, §11a). `emit!` never blocks and never does I/O: the queue is
bounded and token-bucket rate-limited (`rate` records per second sustained, `burst` at once); records beyond either
limit are dropped and counted, and the count travels in the next batch as `dropped`.
"""
mutable struct LogQueue
    records::Vector{Dict{String,Any}}
    max_len::Int
    rate::Float64
    burst::Int
    tokens::Float64
    refilled::Float64
    dropped::Int
    total_dropped::Int
    lock::ReentrantLock
end

LogQueue(; max_len::Integer=2000, rate::Real=50.0, burst::Integer=200) =
    LogQueue(Dict{String,Any}[], Int(max_len), Float64(rate), Int(burst), Float64(burst), time(), 0, 0, ReentrantLock())

function take_token!(q::LogQueue)
    now = time()
    q.tokens = min(Float64(q.burst), q.tokens + (now - q.refilled) * q.rate)
    q.refilled = now
    q.tokens >= 1 || return false
    q.tokens -= 1
    return true
end

"""Queue a record, or count it as dropped. Returns whether it was queued."""
function emit!(q::LogQueue, fields::Dict{String,Any})
    lock(q.lock) do
        if length(q.records) >= q.max_len || !take_token!(q)
            q.dropped += 1
            q.total_dropped += 1
            return false
        end
        push!(q.records, fields)
        return true
    end
end

Base.length(q::LogQueue) = lock(() -> length(q.records), q.lock)
Base.isempty(q::LogQueue) = length(q) == 0

"""
    drain!(q, limit=0) -> (records, dropped)

Take up to `limit` queued records (all when `limit <= 0`) and the count dropped since the last drain.
"""
function drain!(q::LogQueue, limit::Integer=0)
    lock(q.lock) do
        n = limit > 0 ? min(Int(limit), length(q.records)) : length(q.records)
        taken = q.records[1:n]
        deleteat!(q.records, 1:n)
        dropped = q.dropped
        q.dropped = 0
        return taken, dropped
    end
end

"""The payload of a `LOG` message: `{"records": [...], "dropped": n}`."""
batch_payload(records::AbstractVector, dropped::Integer) =
    Vector{UInt8}(codeunits(JSON3.write(Dict{String,Any}("records" => records, "dropped" => Int(dropped)))))

"""
    ProxyLogger(; levelno=20, json=launched_by_manager(), stream=stderr)

The process logger: JSON lines (`name`, `levelno`, `levelname`, `pathname`, `lineno`, `funcName`, `created`,
`msecs`, `process`, `msg`, `exc_text`) or readable text. The level is a Python levelno and can be changed at run
time (`SET_LOG_LEVEL`).
"""
mutable struct ProxyLogger <: Logging.AbstractLogger
    levelno::Int
    json::Bool
    stream::IO
    lock::ReentrantLock
    #: the LOG queue while records travel over the socket, else nothing (records go to `stream`)
    queue::Union{Nothing,LogQueue}
end

launched_by_manager() = get(ENV, LAUNCHED_BY_MANAGER_ENV, "") != ""

"""Whether this process should use the JSON channel toward a manager: launched by one, with stderr a pipe."""
function stderr_is_pipe()
    io = stderr
    while io isa IOContext            # `julia --color=no` wraps the standard streams
        io = io.io
    end
    return io isa Base.PipeEndpoint
end
use_json_channel() = launched_by_manager() && stderr_is_pipe()

ProxyLogger(; levelno::Integer=20, json::Bool=launched_by_manager(), stream::IO=stderr) =
    ProxyLogger(Int(levelno), json, stream, ReentrantLock(), nothing)

Logging.min_enabled_level(l::ProxyLogger) = julia_level(l.levelno)
Logging.shouldlog(l::ProxyLogger, level, _module, group, id) = python_levelno(level) >= l.levelno
Logging.catch_exceptions(::ProxyLogger) = true

function record_fields(level, message, _module, file, line; kwargs...)
    now = time()
    levelno = python_levelno(level)
    fields = Dict{String,Any}(
        "name" => "protocol_proxy.julia." * lowercase(string(something(_module, "main"))),
        "levelno" => levelno,
        "levelname" => python_level_name(levelno),
        "pathname" => string(something(file, "")),
        "lineno" => line === nothing ? 0 : Int(line),
        "funcName" => "",
        "created" => now,
        "msecs" => round((now - floor(now)) * 1000; digits=3),
        "process" => getpid(),
        "msg" => string(message),
        "exc_text" => nothing,
    )
    for (k, v) in kwargs
        if k === :exception
            fields["exc_text"] = format_exception(v)
        else
            fields[string(k)] = v isa Union{Number,AbstractString,Bool,Nothing} ? v : repr(v)
        end
    end
    return fields
end

function format_exception(v)
    io = IOBuffer()
    if v isa Tuple && length(v) == 2
        showerror(io, v[1], v[2])
    elseif v isa Exception
        showerror(io, v)
    else
        print(io, v)
    end
    return String(take!(io))
end

"""One record as a JSON line on `io` (what a manager reads from stderr)."""
function write_json_line(io::IO, fields::AbstractDict)
    println(io, JSON3.write(fields))
    return
end

function Logging.handle_message(l::ProxyLogger, level, message, _module, group, id, file, line; kwargs...)
    fields = record_fields(level, message, _module, file, line; kwargs...)
    queue = l.queue
    if queue !== nothing
        emit!(queue, fields)
        return nothing
    end
    # One write per record, so lines from several Tasks (and from a manager's proxies on the same fd) do not interleave.
    line = l.json ? JSON3.write(fields) * "\n" :
        string(fields["levelname"], " ", fields["name"], ": ", fields["msg"],
               fields["exc_text"] === nothing ? "" : "\n" * fields["exc_text"], "\n")
    lock(l.lock) do
        write(l.stream, line)
        flush(l.stream)
    end
    return nothing
end

"""Set the logger's level from a Python level name (`DEBUG`, `INFO`, ...) or number; returns the level name in force."""
function set_level!(l::ProxyLogger, level)
    if level isa AbstractString
        n = get(PYTHON_LEVELS, uppercase(strip(level)), nothing)
        if n === nothing
            n = tryparse(Int, strip(level))
            n === nothing && throw(ArgumentError("Unknown level: $(repr(level))"))
        end
        l.levelno = n
    elseif level isa Integer
        l.levelno = Int(level)
    else
        throw(ArgumentError("Level not an integer or a valid string: $(repr(level))"))
    end
    return python_level_name(l.levelno)
end

current_level_name(l::ProxyLogger) = python_level_name(l.levelno)

"""The process-wide ProxyLogger, if `install_logger!` ran."""
const PROXY_LOGGER = Ref{Union{Nothing,ProxyLogger}}(nothing)

function install_logger!(; levelno::Integer=20, json::Bool=launched_by_manager())
    logger = ProxyLogger(; levelno, json)
    PROXY_LOGGER[] = logger
    Logging.global_logger(logger)
    return logger
end
