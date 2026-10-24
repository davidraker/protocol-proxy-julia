# Log records on stderr (PROTOCOL.md §9): one JSON object per line with the Python LogRecord attribute names when
# launched by a manager (`_LAUNCHED_BY_PROXY_MANAGER=1`), else readable text for a terminal.

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
end

launched_by_manager() = get(ENV, LAUNCHED_BY_MANAGER_ENV, "") != ""

ProxyLogger(; levelno::Integer=20, json::Bool=launched_by_manager(), stream::IO=stderr) =
    ProxyLogger(Int(levelno), json, stream, ReentrantLock())

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

function Logging.handle_message(l::ProxyLogger, level, message, _module, group, id, file, line; kwargs...)
    fields = record_fields(level, message, _module, file, line; kwargs...)
    lock(l.lock) do
        if l.json
            println(l.stream, JSON3.write(fields))
        else
            println(l.stream, fields["levelname"], " ", fields["name"], ": ", fields["msg"],
                    fields["exc_text"] === nothing ? "" : "\n" * fields["exc_text"])
        end
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
