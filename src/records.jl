# A launched proxy's log records as the manager handles them (PROTOCOL.md §9, §11b): JSON LogRecord lines read from
# its stderr (and stdout), plain lines at the stream's default level or the level of a `<N>` syslog prefix, and the
# entries of `LOG` batches received over the socket. Each becomes a `Record` for the manager-side logger
# `protocol_proxy.proxies.<manifest name>.<proxy name>`.

const PROXIES_LOGGER = "protocol_proxy.proxies"

#: Default level of a plain (non-JSON) line, by the stream it arrived on.
const STREAM_DEFAULT_LEVELS = Dict("stdout" => 20, "stderr" => 30)
#: A plain line may start with a syslog-style severity, `<7>` (debug) to `<0>` (emergency), which sets its level.
const SYSLOG_LEVELS = Dict('7' => 10, '6' => 20, '5' => 20, '4' => 30, '3' => 40, '2' => 50, '1' => 50, '0' => 50)

"""
The manager-side logger for one launched proxy, the proxy name reduced to logger-safe characters (dots would create
further hierarchy): `protocol_proxy.proxies.<manifest>.<safe name>`.
"""
function proxy_logger_name(manifest_name::AbstractString, proxy_name::AbstractString)
    parts = filter(!isempty, split(String(proxy_name), r"[^A-Za-z0-9\-]+"))
    safe = isempty(parts) ? "proxy" : join(parts, "_")
    return "$PROXIES_LOGGER.$manifest_name.$safe"
end

"""
One log record from a launched proxy, as the manager handles it: rebuilt from a JSON line on a pipe, an entry of a
`LOG` batch, or a plain line. `logger` is the manager-side logger name, `remote_name` the proxy's own logger name (or
the stream a plain line came from), `channel` where it arrived (`stdout`, `stderr` or `socket`), `levelno` the Python
level number, `fields` the wire fields of a JSON record (nothing for a plain line).
"""
struct Record
    logger::String
    remote_name::String
    channel::String
    levelno::Int
    message::String
    exc_text::Union{Nothing,String}
    fields::Union{Nothing,Dict{String,Any}}
    proxy::String
    pid::Int
end

level_name(r::Record) = python_level_name(r.levelno)

function levelno_of(value)
    value isa Integer && return Int(value)
    value isa AbstractFloat && return round(Int, value)
    if value isa AbstractString
        n = get(PYTHON_LEVELS, uppercase(strip(value)), nothing)
        n === nothing || return n
        parsed = tryparse(Int, strip(value))
        parsed === nothing || return parsed
    end
    return nothing
end

"""
Rebuild a record from its wire fields (a JSON line or one entry of a LOG batch), attributed to `logger_name` with the
sender's own logger name in `remote_name` and the channel it arrived by in `channel`.
"""
function record_from_fields(fields::AbstractDict, logger_name::AbstractString, channel::AbstractString, pid::Integer,
                            proxy_name::AbstractString)
    f = Dict{String,Any}(String(k) => v for (k, v) in fields)
    remote = get(f, "name", nothing)
    msg = get(f, "msg", nothing)
    exc = get(f, "exc_text", nothing)
    levelno = something(levelno_of(get(f, "levelno", nothing)), levelno_of(get(f, "levelname", nothing)), 20)
    process = levelno_of(get(f, "process", nothing))
    return Record(String(logger_name), remote isa AbstractString ? String(remote) : "", String(channel), levelno,
                  msg === nothing ? "" : string(msg), exc isa AbstractString ? String(exc) : nothing, f, String(proxy_name),
                  process === nothing || process == 0 ? Int(pid) : process)
end

"""
Turn one line read from a proxy's stdout or stderr into a `Record` for `logger_name`. A JSON object with a `msg` field
is rebuilt from its fields; a plain line becomes a record at the stream's default level (stderr WARNING, stdout INFO)
or at the level a leading `<N>` syslog prefix names, with `remote_name` set to the stream. Nothing for an empty line.
"""
function record_from_line(raw::AbstractString, logger_name::AbstractString, stream::AbstractString, pid::Integer,
                          proxy_name::AbstractString)
    line = rstrip(String(raw), ['\r', '\n'])
    isempty(strip(line)) && return nothing
    if startswith(line, "{") && endswith(line, "}")
        fields = try
            JSON3.read(line, Dict{String,Any})
        catch
            nothing
        end
        if fields isa Dict && haskey(fields, "msg")
            return record_from_fields(fields, logger_name, stream, pid, proxy_name)
        end
    end
    levelno = get(STREAM_DEFAULT_LEVELS, String(stream), 30)
    if length(line) > 2 && line[1] == '<' && line[3] == '>' && haskey(SYSLOG_LEVELS, line[2])
        levelno = SYSLOG_LEVELS[line[2]]
        line = line[4:end]
    end
    return Record(String(logger_name), String(stream), String(stream), levelno, line, nothing, nothing, String(proxy_name), Int(pid))
end

"""
The records of one `LOG` batch (`{"records": [...], "dropped": n}`, channel `socket`); a dropped count becomes one
WARNING at the end, as the Python manager logs it. Throws on an undecodable payload.
"""
function records_from_batch(payload::AbstractVector{UInt8}, logger_name::AbstractString, pid::Integer, proxy_name::AbstractString)
    batch = JSON3.read(payload, Dict{String,Any})
    records = Record[]
    for fields in get(batch, "records", Any[])
        fields isa AbstractDict || continue
        push!(records, record_from_fields(fields, logger_name, "socket", pid, proxy_name))
    end
    dropped = levelno_of(get(batch, "dropped", 0))
    if dropped !== nothing && dropped > 0
        push!(records, Record(String(logger_name), "protocol_proxy.logs", "socket", 30,
                              "$proxy_name dropped $dropped log records (rate or queue limit).", nothing, nothing,
                              String(proxy_name), Int(pid)))
    end
    return records
end

"""
The default record handler: the record goes through Julia's global logger at its level, under the manager-side logger
name (a `ProxyLogger` writes it as `name`; other loggers show it as a keyword), the proxy's own logger name in front
of the message for a reader.
"""
function log_record(r::Record)
    msg = isempty(r.remote_name) || r.remote_name == r.channel ? r.message : "[$(r.remote_name)] $(r.message)"
    r.exc_text === nothing || (msg *= "\n" * r.exc_text)
    Logging.@logmsg julia_level(r.levelno) msg _module=nothing _file=r.channel _line=0 _group=:proxies _id=Symbol(r.logger) name=r.logger
    return
end
