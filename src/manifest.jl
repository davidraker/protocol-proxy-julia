# Proxy manifests (PROTOCOL.md §1a): everything a manager needs to launch and key a proxy, as data. A proxy ships a
# `proxy.toml` beside its binary; a manager in any language reads it to learn the command that starts the proxy, which
# launch options identify one process, and which options remotes sharing a process must agree on. Nothing in a
# manifest is executable: identity values may only be normalised by the fixed set of normalisers plus a default.
#
#     [proxy]
#     name = "mqtt"
#     command = ["{python}", "-m", "protocol_proxy.proxy", "--gevent", "protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy"]
#     header_version = 2
#
#     [identity]
#     keys = ["host", "port"]
#     must_match = ["username", "password"]
#
#     [identity.normalize]
#     host = ["strip", "lowercase"]
#     port = [{ default = 1883 }]
#
#     [environment]
#     MQTT_LOG = "info"
#
#     [self_test]
#     command = ["{manifest_dir}/bin/mqtt-proxy", "--self-test"]
#
# Discovery (`search_path`) is the §1a list: PROTOCOL_PROXY_MANIFESTS, the user's configuration directory, this
# installation's share directory (`prefix_directory`), then the system's configuration and data directories.

using TOML

const MANIFEST_FILENAME = "proxy.toml"
const ENV_MANIFEST_PATH = "PROTOCOL_PROXY_MANIFESTS"
const ENV_PREFIX = "PROTOCOL_PROXY_PREFIX"
const MANIFEST_SUBDIR = joinpath("protocol-proxy", "manifests")
#: Placeholders a command may use; the manager resolves them at launch.
const PLACEHOLDERS = ("manifest_dir", "python")
#: The identity normalisers a manifest may name. `default` is a table, `{ default = <value> }`, not a name.
const NORMALISERS = ("lowercase", "strip")
const PLACEHOLDER_PATTERN = r"\{([a-z_]+)\}"
const NAME_PATTERN = r"^[A-Za-z0-9_.-]+$"

"""A manifest that cannot be used: malformed, missing a required field, or asking for something not allowed."""
struct ManifestError <: Exception
    msg::String
end
Base.showerror(io::IO, e::ManifestError) = print(io, "ManifestError: ", e.msg)

"""One normalisation step: a normaliser name (`lowercase`, `strip`) or a default value."""
struct Step
    name::String
    default::Any
    has_default::Bool
end
Step(name::AbstractString) = Step(String(name), nothing, false)
Step(; default) = Step("default", default, true)

"""How launch options select a proxy process and what remotes sharing one must agree on."""
struct Identity
    keys::Vector{String}
    must_match::Vector{String}
    normalize::Dict{String,Vector{Step}}
end
Identity(; keys=String[], must_match=String[], normalize=Dict{String,Vector{Step}}()) =
    Identity(Vector{String}(keys), Vector{String}(must_match), Dict{String,Vector{Step}}(normalize))

"""`value` of option `key` after the manifest's normalisers for it (a missing value takes the default)."""
function normalized(id::Identity, key::AbstractString, value)
    for step in get(id.normalize, String(key), Step[])
        if step.has_default
            value === nothing && (value = step.default)
        elseif value isa AbstractString
            value = step.name == "lowercase" ? lowercase(value) : step.name == "strip" ? strip(value) : value
            value = String(value)
        end
    end
    return value
end

"""
The process key: the proxy name and the normalised identity options when the manifest names `keys`, else the caller's
`unique_remote_id` as given (every device shares a process unless the caller groups).
"""
function process_key(id::Identity, name::AbstractString, unique_remote_id::Tuple, options::AbstractDict)
    isempty(id.keys) && return unique_remote_id
    return (String(name), (normalized(id, k, get(options, k, nothing)) for k in id.keys)...)
end

"""The `must_match` options on which `options` differs from the `first` remote of a shared process."""
conflicts(id::Identity, first::AbstractDict, options::AbstractDict) =
    [k for k in id.must_match if string(normalized(id, k, get(first, k, nothing))) != string(normalized(id, k, get(options, k, nothing)))]

"""One proxy's manifest."""
struct Manifest
    name::String
    command::Vector{String}
    identity::Identity
    environment::Dict{String,String}
    self_test::Union{Nothing,Vector{String}}
    header_version::Int
    #: the file it was read from, nothing for one built in memory
    source::Union{Nothing,String}
end

Manifest(name::AbstractString, command::AbstractVector{<:AbstractString}; identity::Identity=Identity(),
         environment=Dict{String,String}(), self_test=nothing, header_version::Integer=2, source=nothing) =
    Manifest(String(name), Vector{String}(command), identity, Dict{String,String}(environment),
             self_test === nothing ? nothing : Vector{String}(self_test), Int(header_version),
             source === nothing ? nothing : String(source))

"""Read a manifest from TOML text; `source` names it in errors and resolves `{manifest_dir}`."""
function parse_manifest(text::AbstractString; source=nothing)
    data = try
        TOML.parse(String(text))
    catch e
        throw(ManifestError("$(where(source)): not valid TOML: $(sprint(showerror, e))"))
    end
    return manifest_from_dict(data, source)
end

"""Read a manifest file."""
load_manifest(path::AbstractString) = parse_manifest(read(path, String); source=abspath(path))

where(source) = source === nothing ? "manifest" : string(source)

"""Validate decoded TOML data exactly as the Python reference does."""
function manifest_from_dict(data::AbstractDict, source=nothing)
    w = where(source)
    only_keys(data, ["proxy", "identity", "environment", "self_test"], w)
    proxy = table(data, "proxy", w; required=true)
    only_keys(proxy, ["name", "command", "header_version"], "$w [proxy]")
    name = get(proxy, "name", nothing)
    (name isa AbstractString && occursin(NAME_PATTERN, name)) ||
        throw(ManifestError("$w [proxy]: name must be a short identifier, got $(repr(name))"))
    command = command_list(get(proxy, "command", nothing), "$w [proxy] command")
    header_version = get(proxy, "header_version", 2)
    (header_version isa Integer && header_version in (1, 2)) ||
        throw(ManifestError("$w [proxy]: header_version must be 1 or 2, got $(repr(header_version))"))
    identity = parse_identity(table(data, "identity", w), "$w [identity]")
    env_table = table(data, "environment", w)
    environment = Dict{String,String}()
    for (k, v) in env_table
        v isa AbstractString || throw(ManifestError("$w [environment]: values must be strings"))
        check_placeholders(v, "$w [environment] $k")
        environment[String(k)] = String(v)
    end
    self_test_table = table(data, "self_test", w)
    self_test = nothing
    if !isempty(self_test_table)
        only_keys(self_test_table, ["command"], "$w [self_test]")
        self_test = command_list(get(self_test_table, "command", nothing), "$w [self_test] command")
    end
    return Manifest(String(name), command; identity, environment, self_test, header_version=Int(header_version),
                    source=source === nothing ? nothing : string(source))
end

"""The manifest's directory (`{manifest_dir}`), "" for one built in memory."""
manifest_dir(m::Manifest) = m.source === nothing ? "" : dirname(m.source)

"""Substitute the placeholders of one command part."""
function resolve_placeholders(m::Manifest, part::AbstractString, python::AbstractString)
    return replace(String(part), "{python}" => python, "{manifest_dir}" => manifest_dir(m))
end

"""
The argv to start the proxy: the manifest's command with placeholders resolved, then the manager's standard options
(`--proxy-id` and the rest).
"""
launch_command(m::Manifest, python::AbstractString, standard_options::AbstractVector{<:AbstractString}=String[]) =
    vcat([resolve_placeholders(m, part, python) for part in m.command], Vector{String}(standard_options))

"""
The `[environment]` table with its placeholders resolved (§1a: `{manifest_dir}` and `{python}` as in `command`), ready
to be added to the process environment.
"""
resolve_environment(m::Manifest, python::AbstractString) =
    Dict{String,String}(k => resolve_placeholders(m, v, python) for (k, v) in m.environment)

"""The argv of the self test with placeholders resolved, nothing when there is none."""
self_test_command(m::Manifest, python::AbstractString) =
    m.self_test === nothing ? nothing : [resolve_placeholders(m, part, python) for part in m.self_test]

process_key(m::Manifest, unique_remote_id::Tuple, options::AbstractDict) = process_key(m.identity, m.name, unique_remote_id, options)

# ---- Python rendering ------------------------------------------------------------------------------------------------

"""
A process key as Python's repr of a tuple would render it (`('mqtt', 'broker', 1883)`): the proxy name a Python
manager would give the same process, so logs read alike across managers.
"""
function py_tuple(key::Tuple)
    parts = [py_repr(item) for item in key]
    length(parts) == 1 && return "(" * parts[1] * ",)"
    return "(" * join(parts, ", ") * ")"
end

function py_repr(value)
    value === nothing && return "None"
    value isa Bool && return value ? "True" : "False"
    if value isa AbstractString
        s = String(value)
        occursin('\'', s) && !occursin('"', s) && return "\"" * s * "\""
        return "'" * replace(s, "'" => "\\'") * "'"
    end
    value isa Integer && return string(value)
    if value isa AbstractFloat
        return isinteger(value) && abs(value) < 1e16 ? string(Int(value)) * ".0" : string(value)
    end
    return string(value)
end

# ---- discovery -------------------------------------------------------------------------------------------------------

"""
Where this installation keeps manifests: `<prefix>/share/protocol-proxy/manifests`. The prefix is `PROTOCOL_PROXY_PREFIX`
when set, else the directory of the active project (`julia --project=<dir>`: the port's own checkout, so its
`share/protocol-proxy/manifests` is found), else the directory above Julia's `bin` (`Sys.BINDIR`), the Julia
counterpart of a Python environment's `sys.prefix`.
"""
function prefix_directory()
    prefix = get(ENV, ENV_PREFIX, "")
    if isempty(prefix)
        project = Base.active_project()
        prefix = project === nothing ? dirname(Sys.BINDIR) : dirname(project)
    end
    return joinpath(prefix, "share", MANIFEST_SUBDIR)
end

split_path(value::AbstractString) = [p for p in split(value, Sys.iswindows() ? ';' : ':') if !isempty(p)]

"""
The directories searched for manifests, most specific first: `PROTOCOL_PROXY_MANIFESTS` (prepended rather than
replacing the rest), the user's configuration directory (`XDG_CONFIG_HOME` or `~/.config`), this installation's share
directory, then the system's configuration and data directories (`XDG_CONFIG_DIRS` or `/etc`; `XDG_DATA_DIRS` or
`/usr/local/share:/usr/share`). Duplicates are dropped.
"""
function search_path()
    dirs = String[]
    for p in split_path(get(ENV, ENV_MANIFEST_PATH, ""))
        push!(dirs, expanduser(String(p)))
    end
    config_home = get(ENV, "XDG_CONFIG_HOME", "")
    isempty(config_home) && (config_home = joinpath(homedir(), ".config"))
    push!(dirs, joinpath(config_home, MANIFEST_SUBDIR))
    push!(dirs, prefix_directory())
    config_dirs = get(ENV, "XDG_CONFIG_DIRS", "")
    isempty(config_dirs) && (config_dirs = "/etc")
    append!(dirs, [joinpath(String(p), MANIFEST_SUBDIR) for p in split_path(config_dirs)])
    data_dirs = get(ENV, "XDG_DATA_DIRS", "")
    isempty(data_dirs) && (data_dirs = "/usr/local/share:/usr/share")
    append!(dirs, [joinpath(String(p), MANIFEST_SUBDIR) for p in split_path(data_dirs)])
    return unique(dirs)
end

"""
Where the manifest for `name` is: `<dir>/<name>.toml` or `<dir>/<name>/proxy.toml` in the search path, first match
wins. Throws a `ManifestError` naming every place looked.
"""
function locate_manifest(name::AbstractString)
    looked = String[]
    for dir in search_path()
        for candidate in (joinpath(dir, "$name.toml"), joinpath(dir, String(name), MANIFEST_FILENAME))
            push!(looked, candidate)
            isfile(candidate) && return candidate
        end
    end
    throw(ManifestError("No manifest for proxy $(repr(name)); looked at: $(join(looked, ", "))"))
end

"""Load the manifest for `name`."""
find_manifest(name::AbstractString) = load_manifest(locate_manifest(name))

"""Every manifest reachable through the search path, by proxy name (the first found wins)."""
function discover_manifests()
    found = Dict{String,Manifest}()
    for dir in search_path()
        isdir(dir) || continue
        paths = String[]
        for entry in sort(readdir(dir))
            path = joinpath(dir, entry)
            if isfile(path) && endswith(entry, ".toml")
                push!(paths, path)
            elseif isdir(path) && isfile(joinpath(path, MANIFEST_FILENAME))
                push!(paths, joinpath(path, MANIFEST_FILENAME))
            end
        end
        for path in paths
            m = try
                load_manifest(path)
            catch e
                e isa ManifestError || rethrow()
                @warn "skipping $path: $(e.msg)"
                continue
            end
            haskey(found, m.name) || (found[m.name] = m)
        end
    end
    return found
end

# ---- validation helpers ----------------------------------------------------------------------------------------------

function only_keys(t::AbstractDict, allowed::Vector{String}, w::AbstractString)
    unknown = sort([String(k) for k in keys(t) if !(String(k) in allowed)])
    isempty(unknown) || throw(ManifestError("$w: unknown keys $unknown; allowed: $(sort(allowed))"))
    return
end

function table(data::AbstractDict, key::AbstractString, w::AbstractString; required::Bool=false)
    v = get(data, key, nothing)
    if v === nothing
        required && throw(ManifestError("$w: the [$key] table is required"))
        return Dict{String,Any}()
    end
    v isa AbstractDict || throw(ManifestError("$w: [$key] must be a table"))
    return v
end

"""Every `{name}` in `text` must be a known placeholder (commands and environment values alike)."""
function check_placeholders(text::AbstractString, w::AbstractString)
    for m in eachmatch(PLACEHOLDER_PATTERN, text)
        m.captures[1] in PLACEHOLDERS ||
            throw(ManifestError("$w: unknown placeholder {$(m.captures[1])}; allowed: $(collect(PLACEHOLDERS))"))
    end
    return
end

function command_list(value, w::AbstractString)
    (value isa AbstractVector && !isempty(value) && all(p -> p isa AbstractString && !isempty(p), value)) ||
        throw(ManifestError("$w: must be a non-empty list of strings"))
    foreach(part -> check_placeholders(part, w), value)
    return [String(p) for p in value]
end

function names(value, w::AbstractString)
    value === nothing && return String[]
    (value isa AbstractVector && all(v -> v isa AbstractString && !isempty(v), value)) ||
        throw(ManifestError("$w: must be a list of option names"))
    return [String(v) for v in value]
end

function parse_identity(t::AbstractDict, w::AbstractString)
    only_keys(t, ["keys", "must_match", "normalize"], w)
    keys_ = names(get(t, "keys", nothing), "$w keys")
    must_match = names(get(t, "must_match", nothing), "$w must_match")
    known = Set(vcat(keys_, must_match))
    normalize = Dict{String,Vector{Step}}()
    raw_normalize = get(t, "normalize", nothing)
    raw_normalize === nothing || raw_normalize isa AbstractDict || throw(ManifestError("$w.normalize must be a table"))
    for (key, steps) in (raw_normalize === nothing ? Dict{String,Any}() : raw_normalize)
        String(key) in known || throw(ManifestError("$w.normalize: $(repr(key)) is not in keys or must_match"))
        steps isa AbstractVector || throw(ManifestError("$w.normalize: $key must be a list of steps"))
        checked = Step[]
        for step in steps
            if step isa AbstractString
                step in NORMALISERS || throw(ManifestError("$w.normalize: unknown normaliser $(repr(step)) for $key; allowed: $(collect(NORMALISERS)) or { default = <value> }"))
                push!(checked, Step(step))
            elseif step isa AbstractDict && collect(keys(step)) == ["default"]
                push!(checked, Step(; default=step["default"]))
            else
                throw(ManifestError("$w.normalize: a step is a normaliser name or { default = <value> }, got $(repr(step))"))
            end
        end
        normalize[String(key)] = checked
    end
    return Identity(; keys=keys_, must_match, normalize)
end
