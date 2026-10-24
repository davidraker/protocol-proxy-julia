# SIGTERM (PROTOCOL.md §1): the manager stops a proxy with SIGTERM and expects exit code 0.
#
# Julia blocks SIGTERM on its threads and consumes it on a dedicated signal thread, where it is fatal (a backtrace
# and exit code 143), so neither a libuv signal watcher nor `signal(2)` alone sees it. Unblocking SIGTERM on the main
# thread and installing a sigaction handler there works: Linux delivers a process-directed signal to the main thread
# first when that thread does not block it. The handler only stores the signal number into pre-allocated memory; a
# Task polls that word.

const _SIGTERM = Cint(15)
const _SIGINT = Cint(2)
const _SIGNAL_FLAG = Ref{Ptr{Int64}}(C_NULL)

function _signal_handler(sig::Cint)
    p = _SIGNAL_FLAG[]
    p == C_NULL || unsafe_store!(p, Int64(sig))
    return nothing
end

"""Install the SIGTERM handler; returns false (and logs) where that is not possible (not Linux x86_64/aarch64)."""
function install_signal_handlers()
    Sys.islinux() || return false
    if _SIGNAL_FLAG[] == C_NULL
        p = Ptr{Int64}(Libc.malloc(8))
        unsafe_store!(p, 0)
        _SIGNAL_FLAG[] = p
    end
    handler = @cfunction(_signal_handler, Cvoid, (Cint,))
    # struct sigaction (glibc, x86_64 and aarch64): sa_handler (8), sa_mask (128), sa_flags (4 + 4 padding), sa_restorer (8).
    sa = zeros(UInt8, 152)
    GC.@preserve sa begin
        unsafe_store!(Ptr{Ptr{Cvoid}}(pointer(sa)), handler)
        unsafe_store!(Ptr{Cint}(pointer(sa) + 136), Cint(0x10000000))     # SA_RESTART
        rc = ccall(:sigaction, Cint, (Cint, Ptr{Cvoid}, Ptr{Cvoid}), _SIGTERM, pointer(sa), C_NULL)
    end
    rc == 0 || (@warn "sigaction(SIGTERM) failed: $(Libc.strerror(Libc.errno()))"; return false)
    set = zeros(UInt8, 128)
    ccall(:sigemptyset, Cint, (Ptr{Cvoid},), set)
    ccall(:sigaddset, Cint, (Ptr{Cvoid}, Cint), set, _SIGTERM)
    rc = ccall(:pthread_sigmask, Cint, (Cint, Ptr{Cvoid}, Ptr{Cvoid}), 1, set, C_NULL)      # SIG_UNBLOCK
    rc == 0 || (@warn "pthread_sigmask(SIG_UNBLOCK, SIGTERM) failed ($rc)"; return false)
    return true
end

"""The signal number received, or 0."""
signal_received() = _SIGNAL_FLAG[] == C_NULL ? 0 : Int(unsafe_load(_SIGNAL_FLAG[]))

parent_pid() = Int(ccall(:getppid, Cint, ()))
