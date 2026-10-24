# Entry point of the Julia conformance harness; run through bin/conformance.
using ProtocolProxy
exit(ProtocolProxy.conformance_main(ARGS))
