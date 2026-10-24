# Entry point of the Julia echo proxy; run through bin/echo-proxy.
using ProtocolProxy
exit(ProtocolProxy.echo_main(ARGS))
