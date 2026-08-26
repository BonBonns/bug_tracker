# Provenance Contract

The portable layer tracks value movement through assignments, arguments/parameters,
returns, expressions, state, aliases, and closures. The canonical Java implementation
in this package is the Gate-23 `PHPCGFactory.java`, which cumulatively contains the
frontend-call bridge, state return bridge, MAY/UNKNOWN return channel, and lexical
closure return bridge.
