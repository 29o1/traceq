# Security Policy

## Reporting a vulnerability

Prefer GitHub private vulnerability reporting when it is available. Otherwise,
open an issue asking for a private contact channel, without including exploit
details or sensitive trace data in the public issue.

Relevant reports include memory-safety bugs in GTSW or GTSC parsing,
resource-exhaustion paths that bypass documented limits, and unsafe handling of
output paths. Please include a minimal, non-sensitive reproducer when possible.

## Trace metadata limits

Profile 2 capture and replay share a per-trace limit of 1,048,576 module and
instruction-site metadata fragments across all blocks. Each fragment contains
up to 24 bytes of name or disassembly text. Repeated execution of a recorded
site uses no additional fragments. Capture reports failure if it exceeds this
limit, and queries reject over-limit files with `TRACE_ERROR`.

## Responsible use

Only capture or analyze devices, processes, binaries, and trace data that you
own or are authorized to inspect. Trace files can contain runtime addresses,
register and memory values, call arguments, and application data; review them
before attaching them to a public issue.
