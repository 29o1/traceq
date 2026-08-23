# Public benchmark traces

The checked-in logs were captured from an author-controlled Android test app
while tracing narrow Android libc operations with
[GumTrace](https://github.com/lidongyooo/GumTrace):

- `memcpy_device.log`: one large `memcpy` path, including the SIMD copy loop.
- `write_device.log`: a short `write` path used as a small-input boundary case.

They were reviewed to exclude third-party application code, payload dumps,
credentials, device identifiers, and application-specific strings. Runtime
addresses and register or memory values remain because they are required to
exercise traceq's real import and query path.

Third-party application traces are intentionally not published. To benchmark a
larger trace, pass a log you are authorized to use directly to
`python3 bench/run.py run`, or keep it under the ignored `bench/private/`
directory and pass that path explicitly.
