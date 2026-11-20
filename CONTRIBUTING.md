# Contributing

Issues and pull requests are welcome.

- **Bugs**: include the Python or Node version, the client library you instrument, and the
  `AVOWA_DEBUG=1` output (it prints what was patched and what was sent, never prompt content).
- **New provider wrappers**: the rule is that everything recorded must be *observed from the call
  path*. A wrapper may record what the SDK can see happen: the model id the provider returned, the
  host that answered, the latency. It may not record anything the application merely asserts about
  itself. If a value cannot be observed, leave it out rather than defaulting it.
- **No prompt or completion content** may be added to a signal, in any form, including truncated,
  hashed, or "just for debugging". The privacy boundary is the product.
- Keep the runtime dependency-free (standard library only) and keep failures silent: a compliance
  SDK must never break the request path it observes.

By contributing you agree your contribution is licensed under Apache-2.0, as in `LICENSE`.
