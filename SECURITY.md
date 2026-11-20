# Security policy

This SDK runs inside other people's production systems, so we would rather hear about a problem
early and loudly.

**Reporting**: email support@avowa.ai with "Security" in the subject, the version, what you observed, and how to reproduce it.
Please do not open a public issue for a vulnerability. We aim to acknowledge within 2 business days.

**In scope**: anything that makes the SDK send data it should not, break the host application,
block the request path, or misreport what was observed.

**Design constraints we hold ourselves to** (a break in any of these is a vulnerability):

- Signals carry **metadata only**: model id, host, region, latency, counts, hashed references, and what you record.
  Prompts, completions, tool arguments and user data never leave your process.
- Capture is **fire-and-forget**: a failure to send must never raise into the caller.
- The SDK records what it **observes**. It never upgrades an application's assertion into evidence.
