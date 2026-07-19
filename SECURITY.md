# Security model

The managed host is treated as potentially compromised. The central server is the control plane; each bridge is restricted to one host credential; GPT-5.6 is an investigator, not an approver. Bridges bind to loopback, read tools are bounded, logs are not instructions, and mutable operations require exact host/tool/argument binding, expiry, signature and single-use nonce validation.

ScreamSIEM is a Build Week MVP. SQLite is not tamper-proof, a compromised host can lie to user-space collectors, SSH polling can miss short-lived activity, GPT can be wrong, and model-generated manual commands require human review. Do not expose the dashboard without reverse-proxy authentication. Remote binding requires an explicit `SCREAMSIEM_ALLOW_UNAUTHENTICATED_REMOTE=1` override and should only be used behind an authenticated proxy.
