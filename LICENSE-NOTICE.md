# License and usage notice

Copyright (c) 2026 the USF Adaptive Semantic Factory authors.

This repository is an internal operational tool built to advance the Universal
Service Foundation (USF) semantic programme. No open-source license is granted
by default; all rights reserved by the copyright holders unless a separate
written agreement states otherwise.

## Operational safety notice

This software orchestrates third-party AI providers and executes generated code
in isolated repositories. It is delivered in a **safe-by-default** configuration:

- No autonomous mutation of the USF repository or Stardog semantic authority.
- No billable model inference without an explicit budget flag.
- No source-code egress to external providers without an explicit flag.
- No publication to semantic authority (interface present, gate disabled).

The factory reads USF semantic state only through the read-only USF MCP
boundary. It never treats repository graph files as semantic authority and never
mutates the USF checkout used by the live programme.

Credentials are handled through `/root/.env` (root-owned, mode 0600) and are
never printed, logged, committed, or stored in the state database.

Third-party model providers are governed by their own terms. Sending repository
content to an external provider is a data-egress event; see
`config/data-egress-policy.yaml` and `docs/security.md`.
