# Security Policy

Pipelock Agent Egress Control is a downstream consumer of the [Pipelock](https://github.com/pipelab-org/pipelock) project. Its security posture is governed by the same disclosure process and response SLA.

## Reporting a vulnerability

Use the upstream Pipelock advisory channel rather than this repository:

- [Pipelock Security Advisories](https://github.com/pipelab-org/pipelock/security/advisories/new)

When the report is specific to this action (the wrapper around Pipelock, not the Pipelock binary itself), say so in the advisory body and include:

- The version of this action involved (commit SHA preferred over tag).
- The version of the Pipelock binary that was pinned at runtime.
- The runner OS and image version.
- Steps to reproduce.

## Supported versions

The action ships in lockstep with the Pipelock binaries it wraps. Only the latest tagged release of this action is supported. Pin by full-length commit SHA in your workflow for the only form of pinning git treats as immutable.

## Response SLA and CVE process

Both follow the upstream [Pipelock SECURITY.md](https://github.com/pipelab-org/pipelock/blob/main/SECURITY.md) and [coordinated disclosure policy](https://github.com/pipelab-org/pipelock/blob/main/docs/security/coordinated-disclosure.md).

## What this action does not prove

Read [`docs/security/audit-packet-threat-model.md`](https://github.com/pipelab-org/pipelock/blob/main/docs/security/audit-packet-threat-model.md) before treating a verified Audit Packet as provenance. The trust assumptions (signer key pinned outside the runner, verifier run outside the runner, binary pinned by checksum, action pinned by full SHA, workflow scoped so the wrapped script is the sole secret-bearing step) are not assumptions this action enforces; they are assumptions the relying party must verify.
