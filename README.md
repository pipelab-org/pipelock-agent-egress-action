# Pipelock Agent Egress Action

[![CI](https://github.com/pipelab-org/pipelock-agent-egress-action/actions/workflows/ci.yml/badge.svg)](https://github.com/pipelab-org/pipelock-agent-egress-action/actions/workflows/ci.yml)
[![CodeQL](https://github.com/pipelab-org/pipelock-agent-egress-action/actions/workflows/codeql.yml/badge.svg)](https://github.com/pipelab-org/pipelock-agent-egress-action/actions/workflows/codeql.yml)
[![Lint](https://github.com/pipelab-org/pipelock-agent-egress-action/actions/workflows/lint.yml/badge.svg)](https://github.com/pipelab-org/pipelock-agent-egress-action/actions/workflows/lint.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pipelab-org/pipelock-agent-egress-action/badge)](https://scorecard.dev/viewer/?uri=github.com/pipelab-org/pipelock-agent-egress-action)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/pipelab-org/pipelock-agent-egress-action)](https://github.com/pipelab-org/pipelock-agent-egress-action/releases)

Verifiable Egress Control is the missing CI primitive for AI agents. Run the agent script, control what leaves the runner, verify the receipts, produce an Audit Packet a third party can inspect. Pipelock is staking that category as an open-source agent firewall with mediator-signed action receipts from outside the agent trust boundary.

## What this action is for

Run an agent script in CI. Control supported egress. Verify receipts. Produce an Audit Packet.

That is the whole promise.

Agents are starting to run inside pull requests, issue triage jobs, release workflows, docs bots, and security automation. Those jobs touch source code, secrets, package registries, cloud APIs, MCP tools, and the public internet. A normal CI log can tell you what the agent said it did. A Pipelock Audit Packet is meant to prove what the network boundary saw.

## What an Audit Packet is

An Audit Packet is the evidence bundle from one agent run. It includes the receipt chain, verifier output, policy hash, allowed and blocked totals, scanner config snapshot, posture metadata, and a Markdown summary humans can read. The receipts are signed by Pipelock at the network boundary, not by the agent process. The packet does not ask you to trust the agent's transcript. It gives you control-point evidence from outside the agent trust boundary.

Trusted evidence requires signer-key pinning. The verifier can run without a pinned key and confirm a receipt is internally consistent, but that proves self-consistency, not provenance. Pin the signer key from a known source (your Pipelock deployment or a published trust anchor) when you need the evidence to count.

## V0 enforcement boundary

The action enforces egress for **the script executed inside the Pipelock action boundary**. It does not contain sibling steps in your workflow, later workflow steps, or other actions in the caller workflow. It is not a job-wide network firewall.

**Enforced for the action script on supported Linux runners:**

- HTTP and HTTPS traffic routed through Pipelock at the network egress level
- WebSocket destinations contained at the network egress level
- Frame-level WebSocket scanning when the script explicitly uses Pipelock's `/ws?url=...` proxy path
- Direct network, DNS, and raw TCP from the action script blocked inside the namespace
- Non-root execution as `pipelock-agent` with sudo denied and capabilities dropped
- Non-root Pipelock listener execution as `pipelock-host` with sudo denied and capabilities dropped
- Signed receipt verification and local Audit Packet generation

**Fail-closed in v0 unless explicitly enabled by a later container enforcement mode:**

- Nested Docker workloads launched from the action script
- GitHub service containers
- Sibling container actions in the caller workflow
- MCP transports

**Out of scope for v0:**

- macOS and Windows runners
- SSH egress (planned for a later release)
- Browsers without explicit proxy configuration
- Steps in the caller workflow that run outside the Pipelock action boundary
- MCP stdio and MCP HTTP/SSE. MCP stdio does not traverse a network proxy; MCP HTTP/SSE needs explicit Pipelock MCP listener wiring and is planned for v0.2.

If a path is not under the Pipelock control point, this action says so. No magic. No fake containment story.

## What this action does not prove

The Audit Packet is evidence about traffic that crossed the Pipelock control point. It is not evidence about the runner that produced it. A relying party should pin the following before treating a `valid` verdict as provenance:

- Signer key pinned from a source outside the run environment. A key fetched from the same runner Pipelock just ran on is not pinned in the sense this action uses. Hand the public key over before the run or fetch it from a known trust anchor.
- Verifier run outside the run environment. The Go, Rust, TypeScript, and Python verifiers all run offline. Running the verifier inside the same runner that produced the packet reduces the verdict to "the runner's verifier reported a verdict."
- Pipelock binary pinned by checksum. This action does not download `latest`. Install a pinned binary in an earlier workflow step. A compromised runner that swaps the binary can still produce receipts that verify if it can use the configured signing key, so checksum pinning and signer-key pinning have to travel together.
- This action pinned by full-length commit SHA, not a tag. Tags are mutable. Short SHAs are prefix identifiers, not immutable release anchors. The "Pinning options" block below uses the full 40-character SHA for the same reason.
- Workflow scoped so the wrapped agent script is the sole secret-bearing step in the job. Sibling steps and steps that run before this action are outside the boundary. Secrets passed to other steps via `env:` or surfaced via `outputs:` are not in the receipt chain.

A missing receipt is not a proof of absence. The packet does not enumerate traffic Pipelock should have seen but didn't. Complement with runner-level network telemetry if the threat model needs negative-space evidence.

The canonical text on what a verified packet proves and does not prove is in [pipelock/docs/security/audit-packet-threat-model.md](https://github.com/pipelab-org/pipelock/blob/main/docs/security/audit-packet-threat-model.md).

## Action interface

```yaml
- uses: luckyPipewrench/pipelock-agent-egress-action@8f1894db09ec98d0bcbc46d0cc1cedffe5e5b504 # v0.1.0
  with:
    script-path: "./ci/agent-review.sh"
    pipelock-bin: "/usr/local/bin/pipelock"
    config: ".pipelock/ci.yaml"
    agent-identity: "ci-agent"
    signer-private-key-path: "${{ runner.temp }}/pipelock-signing/id_ed25519"
    signer-public-key: "${{ secrets.PIPELOCK_RECEIPT_PUBLIC_KEY }}"
    audit-packet-dir: "pipelock-audit-packet"
```

### Pinning options

```yaml
# Full-length commit SHA (recommended for security-sensitive workflows)
uses: luckyPipewrench/pipelock-agent-egress-action@8f1894db09ec98d0bcbc46d0cc1cedffe5e5b504 # v0.1.0

# Precise tag (cryptographically signed, but tags are mutable in git)
uses: luckyPipewrench/pipelock-agent-egress-action@v0.1.0

# Floating-minor (auto-pulls v0.1.x patches)
uses: luckyPipewrench/pipelock-agent-egress-action@v0.1

# Floating-major (auto-pulls v0.x features, breaks at v1.0.0)
uses: luckyPipewrench/pipelock-agent-egress-action@v0
```

All four forms currently point to the same v0.1.0 commit. Full-length commit SHA is the only form git treats as immutable. Short SHAs are prefix identifiers and tags can be repointed; for an evidence-bearing action, use the full SHA and update by hand when a new release ships.

Optional `script-args` is newline-delimited. Each line is passed as one argv element to the Bash script; it is not evaluated as shell by the action wrapper.

This pre-release action does not download `latest` Pipelock binaries. Install a pinned Pipelock binary in an earlier workflow step and pass `pipelock-bin`, or make `pipelock` available on `PATH`.

Trusted receipt verification requires both `signer-private-key-path` and `signer-public-key`. Omit both inputs to use an ephemeral signer; the verifier verdict will be `self_consistent_only`, not trusted provenance.

The action preserves caller policy from `config`, then materializes an action-owned runtime config that forces the listener, proxy, default identity, and receipt-signing fields required for this boundary.

Self-hosted runner note: the action creates or reuses local `pipelock-agent` and `pipelock-host` accounts and writes a short-lived sudoers deny file during the run. Hosted runners are discarded after the job; self-hosted operators should reserve those accounts for this action.

Supported Linux runners must provide passwordless sudo plus `ip`, `iptables`, `ip6tables`, `setpriv`, `unshare`, `curl`, `python3`, `ruby`, `realpath`, `getent`, `visudo`, `install`, `mount`, and `umount`.

The hosted smoke workflow exercises allowed proxy traffic, direct DNS/raw TCP/HTTP denial, sudo escape denial, Docker socket masking, capability drop, path traversal rejection, trusted verification, and empty-chain failure handling.

Outputs:

- `audit-packet-path`
- `receipt-count`
- `verifier-verdict`

Required workflow permission:

```yaml
permissions:
  contents: read
```

## Development status

This repo is pre-release. The first useful milestone is not a polished Marketplace listing. It is a working Linux runner path that launches an agent script, enforces supported egress through Pipelock, verifies the generated receipt chain, and writes a local Audit Packet.

Track development in this repo and in Pipelock:

- https://github.com/pipelab-org/pipelock-agent-egress-action
- https://github.com/pipelab-org/pipelock
- https://pipelab.org/learn/action-receipt-spec/

## Pull request reviews

The repository owner can manually request a review by posting one of two exact commands on the chosen pull request: `/review` for the default profile or `/review deep` for the deeper profile. Comments with additional text do not trigger a review. Other commenters cannot start this workflow.

The caller runs from the default branch and passes matching immutable workflow and reviewer-source pins. Manual workflow dispatch is deliberately unavailable. If a review does not appear, inspect the Actions run before retrying: source validation can fail before a status comment is created.

The read-only caller check runs when the caller workflow, its contract test, or the check workflow changes. It checks the local caller shape and matching pins; it does not execute the external reviewer. The legacy local-runner tests do not define this caller contract.

For source updates and recovery, follow the [shared reviewer guide](https://github.com/pipelab-org/pipelock/blob/3e8534e0dd621c62879238cc01d56f7e58e9d096/docs/guides/pr-review.md). A caller change takes effect after it reaches the default branch; a review of its own PR still uses the previous caller.

## License

Apache 2.0.
