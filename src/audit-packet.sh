#!/usr/bin/env bash
# Pipelock Audit Packet writer (schema_version: pipelock.audit_packet.v0).
#
# Emits packet.json conforming to
# https://pipelab.org/schemas/audit-packet-v0.schema.json
# (see sdk/audit-packet/v0.json in luckyPipewrench/pipelock).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: audit-packet.sh \
  --receipt-chain <evidence.jsonl path or empty> \
  --verifier-output <verifier.txt path> \
  --posture <posture.json path with schema-shaped posture fields> \
  --output-dir <packet output dir> \
  --run-started-at <RFC 3339 UTC timestamp> \
  --run-completed-at <RFC 3339 UTC timestamp> \
  --agent-identity <identity string> \
  --agent-exit-code <integer> \
  --verifier-verdict <valid|invalid|error|not_run|self_consistent_only> \
  [--user-config-path <path>] \
  [--runtime-config-path <path>] \
  [--config-snapshot-sha256 <hex>] \
  [--signer-public-key <hex|text|path>]
EOF
}

RECEIPT_CHAIN=""
VERIFIER_OUTPUT=""
POSTURE=""
OUTPUT_DIR="pipelock-audit-packet"
RUN_STARTED_AT=""
RUN_COMPLETED_AT=""
AGENT_IDENTITY=""
AGENT_EXIT_CODE=""
VERIFIER_VERDICT=""
USER_CONFIG_PATH=""
RUNTIME_CONFIG_PATH=""
CONFIG_SNAPSHOT_SHA256=""
SIGNER_PUBLIC_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --receipt-chain) RECEIPT_CHAIN="$2"; shift 2 ;;
    --verifier-output) VERIFIER_OUTPUT="$2"; shift 2 ;;
    --posture) POSTURE="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --run-started-at) RUN_STARTED_AT="$2"; shift 2 ;;
    --run-completed-at) RUN_COMPLETED_AT="$2"; shift 2 ;;
    --agent-identity) AGENT_IDENTITY="$2"; shift 2 ;;
    --agent-exit-code) AGENT_EXIT_CODE="$2"; shift 2 ;;
    --verifier-verdict) VERIFIER_VERDICT="$2"; shift 2 ;;
    --user-config-path) USER_CONFIG_PATH="$2"; shift 2 ;;
    --runtime-config-path) RUNTIME_CONFIG_PATH="$2"; shift 2 ;;
    --config-snapshot-sha256) CONFIG_SNAPSHOT_SHA256="$2"; shift 2 ;;
    --signer-public-key) SIGNER_PUBLIC_KEY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; echo "unknown flag: $1" >&2; exit 64 ;;
  esac
done

[[ -n "$VERIFIER_OUTPUT" ]] || { usage >&2; echo "--verifier-output is required" >&2; exit 64; }
[[ -n "$POSTURE" ]] || { usage >&2; echo "--posture is required" >&2; exit 64; }
[[ -n "$RUN_STARTED_AT" ]] || { usage >&2; echo "--run-started-at is required" >&2; exit 64; }
[[ -n "$RUN_COMPLETED_AT" ]] || { usage >&2; echo "--run-completed-at is required" >&2; exit 64; }
[[ -n "$AGENT_IDENTITY" ]] || { usage >&2; echo "--agent-identity is required" >&2; exit 64; }
[[ -n "$AGENT_EXIT_CODE" ]] || { usage >&2; echo "--agent-exit-code is required" >&2; exit 64; }
[[ -n "$VERIFIER_VERDICT" ]] || { usage >&2; echo "--verifier-verdict is required" >&2; exit 64; }
[[ -f "$VERIFIER_OUTPUT" ]] || { echo "verifier output not found: $VERIFIER_OUTPUT" >&2; exit 1; }
[[ -f "$POSTURE" ]] || { echo "posture file not found: $POSTURE" >&2; exit 1; }

# Resolve --signer-public-key: a file path expands to its contents, otherwise
# the value is emitted as-is. Only emitted when the user pinned a long-lived
# signer key (see schema asymmetric trust invariants).
RESOLVED_SIGNER_KEY=""
if [[ -n "$SIGNER_PUBLIC_KEY" ]]; then
  if [[ -f "$SIGNER_PUBLIC_KEY" ]]; then
    RESOLVED_SIGNER_KEY="$(cat "$SIGNER_PUBLIC_KEY")"
  else
    RESOLVED_SIGNER_KEY="$SIGNER_PUBLIC_KEY"
  fi
fi

mkdir -p "$OUTPUT_DIR"
if [[ -n "$RECEIPT_CHAIN" && -f "$RECEIPT_CHAIN" ]]; then
  cp "$RECEIPT_CHAIN" "$OUTPUT_DIR/evidence.jsonl"
else
  : >"$OUTPUT_DIR/evidence.jsonl"
fi
cp "$VERIFIER_OUTPUT" "$OUTPUT_DIR/verifier.txt"

AP_OUT_DIR="$OUTPUT_DIR" \
AP_POSTURE="$POSTURE" \
AP_RUN_STARTED_AT="$RUN_STARTED_AT" \
AP_RUN_COMPLETED_AT="$RUN_COMPLETED_AT" \
AP_AGENT_IDENTITY="$AGENT_IDENTITY" \
AP_AGENT_EXIT_CODE="$AGENT_EXIT_CODE" \
AP_VERIFIER_VERDICT="$VERIFIER_VERDICT" \
AP_USER_CONFIG_PATH="$USER_CONFIG_PATH" \
AP_RUNTIME_CONFIG_PATH="$RUNTIME_CONFIG_PATH" \
AP_CONFIG_SNAPSHOT_SHA256="$CONFIG_SNAPSHOT_SHA256" \
AP_SIGNER_KEY="$RESOLVED_SIGNER_KEY" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
from datetime import datetime, timezone

VALID_VERDICTS = {"valid", "invalid", "error", "not_run", "self_consistent_only"}
TOTALS_KEYS = ("allow", "block", "warn", "ask", "strip", "forward", "redirect", "other")
POSTURE_ALLOWED = {
    "enforcement_mode",
    "runner_os",
    "runner_arch",
    "raw_socket_status",
    "docker_socket_status",
    "dns_udp_status",
    "browser_proxy_status",
    "websocket_frame_scanning",
    "network_namespace",
    "agent_user",
    "agent_uid",
    "host_user",
    "host_uid",
    "host_ip",
    "agent_ip",
    "proxy_url",
    "script_basename",
    "script_arg_count",
    "unsupported_paths",
}
POSTURE_REQUIRED = {
    "enforcement_mode",
    "runner_os",
    "raw_socket_status",
    "docker_socket_status",
    "dns_udp_status",
    "browser_proxy_status",
    "websocket_frame_scanning",
    "unsupported_paths",
}

out_dir = pathlib.Path(os.environ["AP_OUT_DIR"])
posture_raw = json.loads(pathlib.Path(os.environ["AP_POSTURE"]).read_text(encoding="utf-8"))
evidence_path = out_dir / "evidence.jsonl"
packet_path = out_dir / "packet.json"
summary_path = out_dir / "summary.md"

verdict = os.environ["AP_VERIFIER_VERDICT"]
if verdict not in VALID_VERDICTS:
    raise SystemExit(
        f"audit-packet: --verifier-verdict {verdict!r} not in {sorted(VALID_VERDICTS)}"
    )

POSTURE_ENUMS = {
    "raw_socket_status": {"denied", "allowed", "unknown"},
    "docker_socket_status": {"denied", "masked", "allowed", "absent", "unknown"},
    "dns_udp_status": {"denied", "proxied", "allowed", "unknown"},
    "browser_proxy_status": {"forced", "advisory", "absent", "unknown"},
    "websocket_frame_scanning": {
        "explicit_ws_proxy_path_required",
        "always_on",
        "off",
    },
}


def require_utc_timestamp(name: str, value: str) -> None:
    if not value.endswith("Z"):
        raise SystemExit(
            f"audit-packet: {name} must be RFC 3339 UTC timestamp ending in Z"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SystemExit(
            f"audit-packet: {name} must be RFC 3339 UTC timestamp ending in Z"
        ) from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SystemExit(f"audit-packet: {name} must not carry a non-UTC offset")


require_utc_timestamp("--run-started-at", os.environ["AP_RUN_STARTED_AT"])
require_utc_timestamp("--run-completed-at", os.environ["AP_RUN_COMPLETED_AT"])

unknown = set(posture_raw) - POSTURE_ALLOWED
if unknown:
    raise SystemExit(
        f"audit-packet: posture has fields outside v0 schema: {sorted(unknown)}"
    )
posture = dict(posture_raw)
missing = POSTURE_REQUIRED - posture.keys()
if missing:
    raise SystemExit(f"audit-packet: posture is missing required fields: {sorted(missing)}")
if not isinstance(posture.get("unsupported_paths"), list):
    raise SystemExit("audit-packet: posture.unsupported_paths must be an array")
for field, valid_values in POSTURE_ENUMS.items():
    value = posture.get(field)
    if value not in valid_values:
        raise SystemExit(
            f"audit-packet: posture.{field} {value!r} not in {sorted(valid_values)}"
        )

totals = {key: 0 for key in TOTALS_KEYS}
receipt_count = 0
policy_hashes: set[str] = set()
transports: dict[str, int] = {}

with evidence_path.open("rb") as fh:
    for raw in fh:
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            # A torn export can end inside a UTF-8 sequence; same rule as run.sh.
            continue
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            # Malformed lines do not count as receipts; counting them would
            # break the totals-sum-equals-receipt-count invariant.
            continue
        if not isinstance(entry, dict) or entry.get("type") != "action_receipt":
            continue
        # A receipt without an action record object is malformed, not an
        # action. run.sh applies the same rule so the counts agree.
        detail = entry.get("detail")
        action_record = detail.get("action_record") if isinstance(detail, dict) else None
        if not isinstance(action_record, dict):
            continue
        # Session open and close receipts are chain bookkeeping Pipelock writes
        # even when the agent does nothing. The verifier still checks them as
        # part of the chain, but they are not agent actions, so they do not
        # count toward receipt_count or the verdict totals.
        if action_record.get("session_control"):
            continue
        receipt_count += 1
        verdict_name = str(action_record.get("verdict") or "other")
        totals[verdict_name if verdict_name in totals else "other"] += 1
        policy_hash = action_record.get("policy_hash")
        if policy_hash:
            policy_hashes.add(str(policy_hash))
        transport = str(action_record.get("transport") or "unknown")
        transports[transport] = transports.get(transport, 0) + 1

# Schema requires totals.allow + ... + totals.other == receipt_count. This is
# also the Go binding's invariant in sdk/audit-packet/audit_packet.go.
totals_sum = sum(totals.values())
if totals_sum != receipt_count:
    raise SystemExit(
        f"audit-packet: totals sum {totals_sum} != receipt_count {receipt_count}"
    )

# Provider detection: GITHUB_ACTIONS=true is the canonical marker. Hosted vs
# self-hosted is RUNNER_ENVIRONMENT (set by GitHub on hosted, "self-hosted"
# on self-hosted runners with recent runner versions).
def detect_provider() -> str:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        env = os.environ.get("RUNNER_ENVIRONMENT", "").lower()
        if env == "self-hosted":
            return "self_hosted"
        return "github_actions"
    return "local"

run_block: dict[str, object] = {
    "provider": detect_provider(),
    "agent_identity": os.environ["AP_AGENT_IDENTITY"],
    "started_at": os.environ["AP_RUN_STARTED_AT"],
}
for src_env, dst_key in (
    ("GITHUB_REPOSITORY", "repository"),
    ("GITHUB_WORKFLOW", "workflow"),
    ("GITHUB_RUN_ID", "run_id"),
    ("GITHUB_RUN_ATTEMPT", "run_attempt"),
    ("GITHUB_REF", "ref"),
    ("GITHUB_SHA", "sha"),
):
    value = os.environ.get(src_env, "")
    if value:
        run_block[dst_key] = value
if os.environ.get("AP_RUN_COMPLETED_AT"):
    run_block["completed_at"] = os.environ["AP_RUN_COMPLETED_AT"]
try:
    run_block["agent_exit_code"] = int(os.environ["AP_AGENT_EXIT_CODE"])
except ValueError as exc:
    raise SystemExit(f"audit-packet: --agent-exit-code is not an integer: {exc}") from exc

policy_block: dict[str, object] = {
    "policy_hashes": sorted(policy_hashes),
}
if os.environ.get("AP_USER_CONFIG_PATH"):
    policy_block["config_path"] = os.environ["AP_USER_CONFIG_PATH"]
if os.environ.get("AP_RUNTIME_CONFIG_PATH"):
    policy_block["runtime_config_path"] = os.environ["AP_RUNTIME_CONFIG_PATH"]
if os.environ.get("AP_CONFIG_SNAPSHOT_SHA256"):
    policy_block["config_snapshot_sha256"] = os.environ["AP_CONFIG_SNAPSHOT_SHA256"]

summary_block: dict[str, object] = {
    "receipt_count": receipt_count,
    "totals": totals,
}
if transports:
    summary_block["transports"] = transports

# trusted is derived from verdict, NOT from the user's intent flag. A pinned-key
# signature failure produces verdict=invalid, trusted=false, with signer_key
# retained as forensic state. verifier=error / not_run omit signer_key because
# no signed chain was verified or rejected under that key. This satisfies the
# schema's asymmetric trust invariants:
#   if trusted=true then verdict=valid AND signer_key set
#   if verdict=valid then trusted=true AND signer_key set
trusted = verdict == "valid"
verifier_block: dict[str, object] = {
    "verdict": verdict,
    "trusted": trusted,
    "receipt_count": receipt_count,
    "output_file": "verifier.txt",
}
signer_key = os.environ.get("AP_SIGNER_KEY", "").strip()
if signer_key and verdict in {"valid", "invalid"}:
    verifier_block["signer_key"] = signer_key
elif trusted:
    raise SystemExit(
        "audit-packet: trusted=true requires --signer-public-key (schema invariant)"
    )

artifacts_block: dict[str, str] = {
    "packet": "packet.json",
    "summary": "summary.md",
    "evidence": "evidence.jsonl",
    "verifier": "verifier.txt",
}

packet = {
    "schema_version": "pipelock.audit_packet.v0",
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "run": run_block,
    "policy": policy_block,
    "summary": summary_block,
    "verifier": verifier_block,
    "posture": posture,
    "artifacts": artifacts_block,
}

packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")

summary_lines = [
    "# Pipelock Audit Packet",
    "",
    f"- Schema: `{packet['schema_version']}`",
    f"- Verifier verdict: `{verdict}`",
    f"- Trusted verification: `{str(trusted).lower()}`",
    f"- Receipt count: `{receipt_count}`",
    f"- Provider: `{run_block['provider']}`",
    f"- Agent identity: `{run_block['agent_identity']}`",
    f"- Agent exit code: `{run_block['agent_exit_code']}`",
    f"- Enforcement mode: `{posture['enforcement_mode']}`",
    f"- Runner OS: `{posture['runner_os']}`",
    f"- Script: `{posture.get('script_basename', '<unknown>')}` (args: `{posture.get('script_arg_count', 0)}`)",
    "",
    "## Totals",
    "",
]
for key in TOTALS_KEYS:
    summary_lines.append(f"- {key}: `{totals[key]}`")
summary_lines.extend([
    "",
    "## Posture status",
    "",
    f"- raw_socket_status: `{posture['raw_socket_status']}`",
    f"- docker_socket_status: `{posture['docker_socket_status']}`",
    f"- dns_udp_status: `{posture['dns_udp_status']}`",
    f"- browser_proxy_status: `{posture['browser_proxy_status']}`",
    f"- websocket_frame_scanning: `{posture['websocket_frame_scanning']}`",
    "",
])
unsupported = posture.get("unsupported_paths") or []
if unsupported:
    summary_lines.append("## Unsupported paths (out of scope, by design)")
    summary_lines.append("")
    for path_label in unsupported:
        summary_lines.append(f"- `{path_label}`")
    summary_lines.append("")

summary_lines.extend([
    "## Artifacts",
    "",
    "- `packet.json`",
    "- `summary.md`",
    "- `evidence.jsonl`",
    "- `verifier.txt`",
    "",
])
if verdict == "self_consistent_only":
    summary_lines.extend([
        "## Warning",
        "",
        "Trusted evidence requires signer-key pinning. This packet only proves internal receipt-chain consistency.",
        "",
    ])

summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
PY
