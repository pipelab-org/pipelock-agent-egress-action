#!/usr/bin/env bash
# Pipelock agent egress action entrypoint.
set -Eeuo pipefail

AGENT_USER="pipelock-agent"
HOST_USER="pipelock-host"
AGENT_NAME="action-ephemeral"
RUN_SUFFIX="$$"
NETNS="pipelock-agent-$RUN_SUFFIX"
HOST_IF="plh$RUN_SUFFIX"
AGENT_IF="pla$RUN_SUFFIX"
IP_OCTET_2=$((20 + (RUN_SUFFIX % 200)))
IP_OCTET_3=$((30 + ((RUN_SUFFIX / 200) % 200)))
HOST_IP="10.$IP_OCTET_2.$IP_OCTET_3.1"
AGENT_IP="10.$IP_OCTET_2.$IP_OCTET_3.2"
PIPELOCK_PORT="8888"

SCRIPT_PATH=""
SCRIPT_ARGS_RAW=""
CONFIG=".pipelock/ci.yaml"
AGENT_IDENTITY="github-actions-agent"
PIPELOCK_VERSION=""
PIPELOCK_BIN=""
SIGNER_PRIVATE_KEY_PATH=""
SIGNER_PUBLIC_KEY=""
VERIFY_SIGNER_KEY=""
TRUSTED_VERIFICATION="false"
AUDIT_PACKET_DIR="pipelock-audit-packet"
WORKING_DIRECTORY="."
FAIL_ON_VERIFIER_ERROR="true"
DEBUG="false"

RUNTIME_ROOT=""
ACTION_WORK_ROOT=""
SCRIPT_STAGING_DIR=""
SCRIPT_RUN_PATH=""
RUNTIME_BIN=""
RUNTIME_CONFIG=""
MATERIALIZED_CONFIG=""
RUNTIME_KEYSTORE=""
RUNTIME_SIGNING_DIR=""
RUNTIME_SIGNER_PRIVATE_KEY=""
EVIDENCE_DIR=""
POSTURE_PATH=""
VERIFIER_OUTPUT=""
EVIDENCE_EXPORT=""
KEYGEN_OUTPUT=""
PIPELOCK_PID=""
RECORDER_PID=""
RECORDER_START_TIME=""
AGENT_EXIT_CODE=0
VERIFIER_VERDICT="error"
RECEIPT_COUNT=0
RUN_STARTED_AT=""
RUN_COMPLETED_AT=""
CONFIG_SNAPSHOT_SHA256=""
CREATED_AGENT_USER="false"
CREATED_HOST_USER="false"
SUDOERS_DENY_FILE=""
ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=src/verify-recorder.sh
source "$ACTION_DIR/src/verify-recorder.sh"

usage() {
  cat <<'EOF'
Usage: run.sh \
  --script-path <script under working directory> \
  [--script-args <newline-delimited args>] \
  --config <pipelock config path> \
  --agent-identity <identity string> \
  --pipelock-version <reserved release version or empty> \
  --pipelock-bin <binary path or empty> \
  --signer-private-key-path <private key path or empty> \
  --signer-public-key <public key value/path or empty> \
  --audit-packet-dir <output dir> \
  --working-directory <directory> \
  --fail-on-verifier-error <true|false> \
  --debug <true|false>
EOF
}

note() {
  printf 'pipelock-agent-egress-action: %s\n' "$*" >&2
}

die() {
  printf 'pipelock-agent-egress-action: error: %s\n' "$*" >&2
  exit 1
}

debug() {
  if [[ "$DEBUG" == "true" ]]; then
    note "$@"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

bool_input() {
  local name="$1"
  local value="$2"
  case "$value" in
    true|false) ;;
    *) die "$name must be true or false, got $value" ;;
  esac
}

cleanup() {
  set +e
  if ! stop_pipelock; then
    note "recorder shutdown unconfirmed; preserving runtime resources for inspection"
    return
  fi
  sudo ip netns del "$NETNS" >/dev/null 2>&1
  sudo ip link del "$HOST_IF" >/dev/null 2>&1
  if [[ -n "$RUNTIME_ROOT" ]]; then
    sudo rm -rf "$RUNTIME_ROOT" >/dev/null 2>&1
  fi
  if [[ -n "$ACTION_WORK_ROOT" ]]; then
    rm -rf "$ACTION_WORK_ROOT" >/dev/null 2>&1
  fi
  if [[ -n "$SCRIPT_STAGING_DIR" ]]; then
    sudo rm -rf "$SCRIPT_STAGING_DIR" >/dev/null 2>&1
  fi
  if [[ -n "$SUDOERS_DENY_FILE" ]]; then
    sudo rm -f "$SUDOERS_DENY_FILE" >/dev/null 2>&1
  fi
  if [[ "$CREATED_AGENT_USER" == "true" ]]; then
    sudo userdel -r "$AGENT_USER" >/dev/null 2>&1
  fi
  if [[ "$CREATED_HOST_USER" == "true" ]]; then
    sudo userdel -r "$HOST_USER" >/dev/null 2>&1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --script-path) SCRIPT_PATH="$2"; shift 2 ;;
    --script-args) SCRIPT_ARGS_RAW="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --agent-identity) AGENT_IDENTITY="$2"; shift 2 ;;
    --pipelock-version) PIPELOCK_VERSION="$2"; shift 2 ;;
    --pipelock-bin) PIPELOCK_BIN="$2"; shift 2 ;;
    --signer-private-key-path) SIGNER_PRIVATE_KEY_PATH="$2"; shift 2 ;;
    --signer-public-key) SIGNER_PUBLIC_KEY="$2"; shift 2 ;;
    --audit-packet-dir) AUDIT_PACKET_DIR="$2"; shift 2 ;;
    --working-directory) WORKING_DIRECTORY="$2"; shift 2 ;;
    --fail-on-verifier-error) FAIL_ON_VERIFIER_ERROR="$2"; shift 2 ;;
    --debug) DEBUG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown flag: $1" ;;
  esac
done

[[ -n "$SCRIPT_PATH" ]] || die "--script-path is required"
bool_input "--fail-on-verifier-error" "$FAIL_ON_VERIFIER_ERROR"
bool_input "--debug" "$DEBUG"

require_cmd sudo
require_cmd ip
require_cmd iptables
require_cmd ip6tables
require_cmd setpriv
require_cmd unshare
require_cmd curl
require_cmd python3
require_cmd ruby
require_cmd realpath
require_cmd getent
require_cmd visudo
require_cmd grep
require_cmd install
require_cmd mount
require_cmd umount
sudo -n true >/dev/null 2>&1 || die "passwordless sudo is required on supported Linux runners"
[[ "$(uname -s)" == "Linux" ]] || die "only Linux runners are supported"

if [[ -n "$SIGNER_PUBLIC_KEY" && -z "$SIGNER_PRIVATE_KEY_PATH" ]]; then
  die "signer-public-key requires signer-private-key-path; omit signer-public-key for ephemeral self-consistent verification"
fi

WORKDIR_REAL="$(realpath -e "$WORKING_DIRECTORY")"
CONFIG_REAL=""
if [[ -n "$CONFIG" ]]; then
  if [[ "$CONFIG" = /* ]]; then
    CONFIG_CANDIDATE="$CONFIG"
  else
    CONFIG_CANDIDATE="$WORKDIR_REAL/$CONFIG"
  fi
  CONFIG_CANONICAL="$(realpath -m "$CONFIG_CANDIDATE")"
  case "$CONFIG_CANONICAL" in
    "$WORKDIR_REAL"|"$WORKDIR_REAL"/*) ;;
    *) die "config path escapes working-directory: $CONFIG" ;;
  esac
  if [[ -e "$CONFIG_CANONICAL" ]]; then
    CONFIG_REAL="$(realpath -e "$CONFIG_CANONICAL")"
    [[ -f "$CONFIG_REAL" ]] || die "config path is not a file: $CONFIG_REAL"
  fi
fi

if [[ "$SCRIPT_PATH" = /* ]]; then
  SCRIPT_REAL="$(realpath -e "$SCRIPT_PATH")"
else
  SCRIPT_REAL="$(realpath -e "$WORKDIR_REAL/$SCRIPT_PATH")"
fi
case "$SCRIPT_REAL" in
  "$WORKDIR_REAL"/*) ;;
  *) die "script-path escapes working-directory: $SCRIPT_PATH" ;;
esac
[[ -f "$SCRIPT_REAL" ]] || die "script-path is not a file: $SCRIPT_REAL"
[[ -r "$SCRIPT_REAL" ]] || die "script-path is not readable: $SCRIPT_REAL"

SCRIPT_ARGV=()
if [[ -n "$SCRIPT_ARGS_RAW" ]]; then
  while IFS= read -r arg; do
    SCRIPT_ARGV+=("$arg")
  done <<<"$SCRIPT_ARGS_RAW"
fi
SCRIPT_BASENAME="$(basename "$SCRIPT_REAL")"
note "script: $SCRIPT_BASENAME (${#SCRIPT_ARGV[@]} args)"
if [[ "$DEBUG" == "true" ]]; then
  debug "validated script path: $SCRIPT_REAL"
  debug "script args: ${SCRIPT_ARGV[*]:-<none>}"
fi

resolve_pipelock_bin() {
  local candidate=""
  if [[ -n "$PIPELOCK_BIN" ]]; then
    candidate="$(realpath -e "$PIPELOCK_BIN")"
  elif command -v pipelock >/dev/null 2>&1; then
    candidate="$(command -v pipelock)"
  else
    if [[ -n "$PIPELOCK_VERSION" ]]; then
      die "pinned release install is not wired yet; provide --pipelock-bin or put pipelock on PATH"
    fi
    die "pipelock-bin is required unless pipelock is already on PATH; this action does not download latest releases"
  fi
  [[ -x "$candidate" ]] || die "pipelock binary is not executable: $candidate"
  printf '%s\n' "$candidate"
}

HOST_PIPELOCK_BIN="$(resolve_pipelock_bin)"
"$HOST_PIPELOCK_BIN" --version >/dev/null 2>&1 || die "pipelock binary failed --version: $HOST_PIPELOCK_BIN"

RUNTIME_ROOT="/tmp/pipelock-agent-egress-${GITHUB_RUN_ID:-local}-$$"
ACTION_WORK_ROOT="${RUNNER_TEMP:-/tmp}/pipelock-agent-egress-work-${GITHUB_RUN_ID:-local}-$$"
SCRIPT_STAGING_DIR="/tmp/pipelock-agent-egress-script-${GITHUB_RUN_ID:-local}-$$"
RUNTIME_BIN="$RUNTIME_ROOT/bin/pipelock"
RUNTIME_CONFIG="$RUNTIME_ROOT/config/action.yaml"
MATERIALIZED_CONFIG="$ACTION_WORK_ROOT/action.yaml"
RUNTIME_KEYSTORE="$RUNTIME_ROOT/keys"
RUNTIME_SIGNING_DIR="$RUNTIME_ROOT/signing"
RUNTIME_SIGNER_PRIVATE_KEY="$RUNTIME_SIGNING_DIR/id_ed25519"
EVIDENCE_DIR="$RUNTIME_ROOT/evidence"
POSTURE_PATH="$ACTION_WORK_ROOT/posture.json"
VERIFIER_OUTPUT="$ACTION_WORK_ROOT/verifier.txt"
EVIDENCE_EXPORT="$ACTION_WORK_ROOT/export/evidence.jsonl"
KEYGEN_OUTPUT="$ACTION_WORK_ROOT/keygen.txt"
PIPELOCK_LOG="$ACTION_WORK_ROOT/logs/pipelock.log"

trap cleanup EXIT

mkdir -p "$ACTION_WORK_ROOT"/{export,logs}
chmod 0700 "$ACTION_WORK_ROOT" "$ACTION_WORK_ROOT"/{export,logs}
sudo mkdir -p "$SCRIPT_STAGING_DIR"
sudo chmod 0755 "$SCRIPT_STAGING_DIR"
SCRIPT_RUN_PATH="$SCRIPT_STAGING_DIR/$SCRIPT_BASENAME"
sudo install -m 0555 -o root -g root "$SCRIPT_REAL" "$SCRIPT_RUN_PATH"
sudo mkdir -p "$RUNTIME_ROOT"/{bin,config,keys,signing,evidence}
sudo chmod 0755 "$RUNTIME_ROOT" "$RUNTIME_ROOT/bin"
sudo chmod 0700 "$RUNTIME_ROOT"/{keys,signing,evidence}
sudo install -m 0555 -o root -g root "$HOST_PIPELOCK_BIN" "$RUNTIME_BIN"

ensure_unprivileged_user() {
  local user="$1"
  local shell="$2"
  local created_var="$3"

  if id "$user" >/dev/null 2>&1; then
    printf -v "$created_var" '%s' "false"
  else
    sudo useradd --system --create-home --shell "$shell" "$user"
    printf -v "$created_var" '%s' "true"
  fi

  local groups
  groups="$(id -nG "$user")"
  for forbidden in sudo wheel docker kvm; do
    case " $groups " in
      *" $forbidden "*) die "$user must not belong to privileged group $forbidden" ;;
    esac
  done
}

write_sudoers_deny_file() {
  SUDOERS_DENY_FILE="/etc/sudoers.d/pipelock-agent-egress-action-$$"
  {
    printf '%s ALL=(ALL:ALL) !ALL\n' "$AGENT_USER"
    printf '%s ALL=(ALL:ALL) !ALL\n' "$HOST_USER"
  } | sudo tee "$SUDOERS_DENY_FILE" >/dev/null
  sudo chmod 0440 "$SUDOERS_DENY_FILE"
  sudo visudo -cf "$SUDOERS_DENY_FILE" >/dev/null
}

ensure_agent_user() {
  ensure_unprivileged_user "$AGENT_USER" /bin/bash CREATED_AGENT_USER
}

ensure_host_user() {
  if [[ -x /usr/sbin/nologin ]]; then
    ensure_unprivileged_user "$HOST_USER" /usr/sbin/nologin CREATED_HOST_USER
  else
    ensure_unprivileged_user "$HOST_USER" /bin/false CREATED_HOST_USER
  fi
}

ensure_agent_user
ensure_host_user
write_sudoers_deny_file

AGENT_UID="$(id -u "$AGENT_USER")"
AGENT_GID="$(id -g "$AGENT_USER")"
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)"
HOST_UID="$(id -u "$HOST_USER")"
HOST_GID="$(id -g "$HOST_USER")"
HOST_HOME="$(getent passwd "$HOST_USER" | cut -d: -f6)"

sudo chown root:"$HOST_GID" "$RUNTIME_ROOT/config" "$RUNTIME_SIGNING_DIR"
sudo chmod 0750 "$RUNTIME_ROOT/config" "$RUNTIME_SIGNING_DIR"
sudo chown "$HOST_UID":"$HOST_GID" "$EVIDENCE_DIR"
sudo chmod 0700 "$EVIDENCE_DIR"

if [[ -n "$SIGNER_PRIVATE_KEY_PATH" ]]; then
  SIGNER_PRIVATE_KEY_PATH="$(realpath -e "$SIGNER_PRIVATE_KEY_PATH")"
  sudo test -r "$SIGNER_PRIVATE_KEY_PATH" || die "signer private key is not readable by root: $SIGNER_PRIVATE_KEY_PATH"
  sudo install -m 0640 -o root -g "$HOST_GID" "$SIGNER_PRIVATE_KEY_PATH" "$RUNTIME_SIGNER_PRIVATE_KEY"
  SIGNER_PRIVATE_KEY_PATH="$RUNTIME_SIGNER_PRIVATE_KEY"
  if [[ -n "$SIGNER_PUBLIC_KEY" ]]; then
    VERIFY_SIGNER_KEY="$SIGNER_PUBLIC_KEY"
    TRUSTED_VERIFICATION="true"
  fi
else
  if ! sudo "$RUNTIME_BIN" keygen "$AGENT_NAME" --keystore "$RUNTIME_KEYSTORE" --force >"$KEYGEN_OUTPUT" 2>&1; then
    sed -n '1,80p' "$KEYGEN_OUTPUT" >&2 || true
    die "pipelock keygen failed; expected CLI: pipelock keygen <agent-name> --keystore <dir> --force"
  fi
  KEYGEN_PRIVATE_KEY_PATH="$RUNTIME_KEYSTORE/agents/$AGENT_NAME/id_ed25519"
  EPHEMERAL_PUBLIC_KEY_PATH="$RUNTIME_KEYSTORE/agents/$AGENT_NAME/id_ed25519.pub"
  sudo install -m 0640 -o root -g "$HOST_GID" "$KEYGEN_PRIVATE_KEY_PATH" "$RUNTIME_SIGNER_PRIVATE_KEY"
  SIGNER_PRIVATE_KEY_PATH="$RUNTIME_SIGNER_PRIVATE_KEY"
  sudo chmod 0644 "$EPHEMERAL_PUBLIC_KEY_PATH"
  if [[ -n "$SIGNER_PUBLIC_KEY" ]]; then
    VERIFY_SIGNER_KEY="$SIGNER_PUBLIC_KEY"
    TRUSTED_VERIFICATION="true"
  else
    VERIFY_SIGNER_KEY="$EPHEMERAL_PUBLIC_KEY_PATH"
    TRUSTED_VERIFICATION="false"
  fi
fi

run_host_probe() {
  sudo HOME="$HOST_HOME" USER="$HOST_USER" LOGNAME="$HOST_USER" setpriv \
    --reuid "$HOST_UID" \
    --regid "$HOST_GID" \
    --clear-groups \
    --no-new-privs \
    --bounding-set=-all \
    --inh-caps=-all \
    --ambient-caps=-all \
    -- "$@"
}

if [[ "$(run_host_probe id -u)" != "$HOST_UID" ]]; then
  die "$HOST_USER did not drop to the expected uid"
fi
if run_host_probe sudo -n true >/dev/null 2>&1; then
  die "$HOST_USER can invoke sudo; host proxy containment would be bypassable"
fi
if ! run_host_probe cat "$SIGNER_PRIVATE_KEY_PATH" >/dev/null 2>&1; then
  die "$HOST_USER cannot read the runtime signing key"
fi

write_runtime_config() {
  local listen_addr="$HOST_IP:$PIPELOCK_PORT"
  "$ACTION_DIR/src/materialize-config.rb" \
    --input "$CONFIG_REAL" \
    --output "$MATERIALIZED_CONFIG" \
    --agent-identity "$AGENT_IDENTITY" \
    --listen "$listen_addr" \
    --evidence-dir "$EVIDENCE_DIR" \
    --signing-key-path "$SIGNER_PRIVATE_KEY_PATH"
  sudo install -m 0640 -o root -g "$HOST_GID" "$MATERIALIZED_CONFIG" "$RUNTIME_CONFIG"
}

write_runtime_config
if command -v sha256sum >/dev/null 2>&1; then
  CONFIG_SNAPSHOT_SHA256="$(sudo sha256sum "$RUNTIME_CONFIG" | awk '{print $1}')"
fi

if ! run_host_probe test -r "$RUNTIME_CONFIG" >/dev/null 2>&1; then
  die "$HOST_USER cannot read the runtime config"
fi
if run_host_probe test -w "$RUNTIME_CONFIG" >/dev/null 2>&1; then
  die "$HOST_USER can write the runtime config"
fi
if run_host_probe test -w "$SIGNER_PRIVATE_KEY_PATH" >/dev/null 2>&1; then
  die "$HOST_USER can write the runtime signing key"
fi
if ! run_host_probe sh -c 'touch "$1"/host-write-probe && rm -f "$1"/host-write-probe' sh "$EVIDENCE_DIR" >/dev/null 2>&1; then
  die "$HOST_USER cannot write to the evidence directory"
fi
if command -v getpcaps >/dev/null 2>&1; then
  if ! run_host_probe sh -c 'getpcaps $$' >"$ACTION_WORK_ROOT/export/host-capabilities.txt" 2>&1; then
    die "host capability probe failed"
  fi
  if grep -Eq 'cap_[a-z0-9_]+' "$ACTION_WORK_ROOT/export/host-capabilities.txt"; then
    sed -n '1,20p' "$ACTION_WORK_ROOT/export/host-capabilities.txt" >&2 || true
    die "$HOST_USER retained Linux capabilities after setpriv"
  fi
fi

setup_network_boundary() {
  sudo ip netns del "$NETNS" >/dev/null 2>&1 || true
  sudo ip link del "$HOST_IF" >/dev/null 2>&1 || true

  sudo ip netns add "$NETNS"
  sudo ip link add "$HOST_IF" type veth peer name "$AGENT_IF"
  sudo ip link set "$AGENT_IF" netns "$NETNS"
  sudo ip addr add "$HOST_IP/30" dev "$HOST_IF"
  sudo ip link set "$HOST_IF" up
  sudo ip -n "$NETNS" addr add "$AGENT_IP/30" dev "$AGENT_IF"
  sudo ip -n "$NETNS" link set lo up
  sudo ip -n "$NETNS" link set "$AGENT_IF" up
  sudo ip -n "$NETNS" route add default via "$HOST_IP"

  sudo ip netns exec "$NETNS" iptables -P OUTPUT DROP
  sudo ip netns exec "$NETNS" iptables -F OUTPUT
  sudo ip netns exec "$NETNS" iptables -A OUTPUT -o lo -j ACCEPT
  sudo ip netns exec "$NETNS" iptables -A OUTPUT -p tcp -d "$HOST_IP" --dport "$PIPELOCK_PORT" -j ACCEPT
  sudo ip netns exec "$NETNS" iptables -A OUTPUT -j REJECT
  sudo ip netns exec "$NETNS" ip6tables -P OUTPUT DROP
  sudo ip netns exec "$NETNS" ip6tables -F OUTPUT
  sudo ip netns exec "$NETNS" ip6tables -A OUTPUT -j REJECT
}

setup_network_boundary

sudo HOME="$HOST_HOME" USER="$HOST_USER" LOGNAME="$HOST_USER" setpriv \
  --reuid "$HOST_UID" \
  --regid "$HOST_GID" \
  --clear-groups \
  --no-new-privs \
  --bounding-set=-all \
  --inh-caps=-all \
  --ambient-caps=-all \
  -- "$RUNTIME_BIN" run --config "$RUNTIME_CONFIG" >"$PIPELOCK_LOG" 2>&1 &
PIPELOCK_PID="$!"

for _ in $(seq 1 80); do
  if [[ -z "$RECORDER_PID" ]]; then
    capture_recorder_pid || true
  fi
  if curl -fsS --max-time 1 "http://$HOST_IP:$PIPELOCK_PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if ! curl -fsS --max-time 2 "http://$HOST_IP:$PIPELOCK_PORT/health" >/dev/null 2>&1; then
  sed -n '1,120p' "$PIPELOCK_LOG" >&2 || true
  die "pipelock listener did not become healthy on $HOST_IP:$PIPELOCK_PORT"
fi

if [[ -z "$RECORDER_PID" ]]; then
  die "could not identify the recorder child of the sudo launcher"
fi

run_agent_probe() {
  sudo -E ip netns exec "$NETNS" setpriv \
    --reuid "$AGENT_UID" \
    --regid "$AGENT_GID" \
    --clear-groups \
    --no-new-privs \
    --bounding-set=-all \
    --inh-caps=-all \
    --ambient-caps=-all \
    -- "$@"
}

if run_agent_probe sudo -n true >/dev/null 2>&1; then
  die "$AGENT_USER can invoke sudo; containment would be bypassable"
fi
if run_agent_probe cat "$SIGNER_PRIVATE_KEY_PATH" >/dev/null 2>&1; then
  die "$AGENT_USER can read the signing private key"
fi
if run_agent_probe sh -c 'echo malicious >> "$1"/write-probe' sh "$EVIDENCE_DIR" >/dev/null 2>&1; then
  die "$AGENT_USER can write to the evidence directory"
fi
if command -v getpcaps >/dev/null 2>&1; then
  if ! run_agent_probe sh -c 'getpcaps $$' >"$ACTION_WORK_ROOT/export/capabilities.txt" 2>&1; then
    die "capability probe failed"
  fi
  if grep -Eq 'cap_[a-z0-9_]+' "$ACTION_WORK_ROOT/export/capabilities.txt"; then
    sed -n '1,20p' "$ACTION_WORK_ROOT/export/capabilities.txt" >&2 || true
    die "$AGENT_USER retained Linux capabilities after setpriv"
  fi
fi

PROXY_URL="http://$HOST_IP:$PIPELOCK_PORT"
CA_BUNDLE="${PIPELOCK_CA_BUNDLE:-}"
if [[ -z "$CA_BUNDLE" && -f "$HOME/.pipelock/ca.pem" ]]; then
  CA_BUNDLE="$HOME/.pipelock/ca.pem"
fi

note "launching script inside $NETNS as $AGENT_USER"
RUN_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
set +e
sudo -E ip netns exec "$NETNS" unshare --mount --propagation private bash -c '
set -euo pipefail
workdir="$1"; shift
agent_uid="$1"; shift
agent_gid="$1"; shift
agent_home="$1"; shift
proxy_url="$1"; shift
ca_bundle="$1"; shift
docker_sock_created="false"
cleanup_docker_sock() {
  set +e
  umount /var/run/docker.sock >/dev/null 2>&1
  if [[ "$docker_sock_created" == "true" ]]; then
    rm -f /var/run/docker.sock
  fi
}
trap cleanup_docker_sock EXIT
if [[ ! -e /var/run/docker.sock ]]; then
  install -m 000 /dev/null /var/run/docker.sock
  docker_sock_created="true"
fi
mount --bind /dev/null /var/run/docker.sock
cd "$workdir"
export HOME="$agent_home"
export HTTP_PROXY="$proxy_url"
export HTTPS_PROXY="$proxy_url"
export http_proxy="$proxy_url"
export https_proxy="$proxy_url"
unset NO_PROXY
unset no_proxy
if [[ -n "$ca_bundle" ]]; then
  export NODE_EXTRA_CA_CERTS="$ca_bundle"
  export REQUESTS_CA_BUNDLE="$ca_bundle"
  export SSL_CERT_FILE="$ca_bundle"
  export CURL_CA_BUNDLE="$ca_bundle"
  export GIT_SSL_CAINFO="$ca_bundle"
  export PIP_CERT="$ca_bundle"
  export NPM_CONFIG_CAFILE="$ca_bundle"
  export YARN_CA_FILE="$ca_bundle"
  export PNPM_CONFIG_CAFILE="$ca_bundle"
  export AWS_CA_BUNDLE="$ca_bundle"
  export SSL_CERT_DIR="$(dirname "$ca_bundle")"
  export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="$ca_bundle"
  export NODE_OPTIONS="${NODE_OPTIONS:-} --use-openssl-ca"
fi
setpriv \
  --reuid "$agent_uid" \
  --regid "$agent_gid" \
  --clear-groups \
  --no-new-privs \
  --bounding-set=-all \
  --inh-caps=-all \
  --ambient-caps=-all \
  -- bash "$@"
' bash "$WORKDIR_REAL" "$AGENT_UID" "$AGENT_GID" "$AGENT_HOME" "$PROXY_URL" "$CA_BUNDLE" "$SCRIPT_RUN_PATH" "${SCRIPT_ARGV[@]}"
AGENT_EXIT_CODE=$?
RUN_COMPLETED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
set -e

if [[ "$AGENT_EXIT_CODE" -ne 0 ]]; then
  note "script exited with code $AGENT_EXIT_CODE; continuing to verify receipts"
fi

finalize_recorder

if [[ -s "$EVIDENCE_EXPORT" ]]; then
  RECEIPT_COUNT="$(python3 - "$EVIDENCE_EXPORT" <<'PY'
import json
import sys

count = 0
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    for line in fh:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or entry.get("type") != "action_receipt":
            continue
        # Session open/close receipts are chain bookkeeping, not agent actions.
        # A receipt without an action record object is malformed, not an
        # action. audit-packet.sh applies the same rule so the counts agree.
        detail = entry.get("detail")
        record = detail.get("action_record") if isinstance(detail, dict) else None
        if not isinstance(record, dict) or record.get("session_control"):
            continue
        count += 1
print(count)
PY
)"
fi

# A chain holding only Pipelock's session open and close receipts records no
# agent action, so it is not evidence that anything was enforced. Keep the
# no-evidence contract: zero agent action receipts is an error verdict.
if [[ "$RECEIPT_COUNT" -eq 0 && "$VERIFIER_VERDICT" != "error" && "$VERIFIER_VERDICT" != "invalid" ]]; then
  VERIFIER_VERDICT="error"
  printf '\nno_agent_action_receipts; the chain holds only session receipts\n' >>"$VERIFIER_OUTPUT"
fi

# posture.json carries ONLY schema-allowed posture fields (sdk/audit-packet/v0.json
# § posture.additionalProperties: false). Run-context, policy, summary, and
# verifier inputs are passed to audit-packet.sh as flags so the posture file is
# a clean enforcement-only artifact.
POSTURE_NETNS="$NETNS" \
POSTURE_AGENT_USER="$AGENT_USER" \
POSTURE_AGENT_UID="$AGENT_UID" \
POSTURE_HOST_USER="$HOST_USER" \
POSTURE_HOST_UID="$HOST_UID" \
POSTURE_HOST_IP="$HOST_IP" \
POSTURE_AGENT_IP="$AGENT_IP" \
POSTURE_PROXY_URL="$PROXY_URL" \
POSTURE_SCRIPT_BASENAME="$SCRIPT_BASENAME" \
POSTURE_SCRIPT_ARG_COUNT="${#SCRIPT_ARGV[@]}" \
python3 - "$POSTURE_PATH" <<'PY'
import json
import os
import sys

# Enforcement claims for `linux_netns_iptables_setpriv`:
#   raw_socket_status: agent runs in a NETNS with `iptables -P OUTPUT DROP`
#     and setpriv `--bounding-set=-all`, so CAP_NET_RAW is dropped and any raw
#     socket egress would also hit the iptables drop.
#   docker_socket_status: /var/run/docker.sock is bind-mounted to /dev/null
#     inside the boundary mount namespace.
#   dns_udp_status: NETNS iptables drops UDP egress (only TCP to HOST_IP:8888
#     is allowed); ip6tables defaults to drop.
#   browser_proxy_status: HTTPS_PROXY/HTTP_PROXY exported and NO_PROXY unset
#     inside the boundary, and the netns has no other allowed TCP path.
#   websocket_frame_scanning: frame-level scanning fires only on the explicit
#     /ws?url= proxy path; arbitrary wss:// destinations are network-contained
#     but not frame-scanned.
posture = {
    "enforcement_mode": "linux_netns_iptables_setpriv",
    "runner_os": os.environ.get("RUNNER_OS", "Linux"),
    "runner_arch": os.environ.get("RUNNER_ARCH", ""),
    "raw_socket_status": "denied",
    "docker_socket_status": "masked",
    "dns_udp_status": "denied",
    "browser_proxy_status": "forced",
    "websocket_frame_scanning": "explicit_ws_proxy_path_required",
    "network_namespace": os.environ["POSTURE_NETNS"],
    "agent_user": os.environ["POSTURE_AGENT_USER"],
    "agent_uid": int(os.environ["POSTURE_AGENT_UID"]),
    "host_user": os.environ["POSTURE_HOST_USER"],
    "host_uid": int(os.environ["POSTURE_HOST_UID"]),
    "host_ip": os.environ["POSTURE_HOST_IP"],
    "agent_ip": os.environ["POSTURE_AGENT_IP"],
    "proxy_url": os.environ["POSTURE_PROXY_URL"],
    "script_basename": os.environ["POSTURE_SCRIPT_BASENAME"],
    "script_arg_count": int(os.environ["POSTURE_SCRIPT_ARG_COUNT"]),
    # Honest disclosure of paths the v0 boundary does not control. Lifted
    # verbatim from README "Out of scope" + "Fail-closed in v0" sections.
    "unsupported_paths": [
        "mcp_transports",
        "nested_docker",
        "non_proxy_browser_egress",
        "service_containers",
        "sibling_steps",
        "ssh_egress",
    ],
}
if not posture["runner_arch"]:
    posture.pop("runner_arch")
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(posture, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

"$ACTION_DIR/src/audit-packet.sh" \
  --receipt-chain "$EVIDENCE_EXPORT" \
  --verifier-output "$VERIFIER_OUTPUT" \
  --posture "$POSTURE_PATH" \
  --output-dir "$AUDIT_PACKET_DIR" \
  --run-started-at "$RUN_STARTED_AT" \
  --run-completed-at "$RUN_COMPLETED_AT" \
  --agent-identity "$AGENT_IDENTITY" \
  --agent-exit-code "$AGENT_EXIT_CODE" \
  --verifier-verdict "$VERIFIER_VERDICT" \
  --user-config-path "$CONFIG" \
  --runtime-config-path "$RUNTIME_CONFIG" \
  --config-snapshot-sha256 "$CONFIG_SNAPSHOT_SHA256" \
  --signer-public-key "$SIGNER_PUBLIC_KEY"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'audit_packet_path=%s\n' "$AUDIT_PACKET_DIR"
    printf 'receipt_count=%s\n' "$RECEIPT_COUNT"
    printf 'verifier_verdict=%s\n' "$VERIFIER_VERDICT"
  } >>"$GITHUB_OUTPUT"
fi

if [[ "$FAIL_ON_VERIFIER_ERROR" == "true" && "$VERIFIER_VERDICT" != "valid" ]]; then
  note "verifier verdict is $VERIFIER_VERDICT; failing because fail-on-verifier-error=true"
  exit 1
fi

exit "$AGENT_EXIT_CODE"
