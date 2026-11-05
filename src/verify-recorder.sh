#!/usr/bin/env bash
# Recorder finalization shared by the entrypoint and unprivileged tests.
# Uses the entrypoint's runtime paths, signer trust, PID and verdict variables.
# VERIFIER_VERDICT is consumed by run.sh after this sourced helper returns.
# shellcheck disable=SC2034

# Linux proc(5): stat field 22 is the process start time; a zombie cannot write.
# Keep it with the PID so a reused PID is never treated as our recorder.
recorder_process() {
  sudo python3 -I - "$1" "$PIPELOCK_PID" "$RUNTIME_BIN" "${RECORDER_PID:-}" "${RECORDER_START_TIME:-}" <<'PYPROC'
import os
from pathlib import Path
import sys

action, launcher, binary, recorder, started = sys.argv[1:]

def state(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return fields[0], fields[19]

try:
    if action == "capture":
        children = Path(f"/proc/{launcher}/task/{launcher}/children").read_text().split()
        matches = []
        for pid in children:
            try:
                before = state(pid)
                if os.path.samefile(f"/proc/{pid}/exe", binary):
                    if state(pid) == before and before[0] != "Z":
                        matches.append((pid, before[1]))
            except FileNotFoundError:
                continue
        if len(matches) != 1:
            sys.exit(2)
        print(*matches[0])
    else:
        current, birth = state(recorder)
        print("stopped" if birth != started or current == "Z" else "running")
except FileNotFoundError:
    if action == "status":
        print("stopped")
    else:
        sys.exit(2)
except (OSError, ValueError, IndexError):
    sys.exit(2)
PYPROC
}

capture_recorder_pid() {
  local identity
  if ! identity="$(recorder_process capture)"; then
    return 1
  fi
  read -r RECORDER_PID RECORDER_START_TIME <<<"$identity"
}

recorder_running() {
  local state
  # sudo and Python failures must never masquerade as a confirmed exit.
  if ! state="$(recorder_process status)"; then
    return 2
  fi
  case "$state" in
    running) return 0 ;;
    stopped) return 1 ;;
    *) return 2 ;;
  esac
}

stop_pipelock() {
  local status
  if [[ -z "$PIPELOCK_PID" ]]; then
    return 0
  fi
  if [[ -z "${RECORDER_PID:-}" || -z "${RECORDER_START_TIME:-}" ]]; then
    printf 'could not confirm recorder identity; refusing evidence export\n' >"$VERIFIER_OUTPUT"
    return 1
  fi
  if recorder_running; then
    # ESRCH between observation and signal is harmless; the status checks
    # below, rather than kill's exit code, decide whether stopping succeeded.
    sudo kill "$RECORDER_PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 25); do
      recorder_running || break
      sleep 0.2
    done
    if recorder_running; then
      sudo kill -KILL "$RECORDER_PID" >/dev/null 2>&1 || true
      # SIGKILL is asynchronous, so allow the kernel to finish the exit.
      for _ in $(seq 1 25); do
        recorder_running || break
        sleep 0.2
      done
    fi
  fi
  if recorder_running; then
    status=0
  else
    status=$?
  fi
  if [[ "$status" -ne 1 ]]; then
    printf 'could not confirm recorder stopped; refusing evidence export\n' >"$VERIFIER_OUTPUT"
    return 1
  fi
  wait "$PIPELOCK_PID" >/dev/null 2>&1 || true
  PIPELOCK_PID=""
  RECORDER_PID=""
  RECORDER_START_TIME=""
}

verify_recorder() {
  local help_output verify_status
  local -a verify_args=(verify-receipt --chain "$EVIDENCE_DIR")

  # Pipelock 3.6 added whole-recorder verification; older pinned binaries
  # retain their receipt-chain contract. A failed probe is not a legacy binary.
  if ! help_output="$(sudo "$RUNTIME_BIN" verify-receipt --help 2>&1)"; then
    VERIFIER_VERDICT="error"
    printf 'could not inspect verify-receipt support:\n%s\n' "$help_output" >"$VERIFIER_OUTPUT"
    return
  fi
  if grep -Eq '^[[:space:]]+--whole-recorder([[:space:]]|$)' <<<"$help_output"; then
    verify_args+=(--whole-recorder)
  fi
  if [[ -n "$VERIFY_SIGNER_KEY" ]]; then
    verify_args+=(--key "$VERIFY_SIGNER_KEY")
  fi

  # Only exit 0 is accepted. In particular, exit 3 means the chain end is
  # unproven, which Audit Packet v0 cannot represent as a separate verdict.
  if sudo "$RUNTIME_BIN" "${verify_args[@]}" >"$VERIFIER_OUTPUT" 2>&1; then
    verify_status=0
  else
    verify_status=$?
  fi
  if [[ "$verify_status" -ne 0 ]]; then
    VERIFIER_VERDICT="invalid"
  elif [[ -n "$VERIFY_SIGNER_KEY" && "$TRUSTED_VERIFICATION" == "true" ]]; then
    VERIFIER_VERDICT="valid"
  else
    VERIFIER_VERDICT="self_consistent_only"
    printf '\nWARNING: trusted evidence requires signer-public-key pinning; ephemeral signer proves chain self-consistency only.\n' >>"$VERIFIER_OUTPUT"
  fi
}

export_recorder_shards() {
  # Flatten the proxy session's shards, in sequence order, into the packet
  # copy. Shards are named evidence-<session>-<seq>.jsonl, where the session
  # is everything before the last dash. Pipelock before 3.6 records session
  # "proxy"; 3.6 and later record one "proxy.run.<hex>" session per process
  # start. Anything else in the directory is not part of this chain.
  sudo python3 -I - "$EVIDENCE_DIR" "$EVIDENCE_EXPORT" <<'PY'
import os
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
session_pattern = re.compile(r"proxy(?:\.run\.[0-9a-f]+)?")
found = []
for name in os.listdir(src):
    if not name.startswith("evidence-") or not name.endswith(".jsonl"):
        continue
    session, sep, tail = name[len("evidence-"):-len(".jsonl")].rpartition("-")
    if not sep or not session_pattern.fullmatch(session):
        continue
    # internal/evidencename.Parse uses Go's uint64 decimal parser and maps
    # invalid or overflowing tails to zero; ties sort by basename.
    digits = tail.lstrip("0") or "0"
    seq = 0
    if re.fullmatch(r"[0-9]+", tail) and len(digits) <= 20:
        parsed = int(digits)
        if parsed <= (1 << 64) - 1:
            seq = parsed
    path = os.path.join(src, name)
    if os.path.isfile(path) and not os.path.islink(path):
        found.append((session, seq, name))
with open(dst, "wb") as out:
    for _, _, name in sorted(found):
        with open(os.path.join(src, name), "rb") as fh:
            data = fh.read()
            out.write(data)
            if data and not data.endswith(b"\n"):
                out.write(b"\n")
PY
}

finalize_recorder() {
  # Stop and reap the writer before exporting or verifying: clean shutdown
  # writes the transcript root and trailing checkpoint that prove its end.
  if ! stop_pipelock; then
    VERIFIER_VERDICT="error"
    return
  fi
  if ! sudo test -d "$EVIDENCE_DIR"; then
    VERIFIER_VERDICT="error"
    printf 'no evidence directory found: %s\n' "$EVIDENCE_DIR" >"$VERIFIER_OUTPUT"
  else
    if ! export_recorder_shards 2>"$VERIFIER_OUTPUT"; then
      VERIFIER_VERDICT="error"
      printf '\ncould not export recorder shards; evidence copy is incomplete\n' >>"$VERIFIER_OUTPUT"
      return
    fi
    sudo chown "$(id -u):$(id -g)" "$EVIDENCE_EXPORT" >/dev/null 2>&1 || true
    sudo chmod 0600 "$EVIDENCE_EXPORT" >/dev/null 2>&1 || true
    if [[ ! -s "$EVIDENCE_EXPORT" ]]; then
      VERIFIER_VERDICT="error"
      printf 'no_signed_receipts_emitted; signing_key_path not configured or pipelock not invoked\n' >"$VERIFIER_OUTPUT"
    else
      verify_recorder
    fi
  fi
}
