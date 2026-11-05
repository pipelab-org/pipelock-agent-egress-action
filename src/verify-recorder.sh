#!/usr/bin/env bash
# Recorder finalization shared by the entrypoint and unprivileged tests.
# Uses the entrypoint's runtime paths, signer trust, PID and verdict variables.
# VERIFIER_VERDICT is consumed by run.sh after this sourced helper returns.
# shellcheck disable=SC2034

stop_pipelock() {
  if [[ -n "$PIPELOCK_PID" ]]; then
    if sudo kill -0 "$PIPELOCK_PID" >/dev/null 2>&1; then
      sudo kill "$PIPELOCK_PID" >/dev/null 2>&1
      for _ in $(seq 1 25); do
        sudo kill -0 "$PIPELOCK_PID" >/dev/null 2>&1 || break
        sleep 0.2
      done
      if sudo kill -0 "$PIPELOCK_PID" >/dev/null 2>&1; then
        sudo kill -KILL "$PIPELOCK_PID" >/dev/null 2>&1
      fi
    fi
    wait "$PIPELOCK_PID" >/dev/null 2>&1 || true
    PIPELOCK_PID=""
  fi
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
  sudo python3 -I - "$EVIDENCE_DIR" "$EVIDENCE_EXPORT" <<'PY' || true
import os
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
shard = re.compile(r"evidence-(proxy|proxy\.run\.[0-9a-f]+)-([0-9]+)\.jsonl")
found = []
for name in os.listdir(src):
    m = shard.fullmatch(name)
    if m and os.path.isfile(os.path.join(src, name)) and not os.path.islink(os.path.join(src, name)):
        found.append((m.group(1), int(m.group(2)), name))
with open(dst, "wb") as out:
    for _, _, name in sorted(found):
        with open(os.path.join(src, name), "rb") as fh:
            out.write(fh.read())
PY
}

finalize_recorder() {
  # Stop and reap the writer before exporting or verifying: clean shutdown
  # writes the transcript root and trailing checkpoint that prove its end.
  stop_pipelock
  if ! sudo test -d "$EVIDENCE_DIR"; then
    VERIFIER_VERDICT="error"
    printf 'no evidence directory found: %s\n' "$EVIDENCE_DIR" >"$VERIFIER_OUTPUT"
  else
    export_recorder_shards
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
