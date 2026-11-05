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

finalize_recorder() {
  # Stop and reap the writer before exporting or verifying: clean shutdown
  # writes the transcript root and trailing checkpoint that prove its end.
  stop_pipelock
  if ! sudo test -d "$EVIDENCE_DIR"; then
    VERIFIER_VERDICT="error"
    printf 'no evidence directory found: %s\n' "$EVIDENCE_DIR" >"$VERIFIER_OUTPUT"
  else
    sudo sh -c 'cat "$1"/evidence-proxy-*.jsonl > "$2" 2>/dev/null' sh "$EVIDENCE_DIR" "$EVIDENCE_EXPORT" || true
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
