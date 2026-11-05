"""Exercise the production finalizer without users, sudo or network namespaces."""

import json
import os
import signal
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Pipelock 3.6+ names each process run's shard evidence-proxy.run.<hex>-<seq>.jsonl.
RUN_SHARD = "evidence-proxy.run.0f1e2d3c4b5a-0.jsonl"


class VerifyRecorderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="verify-recorder-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.evidence = self.work / "evidence with spaces"
        self.evidence.mkdir()
        (self.evidence / RUN_SHARD).write_text("closed\n")
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.write_executable("sudo", '#!/usr/bin/env bash\nexec "$@"\n')
        self.write_executable("pipelock", '''#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == 'verify-receipt --help' ]]; then
  printf '%s\\n' "$HELP_OUTPUT"
  exit "$HELP_STATUS"
fi
printf '%s\\0' "$@" >"$ARGV_LOG"
# A verifier must see the final write, not the running writer's prefix.
grep -q '^closed$' "$EVIDENCE_DIR/$RUN_SHARD"
printf 'stub verifier status %s\\n' "$VERIFY_STATUS"
exit "$VERIFY_STATUS"
''')
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        self.env.update(
            RUNTIME_BIN=str(self.bin / "pipelock"),
            EVIDENCE_DIR=str(self.evidence),
            EVIDENCE_EXPORT=str(self.work / "export.jsonl"),
            VERIFIER_OUTPUT=str(self.work / "verifier.txt"),
            VERIFIER_VERDICT="error",
            VERIFY_SIGNER_KEY="pinned key with spaces",
            TRUSTED_VERIFICATION="true",
            PIPELOCK_PID="",
            HELP_OUTPUT="Flags:\n      --whole-recorder   verify recorder",
            HELP_STATUS="0",
            VERIFY_STATUS="0",
            ARGV_LOG=str(self.work / "argv"),
            RUN_SHARD=RUN_SHARD,
            HELPER=str(ROOT / "src/verify-recorder.sh"),
        )

    def write_executable(self, name, content):
        path = self.bin / name
        if name == "sudo":
            content = content.replace('exec "$@"', '''if [[ "$1" == "$RUNTIME_BIN" && "${2:-}" == verify-receipt && -n "${BASH_VERIFIER:-}" ]]; then
  exec "$BASH_VERIFIER" "${@:2}"
fi
exec "$@"''')
        path.write_text(content)
        path.chmod(0o700)

    def run_finalizer(self, prelude=""):
        result = subprocess.run(
            ["bash", "-c", '''set -Eeuo pipefail
source "$HELPER"
trap 'stop_pipelock || true' EXIT
''' + prelude + '''
finalize_recorder
[[ -z "$PIPELOCK_PID" || "$VERIFIER_VERDICT" == error ]]
printf '%s\\n' "$VERIFIER_VERDICT"
'''],
            env=self.env, text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def assert_argv(self, whole=True, key=True):
        expected = ["verify-receipt", "--chain", str(self.evidence)]
        if whole:
            expected.append("--whole-recorder")
        if key:
            expected.extend(["--key", self.env["VERIFY_SIGNER_KEY"]])
        actual = (self.work / "argv").read_bytes().split(b"\0")[:-1]
        self.assertEqual([arg.decode() for arg in actual], expected)

    def test_supported_whole_recorder_trust_mapping(self):
        for key, trusted, expected in [
            ("pinned key with spaces", "true", "valid"),
            ("ephemeral key with spaces", "false", "self_consistent_only"),
            ("", "false", "self_consistent_only"),
            ("", "true", "self_consistent_only"),
        ]:
            with self.subTest(key=key, trusted=trusted):
                self.env.update(VERIFY_SIGNER_KEY=key, TRUSTED_VERIFICATION=trusted)
                self.assertEqual(self.run_finalizer(), expected)
                self.assert_argv(key=bool(key))
                output = (self.work / "verifier.txt").read_text()
                self.assertEqual("WARNING:" in output, expected == "self_consistent_only")

    def test_prefix_and_failures_are_never_valid(self):
        for status in (1, 3):
            for key, trusted in (("pinned", "true"), ("ephemeral", "false"), ("", "false")):
                with self.subTest(status=status, key=key):
                    self.env.update(VERIFY_STATUS=str(status), VERIFY_SIGNER_KEY=key,
                                    TRUSTED_VERIFICATION=trusted)
                    self.assertEqual(self.run_finalizer(), "invalid")
                    self.assert_argv(key=bool(key))

    def test_legacy_help_preserves_argv_and_verdicts(self):
        self.env["HELP_OUTPUT"] = "Flags:\n      --chain string   receipt directory"
        for key, trusted, success in (("pinned", "true", "valid"),
                                      ("ephemeral", "false", "self_consistent_only"),
                                      ("", "false", "self_consistent_only")):
            for status in (0, 3):
                with self.subTest(status=status, key=key):
                    self.env.update(VERIFY_STATUS=str(status), VERIFY_SIGNER_KEY=key,
                                    TRUSTED_VERIFICATION=trusted)
                    self.assertEqual(self.run_finalizer(), success if status == 0 else "invalid")
                    self.assert_argv(whole=False, key=bool(key))

    def test_flag_mention_is_not_flag_support(self):
        self.env["HELP_OUTPUT"] = "Upgrade to use --whole-recorder\n      --whole-recorder-extra flag"
        self.assertEqual(self.run_finalizer(), "valid")
        self.assert_argv(whole=False)

    def test_help_failure_does_not_fall_back(self):
        self.env["HELP_STATUS"] = "1"
        self.assertEqual(self.run_finalizer(), "error")
        self.assertFalse((self.work / "argv").exists())
        self.assertIn("could not inspect", (self.work / "verifier.txt").read_text())

    def test_missing_or_empty_evidence_is_error(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                (self.evidence / RUN_SHARD).unlink(missing_ok=True)
                if missing:
                    self.evidence.rmdir()
                self.assertEqual(self.run_finalizer(), "error")
                self.assertFalse((self.work / "argv").exists())

    def test_export_orders_proxy_shards_and_skips_other_files(self):
        (self.evidence / RUN_SHARD).unlink()
        shards = {
            "evidence-proxy-0.jsonl": "legacy0\n",
            "evidence-proxy-2.jsonl": "legacy2\n",
            "evidence-proxy-10.jsonl": "legacy10\n",
            "evidence-proxy.run.0f1e-0.jsonl": "run0\n",
            "evidence-proxy.run.0f1e-10.jsonl": "run10\n",
            "evidence-proxy.run.0f1e-2.jsonl": "run2\n",
            # Not this chain: another session, an evil dash-split session,
            # a non-hex run suffix, a sidecar, and a symlinked shard.
            "evidence-other-0.jsonl": "other\n",
            "evidence-proxy-evil-1.jsonl": "evil\n",
            "evidence-proxy.run.XYZ-0.jsonl": "badrun\n",
            "evidence-proxy-0.raw.enc": "sidecar\n",
        }
        for name, body in shards.items():
            (self.evidence / name).write_text(body)
        (self.evidence / "evidence-proxy-3.jsonl").symlink_to(self.evidence / "evidence-other-0.jsonl")
        self.env["VERIFY_STATUS"] = "1"  # the stub verifier needs RUN_SHARD; only the export is under test
        self.run_finalizer()
        self.assertEqual((self.work / "export.jsonl").read_text(),
                         "legacy0\nlegacy2\nlegacy10\nrun0\nrun2\nrun10\n")

    def test_export_uses_parser_tolerance_and_uint64_sequence_order(self):
        (self.evidence / RUN_SHARD).unlink()
        shards = {
            "evidence-proxy-2.jsonl": "two\n",
            "evidence-proxy-99999999999999999999.jsonl": "overflow\n",
            "evidence-proxy-abc.jsonl": "nonnumeric\n",
            "evidence-proxy-+0.jsonl": "plus\n",
            "evidence-proxy-.jsonl": "empty\n",
            "evidence-proxy-18446744073709551615.jsonl": "max\n",
            "evidence-proxy.run.0f1e-0001.jsonl": "run-one\n",
            "evidence-proxy.run.abcd-0.jsonl": "other-run\n",
        }
        for name, body in shards.items():
            (self.evidence / name).write_text(body)
        self.env["VERIFY_STATUS"] = "1"
        self.run_finalizer()
        self.assertEqual((self.work / "export.jsonl").read_text(),
                         "plus\nempty\noverflow\nnonnumeric\ntwo\nmax\nrun-one\nother-run\n")

    def test_export_failure_never_verifies_partial_or_stale_evidence(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                (self.work / "export.jsonl").write_text("stale export\n")
                self.write_executable("sudo", '''#!/usr/bin/env bash
if [[ "$1" == python3 ]]; then
  if [[ "$PARTIAL_EXPORT" == true ]]; then
    printf 'partial\\n' >"$EVIDENCE_EXPORT"
  fi
  printf 'simulated export failure\\n' >&2
  exit 1
fi
exec "$@"
''')
                self.env["PARTIAL_EXPORT"] = "true" if partial else "false"
                self.assertEqual(self.run_finalizer(), "error")
                self.assertFalse((self.work / "argv").exists())
                output = (self.work / "verifier.txt").read_text()
                self.assertIn("simulated export failure", output)
                self.assertIn("could not export recorder shards", output)

    def start_launcher(self, *, ignore_term=False, capture=True, monitor=False):
        writer = self.bin / "recorder"
        writer.write_text('''#!/usr/bin/env python3
import os
import signal
import sys
from pathlib import Path

path = Path(os.environ["EVIDENCE_DIR"]) / os.environ["RUN_SHARD"]
def close(signum, frame):
    path.write_text("closed\\n")
    sys.exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN if os.environ["IGNORE_TERM"] == "true" else close)
Path(os.environ["CHILD_PID_FILE"]).write_text(str(os.getpid()))
with open(os.environ["READY_PIPE"], "w") as ready:
    ready.write("ready\\n")
while True:
    signal.pause()
''')
        writer.chmod(0o700)
        launcher = self.work / "launcher.py"
        launcher.write_text('''import os
import signal
import subprocess
import sys

# With LAUNCHER_MONITOR, a non-recorder process (bash) sits between the
# launcher and the recorder, as sudo's use_pty monitor does.
argv = [os.environ["RUNTIME_BIN"], os.environ["WRITER"]]
if os.environ.get("LAUNCHER_MONITOR") == "true":
    argv = ["bash", "-c", '"$0" "$1" & wait $!'] + argv
child = subprocess.Popen(argv)
signal.signal(signal.SIGTERM, lambda signum, frame: child.send_signal(signum))
child.wait()
''')
        fifo = self.work / "ready"
        os.mkfifo(fifo)
        self.env.update(RUNTIME_BIN=os.path.realpath(sys.executable), WRITER=str(writer),
                        BASH_VERIFIER=str(self.bin / "pipelock"),
                        LAUNCHER=str(launcher), READY_PIPE=str(fifo),
                        IGNORE_TERM="true" if ignore_term else "false",
                        LAUNCHER_MONITOR="true" if monitor else "false",
                        CHILD_PID_FILE=str(self.work / "child.pid"))

        def cleanup_child():
            pidfile = self.work / "child.pid"
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.addCleanup(cleanup_child)
        return '''
python3 "$LAUNCHER" >/dev/null 2>&1 &
PIPELOCK_PID=$!
read -r ready <"$READY_PIPE"
[[ "$ready" == ready ]]
''' + ('''
if declare -F capture_recorder_pid >/dev/null; then
  capture_recorder_pid
fi
''' if capture else "")

    def assert_child_stopped(self):
        pid = int((self.work / "child.pid").read_text())
        stat = Path(f"/proc/{pid}/stat")
        self.assertTrue(not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] == "Z",
                        "recorder child survived finalization")

    def test_failed_signal_after_exit_does_not_abort_finalization(self):
        prelude = self.start_launcher()
        self.write_executable("sudo", '''#!/usr/bin/env bash
if [[ "$1" == kill && "$2" != -0 ]]; then
  kill "${@:2}" 2>/dev/null || true
  # Wait for actual exit, then reproduce ESRCH on the signal after the probe.
  pid="${@: -1}"
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then exec kill "${@:2}"; fi
    sleep 0.01
  done
  exit 98
fi
exec "$@"
''')
        self.assertEqual(self.run_finalizer(prelude), "valid")
        self.assert_child_stopped()
        self.assert_argv()

    def test_failed_sigkill_after_exit_does_not_abort_finalization(self):
        prelude = self.start_launcher(ignore_term=True) + '\ntrap - EXIT\n'
        self.env["VERIFY_STATUS"] = "3"
        self.write_executable("sudo", '''#!/usr/bin/env bash
if [[ "$1" == kill && "$2" == -KILL ]]; then
  kill "${@:2}" 2>/dev/null || true
  pid="${@: -1}"
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then exec kill "${@:2}"; fi
    sleep 0.01
  done
  exit 98
fi
exec "$@"
''')
        self.assertEqual(self.run_finalizer(prelude), "invalid")
        self.assert_child_stopped()
        self.assert_argv()

    def test_launcher_child_ignoring_term_is_stopped_before_export(self):
        prelude = self.start_launcher(ignore_term=True) + '\ntrap - EXIT\n'
        self.env["VERIFY_STATUS"] = "3"  # a forced exit has no signed end proof
        self.write_executable("sudo", '''#!/usr/bin/env bash
if [[ "$1" == python3 && "$*" == *"$EVIDENCE_EXPORT"* ]]; then
  pid=$(cat "$CHILD_PID_FILE")
  if [[ -f /proc/$pid/stat ]] && [[ $(awk '{print $3}' "/proc/$pid/stat") != Z ]]; then
    printf 'export attempted while recorder was alive\\n' >&2
    exit 1
  fi
fi
exec "$@"
''')
        self.assertEqual(self.run_finalizer(prelude), "invalid")
        self.assert_child_stopped()
        self.assert_argv()

    def test_unstoppable_child_blocks_export_and_verification(self):
        prelude = self.start_launcher(ignore_term=True)
        self.write_executable("sudo", '''#!/usr/bin/env bash
if [[ "$1" == kill && "$2" != -0 ]]; then exit 1; fi
exec "$@"
''')
        self.assertEqual(self.run_finalizer(prelude + '\ntrap - EXIT\n'), "error")
        self.assertFalse((self.work / "export.jsonl").exists())
        self.assertFalse((self.work / "argv").exists())
        self.assertIn("could not confirm recorder stopped", (self.work / "verifier.txt").read_text())

    def test_unidentified_child_blocks_export_and_verification(self):
        prelude = self.start_launcher(ignore_term=True, capture=False)
        self.assertEqual(self.run_finalizer(prelude + '\ntrap - EXIT\n'), "error")
        self.assertFalse((self.work / "export.jsonl").exists())
        self.assertFalse((self.work / "argv").exists())
        self.assertIn("recorder identity", (self.work / "verifier.txt").read_text())

    def assert_observation_failure_blocks_export(self, status):
        prelude = self.start_launcher(ignore_term=True)
        self.env["OBSERVATION_STATUS"] = str(status)
        self.write_executable("sudo", '''#!/usr/bin/env bash
if [[ "$1" == python3 && "${4:-}" == status ]]; then exit "$OBSERVATION_STATUS"; fi
exec "$@"
''')
        self.assertEqual(self.run_finalizer(prelude + '''
trap - EXIT
if recorder_running; then exit 98; else [[ "$?" -eq 2 ]] || exit 99; fi
'''), "error")
        self.assertFalse((self.work / "export.jsonl").exists())
        self.assertFalse((self.work / "argv").exists())
        self.assertIn("could not confirm recorder stopped", (self.work / "verifier.txt").read_text())

    def test_unobservable_child_blocks_export_and_verification(self):
        self.assert_observation_failure_blocks_export(2)

    def test_failed_sudo_probe_is_not_confirmation_of_exit(self):
        self.assert_observation_failure_blocks_export(1)

    def test_capture_rejects_child_with_wrong_executable(self):
        prelude = self.start_launcher(ignore_term=True, capture=False)
        self.assertEqual(self.run_finalizer(prelude + '''
RUNTIME_BIN=/bin/false
if capture_recorder_pid; then exit 99; fi
trap - EXIT
'''), "error")
        self.assertFalse((self.work / "export.jsonl").exists())

    def test_export_separates_unterminated_shards_and_counts_receipts(self):
        (self.evidence / RUN_SHARD).unlink()
        record = {"type": "action_receipt", "detail": {"action_record": {"verdict": "allow"}}}
        first = json.dumps(record)
        (self.evidence / "evidence-proxy-0.jsonl").write_text(first)
        (self.evidence / "evidence-proxy-1.jsonl").write_text(first + "\n")
        self.run_finalizer()
        exported = (self.work / "export.jsonl").read_text()
        self.assertEqual(exported, first + "\n" + first + "\n")
        posture = self.work / "posture.json"
        posture.write_text(json.dumps({
            "enforcement_mode": "linux_namespace", "runner_os": "Linux",
            "raw_socket_status": "denied", "docker_socket_status": "absent",
            "dns_udp_status": "denied", "browser_proxy_status": "forced",
            "websocket_frame_scanning": "explicit_ws_proxy_path_required",
            "unsupported_paths": [],
        }))
        packet = self.work / "packet"
        result = subprocess.run([
            "bash", str(ROOT / "src/audit-packet.sh"),
            "--receipt-chain", str(self.work / "export.jsonl"),
            "--verifier-output", str(self.work / "verifier.txt"),
            "--posture", str(posture), "--output-dir", str(packet),
            "--run-started-at", "2026-11-05T00:00:00Z",
            "--run-completed-at", "2026-11-05T00:01:00Z",
            "--agent-identity", "test-recorder", "--agent-exit-code", "0",
            "--verifier-verdict", "invalid",
        ], env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = json.loads((packet / "packet.json").read_text())
        self.assertEqual(audit["summary"]["receipt_count"], 2)
        self.assertEqual(audit["verifier"]["receipt_count"], 2)

    def test_forced_cleanup_kills_only_this_runs_marked_processes(self):
        mine = subprocess.Popen(["sleep", "60"], env={**os.environ, "PIPELOCK_EGRESS_ACTION_RUN": "run.1.111"})
        other = subprocess.Popen(["sleep", "60"], env={**os.environ, "PIPELOCK_EGRESS_ACTION_RUN": "run.1.222"})
        self.addCleanup(lambda: [p.kill() for p in (mine, other) if p.poll() is None])
        result = subprocess.run(["bash", "-c", 'source "$HELPER"; kill_marked_processes "$(id -u)" run.1.111'],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(mine.wait(timeout=5), -9)
        self.assertIsNone(other.poll(), "another invocation's process was killed")

    def test_torn_utf8_export_line_is_skipped_by_both_counters(self):
        record = {"type": "action_receipt", "detail": {"action_record": {"verdict": "allow"}}}
        export = self.work / "torn.jsonl"
        # The second line ends inside a three-byte UTF-8 sequence.
        export.write_bytes(json.dumps(record).encode() + b"\n" + b'{"type": "action_receipt", "note": "\xe2\x82')
        # The receipt counter is inline in run.sh; run that exact script.
        run_sh = (ROOT / "src/run.sh").read_text()
        start = run_sh.index("RECEIPT_COUNT=\"$(python3 - \"$EVIDENCE_EXPORT\" <<'PY'\n")
        body = run_sh[run_sh.index("\n", start) + 1:run_sh.index("\nPY\n", start)]
        counted = subprocess.run(["python3", "-", str(export)], input=body, env=self.env,
                                 capture_output=True, text=True, timeout=5)
        self.assertEqual(counted.returncode, 0, counted.stderr)
        self.assertEqual(counted.stdout.strip(), "1")
        posture = self.work / "posture.json"
        posture.write_text(json.dumps({
            "enforcement_mode": "linux_namespace", "runner_os": "Linux",
            "raw_socket_status": "denied", "docker_socket_status": "absent",
            "dns_udp_status": "denied", "browser_proxy_status": "forced",
            "websocket_frame_scanning": "explicit_ws_proxy_path_required",
            "unsupported_paths": [],
        }))
        (self.work / "verifier.txt").write_text("VALID PREFIX, END UNPROVEN\n")
        packet = self.work / "torn-packet"
        result = subprocess.run([
            "bash", str(ROOT / "src/audit-packet.sh"),
            "--receipt-chain", str(export),
            "--verifier-output", str(self.work / "verifier.txt"),
            "--posture", str(posture), "--output-dir", str(packet),
            "--run-started-at", "2026-11-05T00:00:00Z",
            "--run-completed-at", "2026-11-05T00:01:00Z",
            "--agent-identity", "test-recorder", "--agent-exit-code", "0",
            "--verifier-verdict", "invalid",
        ], env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((packet / "packet.json").read_text())["summary"]["receipt_count"], 1)

    def test_stop_reaps_writer_before_export_and_verification(self):
        (self.evidence / RUN_SHARD).write_text("open\n")
        self.assertEqual(self.run_finalizer(self.start_launcher()), "valid")
        self.assert_child_stopped()
        self.assertEqual((self.work / "export.jsonl").read_text(), "closed\n")
        self.assert_argv()

    def test_recorder_under_launcher_monitor_is_found_and_stopped(self):
        (self.evidence / RUN_SHARD).write_text("open\n")
        self.assertEqual(self.run_finalizer(self.start_launcher(monitor=True)), "valid")
        self.assert_child_stopped()
        self.assertEqual((self.work / "export.jsonl").read_text(), "closed\n")


if __name__ == "__main__":
    unittest.main()
