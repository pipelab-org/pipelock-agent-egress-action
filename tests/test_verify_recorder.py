"""Exercise the production finalizer without users, sudo or network namespaces."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VerifyRecorderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="verify-recorder-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.evidence = self.work / "evidence with spaces"
        self.evidence.mkdir()
        (self.evidence / "evidence-proxy-run.jsonl").write_text("closed\n")
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
grep -q '^closed$' "$EVIDENCE_DIR/evidence-proxy-run.jsonl"
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
            HELPER=str(ROOT / "src/verify-recorder.sh"),
        )

    def write_executable(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o700)

    def run_finalizer(self, prelude=""):
        result = subprocess.run(
            ["bash", "-c", '''set -Eeuo pipefail
source "$HELPER"
trap stop_pipelock EXIT
''' + prelude + '''
finalize_recorder
[[ -z "$PIPELOCK_PID" ]]
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
                (self.evidence / "evidence-proxy-run.jsonl").unlink(missing_ok=True)
                if missing:
                    self.evidence.rmdir()
                self.assertEqual(self.run_finalizer(), "error")
                self.assertFalse((self.work / "argv").exists())

    def test_stop_reaps_writer_before_export_and_verification(self):
        writer = self.work / "writer.py"
        writer.write_text('''import signal
import sys
from pathlib import Path

path = Path(sys.argv[1]) / "evidence-proxy-run.jsonl"
def close(signum, frame):
    path.write_text("closed\\n")
    sys.exit(0)
signal.signal(signal.SIGTERM, close)
path.write_text("open\\n")
print("ready", flush=True)
while True:
    signal.pause()
''')
        fifo = self.work / "ready"
        os.mkfifo(fifo)
        self.env.update(WRITER=str(writer), READY_PIPE=str(fifo))
        self.assertEqual(self.run_finalizer('''
python3 "$WRITER" "$EVIDENCE_DIR" >"$READY_PIPE" &
PIPELOCK_PID=$!
read -r ready <"$READY_PIPE"
[[ "$ready" == ready ]]
'''), "valid")
        self.assertEqual((self.work / "export.jsonl").read_text(), "closed\n")
        self.assert_argv()


if __name__ == "__main__":
    unittest.main()
