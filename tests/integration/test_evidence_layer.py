"""End-to-end test for the Evidence Layer.

Verifies:
  1. The baseline script correctly captures a synthetic evidence directory.
  2. Tampering with the source is detectable by re-running the script with --verify.
  3. Skipped: kernel-level read-only mount enforcement (requires sudo, tested manually).

The mount script test is documented as a manual procedure because the test
harness does not have sudo. The architecture document's spoliation test plan
(§13) covers the in-process verification of read-only enforcement.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_SCRIPT = REPO_ROOT / "scripts" / "baseline_evidence.py"


def run_baseline(case_id: str, evidence_root: Path, baseline_dir: Path,
                 verify: bool = False) -> subprocess.CompletedProcess[str]:
    """Invoke the baseline script and return the completed process."""
    cmd = [
        sys.executable, str(BASELINE_SCRIPT), case_id,
        "--evidence-root", str(evidence_root),
        "--baseline-dir", str(baseline_dir),
    ]
    if verify:
        cmd.append("--verify")
    return subprocess.run(cmd, capture_output=True, text=True)


def main() -> int:
    """Run the test. Returns 0 on success, 1 on failure."""
    case_id = "test_case_001"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        evidence_root_parent = tmp / "evidence"
        evidence_case = evidence_root_parent / case_id
        evidence_case.mkdir(parents=True)
        baseline_dir = tmp / "baselines"

        # Populate with synthetic forensic-shaped files.
        (evidence_case / "Windows" / "System32" / "config").mkdir(parents=True)
        (evidence_case / "Windows" / "System32" / "config" / "SOFTWARE").write_bytes(
            b"Synthetic SOFTWARE hive contents (registry data goes here)."
        )
        (evidence_case / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(
            b"Synthetic SYSTEM hive contents."
        )
        (evidence_case / "Users" / "admin").mkdir(parents=True)
        (evidence_case / "Users" / "admin" / "NTUSER.DAT").write_bytes(
            b"Synthetic per-user registry hive."
        )

        # Phase 1: build the baseline.
        result = run_baseline(case_id, evidence_root_parent, baseline_dir, verify=False)
        if result.returncode != 0:
            print("FAIL: baseline build returned non-zero", file=sys.stderr)
            print(f"stdout: {result.stdout}", file=sys.stderr)
            print(f"stderr: {result.stderr}", file=sys.stderr)
            return 1
        print("OK: baseline build succeeded")

        # Phase 2: inspect the baseline file.
        baseline_path = baseline_dir / f"{case_id}_baseline.json"
        if not baseline_path.is_file():
            print(f"FAIL: baseline file not created at {baseline_path}", file=sys.stderr)
            return 1
        baseline = json.loads(baseline_path.read_text())
        if baseline["total_files"] != 3:
            print(f"FAIL: expected 3 files, got {baseline['total_files']}", file=sys.stderr)
            return 1
        if baseline["algorithm"] != "sha256":
            print(f"FAIL: algorithm field wrong: {baseline['algorithm']}", file=sys.stderr)
            return 1
        expected_paths = {
            "Users/admin/NTUSER.DAT",
            "Windows/System32/config/SOFTWARE",
            "Windows/System32/config/SYSTEM",
        }
        actual_paths = {f["path"] for f in baseline["files"]}
        if actual_paths != expected_paths:
            print(f"FAIL: paths mismatch. Expected {expected_paths}, got {actual_paths}", file=sys.stderr)
            return 1
        print(f"OK: baseline schema valid, captured 3 expected files")

        # Phase 3: verify with no changes — should pass.
        result = run_baseline(case_id, evidence_root_parent, baseline_dir, verify=True)
        if result.returncode != 0:
            print(f"FAIL: clean verify returned non-zero", file=sys.stderr)
            print(f"stderr: {result.stderr}", file=sys.stderr)
            return 1
        print("OK: clean verify passes")

        # Phase 4: tamper with one file — verify should detect it.
        tampered_file = evidence_case / "Windows" / "System32" / "config" / "SOFTWARE"
        tampered_file.write_bytes(b"TAMPERED CONTENT -- original bytes overwritten.")
        result = run_baseline(case_id, evidence_root_parent, baseline_dir, verify=True)
        if result.returncode == 0:
            print("FAIL: tampering was NOT detected by verify", file=sys.stderr)
            return 1
        if "MODIFIED" not in result.stderr or "Windows/System32/config/SOFTWARE" not in result.stderr:
            print(f"FAIL: verify reported failure but did not name the modified file", file=sys.stderr)
            print(f"stderr: {result.stderr}", file=sys.stderr)
            return 1
        print("OK: tampering correctly detected")

        # Phase 5: add a new file — verify should detect it as ADDED.
        # First, restore the tampered file so we isolate the new-file detection.
        tampered_file.write_bytes(b"Synthetic SOFTWARE hive contents (registry data goes here).")
        (evidence_case / "Users" / "admin" / "Documents").mkdir(parents=True)
        (evidence_case / "Users" / "admin" / "Documents" / "secret.txt").write_bytes(b"new file")
        result = run_baseline(case_id, evidence_root_parent, baseline_dir, verify=True)
        if result.returncode == 0:
            print("FAIL: added file was NOT detected by verify", file=sys.stderr)
            return 1
        if "ADDED" not in result.stderr or "Users/admin/Documents/secret.txt" not in result.stderr:
            print(f"FAIL: verify reported failure but did not name the added file", file=sys.stderr)
            print(f"stderr: {result.stderr}", file=sys.stderr)
            return 1
        print("OK: added file correctly detected")

    print("=" * 60)
    print("EVIDENCE LAYER TEST PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
