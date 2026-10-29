from pathlib import Path
import subprocess
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_portfolio_demo_reports_expected_synthetic_decisions() -> None:
    result = subprocess.run(
        [sys.executable, "examples/demo.py"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    output = result.stdout
    decisions = [
        line.removeprefix("Decision: ").strip()
        for line in output.splitlines()
        if line.startswith("Decision: ")
    ]

    assert decisions == ["ALLOW", "DENY", "DENY"]
    assert output.count("Evidence JSON:") == 3
    assert "section reported occupied" in output
    assert "stale context" in output
