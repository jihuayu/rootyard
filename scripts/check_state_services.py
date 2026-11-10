#!/usr/bin/env python3
"""Validate the checked-in W0 state-services documentation and configuration."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import state_services_checks as checks


def main():
    snapshot, producers, contract, budgets, dependencies = checks.validate_all()
    print(
        "PASS: design snapshot SHA-256 {}; {} producers; {} deployment profiles; "
        "{} provisional budgets; {} dependency candidates".format(
            snapshot["design_snapshot"]["checked_in_sha256"],
            len(producers["entries"]),
            len(contract["profiles"]),
            len(budgets["budgets"]),
            len(dependencies["candidates"]),
        )
    )


if __name__ == "__main__":
    main()
