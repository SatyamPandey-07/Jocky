import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "compiler"))

import pytest  # noqa: E402

EXAMPLES = ROOT / "examples"
LAB = EXAMPLES / "evidence" / "incident42_lab"


@pytest.fixture(scope="session")
def incident42_source() -> str:
    return (EXAMPLES / "incident_42.jocky").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def lab_dataset() -> Path:
    return LAB


@pytest.fixture(scope="session")
def signing_key():
    from jocky.contract import generate_key

    return generate_key()
