from pathlib import Path

import pytest

from coveragekit import frameworks

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def attack():
    return frameworks.load("attack")


@pytest.fixture(scope="session")
def atlas():
    return frameworks.load("atlas")


@pytest.fixture()
def mini_attack():
    return frameworks.build_attack(FIXTURES / "mini-attack.json")
