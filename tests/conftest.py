from pathlib import Path

import pytest

from datagen.generate import generate


@pytest.fixture(scope="session")
def dataset(tmp_path_factory) -> Path:
    """Full-scale default-seed dataset, generated once per test session."""
    out = tmp_path_factory.mktemp("data")
    generate(7, out)
    return out


@pytest.fixture
def anyio_backend():
    return "asyncio"
