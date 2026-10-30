"""Verify the public distribution name and stable import namespace."""

from importlib.metadata import metadata, version
from importlib.util import find_spec

import sentinel_interlock


def test_distribution_metadata_uses_kernveil_name() -> None:
    assert metadata("kernveil")["Name"] == "kernveil"
    assert version("kernveil") == sentinel_interlock.__version__


def test_existing_import_namespace_remains_available() -> None:
    assert find_spec("sentinel_interlock") is not None
