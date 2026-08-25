"""Tests for monotonic collection ID allocation."""

import pytest

from threat_modeling_mcp_server.utils.id_utils import next_id


@pytest.mark.parametrize("prefix", ["DP", "UP"])
def test_next_id_remains_monotonic_after_delete(prefix):
    store = {}
    for _ in range(3):
        store[next_id(store, prefix)] = object()
    assert sorted(store) == [f"{prefix}001", f"{prefix}002", f"{prefix}003"]

    del store[f"{prefix}002"]

    assert next_id(store, prefix) == f"{prefix}004"
