
from backend.app.attacks.simulator import (
    simulate_unauthorized_tool_attack,
)

from backend.app.models.agent import ToolPermission


def test_attack_is_blocked():
    result = simulate_unauthorized_tool_attack()

    assert result.blocked is True


def test_unauthorized_tool_never_executes():
    result = simulate_unauthorized_tool_attack()

    assert result.tool_executed is False


def test_attack_targets_delete_file():
    result = simulate_unauthorized_tool_attack()

    assert result.requested_tool == ToolPermission.DELETE_FILE


def test_attack_contains_malicious_instruction():
    result = simulate_unauthorized_tool_attack()

    assert "Ignore previous instructions" in result.payload


def test_block_reason_identifies_unauthorized_access():
    result = simulate_unauthorized_tool_attack()

    assert "not authorized" in result.reason
