
from uuid import UUID

import pytest

from backend.app.models.message import MessageType
from backend.app.orchestration.workflow import run_workflow


def test_three_agent_workflow():
    result = run_workflow("Research AI security")

    UUID(result["session_id"])

    messages = result["messages"]

    assert len(messages) == 3

    assert [m.sender_id for m in messages] == [
        "research_agent",
        "analysis_agent",
        "execution_agent",
    ]

    assert [m.message_type for m in messages] == [
        MessageType.INFORMATION,
        MessageType.ANALYSIS,
        MessageType.RESULT,
    ]

    assert "Research AI security" in result["final_output"]


def test_message_provenance_chain():
    result = run_workflow("Analyze prompt injection")

    messages = result["messages"]

    assert messages[0].parent_message_id is None

    assert (
        messages[1].parent_message_id
        == messages[0].message_id
    )

    assert (
        messages[2].parent_message_id
        == messages[1].message_id
    )

    assert len({m.message_id for m in messages}) == 3


def test_workflow_sessions_are_unique():
    first = run_workflow("Task A")
    second = run_workflow("Task B")

    assert first["session_id"] != second["session_id"]


def test_empty_task_is_rejected():
    with pytest.raises(ValueError, match="Task cannot be empty"):
        run_workflow("   ")


def test_workflow_output_is_not_empty():
    result = run_workflow("Test agent communication")

    assert result["final_output"].strip()
