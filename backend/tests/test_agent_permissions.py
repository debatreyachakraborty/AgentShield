
import pytest
from pydantic import ValidationError

from backend.app.models.agent import (
    AgentIdentity,
    AgentRole,
    ToolPermission,
    ToolAccessRequest,
    check_tool_permission,
)


@pytest.fixture
def research_agent():
    return AgentIdentity(
        agent_id="agent_001",
        name="Research Agent",
        role=AgentRole.RESEARCHER,
        allowed_tools={
            ToolPermission.WEB_SEARCH,
            ToolPermission.READ_FILE,
        },
    )


def test_authorized_tool_access(research_agent):
    request = ToolAccessRequest(
        agent_id="agent_001",
        requested_tool=ToolPermission.WEB_SEARCH,
    )

    decision = check_tool_permission(research_agent, request)

    assert decision.allowed is True


def test_unauthorized_tool_access(research_agent):
    request = ToolAccessRequest(
        agent_id="agent_001",
        requested_tool=ToolPermission.DELETE_FILE,
    )

    decision = check_tool_permission(research_agent, request)

    assert decision.allowed is False
    assert "not authorized" in decision.reason


def test_agent_identity_mismatch(research_agent):
    request = ToolAccessRequest(
        agent_id="agent_999",
        requested_tool=ToolPermission.WEB_SEARCH,
    )

    decision = check_tool_permission(research_agent, request)

    assert decision.allowed is False
    assert decision.reason == "Agent identity mismatch."


def test_agent_has_no_permissions_by_default():
    agent = AgentIdentity(
        agent_id="agent_002",
        name="New Agent",
        role=AgentRole.ANALYST,
    )

    assert agent.allowed_tools == set()


def test_invalid_agent_role():
    with pytest.raises(ValidationError):
        AgentIdentity(
            agent_id="agent_003",
            name="Invalid Agent",
            role="super_admin",
        )
