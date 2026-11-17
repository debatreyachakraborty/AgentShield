
import pytest

from backend.app.models.agent import (
    AgentIdentity,
    AgentRole,
    ToolPermission,
)

from backend.app.security.enforcement.engine import (
    SecurityEnforcementEngine,
    SecurityViolation,
)


@pytest.fixture
def engine():
    security = SecurityEnforcementEngine()

    security.register_tool(
        ToolPermission.WEB_SEARCH,
        lambda query: f"Search results for: {query}",
    )

    security.register_tool(
        ToolPermission.DELETE_FILE,
        lambda filename: f"Deleted: {filename}",
    )

    return security


@pytest.fixture
def research_agent():
    return AgentIdentity(
        agent_id="research_001",
        name="Research Agent",
        role=AgentRole.RESEARCHER,
        allowed_tools={
            ToolPermission.WEB_SEARCH,
        },
    )


def test_authorized_tool_execution(engine, research_agent):
    result = engine.execute(
        research_agent,
        ToolPermission.WEB_SEARCH,
        query="AI security",
    )

    assert result == "Search results for: AI security"


def test_unauthorized_tool_is_blocked(engine, research_agent):
    executed = []

    engine.register_tool(
        ToolPermission.DELETE_FILE,
        lambda filename: executed.append(filename),
    )

    with pytest.raises(SecurityViolation):
        engine.execute(
            research_agent,
            ToolPermission.DELETE_FILE,
            filename="important.txt",
        )

    assert executed == []


def test_unregistered_tool_is_blocked(engine, research_agent):
    research_agent.allowed_tools.add(ToolPermission.READ_FILE)

    with pytest.raises(SecurityViolation, match="not registered"):
        engine.execute(
            research_agent,
            ToolPermission.READ_FILE,
            filename="report.txt",
        )


def test_invalid_tool_handler_is_rejected(engine):
    with pytest.raises(TypeError):
        engine.register_tool(
            ToolPermission.READ_FILE,
            "not_a_function",
        )


def test_agent_without_permissions_is_blocked(engine):
    agent = AgentIdentity(
        agent_id="new_001",
        name="New Agent",
        role=AgentRole.ANALYST,
    )

    with pytest.raises(SecurityViolation):
        engine.execute(
            agent,
            ToolPermission.WEB_SEARCH,
            query="test",
        )
