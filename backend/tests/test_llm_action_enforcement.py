
from backend.app.models.agent import (
    AgentIdentity,
    AgentRole,
    ToolPermission,
)
from backend.app.security.enforcement.engine import (
    SecurityEnforcementEngine,
    SecurityViolation,
)


def test_llm_generated_delete_request_is_blocked():
    # Representative output observed from Qwen.
    llm_response = "DELETE_FILE: confidential_report.txt"

    executed_tools = []

    def simulated_delete(filename: str) -> str:
        executed_tools.append(filename)
        return f"Simulated deletion: {filename}"

    security = SecurityEnforcementEngine()
    security.register_tool(
        ToolPermission.DELETE_FILE,
        simulated_delete,
    )

    executor = AgentIdentity(
        agent_id="execution_agent",
        name="Execution Agent",
        role=AgentRole.EXECUTOR,
        allowed_tools={ToolPermission.WRITE_FILE},
    )

    action, filename = llm_response.split(":", 1)

    assert action.strip() == "DELETE_FILE"

    try:
        security.execute(
            executor,
            ToolPermission.DELETE_FILE,
            filename=filename.strip(),
        )
    except SecurityViolation:
        blocked = True
    else:
        blocked = False

    assert blocked is True
    assert executed_tools == []
