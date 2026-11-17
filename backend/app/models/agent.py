
from enum import Enum

from pydantic import BaseModel, Field


class AgentRole(str, Enum):
    RESEARCHER = "researcher"
    ANALYST = "analyst"
    EXECUTOR = "executor"


class ToolPermission(str, Enum):
    WEB_SEARCH = "web_search"
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    EXECUTE_CODE = "execute_code"
    DELETE_FILE = "delete_file"


class AgentIdentity(BaseModel):
    agent_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    role: AgentRole
    allowed_tools: set[ToolPermission] = Field(default_factory=set)


class ToolAccessRequest(BaseModel):
    agent_id: str
    requested_tool: ToolPermission


class PermissionDecision(BaseModel):
    allowed: bool
    reason: str


def check_tool_permission(
    agent: AgentIdentity,
    request: ToolAccessRequest,
) -> PermissionDecision:

    if agent.agent_id != request.agent_id:
        return PermissionDecision(
            allowed=False,
            reason="Agent identity mismatch.",
        )

    if request.requested_tool not in agent.allowed_tools:
        return PermissionDecision(
            allowed=False,
            reason=(
                f"Agent '{agent.agent_id}' is not authorized "
                f"to use '{request.requested_tool.value}'."
            ),
        )

    return PermissionDecision(
        allowed=True,
        reason="Tool access authorized.",
    )
