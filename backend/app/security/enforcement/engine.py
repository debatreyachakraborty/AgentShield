
from collections.abc import Callable
from typing import Any

from backend.app.models.agent import (
    AgentIdentity,
    ToolAccessRequest,
    ToolPermission,
    check_tool_permission,
)


class SecurityViolation(Exception):
    """Raised when an agent attempts an unauthorized action."""


class SecurityEnforcementEngine:
    def __init__(self):
        self._tools: dict[ToolPermission, Callable[..., Any]] = {}

    def register_tool(
        self,
        tool: ToolPermission,
        handler: Callable[..., Any],
    ) -> None:
        if not callable(handler):
            raise TypeError("Tool handler must be callable.")

        self._tools[tool] = handler

    def execute(
        self,
        agent: AgentIdentity,
        tool: ToolPermission,
        **kwargs: Any,
    ) -> Any:
        request = ToolAccessRequest(
            agent_id=agent.agent_id,
            requested_tool=tool,
        )

        decision = check_tool_permission(agent, request)

        if not decision.allowed:
            raise SecurityViolation(decision.reason)

        handler = self._tools.get(tool)

        if handler is None:
            raise SecurityViolation(
                f"Tool '{tool.value}' is not registered."
            )

        return handler(**kwargs)
