
from backend.app.monitoring.audit import (
    AuditEventType,
    SecurityAuditLogger,
)
from backend.app.security.provenance.tracker import (
    ProvenanceTracker,
)
from backend.app.security.detection.detector import (
    assess_threat,
)
from typing import TypedDict
from uuid import uuid4

from langgraph.graph import StateGraph, START, END

from backend.app.attacks.scenarios import (
    get_attack_scenario,
)
from backend.app.models.agent import (
    AgentIdentity,
    AgentRole,
    ToolPermission,
)
from backend.app.models.message import (
    AgentMessage,
    MessageType,
)
from backend.app.security.enforcement.engine import (
    SecurityEnforcementEngine,
    SecurityViolation,
)



class WorkflowState(TypedDict):
    session_id: str
    task: str
    messages: list[AgentMessage]
    final_output: str
    tool_allowed: bool
    attack_scenario_id: str | None
    attack_detected: bool
    threat_detected: bool
    threat_score: float



def research_agent(state: WorkflowState) -> dict:
    content = f"Research findings for: {state['task']}"
    metadata = {"source": "simulated_research"}

    if state["attack_scenario_id"]:
        scenario = get_attack_scenario(
            state["attack_scenario_id"]
        )
        content += f"\n\n{scenario.payload}"
        metadata["untrusted_content"] = True
        metadata["attack_scenario_id"] = scenario.scenario_id

    message = AgentMessage(
        sender_id="research_agent",
        recipient_id="analysis_agent",
        message_type=MessageType.INFORMATION,
        content=content,
        metadata=metadata,
    )

    return {"messages": state["messages"] + [message]}



def analysis_agent(state: WorkflowState) -> dict:
    previous = state["messages"][-1]

    assessment = assess_threat(previous.content)

    message = AgentMessage(
        sender_id="analysis_agent",
        recipient_id="execution_agent",
        message_type=MessageType.ANALYSIS,
        content=f"Analysis of: {previous.content}",
        parent_message_id=previous.message_id,
        metadata={
            "inherited_untrusted_content": previous.metadata.get(
                "untrusted_content", False
            ),
            "threat_detected": assessment.suspicious,
            "threat_score": assessment.risk_score,
            "threat_level": assessment.threat_level.value,
            "matched_rules": [
                finding.rule_id
                for finding in assessment.findings
            ],
        },
    )

    return {
        "messages": state["messages"] + [message],
        "threat_detected": assessment.suspicious,
        "threat_score": assessment.risk_score,
    }



def execution_agent(state: WorkflowState) -> dict:
    previous = state["messages"][-1]

    security = SecurityEnforcementEngine()

    security.register_tool(
        ToolPermission.WRITE_FILE,
        lambda content: f"Simulated report saved: {content}",
    )

    security.register_tool(
        ToolPermission.DELETE_FILE,
        lambda filename: f"Simulated deletion: {filename}",
    )

    executor = AgentIdentity(
        agent_id="execution_agent",
        name="Execution Agent",
        role=AgentRole.EXECUTOR,
        allowed_tools={ToolPermission.WRITE_FILE},
    )

    requested_tool = ToolPermission.WRITE_FILE
    kwargs = {"content": previous.content}

    if state["attack_scenario_id"]:
        scenario = get_attack_scenario(
            state["attack_scenario_id"]
        )
        requested_tool = scenario.requested_tool
        kwargs = {"filename": "confidential_report.txt"}

    try:
        output = security.execute(
            executor,
            requested_tool,
            **kwargs,
        )
        allowed = True
    except SecurityViolation as error:
        output = f"BLOCKED: {error}"
        allowed = False

    message = AgentMessage(
        sender_id="execution_agent",
        recipient_id="system",
        message_type=MessageType.RESULT,
        content=output,
        parent_message_id=previous.message_id,
        metadata={
            "tool_allowed": allowed,
            "requested_tool": requested_tool.value,
        },
    )

    return {
        "messages": state["messages"] + [message],
        "final_output": output,
        "tool_allowed": allowed,
        "attack_detected": (
            bool(state["attack_scenario_id"]) and not allowed
        ),
    }


def build_workflow():
    graph = StateGraph(WorkflowState)

    graph.add_node("research", research_agent)
    graph.add_node("analysis", analysis_agent)
    graph.add_node("execution", execution_agent)

    graph.add_edge(START, "research")
    graph.add_edge("research", "analysis")
    graph.add_edge("analysis", "execution")
    graph.add_edge("execution", END)

    return graph.compile()


def run_workflow(
    task: str,
    attack_scenario_id: str | None = None,
) -> WorkflowState:
    if not isinstance(task, str) or not task.strip():
        raise ValueError("Task cannot be empty.")

    if attack_scenario_id is not None:
        get_attack_scenario(attack_scenario_id)

    workflow = build_workflow()

    initial_state: WorkflowState = {
        "session_id": str(uuid4()),
        "task": task,
        "messages": [],
        "final_output": "",
        "tool_allowed": False,
        "attack_scenario_id": attack_scenario_id,
        "attack_detected": False,
        "threat_detected": False,
        "threat_score": 0.0,
    }


    result = workflow.invoke(initial_state)

    tracker = ProvenanceTracker()

    for message in result["messages"]:
        tracker.track_message(message)

    result["provenance_chain"] = [
        record.model_dump()
        for record in tracker.get_chain(
            result["messages"][-1].message_id
        )
    ]

    result["untrusted_message_count"] = sum(
        record.is_untrusted
        for record in tracker.records.values()
    )

    audit_logger = SecurityAuditLogger()

    for message in result["messages"]:
        audit_logger.log_event(
            session_id=result["session_id"],
            event_type=AuditEventType.MESSAGE_TRACKED,
            agent_id=message.sender_id,
            description=f"Message sent to {message.recipient_id}",
            metadata={
                "message_id": message.message_id,
                "parent_message_id": message.parent_message_id,
            },
        )

    if result["threat_detected"]:
        audit_logger.log_event(
            session_id=result["session_id"],
            event_type=AuditEventType.THREAT_DETECTED,
            agent_id="analysis_agent",
            description="Suspicious content detected",
            metadata={
                "risk_score": result["threat_score"],
            },
        )

    audit_logger.log_event(
        session_id=result["session_id"],
        event_type=(
            AuditEventType.TOOL_ALLOWED
            if result["tool_allowed"]
            else AuditEventType.TOOL_BLOCKED
        ),
        agent_id="execution_agent",
        description=result["final_output"],
        metadata={
            "requested_tool": result["messages"][-1].metadata[
                "requested_tool"
            ],
        },
    )

    result["audit_events"] = audit_logger.export_events()

    return result
