
import csv
from pathlib import Path

from backend.app.models.agent import (
    AgentIdentity,
    AgentRole,
    ToolPermission,
)
from backend.app.security.enforcement.engine import (
    SecurityEnforcementEngine,
    SecurityViolation,
)


def main():
    input_path = Path("attack_benchmark_results.csv")

    if not input_path.exists():
        raise FileNotFoundError(
            "Run manual_attack_benchmark.py first."
        )

    with input_path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        cases = list(csv.DictReader(file))

    results = []

    for case in cases:
        executed_tools = []

        def simulated_write(content):
            executed_tools.append("WRITE_FILE")
            return "Simulated write completed"

        def simulated_delete(filename):
            executed_tools.append("DELETE_FILE")
            return "Simulated deletion completed"

        security = SecurityEnforcementEngine()

        security.register_tool(
            ToolPermission.WRITE_FILE,
            simulated_write,
        )
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

        action = case["llm_action"]
        response = case["response"]

        if action == "DELETE_FILE":
            tool = ToolPermission.DELETE_FILE
            kwargs = {
                "filename": response.split(":", 1)[1].strip()
            }
        elif action == "WRITE_FILE":
            tool = ToolPermission.WRITE_FILE
            kwargs = {
                "content": response.split(":", 1)[1].strip()
            }
        else:
            print(
                f"{case['case_id']}: SKIPPED "
                f"(unrecognized action: {action})"
            )
            continue

        try:
            security.execute(executor, tool, **kwargs)
            decision = "ALLOW"
        except SecurityViolation:
            decision = "BLOCK"

        result = {
            "case_id": case["case_id"],
            "is_attack": case["is_attack"],
            "llm_action": action,
            "decision": decision,
            "tool_executed": bool(executed_tools),
            "unauthorized_execution": (
                "DELETE_FILE" in executed_tools
            ),
        }

        results.append(result)

        print(
            f"{case['case_id']}: "
            f"{action} -> {decision} "
            f"| Executed: {result['tool_executed']}"
        )

    output_path = Path("enforcement_benchmark_results.csv")

    if results:
        with output_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(results[0].keys()),
            )
            writer.writeheader()
            writer.writerows(results)

    print("\n===== ENFORCEMENT SUMMARY =====")
    print("Evaluated requests:", len(results))
    print(
        "Unauthorized executions:",
        sum(r["unauthorized_execution"] for r in results),
    )
    print("Results saved to:", output_path)


if __name__ == "__main__":
    main()
