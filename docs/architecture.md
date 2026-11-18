
# AgentShield — System Architecture

AgentShield is a multi-agent AI security prototype that combines prompt-injection detection, contextual analysis, LLM-assisted classification, and runtime tool authorization.

## 1. Multi-Agent Security Workflow

```mermaid
flowchart TD
    A["User Task"] --> B["Input Security Agent"]
    B --> C{"Input Allowed?"}

    C -->|No| X["Block and Stop"]
    C -->|Yes| D["Research Agent"]

    D --> E["Hybrid Security Gateway"]

    E --> F["Rule-Based Detection"]
    E --> G["Contextual Threat Detection"]
    E --> H["LLM-Assisted Classification"]

    F --> I{"Security Decision"}
    G --> I
    H --> I

    I -->|BLOCK / REVIEW / ERROR| X
    I -->|ALLOW| J["Analysis Agent"]

    J --> K["Execution Agent"]
    K --> L["Tool Permission Engine"]

    L --> M{"Authorized?"}
    M -->|No| N["Reject Tool Request"]
    M -->|Yes| O["Simulated Tool Execution"]

    O --> P["Workflow Result"]

    B -.-> Q["Audit Logging"]
    E -.-> Q
    L -.-> Q

    D -.-> R["Message Provenance"]
    J -.-> R
    K -.-> R
```

## 2. Security Layers

| Layer | Responsibility |
|---|---|
| Input Security | Screens initial tasks for suspicious instructions |
| Hybrid Gateway | Evaluates research output using security detection mechanisms |
| Contextual Detection | Identifies suspicious instruction patterns and contextual signals |
| LLM Classification | Uses a local LLM to assist security analysis |
| Tool Enforcement | Checks agent permissions before tool execution |
| Provenance | Tracks message relationships and untrusted-content propagation |
| Audit Logging | Records security-relevant workflow events |

## 3. Runtime Authorization Example

The following example illustrates the separate tool-enforcement mechanism.

```mermaid
flowchart TD
    A["LLM Output"] --> B["DELETE_FILE: confidential_report.txt"]
    B --> C["Parse Requested Action"]
    C --> D["Security Enforcement Engine"]
    D --> E{"DELETE_FILE Permission?"}
    E -->|No| F["BLOCK"]
    E -->|Yes| G["Execute Registered Tool Handler"]
    F --> H["No Deletion Executed"]
```

In the controlled experiment, the LLM generated an unauthorized deletion request.

The permission engine rejected that request because the execution agent lacked `DELETE_FILE` authorization.

No real file deletion was attempted.

## 4. Trust Boundaries

AgentShield distinguishes between:

- **Untrusted content:** Research notes, external information, and agent-generated text.
- **Security decisions:** Gateway assessments of potentially malicious instructions.
- **Tool authorization:** Permission checks applied independently of LLM-generated requests.

The experimental design demonstrates why detecting malicious instructions and enforcing tool permissions are separate security responsibilities.

## 5. Implementation Notes

- Multi-agent orchestration uses LangGraph.
- LLM-backed experiments use Ollama with `qwen2.5:3b`.
- Tool operations are simulated.
- Security audit records are maintained in memory.
- The benchmark uses five controlled cases.
- The architecture is a research prototype, not a production-certified security system.
