
# AgentShield

### Multi-Agent Security Testing & Runtime Protection Platform

AgentShield is a Python-based security research prototype designed to simulate prompt-injection attacks in multi-agent AI workflows, evaluate security controls, and generate traceable evidence of security decisions.

The project currently uses deterministic agent simulations to demonstrate how malicious instructions can propagate across agent boundaries and how permission enforcement can block unauthorized tool operations.

## Problem Statement

Multi-agent AI systems exchange information and may use external tools to complete tasks. Untrusted content can contain malicious instructions that attempt to influence downstream agents.

AgentShield explores this security problem through controlled attack simulations, rule-based threat detection, message provenance tracking, and tool permission enforcement.

## Implemented Features

- **Multi-Agent Orchestration:** Three-agent Research → Analysis → Execution workflow built with LangGraph.
- **Attack Simulation:** Controlled cross-agent prompt-injection scenarios.
- **Threat Detection:** Rule-based detection of suspicious instructions with risk scoring.
- **Tool Permission Enforcement:** Agent-specific permissions that block unauthorized simulated tool operations.
- **Message Provenance Tracking:** Parent-child message relationships and inherited untrusted-content labels.
- **Security Audit Logging:** Structured records of message tracking, threat detection, and tool authorization decisions.
- **Automated Testing:** 60 passing tests covering security components and workflow integration.

## Technology Stack

- Python 3.12
- FastAPI
- LangGraph
- Pydantic
- pytest

## Current Architecture

```text
                  User Task
                      |
                      v
                Research Agent
                      |
                      v
                Analysis Agent
                (Threat Detection)
                      |
                      v
                Execution Agent
                (Tool Enforcement)
                      |
                      v
                Workflow Result

        Supporting Security Components
        ------------------------------
        - Message Provenance Tracker
        - Security Audit Logger
        - Attack Scenario Simulator
```

## Project Structure

```text
AgentShield/
├── backend/
│   ├── app/
│   │   ├── attacks/
│   │   ├── models/
│   │   ├── monitoring/
│   │   ├── orchestration/
│   │   └── security/
│   │       ├── detection/
│   │       ├── enforcement/
│   │       └── provenance/
│   └── tests/
├── .gitignore
└── README.md
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/debatreyachakraborty/AgentShield.git
cd AgentShield
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

The project currently does not include a pinned dependency manifest. Install the core packages:

```bash
python -m pip install fastapi uvicorn langgraph pydantic pytest httpx
```

### 4. Start the API

```bash
python -m uvicorn backend.app.main:app --reload
```

Visit:

- API documentation: http://127.0.0.1:8000/docs
- Health endpoint: http://127.0.0.1:8000/health

### 5. Run automated tests

```bash
python -m pytest backend/tests/ -v
```

## Current Limitations

AgentShield is under active development.

- Agents currently use deterministic simulation rather than live LLM inference.
- Attack scenarios are predefined.
- Threat detection uses manually defined rules, not a trained ML model.
- Tool operations are simulated.
- Audit events are generated in memory and are not tamper-resistant.
- The prototype has not yet been validated against real-world adversarial benchmarks.

## Planned Improvements

- Live LLM-based multi-agent workflows
- Broader prompt-injection attack datasets
- ML-based threat detection
- Persistent security event storage
- Security monitoring dashboard
- Comparative attack evaluation and reporting

## Author

[Debatreya Chakraborty](https://github.com/debatreyachakraborty)

## Project Status

Active development — security core prototype implemented.
