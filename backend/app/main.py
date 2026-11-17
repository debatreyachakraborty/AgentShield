
from datetime import datetime, timezone

from fastapi import FastAPI

app = FastAPI(
    title="AgentShield API",
    description="Multi-Agent Security Testing and Runtime Protection Platform",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "application": "AgentShield",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "agentshield-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
