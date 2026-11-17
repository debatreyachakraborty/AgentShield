
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class MessageType(str, Enum):
    TASK = "task"
    INFORMATION = "information"
    ANALYSIS = "analysis"
    ACTION_REQUEST = "action_request"
    RESULT = "result"


class AgentMessage(BaseModel):
    message_id: str = Field(
        default_factory=lambda: str(uuid4())
    )

    sender_id: str
    recipient_id: str
    message_type: MessageType
    content: str

    parent_message_id: str | None = None

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    metadata: dict = Field(default_factory=dict)
