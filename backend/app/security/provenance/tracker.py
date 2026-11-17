
from pydantic import BaseModel, Field

from backend.app.models.message import AgentMessage


class ProvenanceRecord(BaseModel):
    message_id: str
    sender_id: str
    recipient_id: str
    parent_message_id: str | None
    is_untrusted: bool
    origin_message_id: str


class ProvenanceTracker:
    def __init__(self):
        self.records: dict[str, ProvenanceRecord] = {}

    def track_message(
        self,
        message: AgentMessage,
    ) -> ProvenanceRecord:

        if message.message_id in self.records:
            raise ValueError("Message already tracked.")

        parent = None

        if message.parent_message_id is not None:
            parent = self.records.get(
                message.parent_message_id
            )

            if parent is None:
                raise ValueError(
                    "Parent message must be tracked first."
                )

        is_untrusted = bool(
            message.metadata.get("untrusted_content", False)
        )

        if parent is not None:
            is_untrusted = is_untrusted or parent.is_untrusted

        origin_message_id = (
            parent.origin_message_id
            if parent is not None
            else message.message_id
        )

        record = ProvenanceRecord(
            message_id=message.message_id,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            parent_message_id=message.parent_message_id,
            is_untrusted=is_untrusted,
            origin_message_id=origin_message_id,
        )

        self.records[message.message_id] = record

        return record

    def trace_origin(
        self,
        message_id: str,
    ) -> ProvenanceRecord:

        record = self.records.get(message_id)

        if record is None:
            raise ValueError("Unknown message ID.")

        return self.records[record.origin_message_id]

    def get_chain(
        self,
        message_id: str,
    ) -> list[ProvenanceRecord]:

        chain = []
        visited = set()

        while message_id is not None:
            if message_id in visited:
                raise ValueError("Provenance cycle detected.")

            visited.add(message_id)

            record = self.records.get(message_id)

            if record is None:
                raise ValueError("Broken provenance chain.")

            chain.append(record)
            message_id = record.parent_message_id

        return list(reversed(chain))
