
import pytest

from backend.app.models.message import (
    AgentMessage,
    MessageType,
)
from backend.app.security.provenance.tracker import (
    ProvenanceTracker,
)


def make_message(
    sender: str,
    recipient: str,
    parent_id: str | None = None,
    untrusted: bool = False,
) -> AgentMessage:
    return AgentMessage(
        sender_id=sender,
        recipient_id=recipient,
        message_type=MessageType.INFORMATION,
        content="Test message",
        parent_message_id=parent_id,
        metadata={"untrusted_content": untrusted},
    )


def test_root_message_is_tracked():
    tracker = ProvenanceTracker()
    message = make_message("research", "analysis")

    record = tracker.track_message(message)

    assert record.message_id == message.message_id
    assert record.origin_message_id == message.message_id
    assert record.is_untrusted is False


def test_untrusted_status_propagates():
    tracker = ProvenanceTracker()

    first = make_message(
        "research", "analysis", untrusted=True
    )
    second = make_message(
        "analysis", "execution", first.message_id
    )

    tracker.track_message(first)
    record = tracker.track_message(second)

    assert record.is_untrusted is True
    assert record.origin_message_id == first.message_id


def test_complete_message_chain():
    tracker = ProvenanceTracker()

    first = make_message(
        "research", "analysis", untrusted=True
    )
    second = make_message(
        "analysis", "execution", first.message_id
    )
    third = make_message(
        "execution", "system", second.message_id
    )

    for message in (first, second, third):
        tracker.track_message(message)

    chain = tracker.get_chain(third.message_id)

    assert [record.sender_id for record in chain] == [
        "research",
        "analysis",
        "execution",
    ]


def test_trace_origin():
    tracker = ProvenanceTracker()

    first = make_message("research", "analysis")
    second = make_message(
        "analysis", "execution", first.message_id
    )

    tracker.track_message(first)
    tracker.track_message(second)

    origin = tracker.trace_origin(second.message_id)

    assert origin.message_id == first.message_id


def test_missing_parent_is_rejected():
    tracker = ProvenanceTracker()

    message = make_message(
        "analysis",
        "execution",
        parent_id="nonexistent-message",
    )

    with pytest.raises(
        ValueError,
        match="Parent message must be tracked first",
    ):
        tracker.track_message(message)


def test_duplicate_message_is_rejected():
    tracker = ProvenanceTracker()
    message = make_message("research", "analysis")

    tracker.track_message(message)

    with pytest.raises(
        ValueError,
        match="Message already tracked",
    ):
        tracker.track_message(message)


def test_unknown_message_is_rejected():
    tracker = ProvenanceTracker()

    with pytest.raises(
        ValueError,
        match="Unknown message ID",
    ):
        tracker.trace_origin("unknown")
