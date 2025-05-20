#!/usr/bin/env python
"""
Simple in-memory event store for MCP connection management.
"""


class SimpleEventStore:
    """
    Simple in-memory event store for session management.

    This provides basic event persistence capability for streamable HTTP connections,
    allowing clients to recover missed events after reconnection.
    """

    def __init__(self, max_events=1000):
        self.events = {}
        self.max_events = max_events

    async def store_event(self, session_id, event_id, event_data):
        if session_id not in self.events:
            self.events[session_id] = []

        self.events[session_id].append((event_id, event_data))

        # Trim events if needed
        if len(self.events[session_id]) > self.max_events:
            self.events[session_id] = self.events[session_id][-self.max_events :]

    async def get_events_since(self, session_id, last_event_id=None):
        if session_id not in self.events:
            return []

        if not last_event_id:
            return self.events[session_id]

        # Find the index of the last event
        for i, (event_id, _) in enumerate(self.events[session_id]):
            if event_id == last_event_id:
                return self.events[session_id][i + 1 :]

        # If not found, return all events
        return self.events[session_id]

    async def cleanup_session(self, session_id):
        if session_id in self.events:
            del self.events[session_id]
