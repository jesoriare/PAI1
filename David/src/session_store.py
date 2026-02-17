from dataclasses import dataclass, field
from typing import Dict, Set, Optional


@dataclass
class Session:
    username: str
    session_key_hex: str
    seen_nonces: Set[str] = field(default_factory=set)


class SessionStore:
    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}

    def create(self, session_id: str, username: str, session_key_hex: str) -> None:
        self._sessions[session_id] = Session(username=username, session_key_hex=session_key_hex)

    def get(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def nonce_seen(self, session_id: str, nonce_hex: str) -> bool:
        s = self._sessions.get(session_id)
        if not s:
            return True
        return nonce_hex in s.seen_nonces

    def mark_nonce(self, session_id: str, nonce_hex: str) -> None:
        s = self._sessions.get(session_id)
        if not s:
            return
        s.seen_nonces.add(nonce_hex)
