from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


def canonical_args(arguments: dict) -> str:
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class ApprovalToken:
    action_id: str
    host_id: str
    tool: str
    arguments_hash: str
    issued_at: int
    expires_at: int
    nonce: str

    def payload(self) -> dict:
        return {"action_id":self.action_id,"host_id":self.host_id,"tool":self.tool,"arguments_hash":self.arguments_hash,"issued_at":self.issued_at,"expires_at":self.expires_at,"nonce":self.nonce}

    def encode(self, secret: str) -> str:
        raw=json.dumps(self.payload(),sort_keys=True,separators=(",",":")).encode(); body=base64.urlsafe_b64encode(raw).decode().rstrip("=")
        sig=hmac.new(secret.encode(),body.encode(),hashlib.sha256).hexdigest(); return body+"."+sig

    @classmethod
    def issue(cls, action_id: str, host_id: str, tool: str, arguments: dict, secret: str, ttl: int = 120) -> str:
        now=int(time.time()); token=cls(action_id,host_id,tool,hashlib.sha256(canonical_args(arguments).encode()).hexdigest(),now,now+ttl,secrets.token_urlsafe(18)); return token.encode(secret)

    @classmethod
    def verify(cls, encoded: str, secret: str, host_id: str, tool: str, arguments: dict) -> "ApprovalToken":
        try: body,sig=encoded.split(".",1); expected=hmac.new(secret.encode(),body.encode(),hashlib.sha256).hexdigest();
        except ValueError as exc: raise ValueError("malformed approval token") from exc
        if not hmac.compare_digest(sig,expected): raise ValueError("invalid approval signature")
        raw=base64.urlsafe_b64decode(body+"="*(-len(body)%4)); value=json.loads(raw); token=cls(**value)
        if token.host_id!=host_id or token.tool!=tool: raise ValueError("approval target mismatch")
        if token.expires_at < int(time.time()): raise ValueError("approval token expired")
        if token.arguments_hash != hashlib.sha256(canonical_args(arguments).encode()).hexdigest(): raise ValueError("approval arguments mismatch")
        return token
