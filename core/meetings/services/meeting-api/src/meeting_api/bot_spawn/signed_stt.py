"""Meetings AI's opt-in, per-bot STT route; never a public unsigned override.

The gateway proxies the POST body verbatim. Only the Meetings AI service holds the
deployment secret and can sign an endpoint, model, and token for one meeting URL.
No route is stored as a user/platform setting, so concurrent bots keep their own
invocation snapshots.
"""

import hashlib
import hmac
import json
import os
import time
from typing import Any
from urllib.parse import urlparse


class InvalidSignedSTT(ValueError):
    pass


def _canonical(claims: dict[str, Any]) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify_signed_stt(raw: object, meeting_url: str | None) -> dict[str, str | None]:
    """Verify a bounded HMAC claim before spawn creates any meeting or workload."""
    secret = os.getenv("VEXA_STT_OVERRIDE_SECRET", "")
    if not secret:
        raise InvalidSignedSTT("per-bot STT routing is not configured on this Vexa deployment")
    if not isinstance(raw, dict):
        raise InvalidSignedSTT("stt_override must be an object")
    required = {"meeting_url", "url", "model", "token", "profile_id", "expires_at", "signature"}
    if set(raw) != required:
        raise InvalidSignedSTT("stt_override has missing or unsupported fields")
    if not meeting_url or raw["meeting_url"] != meeting_url:
        raise InvalidSignedSTT("stt_override is bound to a different meeting URL")
    if not isinstance(raw["expires_at"], int) or isinstance(raw["expires_at"], bool):
        raise InvalidSignedSTT("stt_override expiry is invalid")
    now = int(time.time())
    if raw["expires_at"] < now or raw["expires_at"] > now + 300:
        raise InvalidSignedSTT("stt_override has expired or exceeds the five-minute limit")
    for field in ("meeting_url", "url", "model", "profile_id", "signature"):
        if not isinstance(raw[field], str) or not raw[field].strip() or len(raw[field]) > 2048:
            raise InvalidSignedSTT(f"stt_override {field} is invalid")
    if raw["token"] is not None and (
        not isinstance(raw["token"], str) or len(raw["token"]) > 2048
    ):
        raise InvalidSignedSTT("stt_override token is invalid")
    endpoint = urlparse(raw["url"])
    if endpoint.scheme not in {"http", "https"} or not endpoint.hostname or endpoint.username or endpoint.password:
        raise InvalidSignedSTT("stt_override URL must be an HTTP(S) endpoint without embedded credentials")
    claims = {key: value for key, value in raw.items() if key != "signature"}
    expected = hmac.new(secret.encode(), _canonical(claims), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, raw["signature"]):
        raise InvalidSignedSTT("stt_override signature is invalid")
    return {
        "url": raw["url"], "model": raw["model"],
        "token": raw["token"], "profile_id": raw["profile_id"],
    }
