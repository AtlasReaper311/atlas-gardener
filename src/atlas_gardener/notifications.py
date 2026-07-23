"""Bounded, transition-oriented atlas-notify producer for Gardener controller runs."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol

from atlas_gardener.errors import GardenerError

NOTIFY_URL = "https://api.atlas-systems.uk/notify"
ALLOWED_EVENTS = {
    "finding_received",
    "pr_opened",
    "pr_merged",
    "ci_failed",
    "remediation_refused",
    "controller_error",
    "kill_switch_active",
}
LEVELS = {"success", "failure", "warning", "info"}


class NotifyTransport(Protocol):
    def send(self, payload: dict[str, Any], token: str) -> int: ...


class HttpNotifyTransport:
    def send(self, payload: dict[str, Any], token: str) -> int:
        request = urllib.request.Request(
            NOTIFY_URL,
            data=json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "atlas-gardener/automatic-controller",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status
        except urllib.error.HTTPError as error:
            raise GardenerError(f"atlas-notify returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise GardenerError("atlas-notify was unavailable") from error


def build_notification(
    *,
    event: str,
    level: str,
    title: str,
    message: str,
    run_url: str,
    fields: dict[str, str] | None = None,
) -> dict[str, Any]:
    if event not in ALLOWED_EVENTS:
        raise GardenerError(f"unsupported Gardener notification event: {event}")
    if level not in LEVELS:
        raise GardenerError(f"unsupported Gardener notification level: {level}")
    if not 1 <= len(title) <= 120 or not 1 <= len(message) <= 500:
        raise GardenerError("Gardener notification title or message is outside the bound")
    bounded_fields = dict(sorted((fields or {}).items()))
    if len(bounded_fields) > 10:
        raise GardenerError("Gardener notification has too many fields")
    for key, value in bounded_fields.items():
        if not 1 <= len(key) <= 64 or len(value) > 200:
            raise GardenerError("Gardener notification field is outside the bound")
    bounded_fields["event"] = event
    return {
        "source": "alert",
        "signal_class": "gardener",
        "level": level,
        "title": title,
        "message": message,
        "fields": bounded_fields,
        "url": run_url,
        "persist_only": True,
    }


def send_notification(
    payload: dict[str, Any],
    *,
    transport: NotifyTransport | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    credential = token if token is not None else os.environ.get("NOTIFY_TOKEN", "")
    if not credential:
        return {"status": "skipped", "reason": "NOTIFY_TOKEN is not configured"}
    status = (transport or HttpNotifyTransport()).send(payload, credential)
    if status >= 300:
        raise GardenerError(f"atlas-notify returned HTTP {status}")
    return {"status": "delivered", "http_status": status, "event": payload["fields"]["event"]}
