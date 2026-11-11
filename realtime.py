"""রিয়েল-টাইম: WebSocket হাব, change_log poller (§৯)।

নিয়ম: WS-এ কখনো সংবেদনশীল ডেটা যায় না, শুধু "বদলেছে" সংকেত।
"""

import asyncio
import json
import logging
import time

from fastapi import WebSocket, WebSocketDisconnect

from config import get_settings
from db import read_many, read_one, utcnow
from errors import ApiError
from ratelimit import enforce
from security import client_ip, cookie_name, token_hash

log = logging.getLogger("realtime")

PUBLIC_SCOPES = frozenset({"donors", "requests", "stats", "leaderboard"})
ADMIN_SCOPES = frozenset({"admin_requests", "admin_contacts", "admin_donors", "admin_reports"})
_ADMIN_RECHECK_SECONDS = 60


class Hub:
    def __init__(self) -> None:
        self._clients: dict[WebSocket, bool] = {}  # ws -> is_admin
        self.own_versions: set[int] = set()  # এই worker নিজে যা broadcast করেছে

    def add(self, ws: WebSocket, is_admin: bool) -> None:
        self._clients[ws] = is_admin

    def remove(self, ws: WebSocket) -> None:
        self._clients.pop(ws, None)

    async def broadcast(self, version: int, scopes: list[str]) -> None:
        for ws, is_admin in list(self._clients.items()):
            allowed = PUBLIC_SCOPES | ADMIN_SCOPES if is_admin else PUBLIC_SCOPES
            send = [s for s in scopes if s in allowed]
            if not send:
                continue
            payload = json.dumps({"t": "change", "v": version, "scopes": send})
            try:
                await asyncio.wait_for(ws.send_text(payload), timeout=3)
            except Exception:
                self.remove(ws)


hub = Hub()


async def announce(version: int, scopes: list[str]) -> None:
    """Commit-এর পর নিজের worker-এ সরাসরি broadcast (কম latency)।"""
    hub.own_versions.add(version)
    await hub.broadcast(version, scopes)


async def poll_changes() -> None:
    """অন্য worker-এর পরিবর্তন ধরতে প্রতি ১ সেকেন্ডে change_log পড়া।"""
    row = await read_one("SELECT COALESCE(MAX(version), 0) AS v FROM change_log")
    last = int(row["v"])
    while True:
        await asyncio.sleep(1)
        try:
            rows = await read_many(
                "SELECT version, scopes FROM change_log WHERE version > :last ORDER BY version LIMIT 200",
                last=last,
            )
        except Exception:
            log.exception("change_log poll failed")
            continue
        for r in rows:
            last = int(r["version"])
            if last in hub.own_versions:
                hub.own_versions.discard(last)
                continue
            await hub.broadcast(last, r["scopes"].split(","))


async def _admin_session_ok(ws: WebSocket) -> bool:
    raw = ws.cookies.get(cookie_name("admin"))
    if not raw:
        return False
    row = await read_one(
        """SELECT 1 AS ok FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
        WHERE s.token_hash = :th AND s.expires_at > :now AND a.must_change_password = FALSE""",
        th=token_hash(raw),
        now=utcnow(),
    )
    return row is not None


async def ws_endpoint(ws: WebSocket) -> None:
    s = get_settings()

    # Cross-Site WebSocket Hijacking রোধ: Origin যাচাই (handshake-এ 403)
    origin = (ws.headers.get("origin") or "").rstrip("/")
    if origin not in s.origins:
        await ws.close(code=1008)
        return
    try:
        await enforce("ws_connect", client_ip(ws))
    except ApiError:
        await ws.close(code=1008)
        return

    await ws.accept()
    conn_key = f"conn:{id(ws)}"

    try:
        hello = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=5))
    except (asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        await ws.close(code=4400)
        return
    if not isinstance(hello, dict) or hello.get("t") != "hello":
        await ws.close(code=4400)
        return

    channel = hello.get("channel", "public")
    if channel not in ("public", "admin"):
        await ws.close(code=4400)
        return
    is_admin = channel == "admin"
    if is_admin and not await _admin_session_ok(ws):
        await ws.close(code=4401)
        return

    hub.add(ws, is_admin)
    try:
        cur = await read_one("SELECT COALESCE(MAX(version), 0) AS v FROM change_log")
        await ws.send_text(
            json.dumps({"t": "hello", "v": int(cur["v"]), "role": "admin" if is_admin else "public"})
        )
        last_check = time.monotonic()
        while True:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=_ADMIN_RECHECK_SECONDS)
            except asyncio.TimeoutError:
                raw = None

            if is_admin and time.monotonic() - last_check >= _ADMIN_RECHECK_SECONDS:
                last_check = time.monotonic()
                if not await _admin_session_ok(ws):
                    await ws.close(code=4401)
                    return
            if raw is None:
                continue

            if len(raw.encode("utf-8")) > 1024:
                await ws.close(code=4400)
                return
            try:
                await enforce("ws_msg", conn_key)
            except ApiError:
                await ws.close(code=4429)
                return
            try:
                msg = json.loads(raw)
            except ValueError:
                await ws.close(code=4400)
                return
            if isinstance(msg, dict) and msg.get("t") == "ping":
                await ws.send_text(json.dumps({"t": "pong"}))
            else:
                await ws.close(code=4400)
                return
    except WebSocketDisconnect:
        pass
    finally:
        hub.remove(ws)
