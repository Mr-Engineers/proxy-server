"""Human-in-the-loop (ADR 0004): long-poll agenta, rozstrzygnięcia operatora, jednokrotne wykonanie."""

import asyncio
from collections import defaultdict
from typing import Any

import asyncpg
from fastapi import FastAPI

from app import gateway
from app.core.ids import new_id
from app.pipeline.catalog import parse_json, request_document
from app.pipeline.models import ChainStep
from app.policy.cedar import budget_windows
from app.store.runtime import RuntimeStore, request_sha256
from app.upstream.client import UpstreamError


class ApprovalError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class ApprovalNotifier:
    """Budzi long-polle po `NOTIFY proxy_approvals` (lub lokalnie po rozstrzygnięciu w tym procesie)."""

    def __init__(self) -> None:
        self._waiters: dict[str, set[asyncio.Event]] = defaultdict(set)

    def notify(self, approval_id: str) -> None:
        for event in self._waiters.get(approval_id, ()):
            event.set()

    async def wait(self, approval_id: str, timeout: float) -> None:
        event = asyncio.Event()
        self._waiters[approval_id].add(event)
        try:
            await asyncio.wait_for(event.wait(), timeout)
        except TimeoutError:
            pass
        finally:
            self._waiters[approval_id].discard(event)
            if not self._waiters[approval_id]:
                self._waiters.pop(approval_id, None)


def agent_view(approval: asyncpg.Record) -> tuple[int, dict[str, Any]]:
    base = {"decision_id": approval["decision_id"], "approval_id": approval["id"]}
    status = approval["status"]
    if status == "pending":
        return 202, {
            "status": "pending_approval",
            **base,
            "poll_url": f"/v1/approvals/{approval['id']}?wait=30",
            "expires_at": approval["expires_at"].isoformat(),
        }
    if status == "approved":
        if approval["execution_result"] is None:
            return 202, {"status": "pending_approval", **base, "poll_url": f"/v1/approvals/{approval['id']}?wait=30"}
        return 200, {"status": "approved", **base, "result": approval["execution_result"]}
    if status == "rejected":
        return 200, {"status": "rejected", **base, "feedback": approval["feedback"] or ""}
    return 200, {"status": "expired", **base}


class ApprovalService:
    def __init__(self, application: FastAPI) -> None:
        self.application = application

    @property
    def store(self) -> RuntimeStore:
        return self.application.state.store

    async def resolve(
        self,
        approval_id: str,
        actor: str,
        mode: str,
        feedback: str | None = None,
        ttl_seconds: int | None = None,
    ) -> asyncpg.Record:
        status = "rejected" if mode == "deny" else "approved"
        human = ChainStep(
            stage="human",
            outcome="deny" if mode == "deny" else "allow",
            detail=(
                f"Denied by {actor}" + (f": {feedback}" if feedback else "")
                if mode == "deny"
                else f"Allowed {'temporarily ' if mode == 'temporary' else ''}by {actor}"
            ),
        )
        async with self.store.pool.acquire() as conn, conn.transaction():
            approval = await conn.fetchrow(
                """
                update proxy.approvals
                   set status = $2, resolved_by = $3, resolved_at = now(), feedback = $4,
                       resolution_mode = $5, temporary_ttl_seconds = $6
                 where id = $1 and status = 'pending' and expires_at > now()
                returning *
                """,
                approval_id, status, actor, feedback if mode == "deny" else None, mode,
                ttl_seconds if mode == "temporary" else None,
            )
            if approval is None:
                existing = await conn.fetchrow("select status, expires_at from proxy.approvals where id = $1", approval_id)
                if existing is None:
                    raise ApprovalError(404, "Unknown approval")
                raise ApprovalError(409, f"Approval is already {existing['status'] if existing['status'] != 'pending' else 'expired'}")
            await self.store.append_chain(approval["decision_id"], human, conn=conn)
            await self.store.set_decision_status(
                approval["decision_id"], "rejected" if mode == "deny" else "approved", conn=conn
            )
            if mode == "temporary":
                await conn.execute(
                    """
                    insert into proxy.temporary_grants (agent_id, tool, approval_id, expires_at, created_by)
                    values ($1, $2, $3, now() + make_interval(secs => $4), $5)
                    """,
                    approval["agent_id"], approval["tool"], approval_id, ttl_seconds, actor,
                )
        self.application.state.notifier.notify(approval_id)
        if mode != "deny":
            approval = await self.execute(approval)
        return approval

    async def execute(self, approval: asyncpg.Record) -> asyncpg.Record:
        """Wykonuje zapamiętany request dokładnie raz (hash + `executed_at is null`)."""
        stored_json = approval["request"]
        if request_sha256(stored_json) != bytes(approval["request_sha256"]):
            result = {"status_code": 409, "error": "request_tampered"}
            return await self._finish(approval, result)

        claimed = await self.store.pool.fetchval(
            "update proxy.approvals set executed_at = now() where id = $1 and executed_at is null returning id",
            approval["id"],
        )
        if claimed is None:
            return await self.store.get_approval(approval["id"])

        stored = gateway.StoredRequest.from_json(stored_json)
        snapshot = self.application.state.snapshot
        app = snapshot.apps.get(stored.app_id)
        tool = snapshot.tool(stored.tool)
        if app is None or tool is None:
            return await self._finish(approval, {"status_code": 409, "error": "action_no_longer_configured"}, claimed=True)

        decision = await self.store.pool.fetchrow(
            "select signals from proxy.decisions where id = $1", approval["decision_id"]
        )
        facts = (decision["signals"] or {}).get("facts", {}) if decision else {}
        pack = snapshot.policy_packs.get(app.id)
        outcome = await gateway.execute(
            self.application,
            app=app,
            tool=tool,
            stored=stored,
            decision_id=approval["decision_id"],
            session_id=approval["session_id"],
            agent_id=approval["agent_id"],
            request_id=new_id("req"),
            request_doc=request_document(stored.query, {}, stored.body),
            facts=facts,
            record_spend=bool(budget_windows(pack, approval["agent_id"], tool.name)),
        )
        if isinstance(outcome, UpstreamError):
            result = {"status_code": outcome.status_code, "error": outcome.code, "message": outcome.message}
        else:
            body = parse_json(outcome.content) if outcome.content else None
            result = {
                "status_code": outcome.status_code,
                "body": body if body is not None else outcome.content.decode("utf-8", errors="replace"),
            }
        return await self._finish(approval, result, claimed=True)

    async def _finish(self, approval: asyncpg.Record, result: dict, claimed: bool = False) -> asyncpg.Record:
        row = await self.store.pool.fetchrow(
            """
            update proxy.approvals
               set execution_result = $2, executed_at = coalesce(executed_at, now())
             where id = $1 returning *
            """,
            approval["id"], result,
        )
        self.application.state.notifier.notify(approval["id"])
        return row


async def listen(application: FastAPI, dsn_kwargs: dict, on_config: Any) -> asyncpg.Connection:
    conn = await asyncpg.connect(**dsn_kwargs)

    def approvals(_conn: Any, _pid: int, _channel: str, payload: str) -> None:
        application.state.notifier.notify(payload)

    def config(_conn: Any, _pid: int, _channel: str, payload: str) -> None:
        on_config(payload)

    await conn.add_listener("proxy_approvals", approvals)
    await conn.add_listener("proxy_config", config)
    return conn

