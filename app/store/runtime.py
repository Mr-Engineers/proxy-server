"""Zapis stanu działania proxy: sesje, hopy, decyzje, approvale, ledger wydatków."""

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import asyncpg

from app.core.ids import new_id
from app.pipeline.models import ChainStep, Decision


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


async def init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec("jsonb", encoder=_dumps, decoder=json.loads, schema="pg_catalog")
    await conn.set_type_codec("json", encoder=_dumps, decoder=json.loads, schema="pg_catalog")


def request_sha256(request: dict[str, Any]) -> bytes:
    return hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).digest()


class SessionError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class RuntimeStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    # --- agenci i sesje -----------------------------------------------------

    async def touch_agent(self, agent_id: str) -> None:
        await self.pool.execute(
            """
            insert into proxy.agent_activity (agent_id, last_seen_at) values ($1, now())
            on conflict (agent_id) do update set last_seen_at = excluded.last_seen_at
             where proxy.agent_activity.last_seen_at < now() - interval '5 seconds'
            """,
            agent_id,
        )

    async def create_session(self, agent_id: str, task: str | None) -> asyncpg.Record:
        return await self.pool.fetchrow(
            "insert into proxy.sessions (id, agent_id, task) values ($1, $2, $3) returning *",
            new_id("ses"),
            agent_id,
            task,
        )

    async def get_session(self, session_id: str) -> asyncpg.Record | None:
        return await self.pool.fetchrow("select * from proxy.sessions where id = $1", session_id)

    async def require_session(self, session_id: str | None, agent_id: str) -> asyncpg.Record:
        if not session_id:
            raise SessionError(400, "session_required", "X-Session-Id header is required, create one with POST /v1/sessions")
        session = await self.get_session(session_id)
        if session is None or session["agent_id"] != agent_id:
            raise SessionError(403, "invalid_session", "Session does not exist or belongs to another agent")
        if session["status"] == "terminated":
            raise SessionError(403, "session_terminated", "Session was terminated")
        if session["status"] != "active":
            raise SessionError(403, "session_closed", "Session is not active")
        return session

    async def close_session(self, session_id: str) -> asyncpg.Record | None:
        return await self.pool.fetchrow(
            """
            update proxy.sessions set status = 'closed', closed_at = now()
             where id = $1 and status = 'active' returning *
            """,
            session_id,
        )

    async def update_state(self, session_id: str, update: Callable[[dict], dict]) -> dict:
        async with self.pool.acquire() as conn, conn.transaction():
            state = await conn.fetchval("select state from proxy.sessions where id = $1 for update", session_id)
            new_state = update(state or {})
            await conn.execute(
                "update proxy.sessions set state = $2, last_activity_at = now() where id = $1", session_id, new_state
            )
            return new_state

    async def register_deny(self, session_id: str, limit: int) -> bool:
        """Zwraca True, jeśli ta odmowa przekroczyła limit i sesja została zakończona."""
        row = await self.pool.fetchrow(
            """
            update proxy.sessions
               set deny_count = deny_count + 1,
                   status = case when deny_count + 1 >= $2 then 'terminated' else status end,
                   closed_at = case when deny_count + 1 >= $2 then now() else closed_at end,
                   termination_reason = case when deny_count + 1 >= $2 then 'deny_limit' else termination_reason end
             where id = $1 and status = 'active'
            returning status
            """,
            session_id,
            limit,
        )
        return row is not None and row["status"] == "terminated"

    # --- hopy i decyzje -----------------------------------------------------

    async def insert_hop(
        self,
        *,
        session_id: str,
        agent_id: str,
        direction: str,
        protocol: str,
        app_id: str,
        payload: Any,
        tool_id: str | None = None,
        action: str | None = None,
        http_method: str | None = None,
        http_path: str | None = None,
        upstream_status: int | None = None,
        upstream_latency_ms: float | None = None,
    ) -> str:
        hop_id = new_id("hop")
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute("select pg_advisory_xact_lock(hashtext($1))", session_id)
            seq = await conn.fetchval(
                "select coalesce(max(seq), -1) + 1 from proxy.hops where session_id = $1", session_id
            )
            await conn.execute(
                """
                insert into proxy.hops (id, session_id, agent_id, seq, direction, protocol, app_id, tool_id, action,
                                        http_method, http_path, payload, upstream_status, upstream_latency_ms)
                values ($1, $2, $3, $4, $5, $6, $7, $8::uuid, $9, $10, $11, $12, $13, $14)
                """,
                hop_id, session_id, agent_id, seq, direction, protocol, app_id, tool_id, action,
                http_method, http_path, payload, upstream_status,
                round(upstream_latency_ms, 2) if upstream_latency_ms is not None else None,
            )
            await conn.execute("update proxy.sessions set last_activity_at = now() where id = $1", session_id)
        return hop_id

    async def insert_decision(
        self,
        decision: Decision,
        *,
        hop_id: str,
        session_id: str,
        agent_id: str,
        app_id: str,
        tool: str,
        kind: str,
        args_redacted: Any,
        action_status: str,
        http_status: int,
        request_id: str,
    ) -> None:
        signals = dict(decision.signals)
        signals.setdefault("allow_prob", decision.allow_prob)
        signals.setdefault("deny_prob", decision.deny_prob)
        if decision.facts:
            signals.setdefault("facts", decision.facts)
        await self.pool.execute(
            """
            insert into proxy.decisions (id, hop_id, session_id, verdict, confidence, reasons, signals, degraded,
                                         latency_ms, config_revision, agent_id, app_id, tool, kind, chain,
                                         args_redacted, action_status, http_status, request_id, quota_id,
                                         retry_after_seconds)
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
            """,
            decision.id, hop_id, session_id, decision.verdict.value, round(decision.confidence, 4),
            [reason.model_dump() for reason in decision.reasons], signals, decision.degraded,
            round(decision.latency_ms, 2), decision.config_revision, agent_id, app_id, tool, kind,
            [step.model_dump() for step in decision.chain], args_redacted, action_status, http_status,
            request_id, decision.quota_id, decision.retry_after_seconds,
        )

    async def set_decision_status(
        self,
        decision_id: str,
        action_status: str,
        http_status: int | None = None,
        upstream_status: int | None = None,
        conn: asyncpg.Connection | None = None,
    ) -> None:
        await (conn or self.pool).execute(
            """
            update proxy.decisions
               set action_status = $2,
                   http_status = coalesce($3, http_status),
                   upstream_status = coalesce($4, upstream_status)
             where id = $1
            """,
            decision_id, action_status, http_status, upstream_status,
        )

    async def append_chain(self, decision_id: str, step: ChainStep, conn: asyncpg.Connection | None = None) -> None:
        await (conn or self.pool).execute(
            """
            update proxy.decisions
               set chain = (select coalesce(jsonb_agg(s), '[]'::jsonb) from jsonb_array_elements(chain) s
                             where s->>'stage' <> 'human') || jsonb_build_array($2::jsonb)
             where id = $1
            """,
            decision_id, step.model_dump(),
        )

    # --- limity i budżety ---------------------------------------------------

    async def count_calls(self, agent_id: str, seconds: int) -> int:
        return await self.pool.fetchval(
            """
            select count(*) from proxy.decisions
             where agent_id = $1 and verdict <> 'rate_limited' and created_at > now() - make_interval(secs => $2)
            """,
            agent_id, seconds,
        )

    async def oldest_call_age(self, agent_id: str, seconds: int) -> float | None:
        return await self.pool.fetchval(
            """
            select extract(epoch from now() - min(created_at))::float8 from proxy.decisions
             where agent_id = $1 and verdict <> 'rate_limited' and created_at > now() - make_interval(secs => $2)
            """,
            agent_id, seconds,
        )

    async def spent(self, agent_id: str, app_id: str, windows: dict[str, int]) -> dict[str, int]:
        result = {}
        for window, seconds in windows.items():
            amount = await self.pool.fetchval(
                """
                select coalesce(sum(amount), 0) from proxy.spend_ledger
                 where agent_id = $1 and app_id = $2 and created_at > now() - make_interval(secs => $3)
                """,
                agent_id, app_id, seconds,
            )
            result[window] = int(Decimal(amount) * 100)
        return result

    async def record_spend(self, agent_id: str, app_id: str, decision_id: str, minor: int, currency: str) -> None:
        await self.pool.execute(
            "insert into proxy.spend_ledger (agent_id, app_id, decision_id, amount, currency) values ($1, $2, $3, $4, $5)",
            agent_id, app_id, decision_id, Decimal(minor) / 100, currency,
        )

    async def has_temporary_grant(self, agent_id: str, tool: str) -> bool:
        return await self.pool.fetchval(
            "select exists (select 1 from proxy.temporary_grants where agent_id = $1 and tool = $2 and expires_at > now())",
            agent_id, tool,
        )

    # --- approvale ----------------------------------------------------------

    async def create_approval(
        self,
        *,
        decision_id: str,
        session_id: str,
        agent_id: str,
        tool: str,
        request: dict[str, Any],
        ttl_seconds: int,
    ) -> asyncpg.Record:
        return await self.pool.fetchrow(
            """
            insert into proxy.approvals (id, decision_id, session_id, agent_id, tool, request, request_sha256, expires_at)
            values ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))
            returning *
            """,
            new_id("apr"), decision_id, session_id, agent_id, tool, request, request_sha256(request), ttl_seconds,
        )

    async def get_approval(self, approval_id: str) -> asyncpg.Record | None:
        return await self.pool.fetchrow("select * from proxy.approvals where id = $1", approval_id)

    async def expire_due(self) -> list[str]:
        async with self.pool.acquire() as conn, conn.transaction():
            rows = await conn.fetch(
                """
                update proxy.approvals set status = 'expired', resolved_at = now()
                 where status = 'pending' and expires_at <= now()
                returning id, decision_id
                """
            )
            for row in rows:
                await self.set_decision_status(row["decision_id"], "expired", conn=conn)
                await self.append_chain(
                    row["decision_id"], ChainStep(stage="human", outcome="expired", detail="Approval timed out"), conn=conn
                )
        return [row["id"] for row in rows]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def seconds_until(moment: datetime) -> int:
    return max(int((moment - utcnow()) / timedelta(seconds=1)), 0)
