"""Zadania w tle: wygaszanie approvali (timeout → expired) i retencja audytu (A7)."""

import asyncio
import logging

import asyncpg
from fastapi import FastAPI

logger = logging.getLogger("proxy.jobs")

RETENTION_SQL = """
with old_decisions as (
  select d.id from proxy.decisions d
   where d.created_at < now() - make_interval(days => $1)
     and not exists (select 1 from proxy.approvals a where a.decision_id = d.id and a.status = 'pending')
), del_grants as (
  delete from proxy.temporary_grants where expires_at < now() - interval '1 day'
     or approval_id in (select a.id from proxy.approvals a join old_decisions o on o.id = a.decision_id)
), del_spend as (
  delete from proxy.spend_ledger where decision_id in (select id from old_decisions)
     or created_at < now() - make_interval(days => greatest($1, 31))
), del_approvals as (
  delete from proxy.approvals where decision_id in (select id from old_decisions) returning id
)
delete from proxy.decisions where id in (select id from old_decisions)
"""

HOPS_SQL = """
delete from proxy.hops h
 where h.created_at < now() - make_interval(days => $1)
   and not exists (select 1 from proxy.decisions d where d.hop_id = h.id)
"""

SESSIONS_SQL = """
delete from proxy.sessions s
 where s.status <> 'active' and s.last_activity_at < now() - make_interval(days => $1)
   and not exists (select 1 from proxy.hops h where h.session_id = s.id)
   and not exists (select 1 from proxy.decisions d where d.session_id = s.id)
   and not exists (select 1 from proxy.approvals a where a.session_id = s.id)
"""


async def apply_retention(pool: asyncpg.Pool, days: int) -> None:
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(RETENTION_SQL, days)
        await conn.execute(HOPS_SQL, days)
        await conn.execute(SESSIONS_SQL, days)


async def _loop(name: str, interval: float, job) -> None:
    while True:
        try:
            await job()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("job_failed", extra={"fields": {"job": name}})
        await asyncio.sleep(interval)


def start(application: FastAPI) -> list[asyncio.Task]:
    settings = application.state.settings
    store = application.state.store

    async def expire() -> None:
        for approval_id in await store.expire_due():
            application.state.notifier.notify(approval_id)

    async def retention() -> None:
        await apply_retention(store.pool, application.state.snapshot.settings.audit_retention_days)

    return [
        asyncio.create_task(_loop("approval_expiry", settings.approval_sweep_seconds, expire)),
        asyncio.create_task(_loop("audit_retention", settings.retention_sweep_seconds, retention)),
    ]
