from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from guarded_agent_runner.capability import assert_no_scope_expansion
from guarded_agent_runner.models import ApprovalRequest, ApprovalStatus, AuditEvent, Run, utcnow


class Base(DeclarativeBase):
    pass


class RunRecord(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ApprovalRecord(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class Repository:
    def __init__(self, database_url: str = "sqlite:///./guarded_agent_runner.db") -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, connect_args=connect_args)
        self._sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    @classmethod
    def in_memory(cls) -> Repository:
        return cls("sqlite+pysqlite:///:memory:")

    def save_run(self, run: Run) -> None:
        with self._sessions.begin() as session:
            record = session.get(RunRecord, run.id)
            if record is None:
                session.add(RunRecord(id=run.id, payload=run.model_dump_json(), updated_at=utcnow()))
                return
            previous = Run.model_validate_json(record.payload)
            assert_no_scope_expansion(run.scope, previous.scope)
            record.payload = run.model_dump_json()
            record.updated_at = utcnow()

    def get_run(self, run_id: str) -> Run | None:
        with self._sessions() as session:
            record = session.get(RunRecord, run_id)
            return Run.model_validate_json(record.payload) if record else None

    def save_approval(self, approval: ApprovalRequest) -> None:
        with self._sessions.begin() as session:
            record = session.get(ApprovalRecord, approval.id)
            if record is None:
                session.add(
                    ApprovalRecord(
                        id=approval.id,
                        run_id=approval.run_id,
                        status=approval.status.value,
                        payload=approval.model_dump_json(),
                        created_at=approval.created_at,
                    )
                )
                return
            record.run_id = approval.run_id
            record.status = approval.status.value
            record.payload = approval.model_dump_json()

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        with self._sessions() as session:
            record = session.get(ApprovalRecord, approval_id)
            return ApprovalRequest.model_validate_json(record.payload) if record else None

    def latest_approval_for_run(self, run_id: str) -> ApprovalRequest | None:
        with self._sessions() as session:
            statement = (
                select(ApprovalRecord)
                .where(ApprovalRecord.run_id == run_id)
                .order_by(ApprovalRecord.created_at.desc())
                .limit(1)
            )
            record = session.scalar(statement)
            return ApprovalRequest.model_validate_json(record.payload) if record else None

    def pending_approval_for_run(self, run_id: str) -> ApprovalRequest | None:
        with self._sessions() as session:
            statement = (
                select(ApprovalRecord)
                .where(
                    ApprovalRecord.run_id == run_id,
                    ApprovalRecord.status == ApprovalStatus.PENDING.value,
                )
                .order_by(ApprovalRecord.created_at.desc())
                .limit(1)
            )
            record = session.scalar(statement)
            return ApprovalRequest.model_validate_json(record.payload) if record else None

    def append_audit(self, event: AuditEvent) -> AuditEvent:
        with self._sessions.begin() as session:
            record = AuditRecord(
                run_id=event.run_id,
                timestamp=event.timestamp,
                payload=event.model_dump_json(exclude={"id"}),
            )
            session.add(record)
            session.flush()
            event.id = record.id
        return event

    def list_audit(self, run_id: str) -> list[AuditEvent]:
        with self._sessions() as session:
            records = session.scalars(
                select(AuditRecord)
                .where(AuditRecord.run_id == run_id)
                .order_by(AuditRecord.timestamp.asc(), AuditRecord.id.asc())
            ).all()
            events: list[AuditEvent] = []
            for record in records:
                payload = json.loads(record.payload)
                payload["id"] = record.id
                events.append(AuditEvent.model_validate(payload))
            return events

    def close(self) -> None:
        self.engine.dispose()
