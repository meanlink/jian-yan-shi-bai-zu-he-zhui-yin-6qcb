from sqlalchemy import String, Double, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base
class Report(Base):
    __tablename__ = 'reports'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    job_id: Mapped[int] = mapped_column(ForeignKey('jobs.id'))
    destination: Mapped[str] = mapped_column(String(120))
    interval_seconds: Mapped[int]
    next_run: Mapped[float] = mapped_column(Double)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
class Delivery(Base):
    __tablename__ = 'deliveries'
    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey('reports.id'))
    created_at: Mapped[float] = mapped_column(Double)
    checksum: Mapped[str] = mapped_column(String(64))
    filename: Mapped[str] = mapped_column(String(160))
    destination: Mapped[str] = mapped_column(String(120))
    # 数字签章。历史归档没有以下字段，signing_state 为 unsigned。
    archive_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    key_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    signing_state: Mapped[str] = mapped_column(String(20), default='unsigned', index=True)
    signed_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    attempts: Mapped[int] = mapped_column(default=0)
    last_attempt_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    error: Mapped[str] = mapped_column(String(1000), default='')
    scheduled_for: Mapped[float | None] = mapped_column(Double, nullable=True, index=True)
    verify_state: Mapped[str] = mapped_column(String(20), default='unverified')
    verify_message: Mapped[str] = mapped_column(String(1000), default='')
    verified_at: Mapped[float | None] = mapped_column(Double, nullable=True)
