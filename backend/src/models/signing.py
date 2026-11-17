from sqlalchemy import String, Text, Double
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base


class SigningKey(Base):
    """Ed25519 归档签章密钥。私钥只留在服务端，绝不进入信任目录。"""

    __tablename__ = 'signing_keys'
    id: Mapped[int] = mapped_column(primary_key=True)
    key_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    algorithm: Mapped[str] = mapped_column(String(20), default='Ed25519')
    public_key: Mapped[str] = mapped_column(String(200))
    private_key: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default='active', index=True)
    created_at: Mapped[float] = mapped_column(Double)
    created_by: Mapped[str] = mapped_column(String(150), default='system')
    retired_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    revoked_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    revoked_reason: Mapped[str] = mapped_column(String(300), default='')
