from sqlalchemy import inspect, text
from src.config.database import Base, engine
from src import models  # noqa: F401  导入以注册 ORM 模型


DELIVERY_COLUMNS = {
    'archive_id': 'VARCHAR(40) NULL',
    'key_id': 'VARCHAR(80) NULL',
    'signing_state': "VARCHAR(20) NOT NULL DEFAULT 'unsigned'",
    'signed_at': 'DOUBLE NULL',
    'attempts': 'INTEGER NOT NULL DEFAULT 0',
    'last_attempt_at': 'DOUBLE NULL',
    'error': 'VARCHAR(1000) NOT NULL DEFAULT \'\'',
    'scheduled_for': 'DOUBLE NULL',
    'verify_state': "VARCHAR(20) NOT NULL DEFAULT 'unverified'",
    'verify_message': 'VARCHAR(1000) NOT NULL DEFAULT \'\'',
    'verified_at': 'DOUBLE NULL',
}


def _upgrade_deliveries():
    """给已有库补列与索引。新增列一律可空或带默认值，历史归档保持 unsigned。"""
    inspector = inspect(engine)
    if 'deliveries' not in inspector.get_table_names():
        return
    existing = {column['name'] for column in inspector.get_columns('deliveries')}
    with engine.begin() as connection:
        for name, ddl in DELIVERY_COLUMNS.items():
            if name in existing:
                continue
            connection.execute(text(f'ALTER TABLE deliveries ADD COLUMN {name} {ddl}'))
    indexes = {index['name'] for index in inspector.get_indexes('deliveries')}
    with engine.begin() as connection:
        for name in ('archive_id', 'signing_state', 'scheduled_for'):
            index_name = f'ix_deliveries_{name}'
            if index_name in indexes:
                continue
            connection.execute(text(
                f'CREATE INDEX {index_name} ON deliveries ({name})'
            ))


def migrate():
    Base.metadata.create_all(engine)
    _upgrade_deliveries()


if __name__ == '__main__':
    migrate()
