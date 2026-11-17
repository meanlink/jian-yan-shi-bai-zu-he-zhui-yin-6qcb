"""归档数字签章：密钥生命周期、清单签名与验真。

私钥仅保存在服务端数据库；信任目录只输出公钥与状态。
"""
import base64
import hashlib
import json
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from src.models import SigningKey

ALGORITHM = 'Ed25519'
ACTIVE = 'active'
RETIRED = 'retired'
REVOKED = 'revoked'
MANIFEST_SCHEMA = 'assay-archive/v1'
SIGNATURE_SCHEMA = 'assay-archive-signature/v1'
BOOTSTRAP_KEY_ID = 'sk-bootstrap'


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode('ascii'), validate=True)


def _new_key(db, actor: str, key_id: str | None = None) -> SigningKey:
    key_id = key_id or f"sk-{time.strftime('%Y%m%d', time.gmtime())}-{secrets.token_hex(4)}"
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode('ascii')
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    key = SigningKey(
        key_id=key_id, algorithm=ALGORITHM, public_key=_b64(public_raw),
        private_key=private_pem, status=ACTIVE, created_at=time.time(), created_by=actor,
    )
    db.add(key)
    db.flush()
    return key


def ensure_bootstrap_key(db) -> None:
    """仅在系统从未有过任何签章密钥时创建初始密钥。"""
    if db.scalar(select(SigningKey.id).limit(1)):
        return
    try:
        _new_key(db, 'system', BOOTSTRAP_KEY_ID)
        db.commit()
    except IntegrityError:
        db.rollback()


def active_key(db) -> SigningKey | None:
    return db.scalar(
        select(SigningKey).where(SigningKey.status == ACTIVE).order_by(SigningKey.id.desc()).limit(1)
    )


def require_active_key(db) -> SigningKey:
    key = active_key(db)
    if key is None:
        raise RuntimeError('没有可用的签章密钥，请负责人轮换密钥后再归档')
    return key


def rotate(db, actor: str) -> SigningKey:
    now = time.time()
    # 锁住当前在用密钥，避免并发轮换留下两把 active 密钥。
    for key in db.scalars(
        select(SigningKey).where(SigningKey.status == ACTIVE).with_for_update()
    ):
        key.status = RETIRED
        key.retired_at = now
    return _new_key(db, actor)


def revoke(db, key_id: str, reason: str, actor: str) -> SigningKey:
    key = db.scalar(select(SigningKey).where(SigningKey.key_id == key_id).with_for_update())
    if key is None:
        raise HTTPException(404, '签章密钥不存在')
    if key.status == REVOKED:
        raise HTTPException(409, '该密钥已经撤销')
    key.status = REVOKED
    key.revoked_at = time.time()
    key.revoked_reason = (reason or '').strip()[:300]
    return key


def canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False,
    ).encode('utf-8')


def build_manifest(*, archive_id, delivery_id, report_id, report_name, job_id, job_name,
                   destination, created_at, key_id, files):
    return {
        'schema': MANIFEST_SCHEMA,
        'algorithm': ALGORITHM,
        'key_id': key_id,
        'archive_id': archive_id,
        'delivery_id': delivery_id,
        'report_id': report_id,
        'report_name': report_name,
        'job_id': job_id,
        'job_name': job_name,
        'destination': destination,
        'created_at': created_at,
        'files': [
            {'name': name, 'sha256': digest, 'size': size}
            for name, digest, size in files
        ],
    }


def manifest_bytes(manifest: dict) -> bytes:
    return canonical(manifest)


def signature_payload(manifest: bytes, signature: str, key_id: str) -> dict:
    return {
        'schema': SIGNATURE_SCHEMA,
        'algorithm': ALGORITHM,
        'key_id': key_id,
        'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
        'signature': signature,
    }


def sign(key: SigningKey, manifest: bytes) -> str:
    private = serialization.load_pem_private_key(key.private_key.encode('ascii'), password=None)
    return _b64(private.sign(manifest))


def verify_signature(public_key_b64: str, manifest: bytes, signature_b64: str) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(_unb64(public_key_b64))
        public.verify(_unb64(signature_b64), manifest)
        return True
    except Exception:
        return False


def trust_directory(db) -> dict:
    keys = list(db.scalars(select(SigningKey).order_by(SigningKey.id)))
    return {
        'version': 1,
        'algorithm': ALGORITHM,
        'generated_at': time.time(),
        'keys': [
            {
                'key_id': key.key_id,
                'algorithm': key.algorithm,
                'public_key': key.public_key,
                'status': key.status,
                'created_at': key.created_at,
                'created_by': key.created_by,
                'retired_at': key.retired_at,
                'revoked_at': key.revoked_at,
                'revoked_reason': key.revoked_reason,
            }
            for key in keys
        ],
    }


def find_key(db, key_id: str) -> SigningKey | None:
    return db.scalar(select(SigningKey).where(SigningKey.key_id == key_id))


def key_dict(key: SigningKey, signed_count: int = 0) -> dict:
    return {
        'key_id': key.key_id,
        'algorithm': key.algorithm,
        'public_key': key.public_key,
        'status': key.status,
        'created_at': key.created_at,
        'created_by': key.created_by,
        'retired_at': key.retired_at,
        'revoked_at': key.revoked_at,
        'revoked_reason': key.revoked_reason,
        'signed_count': signed_count,
    }
