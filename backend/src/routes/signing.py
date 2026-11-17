import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from src.config.database import get_db
from src.middlewares.auth import admin_only, current_user
from src.models import Delivery, SigningKey
from src.services import archive, signing
from src.services.audit import record

router = APIRouter()


class RevokeInput(BaseModel):
    reason: str = Field(default='', max_length=300)


@router.get('/keys')
def list_keys(db=Depends(get_db), u=Depends(current_user)):
    counts = dict(db.execute(
        select(Delivery.key_id, func.count()).where(Delivery.key_id.is_not(None))
        .group_by(Delivery.key_id)
    ).all())
    keys = db.scalars(select(SigningKey).order_by(SigningKey.id.desc()))
    return {'keys': [signing.key_dict(k, counts.get(k.key_id, 0)) for k in keys],
            'rotate_allowed': u.role == 'admin'}


@router.post('/keys/rotate', status_code=201)
def rotate(db=Depends(get_db), u=Depends(admin_only)):
    key = signing.rotate(db, u.email)
    record(db, u.email, 'signing_key.rotate', {'key_id': key.key_id})
    db.commit()
    return signing.key_dict(key)


@router.post('/keys/{key_id}/revoke')
def revoke(key_id: str, data: RevokeInput, db=Depends(get_db), u=Depends(admin_only)):
    key = signing.revoke(db, key_id, data.reason, u.email)
    record(db, u.email, 'signing_key.revoke', {'key_id': key.key_id, 'reason': key.revoked_reason})
    db.flush()
    # 用当前信任目录复核受该密钥影响的原件，让状态在页面上可见。
    for delivery in db.scalars(select(Delivery).where(
        Delivery.key_id == key.key_id, Delivery.signing_state == archive.SIGNED,
    )):
        archive.verify(db, delivery)
    db.commit()
    return signing.key_dict(key)


@router.get('/trust-directory')
def trust_directory(db=Depends(get_db), u=Depends(current_user)):
    return signing.trust_directory(db)


@router.get('/deliveries/{id}/verify')
def verify(id: int, db=Depends(get_db), u=Depends(current_user)):
    delivery = db.get(Delivery, id)
    if not delivery:
        raise HTTPException(404, '归档不存在')
    result = archive.verify(db, delivery)
    db.commit()
    return result


@router.post('/deliveries/verify-all')
def verify_all(db=Depends(get_db), u=Depends(current_user)):
    results = []
    for delivery in db.scalars(select(Delivery).order_by(Delivery.id)):
        if delivery.signing_state == archive.PENDING:
            continue
        results.append(archive.verify(db, delivery))
    db.commit()
    summary = {}
    for item in results:
        summary[item['result']] = summary.get(item['result'], 0) + 1
    return {'checked': len(results), 'summary': summary, 'results': results}


@router.get('/deliveries/{id}/manifest')
def manifest(id: int, db=Depends(get_db), u=Depends(current_user)):
    delivery = db.get(Delivery, id)
    if not delivery:
        raise HTTPException(404, '归档不存在')
    if delivery.signing_state != archive.SIGNED:
        raise HTTPException(409, '该归档没有签章清单')
    paths = archive.archive_paths(delivery)
    try:
        with open(paths['manifest'], 'r', encoding='utf-8') as handle:
            manifest_data = json.load(handle)
        with open(paths['signature'], 'r', encoding='utf-8') as handle:
            signature_data = json.load(handle)
    except (OSError, ValueError):
        raise HTTPException(404, '归档清单缺失，请重新验真')
    return {'manifest': manifest_data, 'signature': signature_data,
            'key_id': delivery.key_id}
