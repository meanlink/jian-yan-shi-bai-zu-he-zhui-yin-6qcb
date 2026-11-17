"""归档附件的生成、原子落盘、签章与验真。

每份归档 = CSV 与 JSON 两件附件 + 清单 + 签章记录。清单列出两件附件的
SHA256 与字节数，Ed25519 签名覆盖清单的规范化字节。只有四件文件全部写入
磁盘并 fsync 后，归档才进入 signed 状态并开放下载。
"""
import csv
import hashlib
import io
import json
import os
import secrets
import tempfile
import time

from sqlalchemy import select

from src.config.settings import ARTIFACT_DIR
from src.models import Delivery, Job, Report
from src.services import signing

PENDING = 'pending'
SIGNED = 'signed'
UNSIGNED = 'unsigned'  # 历史归档，没有签章

UNVERIFIED = 'unverified'
VERIFIED = 'verified'
AFFECTED = 'affected'
TAMPERED = 'tampered'
MISSING = 'missing'
MISMATCHED = 'mismatched'
INCOMPLETE = 'incomplete'
UNKNOWN_KEY = 'unknown_key'


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive_paths(delivery: Delivery, base: str | None = None) -> dict:
    directory = base or ARTIFACT_DIR
    csv_path = os.path.join(directory, delivery.filename)
    return {
        'csv': csv_path,
        'json': csv_path + '.json',
        'manifest': csv_path + '.manifest.json',
        'signature': csv_path + '.sig.json',
    }


def _atomic_write(path: str, data: bytes) -> None:
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.part-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _write_if_changed(path: str, data: bytes) -> None:
    try:
        with open(path, 'rb') as handle:
            if handle.read() == data:
                return
    except FileNotFoundError:
        pass
    _atomic_write(path, data)


def render_csv(job: Job) -> bytes:
    out = io.StringIO()
    out.write('﻿')
    table = (job.result or {}).get('table', {})
    cols = table.get('columns', [])
    writer = csv.writer(out)

    def safe(value):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
        text = str(value)
        return "'" + text if text.startswith(('=', '+', '-', '@', '\t', '\r')) else text

    writer.writerow([safe(c['label']) for c in cols])
    for row in table.get('rows', []):
        writer.writerow([safe(row.get(c['key'], '')) for c in cols])
    return out.getvalue().encode('utf-8')


def render_json(job: Job, delivery: Delivery, checksum: str) -> bytes:
    payload = {
        'archive_id': delivery.archive_id,
        'delivery_id': delivery.id,
        'key_id': delivery.key_id,
        'job_id': job.id,
        'job': job.name,
        'params': job.params,
        'result': job.result,
        'checksum': checksum,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False,
    ).encode('utf-8')


def _existing_signature(paths: dict, key: signing.SigningKey, manifest: bytes) -> str | None:
    try:
        with open(paths['signature'], 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
    except (FileNotFoundError, ValueError, OSError):
        return None
    if payload.get('key_id') != key.key_id:
        return None
    if payload.get('manifest_sha256') != sha256_bytes(manifest):
        return None
    signature = payload.get('signature', '')
    if not signature or not signing.verify_signature(key.public_key, manifest, signature):
        return None
    return signature


def claim(db, report: Report) -> Delivery | None:
    """登记归档。每个计划的时间槽最多一份归档；已有未完成归档时先恢复它。"""
    job = db.get(Job, report.job_id)
    if not job or job.status != 'completed' or not job.approved:
        return None
    if db.scalar(select(Delivery.id).where(
        Delivery.report_id == report.id, Delivery.signing_state == PENDING,
    ).limit(1)):
        return None
    slot = report.next_run
    existing = db.scalar(select(Delivery).where(
        Delivery.report_id == report.id, Delivery.scheduled_for == slot,
    ))
    if existing is None:
        key = signing.active_key(db)
        delivery = Delivery(
            report_id=report.id, created_at=time.time(), checksum='', filename='',
            destination=report.destination, signing_state=PENDING,
            archive_id='arc-' + secrets.token_hex(8),
            key_id=key.key_id if key else None, scheduled_for=slot,
            verify_state=UNVERIFIED,
        )
        db.add(delivery)
        db.flush()
        delivery.filename = f'report-{report.id}-delivery-{delivery.id}.csv'
        existing = delivery
    report.next_run = time.time() + max(60, report.interval_seconds)
    return existing


def finalize(db, delivery: Delivery) -> Delivery:
    """把归档写全并签章。可重复执行：已存在的正确文件与签名不会被改写。

    密钥选择：已签发且签名有效的归档沿用原密钥（即使该密钥已退役）；
    尚未签章的归档一律使用当前在用密钥，退役/撤销密钥不再新签。
    """
    report = db.get(Report, delivery.report_id)
    job = db.get(Job, report.job_id) if report else None
    if job is None:
        raise ValueError('归档对应分析任务不存在')

    csv_data = render_csv(job)
    delivery.checksum = sha256_bytes(csv_data)
    paths = archive_paths(delivery)
    stored = signing.find_key(db, delivery.key_id) if delivery.key_id else None
    active = signing.active_key(db)
    key = None
    signature = None

    # 已登记归档沿用登记时的密钥，保证同份附件始终由同一密钥签署；
    # 只有登记密钥从未签成（已撤销/不存在）时才改用当前在用密钥。
    if stored is not None:
        delivery.key_id = stored.key_id
        manifest, manifest_data = _manifest_for(job, report, delivery, stored, paths, csv_data)
        signature = _existing_signature(paths, stored, manifest_data)
        if signature is not None or stored.status in (signing.ACTIVE, signing.RETIRED):
            signature = signature or signing.sign(stored, manifest_data)
            key = stored

    if key is None:
        if active is None:
            raise RuntimeError('没有可用的签章密钥，请负责人创建或轮换密钥')
        key = active
        delivery.key_id = key.key_id
        manifest, manifest_data = _manifest_for(job, report, delivery, key, paths, csv_data)
        signature = _existing_signature(paths, key, manifest_data) or signing.sign(key, manifest_data)

    signature_data = json.dumps(
        signing.signature_payload(manifest_data, signature, key.key_id),
        sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False,
    ).encode('utf-8')
    json_data = render_json(job, delivery, delivery.checksum)

    # 先附件、再清单、最后签章记录；全部 fsync 后才在数据库标记 signed。
    _write_if_changed(paths['csv'], csv_data)
    _write_if_changed(paths['json'], json_data)
    _write_if_changed(paths['manifest'], manifest_data)
    _write_if_changed(paths['signature'], signature_data)

    delivery.signing_state = SIGNED
    delivery.signed_at = time.time()
    delivery.error = ''
    db.flush()
    return delivery


def _manifest_for(job, report, delivery, key, paths, csv_data):
    json_data = render_json(job, delivery, delivery.checksum)
    manifest = signing.build_manifest(
        archive_id=delivery.archive_id,
        delivery_id=delivery.id, report_id=delivery.report_id,
        report_name=report.name, job_id=job.id, job_name=job.name,
        destination=delivery.destination, created_at=delivery.created_at,
        key_id=key.key_id,
        files=[
            (os.path.basename(paths['csv']), sha256_bytes(csv_data), len(csv_data)),
            (os.path.basename(paths['json']), sha256_bytes(json_data), len(json_data)),
        ],
    )
    manifest_data = signing.manifest_bytes(manifest)
    return manifest, manifest_data


def deliver(db, report: Report) -> Delivery | None:
    """登记并完成一份归档。供 seed 与 worker 复用。"""
    delivery = claim(db, report)
    if delivery is None:
        return None
    db.commit()
    try:
        finalize(db, delivery)
        db.commit()
    except Exception as exc:
        db.rollback()
        _record_failure(db, delivery.id, exc)
    return delivery


def _record_failure(db, delivery_id: int, exc: Exception) -> None:
    delivery = db.get(Delivery, delivery_id)
    if delivery is None:
        return
    delivery.attempts = (delivery.attempts or 0) + 1
    delivery.last_attempt_at = time.time()
    delivery.error = str(exc)[:990]
    db.commit()


def recover_failure(db, delivery_id: int, exc: Exception) -> None:
    _record_failure(db, delivery_id, exc)


def resume_pending(db, limit: int = 20, retry_after: float = 30.0) -> list[int]:
    """待恢复的归档。失败后短暂退避，避免每个 tick 反复冲击同一故障。"""
    cutoff = time.time() - retry_after
    return list(db.scalars(
        select(Delivery.id).where(
            Delivery.signing_state == PENDING,
            (Delivery.last_attempt_at.is_(None)) | (Delivery.last_attempt_at <= cutoff),
        ).order_by(Delivery.id).limit(limit)
    ))


def verify(db, delivery: Delivery, persist: bool = True) -> dict:
    """用当前信任目录验真归档。返回结构化结果并可按需记录最近状态。"""
    result = _verify(db, delivery)
    if persist:
        delivery.verify_state = result['result']
        delivery.verify_message = result['message'][:990]
        delivery.verified_at = result['checked_at']
        db.flush()
    return result


def _result(delivery, state, message, problems=None, key=None, files=None, checks=None):
    return {
        'delivery_id': delivery.id,
        'archive_id': delivery.archive_id,
        'result': state,
        'message': message,
        'problems': problems or [],
        'key_id': delivery.key_id or (key.key_id if key else None),
        'key_status': key.status if key else None,
        'affected': state == AFFECTED,
        'files': files or [],
        'checks': checks or {},
        'checked_at': time.time(),
    }


def _verify(db, delivery: Delivery) -> dict:
    if delivery.signing_state == UNSIGNED:
        return _result(delivery, UNSIGNED, '历史归档，无数字签章，无法确认原件完整性与来源。')
    if delivery.signing_state != SIGNED:
        return _result(delivery, INCOMPLETE, '归档尚未完成签章与落盘，暂不可验真。')
    paths = archive_paths(delivery)
    files = []
    missing = []
    for name in ('csv', 'json', 'manifest', 'signature'):
        if not os.path.isfile(paths[name]):
            missing.append(os.path.basename(paths[name]))
    if missing:
        return _result(
            delivery, MISSING,
            '归档缺件：' + '、'.join(missing) + '。',
            problems=['缺少文件：' + name for name in missing],
        )

    try:
        with open(paths['signature'], 'r', encoding='utf-8') as handle:
            signature_payload = json.load(handle)
        with open(paths['manifest'], 'rb') as handle:
            manifest_data = handle.read()
        manifest = json.loads(manifest_data.decode('utf-8'))
    except (ValueError, UnicodeDecodeError, OSError) as exc:
        return _result(delivery, TAMPERED, '清单或签章记录无法解析。', problems=[str(exc)])

    key = signing.find_key(db, str(signature_payload.get('key_id', '')))
    if key is None:
        return _result(delivery, UNKNOWN_KEY, '当前信任目录中没有签发该归档的密钥。',
                       problems=[f"未知密钥 {signature_payload.get('key_id')}"])

    problems = []
    checks = {}
    checks['manifest_hash'] = signature_payload.get('manifest_sha256') == sha256_bytes(manifest_data)
    checks['signature'] = signing.verify_signature(
        key.public_key, manifest_data, str(signature_payload.get('signature', '')),
    )
    checks['key_id'] = manifest.get('key_id') == signature_payload.get('key_id') == key.key_id
    checks['archive_id'] = manifest.get('archive_id') == delivery.archive_id
    checks['delivery_id'] = manifest.get('delivery_id') == delivery.id
    if not checks['manifest_hash'] or not checks['signature']:
        return _result(
            delivery, TAMPERED, '清单签名校验失败，归档可能被篡改。',
            problems=['清单内容与签章记录不一致' if not checks['manifest_hash'] else 'Ed25519 签名无效'],
            key=key, checks=checks,
        )
    if not checks['key_id'] or not checks['archive_id'] or not checks['delivery_id']:
        return _result(
            delivery, MISMATCHED, '清单、签章与归档登记不匹配，可能混入了其他归档的文件。',
            problems=['清单中的归档标识与本次归档不一致'], key=key, checks=checks,
        )

    manifest_files = {entry.get('name'): entry for entry in manifest.get('files', [])}
    expected = {
        os.path.basename(paths['csv']): paths['csv'],
        os.path.basename(paths['json']): paths['json'],
    }
    if set(expected) != set(manifest_files):
        return _result(
            delivery, MISMATCHED, '清单所列附件与归档附件不一致。',
            problems=['附件清单不匹配'], key=key, checks=checks,
        )
    for name, path in expected.items():
        with open(path, 'rb') as handle:
            data = handle.read()
        digest = sha256_bytes(data)
        entry = manifest_files[name]
        ok = digest == entry.get('sha256') and len(data) == entry.get('size')
        files.append({'name': name, 'sha256': digest, 'size': len(data), 'ok': ok})
        if not ok:
            problems.append(f'{name} 内容与清单指纹不符')
    checks['files'] = all(item['ok'] for item in files)

    # JSON 附件内嵌归档标识，防止两套归档的附件交叉混搭。
    try:
        with open(paths['json'], 'rb') as handle:
            inner = json.loads(handle.read().decode('utf-8'))
    except (ValueError, UnicodeDecodeError, OSError):
        inner = {}
    id_problem = (
        inner.get('archive_id') != manifest.get('archive_id')
        or inner.get('delivery_id') != manifest.get('delivery_id')
        or inner.get('key_id') != manifest.get('key_id')
        or inner.get('checksum') != delivery.checksum
    )
    if id_problem:
        problems.append('JSON 附件内嵌的归档标识与清单不一致')
    checks['attachment_ids'] = not id_problem
    if problems:
        return _result(
            delivery, TAMPERED if not checks['files'] else MISMATCHED,
            '归档验真失败：' + '；'.join(problems) + '。',
            problems=problems, key=key, files=files, checks=checks,
        )

    if key.status == signing.REVOKED:
        return _result(
            delivery, AFFECTED,
            f'签名有效，但签发密钥 {key.key_id} 已被撤销，此原件受影响，请以重新签章的副本为准。',
            problems=[f'密钥已撤销：{key.revoked_reason or "未填写原因"}'],
            key=key, files=files, checks=checks,
        )
    suffix = '（签发密钥已退役，旧件仍可验真）' if key.status == signing.RETIRED else ''
    return _result(
        delivery, VERIFIED, f'两件附件与清单、Ed25519 签名均一致{suffix}。',
        key=key, files=files, checks=checks,
    )
