#!/usr/bin/env python3
"""归档数字签章独立验真工具。

只依赖 Python 标准库与 cryptography，不导入后端代码、不接触私钥。
输入是归档的四件文件（CSV、JSON、清单、签章记录）与一份仅含公钥的
信任目录。任何篡改、缺件、交叉混搭或未知密钥都会返回非零退出码。

用法：
    python tools/verify_archive.py --trust trust-directory.json \\
        report-1-delivery-2.csv report-1-delivery-2.csv.json \\
        report-1-delivery-2.csv.manifest.json report-1-delivery-2.csv.sig.json

    # 或指定一个目录，按 <csv>.manifest.json / <csv>.sig.json 约定查找
    python tools/verify_archive.py --trust trust-directory.json --dir ./archive

退出码：0 验真通过；2 验真失败（篡改/缺件/混搭/未知密钥）；3 签名有效但
签发密钥已撤销（原件受影响）；4 参数或信任目录本身不合法。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    Ed25519PublicKey = None

MANIFEST_SCHEMA = 'assay-archive/v1'
SIGNATURE_SCHEMA = 'assay-archive-signature/v1'

OK = 'verified'
TAMPERED = 'tampered'
MISSING = 'missing'
MISMATCHED = 'mismatched'
UNKNOWN_KEY = 'unknown_key'
REVOKED = 'affected'
BAD_DIRECTORY = 'bad_trust_directory'


class VerificationError(Exception):
    def __init__(self, state, message, problems=None):
        super().__init__(message)
        self.state = state
        self.message = message
        self.problems = problems or []


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def b64decode(value):
    return base64.b64decode(value.encode('ascii'), validate=True)


def load_json(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def load_trust(path):
    try:
        directory = load_json(path)
    except (OSError, ValueError) as exc:
        raise VerificationError(BAD_DIRECTORY, f'无法读取信任目录：{exc}') from exc
    if not isinstance(directory, dict) or not isinstance(directory.get('keys'), list):
        raise VerificationError(BAD_DIRECTORY, '信任目录缺少 keys 列表。')
    keys = {}
    for entry in directory['keys']:
        if not isinstance(entry, dict) or not entry.get('key_id'):
            raise VerificationError(BAD_DIRECTORY, '信任目录包含无效密钥条目。')
        if 'private_key' in entry:
            raise VerificationError(BAD_DIRECTORY, '信任目录不应包含私钥。')
        if entry.get('algorithm') != 'Ed25519':
            raise VerificationError(BAD_DIRECTORY, f"不支持的算法：{entry.get('algorithm')}")
        try:
            b64decode(entry.get('public_key', ''))
        except Exception as exc:
            raise VerificationError(BAD_DIRECTORY, f"密钥 {entry['key_id']} 公钥格式无效。") from exc
        keys[entry['key_id']] = entry
    if directory.get('algorithm') not in (None, 'Ed25519'):
        raise VerificationError(BAD_DIRECTORY, '信任目录算法不是 Ed25519。')
    return keys


def resolve_files(paths, directory):
    if paths:
        if len(paths) != 4:
            raise VerificationError(BAD_DIRECTORY, '需要同时提供 CSV、JSON、清单、签章四个文件。')
        csv_path, json_path, manifest_path, signature_path = paths
    else:
        if not directory:
            raise VerificationError(BAD_DIRECTORY, '请提供四个文件或 --dir 目录。')
        candidates = [name for name in os.listdir(directory) if name.endswith('.csv')]
        if len(candidates) != 1:
            raise VerificationError(
                BAD_DIRECTORY, f'目录中应有且仅有一个 .csv 归档附件，实际 {len(candidates)} 个。',
            )
        csv_path = os.path.join(directory, candidates[0])
        json_path = csv_path + '.json'
        manifest_path = csv_path + '.manifest.json'
        signature_path = csv_path + '.sig.json'
    return csv_path, json_path, manifest_path, signature_path


def verify(csv_path, json_path, manifest_path, signature_path, trust):
    missing = [os.path.basename(p) for p in (csv_path, json_path, manifest_path, signature_path)
               if not os.path.isfile(p)]
    if missing:
        raise VerificationError(MISSING, '归档缺件：' + '、'.join(missing),
                                ['缺少文件：' + name for name in missing])

    try:
        signature = load_json(signature_path)
        with open(manifest_path, 'rb') as handle:
            manifest_data = handle.read()
        manifest = json.loads(manifest_data.decode('utf-8'))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise VerificationError(TAMPERED, '清单或签章记录无法解析。', [str(exc)]) from exc

    if signature.get('schema') != SIGNATURE_SCHEMA:
        raise VerificationError(TAMPERED, '签章记录格式不受支持。')
    key_id = signature.get('key_id')
    key = trust.get(key_id)
    if key is None:
        raise VerificationError(UNKNOWN_KEY, f'当前信任目录中没有密钥 {key_id}。')

    if signature.get('manifest_sha256') != sha256_bytes(manifest_data):
        raise VerificationError(TAMPERED, '清单指纹与签章记录不一致，归档已被篡改。')
    if Ed25519PublicKey is None:
        raise VerificationError(BAD_DIRECTORY, '缺少 cryptography 依赖，无法执行签名校验。')
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(key['public_key'])).verify(
            b64decode(signature.get('signature', '')), manifest_data,
        )
    except Exception as exc:
        raise VerificationError(TAMPERED, 'Ed25519 签名无效，归档已被篡改。', [str(exc)]) from exc

    if manifest.get('schema') != MANIFEST_SCHEMA:
        raise VerificationError(MISMATCHED, '清单格式不受支持。')
    if manifest.get('algorithm') != 'Ed25519' or manifest.get('key_id') != key_id:
        raise VerificationError(MISMATCHED, '清单算法或密钥标识与签章记录不一致。')
    if signature.get('algorithm') != 'Ed25519':
        raise VerificationError(MISMATCHED, '签章算法不受支持。')
    if not manifest.get('archive_id') or not manifest.get('delivery_id'):
        raise VerificationError(MISMATCHED, '清单缺少归档标识，无法确认两件附件同属一份归档。')

    expected = {os.path.basename(csv_path), os.path.basename(json_path)}
    listed = {entry.get('name'): entry for entry in manifest.get('files', [])}
    if set(listed) != expected:
        raise VerificationError(
            MISMATCHED,
            '清单所列附件与提供的附件不一致，可能混入了其他归档的文件。',
            [f'清单：{sorted(listed)}；实际：{sorted(expected)}'],
        )

    files = []
    for path in (csv_path, json_path):
        name = os.path.basename(path)
        with open(path, 'rb') as handle:
            data = handle.read()
        entry = listed[name]
        digest = sha256_bytes(data)
        if digest != entry.get('sha256') or len(data) != entry.get('size'):
            raise VerificationError(TAMPERED, f'{name} 内容与清单指纹不符，归档已被篡改。')
        files.append({'name': name, 'sha256': digest, 'size': len(data)})

    try:
        inner = load_json(json_path)
    except (OSError, ValueError) as exc:
        raise VerificationError(TAMPERED, 'JSON 附件无法解析。', [str(exc)]) from exc
    if (inner.get('archive_id') != manifest.get('archive_id')
            or inner.get('delivery_id') != manifest.get('delivery_id')
            or inner.get('key_id') != manifest.get('key_id')):
        raise VerificationError(MISMATCHED, 'JSON 附件内嵌归档标识与清单不一致，附件可能被混搭。')

    status = key.get('status')
    if status == 'revoked':
        return {
            'result': REVOKED,
            'message': f'签名有效，但签发密钥 {key_id} 已撤销，此原件受影响。',
            'key_id': key_id, 'key_status': status,
            'revoked_reason': key.get('revoked_reason', ''),
            'archive_id': manifest.get('archive_id'),
            'delivery_id': manifest.get('delivery_id'),
            'files': files,
        }
    if status not in ('active', 'retired'):
        raise VerificationError(BAD_DIRECTORY, f'信任目录中密钥 {key_id} 状态无效：{status}')
    note = '（签发密钥已退役，旧件仍可验真）' if status == 'retired' else ''
    return {
        'result': OK,
        'message': f'签名有效，两件附件与清单一致{note}。',
        'key_id': key_id, 'key_status': status,
        'archive_id': manifest.get('archive_id'),
        'delivery_id': manifest.get('delivery_id'),
        'files': files,
    }


EXIT = {OK: 0, REVOKED: 3, BAD_DIRECTORY: 4}


def main(argv=None):
    parser = argparse.ArgumentParser(description='独立验真归档数字签章（不持有私钥）')
    parser.add_argument('files', nargs='*', help='CSV、JSON、清单、签章四个文件')
    parser.add_argument('--dir', help='包含一份归档四件文件的目录')
    parser.add_argument('--trust', required=True, help='信任目录 JSON（仅含公钥）')
    parser.add_argument('--json', action='store_true', help='仅输出机器可读 JSON')
    args = parser.parse_args(argv)
    try:
        trust = load_trust(args.trust)
        csv_path, json_path, manifest_path, signature_path = resolve_files(args.files, args.dir)
        report = verify(csv_path, json_path, manifest_path, signature_path, trust)
        code = EXIT.get(report['result'], 2)
    except VerificationError as exc:
        report = {'result': exc.state, 'message': exc.message, 'problems': exc.problems}
        code = EXIT.get(exc.state, 2)
    except OSError as exc:
        report = {'result': MISSING, 'message': f'读取文件失败：{exc}', 'problems': []}
        code = 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(report['message'])
        for problem in report.get('problems', []):
            print('  - ' + problem)
        print(f"结果：{report['result']}")
    return code


if __name__ == '__main__':
    sys.exit(main())
