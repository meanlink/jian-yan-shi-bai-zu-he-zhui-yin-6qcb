import time

from fastapi import HTTPException

from src.models import Job, Report
from src.services import archive


def create(db, data):
    j = db.get(Job, data.job_id)
    if not j or j.status != 'completed' or not j.approved:
        raise HTTPException(409, '请先选择已完成且获批准的分析结果')
    r = Report(name=data.name, job_id=j.id, destination=data.destination,
               interval_seconds=data.interval_seconds,
               next_run=time.time() + data.delay_seconds, enabled=True)
    db.add(r)
    db.flush()
    return r


def deliver(db, report):
    """兼容旧调用：登记并签章一份归档。"""
    return archive.deliver(db, report)
