import time, json, logging
from pathlib import Path
from sqlalchemy import select, update
from redis import Redis
from src.config.database import Session
from src.config.settings import REDIS_URL
from src.models import Job, Dataset, Report, Delivery
from src.services.business import analyze
from src.services import archive
from src.services.audit import record
logging.basicConfig(level=logging.INFO)
def execute(job_id):
    with Session() as db:
        j=db.get(Job,job_id)
        if not j or j.status!='queued':return
        j.status='running'; db.commit()
        try:
            d=db.get(Dataset,j.dataset_id)
            result=analyze(d.records,j.params)
            json.dumps(result,allow_nan=False)
            j.result=result;j.status='completed';j.finished_at=time.time()
            record(db,'worker','job.completed',{'id':j.id})
        except Exception as e:
            logging.exception('Analysis failed')
            j.status='failed';j.error=str(e)[:990];j.finished_at=time.time()
            record(db,'worker','job.failed',{'id':j.id,'error':j.error})
        db.commit()
def resume_pending():
    """签章中断的归档按原登记恢复，不重新登记、不改签已完成的原件。"""
    with Session() as db:
        pending=archive.resume_pending(db)
    for delivery_id in pending:
        with Session() as db:
            delivery=db.get(Delivery,delivery_id)
            if not delivery or delivery.signing_state!=archive.PENDING:continue
            # 抢占：用条件更新标记本次尝试，避免多个 worker 同时签同一份。
            claimed=db.execute(update(Delivery).where(
                Delivery.id==delivery_id,
                Delivery.signing_state==archive.PENDING,
            ).values(last_attempt_at=time.time())).rowcount
            db.commit()
            if not claimed:continue
            try:
                archive.finalize(db,delivery)
                record(db,'worker','archive.signed',{'delivery':delivery.id,'key_id':delivery.key_id})
                db.commit()
            except Exception as exc:
                logging.exception('Archive signing retry failed')
                archive.recover_failure(db,delivery_id,exc)
def tick():
    with Session() as db:
        queued=list(db.scalars(select(Job.id).where(Job.status=='queued').limit(3)))
    for job_id in queued:execute(job_id)
    with Session() as db:
        due=list(db.scalars(select(Report).where(Report.enabled==True,Report.next_run<=time.time())))
        for r in due:
            d=archive.claim(db,r)
            if d:db.commit();record(db,'worker','report.queued',{'id':r.id,'delivery':d.id})
        db.commit()
    resume_pending()
def main():
    r=Redis.from_url(REDIS_URL,socket_timeout=3)
    # This Compose stack has a single worker. A crash must not strand its jobs.
    with Session() as db:
        for j in db.scalars(select(Job).where(Job.status=='running')):
            j.status='queued';record(db,'worker','job.recovered',{'id':j.id})
        db.commit()
    while True:
        Path('/tmp/heartbeat').touch()
        try:
            item=r.blpop('analysis:queue',timeout=1)
            if item:execute(int(item[1]))
            tick()
        except Exception:
            logging.exception('Worker retry');time.sleep(2)
if __name__=='__main__':main()
