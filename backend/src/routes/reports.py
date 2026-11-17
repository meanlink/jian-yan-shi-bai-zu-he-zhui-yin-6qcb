import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from src.config.database import get_db
from src.models import Report, Delivery
from src.schemas.report import ReportInput
from src.middlewares.auth import current_user, admin_only
from src.services import reports, archive
from src.services.audit import record
from src.utils.serialization import report_dict, delivery_dict
router=APIRouter()
@router.get('/reports')
def listing(db=Depends(get_db),u=Depends(current_user)):
    return [report_dict(r) for r in db.scalars(select(Report).order_by(Report.id.desc()))]
@router.post('/reports',status_code=201)
def create(data:ReportInput,db=Depends(get_db),u=Depends(admin_only)):
    r=reports.create(db,data); record(db,u.email,'report.schedule',{'id':r.id,'destination':r.destination}); db.commit()
    return report_dict(r)
@router.post('/reports/{id}/toggle')
def toggle(id:int,db=Depends(get_db),u=Depends(admin_only)):
    r=db.get(Report,id)
    if not r:raise HTTPException(404,'分发计划不存在')
    r.enabled=not r.enabled;record(db,u.email,'report.toggle',{'id':id,'enabled':r.enabled});db.commit()
    return report_dict(r)
@router.get('/deliveries')
def deliveries(db=Depends(get_db),u=Depends(current_user)):
    return [delivery_dict(d) for d in db.scalars(select(Delivery).order_by(Delivery.id.desc()).limit(100))]
@router.get('/deliveries/{id}/download')
def download(id:int,format:str='csv',db=Depends(get_db),u=Depends(current_user)):
    d=db.get(Delivery,id)
    if not d:raise HTTPException(404,'归档不存在')
    if format not in ('csv','json','manifest','signature'):raise HTTPException(422,'支持 CSV、JSON、清单或签章')
    if d.signing_state=='pending':
        raise HTTPException(409,'归档尚未完成签章与落盘，暂不开放下载')
    if d.signing_state=='unsigned' and format in ('manifest','signature'):
        raise HTTPException(409,'历史归档没有数字签章附件')
    if d.signing_state=='signed':
        missing=[os.path.basename(p) for p in archive.archive_paths(d).values() if not os.path.isfile(p)]
        if missing:raise HTTPException(409,'归档缺件（'+'、'.join(missing)+'），暂不开放下载')
    suffix={'csv':'','json':'.json','manifest':'.manifest.json','signature':'.sig.json'}[format]
    filename=d.filename+suffix
    p=os.path.join(archive.ARTIFACT_DIR,filename)
    if not os.path.exists(p):raise HTTPException(404,'归档文件不存在或已缺件')
    media_type={'csv':'text/csv; charset=utf-8','json':'application/json','manifest':'application/json','signature':'application/json'}[format]
    return FileResponse(p,filename=filename,media_type=media_type)
