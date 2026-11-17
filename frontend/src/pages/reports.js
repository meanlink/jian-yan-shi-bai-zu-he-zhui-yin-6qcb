import {jobs,reports,signing} from '../api/entities.js';
import {download,saveTrustDirectory} from '../api/client.js';
import {workspace} from '../stores/workspace.js';
import {session} from '../stores/session.js';
import {heading} from '../components/common/shell.js';
import {verifyBadge,signingBadge,keyBadge} from '../components/common/status.js';
import {VerifyState} from '../constants/enums.js';
import {esc,date,notify} from '../utils/dom.js';
import {submit} from '../hooks/forms.js';

const isAdmin=()=>session.user.role==='admin';

function keyPanel(keys,rotateAllowed){
 const active=keys.filter(k=>k.status==='active');
 const signedCount=keys.reduce((n,k)=>n+(k.signed_count||0),0);
 return '<section class="panel"><div class="section-title"><h2>签章密钥</h2><span>'+keys.length+' 把 · '+signedCount+' 份归档已签章</span></div>'+
  '<p class="hint">归档由服务端持有私钥的 Ed25519 密钥签章；公开的信任目录只含公钥，供独立验真工具使用。负责人可轮换；退役密钥停止新签，旧件仍可验真；泄露密钥应撤销而非删除。</p>'+
  '<div class="key-list">'+keys.map(k=>'<article class="key-row"><div><strong>'+esc(k.key_id)+'</strong> '+keyBadge(k.status)+'<p>'+k.signed_count+' 份归档 · 创建 '+date(k.created_at)+' · '+esc(k.created_by)+'</p>'+
    (k.retired_at?'<small>退役于 '+date(k.retired_at)+'</small> ':'')+
    (k.revoked_at?'<small>撤销于 '+date(k.revoked_at)+' · '+esc(k.revoked_reason||'未填写原因')+'</small>':'')+
    '<pre class="public-key">公钥 '+esc(k.public_key)+'</pre></div>'+
    (isAdmin()&&k.status!=='revoked'?'<button class="button small" data-revoke="'+esc(k.key_id)+'">撤销密钥</button>':'')+
  '</article>').join('')+'</div>'+
  '<div class="key-actions">'+
   (isAdmin()&&rotateAllowed?'<button class="button" id="rotate-key">轮换签章密钥 ↻</button>':'')+
   (isAdmin()&&!active.length?'<p class="warning">当前没有在用密钥，新归档将无法签章。请先轮换密钥。</p>':'')+
   '<button class="button" id="save-trust">下载信任目录（含公钥）↓</button>'+
  '</div>'+
  '<details class="hint-block"><summary>独立验真工具</summary><p>接收方无需私钥，也不需要访问后端。把归档的 CSV、JSON、<code>.manifest.json</code>、<code>.sig.json</code> 四件文件与信任目录放好，运行：</p><pre>python tools/verify_archive.py --trust trust-directory.json \\\n  report-1-delivery-2.csv report-1-delivery-2.csv.json \\\n  report-1-delivery-2.csv.manifest.json report-1-delivery-2.csv.sig.json</pre><p>退出码 0 通过；2 表示篡改、缺件或混搭；3 表示签名有效但签发密钥已撤销。</p></details>'+
  '</section>';
}

function deliveryRow(d){
 const buttons=['csv','json'].map(f=>'<button class="text-button" data-download="'+d.id+'" data-format="'+f+'">'+f.toUpperCase()+' ↓</button>').join('')+
  (d.signing_state==='signed'?'<button class="text-button" data-download="'+d.id+'" data-format="manifest">清单 ↓</button><button class="text-button" data-download="'+d.id+'" data-format="signature">签章 ↓</button>':'');
 return '<div class="delivery"><div><strong>'+esc(d.filename||('归档 #'+d.id))+'</strong> '+signingBadge(d.signing_state)+' '+(d.signing_state==='unsigned'?'':verifyBadge(d.verify_state))+
  '<p>'+esc(d.destination)+' · '+date(d.created_at)+' · 密钥 '+esc(d.key_id||'—')+'</p>'+
  '<small>SHA256 '+esc((d.checksum||'').slice(0,24))+'…'+(d.verify_message?' · '+esc(d.verify_message):'')+'</small>'+
  (d.error?'<small class="error-text">最近一次签章失败：'+esc(d.error)+'（重试 '+d.attempts+' 次）</small>':'')+
  (d.signing_state==='unsigned'?'<small class="warn-text">旧归档没有数字签章，无法确认原件未被替换。</small>':'')+
  '</div><div class="delivery-actions">'+buttons+(d.signing_state==='signed'?'<button class="text-button" data-verify="'+d.id+'">验真</button>':'')+'</div></div>';
}

export async function reportPage(){
 const [list,deliveries,allJobs,keyData]=await Promise.all([reports.list(),reports.deliveries(),jobs.list(),signing.keys()]);workspace.reports=list;
 const approved=allJobs.filter(j=>j.approved&&j.status==='completed');
 const counts={};deliveries.forEach(d=>{const k=d.signing_state==='pending'?'pending':(d.verify_state||'unverified');counts[k]=(counts[k]||0)+1;});
 return heading('05 / DISTRIBUTION','定时分发、归档与数字签章','批准后的结果交付到本地收件箱。每份归档含 CSV 与 JSON 两件附件、SHA256 清单与 Ed25519 签章，接收方可离线验真。','<button class="button" id="refresh-reports">刷新收件箱 ↻</button>')+
  '<div class="report-grid"><section class="panel"><div class="section-title"><h2>创建分发计划</h2></div><form id="report-form"><label>简报名称<input name="name" required minlength="2" value="日间业务复核简报"></label><label>已批准分析<select name="job_id" required>'+approved.map(j=>'<option value="'+j.id+'">'+esc(j.name)+'</option>').join('')+'</select></label><label>业务接收组<input name="destination" value="业务复核组 · 本地收件箱" required></label><div class="parameter-grid"><label>分发周期<select name="interval_seconds"><option value="86400">每日</option><option value="604800">每周</option><option value="60">每分钟（验收）</option></select></label><label>首次执行<select name="delay_seconds"><option value="0">立即</option><option value="60">1 分钟后</option><option value="3600">1 小时后</option></select></label></div><button type="submit" class="primary" '+(session.user.role!=='admin'||!approved.length?'disabled':'')+'>保存分发计划</button></form><p class="hint">由后台 worker 按到期时间生成并签章。仅负责人可创建或暂停；接收组为本地标签。签章中断时按原登记恢复，不重复登记或改签原件。</p></section><section><div class="section-title"><h2>运行中的计划</h2><span>'+list.filter(r=>r.enabled).length+' 条已启用</span></div><div class="schedule-list">'+list.map(r=>'<article><div><strong>'+esc(r.name)+'</strong><p>'+esc(r.destination)+'</p><small>下次 '+date(r.next_run)+' · 周期 '+r.interval_seconds+' 秒</small></div><button class="button small" data-toggle="'+r.id+'" '+(session.user.role!=='admin'?'disabled':'')+'>'+(r.enabled?'暂停':'启用')+'</button></article>').join('')+'</div><section class="panel inbox"><div class="section-title"><h2>本地收件箱</h2><span>'+deliveries.length+' 份归档 · '+Object.entries(counts).map(([k,v])=>v+' '+esc(k==='pending'?'签章中':VerifyState[k]||k)).join(' / ')+'</span></div><div class="inbox-tools"><button class="button small" id="verify-all">全部验真</button></div>'+deliveries.map(deliveryRow).join('')+(!deliveries.length?'<p class="empty">计划执行后，文件会出现在此处。等待片刻后刷新。</p>':'')+'</section></section></div>'+keyPanel(keyData.keys,keyData.rotate_allowed);
}

export function bindReports(refresh){
 document.querySelector('#refresh-reports').onclick=refresh;
 submit(document.querySelector('#report-form'),async f=>{await reports.create({name:f.get('name'),job_id:Number(f.get('job_id')),destination:f.get('destination'),interval_seconds:Number(f.get('interval_seconds')),delay_seconds:Number(f.get('delay_seconds'))});notify('计划已保存，后台将按到期时间归档并签章');await refresh();});
 document.querySelectorAll('[data-toggle]').forEach(b=>b.onclick=async()=>{try{await reports.toggle(b.dataset.toggle);await refresh();}catch(e){notify(e.message,true);}});
 document.querySelectorAll('[data-download]').forEach(b=>b.onclick=()=>download(b.dataset.download,b.dataset.format).catch(e=>notify(e.message,true)));
 document.querySelectorAll('[data-verify]').forEach(b=>b.onclick=async()=>{try{const r=await signing.verify(b.dataset.verify);notify(r.message,r.result!=='verified'&&r.result!=='unsigned');await refresh();}catch(e){notify(e.message,true);}});
 document.querySelector('#verify-all')?.addEventListener('click',async()=>{try{const r=await signing.verifyAll();notify('已验真 '+r.checked+' 份归档：'+Object.entries(r.summary).map(([k,v])=>v+' '+k).join('，'));await refresh();}catch(e){notify(e.message,true);}});
 document.querySelector('#rotate-key')?.addEventListener('click',async()=>{if(!confirm('轮换后旧密钥退役：停止新签，已签章的旧件仍可验真。继续？'))return;try{const k=await signing.rotate();notify('已轮换为密钥 '+k.key_id);await refresh();}catch(e){notify(e.message,true);}});
 document.querySelector('#save-trust')?.addEventListener('click',()=>saveTrustDirectory().catch(e=>notify(e.message,true)));
 document.querySelectorAll('[data-revoke]').forEach(b=>b.onclick=async()=>{const reason=prompt('撤销密钥 '+b.dataset.revoke+' 的原因（将记录并公示在信任目录）：');if(reason===null)return;if(!confirm('撤销后该密钥停止签章，使用它的原件会在验真时标注受影响。继续？'))return;try{await signing.revoke(b.dataset.revoke,reason);notify('密钥已撤销');await refresh();}catch(e){notify(e.message,true);}});
}
