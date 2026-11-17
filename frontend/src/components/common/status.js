import {JobStatus,VerifyState,SigningState,KeyStatus} from '../../constants/enums.js';
import {esc} from '../../utils/dom.js';
export const status=v=>'<span class="status '+esc(v)+'">'+esc(JobStatus[v]||v)+'</span>';
const tone=v=>v==='verified'||v==='active'||v==='signed'?'ok':v==='affected'||v==='retired'?'warn':v==='unverified'||v==='unsigned'||v==='pending'?'neutral':'bad';
export const verifyBadge=v=>'<span class="badge '+tone(v)+'">'+esc(VerifyState[v]||v)+'</span>';
export const signingBadge=v=>'<span class="badge '+tone(v)+'">'+esc(SigningState[v]||v)+'</span>';
export const keyBadge=v=>'<span class="badge '+tone(v)+'">'+esc(KeyStatus[v]||v)+'</span>';
