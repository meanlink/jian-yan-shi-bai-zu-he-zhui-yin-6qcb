import {api} from './client.js';
export const datasets={list:()=>api('/datasets'),get:id=>api('/datasets/'+id),create:data=>api('/datasets',{method:'POST',body:JSON.stringify(data)})};
export const jobs={list:()=>api('/jobs'),get:id=>api('/jobs/'+id),create:data=>api('/jobs',{method:'POST',body:JSON.stringify(data)}),approve:id=>api('/jobs/'+id+'/approve',{method:'POST'})};
export const reports={list:()=>api('/reports'),create:data=>api('/reports',{method:'POST',body:JSON.stringify(data)}),toggle:id=>api('/reports/'+id+'/toggle',{method:'POST'}),deliveries:()=>api('/deliveries')};
export const signing={keys:()=>api('/keys'),rotate:()=>api('/keys/rotate',{method:'POST'}),revoke:(key_id,reason)=>api('/keys/'+encodeURIComponent(key_id)+'/revoke',{method:'POST',body:JSON.stringify({reason})}),verify:id=>api('/deliveries/'+id+'/verify'),verifyAll:()=>api('/deliveries/verify-all',{method:'POST'}),trust:()=>api('/trust-directory')};
