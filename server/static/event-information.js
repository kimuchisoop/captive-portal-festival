'use strict';
(() => {
 const $=id=>document.getElementById(id),form=$('event-form'),keys=['name_ja','name_en','ssid','contact_ja','contact_en'];
 const ssid=$('event-ssid'),encoder=new TextEncoder();
 let user=null,epoch=0,sha=null,key=crypto.randomUUID(),last=null;
 const local=value=>value?new Date(Date.parse(value)+9*3600000).toISOString().slice(0,19):'';
 const utc=value=>value?new Date(value+(value.length===16?':00':'')+'+09:00').toISOString().replace('.000Z','Z'):null;
 function updateSsid(){
   const bytes=encoder.encode(ssid.value.trim()).length;
   $('event-ssid-bytes').textContent=`${bytes} / 32バイト（前後の空白を除く）。`+(bytes>32?' 上限を超えています。短くしてください。':' 空欄は未確定として保存します。');
   ssid.setCustomValidity(bytes>32?'SSIDをUTF-8で32バイト以内にしてください。':'');
   ssid.setAttribute('aria-invalid',String(bytes>32));return bytes<=32;
 }
 async function api(path,data){
   const active=epoch,headers={'Content-Type':'application/json'};
   const ensure=()=>{if(active!==epoch)throw Object.assign(new Error('ログイン状態が変わりました。'),{stale:true});};
   if(data!==undefined){
     const session=await window.AdminFeedback.exchange('/v1/admin/session',{cache:'no-store'},ensure);
     if(!session.response.ok||!session.valid){const error=window.AdminFeedback.failure(session.response,session.value);if(session.response.status===401)window.AdminFeedback.expired(error);throw error;}
     headers['X-CSRF-Token']=session.value.csrf_token;headers['Idempotency-Key']=key;
   }
   ensure();
   const {response,value,valid}=await window.AdminFeedback.exchange(path,{method:data===undefined?'GET':'POST',headers,body:data===undefined?undefined:JSON.stringify(data),cache:'no-store'},ensure);
   if(!response.ok||!valid){const error=window.AdminFeedback.failure(response,value,{write:data!==undefined});if(response.status===401)window.AdminFeedback.expired(error);throw error;}
   return value;
 }
 async function load(){const r=await api('/v1/admin/event-information');if(!window.EditGuard.confirmReplace(form))return;sha=r.config_sha256;for(const k of keys)$('event-'+k).value=r.values[k]||'';for(const k of ['service_start_utc','service_end_utc'])$('event-'+k).value=local(r.values[k]);$('event-period_confirmed').checked=r.values.period_confirmed;updateSsid();window.EditGuard.reset(form);$('event-status').textContent=r.values.period_confirmed?'現在の設定を読み込みました。':'正式会期は未確認です。表示中の日時はローカル試験用の設定値です。';}
 ssid.addEventListener('input',updateSsid);
 form.addEventListener('reset',()=>queueMicrotask(updateSsid));
 form.addEventListener('submit',async e=>{
   e.preventDefault();if(!updateSsid()){ssid.reportValidity();return;}
   const b=window.AdminFeedback.submitButton(e);if(b)b.disabled=true;
   const active=epoch,submitted=window.EditGuard.capture(form);
   try{
     const values={};for(const k of keys)values[k]=$('event-'+k).value.trim()||null;
     for(const k of ['service_start_utc','service_end_utc'])values[k]=utc($('event-'+k).value);
     values.period_confirmed=$('event-period_confirmed').checked;
     const data={values,config_sha256:sha},serialized=JSON.stringify(data);
     if(last!==null&&last!==serialized)key=crypto.randomUUID();last=serialized;
     const r=await api('/v1/admin/event-information/plans',data);window.EditGuard.saved(form,submitted);
     $('event-status').textContent=`変更案を保存しました：${r.filename}。次は別の設定管理担当者へ内容の確認を依頼してください。確認後、アプリ・定期処理を停止してサーバー端末で手順に沿って適用します。`;
   }catch(error){if(active===epoch&&!error.stale)$('event-status').textContent=error.message;}
   finally{if(b)b.disabled=false;}
 });
 $('event-reload').addEventListener('click',()=>load().catch(e=>{if(!e.stale)$('event-status').textContent=e.message;}));
 window.addEventListener('operator-session',e=>{if(user?.id===e.detail?.id&&user?.role===e.detail?.role)return;epoch++;user=e.detail;sha=null;last=null;key=crypto.randomUUID();form.reset();updateSsid();window.EditGuard.reset(form);$('event-status').textContent='';$('event-panel').hidden=user?.role!=='settings';if(user?.role==='settings')load().catch(error=>{if(!error.stale)$('event-status').textContent=error.message;});});
 updateSsid();
})();
