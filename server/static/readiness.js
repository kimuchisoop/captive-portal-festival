'use strict';
(() => {
  const $=id=>document.getElementById(id),outcomes={pending:'未確認',ok:'確認済み',problem:'要対応',na:'対象外'};
  let account=null,epoch=0,generation=0,run=null,cursor=null,loadedFilter=null;
  let startKey=crypto.randomUUID(),supportKey=crypto.randomUUID(),supportPayload=null;
  const dt=value=>new Date(typeof value==='number'?value*1000:value).toLocaleString('ja-JP',{timeZone:'Asia/Tokyo'});
  function clear(){
    epoch++;generation++;account=null;run=null;cursor=null;loadedFilter=null;
    for(const id of ['daily-panel','support-panel'])$(id).hidden=true;
    for(const id of ['daily-items','daily-history','support-list'])$(id).replaceChildren();
    for(const id of ['daily-summary','support-status'])$(id).textContent='';
    $('support-correlation').value='';$('daily-day').value='';$('daily-phase').value='before';
    $('daily-start').hidden=true;$('daily-more').hidden=true;
    startKey=crypto.randomUUID();supportKey=crypto.randomUUID();supportPayload=null;
  }
  async function api(path,data,key) {
    const current=epoch,headers={'Content-Type':'application/json'};
    const ensure=()=>{if(current!==epoch)throw Object.assign(new Error('ログイン状態が変わりました。'),{stale:true});};
    if(data!==undefined){
      const session=await window.AdminFeedback.exchange('/v1/admin/session',{cache:'no-store'},ensure);
      if(!session.response.ok||!session.valid){
        const error=window.AdminFeedback.failure(session.response,session.value);
        if(session.response.status===401)window.AdminFeedback.expired(error);
        throw error;
      }
      headers['X-CSRF-Token']=session.value.csrf_token;headers['Idempotency-Key']=key||crypto.randomUUID();
    }
    ensure();
    const {response,value,valid}=await window.AdminFeedback.exchange(path,{method:data===undefined?'GET':'POST',headers,body:data===undefined?undefined:JSON.stringify(data),cache:'no-store'},ensure);
    if(!response.ok||!valid){
      const error=window.AdminFeedback.failure(response,value,{write:data!==undefined});
      if(response.status===401)window.AdminFeedback.expired(error);
      throw error;
    }
    return value;
  }
  function paragraph(parent,text){const p=document.createElement('p');p.textContent=text;parent.append(p);return p;}
  async function loadDaily(more=false){
    const token=more?generation:++generation;
    const filter=more?loadedFilter:{day:$('daily-day').value,phase:$('daily-phase').value};
    const query=new URLSearchParams();if(filter.day)query.set('day',filter.day);query.set('phase',filter.phase);
    if(more&&cursor)query.set('before',cursor);
    const r=await api('/v1/admin/checklists?'+query);if(token!==generation)return;
    const canEdit=['operator','settings'].includes(account.role);
    if(!more){
      if(!window.EditGuard.confirmReplace($('daily-items')))return;
      run=r.run;loadedFilter={day:r.day,phase:r.phase};$('daily-day').value=r.day;
      $('daily-items').replaceChildren();$('daily-history').replaceChildren();
      $('daily-summary').textContent=`${r.day} ／ 確認済み ${r.summary.confirmed}/${r.summary.total} ／ 未確認 ${r.summary.pending} ／ 要対応 ${r.summary.problems}`;
      $('daily-start').hidden=Boolean(run)||!canEdit;
      if(!run)paragraph($('daily-items'),canEdit?'この日の確認はまだ開始していません。開始すると各項目を記録できます。':'この日の確認はまだ開始していません。運用担当者へ確認してください。');
      for(const item of r.items){
        const row=document.createElement('details');row.className='item';const summary=document.createElement('summary');
        const entry=item.entry;summary.textContent=outcomes[entry?.outcome||'pending']+' ／ '+item.label;row.append(summary);
        if(entry)paragraph(row,`${dt(entry.checked_at)} ／ 記録：${entry.actor_name} ／ 担当：${entry.assignee_name||'未割り当て'}${entry.note?' ／ '+entry.note:''}`);
        if(run&&canEdit){
          const form=document.createElement('form'),owner=document.createElement('select'),outcome=document.createElement('select'),note=document.createElement('textarea');
          form.dataset.draftName='当日の確認';
          owner.id='daily-owner-'+item.item_id;outcome.id='daily-outcome-'+item.item_id;note.id='daily-note-'+item.item_id;
          owner.append(new Option('未割り当て',''));for(const a of r.assignees)owner.append(new Option(a.username,a.id));owner.value=entry?.assignee||account.id;
          for(const [value,label] of Object.entries(outcomes))outcome.append(new Option(label,value));outcome.value=entry?.outcome||'pending';note.rows=3;note.maxLength=1000;
          for(const [input,labelText] of [[owner,'担当者'],[outcome,'確認結果'],[note,'確認内容・未対応事項（要対応・対象外の場合は必須）']]){
            const label=document.createElement('label');label.htmlFor=input.id;label.textContent=labelText;form.append(label,input);
          }
          const save=document.createElement('button');save.textContent='この項目を記録';form.append(save);
          let key=crypto.randomUUID(),lastPayload=null;
          form.addEventListener('submit',async e=>{
            e.preventDefault();save.disabled=true;const submitted=window.EditGuard.capture(form);
            const data={item_id:item.item_id,outcome:outcome.value,assignee:owner.value||null,note:note.value,expected_entry_id:entry?.id||null};
            const text=JSON.stringify(data);if(lastPayload!==null&&lastPayload!==text)key=crypto.randomUUID();lastPayload=text;
            try{await api('/v1/admin/checklists/'+r.run.id+'/entries',data,key);window.EditGuard.saved(form,submitted);await loadDaily();}
            catch(error){$('daily-summary').textContent=error.message;}finally{save.disabled=false;}
          });row.append(form);
        }$('daily-items').append(row);
      }
    }
    for(const h of r.history)paragraph($('daily-history'),`${dt(h.checked_at)} ／ ${h.actor_name} ／ ${outcomes[h.outcome]} ／ ${r.items.find(i=>i.item_id===h.item_id)?.label||h.item_id}${h.note?' ／ '+h.note:''}`);
    cursor=r.next_cursor;$('daily-more').hidden=!cursor;
  }
  async function loadSupport(){
    const r=await api('/v1/admin/support-bundles');$('support-list').replaceChildren();
    for(const report of r.items){
      const row=document.createElement('div');row.className='item';paragraph(row,`${dt(report.created_at_utc)} ／ ${(report.bytes/1024).toFixed(1)} KiB`);
      const link=document.createElement('a');link.href=report.download_url;link.textContent='調査資料をダウンロード';link.download='support-'+report.report_id+'.json';row.append(link);$('support-list').append(row);
    }
    if(!r.items.length)$('support-list').textContent='作成した資料はありません。';
  }
  $('daily-filter').addEventListener('submit',async e=>{e.preventDefault();startKey=crypto.randomUUID();try{await loadDaily();}catch(error){$('daily-summary').textContent=error.message;}});
  $('daily-start').addEventListener('click',async()=>{
    $('daily-start').disabled=true;
    try{await api('/v1/admin/checklists',loadedFilter,startKey);await loadDaily();}
    catch(error){$('daily-summary').textContent=error.message;}finally{$('daily-start').disabled=false;}
  });
  $('daily-more').addEventListener('click',async()=>{try{await loadDaily(true);}catch(error){$('daily-summary').textContent=error.message;}});
  $('support-form').addEventListener('submit',async e=>{
    e.preventDefault();const b=window.AdminFeedback.submitButton(e);if(b)b.disabled=true;
    const data={correlation_id:$('support-correlation').value.trim()||null},text=JSON.stringify(data);
    if(supportPayload!==null&&supportPayload!==text)supportKey=crypto.randomUUID();supportPayload=text;
    try{await api('/v1/admin/support-bundles',data,supportKey);await loadSupport();$('support-status').textContent='調査資料を保存しました。外部へは送信していません。';supportKey=crypto.randomUUID();supportPayload=null;}
    catch(error){$('support-status').textContent=error.message;}finally{if(b)b.disabled=false;}
  });
  window.addEventListener('operator-session',async event=>{
    if(!event.detail){clear();return;}
    if(account&&account.id===event.detail.id&&account.role===event.detail.role)return;
    clear();account=event.detail;$('daily-panel').hidden=false;
    const canOperate=['operator','settings'].includes(account.role);$('support-panel').hidden=!canOperate;
    await Promise.allSettled([loadDaily().catch(e=>{$('daily-summary').textContent=e.message;}),canOperate?loadSupport().catch(e=>{$('support-status').textContent=e.message;}):Promise.resolve()]);
  });
})();
