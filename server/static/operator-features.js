'use strict';
(() => {
  const $=id=>document.getElementById(id);
  const panels=['handover-panel','growth-panel','terms-editor-panel','mfa-status-panel'];
  const labels={open:'未着手',in_progress:'対応中',handled:'対応記録済み'};
  let user=null,epoch=0,caseCursor=null,preview=null,publication=null;
  let caseGeneration=0,growthGeneration=0,termsGeneration=0;
  const dt=value=>new Date(typeof value==='number'?value*1000:value).toLocaleString('ja-JP',{timeZone:'Asia/Tokyo'});
  const size=value=>(value/1048576).toLocaleString('ja-JP',{maximumFractionDigits:2})+' MiB';
  function clear() {
    epoch++;caseGeneration++;growthGeneration++;termsGeneration++;user=null;preview=null;publication=null;caseCursor=null;
    for(const id of panels)$(id).hidden=true;
    for(const id of ['handover-list','handover-history','growth-rows','growth-forecast','terms-revisions'])$(id).replaceChildren();
    for(const id of ['handover-status','growth-status','terms-editor-status','terms-preview-ja','terms-preview-en','terms-preview-version','mfa-status-text'])$(id).textContent='';
    for(const id of ['terms-version','policy-version','terms-ja','terms-en'])$(id).value='';
    window.EditGuard.reset($('terms-editor'));
    $('terms-preview').hidden=true;$('terms-apply-confirm').checked=false;$('terms-apply').disabled=true;
  }
  async function api(path,data,key) {
    const active=epoch,headers={'Content-Type':'application/json'};
    const ensure=()=>{if(active!==epoch)throw Object.assign(new Error('ログイン状態が変わりました。'),{stale:true});};
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
  function action(parent,label,fn){
    const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent=label;
    b.addEventListener('click',async()=>{b.disabled=true;try{await fn();}catch(e){$('terms-editor-status').textContent=e.message;}finally{b.disabled=false;}});parent.append(b);
  }
  async function loadCases(more=false){
    const generation=more?caseGeneration:++caseGeneration;
    const r=await api('/v1/admin/notification-cases'+(more&&caseCursor?'?before='+caseCursor:''));
    if(generation!==caseGeneration)return;
    if(!more){
      if(!window.EditGuard.confirmReplace($('handover-list')))return;
      $('handover-list').replaceChildren();$('handover-history').replaceChildren();
      if(!r.items.length)paragraph($('handover-list'),'通知はありません。');
      for(const n of r.items){
        const row=document.createElement('details');row.className='item';
        const title=document.createElement('summary');title.textContent=`${labels[n.workflow?.status||'open']} ／ ${n.condition==='resolved'?'検知上は解消':'検知中'} ／ ${n.message}`;row.append(title);
        paragraph(row,`担当：${n.workflow?.assignee_name||'未割り当て'} ／ 発生回：${n.generation}`);
        if(n.workflow)paragraph(row,n.workflow.note);
        if(['operator','settings'].includes(user.role)){
          const form=document.createElement('form');form.dataset.draftName='引き継ぎ';
          const select=document.createElement('select'),state=document.createElement('select'),note=document.createElement('textarea');
          select.id='owner-'+n.id;state.id='state-'+n.id;note.id='note-'+n.id;
          select.append(new Option('未割り当て',''));
          for(const a of r.assignees)select.append(new Option(a.username,a.id));select.value=n.workflow?.assignee||'';
          for(const [value,label] of Object.entries(labels))state.append(new Option(label,value));state.value=n.workflow?.status||'open';
          note.rows=3;note.maxLength=1000;note.required=true;
          for(const [id,text,input] of [[select.id,'担当者',select],[state.id,'対応状況',state],[note.id,'引き継ぎ内容（最大1,000文字）',note]]){
            const label=document.createElement('label');label.htmlFor=id;label.textContent=text;form.append(label,input);
          }
          const save=document.createElement('button');save.textContent='対応履歴を追加';form.append(save);
          // Retain the same request key for a retry of the same payload, including ambiguous network failures.
          let key=crypto.randomUUID(),lastPayload=null;
          form.addEventListener('submit',async e=>{
            e.preventDefault();save.disabled=true;const submitted=window.EditGuard.capture(form);
            const data={generation:n.generation,expected_update_id:n.workflow?.id||null,assignee:select.value||null,status:state.value,note:note.value};
            const serialized=JSON.stringify(data);if(lastPayload!==null&&lastPayload!==serialized)key=crypto.randomUUID();lastPayload=serialized;
            try{await api('/v1/admin/notification-cases/'+n.id,data,key);window.EditGuard.saved(form,submitted);await loadCases();$('handover-status').textContent='対応履歴を追加しました。機器の検知状態は変更していません。';}
            catch(error){$('handover-status').textContent=error.message;}finally{save.disabled=false;}
          });row.append(form);
        }
        $('handover-list').append(row);
      }
    }
    for(const h of r.history)paragraph($('handover-history'),`${dt(h.created_at)} ／ ${h.actor_name} → ${h.assignee_name||'未割り当て'} ／ ${labels[h.status]} ／ ${h.note}`);
    caseCursor=r.next_cursor;$('handover-more').hidden=!caseCursor;
  }
  async function loadGrowth(){
    const generation=++growthGeneration,r=await api('/v1/admin/storage-history');if(generation!==growthGeneration)return;
    $('growth-rows').replaceChildren();$('growth-forecast').replaceChildren();
    $('growth-status').textContent=r.forecast?'増加傾向から計算した参考値です。容量を保証する値ではありません。':'予測に必要な記録がまだ揃っていません。定期処理の稼働を継続してください。';
    for(const sample of r.items.slice().reverse()){
      const row=document.createElement('tr');for(const value of [dt(sample.observed_at_utc),size(sample.database_bytes),size(sample.backup_bytes),size(sample.application_free_bytes)]){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}$('growth-rows').append(row);
    }
    if(r.forecast)for(const [key,label] of [['database','MySQL推定使用量'],['backup','バックアップ']]){
      const f=r.forecast[key];paragraph($('growth-forecast'),`${label}：1日あたり ${size(f.bytes_per_day)} ／ 警告値まで ${f.days_to_warning===null?'算出対象外':f.days_to_warning+'日（参考）'}`);
    }
  }
  async function loadTerms(){
    const generation=++termsGeneration,r=await api('/v1/admin/terms-revisions');if(generation!==termsGeneration)return;
    publication=r.publication;$('terms-revisions').replaceChildren();
    if(!r.items.length)paragraph($('terms-revisions'),'保存した下書きはありません。');
    for(const revision of r.items){
      const row=document.createElement('div');row.className='item';paragraph(row,`${revision.version} ／ ${revision.policy_version} ／ ${dt(revision.created_at_utc)}${publication?.revision_id===revision.id?' ／ ローカル適用中':''}`);
      action(row,'内容をプレビュー',async()=>{
        preview=await api('/v1/admin/terms-revisions/'+revision.id);
        $('terms-preview-version').textContent=preview.version+' ／ '+preview.policy_version;
        $('terms-preview-ja').textContent=preview.ja;$('terms-preview-en').textContent=preview.en;
        $('terms-preview').hidden=false;$('terms-apply-confirm').checked=false;$('terms-apply').disabled=true;
        $('terms-preview').scrollIntoView({block:'start'});
      });$('terms-revisions').append(row);
    }
  }
  let draftKey=crypto.randomUUID(),draftPayload=null,applyKey=crypto.randomUUID();
  $('terms-editor').addEventListener('submit',async e=>{
    e.preventDefault();const b=window.AdminFeedback.submitButton(e);if(b)b.disabled=true;const submitted=window.EditGuard.capture($('terms-editor'));
    const data={version:$('terms-version').value,policy_version:$('policy-version').value,ja:$('terms-ja').value,en:$('terms-en').value};
    const serialized=JSON.stringify(data);if(draftPayload!==null&&draftPayload!==serialized)draftKey=crypto.randomUUID();draftPayload=serialized;
    try{await api('/v1/admin/terms-revisions',data,draftKey);window.EditGuard.saved($('terms-editor'),submitted);await loadTerms();$('terms-editor-status').textContent='新しい下書きを保存しました。適用前にプレビューしてください。';}
    catch(error){$('terms-editor-status').textContent=error.message;}finally{if(b)b.disabled=false;}
  });
  $('terms-apply-confirm').addEventListener('change',()=>{$('terms-apply').disabled=!$('terms-apply-confirm').checked;applyKey=crypto.randomUUID();});
  $('terms-apply').addEventListener('click',async()=>{
    if(!preview||!$('terms-apply-confirm').checked)return;$('terms-apply').disabled=true;
    try{await api('/v1/admin/terms-publications',{revision_id:preview.id,preview_sha256:preview.preview_sha256,expected_publication_id:publication?.id||null},applyKey);
      await loadTerms();$('terms-apply-confirm').checked=false;$('terms-editor-status').textContent='ローカル版へ適用しました。過去の規約・同意記録は保持しています。';}
    catch(error){$('terms-editor-status').textContent=error.message;$('terms-apply').disabled=false;}
  });
  for(const [id,fn,status] of [['handover-refresh',()=>loadCases(),'handover-status'],['handover-more',()=>loadCases(true),'handover-status'],['growth-refresh',loadGrowth,'growth-status'],['terms-refresh',loadTerms,'terms-editor-status']]){
    $(id).addEventListener('click',async()=>{$(id).disabled=true;try{await fn();}catch(e){$(status).textContent=e.message;}finally{$(id).disabled=false;}});
  }
  window.addEventListener('operator-session',async event=>{
    if(!event.detail){clear();return;}
    const same=user&&user.id===event.detail.id&&user.role===event.detail.role;
    if(same)return;clear();user=event.detail;
    for(const id of ['handover-panel','growth-panel','mfa-status-panel'])$(id).hidden=false;
    $('terms-editor-panel').hidden=user.role!=='settings';
    await Promise.allSettled([
      loadCases().catch(e=>{$('handover-status').textContent=e.message;}),
      loadGrowth().catch(e=>{$('growth-status').textContent=e.message;}),
      user.role==='settings'?loadTerms().catch(e=>{$('terms-editor-status').textContent=e.message;}):Promise.resolve(),
      api('/v1/admin/mfa-status').then(r=>{$('mfa-status-text').textContent=r.enabled?`追加認証：有効 ／ 未使用の復旧コード：${r.recovery_codes_remaining}個`:'追加認証：未設定（登録はサーバー端末で行います）';}).catch(()=>{})
    ]);
  });
})();
