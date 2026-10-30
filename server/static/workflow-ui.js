'use strict';
(() => {
  const $=id=>document.getElementById(id), planRoot='/v1/admin/event-information/plans', exportRoot='/v1/admin/consent-archive-exports';
  let epoch=0,user=null,activeIdentity='',selectedPlan=null,preview=null,planCursor=null,jobCursor=null,alertCursor=null;
  const keys=new Map();
  const generations={plans:0,planDetail:0,jobs:0,jobDetail:0,alerts:0,preview:0};
  function latest(kind,more=false){
    const identity=epoch,version=more?generations[kind]:++generations[kind];
    return ()=>{if(identity!==epoch||version!==generations[kind])throw Object.assign(new Error('表示が更新されました。'),{stale:true});};
  }
  function viewGuard(parent){
    const root=parent.closest('#workflow-plan-detail,#workflow-export-detail,#workflow-preview');
    const token=root?.dataset.workflowRevision,identity=epoch;
    return ()=>{if(identity!==epoch||!parent.isConnected||(root&&root.dataset.workflowRevision!==token))throw Object.assign(new Error('表示が更新されました。'),{stale:true});};
  }
  const status=text=>{$('workflow-status').textContent=text;};
  function navigate(name){const control=document.querySelector('[data-admin-view="'+name+'"]');if(control&&!control.disabled)control.click();}
  const date=value=>value?new Date(value).toLocaleString('ja-JP',{timeZone:'Asia/Tokyo'})+' JST':'未確認';
  const jst=value=>new Date(value+(value.length===16?':00':'')+'+09:00').toISOString().replace('.000Z','Z');
  const labels={saved:'保存済み',review_pending:'別担当の確認待ち',reviewed:'確認済み',review_required:'再確認が必要',withdrawn:'取り下げ',queued:'準備待ち',preparing:'準備中',ready:'準備完了',failed:'準備失敗',recovery_required:'復旧後の照合が必要',not_attempted:'未適用',unknown:'未確認',restart_required:'再起動・反映確認待ち',partial:'一部の反映を確認',matched:'アプリと定期処理の反映を確認',superseded:'後続の設定あり',conflict:'照合が必要'};
  const proofNames={matches:'一致',missing:'見つかりません',mismatch:'不一致',unreadable:'読み取り不能',verified:'照合済み',report_missing:'確認資料が見つかりません',report_mismatch:'確認資料が不一致',not_checked:'未確認'};
  const preparationErrors={row_limit_exceeded:'対象件数が上限を超えました。検索期間を分けて新しく依頼してください。',source_read_interrupted:'元の記録の読み取りを完了できませんでした。担当者が状態を確認してから再依頼してください。',storage_unavailable:'保存処理を完了できませんでした。保存先と容量を確認してください。',preparation_interrupted:'準備が中断しました。途中の記録は保持しています。',snapshot_integrity_error:'出力コピーの整合性を確認できません。サーバー担当へ連絡してください。'};
  async function api(path,data){
    const current=epoch,headers={'Content-Type':'application/json'};
    const ensure=()=>{if(current!==epoch)throw Object.assign(new Error('表示が更新されました。'),{stale:true});};
    let intent;
    if(data!==undefined){
      const session=await window.AdminFeedback.exchange('/v1/admin/session',{cache:'no-store'},ensure);
      if(!session.response.ok||!session.valid){
        const error=window.AdminFeedback.failure(session.response,session.value);
        if(session.response.status===401)window.AdminFeedback.expired(error);
        throw error;
      }
      headers['X-CSRF-Token']=session.value.csrf_token;
      intent=JSON.stringify([path,data]);if(!keys.has(intent))keys.set(intent,crypto.randomUUID());
      headers['Idempotency-Key']=keys.get(intent);
    }
    ensure();
    const {response,value,valid}=await window.AdminFeedback.exchange(path,{method:data===undefined?'GET':'POST',headers,body:data===undefined?undefined:JSON.stringify(data),cache:'no-store'},ensure);
    if(!response.ok||!valid){
      const error=window.AdminFeedback.failure(response,value,{write:data!==undefined});
      if(response.status===401)window.AdminFeedback.expired(error);
      if(response.status===409)keys.delete(intent);
      throw error;
    }
    if(intent)keys.delete(intent);
    return value;
  }
  function button(parent,title,action){
    const element=document.createElement('button');element.type='button';element.className='secondary';element.textContent=title;
    element.addEventListener('click',async()=>{element.disabled=true;try{await action();}catch(error){if(!error.stale)status(error.message);}finally{element.disabled=false;}});
    parent.append(element);return element;
  }
  function card(parent,title,text){
    const section=document.createElement('article'),heading=document.createElement('h3'),body=document.createElement('p');
    heading.textContent=title;body.textContent=text;section.append(heading,body);parent.append(section);return section;
  }
  function listMore(id,cursor,load){$(id).replaceChildren();if(cursor)button($(id),'続きを表示',()=>load(true));}
  async function loadPlans(more=false){
    const ensure=latest('plans',more);
    const value=await api(planRoot+(more&&planCursor?'?cursor='+encodeURIComponent(planCursor):''));
    ensure();
    if(!more)$('workflow-plans').replaceChildren();
    for(const plan of value.items){
      const row=card($('workflow-plans'),labels[plan.effective_state]||plan.effective_state,`${date(plan.created_at_utc)} ／ 版 ${plan.version}`);
      button(row,'案の内容と確認状況',()=>showPlan(plan.plan_id));
    }
    if(!more&&!value.items.length)$('workflow-plans').textContent='登録された変更案はありません。上の案内情報フォームから保存できます。';
    planCursor=value.next_cursor;listMore('workflow-plans-more',planCursor,loadPlans);
  }
  async function showPlan(id){
    const ensure=latest('planDetail');
    $('workflow-plan-detail').dataset.workflowRevision=String(generations.planDetail);
    const plan=await api(planRoot+'/'+encodeURIComponent(id));ensure();selectedPlan=plan;const root=$('workflow-plan-detail');root.replaceChildren();root.dataset.workflowRevision=String(generations.planDetail);
    navigate('maintenance');
    card(root,'変更案 '+plan.plan_id,`${labels[plan.effective_state]} ／ 版 ${plan.version} ／ 原本：${proofNames[plan.source_file_status]||'未確認'} ／ 対象：${plan.target_matches?'一致':'不一致'}`);
    const names={name_ja:'学校祭名',name_en:'学校祭名（英語）',ssid:'SSID',contact_ja:'窓口',contact_en:'窓口（英語）',period_confirmed:'会期確認',service_start_utc:'受付開始',service_end_utc:'受付終了'};
    const table=document.createElement('table'),header=document.createElement('tr');
    for(const value of ['項目','保存時の設定','変更案']){const cell=document.createElement('th');cell.textContent=value;header.append(cell);}table.append(header);
    for(const [key,label] of Object.entries(names)){
      const row=document.createElement('tr');
      for(const value of [label,plan.base_values[key],plan.values[key]]){const cell=document.createElement('td');cell.textContent=value===null?'未確定':typeof value==='boolean'?(value?'確認済み':'未確認'):String(value);row.append(cell);}table.append(row);
    }root.append(table);
    if(plan.import_provenance)card(root,'旧案からの取り込み',`元の案 ${plan.import_provenance.source_plan_id} ／ 証拠の状態：${proofNames[plan.import_provenance.status]||'未確認'}`);
    if(plan.reason_codes.length)card(root,'再確認する内容','対象・元設定・原本・確認者・期限のいずれかが現在の条件と一致しません。対象が異なる場合は現在の設定から新しい案を作成してください。');
    if(plan.review_valid_until_utc)card(root,'確認の有効期限',date(plan.review_valid_until_utc));
    const data={expected_version:plan.version,content_sha256:plan.content_sha256,note:null};
    if(plan.target_matches&&plan.base_config_matches&&plan.state!=='withdrawn'){
      button(root,'別担当へ確認を依頼',async()=>{ensure();await api(planRoot+'/'+id+'/review-requests',data);ensure();await showPlan(id);await loadPlans();});
      if(plan.state==='review_pending'&&plan.created_by!==user.id)button(root,'内容を確認して承認を記録',async()=>{ensure();await api(planRoot+'/'+id+'/reviews',data);ensure();await showPlan(id);await loadPlans();});
    }
    if(plan.state!=='withdrawn')button(root,'不要な案として取り下げ',async()=>{ensure();await api(planRoot+'/'+id+'/withdrawals',{...data,reason_code:'not_required'});ensure();await showPlan(id);await loadPlans();});
    button(root,'確認・変更の履歴',async()=>showEvents(planRoot+'/'+id+'/events',root,'plan'));
    button(root,'適用と反映の状況',async()=>{
      const result=await api(planRoot+'/'+id+'/application-status');
      ensure();
      card(root,'適用と反映',`${labels[result.activation_state]}。APの通信許可は未確認です。`);
      card(root,'サーバー担当へ渡す情報',`変更案番号：${plan.plan_id} ／ 版：${plan.version}。確認済みの案は停止中のサーバー端末で適用します。`);
      const attempts=await api(planRoot+'/'+id+'/apply-attempts');
      ensure();
      for(const attempt of attempts.items){
        const item=card(root,'適用の記録',`${date(attempt.created_at_utc)} ／ ${attempt.latest_observation?.outcome||'照合未完了'}`);
        button(item,'照合の履歴',()=>showEvents(planRoot+'/'+id+'/apply-attempts/'+attempt.attempt_id+'/observations',item,'observation'));
      }
      if(attempts.next_cursor)button(root,'以前の適用記録',()=>showEvents(planRoot+'/'+id+'/apply-attempts',root,'attempt',attempts.next_cursor));
    });
  }
  async function showEvents(path,parent,kind,cursor){
    const ensure=viewGuard(parent);
    const value=await api(path+(cursor?'?cursor='+encodeURIComponent(cursor):''));
    ensure();
    for(const item of value.items){
      const action=kind==='observation'?item.outcome:kind==='attempt'?item.latest_observation?.outcome||'照合未完了':item.kind;
      const row=card(parent,'履歴',`${date(item.created_at_utc)} ／ ${action} ${item.version?'／ 版 '+item.version:''}`);
      if(kind==='attempt')button(row,'照合の履歴',()=>showEvents(path+'/'+item.attempt_id+'/observations',row,'observation'));
    }
    if(value.next_cursor)button(parent,'以前の履歴',()=>showEvents(path,parent,kind,value.next_cursor));
  }
  async function loadJobs(more=false){
    const ensure=latest('jobs',more);
    const value=await api(exportRoot+(more&&jobCursor?'?cursor='+encodeURIComponent(jobCursor):''));
    ensure();
    if(!more)$('workflow-exports').replaceChildren();
    for(const job of value.items){const row=card($('workflow-exports'),labels[job.effective_state],`${date(job.created_at_utc)} ／ 依頼番号 ${job.export_id}`);button(row,'詳細と取得',()=>showJob(job.export_id));}
    if(!more&&!value.items.length)$('workflow-exports').textContent='自分の出力依頼はありません。';
    jobCursor=value.next_cursor;listMore('workflow-exports-more',jobCursor,loadJobs);
  }
  async function showJob(id){
    const ensure=latest('jobDetail');
    $('workflow-export-detail').dataset.workflowRevision=String(generations.jobDetail);
    const job=await api(exportRoot+'/'+encodeURIComponent(id));ensure();const root=$('workflow-export-detail');root.replaceChildren();root.dataset.workflowRevision=String(generations.jobDetail);
    navigate('records');
    card(root,labels[job.effective_state],`依頼番号 ${job.export_id} ／ 検索基準 ${date(job.as_of_utc)}。元の記録は削除しません。`);
    if(job.error_code)card(root,'準備できなかった理由',preparationErrors[job.error_code]||'サーバー担当へ状態の確認を依頼してください。');
    if(job.snapshot){card(root,'固定した出力対象',`${job.snapshot.total_count}件 ／ 準備完了 ${date(job.snapshot.prepared_at_utc)}。準備完了は端末への保存完了を意味しません。`);button(root,'先頭のCSVページを取得',()=>download(job,job.snapshot.first_page_cursor,root));}
    if(job.state==='failed')button(root,'同じ条件で新しく準備を依頼',async()=>{ensure();const next=await api(exportRoot,{filters:job.filters,retry_of:job.export_id});ensure();await loadJobs();ensure();await showJob(next.export_id);});
    button(root,'準備と取得の履歴',()=>showEvents(exportRoot+'/'+id+'/events',root,'export'));
    button(root,'現在の状態を更新',()=>showJob(id));
  }
  async function download(job,cursor,parent,afterOrdinal=0){
    const ensure=viewGuard(parent);
    const file=await window.AdminFeedback.csv(exportRoot+'/'+job.export_id+'/content?cursor='+encodeURIComponent(cursor),ensure,
      {kind:'archive',exportId:job.export_id,snapshotId:job.snapshot.snapshot_id,totalCount:job.snapshot.total_count,afterOrdinal});
    ensure();
    const url=URL.createObjectURL(file.blob),link=document.createElement('a');link.href=url;
    link.download=file.filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    status('CSVページを生成しました。ファイルの保存完了は端末側で確認してください。');
    const next=file.nextCursor;if(next)button(parent,'次のCSVページを取得',()=>download(job,next,parent,file.pageEnd));
  }
  async function loadAlerts(more=false){
    const ensure=latest('alerts',more);
    const value=await api('/v1/admin/workflow-alerts'+(more&&alertCursor?'?cursor='+encodeURIComponent(alertCursor):''));
    ensure();
    if(!more)$('workflow-alerts').replaceChildren();
    for(const alert of value.items){
      const row=card($('workflow-alerts'),alert.message,labels[alert.effective_state]||'担当者による確認が必要です。');
      if(alert.resource_kind==='archive_export')button(row,'自分の依頼を確認',()=>showJob(alert.resource_id));
      else if(alert.plan_id&&user.role==='settings')button(row,'変更案を確認',()=>showPlan(alert.plan_id));
    }
    if(!more&&!value.items.length)$('workflow-alerts').textContent='自分の権限で表示する作業はありません。公開通知と定期処理の状態も確認してください。';
    alertCursor=value.next_cursor;listMore('workflow-alerts-more',alertCursor,loadAlerts);
  }
  $('workflow-plans-refresh').addEventListener('click',()=>loadPlans().catch(e=>{if(!e.stale)status(e.message);}));
  $('workflow-exports-refresh').addEventListener('click',()=>loadJobs().catch(e=>{if(!e.stale)status(e.message);}));
  $('workflow-alerts-refresh').addEventListener('click',()=>loadAlerts().catch(e=>{if(!e.stale)status(e.message);}));
  $('workflow-import').addEventListener('submit',async event=>{
    event.preventDefault();const submitter=window.AdminFeedback.submitButton(event);if(submitter)submitter.disabled=true;
    try{const current=await api('/v1/admin/event-information');const value=await api('/v1/admin/event-information/plan-imports',{report_id:$('workflow-report-id').value.trim(),report_sha256:$('workflow-report-sha').value.trim(),expected_config_sha256:current.config_sha256});await loadPlans();await showPlan(value.plan_id);status('旧案を新しい変更案として登録しました。別担当の確認が必要です。');}
    catch(error){if(!error.stale)status(error.message);}finally{if(submitter)submitter.disabled=false;}
  });
  $('workflow-search').addEventListener('submit',async event=>{
    event.preventDefault();const submitter=window.AdminFeedback.submitButton(event);if(submitter)submitter.disabled=true;
    const ensure=latest('preview');
    try{
      const filters={event_id:$('workflow-event-id').value.trim(),accepted_start_utc:jst($('workflow-from').value),accepted_end_utc:jst($('workflow-until').value),language:$('workflow-language').value||null,deadline_scope:$('workflow-deadline').value};
      preview=filters;
      const params=new URLSearchParams({...filters,language:filters.language||''});const value=await api('/v1/admin/consent-archives?'+params);ensure();
      $('workflow-preview').replaceChildren();$('workflow-preview').dataset.workflowRevision=String(generations.preview);
      for(const item of value.items)card($('workflow-preview'),date(item.accepted_at_utc),`${item.language} ／ ${item.deadline_scope==='processing_deadline_elapsed'?'処理期限超過・保持中':'処理期限内'}`);
      if(value.next_cursor)button($('workflow-preview'),'プレビューの続きを表示',()=>previewMore(filters,value.next_cursor,ensure));
      if(!value.items.length)$('workflow-preview').textContent='条件に一致する記録はありません。';
      buttonCreate($('workflow-preview'),filters);
    }catch(error){if(!error.stale)status(error.message);}finally{if(submitter)submitter.disabled=false;}
  });
  async function previewMore(filters,cursor,ensure){
    ensure();
    const params=new URLSearchParams({...filters,language:filters.language||'',cursor}),value=await api('/v1/admin/consent-archives?'+params);
    ensure();
    for(const item of value.items)card($('workflow-preview'),date(item.accepted_at_utc),`${item.language} ／ ${item.deadline_scope==='processing_deadline_elapsed'?'処理期限超過・保持中':'処理期限内'}`);
    if(value.next_cursor)button($('workflow-preview'),'プレビューの続きを表示',()=>previewMore(filters,value.next_cursor,ensure));
  }
  function buttonCreate(parent,filters){button(parent,'この条件でCSVの準備を依頼',async()=>{const result=await api(exportRoot,{filters,retry_of:null});await loadJobs();await showJob(result.export_id);status('準備を受け付けました。完了後にCSVを取得できます。');});}
  window.addEventListener('operator-session',event=>{
    const next=event.detail||null,identity=next?next.id+':'+next.role:'';
    if(identity===activeIdentity)return;
    activeIdentity=identity;user=next;epoch++;keys.clear();selectedPlan=null;preview=null;planCursor=jobCursor=alertCursor=null;
    for(const id of ['workflow-plans','workflow-plan-detail','workflow-exports','workflow-export-detail','workflow-alerts','workflow-preview','workflow-plans-more','workflow-exports-more','workflow-alerts-more'])$(id).replaceChildren();
    $('workflow-import').reset();$('workflow-search').reset();status('');
    $('workflow-plans-panel').hidden=!next||next.role!=='settings';
    $('workflow-import-panel').hidden=!next||next.role!=='settings';
    $('workflow-archive-panel').hidden=!next||!['records','settings'].includes(next.role);
    $('workflow-alerts-panel').hidden=!next;
    // Fetch on explicit action only: hidden tabs do not introduce another polling loop.
  });
})();
