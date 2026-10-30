'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let csrf, role, timer, exportCursor = 0;
  let auditCursor = null, backupCursor = null, auditFilters = {}, auditOptionsReady = false, backupsLoaded = false, sessionEpoch = 0;
  let auditGeneration=0,backupGeneration=0;
  let activeRefreshes=0;
  const roleNames = {viewer:'閲覧',operator:'運用',records:'記録',settings:'設定管理'};
  const message = text => { $('message').textContent = text; };
  const dt = value => value ? new Date(value).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' }) + ' JST' : '未実行';
  async function api(path, data, key, expectedGeneration) {
    const epoch=sessionEpoch;
    const ensure=()=>{if(epoch!==sessionEpoch)throw Object.assign(new Error('セッションが更新されました。'),{stale:true});};
    const headers = { 'Content-Type': 'application/json' };
    if (csrf) headers['X-CSRF-Token'] = csrf;
    if (key) headers['Idempotency-Key'] = key;
    if (expectedGeneration !== undefined) headers['X-Expected-Generation'] = String(expectedGeneration);
    const {response,value,valid}=await window.AdminFeedback.exchange(path,{method:data===undefined?'GET':'POST',headers,
      body:data===undefined?undefined:JSON.stringify(data),cache:'no-store'},ensure);
    if(!response.ok||!valid){
      const credentials=['/v1/admin/login','/v1/admin/mfa'].includes(path);
      const write=data!==undefined&&!['/v1/admin/session','/v1/admin/login','/v1/admin/mfa','/v1/admin/logout'].includes(path);
      const error=window.AdminFeedback.failure(response,value,{write,credentials});
      if(response.status===401&&path!=='/v1/admin/mfa')signedOut();
      throw error;
    }
    return value;
  }
  function signedOut() {
    sessionEpoch++;
    activeRefreshes=0;
    auditGeneration++;backupGeneration++;
    clearTimeout(timer); $('dashboard').hidden = true; $('login-panel').hidden = false;
    for (const id of ['notifications', 'grants', 'settings', 'users', 'service-info','storage-info','backup-list','audit-list','diagnostic-results','ap-info','ap-requirements']) $(id).replaceChildren();
    for (const id of ['audit-actor','audit-action']) $(id).replaceChildren(new Option('すべて',''));
    for (const id of ['audit-from','audit-until']) $(id).value='';
    for (const id of ['audit-status','diagnostic-status','storage-warning','export-status']) $(id).textContent='';
    auditCursor=null;backupCursor=null;auditFilters={};auditOptionsReady=false;backupsLoaded=false;
    exportCursor = 0;
    $('export').textContent='簡易CSVを取得';
    $('mfa-panel').hidden=true;$('mfa-code').value='';
    window.dispatchEvent(new CustomEvent('operator-session',{detail:null}));
  }
  function item(parent, title, text) {
    const div = document.createElement('div'); div.className = 'item';
    const strong = document.createElement('strong'); strong.textContent = title;
    const p = document.createElement('p'); p.textContent = text;
    div.append(strong, p); parent.append(div); return div;
  }
  function button(parent, title, action) {
    const b = document.createElement('button'); b.className = 'secondary'; b.textContent = title;
    b.addEventListener('click', async () => {
      b.disabled = true;
      try { await action(); await refresh(); } catch (e) { message(e.message); } finally { b.disabled = false; }
    }); parent.append(b);
  }
  function bytes(value) {
    if (value === null || value === undefined) return '未取得';
    if (value < 1024) return value + ' B';
    const units=['KiB','MiB','GiB','TiB'];let number=value/1024,index=0;
    while(number>=1024 && index<units.length-1){number/=1024;index++;}
    return number.toLocaleString('ja-JP',{maximumFractionDigits:1})+' '+units[index];
  }
  function definitions(id,fields) {
    $(id).replaceChildren();
    for(const [label,value] of fields){const a=document.createElement('dt'),b=document.createElement('dd');a.textContent=label;b.textContent=value;$(id).append(a,b);}
  }
  async function loadBackups(more=false) {
    const generation=more?backupGeneration:++backupGeneration;
    $('backups-more').disabled=true;
    try {
      const query=new URLSearchParams();if(more && backupCursor)query.set('before',backupCursor);
      const r=await api('/v1/admin/backups?'+query);
      if(generation!==backupGeneration)return;
      if(!more)$('backup-list').replaceChildren();
      if(!r.items.length && !more)$('backup-list').textContent='バックアップはまだありません。';
      const stateNames={passed:'確認済み',failed:'検証失敗',file_changed:'検証後にファイル変更'};
      for(const b of r.items){
        const decrypt=b.checks?.decrypt,restore=b.checks?.restore;
        const row=item($('backup-list'),dt(b.created_at_utc),`${bytes(b.bytes)} ／ ${b.filename}`);
        const p=document.createElement('p');p.textContent=`復号：${decrypt?stateNames[decrypt.status]+'（'+dt(decrypt.checked_at_utc)+'）':'未確認'} ／ 復元：${restore?stateNames[restore.status]+'（'+dt(restore.checked_at_utc)+'）':'未確認'}`;row.append(p);
        const key=crypto.randomUUID();
        button(row,'復号を検証',async()=>{const checked=await api('/v1/admin/backups/'+encodeURIComponent(b.filename)+'/checks',{},key);await loadBackups();message(checked.status==='passed'?'バックアップを復号し、保存形式を確認しました。復元は別途確認が必要です。':'復号を確認できませんでした。鍵・ファイル・対応する版を確認してください。');});
        button(row,'検証履歴を表示',async()=>{
          const history=await api('/v1/admin/backups/'+encodeURIComponent(b.filename)+'/checks');
          const target=document.createElement('div');
          for(const h of history.items)item(target,`${h.stage==='restore'?'復元':'復号'}：${stateNames[h.status]}`,dt(h.checked_at_utc));
          if(!history.items.length)target.textContent='検証履歴はありません。';
          if(history.next_cursor){const note=document.createElement('p');note.textContent='直近100件を表示しています。以前の記録も保持しています。';target.append(note);}
          const old=row.querySelector('.backup-history');if(old)old.remove();target.className='backup-history';row.append(target);
        });
      }
      backupCursor=r.next_cursor;$('backups-more').hidden=!backupCursor;
      backupsLoaded=true;
    } finally {if(generation===backupGeneration)$('backups-more').disabled=false;}
  }
  async function loadAudit(more=false) {
    const generation=more?auditGeneration:++auditGeneration;
    if(!more){$('audit-list').replaceChildren();$('audit-more').hidden=true;$('audit-status').textContent='検索しています。';auditCursor=null;}
    $('audit-more').disabled=true;
    try {
      const query=new URLSearchParams(auditFilters);
      if(more && auditCursor)for(const [k,v] of Object.entries(auditCursor))query.set(k,v);
      const r=await api('/v1/admin/audit?'+query);
      if(generation!==auditGeneration)return;
      if(!more)$('audit-list').replaceChildren();
      if(!auditOptionsReady){
        for(const [id,values] of [['audit-actor',r.actors],['audit-action',r.actions]]){
          for(const v of values)$(id).append(new Option(v.label,v.id));
        }
        auditOptionsReady=true;
      }
      if(!r.items.length && !more)$('audit-list').textContent='条件に一致する履歴はありません。';
      for(const a of r.items)item($('audit-list'),a.action_label,`${dt(a.created_at_utc)} ／ ${a.actor_label}${a.object_id?' ／ 受付・操作番号 '+a.object_id:''}`);
      auditCursor=r.next_cursor;$('audit-more').hidden=!auditCursor;
      $('audit-status').textContent=more?'続きの履歴を表示しました。':'検索結果を表示しました。';
    } finally {if(generation===auditGeneration)$('audit-more').disabled=false;}
  }
  async function refresh(automatic=false) {
    clearTimeout(timer);
    if(automatic===true&&document.hidden)return;
    const epoch=sessionEpoch;
    let completed=false;
    activeRefreshes++;
    try {
      const info = await api('/v1/admin/overview');
      role = info.user.role;
      window.dispatchEvent(new CustomEvent('operator-session-time',{detail:{server_now_utc:info.server_now_utc,expires_at_utc:info.session_expires_at_utc}}));
      const canOperate = ['operator', 'settings'].includes(role);
      // Apply visibility before showing the dashboard or awaiting further network requests.
      $('grants-panel').hidden=!canOperate;
      for(const id of ['records-panel','backups-panel'])$(id).hidden=!['records','settings'].includes(role);
      for(const id of ['settings-panel','audit-panel','diagnostic-panel','ap-panel'])$(id).hidden=role!=='settings';
      $('login-panel').hidden = true; $('dashboard').hidden = false;
      $('user').textContent = `${info.user.username} / ${roleNames[role]}`;
      window.dispatchEvent(new CustomEvent('operator-session',{detail:info.user}));
      $('consent-count').textContent = info.counts.consents;
      $('grant-count').textContent = info.counts.grants;
      $('pending-count').textContent = info.counts.unconfirmed;
      const dl = $('service-info'); dl.replaceChildren();
      for (const [label, value] of [['受付', info.service_state === 'local_only' ? 'ローカル保存のみ' : '停止・期間外'], ['定期処理の最終成功', dt(info.last_job_at_utc)],
        ['暗号化バックアップ', dt(info.last_backup_at_utc)], ['同意保存期限の目安', info.retention_days ? info.retention_days + '日（自動削除停止）' : '未設定'],
        ['バックアップ期限の目安', info.backup_retention_days ? info.backup_retention_days + '日（自動削除停止）' : '未設定']]) {
        const a = document.createElement('dt'), b = document.createElement('dd'); a.textContent = label; b.textContent = value; dl.append(a, b);
      }
      $('worker-warning').hidden = !info.worker_stale;
      const storage=await api('/v1/admin/storage');
      definitions('storage-info',[['MySQL推定使用量',bytes(storage.database_allocated_bytes)],
        ['バックアップ保存先の合計',bytes(storage.backup_bytes)+(storage.backup_bytes_complete?'':'以上（集計不完全）')],
        ['完成バックアップ',`${bytes(storage.backup_completed_bytes)} ／ ${storage.backup_files}件`],
        ['失敗・作成途中のファイル',`${bytes(storage.backup_partial_bytes)} ／ ${storage.backup_partial_files}件（保持中）`],
        ['その他の通常ファイル',`${bytes(storage.backup_other_regular_bytes)} ／ ${storage.backup_other_regular_files}件`],
        ['アプリ保存先の空き容量',bytes(storage.application_disk_free_bytes)],['MySQLサーバーの空き容量','未取得'],['MySQL警告値',storage.db_warning_bytes?bytes(storage.db_warning_bytes):'未設定'],['バックアップ警告値',storage.backup_warning_bytes?bytes(storage.backup_warning_bytes):'未設定']]);
      const warnings=[];
      if(storage.database_warning)warnings.push('MySQLの推定使用量が警告値に達しています。');
      if(storage.backup_warning)warnings.push('バックアップの合計容量が警告値に達しています。');
      if(!storage.backup_bytes_complete)warnings.push('読み取れない項目があるため、容量の全量を確認できません。ファイルを保持して保存先を確認してください。');
      if(!storage.thresholds_configured)warnings.push('容量の警告値が未設定です。ログは削除せず、設定値と保管容量を確認してください。');
      $('storage-warning').textContent=warnings.join(' ');$('storage-warning').hidden=!warnings.length;
      $('notifications').replaceChildren();
      const notifications = await api('/v1/admin/notifications');
      if (!notifications.items.length) $('notifications').textContent = '現在の通知はありません。定期処理が起動しているかも確認してください。';
      for (const n of notifications.items) {
        const div = item($('notifications'), `${n.severity === 'critical' ? '要対応' : '注意'} · ${n.state === 'acknowledged' ? '確認済み' : '未確認'}`, n.message);
        if (canOperate && n.state !== 'acknowledged') {
          const key=crypto.randomUUID();
          button(div, '確認済みにする', () => api(`/v1/admin/notifications/${n.id}/acknowledgements`, {}, key, n.generation));
        }
      }
      $('grants-panel').hidden = !canOperate;
      if (canOperate) {
        const grants = await api('/v1/admin/grants'); $('grants').replaceChildren();
        if (!grants.items.length) $('grants').textContent = '許可レコードはありません。';
        for (const g of grants.items) {
          const authorization = {pending:'同意保存済み・許可待ち',accepted:'受付側で許可済み',rejected:'受付不可',expired:'期限切れ',revoked:'受付側で失効済み'};
          const observation = {unknown:'未確認',active:'接続情報あり',inactive:'未接続',stale:'更新待ち'};
          const revocation = {none:'要求なし',queued:'要求待ち',acknowledged:'装置応答あり',confirmed:'確認済み',failed:'確認できず'};
          const div = item($('grants'), '許可の記録：' + g.grant_id, `${authorization[g.authorization_status]} ／ 接続の確認：${observation[g.observation_state]} ／ 切断：${revocation[g.revocation_state]} ／ 実機の許可確認なし`);
          if (!['revoked', 'expired'].includes(g.authorization_status)) {
            const key = crypto.randomUUID();
            button(div, '受付側で失効させる', () => api(`/v1/admin/grants/${g.grant_id}/revocations`, { reason: 'operator_request' }, key));
          }
        }
      }
      $('records-panel').hidden = !['records', 'settings'].includes(role);
      $('settings-panel').hidden = role !== 'settings';
      $('backups-panel').hidden = !['records','settings'].includes(role);
      for(const id of ['audit-panel','diagnostic-panel','ap-panel'])$(id).hidden=role!=='settings';
      if(['records','settings'].includes(role) && !backupsLoaded)await loadBackups();
      if (role === 'settings') {
        const settings = await api('/v1/admin/settings'); $('settings').replaceChildren();
        const readinessNames = {approved_terms:'正式な利用条件',official_policy:'利用時間などの正式方針',storage_retention_and_roles:'保存期間・担当者',ap_adapter_compatible:'APとの連携',absolute_expiry_supported:'利用期限の実機制御',infrastructure_built:'ネットワーク構築',required_tests_completed:'実機を含む必要な試験'};
        const fields = [['データベース','MySQL'],['ログの自動削除','停止中'],['動作環境','ローカル開発版'],['本番受付','無効'],['受付開始',dt(settings.service_start_utc)],['受付終了',dt(settings.service_end_utc)],['規約の版',settings.terms_version || '未設定'],['利用方針の版',settings.policy_version || '未設定'],['監査期限の目安',settings.audit_retention_days ? settings.audit_retention_days + '日（自動削除停止）' : '未設定']];
        for (const [key, title] of Object.entries(readinessNames)) fields.push([title, settings.production_readiness[key] ? '確認済み' : '未承認・未確認']);
        for (const [title,value] of fields) {
          const a = document.createElement('dt'), b = document.createElement('dd'); a.textContent = title; b.textContent = value; $('settings').append(a,b);
        }
        const users = await api('/v1/admin/users'); $('users').replaceChildren();
        for (const u of users.items) item($('users'), u.username, `${roleNames[u.role]} / ${u.enabled ? '有効' : '無効'}`);
        if(!auditOptionsReady)await loadAudit();
        const ap=await api('/v1/admin/ap-readiness');
        const apNames={product_model:'製品名',sku:'製品番号',os_family:'OS名',os_version:'OSバージョン',management_mode:'管理方式',manager_address:'管理先'};
        definitions('ap-info',[['認証用型式',ap.regulatory_model+'（製品番号・OSは別途確認）'],...Object.entries(apNames).map(([key,label])=>[label,ap.facts[key] || '未確認']),['次の確認',ap.plan]]);
        $('ap-requirements').replaceChildren();
        for(const r of ap.required_capabilities)item($('ap-requirements'),r.label,'実機での確認待ち');
        for(const error of ap.errors)item($('ap-requirements'),'確認情報の形式',error);
      }
      completed=true;
    } catch (e) { if(!e.stale)message(e.message); }
    finally{
      if(epoch===sessionEpoch){
        activeRefreshes--;
        if(completed&&activeRefreshes===0&&!document.hidden&&!$('dashboard').hidden){
          timer=setTimeout(()=>refresh(true),30000);
        }
      }
    }
  }
  document.addEventListener('visibilitychange',()=>{
    clearTimeout(timer);
    if(!document.hidden&&!$('dashboard').hidden&&activeRefreshes===0)void refresh(true);
  });
  $('login-form').addEventListener('submit', async e => {
    e.preventDefault();
    const b = window.AdminFeedback.submitButton(e); if(b)b.disabled = true;
    try {
      csrf = (await api('/v1/admin/session', {})).csrf_token;
      const result = await api('/v1/admin/login', { username: $('username').value, password: $('password').value });
      $('password').value = ''; csrf = result.csrf_token;
      if(result.mfa_required){$('mfa-panel').hidden=false;$('login-panel').hidden=true;$('mfa-code').focus();message('認証アプリのコード、または復旧コードを入力してください。');}
      else {message('ログインしました。');await refresh();}
    } catch (e) { $('password').value = ''; message(e.message); } finally { if(b)b.disabled = false; }
  });
  $('mfa-form').addEventListener('submit',async e=>{
    e.preventDefault();const b=window.AdminFeedback.submitButton(e);if(b)b.disabled=true;
    try {const r=await api('/v1/admin/mfa',{code:$('mfa-code').value.trim()});csrf=r.csrf_token;$('mfa-panel').hidden=true;$('mfa-code').value='';message('追加認証が完了しました。');await refresh();}
    catch(error){$('mfa-code').value='';message(error.message);}finally{if(b)b.disabled=false;}
  });
  $('mfa-restart').addEventListener('click',()=>{signedOut();message('利用者名とパスワードからログインし直してください。');});
  $('refresh').addEventListener('click', refresh);
  $('backups-more').addEventListener('click',()=>loadBackups(true).catch(e=>message(e.message)));
  $('backups-refresh').addEventListener('click',()=>loadBackups().catch(e=>message(e.message)));
  $('audit-more').addEventListener('click',()=>loadAudit(true).catch(e=>message(e.message)));
  $('audit-form').addEventListener('submit',async e=>{
    e.preventDefault();const b=window.AdminFeedback.submitButton(e);if(b)b.disabled=true;
    try {
      auditFilters={};auditCursor=null;auditGeneration++;
      $('audit-list').replaceChildren();$('audit-more').hidden=true;
      if($('audit-from').value)auditFilters.from=new Date($('audit-from').value+'T00:00:00+09:00').toISOString().replace('.000Z','Z');
      if($('audit-until').value){const until=new Date($('audit-until').value+'T00:00:00+09:00');until.setTime(until.getTime()+86400000);auditFilters.until=until.toISOString().replace('.000Z','Z');}
      if($('audit-actor').value)auditFilters.actor=$('audit-actor').value;
      if($('audit-action').value)auditFilters.action=$('audit-action').value;
      if(auditFilters.from && auditFilters.until && auditFilters.from>=auditFilters.until)throw new Error('開始日が終了日より後になっています。日付を確認してください。');
      await loadAudit();
    }catch(error){$('audit-status').textContent=error.message;}finally{if(b)b.disabled=false;}
  });
  $('diagnostic-run').addEventListener('click',async()=>{
    $('diagnostic-run').disabled=true;$('diagnostic-status').textContent='診断しています。';
    try{
      const r=await api('/v1/admin/diagnostics',{});$('diagnostic-results').replaceChildren();
      if(r.target)item($('diagnostic-results'),'接続先',`${r.target.host}:${r.target.port} ／ ${r.target.database} ／ ${r.target.user}`);
      for(const c of r.checks)item($('diagnostic-results'),`${{pass:'確認済み',warning:'要確認',fail:'確認できず'}[c.status]}：${c.label}`,c.detail);
      $('diagnostic-status').textContent=`診断結果を保存しました。権限変更は行っていません。${r.audit_saved?'':' DB監査への保存はできませんでした。'}`;
      await loadAudit();
    }catch(e){$('diagnostic-status').textContent=e.message;}finally{$('diagnostic-run').disabled=false;}
  });
  $('logout').addEventListener('click', async () => {
    try { await api('/v1/admin/logout', {}); signedOut(); message('ログアウトしました。'); } catch (e) { message(e.message); }
  });
  $('export').addEventListener('click', async () => {
    $('export').disabled = true;
    const epoch=sessionEpoch,after=exportCursor;
    try {
      const ensure=()=>{if(epoch!==sessionEpoch)throw Object.assign(new Error('セッションが更新されました。'),{stale:true});};
      const file=await window.AdminFeedback.csv('/v1/admin/consents/export?after=' + after,ensure,{kind:'simple',after});
      const next=file.nextCursor,blob=file.blob;
      if(epoch!==sessionEpoch||!['records','settings'].includes(role))return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `consents-after-${after}.csv`; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      exportCursor = next ? Number(next) : 0;
      $('export').textContent = next ? '簡易CSVの次の最大1,000件を取得' : '簡易CSVを取得';
      $('export-status').textContent = ' CSVページを生成しました。保存完了は端末側で確認してください。'+(next?' 続きがあります。':'');
    } catch (e) { if(epoch===sessionEpoch)message(e.message); } finally { $('export').disabled = false; }
  });
  async function init() {
    try {
      const s = await api('/v1/admin/session', {}); csrf = s.csrf_token;
      if (s.authenticated) await refresh();
      else if(s.mfa_required){$('mfa-panel').hidden=false;$('login-panel').hidden=true;$('mfa-code').focus();}
    } catch (e) { if(!e.stale)message(e.message); }
  }
  window.addEventListener('operator-expired',event=>{signedOut();message(event.detail?.message||'ログイン期限が切れました。未保存の入力は保護のため消去しました。ログインし直してください。');});
  init();
})();
