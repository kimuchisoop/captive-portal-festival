'use strict';
(() => {
  const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  function failure(response,value={},options={}) {
    const status=response?.status||0,code=typeof value?.code==='string'?value.code:'';
    const uncertain=options.write?'保存・処理の成否が未確認の場合は、状態を更新して結果を確認してください。同じ操作を繰り返す前に、必要に応じてサーバー担当へ連絡してください。':'';
    let hint;
    if(code==='session_capacity_exhausted')hint='新しいログインの受付を停止しています。繰り返し送信せず、サーバー担当へ調査番号を伝えてください。既存の記録やログを削除して対処しないでください。';
    else if(code==='session_guard_capacity'||code==='session_source_unavailable')hint='受付の保護処理により、現在は新しいログインを開始できません。時間をおいてから確認し、続く場合はサーバー担当へ連絡してください。';
    else if(code==='credentials_invalid'||(options.credentials&&status===401))hint='入力した利用者名・パスワード、または認証コードを確認してください。';
    else if(status===401||code==='csrf_invalid')hint='再ログインしてください。未保存の入力は消去されます。';
    else if(code==='idempotency_conflict'||code==='idempotency_expired')hint='同じ内容を新しく登録し直さず、保存済みの内容を担当者と確認してください。';
    else if(status===403)hint='操作権限または接続元の設定を管理担当へ確認してください。';
    else if(status===409)hint='一覧・現在の設定を更新し、最新の内容を確認してから操作してください。';
    else if(status===429){
      const raw=response.headers.get('Retry-After');
      const seconds=raw&&/^\d{1,6}$/.test(raw)?Number(raw):null;
      hint=seconds!==null?`${seconds}秒以上待ってから、状態を確認してください。`:'しばらく待ってから、状態を確認してください。';
    }
    else if(status===400||status===422)hint='入力内容を確認して修正してください。解消しない場合は管理担当へ連絡してください。';
    else if(status===404||status===410)hint='対象が現在も利用できるか、一覧を更新して確認してください。';
    else if(status===503)hint='サーバー担当へ受付設定・サーバーの状態を確認してください。';
    else if(!status)hint=options.write?'通信が中断しました。':'通信できません。接続状態を確認し、更新操作で再取得してください。';
    else hint='応答を確認できません。サーバー担当へ連絡してください。';
    const message=typeof value?.message==='string'&&value.message.length<=500&&!/^[a-z][a-z0-9_]*$/.test(value.message)?value.message:'';
    const bodyId=value?.correlation_id,headerId=response?.headers.get('X-Correlation-ID');
    const correlation=typeof bodyId==='string'&&uuid.test(bodyId)?bodyId:typeof headerId==='string'&&uuid.test(headerId)?headerId:null;
    const text=[message,hint,uncertain,correlation?'調査番号：'+correlation:''].filter(Boolean).join(' ');
    return Object.assign(new Error(text),{code,status,correlation_id:correlation,retryable:value?.retryable===true});
  }
  // Only performs the requested fetch. Never retries or creates request keys.
  async function request(path,options={},ensureCurrent=()=>{}) {
    let response;
    try {response=await fetch(path,options);}
    catch {ensureCurrent();throw failure(null,{}, {write:options.method==='POST'&&!['/v1/admin/session','/v1/admin/login','/v1/admin/mfa','/v1/admin/logout'].includes(path)});}
    ensureCurrent();return response;
  }
  async function decode(response,ensureCurrent) {
    let value={},valid=false;
    try {value=await response.json();valid=Boolean(value&&typeof value==='object'&&!Array.isArray(value));}
    catch {value={};}
    ensureCurrent();
    return {response,value:valid?value:{},valid};
  }
  async function exchange(path,options={},ensureCurrent=()=>{}) {
    const response=await request(path,options,ensureCurrent);
    const decoded=await decode(response,ensureCurrent);
    if(response.ok&&(!decoded.valid||!window.ResponseContracts.accepts(path,options.method||'GET',decoded.value))){
      throw failure(response,{code:'response_invalid'},{write:options.method==='POST'&&!['/v1/admin/session','/v1/admin/login','/v1/admin/mfa','/v1/admin/logout'].includes(path)});
    }
    if(response.ok){
      const data=options.body===undefined?undefined:JSON.parse(options.body);
      if(!window.ResponseContracts.identityMatches(path,options.method||'GET',decoded.value,data))throw failure(response,{code:'response_mismatch'},{write:options.method==='POST'});
    }
    return decoded;
  }
  async function download(path,ensureCurrent=()=>{}) {
    const response=await request(path,{cache:'no-store'},ensureCurrent);
    if(!response.ok){
      const {value}=await decode(response,ensureCurrent),error=failure(response,value);
      if(response.status===401)expired(error);
      throw error;
    }
    return response;
  }
  async function blob(response,ensureCurrent=()=>{}) {
    let value;
    try{value=await response.blob();}
    catch{ensureCurrent();throw failure(null);}
    ensureCurrent();return value;
  }
  // Read-only export validation. Does not verify row data, signatures or disk saves.
  async function csv(path,ensureCurrent=()=>{},expected={}) {
    const response=await download(path,ensureCurrent);
    const invalid=()=>failure(response,{code:'csv_response_invalid',message:'CSVの応答形式またはページ情報を確認できません。保存を中止しました。対象の状態を更新して確認してください。'});
    const next=response.headers.get('X-Next-Cursor');
    const disposition=response.headers.get('Content-Disposition')||'';
    const filename=/^attachment;\s*filename="([^"]+)"$/i.exec(disposition)?.[1];
    if(response.status!==200||response.redirected||response.url!==new URL(path,location.origin).href||
       !/^text\/csv\s*;\s*charset\s*=\s*(?:"utf-8"|utf-8)\s*$/i.test(response.headers.get('Content-Type')||'')||!filename||next===null)throw invalid();
    let pageEnd=null;
    if(expected.kind==='simple'){
      if(!Number.isSafeInteger(expected.after)||expected.after<0||filename!=='consents.csv')throw invalid();
      if(next!==''&&(!/^[1-9][0-9]*$/.test(next)||!Number.isSafeInteger(Number(next))||Number(next)<=expected.after))throw invalid();
    }else if(expected.kind==='archive'){
      const {exportId,snapshotId,totalCount,afterOrdinal}=expected;
      if(typeof exportId!=='string'||!uuid.test(exportId)||typeof snapshotId!=='string'||!uuid.test(snapshotId)||
         response.headers.get('X-Snapshot-ID')!==snapshotId||!Number.isSafeInteger(totalCount)||totalCount<0||
         !Number.isSafeInteger(afterOrdinal)||afterOrdinal<0||afterOrdinal>totalCount)throw invalid();
      pageEnd=afterOrdinal+Math.min(1000,totalCount-afterOrdinal);
      const start=pageEnd>afterOrdinal?afterOrdinal+1:afterOrdinal;
      if(filename!==`consent-archive-${exportId}-${start}-${pageEnd}.csv`)throw invalid();
      if(pageEnd<totalCount){
        if(next.length>2048||!/^[A-Za-z0-9_-]+\.[0-9a-f]{64}$/.test(next))throw invalid();
      }else if(next!=='')throw invalid();
    }else throw invalid();
    const value=await blob(response,ensureCurrent);
    const signature=new TextEncoder().encode('\ufeffid,event_id,terms_version,terms_sha256,policy_version,accepted_at_utc,language,delete_after\r\n');
    let prefix;
    try{prefix=new Uint8Array(await value.slice(0,signature.length).arrayBuffer());}
    catch{ensureCurrent();throw invalid();}
    ensureCurrent();
    if(prefix.length!==signature.length||!signature.every((byte,index)=>byte===prefix[index]))throw invalid();
    return {blob:value,filename,nextCursor:next,pageEnd};
  }
  function submitButton(event) {
    return event.submitter||event.currentTarget.querySelector('button:not([type]),button[type="submit"],input[type="submit"]');
  }
  function expired(error){window.dispatchEvent(new CustomEvent('operator-expired',{detail:{message:error.message}}));}
  window.AdminFeedback={exchange,download,blob,csv,failure,submitButton,expired};
})();
