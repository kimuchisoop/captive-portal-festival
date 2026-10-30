'use strict';
(() => {
  const $=id=>document.getElementById(id);let epoch=0,csrf=null;
  window.addEventListener('operator-session',event=>{
    if(!event.detail){epoch++;csrf=null;$('preflight-results').replaceChildren();$('preflight-status').textContent='';}
    $('preflight-panel').hidden=event.detail?.role!=='settings';
  });
  $('preflight-run').addEventListener('click',async()=>{
    const current=epoch;$('preflight-run').disabled=true;$('preflight-status').textContent='設定・鍵・権限・MySQLを確認しています。';
    try{
      const ensure=()=>{if(current!==epoch)throw Object.assign(new Error('ログイン状態が変わりました。'),{stale:true});};
      const session=await window.AdminFeedback.exchange('/v1/admin/session',{cache:'no-store'},ensure);
      if(!session.response.ok||!session.valid){const error=window.AdminFeedback.failure(session.response,session.value);if(session.response.status===401)window.AdminFeedback.expired(error);throw error;}
      csrf=session.value.csrf_token;
      const {response,value:result,valid}=await window.AdminFeedback.exchange('/v1/admin/preflight',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:'{}',cache:'no-store'},ensure);
      if(!response.ok||!valid){const error=window.AdminFeedback.failure(response,result);if(response.status===401)window.AdminFeedback.expired(error);throw error;}
      $('preflight-results').replaceChildren();
      for(const item of result.checks){const row=document.createElement('div');row.className='item';const title=document.createElement('strong');title.textContent=`${{pass:'確認済み',fail:'要修正',warning:'要確認',skipped:'省略'}[item.status]}：${item.label}`;const text=document.createElement('p');text.textContent=item.detail;row.append(title,text);$('preflight-results').append(row);}
      $('preflight-status').textContent=`要修正 ${result.failed}件。本番運用の準備完了を意味しません。`;
    }catch(error){if(current===epoch)$('preflight-status').textContent=error.message;}
    finally{$('preflight-run').disabled=false;}
  });
})();
