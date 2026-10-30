'use strict';
(() => {
  const $=id=>document.getElementById(id);let active=false,generation=0;
  async function load(){
    const current=++generation;if(!active)return;
    $('usage-load').disabled=true;$('usage-status').textContent='集計しています。';
    try{
      const ensure=()=>{if(!active||generation!==current)throw Object.assign(new Error('表示が更新されました。'),{stale:true});};
      const {response,value:result,valid}=await window.AdminFeedback.exchange('/v1/admin/usage-summary?day='+encodeURIComponent($('usage-day').value),{cache:'no-store'},ensure);
      if(!response.ok||!valid){const error=window.AdminFeedback.failure(response,result);if(response.status===401)window.AdminFeedback.expired(error);throw error;}
      $('usage-rows').replaceChildren();
      for(const hour of result.hours){
        const row=document.createElement('tr');
        for(const value of [hour.hour_jst,hour.consents,hour.client_errors,hour.server_errors]){const cell=document.createElement('td');cell.textContent=String(value);row.append(cell);}
        $('usage-rows').append(row);
      }
      const started=result.error_collection_started_at_utc?new Date(result.error_collection_started_at_utc).toLocaleString('ja-JP',{timeZone:'Asia/Tokyo'}):'未確認';
      $('usage-status').textContent=`${result.day_jst}（日本時間）：同意 ${result.total_consents}件 ／ 記録できたエラー ${result.total_errors}件。エラー集計開始：${started} JST。`;
      $('usage-missed').textContent=result.unrecorded_errors_current_process?`この起動中に記録できなかったエラーが${result.unrecorded_errors_current_process}件あります。` : '';
    }catch(error){if(active&&generation===current)$('usage-status').textContent=error.message;}
    finally{if(generation===current)$('usage-load').disabled=false;}
  }
  $('usage-form').addEventListener('submit',event=>{event.preventDefault();load();});
  window.addEventListener('operator-session',event=>{
    const wasActive=active;active=Boolean(event.detail?.role);$('usage-panel').hidden=!active;
    if(!active){generation++;$('usage-rows').replaceChildren();$('usage-status').textContent='';$('usage-missed').textContent='';$('usage-load').disabled=false;return;}
    if(!wasActive){$('usage-day').value=new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Tokyo',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());load();}
  });
})();
