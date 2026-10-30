'use strict';
(() => {
  const label=document.getElementById('session-remaining'),warning=document.getElementById('session-warning');
  let anchor=0,remaining=0,timer=null,warned=false,epoch=0,expiry=null;
  function tick(){
    const seconds=Math.max(0,Math.ceil((remaining-(performance.now()-anchor))/1000));
    label.textContent=`ログイン期限まで ${Math.floor(seconds/60)}分${seconds%60}秒`;
    if(seconds<=120&&!warned){warned=true;warning.hidden=false;warning.textContent='ログイン期限まで2分以内です。未保存の入力を保存してください。期限切れ時は入力を消去します。再ログインで新しいセッションを開始できます。';}
    if(!seconds){clearInterval(timer);window.dispatchEvent(new Event('operator-expired'));}
  }
  function set(info){anchor=performance.now();remaining=Date.parse(info.expires_at_utc)-Date.parse(info.server_now_utc);if(!Number.isFinite(remaining))return;clearInterval(timer);if(expiry!==info.expires_at_utc){warned=false;warning.hidden=true;}expiry=info.expires_at_utc;tick();if(remaining>0)timer=setInterval(tick,1000);}
  window.addEventListener('operator-session-time',e=>set(e.detail));
  window.addEventListener('operator-session',e=>{if(!e.detail){epoch++;clearInterval(timer);timer=null;expiry=null;label.textContent='';warning.hidden=true;}});
  document.addEventListener('visibilitychange',()=>{if(timer&&!document.hidden)tick();});
  document.getElementById('session-check').addEventListener('click',async()=>{
    const active=epoch,ensure=()=>{if(active!==epoch)throw Object.assign(new Error('ログイン状態が変わりました。'),{stale:true});};
    try{
      const {response,value,valid}=await window.AdminFeedback.exchange('/v1/admin/session-status',{cache:'no-store'},ensure);
      if(!response.ok||!valid){const error=window.AdminFeedback.failure(response,value);if(response.status===401){window.AdminFeedback.expired(error);return;}throw error;}
      set(value);
    }catch(error){if(active===epoch&&!error.stale){warning.hidden=false;warning.textContent='期限を再確認できません。表示中の期限は延長しません。 '+error.message;}}
  });
})();
