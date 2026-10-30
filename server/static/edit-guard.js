'use strict';
(() => {
  const baselines=new Map();
  const signature=form=>JSON.stringify([...form.querySelectorAll('input,textarea,select')].filter(e=>!['password','file','submit','button'].includes(e.type)).map(e=>[e.id,e.type==='checkbox'||e.type==='radio'?e.checked:e.value]));
  function scan(){
    for(const form of baselines.keys())if(!form.isConnected)baselines.delete(form);
    for(const form of document.querySelectorAll('form[data-draft-name]'))if(!baselines.has(form))baselines.set(form,signature(form));
  }
  function dirty(container=document){scan();return [...baselines].filter(([f,s])=>container.contains(f)&&signature(f)!==s);}
  function update(){const n=dirty().length,b=document.getElementById('draft-warning');b.hidden=!n;b.textContent=n?`未保存の入力が${n}件あります。画面の切り替えでは保持します。期限切れ時は保護のため消去します。`:'';}
  window.EditGuard={capture:signature,saved(form,submitted){baselines.set(form,submitted);update();},reset(form){baselines.set(form,signature(form));update();},confirmReplace(container){return !dirty(container).length||confirm('未保存の入力が置き換わります。破棄して更新しますか？');},update};
  new MutationObserver(update).observe(document.getElementById('dashboard'),{childList:true,subtree:true});
  document.addEventListener('input',update);document.addEventListener('change',update);
  window.addEventListener('beforeunload',e=>{if(dirty().length){e.preventDefault();e.returnValue='';}});
  document.addEventListener('click',e=>{
    const target=e.target.closest('a,button');if(!target)return;
    const leaving=target.tagName==='A'&&!target.download&&target.getAttribute('href')&&!target.getAttribute('href').startsWith('#');
    if((leaving||['logout','refresh','mfa-restart'].includes(target.id))&&dirty().length&&!confirm('未保存の入力があります。この操作を続けますか？')){e.preventDefault();e.stopImmediatePropagation();}
  },true);
  window.addEventListener('operator-session',e=>{if(!e.detail){baselines.clear();queueMicrotask(update);}});
  scan();update();
})();
