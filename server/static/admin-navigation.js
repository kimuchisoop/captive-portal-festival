'use strict';
(() => {
  const $=id=>document.getElementById(id);
  const mapping={event:['service-panel','usage-panel','notifications-panel','daily-panel','handover-panel','grants-panel','workflow-alerts-panel'],
    records:['records-panel','backups-panel','audit-panel','support-panel','workflow-archive-panel'],
    maintenance:['preflight-panel','storage-panel','growth-panel','mfa-status-panel','terms-editor-panel','event-panel','diagnostic-panel','ap-panel','settings-panel','workflow-plans-panel','workflow-import-panel']};
  let selected='event',active=false;
  const buttons=[...document.querySelectorAll('[data-admin-view]')];
  for(const [name,ids] of Object.entries(mapping))for(const id of ids)$('view-'+name).append($(id));
  function show(name,focus=false){
    selected=name;
    for(const key of Object.keys(mapping))$('view-'+key).hidden=key!==name;
    for(const button of buttons)button.setAttribute('aria-pressed',String(button.dataset.adminView===name));
    if(focus)$('view-'+name+'-title').focus();
  }
  for(const button of buttons)button.addEventListener('click',()=>show(button.dataset.adminView,true));
  window.addEventListener('operator-session',event=>{
    const role=event.detail?.role;
    if(!role){active=false;show('event');$('nav-records').disabled=true;return;}
    $('nav-records').disabled=!['records','settings','operator'].includes(role);
    if(!active){active=true;show('event');}
    if(selected==='records'&&$('nav-records').disabled)show('event');
  });
  show('event');
})();
