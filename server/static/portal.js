'use strict';
(() => {
  const $=id=>document.getElementById(id),copy=window.PortalCopy;
  const languageCode=()=> $('language').value==='en'?'en':'ja';
  const text=()=>copy[$('language').value]||copy.ja;
  const launch=new URLSearchParams(location.hash.slice(1)).get('local_launch');
  if(location.hash)history.replaceState(null,'',location.pathname);
  window.addEventListener('hashchange',()=>{
    if(!new URLSearchParams(location.hash.slice(1)).has('local_launch'))return;
    if(leaveRisk()){history.replaceState(null,'',location.pathname);showLeaveWarning();return;}
    location.reload();
  });
  function uuid(){
    if(crypto.randomUUID)return crypto.randomUUID();
    const bytes=crypto.getRandomValues(new Uint8Array(16));bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
    return [...bytes].map((v,i)=>([4,6,8,10].includes(i)?'-':'')+v.toString(16).padStart(2,'0')).join('');
  }
  let csrf,context,terms,ready=false,busy=false,saved=null,pending=null,unconfirmedStatus=false;
  let eventInfo=null,lastFailure=null,bootstrapFailure=null,retryAllowed=true,retryAt=0,retryTimer=null;
  let renderedEventInfo,renderedInformationLanguage;
  let generation=0,state='loading',termsLoading=true;
  let copyBusy=false;
  const retryKey=uuid(),contextKey=uuid();
  const leaveRisk=()=>busy||Boolean(pending&&!saved);
  function showLeaveWarning(){render();$('leave-warning').focus();}
  window.addEventListener('beforeunload',event=>{if(leaveRisk()){event.preventDefault();event.returnValue='';}});
  document.addEventListener('click',event=>{
    const link=event.target instanceof Element?event.target.closest('a[href]'):null;
    if(!leaveRisk()||!link||link.hasAttribute('download')||link.target==='_blank'||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey)return;
    event.preventDefault();showLeaveWarning();
  },true);
  function inquiryText(){
    const t=text(),status=busy?t.saving:saved?t.saved:pending?t.inquiryUnknown:t.inquiryNotSent;
    return [t.inquiryIntro,`${t.inquiryState}: ${status}`,`${t.receipt}: ${saved?.id||t.inquiryUnavailable}`,`${t.correlation}: ${lastFailure?.correlation_id||t.inquiryUnavailable}`].join('\n');
  }
  function failure(response,value={}){
    const status=response?.status||0,rawCode=value?.code;
    const code=typeof rawCode==='string'&&/^[a-z0-9_]{1,80}$/.test(rawCode)?rawCode:'request_failed';
    const pattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const bodyId=value?.correlation_id,headerId=response?.headers.get('X-Correlation-ID');
    const correlation=typeof bodyId==='string'&&pattern.test(bodyId)?bodyId:typeof headerId==='string'&&pattern.test(headerId)?headerId:null;
    const rawWait=response?.headers.get('Retry-After');
    const wait=rawWait&&/^\d{1,6}$/.test(rawWait)?Number(rawWait):null;
    return Object.assign(new Error('Portal request failed'),{code,status,correlation_id:correlation,wait});
  }
  function failureText(error){
    const t=text();let message;
    if(saved)message=t.errorStatus;
    else if(pending)message=retryAllowed?t.errorSameSubmission:t.errorPendingStaff;
    else if(['response_invalid','response_mismatch'].includes(error.code))message=t.errorResponse;
    else if(error.code==='session_capacity_exhausted')message=t.sessionCapacity;
    else if(['session_guard_capacity','session_source_unavailable'].includes(error.code))message=t.sessionProtection;
    else if(error.status===429)message=t.errorWait;
    else if(error.status===401||error.status===403||error.code==='context_not_found')message=t.errorBeforeConsent;
    else if(error.status===410||error.code==='service_closed')message=t.closed;
    else message=error.status?t.errorStaff:t.errorNetwork;
    const wait=pending&&retryAllowed?Math.max(0,Math.ceil((retryAt-performance.now())/1000)):error.status===429?error.wait:null;
    return [message,wait?`${t.waitSeconds}: ${wait}`:'',error.correlation_id?`${t.correlation}: ${error.correlation_id}`:''].filter(Boolean).join(' ');
  }
  function setRetry(error){
    clearTimeout(retryTimer);retryAt=0;
    const blocked=['intake_disabled','service_closed','schema5_recovery_required','adapter_unavailable','session_capacity_exhausted'].includes(error.code);
    retryAllowed=!blocked&&(error.status===0||error.status>=500||(['response_invalid','response_mismatch'].includes(error.code)&&error.status>=200&&error.status<300)||(error.status===429&&error.wait!==null));
    if(retryAllowed&&error.status===429&&error.wait){retryAt=performance.now()+error.wait*1000;retryTimer=setTimeout(render,error.wait*1000+100);}
  }
  async function api(path,data,key,expected){
    const headers={'Content-Type':'application/json'};
    if(csrf)headers['X-CSRF-Token']=csrf;if(key)headers['Idempotency-Key']=key;
    let response;
    try{response=await fetch(path,{method:data===undefined?'GET':'POST',headers,body:data===undefined?undefined:JSON.stringify(data),cache:'no-store'});}
    catch{throw failure(null,{code:'network_unavailable'});}
    let result;
    try{result=await response.json();}catch{throw failure(response,{code:'response_invalid'});}
    if(!response.ok)throw failure(response,result);
    if(!window.ResponseContracts.accepts(path,data===undefined?'GET':'POST',result))throw failure(response,{code:'response_invalid'});
    if(!window.ResponseContracts.identityMatches(path,data===undefined?'GET':'POST',result,data,expected))throw failure(response,{code:'response_mismatch'});
    return result;
  }
  function render(){
    const t=text();document.documentElement.lang=languageCode();document.title=t.title+' · '+(languageCode()==='en'?'Local review':'ローカル確認版');
    const map={'heading':'title','subtitle':'subtitle','local-notice':'notice','admin-link':'admin','footer':'footer','skip-link':'skip','terms-heading':'termsHeading','terms-help':'termsHelp','agreement':'agreement','text-standard':'standard','text-large':'large','contrast-standard':'contrastNormal','contrast-high':'contrastHigh','text-size-label':'size','contrast-label':'contrast','portal-help-title':'helpTitle','portal-help-text':'helpText'};
    for(const [id,key] of Object.entries(map))$(id).textContent=t[key];
    $('event-info-title').textContent=t.infoTitle;
    const name=eventInfo&&(languageCode()==='en'?(eventInfo.name_en||eventInfo.name_ja):(eventInfo.name_ja||eventInfo.name_en));
    if(name){$('heading').textContent=name+' Wi-Fi';$('heading').lang=languageCode()==='en'&&eventInfo.name_en?'en':eventInfo.name_ja?'ja':'en';document.title=name+' Wi-Fi';}else $('heading').lang=languageCode();
    if(renderedEventInfo!==eventInfo||renderedInformationLanguage!==$('language').value){
      const contact=eventInfo&&(languageCode()==='en'?(eventInfo.contact_en||eventInfo.contact_ja):(eventInfo.contact_ja||eventInfo.contact_en));
      const dates=eventInfo?.period_confirmed&&eventInfo.service_start_utc&&eventInfo.service_end_utc?[eventInfo.service_start_utc,eventInfo.service_end_utc].map(v=>new Date(v).toLocaleString(languageCode()==='en'?'en-GB':'ja-JP',{timeZone:'Asia/Tokyo'})).join(' - ')+' JST'+(eventInfo.daily_service_hours?' / '+eventInfo.daily_service_hours.open+'-'+eventInfo.daily_service_hours.close:''):t.unconfirmed;
      const fragment=document.createDocumentFragment();
      for(const [label,value] of [[t.ssid,eventInfo?.ssid||t.unconfirmed],[t.period,dates],[t.contact,contact||t.unconfirmed]]){const a=document.createElement('dt'),b=document.createElement('dd');a.textContent=label;b.textContent=value;fragment.append(a,b);}
      $('event-info').replaceChildren(fragment);
      renderedEventInfo=eventInfo;renderedInformationLanguage=$('language').value;
    }
    $('simple-note').textContent=$('language').value==='ja-easy'?t.simpleNote:'';$('simple-note').hidden=$('language').value!=='ja-easy';
    $('connect').textContent=busy?t.saving:pending&&!saved?t.retryButton:t.button;
    const pendingText=pending&&!retryAllowed?t.errorPendingStaff:pending&&performance.now()<retryAt?t.errorWait:t.pending;
    $('message').textContent=busy?t.saving:saved?t.saved:pending?pendingText:t[state];
    $('connect-help').textContent=busy?t.saving:saved?t.helpSaved:pending?pendingText:ready?t.helpReady:t.helpStopped;
    $('connect').disabled=!ready||!$('accepted').checked||busy||Boolean(saved)||Boolean(pending&&(!retryAllowed||performance.now()<retryAt));
    $('error-detail').hidden=!lastFailure||busy;$('error-detail').textContent=lastFailure&&!busy?failureText(lastFailure):'';
    $('leave-warning').hidden=!leaveRisk();$('leave-warning').textContent=t.leaveWarning;
    $('inquiry-panel').hidden=!(saved||pending||lastFailure);
    for(const [id,key] of [['inquiry-title','inquiryTitle'],['inquiry-label','inquiryLabel'],['inquiry-help','inquiryHelp'],['inquiry-copy','inquiryCopy'],['inquiry-select','inquirySelect']])$(id).textContent=t[key];
    const inquiry=inquiryText();if($('inquiry-text').value!==inquiry){$('inquiry-text').value=inquiry;$('inquiry-status').textContent='';}
    $('inquiry-copy').disabled=busy||copyBusy;$('inquiry-select').disabled=busy;
    $('accepted').disabled=!ready||busy||Boolean(saved);$('language').disabled=busy||Boolean(pending&&!saved);
    $('consent-step').setAttribute('aria-busy',String(busy));$('terms').setAttribute('aria-busy',String(termsLoading));
    if(terms)$('version').textContent=t.version+': '+(terms.version||t.unconfigured);
    if(saved)$('detail').textContent=`${t.receipt}: ${saved.id}\n${t.savedVersion}: ${saved.version} / ${saved.language}${unconfirmedStatus?'\n'+t.statusNote:''}`;
  }
  async function language(){
    const version=++generation,lang=languageCode();ready=false;termsLoading=true;if(!saved)lastFailure=bootstrapFailure;$('accepted').checked=Boolean(saved);state='loading';render();$('terms').textContent=text().loadingTerms;
    try{
      const info=await api('/v1/public?lang='+lang);
      const result=context&&!saved&&info.service_state==='local_only'?await api('/v1/contexts/'+context+'?lang='+lang):info;
      if(version!==generation)return;
      eventInfo=info.event_information?{...info.event_information,daily_service_hours:info.daily_service_hours||null}:null;terms=result.terms;$('terms').textContent=terms.text;$('terms').lang=terms.language;
      ready=Boolean(context&&info.service_state==='local_only'&&!saved);
      state=ready?'ready':info.service_state==='service_closed'?'closed':info.service_state==='local_only'?'link':'stopped';
    }catch(error){if(version!==generation)return;lastFailure=error;state='error';$('terms').textContent=text().termsFailed;}
    if(version===generation){termsLoading=false;render();}
  }
  $('language').addEventListener('change',language);
  for(const [prefix,attribute,names] of [['text','textSize',['standard','large']],['contrast','contrast',['standard','high']]]){
    for(const name of names)$(prefix+'-'+name).addEventListener('click',()=>{
      document.documentElement.dataset[attribute]=name;
      for(const other of names)$(prefix+'-'+other).setAttribute('aria-pressed',String(other===name));
    });
  }
  $('accepted').addEventListener('change',render);
  $('connect').addEventListener('click',async()=>{
    if(!ready||!$('accepted').checked||busy||saved||(pending&&(!retryAllowed||performance.now()<retryAt)))return;
    if(!pending)pending={context_id:context,accepted:true,terms_document_id:terms.document_id,terms_sha256:terms.sha256,policy_version:terms.policy_version,language:terms.language};
    busy=true;lastFailure=null;render();
    try{
      const result=await api('/v1/consents',pending,retryKey);
      saved={id:result.consent_id,version:terms.version,language:pending.language};ready=false;
      try{await api('/v1/grants/'+result.grant_id,undefined,undefined,{consent_id:result.consent_id});}catch(error){unconfirmedStatus=true;lastFailure=error;}
      pending=null;clearTimeout(retryTimer);retryAt=0;
    }catch(error){
      // Retain the exact payload and retry key after an uncertain write. Never create a new consent to hide an error.
      lastFailure=error;setRetry(error);state='pending';
    }finally{busy=false;render();}
  });
  function selectInquiry(){const input=$('inquiry-text');input.focus();input.select();input.setSelectionRange(0,input.value.length);}
  $('inquiry-select').addEventListener('click',()=>{selectInquiry();$('inquiry-status').textContent=text().copyFallback;});
  $('inquiry-copy').addEventListener('click',async()=>{
    if(busy||copyBusy)return;
    const snapshot=$('inquiry-text').value;copyBusy=true;$('inquiry-copy').disabled=true;
    try{
      if(!window.isSecureContext||!navigator.clipboard?.writeText)throw new Error();
      await navigator.clipboard.writeText(snapshot);
      if($('inquiry-text').value===snapshot)$('inquiry-status').textContent=text().copyDone;
    }catch{if($('inquiry-text').value===snapshot){selectInquiry();$('inquiry-status').textContent=text().copyFallback;}}
    finally{copyBusy=false;$('inquiry-copy').disabled=busy;}
  });
  async function init(){
    try{const session=await api('/v1/session',{});csrf=session.csrf_token;if(launch)context=(await api('/v1/contexts',{launch_ref:launch},contextKey)).context_id;bootstrapFailure=null;}
    catch(error){bootstrapFailure=error;lastFailure=error;state='error';}
    await language();
  }
  render();init();
})();
