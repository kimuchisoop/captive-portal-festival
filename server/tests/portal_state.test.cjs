'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..'),elements=new Map(),requests=[];let failConsent=true,failGrant=true,delayEnglish=false,releaseEnglish,publicState='local_only';
function element(id){if(!elements.has(id))elements.set(id,{value:id==='language'?'ja':'',checked:false,disabled:false,hidden:false,textContent:'',dataset:{},listeners:{},replaceChildren(){this.children=[];},append(...items){this.children=(this.children||[]).concat(items);},setAttribute(name,value){this[name]=value;},addEventListener(name,callback){this.listeners[name]=callback;}});return elements.get(id);}
const fixtures=JSON.parse(fs.readFileSync(path.join(__dirname,'response-fixtures.json'),'utf8'));
const contextId=fixtures['/v1/contexts'].context_id,receiptId=fixtures['/v1/consents'].consent_id;
const terms=lang=>({...fixtures['/v1/public'].terms,text:lang==='en'?'English terms':'日本語の規約',language:lang,version:'draft-1'});
const fetch=async(url,options)=>{
 requests.push({url,options:JSON.parse(JSON.stringify(options))});
 const response=value=>({ok:true,status:200,headers:{get:()=>null},json:async()=>value});
 if(url==='/v1/session')return response(fixtures[url]);
 if(url==='/v1/contexts')return response(fixtures[url]);
 if(url==='/v1/consents'){if(failConsent){failConsent=false;throw new Error('Uncertain network write');}return response(fixtures[url]);}
 if(url.startsWith('/v1/grants/')&&failGrant)throw new Error('Status lookup unavailable');
 const lang=url.endsWith('lang=en')?'en':'ja';
 if(delayEnglish&&url==='/v1/public?lang=en')await new Promise(resolve=>releaseEnglish=resolve);
 const value=url.startsWith('/v1/contexts/')?fixtures['/v1/contexts/'+contextId]:fixtures['/v1/public'];
 return response({...value,service_state:publicState,terms:terms(lang)});
};
const context=vm.createContext({window:{addEventListener(){}},document:{addEventListener(){},createDocumentFragment(){return {append(){}};},getElementById:element,createElement(){return element('created-'+Math.random());},documentElement:{dataset:{}}},location:{origin:'http://127.0.0.1:8890',hash:'#local_launch=local-only-test',pathname:'/',reload(){}},history:{replaceState(){}},URL,performance,clearTimeout,setTimeout,URLSearchParams,crypto:webcrypto,Uint8Array,fetch,console});
for(const name of ['response-contracts.js','portal-copy.js','portal.js'])vm.runInContext(fs.readFileSync(path.join(root,'static',name),'utf8'),context,{filename:name});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
  const expected=Object.keys(context.window.PortalCopy.ja).sort();
  for(const [lang,copy] of Object.entries(context.window.PortalCopy)){assert.deepEqual(Object.keys(copy).sort(),expected);assert.ok(Object.values(copy).every(v=>typeof v==='string'&&v.length>0),lang);}
  await flush();await flush();assert.equal(element('connect').disabled,true);
  element('accepted').checked=true;element('accepted').listeners.change();assert.equal(element('connect').disabled,false);
  publicState='service_closed';const contextReads=requests.filter(r=>r.url.startsWith('/v1/contexts/')).length;await element('language').listeners.change();assert.match(element('message').textContent,/提供期間外/);assert.equal(element('connect').disabled,true);assert.equal(requests.filter(r=>r.url.startsWith('/v1/contexts/')).length,contextReads);publicState='local_only';
  element('language').value='en';await element('language').listeners.change();assert.equal(element('accepted').checked,false);assert.equal(element('terms').lang,'en');
  element('accepted').checked=true;element('accepted').listeners.change();await element('connect').listeners.click();
  assert.equal(element('language').disabled,true);assert.match(element('message').textContent,/could not be confirmed/);
  await element('connect').listeners.click();assert.match(element('message').textContent,/consent was saved/);assert.ok(element('detail').textContent.includes(receiptId));assert.match(element('detail').textContent,/could not be checked/);
  const posts=requests.filter(r=>r.url==='/v1/consents');assert.equal(posts.length,2);assert.equal(posts[0].options.body,posts[1].options.body);assert.equal(posts[0].options.headers['Idempotency-Key'],posts[1].options.headers['Idempotency-Key']);
  assert.equal(element('language').disabled,false);assert.equal(element('connect').disabled,true);
  element('language').value='ja-easy';await element('language').listeners.change();assert.match(element('message').textContent,/同意を保存しました/);assert.match(element('detail').textContent,/draft-1 \/ en/);assert.equal(element('simple-note').hidden,false);assert.equal(element('connect').disabled,true);assert.equal(element('accepted').checked,true);
  delayEnglish=true;element('language').value='en';const old=element('language').listeners.change();await flush();element('language').value='ja';await element('language').listeners.change();releaseEnglish();await old;assert.equal(element('terms').lang,'ja');assert.match(element('message').textContent,/同意をサーバーへ保存しました/);
  console.log(JSON.stringify({passed:11,failed:0,checks:['translation key parity','checkbox gating','closed period does not fetch an invalid context','language change clears agreement','uncertain write locks language','identical retry body and key','saved receipt survives status failure','saved receipt survives language change','saved consent cannot resubmit','simple Japanese does not rewrite terms','stale language response ignored']}));
})().catch(error=>{console.error(error);process.exitCode=1;});
