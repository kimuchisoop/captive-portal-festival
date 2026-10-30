'use strict';
// A failure before consent (session 429, context 503) can be checked again from the same page without reloading.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..'),elements=new Map(),requests=[];let sessionFailures=[],contextFailures=[],reloads=0;
function element(id){if(!elements.has(id))elements.set(id,{value:id==='language'?'ja':'',checked:false,disabled:false,hidden:false,textContent:'',dataset:{},listeners:{},replaceChildren(){},append(){},setAttribute(name,value){this[name]=value;},addEventListener(name,callback){this.listeners[name]=callback;}});return elements.get(id);}
const fixtures=JSON.parse(fs.readFileSync(path.join(__dirname,'response-fixtures.json'),'utf8'));
const contextId=fixtures['/v1/contexts'].context_id;
const fetch=async(url,options)=>{
  requests.push({url,options:JSON.parse(JSON.stringify(options))});
  const response=(value,status=200,headers={})=>({ok:status<400,status,headers:{get:name=>headers[name]??null},json:async()=>value});
  const failed=item=>response({code:item.code,message:'x',retryable:true,correlation_id:null},item.status,item.wait===undefined?{}:{'Retry-After':String(item.wait)});
  if(url==='/v1/session')return sessionFailures.length?failed(sessionFailures.shift()):response(fixtures[url]);
  if(url==='/v1/contexts')return contextFailures.length?failed(contextFailures.shift()):response(fixtures[url],201);
  if(url==='/v1/consents')throw new Error('No consent should be sent in these checks');
  const value=url.startsWith('/v1/contexts/')?fixtures['/v1/contexts/'+contextId]:fixtures['/v1/public'];
  return response({...value,service_state:'local_only',terms:{...fixtures['/v1/public'].terms,language:'ja'}});
};
function load(){
  elements.clear();requests.length=0;
  const context=vm.createContext({window:{addEventListener(){}},document:{addEventListener(){},createDocumentFragment(){return {append(){}};},getElementById:element,createElement(){return element('created-'+Math.random());},documentElement:{dataset:{}}},location:{origin:'http://127.0.0.1:8890',hash:'#local_launch=local-only-test',pathname:'/',reload(){reloads++;}},history:{replaceState(){}},URL,performance,clearTimeout,setTimeout,URLSearchParams,crypto:webcrypto,Uint8Array,fetch,console});
  for(const name of ['response-contracts.js','portal-copy.js','portal.js'])vm.runInContext(fs.readFileSync(path.join(root,'static',name),'utf8'),context,{filename:name});
  return context;
}
const flush=async(n=6)=>{for(let i=0;i<n;i++)await new Promise(resolve=>setImmediate(resolve));};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
(async()=>{
  // 1. Session admission returns 429 with a wait: the button counts down, then resumes without reloading.
  sessionFailures=[{status:429,code:'session_guard_capacity',wait:2}];load();await flush();
  assert.equal(element('resume').hidden,false);assert.equal(element('resume').disabled,true);
  assert.match(element('error-detail').textContent,/再確認までの秒数: 2/);assert.match(element('message').textContent,/画面を開き直さずに/);
  await sleep(1100);assert.match(element('error-detail').textContent,/再確認までの秒数: 1/);assert.equal(element('resume').disabled,true);
  await element('resume').listeners.click();assert.equal(requests.filter(r=>r.url==='/v1/session').length,1,'early click is ignored');
  await sleep(1100);assert.equal(element('resume').disabled,false);assert.doesNotMatch(element('error-detail').textContent,/秒数/);
  await element('resume').listeners.click();await flush();
  assert.equal(element('resume').hidden,true);assert.equal(element('error-detail').hidden,true);
  element('accepted').checked=true;element('accepted').listeners.change();assert.equal(element('connect').disabled,false);
  // 2. Context creation fails with 503: resuming repeats it with the same idempotency key.
  contextFailures=[{status:503,code:'database_unavailable'}];load();await flush();
  assert.equal(element('resume').hidden,false);assert.equal(element('resume').disabled,false);
  await element('resume').listeners.click();await flush();assert.equal(element('resume').hidden,true);
  const contexts=requests.filter(r=>r.url==='/v1/contexts');assert.equal(contexts.length,2);assert.equal(contexts[0].options.headers['Idempotency-Key'],contexts[1].options.headers['Idempotency-Key']);
  // 3. A paused intake is not offered as something to retry.
  sessionFailures=[{status:429,code:'session_capacity_exhausted',wait:60}];load();await flush();
  assert.equal(element('resume').hidden,true);assert.match(element('error-detail').textContent,/新しい受付を停止/);
  assert.equal(reloads,0);
  console.log(JSON.stringify({passed:3,failed:0,checks:['session 429 resumes after the wait without reload','context 503 resumes with the same idempotency key','paused intake offers no resume']}));
})().catch(error=>{console.error(error);process.exitCode=1;});
