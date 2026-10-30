'use strict';
// Stage 3 portal: no launch link, the server recognises the device by address, and the page follows the grant until connected.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..'),elements=new Map(),requests=[];let grantReads=0,adapter='vyos';
function element(id){if(!elements.has(id))elements.set(id,{value:id==='language'?'ja':'',checked:false,disabled:false,hidden:false,textContent:'',dataset:{},listeners:{},replaceChildren(){},append(){},setAttribute(name,value){this[name]=value;},addEventListener(name,callback){this.listeners[name]=callback;}});return elements.get(id);}
const fixtures=JSON.parse(fs.readFileSync(path.join(__dirname,'response-fixtures.json'),'utf8'));
const contextId=fixtures['/v1/contexts'].context_id,consent=fixtures['/v1/consents'];
const grant=state=>({...consent,adapter:'vyos',display_state:state,authorization_status:state==='connected'?'accepted':'pending',network_verified:state==='connected',original_expires_at_utc:state==='connected'?'2026-10-31T08:00:00Z':null});
const fetch=async(url,options)=>{
  requests.push({url,body:options.body});
  const response=(value,status=200)=>({ok:status<400,status,headers:{get:()=>null},json:async()=>value});
  if(url==='/v1/session')return response(fixtures[url]);
  if(url==='/v1/contexts'){
    if(adapter!=='vyos')return response({code:'source_entry_unavailable',message:'x',retryable:false,correlation_id:null},403);
    return response(fixtures[url],201);
  }
  if(url==='/v1/consents')return response({...grant('connecting'),operation_id:consent.operation_id},201);
  if(url.startsWith('/v1/grants/'))return response(grant(++grantReads>=3?'connected':'connecting'));
  const value=url.startsWith('/v1/contexts/')?fixtures['/v1/contexts/'+contextId]:fixtures['/v1/public'];
  return response({...value,adapter,service_state:'local_only',terms:{...fixtures['/v1/public'].terms,language:'ja'}});
};
function load(){
  elements.clear();requests.length=0;grantReads=0;
  const context=vm.createContext({window:{addEventListener(){}},document:{addEventListener(){},createDocumentFragment(){return {append(){}};},getElementById:element,createElement(){return element('created-'+Math.random());},documentElement:{dataset:{}}},location:{origin:'https://wifi.example.org',hash:'',pathname:'/',reload(){}},history:{replaceState(){}},URL,performance,clearTimeout,setTimeout:(fn)=>setImmediate(fn),URLSearchParams,crypto:webcrypto,Uint8Array,fetch,console});
  for(const name of ['response-contracts.js','portal-copy.js','portal.js'])vm.runInContext(fs.readFileSync(path.join(root,'static',name),'utf8'),context,{filename:name});
  return context;
}
const flush=async(n=6)=>{for(let i=0;i<n;i++)await new Promise(resolve=>setImmediate(resolve));};
(async()=>{
  const context=load();
  const keys=Object.keys(context.window.PortalNetworkCopy.ja).sort();
  for(const [lang,copy] of Object.entries(context.window.PortalNetworkCopy)){assert.deepEqual(Object.keys(copy).sort(),keys,lang);assert.ok(lang in context.window.PortalCopy,lang);}
  await flush();
  assert.equal(JSON.parse(requests.find(r=>r.url==='/v1/contexts').body).launch_ref,null);
  assert.match(element('local-notice').textContent,/インターネットを使えるように/);assert.match(element('connect').textContent,/つなぐ/);
  element('accepted').checked=true;element('accepted').listeners.change();assert.equal(element('connect').disabled,false);
  await element('connect').listeners.click();assert.match(element('message').textContent,/準備しています/);
  await flush(20);assert.match(element('message').textContent,/つながりました/);assert.match(element('detail').textContent,/利用期限/);
  assert.equal(grantReads,3);
  // Without core-rt the page keeps the local review behaviour and asks for a link.
  adapter='disconnected';load();await flush();
  assert.match(element('message').textContent,/リンク/);assert.match(element('local-notice').textContent,/通信許可は発行しません/);assert.equal(element('error-detail').hidden,true);
  console.log(JSON.stringify({passed:6,failed:0,checks:['network copy key parity','address entry without link','network wording','connecting then connected','expiry shown','local review unchanged']}));
})().catch(error=>{console.error(error);process.exitCode=1;});
