process.env.GIGASHEET_TOKEN=''; process.env.GIGASHEET_CLIENT_ID='test-client';
process.env.GIGASHEET_KEYCHAIN_SERVICE='com.gigasheet.claude-extension.test'; process.env.GIGASHEET_NO_BROWSER='1'; process.env.GIGASHEET_LOGIN_WAIT='2';
const path=require('path'); const srv=path.resolve(process.argv[2]);
const auth=require(path.join(srv,'auth.js')); const bridge=require(path.join(srv,'index.js'));
const sleep=ms=>new Promise(r=>setTimeout(r,ms)); let fails=0;
const check=(l,ok,x='')=>{console.log(`  ${ok?'PASS':'FAIL'}  ${l}${x?'  -> '+x:''}`); if(!ok) fails++;};
(async()=>{
  const mem={refresh_token:'rt-stored'}; let refreshes=0, codes=0, pollN=0, opened=0;
  auth._hooks.keychain={setSecret:async(a,s)=>{mem[a]=s;},getSecret:async(a)=>mem[a]??null,deleteSecret:async(a)=>{delete mem[a];}};
  auth._hooks.openBrowser=()=>{opened++;}; auth._hooks.notify=()=>{};
  auth._hooks.postForm=async(url,f)=>{ if(f.grant_type==='refresh_token'){refreshes++; await sleep(200); return{status:200,json:{access_token:'tok-'+refreshes,expires_in:3600,refresh_token:'rt-new'}};}
    if(url.includes('device/code')){codes++;return{status:200,json:{device_code:'dc',user_code:'UNIT-'+codes,verification_uri_complete:'https://x',interval:1,expires_in:300}};}
    pollN++; if(pollN<3)return{status:400,json:{error:'authorization_pending'}}; return{status:200,json:{access_token:'tok-login',expires_in:3600,refresh_token:'rt-login',id_token:'x.'+Buffer.from(JSON.stringify({email:'unit@test'})).toString('base64url')+'.y'}};};
  console.log('### U1. concurrent refresh deduplicated');
  const toks=await Promise.all(Array.from({length:12},()=>auth.getAccessToken()));
  check('12 callers -> 1 refresh', refreshes===1, String(refreshes)); check('same token', new Set(toks).size===1); check('rotation persisted', mem.refresh_token==='rt-new');
  console.log('### U2/U3. Cloudflare block vs local fallbacks');
  let out=await bridge.interpret(403,'error code: 1010',7,'tools/call',true);
  check('CF block -> -32004, no re-auth wording', out.error&&out.error.code===-32004&&!/token|sign-in/i.test(out.error.message));
  check('credential untouched by CF block', mem.refresh_token==='rt-new');
  out=await bridge.interpret(403,'<html>',8,'initialize'); check('initialize answered locally', out.result&&out.result.serverInfo);
  out=await bridge.interpret(403,'<html>',9,'tools/list'); check('tools/list fallback has 3 annotated tools', out.result.tools.length===3&&out.result.tools.every(t=>t.annotations&&t.annotations.title));
  console.log('### U4. tools/call with OUR bearer refused -> logout + auto-reauth');
  out=await bridge.interpret(401,'{"Success":false,"Message":"Unauthorized"}',10,'tools/call',true);
  check('credential erased', mem.refresh_token===undefined); check('flow started, code in message', /UNIT-1/.test(out.result.content[0].text)); check('browser opened', opened===1);
  console.log('### U5. concurrent expired queries share one flow; background poll completes');
  const flows=await Promise.all(Array.from({length:5},()=>auth.beginInteractiveLogin()));
  check('still one device code', codes===1); for(let i=0;i<60&&flows[0].status==='pending';i++) await sleep(100);
  check('background poll ok', flows[0].status==='ok'); check('login token persisted', mem.refresh_token==='rt-login'); check('identity', auth.describeIdentity()==='unit@test');
  console.log('### U6. login tool returns promptly when unapproved');
  await auth.logout(); auth._hooks.postForm=async(url)=>url.includes('device/code')?{status:200,json:{device_code:'dc2',user_code:'WAIT',verification_uri_complete:'https://x',interval:1,expires_in:300}}:{status:400,json:{error:'authorization_pending'}};
  const t0=Date.now(); const r=await bridge.handleLogin({}); check('returned within ~2s', Date.now()-t0<5000); check('says still waiting', /Still waiting/.test(r.content[0].text));
  console.log(fails?`\n${fails} FAILED`:'\nALL UNIT TESTS PASSED'); process.exit(fails?1:0);
})().catch(e=>{console.error('CRASH',e);process.exit(2);});
