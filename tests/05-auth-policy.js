process.env.GIGASHEET_TOKEN=''; process.env.GIGASHEET_CLIENT_ID='test-client'; process.env.GIGASHEET_NO_BROWSER='';
process.env.GIGASHEET_KEYCHAIN_SERVICE='com.gigasheet.claude-extension.test'; process.env.GIGASHEET_LOGIN_WAIT='1';
const path=require('path'); const srv=path.resolve(process.argv[2]);
const auth=require(path.join(srv,'auth.js')); const bridge=require(path.join(srv,'index.js'));
const sleep=ms=>new Promise(r=>setTimeout(r,ms)); let fails=0;
const check=(l,ok,x='')=>{console.log(`  ${ok?'PASS':'FAIL'}  ${l}${x?'  -> '+x:''}`); if(!ok) fails++;};
const REJ401='{"Success":false,"Message":"Unauthorized"}', REJ403='{"Success":false,"Message":"Forbidden"}';
const OK=(id)=>JSON.stringify({jsonrpc:'2.0',id,result:{content:[{type:'text',text:'rows!'}],isError:false}});
const CALL=(id)=>JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name:'Analyze',arguments:{sheet_id:'s',instructions:'DISPLAY'}}});
(async()=>{
  const mem={refresh_token:'rt-1'}; let refreshes=0, codes=0, opened=0, out=[];
  auth._hooks.keychain={setSecret:async(a,s)=>{mem[a]=s;},getSecret:async(a)=>mem[a]??null,deleteSecret:async(a)=>{delete mem[a];}};
  auth._hooks.openBrowser=()=>{opened++;}; auth._hooks.notify=()=>{};
  auth._hooks.postForm=async(url,f)=>{ if(f.grant_type==='refresh_token'){refreshes++;return{status:200,json:{access_token:'tok-'+refreshes,expires_in:3600,refresh_token:'rt-'+(refreshes+1)}};}
    if(url.includes('device/code')){codes++;return{status:200,json:{device_code:'dc'+codes,user_code:'CODE-'+codes,verification_uri_complete:'https://x/'+codes,interval:1,expires_in:900}};}
    return{status:400,json:{error:'authorization_pending'}};};
  bridge._setWriter(m=>out.push(m));
  const last=()=>out[out.length-1];

  console.log('### F1. stale access token: 403 -> silent refresh -> retry succeeds');
  let seen=[]; bridge._setTransport(async(body,bearer)=>{seen.push(bearer); return seen.length===1?{status:403,text:REJ403}:{status:200,text:OK(1)};});
  await bridge.handle(CALL(1));
  check('user got their rows', last().result && last().result.content[0].text==='rows!');
  check('retried with a NEW token', seen.length===2 && seen[0]!==seen[1], seen.join(' -> '));
  check('credential intact', !!mem.refresh_token); check('no sign-in started', codes===0 && opened===0);

  console.log('### F2. persistent 403 on a fresh token: report, NEVER wipe');
  bridge._setTransport(async()=>({status:403,text:REJ403}));
  await bridge.handle(CALL(2));
  check('error result says sign-in unchanged', /sign-in is unchanged/.test(last().result.content[0].text));
  check('includes server detail', /Forbidden/.test(last().result.content[0].text));
  check('credential intact', !!mem.refresh_token); check('no sign-in started', codes===0 && opened===0);

  console.log('### F3. Cloudflare HTML 403: no token churn, distinct error');
  const before=refreshes; bridge._setTransport(async()=>({status:403,text:'error code: 1010'}));
  await bridge.handle(CALL(3));
  check('-32004 network-protection error', last().error && last().error.code===-32004);
  check('no refresh attempted', refreshes===before); check('credential intact', !!mem.refresh_token);

  console.log('### F4. 401 that survives a refresh: the one case that re-authenticates');
  bridge._setTransport(async()=>({status:401,text:REJ401}));
  await bridge.handle(CALL(4));
  check('credential erased', mem.refresh_token===undefined); check('exactly one code minted', codes===1);
  check('browser opened once', opened===1); check('message has the code', /CODE-1/.test(last().result.content[0].text));

  console.log('### F5. more queries while that sign-in is pending: same code, NO more tabs');
  bridge._setTransport(async()=>({status:200,text:OK(9)}));
  await bridge.handle(CALL(5)); await bridge.handle(CALL(6));
  check('still one code', codes===1); check('still one tab', opened===1, String(opened));

  console.log('### F6. force login discards the pending code and mints a fresh one');
  let r=await bridge.handleLogin({force:true});
  check('new code issued', codes===2 && /CODE-2/.test(r.content[0].text), r.content[0].text.slice(0,80));
  check('explicit login opens the tab', opened===2);

  console.log('### F7. logout discards a pending sign-in');
  await auth.logout(); check('no pending flow after logout', auth.pendingFlowAgeMs()===null);
  r=await bridge.handleLogin({}); check('next login gets a fresh code', codes===3 && /CODE-3/.test(r.content[0].text));

  console.log(fails?`\n${fails} FAILED`:'\nALL POLICY TESTS PASSED'); process.exit(fails?1:0);
})().catch(e=>{console.error('CRASH',e);process.exit(2);});
