process.env.GIGASHEET_TOKEN=''; process.env.GIGASHEET_CLIENT_ID='t'; process.env.GIGASHEET_NO_BROWSER='1';
process.env.GIGASHEET_KEYCHAIN_SERVICE='com.gigasheet.claude-extension.test';
const auth=require(process.argv[2]); const role=process.argv[3]; let minted=0;
auth._hooks.keychain={setSecret:async()=>{},getSecret:async()=>null,deleteSecret:async()=>{}};
auth._hooks.postForm=async(url)=>{ if(url.includes('device/code')){minted++;return{status:200,json:{device_code:'dc-'+role,user_code:'CODE-'+role,verification_uri_complete:'https://x',interval:1,expires_in:900}};} return{status:400,json:{error:'authorization_pending'}};};
auth.beginInteractiveLogin().then(f=>{console.log(JSON.stringify({role,code:f.userCode,minted,adopted:!!f.adopted,shared:!!f.shared})); if(role==='A') process.kill(process.pid,'SIGKILL'); else setTimeout(()=>process.exit(0),1500);});
