process.env.GIGASHEET_TOKEN=''; process.env.GIGASHEET_CLIENT_ID='t'; process.env.GIGASHEET_NO_BROWSER='1';
process.env.GIGASHEET_KEYCHAIN_SERVICE='com.gigasheet.claude-extension.test';
const auth=require(process.argv[2]);
auth._hooks.keychain={setSecret:async()=>{},getSecret:async()=>null,deleteSecret:async()=>{}};
auth._hooks.postForm=async(url)=> url.includes('device/code')?{status:200,json:{device_code:'dc'+process.pid,user_code:'CODE-'+process.pid,verification_uri_complete:'https://x',interval:1,expires_in:300}}:{status:400,json:{error:'authorization_pending'}};
auth.beginInteractiveLogin().then(f=>{console.log(JSON.stringify({pid:process.pid,code:f.userCode,shared:!!f.shared})); setTimeout(()=>process.exit(0),2500);});
