process.env.GIGASHEET_TOKEN = ''; process.env.GIGASHEET_CLIENT_ID = 'test-client';
process.env.GIGASHEET_KEYCHAIN_SERVICE = 'com.gigasheet.claude-extension.test';
const path = require('path'); const srv = path.resolve(process.argv[2]);
const auth = require(path.join(srv, 'auth.js'));
let fails = 0; const check = (l, ok, x='') => { console.log(`  ${ok?'PASS':'FAIL'}  ${l}${x?'  -> '+x:''}`); if(!ok) fails++; };
(async () => {
  const mem = { refresh_token: 'rt-old' };
  auth._hooks.keychain = { setSecret: async (a,s)=>{mem[a]=s;}, getSecret: async (a)=>mem[a]??null, deleteSecret: async (a)=>{delete mem[a];} };
  console.log('### R1. sibling rotated the token between our read and our exchange -> retry with newer, no logout');
  let exchanges = [];
  auth._hooks.postForm = async (url, f) => {
    exchanges.push(f.refresh_token);
    if (f.refresh_token === 'rt-old') { mem.refresh_token = 'rt-sibling'; return { status: 403, json: { error: 'invalid_grant', error_description: 'Unknown or invalid refresh token.' } }; }
    if (f.refresh_token === 'rt-sibling') return { status: 200, json: { access_token: 'tok-ok', expires_in: 3600, refresh_token: 'rt-next' } };
    return { status: 403, json: { error: 'invalid_grant' } };
  };
  const tok = await auth.getAccessToken();
  check('got a token instead of NeedsLogin', tok === 'tok-ok', tok);
  check('exchanged old then the sibling\'s newer token', exchanges.join(',') === 'rt-old,rt-sibling', exchanges.join(','));
  check('newest rotation persisted', mem.refresh_token === 'rt-next');

  console.log('### R2. genuinely dead family -> both attempts fail -> erased + NeedsLogin with reason');
  await auth.logout(); mem.refresh_token = 'rt-dead'; exchanges = [];
  auth._hooks.postForm = async (url, f) => { exchanges.push(f.refresh_token); return { status: 403, json: { error: 'invalid_grant', error_description: 'family revoked' } }; };
  try { await auth.getAccessToken(); check('should have thrown', false); }
  catch (e) { check('NeedsLogin carries the Auth0 reason', e instanceof auth.NeedsLogin && /family revoked/.test(e.message), e.message); }
  check('no pointless second exchange when keychain unchanged', exchanges.length === 1, String(exchanges.length));
  check('dead token erased', mem.refresh_token === undefined);

  console.log('### R3. GIGASHEET_NO_BROWSER suppresses browser + notification');
  process.env.GIGASHEET_NO_BROWSER = '1';
  delete require.cache[path.join(srv, 'auth.js')]; delete require.cache[path.join(srv, 'env.js')];
  const auth2 = require(path.join(srv, 'auth.js'));
  let spawned = false; const cp = require('child_process'); const orig = cp.spawn; cp.spawn = (...a) => { spawned = true; return orig(...a); };
  auth2._hooks.openBrowser('https://example'); auth2._hooks.notify('t', 'b');
  cp.spawn = orig;
  check('nothing spawned', spawned === false);
  console.log(fails ? `\n${fails} FAILED` : '\nALL RETRY TESTS PASSED'); process.exit(fails?1:0);
})().catch(e => { console.error('CRASH', e); process.exit(2); });
