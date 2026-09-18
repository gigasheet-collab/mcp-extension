process.env.GIGASHEET_TOKEN = '';
process.env.GIGASHEET_CLIENT_ID = 'test-client';
process.env.GIGASHEET_KEYCHAIN_SERVICE = 'com.gigasheet.claude-extension.test';
process.env.GIGASHEET_LOGIN_WAIT = '2';
const path = require('path');
const srv = path.resolve(process.argv[2]);
const auth = require(path.join(srv, 'auth.js'));
const bridge = require(path.join(srv, 'index.js'));
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let fails = 0;
const check = (label, ok, extra='') => { console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? '  -> ' + extra : ''}`); if (!ok) fails++; };
(async () => {
  const mem = { refresh_token: 'rt-valid' };
  let codes = 0, opened = 0, notified = [];
  auth._hooks.keychain = { setSecret: async (a, s) => { mem[a] = s; }, getSecret: async (a) => mem[a] ?? null, deleteSecret: async (a) => { delete mem[a]; } };
  auth._hooks.openBrowser = () => { opened++; };
  auth._hooks.notify = (t, b) => { notified.push(t + ' | ' + b); };
  auth._hooks.postForm = async (url, f) => {
    if (url.includes('device/code')) { codes++; return { status: 200, json: { device_code: 'dc', user_code: 'NEW-' + codes, verification_uri_complete: 'https://x/activate', interval: 1, expires_in: 300 } }; }
    if (f.grant_type === 'refresh_token') return f.refresh_token === 'rt-valid'
      ? { status: 200, json: { access_token: 'tok', expires_in: 3600, refresh_token: 'rt-valid', id_token: 'x.' + Buffer.from(JSON.stringify({ email: 'me@test' })).toString('base64url') + '.y' } }
      : { status: 403, json: { error: 'invalid_grant', error_description: 'dead' } };
    return { status: 400, json: { error: 'authorization_pending' } };
  };

  console.log('### L1. gigasheet_login while already signed in -> no-op, no browser, no code');
  let r = await bridge.handleLogin({});
  check('says already signed in', /Already signed in .* as me@test/.test(r.content[0].text), r.content[0].text.slice(0, 60));
  check('not an error', r.isError === false);
  check('no device code requested', codes === 0);
  check('no browser opened', opened === 0);
  check('no notification', notified.length === 0);

  console.log('### L2. gigasheet_login with force=true -> signs out, starts a fresh flow');
  r = await bridge.handleLogin({ force: true });
  check('stored credential erased first', mem.refresh_token === undefined);
  check('new device code requested', codes === 1);
  check('browser opened', opened === 1);
  check('returns waiting message with code', /NEW-1/.test(r.content[0].text));
  check('OS notification sent once, names Gigasheet + code', notified.length === 1 && /Gigasheet/.test(notified[0]) && /NEW-1/.test(notified[0]), notified[0]);

  console.log('### L3. joining a pending flow does not re-notify or mint a new code');
  await auth.beginInteractiveLogin(); await auth.beginInteractiveLogin();
  check('still one device code', codes === 1);
  check('still one notification', notified.length === 1);
  check('implicit joins do NOT open more tabs (only a new code or an explicit login does)', opened === 1, String(opened));

  console.log('### L4. login with dead credential (no force) -> starts flow rather than lying');
  await auth.logout(); mem.refresh_token = 'rt-dead';
  // fresh flow needed: expire the pending one
  auth._hooks.postForm = (orig => async (url, f) => { const x = await orig(url, f); return x; })(auth._hooks.postForm);
  const before = codes;
  r = await bridge.handleLogin({});
  check('dead token erased', mem.refresh_token === undefined);
  check('flow started or joined (not "already signed in")', !/Already signed in/.test(r.content[0].text));

  console.log('### L5. description discourages preemptive calls; schema exposes force');
  check('description says do NOT call preemptively', /do NOT call this preemptively/.test(bridge.LOGIN_TOOL.description));
  check('force in schema', bridge.LOGIN_TOOL.inputSchema.properties.force.type === 'boolean');

  console.log(fails ? `\n${fails} FAILED` : '\nALL LOGIN TESTS PASSED');
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error('CRASH', e); process.exit(2); });
