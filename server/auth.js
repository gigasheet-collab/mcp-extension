'use strict';

/**
 * Auth0 Device Authorization Grant (RFC 8628) for the Gigasheet extension.
 *
 * Device flow rather than loopback PKCE: no redirect URI to register, and no
 * local HTTP listener inside the extension. The user is shown a short code,
 * approves it in their browser, and the bridge polls for the token.
 *
 * Access tokens live in memory. The refresh token goes to the OS keychain so
 * that a restart does not force a fresh login.
 */

const https = require('https');
const { spawn } = require('child_process');
const keychain = require('./keychain');
const { cleanEnv, log } = require('./env');

const AUTH0_DOMAIN = cleanEnv('GIGASHEET_AUTH0_DOMAIN', 'login.gigasheet.com');
const CLIENT_ID = cleanEnv('GIGASHEET_CLIENT_ID');
const AUDIENCE = cleanEnv('GIGASHEET_AUDIENCE', 'https://api.gigasheet.com/users');
const SCOPE = 'openid profile email offline_access';

const DEVICE_CODE_URL = `https://${AUTH0_DOMAIN}/oauth/device/code`;
const TOKEN_URL = `https://${AUTH0_DOMAIN}/oauth/token`;

// Refresh a little early so a token cannot expire mid-request.
const EXPIRY_SKEW_MS = 60 * 1000;
const KEYCHAIN_ACCOUNT = 'refresh_token';

class AuthError extends Error {}
/** No usable credentials. The user must complete the device flow. */
class NeedsLogin extends AuthError {}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Indirection so tests can swap the network and browser without touching the
// real Auth0 tenant or the user's keychain.
const hooks = {
  postForm,
  openBrowser,
  notify,
  keychain,
};

function postForm(url, fields) {
  const body = new URLSearchParams(fields).toString();
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        Accept: 'application/json',
        'User-Agent': 'Mozilla/5.0 (compatible; gigasheet-mcpb/0.3)',
      },
      timeout: 30000,
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { raw += d; });
      res.on('end', () => {
        let json;
        try {
          json = JSON.parse(raw);
        } catch (_) {
          json = { error: `http_${res.statusCode}`, error_description: raw.slice(0, 200) };
        }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', (err) => reject(new AuthError(`Could not reach Auth0 at ${AUTH0_DOMAIN}: ${err.message}`)));
    req.end(body);
  });
}

function requireClientId() {
  if (!CLIENT_ID) {
    throw new AuthError(
      'No Auth0 client ID is configured. The extension needs an Auth0 Native ' +
      'application with the Device Code grant enabled.'
    );
  }
}

// --------------------------------------------------------------------------
// Device flow
// --------------------------------------------------------------------------

/** Request a device + user code. Resolves to the Auth0 payload. */
async function startDeviceFlow() {
  requireClientId();
  const { status, json } = await hooks.postForm(DEVICE_CODE_URL, {
    client_id: CLIENT_ID,
    audience: AUDIENCE,
    scope: SCOPE,
  });
  if (status === 200) return json;

  if (json.error === 'unauthorized_client') {
    throw new AuthError(
      'This Auth0 application is not allowed to use the Device Code grant. ' +
      'In the Auth0 dashboard, the application must be of type Native with ' +
      'the Device Code grant enabled.'
    );
  }
  throw new AuthError(
    `Auth0 refused the device code request: ${json.error_description || json.error || `HTTP ${status}`}`
  );
}

/**
 * Poll the token endpoint until the user approves, declines, or time runs out.
 * `deadlineMs` (epoch ms) caps how long we block independently of the code's
 * own lifetime.
 */
async function pollForToken(deviceCode, interval, expiresIn, deadlineMs) {
  requireClientId();
  let intervalSec = Math.max(parseInt(interval, 10) || 5, 1);
  const codeExpiry = Date.now() + (parseInt(expiresIn, 10) || 900) * 1000;
  const stopAt = deadlineMs ? Math.min(codeExpiry, deadlineMs) : codeExpiry;

  while (Date.now() < stopAt) {
    await sleep(intervalSec * 1000);
    const { status, json } = await hooks.postForm(TOKEN_URL, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: deviceCode,
      client_id: CLIENT_ID,
    });

    if (status === 200) {
      await storeTokens(json, true);
      return json;
    }
    switch (json.error) {
      case 'authorization_pending': continue;
      case 'slow_down': intervalSec += 5; continue;
      case 'access_denied': throw new AuthError('Sign-in was declined.');
      case 'expired_token': throw new AuthError('The sign-in code expired. Start over.');
      default:
        throw new AuthError(
          `Auth0 returned an error: ${json.error_description || json.error || `HTTP ${status}`}`
        );
    }
  }
  throw new AuthError('Timed out waiting for sign-in to be approved.');
}

// --------------------------------------------------------------------------
// Token cache
// --------------------------------------------------------------------------

let accessToken = null;
let accessExpiresAt = 0;
let identity = null;

/**
 * Cache the access token and persist the refresh token.
 *
 * Rotation means every refresh returns a *new* refresh token and invalidates
 * the old one, so this must run on every successful exchange, not just login.
 *
 * `strict` controls what happens when the keychain refuses the write. At
 * login time that is worth surfacing. Mid-session it is not: we still hold a
 * good access token, and failing the request would waste it.
 */
async function storeTokens(payload, strict) {
  accessToken = payload.access_token || null;
  accessExpiresAt = Date.now() + (Number(payload.expires_in) || 3600) * 1000;
  // The access token carries only an opaque `sub`; the human-readable email
  // lives in the ID token. Kept purely for display.
  const who = claimFromJwt(payload.id_token, ['email', 'name']);
  if (who) identity = who;

  const refreshToken = payload.refresh_token;
  if (!refreshToken) return;
  try {
    await hooks.keychain.setSecret(KEYCHAIN_ACCOUNT, refreshToken);
  } catch (err) {
    // Deliberately not falling back to disk: a long-lived refresh token in a
    // plaintext file is worse than making the user sign in again.
    const message = `The refresh token could not be saved to the system keychain (${err.message}). ` +
      'You will have to sign in again next time.';
    if (strict) throw new AuthError(`Signed in, but ${message}`);
    log(`auth: ${message}`);
  }
}

async function readStoredRefreshToken() {
  try {
    return await hooks.keychain.getSecret(KEYCHAIN_ACCOUNT);
  } catch (err) {
    throw new NeedsLogin(`Keychain unavailable (${err.message}).`);
  }
}

async function exchangeRefreshToken(refreshToken) {
  return hooks.postForm(TOKEN_URL, {
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    refresh_token: refreshToken,
  });
}

async function refreshFromStored() {
  let refreshToken = await readStoredRefreshToken();
  if (!refreshToken) throw new NeedsLogin('No stored credentials.');

  requireClientId();
  let { status, json } = await exchangeRefreshToken(refreshToken);

  if (status !== 200) {
    // Claude Desktop runs more than one instance of this bridge at a time. If
    // a sibling rotated the token between our read and our exchange, the one
    // we sent is stale but the keychain now holds a good one. Re-read once
    // before concluding the sign-in is dead; a genuinely revoked family fails
    // both times.
    const latest = await readStoredRefreshToken();
    if (latest && latest !== refreshToken) {
      log('refresh rejected; a sibling instance rotated the token meanwhile - retrying with the newer one');
      refreshToken = latest;
      ({ status, json } = await exchangeRefreshToken(refreshToken));
    }
  }

  if (status === 200) {
    await storeTokens(json, false);
    return json.access_token;
  }

  // Revoked, rotated away, or expired: drop it so we do not keep replaying a
  // dead token. Under reuse detection, retrying is actively harmful.
  const reason = json.error_description || json.error || status;
  log(`stored refresh token rejected by Auth0 (${reason}); erasing it`);
  try {
    await hooks.keychain.deleteSecret(KEYCHAIN_ACCOUNT);
  } catch (_) { /* nothing more to do */ }
  throw new NeedsLogin(`Stored sign-in is no longer valid (${reason}).`);
}

/** The in-memory token if still comfortably valid, else null. Never refreshes. */
function cachedAccessToken() {
  if (accessToken && Date.now() < accessExpiresAt - EXPIRY_SKEW_MS) return accessToken;
  return null;
}

// Serializes refreshes. With refresh token rotation and reuse detection, two
// concurrent refreshes with the same token look like a replay attack to Auth0
// and get the whole token family revoked — logging the user out mid-
// conversation. Only one refresh may be in flight at a time.
let refreshInFlight = null;

/** Resolve a valid access token, refreshing if needed. Rejects with NeedsLogin
 *  if the user has to complete the device flow. */
async function getAccessToken() {
  const cached = cachedAccessToken();
  if (cached) return cached;
  if (!refreshInFlight) {
    refreshInFlight = refreshFromStored().finally(() => { refreshInFlight = null; });
  }
  return refreshInFlight;
}

// --------------------------------------------------------------------------
// Interactive login (shared between the explicit login tool and auto-reauth)
// --------------------------------------------------------------------------

/** Best-effort: pop the verification page in the user's default browser. */
function openBrowser(url) {
  if (cleanEnv('GIGASHEET_NO_BROWSER')) return; // live tests must not pop tabs
  const commands = {
    darwin: [keychain.resolveBinary('open'), [url]],
    linux: ['xdg-open', [url]],
    win32: ['cmd', ['/c', 'start', '', url]],
  };
  const entry = commands[process.platform];
  if (!entry) return;
  try {
    const child = spawn(entry[0], entry[1], { stdio: 'ignore', detached: true, windowsHide: true });
    child.on('error', () => {}); // the user can still click the link in chat
    child.unref();
  } catch (_) { /* same */ }
}

/**
 * Best-effort OS notification, so a browser tab that appears out of nowhere
 * is labelled with who opened it and why. Fire-and-forget on every platform.
 */
function notify(title, body) {
  if (cleanEnv('GIGASHEET_NO_BROWSER')) return;
  const q = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  let cmd;
  let args;
  if (process.platform === 'darwin') {
    cmd = keychain.resolveBinary('osascript');
    args = ['-e', `display notification "${q(body)}" with title "${q(title)}"`];
  } else if (process.platform === 'linux') {
    cmd = 'notify-send';
    args = [title, body];
  } else if (process.platform === 'win32') {
    cmd = keychain.resolveBinary('powershell');
    args = ['-NoProfile', '-NonInteractive', '-Command', [
      'Add-Type -AssemblyName System.Windows.Forms',
      'Add-Type -AssemblyName System.Drawing',
      '$n = New-Object System.Windows.Forms.NotifyIcon',
      '$n.Icon = [System.Drawing.SystemIcons]::Information',
      '$n.Visible = $true',
      `$n.ShowBalloonTip(10000, "${q(title)}", "${q(body)}", [System.Windows.Forms.ToolTipIcon]::Info)`,
      'Start-Sleep -Seconds 12',
      '$n.Dispose()',
    ].join('; ')];
  } else {
    return;
  }
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true, windowsHide: true });
    child.on('error', () => {});
    child.unref();
  } catch (_) { /* purely cosmetic; never fail the login over it */ }
}

let pendingFlow = null;
let flowStarting = null;

// Claude Desktop runs several bridge instances at once (main app, one per
// Code/Cowork session). Each has its own memory, so the in-process dedupe
// above cannot stop five of them opening five browser tabs for five codes.
// A small lock file makes the first one the owner of the sign-in; the rest
// point the user at the tab that is already open.
const os = require('os');
const fs = require('fs');
const path = require('path');
const FLOW_LOCK = path.join(os.tmpdir(), `gigasheet-mcp-signin-${os.userInfo().username}.json`);
const FLOW_LOCK_TTL_MS = 15 * 60 * 1000;

function readFlowLock() {
  let raw;
  try {
    raw = fs.readFileSync(FLOW_LOCK, 'utf8');
  } catch (_) {
    return null; // no lock
  }
  let info;
  try {
    info = JSON.parse(raw);
  } catch (_) {
    // Exists but not yet written: a sibling is between open() and write().
    // Treat a fresh empty file as a live claim; a stale one as abandoned.
    try {
      const age = Date.now() - fs.statSync(FLOW_LOCK).mtimeMs;
      return age < 10000 ? { pid: -1, startedAt: Date.now(), userCode: null } : null;
    } catch (_) { return null; }
  }
  if (!info || info.pid === process.pid) return null;
  if (Date.now() - info.startedAt > FLOW_LOCK_TTL_MS) return null;
  try { process.kill(info.pid, 0); } catch (_) { return null; } // owner gone
  return info;
}

/**
 * Claim the sign-in lock atomically BEFORE talking to Auth0. Several bridge
 * instances start within the same second; checking after the network round
 * trip let every one of them "win". Returns true if this process now owns
 * the sign-in, false if another live instance does.
 */
function claimFlowLock() {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = fs.openSync(FLOW_LOCK, 'wx', 0o600);
      fs.writeSync(fd, JSON.stringify({ pid: process.pid, startedAt: Date.now() }));
      fs.closeSync(fd);
      return true;
    } catch (err) {
      if (err.code !== 'EEXIST') return true; // unusable tmpdir: behave as before
      if (readFlowLock()) return false;       // a live sibling owns it
      try { fs.unlinkSync(FLOW_LOCK); } catch (_) { /* someone else cleaned it */ }
    }
  }
  return true;
}

function writeFlowLock(info) {
  try {
    fs.writeFileSync(FLOW_LOCK, JSON.stringify({
      pid: process.pid, startedAt: Date.now(), userCode: info.userCode, verifyUrl: info.verifyUrl,
    }), { mode: 0o600 });
  } catch (_) { /* best effort */ }
}

/** Wait briefly for the owning instance to publish its code into the lock. */
async function waitForSharedFlow() {
  for (let i = 0; i < 40; i++) {
    const other = readFlowLock();
    if (!other) return null;               // owner gave up or finished
    if (other.userCode) return other;
    await sleep(250);
  }
  return null;
}

function clearFlowLock() {
  try {
    const info = JSON.parse(fs.readFileSync(FLOW_LOCK, 'utf8'));
    if (info.pid === process.pid) fs.unlinkSync(FLOW_LOCK);
  } catch (_) { /* nothing */ }
}

async function pollFlowBackground(info) {
  try {
    await pollForToken(info.deviceCode, info.interval, info.lifetime);
    info.status = 'ok';
  } catch (err) {
    info.status = 'error';
    info.error = err.message;
  } finally {
    clearFlowLock();
  }
}

/**
 * Start (or join) a device flow. Resolves to an object with userCode,
 * verifyUrl, and a live `status` field: pending | ok | error.
 *
 * Idempotent while a flow is pending, so concurrent queries that all hit
 * expired auth share one code instead of racing to create three. Polling
 * runs in the background; callers can return immediately and the tokens land
 * in the keychain whenever the user approves.
 */
async function beginInteractiveLogin(open = true) {
  const live = pendingFlow && pendingFlow.status === 'pending' && Date.now() < pendingFlow.expiresAt;
  if (!live) {
    // Another bridge instance already has a sign-in open: join it instead of
    // opening a second tab. The tokens land in the shared keychain either way.
    if (!flowStarting && !claimFlowLock()) {
      const other = await waitForSharedFlow();
      if (other) {
        log(`sign-in already in progress in another instance (code ${other.userCode}); not opening another tab`);
        return {
          userCode: other.userCode, verifyUrl: other.verifyUrl, status: 'pending', error: null,
          expiresAt: other.startedAt + FLOW_LOCK_TTL_MS, shared: true,
        };
      }
      claimFlowLock(); // owner vanished before publishing; take over
    }
    if (!flowStarting) {
      flowStarting = (async () => {
        const flow = await startDeviceFlow();
        const lifetime = parseInt(flow.expires_in, 10) || 900;
        const info = {
          deviceCode: flow.device_code,
          userCode: flow.user_code || '',
          verifyUrl: flow.verification_uri_complete || flow.verification_uri || '',
          interval: flow.interval || 5,
          lifetime,
          expiresAt: Date.now() + lifetime * 1000,
          status: 'pending',
          error: null,
        };
        pendingFlow = info;
        writeFlowLock(info);
        pollFlowBackground(info); // intentionally not awaited
        hooks.notify(
          'Claude needs to reconnect to Gigasheet',
          `Approve code ${info.userCode} in the browser tab that just opened, then retry in Claude.`
        );
        return info;
      })().catch((err) => { clearFlowLock(); throw err; }).finally(() => { flowStarting = null; });
    }
    await flowStarting;
  }
  if (open && !pendingFlow.shared) hooks.openBrowser(pendingFlow.verifyUrl);
  return pendingFlow;
}

async function logout() {
  accessToken = null;
  accessExpiresAt = 0;
  identity = null;
  try {
    await hooks.keychain.deleteSecret(KEYCHAIN_ACCOUNT);
  } catch (_) { /* nothing stored, or keychain unreachable */ }
}

async function hasStoredCredentials() {
  try {
    return Boolean(await hooks.keychain.getSecret(KEYCHAIN_ACCOUNT));
  } catch (_) {
    return false;
  }
}

/**
 * First matching claim from an unverified JWT payload, or null. Display only.
 * The token is validated by Gigasheet, not here, so nothing read out of it is
 * used for an access decision.
 */
function claimFromJwt(token, names) {
  if (!token || typeof token !== 'string') return null;
  try {
    const part = token.split('.')[1];
    const claims = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    for (const name of names) if (claims[name]) return claims[name];
  } catch (_) { /* not a JWT */ }
  return null;
}

/** Who is signed in, for display. Falls back to the opaque subject. */
function describeIdentity() {
  return identity || claimFromJwt(accessToken, ['email', 'name', 'sub']);
}

/**
 * Permission claims on the current access token. Nothing gates on these
 * today; when Gigasheet adds a role for MCP access, check it here so users
 * get a named reason instead of a bare 403.
 */
function tokenPermissions() {
  return claimFromJwt(accessToken, ['permissions']) || [];
}

module.exports = {
  AuthError,
  NeedsLogin,
  CLIENT_ID,
  startDeviceFlow,
  pollForToken,
  getAccessToken,
  cachedAccessToken,
  beginInteractiveLogin,
  logout,
  hasStoredCredentials,
  describeIdentity,
  tokenPermissions,
  _hooks: hooks,
};
