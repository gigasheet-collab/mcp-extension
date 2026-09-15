#!/usr/bin/env node
'use strict';

/**
 * Gigasheet MCP bridge.
 *
 * Speaks MCP over stdio to the local client and forwards to Gigasheet's remote
 * MCP endpoint over HTTPS. Node standard library only, so the bundle needs no
 * vendored dependencies and runs on the Node that ships inside Claude Desktop.
 *
 * The remote endpoint is stateless: plain JSON responses, no SSE, no session
 * id. So this is a straight request/response bridge. What it adds over a raw
 * pipe:
 *
 *   * Non-JSON-RPC error bodies (the 401 page, Cloudflare blocks) become valid
 *     JSON-RPC errors instead of corrupting the protocol stream.
 *   * The handshake never fails on auth, so the server stays reachable and can
 *     say what is wrong.
 *   * Sign-in via Auth0 device flow, with silent refresh and auto re-auth.
 *   * Notifications are never answered.
 *   * The Analyze tool description is replaced with the full instruction
 *     grammar, and every tool carries the annotations the directory requires.
 */

const https = require('https');
const path = require('path');
const { StringDecoder } = require('string_decoder');
const auth = require('./auth');
const keychain = require('./keychain');
const { cleanEnv, cleanNumberEnv, log } = require('./env');

const VERSION = '0.3.0';
const DEFAULT_URL = 'https://api.gigasheet.com/mcp';
const AUTH_HEADER = 'X-GIGASHEET-TOKEN';

const MCP_URL = cleanEnv('GIGASHEET_MCP_URL', DEFAULT_URL);

// Optional escape hatch: a pasted API token still works, and takes precedence.
// Everyone else goes through the Auth0 device flow.
const TOKEN = cleanEnv('GIGASHEET_TOKEN');

// How long a login tool call may block while waiting for browser approval.
// Kept short on purpose: a long in-call wait reads as a silent hang in the
// Desktop UI. The background poll keeps running after we return, so a slower
// approval still lands - the user just retries their query once done.
const LOGIN_WAIT_MS = cleanNumberEnv('GIGASHEET_LOGIN_WAIT', 45) * 1000;

const REQUEST_TIMEOUT_MS = cleanNumberEnv('GIGASHEET_TIMEOUT', 120) * 1000;
const MAX_RETRIES = 2;
const RETRY_STATUSES = new Set([429, 502, 503, 504]);

// Mozilla-prefixed on purpose: api.gigasheet.com sits behind Cloudflare bot
// scoring, which intermittently 403s (error 1010) clients whose fingerprint
// reads as automation. The old shim ran for months as "Mozilla/5.0" without
// being blocked; a bare "gigasheet-mcpb/x" UA was. The real identity lives in
// the comment field.
const USER_AGENT = `Mozilla/5.0 (compatible; gigasheet-mcpb/${VERSION})`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --------------------------------------------------------------------------
// Tool definitions
//
// The remote ships a one-line Analyze description that omits the instruction
// grammar entirely, so the model has to guess at the syntax. We serve the real
// thing, plus the annotations the Connectors Directory requires on every tool.
// --------------------------------------------------------------------------

const ANALYZE_DESCRIPTION = `Query a dataset that already exists in Gigasheet and return the matching rows.

The \`sheet_id\` is the trailing segment of the sheet URL:
  https://app.gigasheet.com/spreadsheet/my-data/a1b2c3d4_5e6f_7890_abcd_ef1234567890
                                                ^-- this is the sheet_id

\`instructions\` is a semicolon-separated list of actions. Available actions:

  DISPLAY      Emit the result. Nothing is returned without it.
  COLUMN       Restrict output to a column. Repeat for multiple columns.
               Omit entirely to return all columns.
  FILTER       Keep rows matching a condition. Repeat to AND conditions
               together. \`=\` is case-sensitive; all other operators are not.
  SORT         Order rows. Repeat to sort by successive keys, in order given.
  ROWGROUPBY   Group rows by a column.
  AGGREGATE    Compute over groups, e.g. SUM(col), COUNT(col), AVG(col).
               Any aggregate other than the default count() requires a SORT
               on that aggregate in the same query.

Example:
  FILTER Status = Open; FILTER Revenue > 100000; ROWGROUPBY Region;
  AGGREGATE SUM(Revenue); SORT SUM(Revenue) DESC; DISPLAY

Important behaviors:

  * The sheet is reset before every call. Instructions never accumulate, so
    each call must be complete on its own. There is no incremental refinement.
  * Only DISPLAY produces output. Every other action just shapes what DISPLAY
    will return.
  * There is no join. Combining two sheets has to happen in Gigasheet itself,
    before querying.
  * This reads sheets. It cannot create, upload, modify, or delete them.
  * Start with a bare \`DISPLAY\` against an unfamiliar sheet to learn its column
    names before writing filters against them.

If every call returns "Invalid sheet_id parameter" even for sheets you know
exist, the API token is probably missing or lacks access to them, rather than
the id being wrong.`;

const ANALYZE_ANNOTATIONS = {
  title: 'Analyze a Gigasheet dataset',
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

// Local copy of the remote Analyze definition, served when the remote refuses
// an unauthenticated tools/list. Without it, an expired sign-in made Analyze
// vanish from the tool list entirely, so Claude could not even attempt the
// query that would trigger re-auth.
const ANALYZE_TOOL = {
  name: 'Analyze',
  description: ANALYZE_DESCRIPTION,
  inputSchema: {
    type: 'object',
    properties: {
      sheet_id: {
        type: 'string',
        description: 'The sheet id from the Gigasheet sheet URL (the trailing path segment).',
      },
      instructions: {
        type: 'string',
        description: 'Semicolon-separated list of actions; see the tool description for the grammar.',
      },
    },
    required: ['sheet_id', 'instructions'],
  },
  annotations: ANALYZE_ANNOTATIONS,
};

const LOGIN_TOOL = {
  name: 'gigasheet_login',
  description:
    'Sign in to Gigasheet. Queries authenticate on their own, so do NOT call ' +
    'this preemptively - only when a query reports that sign-in is required, ' +
    'or when the user explicitly asks to sign in or switch accounts. If the ' +
    'user is already signed in it does nothing and says so. Pass force=true ' +
    'to sign out and start a fresh sign-in (switch accounts). Opens the ' +
    'approval page in the browser, returns the code, and waits for the user ' +
    'to finish.',
  inputSchema: {
    type: 'object',
    properties: {
      force: {
        type: 'boolean',
        description: 'Sign out first and start a fresh sign-in even if already signed in.',
      },
    },
    required: [],
  },
  annotations: {
    title: 'Sign in to Gigasheet',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

const LOGOUT_TOOL = {
  name: 'gigasheet_logout',
  description:
    "Sign out of Gigasheet and erase the stored credentials from this " +
    "computer's keychain. Takes no arguments.",
  inputSchema: { type: 'object', properties: {}, required: [] },
  annotations: {
    title: 'Sign out of Gigasheet',
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false,
  },
};

const LOCAL_TOOLS = new Set([LOGIN_TOOL.name, LOGOUT_TOOL.name]);

/** Fix up the tool list: fuller Analyze docs + annotations, plus our local auth tools. */
function enrichTools(payload) {
  const tools = payload && payload.result && payload.result.tools;
  if (!Array.isArray(tools)) return payload;

  for (const tool of tools) {
    if (tool && tool.name === 'Analyze') {
      tool.description = ANALYZE_DESCRIPTION;
      tool.annotations = Object.assign({}, tool.annotations, ANALYZE_ANNOTATIONS);
    }
  }

  // Only advertise auth tools when the device flow is actually in play.
  if (!TOKEN) {
    const existing = new Set(tools.map((t) => t && t.name));
    for (const tool of [LOGIN_TOOL, LOGOUT_TOOL]) {
      if (!existing.has(tool.name)) tools.push(Object.assign({}, tool));
    }
  }
  return payload;
}

// --------------------------------------------------------------------------
// JSON-RPC helpers
// --------------------------------------------------------------------------

function errorResponse(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: '2.0', id: id === undefined ? null : id, error };
}

/** Shape a tools/call result the way the MCP spec expects. */
function toolResult(text, isError = false) {
  return { content: [{ type: 'text', text }], isError };
}

function writeMessage(payload) {
  process.stdout.write(JSON.stringify(payload) + '\n');
}

// --------------------------------------------------------------------------
// Local tools
// --------------------------------------------------------------------------

const BROWSER_TIP =
  'If the page opened inside an app window and your passkey does not work ' +
  'there, paste the URL into Chrome or Safari directly - passkeys need a ' +
  'full browser.';

/**
 * Start (or join) the device flow and wait for browser approval.
 *
 * MCP has no way to push a prompt at the user, so the code is delivered as
 * the tool's own result and the model relays it; we also open the
 * verification page in their browser directly. Waiting here lets sign-in
 * finish within a single turn, and if the wait runs out the background poll
 * keeps going, so a later query still benefits from a tardy approval.
 */
async function handleLogin(args) {
  const force = Boolean(args && args.force);
  if (force) {
    await auth.logout();
  } else {
    // Idempotent: the model tends to call this "just in case". If the stored
    // credential still refreshes, there is nothing to do, and opening a
    // browser page would only confuse the user.
    try {
      await auth.getAccessToken();
      const who = auth.describeIdentity();
      return toolResult(
        `Already signed in to Gigasheet${who ? ` as ${who}` : ''}. No action needed - ` +
        'just run the query. (Pass force=true to switch accounts.)'
      );
    } catch (err) {
      if (err instanceof auth.AuthError && !(err instanceof auth.NeedsLogin)) {
        return toolResult(err.message, true);
      }
      if (!(err instanceof auth.NeedsLogin)) throw err;
    }
  }

  let flow;
  try {
    flow = await auth.beginInteractiveLogin();
  } catch (err) {
    if (err instanceof auth.AuthError) return toolResult(err.message, true);
    throw err;
  }

  log(`device flow active; awaiting approval of code ${flow.userCode}`);
  const deadline = Date.now() + LOGIN_WAIT_MS;
  while (Date.now() < deadline && flow.status === 'pending') {
    await sleep(1000);
    // A flow owned by another bridge instance never updates our copy of
    // `status`; the signal that it finished is the credential appearing.
    if (flow.shared && auth.cachedAccessToken() === null) {
      try { await auth.getAccessToken(); flow.status = 'ok'; } catch (_) { /* still pending */ }
    }
  }

  if (flow.status === 'ok') {
    const who = auth.describeIdentity();
    log(`signed in${who ? ` as ${who}` : ''}`);
    return toolResult(`Signed in to Gigasheet${who ? ` as ${who}` : ''}. You can query your sheets now.`);
  }
  if (flow.status === 'error') {
    return toolResult(
      `Sign-in did not complete: ${flow.error}\n\nAsk me to sign in again to get a fresh code.`,
      true
    );
  }
  return toolResult(
    `Still waiting for approval. A browser tab was opened at ${flow.verifyUrl} — enter ` +
    `the code ${flow.userCode} if asked. Once you approve, just retry your query; the ` +
    `sign-in completes in the background.\n\nTip: ${BROWSER_TIP}`,
    true
  );
}

async function handleLogout() {
  await auth.logout();
  log('signed out; stored credentials erased');
  return toolResult('Signed out. Stored credentials erased from the keychain.');
}

/**
 * Expired or missing sign-in on a query: start the login now, open the
 * browser, and tell the user exactly what to do. The background poll means
 * their next query after approving simply works — no second step.
 */
async function autoReauthResult() {
  let flow;
  try {
    flow = await auth.beginInteractiveLogin();
  } catch (err) {
    if (err instanceof auth.AuthError) return toolResult(err.message, true);
    throw err;
  }
  if (flow.shared) {
    log(`auth expired; joining sign-in already open in another instance (code ${flow.userCode})`);
    return toolResult(
      `Your Gigasheet sign-in has expired. A sign-in page is already open in your browser ` +
      `(code ${flow.userCode}, ${flow.verifyUrl}) — approve it there, then retry this query.`,
      true
    );
  }
  log(`auth expired; auto-started device flow with code ${flow.userCode}`);
  return toolResult(
    `Your Gigasheet sign-in has expired, so I started a new one. A browser tab should ` +
    `have opened at ${flow.verifyUrl} — approve the code ${flow.userCode} there (sign in ` +
    `if asked), then retry this query.\n\n${BROWSER_TIP}`,
    true
  );
}

// --------------------------------------------------------------------------
// Transport
// --------------------------------------------------------------------------

/** POST to the remote. Resolves {status, text}; rejects on network death. */
function post(body, bearer) {
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    Accept: 'application/json',
    'User-Agent': USER_AGENT,
  };
  if (TOKEN) headers[AUTH_HEADER] = TOKEN;
  else if (bearer) headers.Authorization = `Bearer ${bearer}`;

  return new Promise((resolve, reject) => {
    const req = https.request(MCP_URL, { method: 'POST', headers, timeout: REQUEST_TIMEOUT_MS }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { text += d; });
      res.on('end', () => resolve({ status: res.statusCode, text }));
    });
    req.on('timeout', () => req.destroy(new Error(`no response within ${REQUEST_TIMEOUT_MS / 1000}s`)));
    req.on('error', reject);
    req.end(body);
  });
}

/** POST, retrying transient failures. Resolves {status, text} or {error}. */
async function postWithRetries(body, id, bearer) {
  let lastDetail = null;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const r = await post(body, bearer);
      if (!RETRY_STATUSES.has(r.status)) return r;
      lastDetail = `HTTP ${r.status} from Gigasheet`;
    } catch (err) {
      lastDetail = `network error: ${err.message}`;
    }
    if (attempt < MAX_RETRIES) {
      const delay = 500 * 2 ** attempt;
      log(`${lastDetail} - retrying in ${delay}ms`);
      await sleep(delay);
    }
  }
  log(`giving up after ${MAX_RETRIES + 1} attempts: ${lastDetail}`);
  return { error: errorResponse(id, -32001, 'Could not reach Gigasheet', lastDetail) };
}

function localHandshake(id) {
  return {
    jsonrpc: '2.0',
    id,
    result: {
      protocolVersion: '2024-11-05',
      capabilities: { tools: { listChanged: true } },
      serverInfo: { name: 'Gigasheet', version: VERSION },
    },
  };
}

function localToolList(id) {
  return enrichTools({
    jsonrpc: '2.0',
    id,
    result: { tools: [Object.assign({}, ANALYZE_TOOL), Object.assign({}, LOGIN_TOOL), Object.assign({}, LOGOUT_TOOL)] },
  });
}

/**
 * Turn a raw HTTP response into a JSON-RPC message the client can accept.
 *
 * The remote returns non-JSON-RPC bodies on auth failure and behind
 * Cloudflare. Forwarding those verbatim is what corrupts the stream, so
 * everything is normalized here.
 */
async function interpret(status, text, id, method, sentBearer = false) {
  if (status === 401 || status === 403) {
    // Two very different failures share these codes. A real auth rejection
    // from Gigasheet is a small JSON body ({"Success":false,...}). A
    // Cloudflare bot-mitigation block ("error code: 1010", HTML) is an
    // infrastructure problem that has nothing to do with the user's
    // credentials — telling them to fix their sign-in for it sends them
    // debugging the wrong thing entirely.
    let authShaped = false;
    try {
      const body = JSON.parse(text);
      authShaped = body !== null && typeof body === 'object' && !Array.isArray(body);
    } catch (_) { /* not JSON */ }

    // Never let auth kill the handshake: a failed initialize takes the whole
    // server down ("Unable to connect to extension server"), leaving no
    // channel to tell anyone what is wrong. Answer the handshake locally and
    // let tool calls carry the actionable error instead.
    if (method === 'initialize') {
      log(`${authShaped ? 'auth rejected' : 'blocked at the network layer'} on initialize (HTTP ${status}); answering handshake locally`);
      return localHandshake(id);
    }
    if (method === 'tools/list') {
      log(`${authShaped ? 'auth rejected' : 'blocked at the network layer'} on tools/list (HTTP ${status}); serving local tool list`);
      return localToolList(id);
    }
    // Desktop asks for these at startup, before any credential is attached.
    // The remote has none to offer anyway, so answer locally. Treating this
    // refusal as "your sign-in is bad" once wiped the stored credential on
    // every launch and opened one browser tab per bridge instance.
    if (method === 'prompts/list') return { jsonrpc: '2.0', id, result: { prompts: [] } };
    if (method === 'resources/list') return { jsonrpc: '2.0', id, result: { resources: [] } };

    if (!authShaped) {
      log(`blocked at the network layer (HTTP ${status}): ${text.trim().slice(0, 120)}`);
      return errorResponse(
        id,
        -32004,
        "Gigasheet's network protection temporarily blocked this request",
        'This is not a sign-in problem - do not re-authenticate. It usually clears on ' +
        'its own; retry in a minute. If it persists, Gigasheet may need to allowlist ' +
        'this extension in their firewall.'
      );
    }

    log(`auth rejected by Gigasheet (HTTP ${status})`);
    if (TOKEN) {
      return errorResponse(
        id,
        -32002,
        'Gigasheet rejected the API token',
        `The token was refused (HTTP ${status}). Check it in the extension settings; ` +
        'you can reissue one from Gigasheet under Profile > API.'
      );
    }
    if (method === 'tools/call' && sentBearer) {
      // Sign-in mode: OUR bearer was genuinely refused (revoked session,
      // permissions change). Start a fresh sign-in instead of explaining one.
      await auth.logout();
      return { jsonrpc: '2.0', id, result: await autoReauthResult() };
    }
    // Anything else: an unauthenticated protocol call the remote will not
    // serve. Not evidence about the stored credential - leave it alone.
    return errorResponse(id, -32002, 'Gigasheet requires sign-in for this request',
      'The stored sign-in was not attached to this request type; query tools sign in automatically.');
  }

  let payload;
  try {
    payload = JSON.parse(text);
  } catch (_) {
    const snippet = text.trim().slice(0, 200) || '(empty body)';
    log(`non-JSON response (HTTP ${status}): ${snippet}`);
    return errorResponse(id, -32003, 'Unexpected response from Gigasheet', `HTTP ${status}: ${snippet}`);
  }

  // A well-formed JSON-RPC reply has one of these. Anything else is some
  // other service's error envelope wearing a 200.
  const isRpc = payload && typeof payload === 'object' && ('result' in payload || 'error' in payload);
  if (!isRpc) {
    const detail = payload && typeof payload === 'object' ? payload.Message : undefined;
    log(`non-JSON-RPC payload (HTTP ${status}): ${JSON.stringify(payload).slice(0, 200)}`);
    return errorResponse(
      id, -32003, 'Unexpected response from Gigasheet',
      detail || `HTTP ${status}: ${JSON.stringify(payload).slice(0, 200)}`
    );
  }

  payload.jsonrpc = payload.jsonrpc || '2.0';
  payload.id = id;
  return method === 'tools/list' ? enrichTools(payload) : payload;
}

// --------------------------------------------------------------------------
// Request handling
// --------------------------------------------------------------------------

async function handle(line) {
  let message;
  try {
    message = JSON.parse(line);
  } catch (_) {
    log(`dropping unparseable input: ${line.trim().slice(0, 200)}`);
    writeMessage(errorResponse(null, -32700, 'Parse error'));
    return;
  }
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    writeMessage(errorResponse(null, -32600, 'Invalid request'));
    return;
  }

  const id = message.id;
  const method = message.method;
  const isNotification = !('id' in message);
  const toolName = method === 'tools/call' ? (message.params || {}).name : undefined;

  // Auth tools are handled here and never forwarded upstream.
  if (LOCAL_TOOLS.has(toolName) && !isNotification) {
    const result = toolName === LOGIN_TOOL.name
      ? await handleLogin((message.params || {}).arguments)
      : await handleLogout();
    writeMessage({ jsonrpc: '2.0', id, result });
    return;
  }

  let bearer = null;
  if (!TOKEN && method === 'tools/call') {
    try {
      bearer = await auth.getAccessToken();
    } catch (err) {
      if (isNotification) return;
      if (err instanceof auth.NeedsLogin) {
        log(`sign-in needed: ${err.message}`);
        writeMessage({ jsonrpc: '2.0', id, result: await autoReauthResult() });
      } else if (err instanceof auth.AuthError) {
        writeMessage({ jsonrpc: '2.0', id, result: toolResult(err.message, true) });
      } else {
        throw err;
      }
      return;
    }
  } else if (!TOKEN) {
    // The remote began rejecting unauthenticated protocol calls (initialize,
    // tools/list) with 403 in Aug 2026, so attach the bearer to everything
    // when we have one. Cached-only: a handshake must never block on a token
    // refresh, and the 403 fallbacks cover the gap.
    bearer = auth.cachedAccessToken();
  }

  const outcome = await postWithRetries(line, id, bearer);
  if (outcome.error) {
    if (!isNotification) writeMessage(outcome.error);
    return;
  }

  // A notification gets no reply, whatever the remote sent back.
  if (isNotification) {
    if (outcome.status >= 400) log(`notification ${method} returned HTTP ${outcome.status}`);
    return;
  }

  writeMessage(await interpret(outcome.status, outcome.text, id, method, Boolean(bearer)));
}

/** Report auth posture at startup so problems land in the logs, not in a
 *  confusing tool error three questions into a conversation. */
async function checkStartup() {
  if (TOKEN) {
    try {
      const r = await post(JSON.stringify({ jsonrpc: '2.0', id: 'startup-check', method: 'tools/list', params: {} }));
      if (r.status === 401 || r.status === 403) {
        log(`WARNING: Gigasheet rejected the configured API token (HTTP ${r.status}).`);
      } else {
        log(`using API token auth; connected to ${MCP_URL}`);
      }
    } catch (err) {
      log(`could not reach Gigasheet at startup (${err.message}); continuing anyway`);
    }
    return;
  }

  if (!auth.CLIENT_ID) {
    log('WARNING: no Auth0 client ID configured. Sign-in cannot start. The extension ' +
        'needs GIGASHEET_CLIENT_ID set to an Auth0 Native application with the Device ' +
        'Code grant enabled.');
    return;
  }
  const keychainProblem = await keychain.unavailableReason();
  if (keychainProblem) {
    log(`WARNING: this system's keychain is not reachable (${keychainProblem}). Sign-in ` +
        'will work but will not persist across restarts.');
  }
  log((await auth.hasStoredCredentials())
    ? 'stored credentials found; will refresh on first query'
    : 'no stored credentials; user will be prompted to sign in');
}

function main() {
  // The client closing our stdout is a normal shutdown, not a crash.
  if (process.stdout && typeof process.stdout.on === 'function') {
    process.stdout.on('error', (err) => {
      if (err && err.code === 'EPIPE') process.exit(0);
      throw err;
    });
  }

  const inflight = new Set();
  const track = (p) => {
    inflight.add(p);
    p.catch((err) => log(`unhandled error: ${err && err.stack || err}`))
     .finally(() => inflight.delete(p));
  };

  track(checkStartup());

  // Raw line splitting rather than readline. Inside Claude Desktop's built-in
  // Node host, process.stdin is a bare Readable with a hand-picked subset of
  // methods copied onto it; the plain 'data' event is the one contract every
  // variant honours, and it is what the official MCP SDK relies on too.
  const decoder = new StringDecoder('utf8');
  let buffered = '';
  const consume = (chunk) => {
    buffered += typeof chunk === 'string' ? chunk : decoder.write(chunk);
    let nl;
    while ((nl = buffered.indexOf('\n')) !== -1) {
      const line = buffered.slice(0, nl).replace(/\r$/, '');
      buffered = buffered.slice(nl + 1);
      if (line.trim()) track(handle(line));
    }
  };
  process.stdin.on('data', consume);
  process.stdin.on('end', async () => {
    buffered += decoder.end();
    if (buffered.trim()) track(handle(buffered));
    await Promise.allSettled(Array.from(inflight));
    process.exit(0);
  });
  if (typeof process.stdin.resume === 'function') process.stdin.resume();
}

// Start when run as the entry point. `require.main === module` is not enough:
// Claude Desktop's built-in Node host loads the entry via dynamic import(),
// under which require.main is the host script and the guard is false — the
// bridge then silently never starts. The host sets process.argv[1] to our
// path, and so does a plain `node server/index.js`, so compare on that.
const invokedDirectly = (() => {
  try {
    return Boolean(process.argv[1]) && path.resolve(process.argv[1]) === __filename;
  } catch (_) {
    return false;
  }
})();

if (invokedDirectly) {
  main();
}

module.exports = {
  VERSION,
  TOKEN,
  ANALYZE_TOOL,
  LOGIN_TOOL,
  LOGOUT_TOOL,
  enrichTools,
  interpret,
  handle,
  handleLogin,
  autoReauthResult,
  errorResponse,
  toolResult,
  _setWriter: (fn) => { writeMessage = fn; },
};
