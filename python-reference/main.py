#!/usr/bin/env python3
"""Gigasheet MCP bridge.

Speaks MCP over stdio to the local client and forwards to Gigasheet's remote
MCP endpoint over HTTPS. Standard library only, so the bundle needs no vendored
dependencies.

The remote endpoint is stateless: plain JSON responses, no SSE, no session id.
So this is a straight request/response bridge. What it adds over a raw pipe:

  * Non-JSON-RPC error bodies (notably the 401 page) are translated into valid
    JSON-RPC errors instead of being written into the protocol stream.
  * A missing token is caught at startup. Unauthenticated calls are accepted by
    the remote and fail later as "Invalid sheet_id parameter", which sends users
    hunting for the wrong bug.
  * Notifications are never answered.
  * The Analyze tool description is replaced with the full instruction grammar.
"""

import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

import auth
import keychain

DEFAULT_URL = "https://api.gigasheet.com/mcp"
AUTH_HEADER = "X-GIGASHEET-TOKEN"

def clean_env(name, default=""):
    """Read an env var, treating unexpanded ${user_config.*} templates as unset.

    When an optional field is left blank, Claude Desktop can pass the manifest's
    literal template string through instead of an empty value. Taking that at
    face value once sent "${user_config.api_token}" upstream as an API token,
    and the resulting 401 on initialize killed the whole connection.
    """
    value = (os.environ.get(name) or "").strip()
    if not value or (value.startswith("${") and value.endswith("}")):
        return default
    return value


def clean_float_env(name, default):
    try:
        return float(clean_env(name, str(default)))
    except ValueError:
        return default


MCP_URL = clean_env("GIGASHEET_MCP_URL", DEFAULT_URL)

# Optional escape hatch: a pasted API token still works, and takes precedence.
# Everyone else goes through the Auth0 device flow.
TOKEN = clean_env("GIGASHEET_TOKEN")

# How long a login tool call may block while waiting for browser approval.
# Kept short on purpose: a long in-call wait reads as a silent hang in the
# Desktop UI. The background poll keeps running after we return, so a slower
# approval still lands - the user just retries their query once done.
LOGIN_WAIT_SECONDS = clean_float_env("GIGASHEET_LOGIN_WAIT", 45)

REQUEST_TIMEOUT = clean_float_env("GIGASHEET_TIMEOUT", 120)
MAX_RETRIES = 2
RETRY_STATUSES = {429, 502, 503, 504}

_stdout_lock = threading.Lock()
_ssl_context = ssl.create_default_context()


def log(message):
    """Claude Desktop surfaces stderr in the extension logs."""
    sys.stderr.write("[gigasheet] %s\n" % message)
    sys.stderr.flush()


# --------------------------------------------------------------------------
# Tool description
#
# The remote ships a one-line description that omits the instruction grammar
# entirely, so the model has to guess at the syntax. We serve the real thing.
# --------------------------------------------------------------------------

ANALYZE_DESCRIPTION = """Query a dataset that already exists in Gigasheet and return the matching rows.

The `sheet_id` is the trailing segment of the sheet URL:
  https://app.gigasheet.com/spreadsheet/my-data/a1b2c3d4_5e6f_7890_abcd_ef1234567890
                                                ^-- this is the sheet_id

`instructions` is a semicolon-separated list of actions. Available actions:

  DISPLAY      Emit the result. Nothing is returned without it.
  COLUMN       Restrict output to a column. Repeat for multiple columns.
               Omit entirely to return all columns.
  FILTER       Keep rows matching a condition. Repeat to AND conditions
               together. `=` is case-sensitive; all other operators are not.
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
  * Start with a bare `DISPLAY` against an unfamiliar sheet to learn its column
    names before writing filters against them.

If every call returns "Invalid sheet_id parameter" even for sheets you know
exist, the API token is probably missing or lacks access to them, rather than
the id being wrong."""


# Local copy of the remote Analyze definition (with our enriched description),
# served when the remote refuses an unauthenticated tools/list. Without it, an
# expired sign-in made Analyze vanish from the tool list entirely, so Claude
# could not even attempt the query that would trigger re-auth.
ANALYZE_TOOL = {
    "name": "Analyze",
    "description": ANALYZE_DESCRIPTION,
    "inputSchema": {
        "type": "object",
        "properties": {
            "sheet_id": {
                "type": "string",
                "description": "The sheet id from the Gigasheet sheet URL "
                               "(the trailing path segment).",
            },
            "instructions": {
                "type": "string",
                "description": "Semicolon-separated list of actions; see the "
                               "tool description for the grammar.",
            },
        },
        "required": ["sheet_id", "instructions"],
    },
}

LOGIN_TOOL = {
    "name": "gigasheet_login",
    "description": (
        "Sign in to Gigasheet. Call this when a Gigasheet query reports that "
        "sign-in is required, or when the user asks to sign in or switch "
        "accounts. Returns a short code and a URL for the user to approve in "
        "their browser, then waits for them to finish. Takes no arguments."
    ),
    "inputSchema": {"type": "object", "properties": {}, "required": []},
}

LOGOUT_TOOL = {
    "name": "gigasheet_logout",
    "description": (
        "Sign out of Gigasheet and erase the stored credentials from this "
        "computer's keychain. Takes no arguments."
    ),
    "inputSchema": {"type": "object", "properties": {}, "required": []},
}

LOCAL_TOOLS = {LOGIN_TOOL["name"], LOGOUT_TOOL["name"]}


def enrich_tools(payload):
    """Fix up the tool list: fuller Analyze docs, plus our local auth tools."""
    try:
        tools = payload["result"]["tools"]
    except (KeyError, TypeError):
        return payload
    if not isinstance(tools, list):
        return payload

    for tool in tools:
        if isinstance(tool, dict) and tool.get("name") == "Analyze":
            tool["description"] = ANALYZE_DESCRIPTION

    # Only advertise auth tools when the device flow is actually in play.
    if not TOKEN:
        existing = {t.get("name") for t in tools if isinstance(t, dict)}
        for tool in (LOGIN_TOOL, LOGOUT_TOOL):
            if tool["name"] not in existing:
                tools.append(dict(tool))

    return payload


def tool_result(text, is_error=False):
    """Shape a tools/call result the way the MCP spec expects."""
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def handle_login():
    """Start (or join) the device flow and wait for browser approval.

    MCP has no way to push a prompt at the user, so the code is delivered as
    the tool's own result and the model relays it; we also open the
    verification page in their browser directly. Waiting here lets sign-in
    finish within a single turn, and if the wait runs out the background poll
    keeps going, so a later query still benefits from a tardy approval.
    """
    try:
        flow = auth.begin_interactive_login()
    except auth.AuthError as exc:
        return tool_result(str(exc), is_error=True)

    log("device flow active; awaiting approval of code %s" % flow["user_code"])
    deadline = time.monotonic() + LOGIN_WAIT_SECONDS
    while time.monotonic() < deadline and flow["status"] == "pending":
        time.sleep(1)

    if flow["status"] == "ok":
        who = auth.describe_identity()
        log("signed in%s" % (" as %s" % who if who else ""))
        return tool_result(
            "Signed in to Gigasheet%s. You can query your sheets now."
            % (" as %s" % who if who else "")
        )
    if flow["status"] == "error":
        return tool_result(
            "Sign-in did not complete: %s\n\nAsk me to sign in again to get a "
            "fresh code." % flow["error"],
            is_error=True,
        )
    return tool_result(
        "Still waiting for approval. A browser tab was opened at %s — enter "
        "the code %s if asked. Once you approve, just retry your query; the "
        "sign-in completes in the background.\n\n"
        "Tip: if the page opened inside an app window and your passkey does "
        "not work there, paste the URL into Chrome or Safari directly - "
        "passkeys need a full browser."
        % (flow["verify_url"], flow["user_code"]),
        is_error=True,
    )


def auto_reauth_result():
    """Expired or missing sign-in on a query: start the login now, open the
    browser, and tell the user exactly what to do. The background poll means
    their next query after approving simply works — no second step."""
    try:
        flow = auth.begin_interactive_login()
    except auth.AuthError as exc:
        return tool_result(str(exc), is_error=True)
    log("auth expired; auto-started device flow with code %s" % flow["user_code"])
    return tool_result(
        "Your Gigasheet sign-in has expired, so I started a new one. A browser "
        "tab should have opened at %s — approve the code %s there (sign in if "
        "asked), then retry this query.\n\n"
        "If the page opened inside an app window and your passkey does not "
        "work there, paste the URL into Chrome or Safari directly - passkeys "
        "need a full browser."
        % (flow["verify_url"], flow["user_code"]),
        is_error=True,
    )


def handle_logout():
    auth.logout()
    log("signed out; stored credentials erased")
    return tool_result("Signed out. Stored credentials erased from the keychain.")




# --------------------------------------------------------------------------
# JSON-RPC helpers
# --------------------------------------------------------------------------

def error_response(request_id, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def write_message(payload):
    line = json.dumps(payload, separators=(",", ":"))
    with _stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

def post(body_bytes, bearer=None):
    """POST to the remote. Returns (status, body_text). Raises on network death."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Mozilla-prefixed on purpose: api.gigasheet.com sits behind Cloudflare
        # bot scoring, which intermittently 403s (error 1010) clients whose
        # fingerprint reads as automation. The old shim ran for months as
        # "Mozilla/5.0" without being blocked; a bare "gigasheet-mcpb/0.2" UA
        # was. Keep the real identity in the comment field.
        "User-Agent": "Mozilla/5.0 (compatible; gigasheet-mcpb/0.2)",
    }
    if TOKEN:
        headers[AUTH_HEADER] = TOKEN
    elif bearer:
        headers["Authorization"] = "Bearer %s" % bearer

    request = urllib.request.Request(
        MCP_URL, data=body_bytes, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT, context=_ssl_context
        ) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # Read the body: the 401 page lives here and we want it for diagnostics.
        return exc.code, exc.read().decode("utf-8", "replace")


def post_with_retries(body_bytes, request_id, bearer=None):
    """POST, retrying transient failures. Returns (status, text) or a JSON-RPC error."""
    last_detail = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            status, text = post(body_bytes, bearer=bearer)
        except (urllib.error.URLError, OSError) as exc:
            last_detail = "network error: %s" % exc
        else:
            if status not in RETRY_STATUSES:
                return status, text
            last_detail = "HTTP %d from Gigasheet" % status

        if attempt < MAX_RETRIES:
            delay = 0.5 * (2 ** attempt)
            log("%s - retrying in %.1fs" % (last_detail, delay))
            time.sleep(delay)

    log("giving up after %d attempts: %s" % (MAX_RETRIES + 1, last_detail))
    return None, error_response(
        request_id, -32001, "Could not reach Gigasheet", last_detail
    )


def interpret(status, text, request_id, method):
    """Turn a raw HTTP response into a JSON-RPC message the client can accept.

    The remote returns non-JSON-RPC bodies on auth failure. Forwarding those
    verbatim is what corrupts the stream, so everything is normalized here.
    """
    if status == 401 or status == 403:
        # Two very different failures share these codes. A real auth rejection
        # from Gigasheet is a small JSON body ({"Success":false,...}). A
        # Cloudflare bot-mitigation block ("error code: 1010", HTML) is an
        # infrastructure problem that has nothing to do with the user's
        # credentials — telling them to fix their sign-in for it sends them
        # debugging the wrong thing entirely.
        is_auth_shaped = False
        try:
            body = json.loads(text)
            is_auth_shaped = isinstance(body, dict)
        except ValueError:
            pass

        if not is_auth_shaped:
            log("blocked at the network layer (HTTP %d): %s"
                % (status, text.strip()[:120]))
            if method == "initialize":
                pass  # fall through to the local-handshake fallback below
            elif method == "tools/list":
                pass
            else:
                return error_response(
                    request_id,
                    -32004,
                    "Gigasheet's network protection temporarily blocked this "
                    "request",
                    "This is not a sign-in problem - do not re-authenticate. "
                    "It usually clears on its own; retry in a minute. If it "
                    "persists, Gigasheet may need to allowlist this "
                    "extension in their firewall.",
                )
        else:
            log("auth rejected by Gigasheet (HTTP %d)" % status)
        # Never let auth kill the handshake: a failed initialize takes the
        # whole server down ("Unable to connect to extension server"), leaving
        # no channel to tell anyone what is wrong. Answer the handshake
        # locally and let tool calls carry the actionable error instead.
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "Gigasheet", "version": "0.2.0"},
                },
            }
        if method == "tools/list":
            return enrich_tools({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": [
                    dict(ANALYZE_TOOL), dict(LOGIN_TOOL), dict(LOGOUT_TOOL),
                ]},
            })
        if TOKEN:
            return error_response(
                request_id,
                -32002,
                "Gigasheet rejected the API token",
                "The token was refused (HTTP %d). Check it in the extension "
                "settings; you can reissue one from Gigasheet under "
                "Profile > API." % status,
            )
        # Sign-in mode: the bearer was genuinely refused (revoked session,
        # permissions change). Start a fresh sign-in right now instead of
        # explaining one.
        auth.logout()
        return {"jsonrpc": "2.0", "id": request_id, "result": auto_reauth_result()}

    try:
        payload = json.loads(text)
    except ValueError:
        snippet = text.strip()[:200] or "(empty body)"
        log("non-JSON response (HTTP %s): %s" % (status, snippet))
        return error_response(
            request_id,
            -32003,
            "Unexpected response from Gigasheet",
            "HTTP %s: %s" % (status, snippet),
        )

    # A well-formed JSON-RPC reply has one of these. Anything else is some
    # other service's error envelope wearing a 200.
    if not isinstance(payload, dict) or not ("result" in payload or "error" in payload):
        detail = payload.get("Message") if isinstance(payload, dict) else None
        log("non-JSON-RPC payload (HTTP %s): %s" % (status, str(payload)[:200]))
        return error_response(
            request_id,
            -32003,
            "Unexpected response from Gigasheet",
            detail or ("HTTP %s: %s" % (status, str(payload)[:200])),
        )

    payload.setdefault("jsonrpc", "2.0")
    payload["id"] = request_id

    if method == "tools/list":
        payload = enrich_tools(payload)

    return payload


# --------------------------------------------------------------------------
# Request handling
# --------------------------------------------------------------------------

def handle(raw_line):
    try:
        message = json.loads(raw_line)
    except ValueError:
        log("dropping unparseable input: %s" % raw_line.strip()[:200])
        write_message(error_response(None, -32700, "Parse error"))
        return

    if not isinstance(message, dict):
        write_message(error_response(None, -32600, "Invalid request"))
        return

    request_id = message.get("id")
    method = message.get("method")
    is_notification = "id" not in message
    tool_name = (message.get("params") or {}).get("name") if method == "tools/call" else None

    # Auth tools are handled here and never forwarded upstream.
    if tool_name in LOCAL_TOOLS and not is_notification:
        handler = handle_login if tool_name == LOGIN_TOOL["name"] else handle_logout
        write_message({"jsonrpc": "2.0", "id": request_id, "result": handler()})
        return

    bearer = None
    if not TOKEN and method == "tools/call":
        try:
            bearer = auth.get_access_token()
        except auth.NeedsLogin:
            if not is_notification:
                write_message({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": auto_reauth_result(),
                })
            return
        except auth.AuthError as exc:
            if not is_notification:
                write_message({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": tool_result(str(exc), is_error=True),
                })
            return
    elif not TOKEN:
        # The remote began rejecting unauthenticated protocol calls
        # (initialize, tools/list) with 403 in Aug 2026, so attach the bearer
        # to everything when we have one. Cached-only: a handshake must never
        # block on a token refresh, and the 403 fallbacks cover the gap.
        bearer = auth.cached_access_token()

    body = raw_line.encode("utf-8")
    result = post_with_retries(body, request_id, bearer=bearer)

    if result[0] is None:  # transport gave up and handed back an error object
        if not is_notification:
            write_message(result[1])
        return

    status, text = result

    # A notification gets no reply, whatever the remote sent back.
    if is_notification:
        if status >= 400:
            log("notification %s returned HTTP %d" % (method, status))
        return

    write_message(interpret(status, text, request_id, method))


def check_startup():
    """Report auth posture at startup so problems land in the logs, not in a
    confusing tool error three questions into a conversation."""
    if TOKEN:
        probe = json.dumps(
            {"jsonrpc": "2.0", "id": "startup-check", "method": "tools/list", "params": {}}
        ).encode("utf-8")
        try:
            status, _ = post(probe)
        except (urllib.error.URLError, OSError) as exc:
            log("could not reach Gigasheet at startup (%s); continuing anyway" % exc)
            return
        if status in (401, 403):
            log("WARNING: Gigasheet rejected the configured API token (HTTP %d)." % status)
        else:
            log("using API token auth; connected to %s" % MCP_URL)
        return

    if not auth.CLIENT_ID:
        log("WARNING: no Auth0 client ID configured. Sign-in cannot start. "
            "The extension needs GIGASHEET_CLIENT_ID set to an Auth0 Native "
            "application with the Device Code grant enabled.")
        return

    if not keychain.available():
        log("WARNING: this system's keychain is not reachable. Sign-in will "
            "work but will not persist across restarts.")

    if auth.has_stored_credentials():
        log("stored credentials found; will refresh on first query")
    else:
        log("no stored credentials; user will be prompted to sign in")


def main():
    check_startup()

    workers = []
    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        worker = threading.Thread(target=handle, args=(raw_line,), daemon=True)
        worker.start()
        workers.append(worker)
        workers = [w for w in workers if w.is_alive()]

    for worker in workers:
        worker.join(timeout=REQUEST_TIMEOUT)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
