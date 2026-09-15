"""Auth0 Device Authorization Grant (RFC 8628) for the Gigasheet extension.

Device flow rather than loopback PKCE: no redirect URI to register, and no local
HTTP listener inside the extension. The user is shown a short code, approves it
in their browser, and the bridge polls for the token.

Access tokens live in memory. The refresh token goes to the OS keychain so that
a restart does not force a fresh login.
"""

import base64
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import keychain

AUTH0_DOMAIN = os.environ.get("GIGASHEET_AUTH0_DOMAIN", "login.gigasheet.com")
CLIENT_ID = (os.environ.get("GIGASHEET_CLIENT_ID") or "").strip()
AUDIENCE = os.environ.get("GIGASHEET_AUDIENCE", "https://api.gigasheet.com/users")
SCOPE = "openid profile email offline_access"

DEVICE_CODE_URL = "https://%s/oauth/device/code" % AUTH0_DOMAIN
TOKEN_URL = "https://%s/oauth/token" % AUTH0_DOMAIN

# Refresh a little early so a token cannot expire mid-request.
EXPIRY_SKEW_SECONDS = 60
KEYCHAIN_ACCOUNT = "refresh_token"

_ssl_context = ssl.create_default_context()

# Guards the in-memory token cache.
_lock = threading.Lock()

# Serializes refreshes across worker threads. With refresh token rotation and
# reuse detection, two threads refreshing with the same token would look like a
# replay attack to Auth0 and get the whole token family revoked — logging the
# user out mid-conversation. Only one refresh may be in flight at a time.
_refresh_lock = threading.Lock()


class AuthError(Exception):
    """Authentication failed in a way the user needs to act on."""


class NeedsLogin(AuthError):
    """No usable credentials. The user must complete the device flow."""


def _post_form(url, fields):
    body = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "gigasheet-mcpb/0.2",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=_ssl_context) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"error": "http_%d" % exc.code, "error_description": raw[:200]}
    except (urllib.error.URLError, OSError) as exc:
        raise AuthError("Could not reach Auth0 at %s: %s" % (AUTH0_DOMAIN, exc))


def _require_client_id():
    if not CLIENT_ID:
        raise AuthError(
            "No Auth0 client ID is configured. The extension needs an Auth0 "
            "Native application with the Device Code grant enabled."
        )


# --------------------------------------------------------------------------
# Device flow
# --------------------------------------------------------------------------

def start_device_flow():
    """Request a device + user code. Returns the Auth0 payload."""
    _require_client_id()
    status, payload = _post_form(DEVICE_CODE_URL, {
        "client_id": CLIENT_ID,
        "audience": AUDIENCE,
        "scope": SCOPE,
    })

    if status == 200:
        return payload

    error = payload.get("error", "")
    if error == "unauthorized_client":
        raise AuthError(
            "This Auth0 application is not allowed to use the Device Code "
            "grant. In the Auth0 dashboard, the application must be of type "
            "Native with the Device Code grant enabled."
        )
    raise AuthError(
        "Auth0 refused the device code request: %s"
        % (payload.get("error_description") or error or "HTTP %d" % status)
    )


def poll_for_token(device_code, interval, expires_in, deadline=None):
    """Poll the token endpoint until the user approves, declines, or time runs out.

    `deadline` caps how long we block, independently of the code's own lifetime,
    so a tool call cannot hang for the full 15 minutes Auth0 allows.
    """
    _require_client_id()
    interval = max(int(interval or 5), 1)
    code_expiry = time.monotonic() + int(expires_in or 900)
    stop_at = min(code_expiry, deadline) if deadline else code_expiry

    while time.monotonic() < stop_at:
        time.sleep(interval)
        status, payload = _post_form(TOKEN_URL, {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": CLIENT_ID,
        })

        if status == 200:
            _store_tokens(payload)
            return payload

        error = payload.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error == "access_denied":
            raise AuthError("Sign-in was declined.")
        if error == "expired_token":
            raise AuthError("The sign-in code expired. Start over.")
        raise AuthError(
            "Auth0 returned an error: %s"
            % (payload.get("error_description") or error or "HTTP %d" % status)
        )

    raise AuthError("Timed out waiting for sign-in to be approved.")


# --------------------------------------------------------------------------
# Token cache
# --------------------------------------------------------------------------

_access_token = None
_access_expires_at = 0.0
_identity = None


def _store_tokens(payload, strict=True):
    """Cache the access token and persist the refresh token.

    Rotation means every refresh returns a *new* refresh token and invalidates
    the old one, so this must run on every successful exchange, not just login.

    `strict` controls what happens when the keychain refuses the write. At login
    time that is worth surfacing. Mid-session it is not: we still hold a good
    access token, and killing the request would waste it. The user simply has to
    sign in again once it expires.
    """
    global _access_token, _access_expires_at, _identity

    with _lock:
        _access_token = payload.get("access_token")
        _access_expires_at = time.monotonic() + float(payload.get("expires_in", 3600))
        # The access token carries only an opaque `sub`; the human-readable
        # email lives in the ID token. Keep it purely for display.
        identity = _claim_from_jwt(payload.get("id_token"), ("email", "name"))
        if identity:
            _identity = identity

    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        return

    try:
        keychain.set_secret(KEYCHAIN_ACCOUNT, refresh_token)
    except keychain.KeychainError as exc:
        # Deliberately not falling back to disk: a long-lived refresh token in a
        # plaintext file is worse than making the user sign in again.
        message = (
            "The refresh token could not be saved to the system keychain (%s). "
            "You will have to sign in again next time." % exc
        )
        if strict:
            raise AuthError("Signed in, but " + message)
        _warn(message)


def _warn(message):
    sys.stderr.write("[gigasheet:auth] %s\n" % message)
    sys.stderr.flush()


def _refresh_from_stored():
    try:
        refresh_token = keychain.get_secret(KEYCHAIN_ACCOUNT)
    except keychain.KeychainError as exc:
        raise NeedsLogin("Keychain unavailable (%s)." % exc)

    if not refresh_token:
        raise NeedsLogin("No stored credentials.")

    _require_client_id()
    status, payload = _post_form(TOKEN_URL, {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    })

    if status == 200:
        _store_tokens(payload, strict=False)
        return payload["access_token"]

    # Revoked, rotated away, or expired: drop it so we do not keep replaying a
    # dead token. Under reuse detection, retrying is actively harmful.
    try:
        keychain.delete_secret(KEYCHAIN_ACCOUNT)
    except keychain.KeychainError:
        pass
    raise NeedsLogin(
        "Stored sign-in is no longer valid (%s)."
        % (payload.get("error_description") or payload.get("error") or status)
    )


def _cached_token():
    """The in-memory access token, if it is still comfortably valid."""
    with _lock:
        token = _access_token
        expires_at = _access_expires_at
    if token and time.monotonic() < expires_at - EXPIRY_SKEW_SECONDS:
        return token
    return None


def cached_access_token():
    """The in-memory token if still valid, else None. Never refreshes, never
    raises — safe to call from paths that must not block, like the handshake."""
    return _cached_token()


def get_access_token():
    """Return a valid access token, refreshing if needed.

    Raises NeedsLogin if the user has to complete the device flow.
    """
    token = _cached_token()
    if token:
        return token

    # Serialize refreshes: concurrent ones would trip Auth0's reuse detection.
    with _refresh_lock:
        # Another thread may have refreshed while we waited for the lock, in
        # which case its result is already good and we must not refresh again.
        token = _cached_token()
        if token:
            return token
        return _refresh_from_stored()


# --------------------------------------------------------------------------
# Interactive login (shared between the explicit login tool and auto-reauth)
# --------------------------------------------------------------------------

_flow_lock = threading.Lock()
_pending_flow = None


def _open_browser(url):
    """Best-effort: pop the verification page in the user's default browser."""
    import subprocess
    commands = {
        "darwin": ["open", url],
        "linux": ["xdg-open", url],
        "win32": ["cmd", "/c", "start", "", url],
    }
    for prefix, cmd in commands.items():
        if sys.platform.startswith(prefix):
            try:
                subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except OSError:
                pass  # the user can still click the link in chat
            return


def _poll_flow_background(info):
    try:
        poll_for_token(info["device_code"], info["interval"], info["lifetime"])
        info["status"] = "ok"
    except AuthError as exc:
        info["status"] = "error"
        info["error"] = str(exc)


def begin_interactive_login(open_browser=True):
    """Start (or join) a device flow. Returns a dict with user_code, verify_url,
    and a live `status` field: pending | ok | error.

    Idempotent while a flow is pending, so concurrent queries that all hit
    expired auth share one code instead of racing to create three. Polling
    happens on a daemon thread; callers can return immediately and the tokens
    land in the keychain whenever the user approves.
    """
    global _pending_flow
    with _flow_lock:
        info = _pending_flow
        if not (info and info["status"] == "pending"
                and time.monotonic() < info["expires_at"]):
            flow = start_device_flow()  # raises AuthError on refusal
            info = {
                "device_code": flow["device_code"],
                "user_code": flow.get("user_code", ""),
                "verify_url": flow.get("verification_uri_complete")
                or flow.get("verification_uri", ""),
                "interval": flow.get("interval", 5),
                "lifetime": int(flow.get("expires_in", 900)),
                "expires_at": time.monotonic() + int(flow.get("expires_in", 900)),
                "status": "pending",
                "error": None,
            }
            _pending_flow = info
            threading.Thread(
                target=_poll_flow_background, args=(info,), daemon=True
            ).start()
    if open_browser:
        _open_browser(info["verify_url"])
    return info


def logout():
    global _access_token, _access_expires_at, _identity
    with _lock:
        _access_token = None
        _access_expires_at = 0.0
        _identity = None
    try:
        keychain.delete_secret(KEYCHAIN_ACCOUNT)
    except keychain.KeychainError:
        pass


def has_stored_credentials():
    try:
        return bool(keychain.get_secret(KEYCHAIN_ACCOUNT))
    except keychain.KeychainError:
        return False


def _claim_from_jwt(token, names):
    """First matching claim from an unverified JWT payload, or None.

    Display only. The token is validated by Gigasheet, not here, so nothing
    read out of it is used for an access decision.
    """
    if not token:
        return None
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None
    for name in names:
        if claims.get(name):
            return claims[name]
    return None


def describe_identity():
    """Who is signed in, for display. Falls back to the opaque subject."""
    return _identity or _claim_from_jwt(_access_token, ("email", "name", "sub"))


def token_permissions():
    """Permission claims on the current access token.

    Nothing gates on these today. When Gigasheet adds a role for MCP access,
    check it here so users get a named reason instead of a bare 403.
    """
    if not _access_token:
        return []
    return _claim_from_jwt(_access_token, ("permissions",)) or []
