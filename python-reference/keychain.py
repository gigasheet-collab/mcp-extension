"""Cross-platform secret storage backed by the OS keychain.

Refresh tokens are long-lived credentials and must not sit in a plaintext file.
Each platform gets its native store; if none is reachable we raise rather than
silently degrading to disk. Standard library only.

Caveat on macOS: the `security` CLI takes the secret as an argument, so it is
briefly visible in `ps` output on a multi-user machine. The Linux and Windows
backends both pass secrets over stdin and do not have this exposure. Replacing
the macOS path with a ctypes call into Security.framework would close it.
"""

import subprocess
import sys

SERVICE = "com.gigasheet.claude-extension"


class KeychainError(Exception):
    """The platform keychain could not be reached or refused the operation."""


def _run(cmd, stdin_data=None, check=True):
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        raise KeychainError("%s is not installed" % cmd[0])
    except subprocess.TimeoutExpired:
        raise KeychainError("%s timed out" % cmd[0])

    if check and proc.returncode != 0:
        raise KeychainError(
            "%s failed (exit %d): %s"
            % (cmd[0], proc.returncode, proc.stderr.strip()[:200])
        )
    return proc


# --------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------

def _darwin_set(account, secret):
    _run([
        "security", "add-generic-password",
        "-U",                # update if it already exists
        "-a", account,
        "-s", SERVICE,
        "-w", secret,
    ])


def _darwin_get(account):
    proc = _run([
        "security", "find-generic-password",
        "-a", account, "-s", SERVICE, "-w",
    ], check=False)
    if proc.returncode != 0:
        return None  # not found is the common case, not an error
    return proc.stdout.strip() or None


def _darwin_delete(account):
    _run([
        "security", "delete-generic-password",
        "-a", account, "-s", SERVICE,
    ], check=False)


# --------------------------------------------------------------------------
# Linux (libsecret)
# --------------------------------------------------------------------------

def _linux_set(account, secret):
    _run([
        "secret-tool", "store",
        "--label=Gigasheet Claude extension",
        "service", SERVICE, "account", account,
    ], stdin_data=secret)


def _linux_get(account):
    proc = _run([
        "secret-tool", "lookup", "service", SERVICE, "account", account,
    ], check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _linux_delete(account):
    _run([
        "secret-tool", "clear", "service", SERVICE, "account", account,
    ], check=False)


# --------------------------------------------------------------------------
# Windows (DPAPI via PowerShell, scoped to the current user)
# --------------------------------------------------------------------------

_PS_STORE = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$secret = [Console]::In.ReadToEnd()
$bytes = [Text.Encoding]::UTF8.GetBytes($secret)
$enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')
$dir = Join-Path $env:LOCALAPPDATA 'Gigasheet'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
[IO.File]::WriteAllBytes((Join-Path $dir '%s.bin'), $enc)
"""

_PS_LOAD = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$path = Join-Path $env:LOCALAPPDATA 'Gigasheet\%s.bin'
if (-not (Test-Path $path)) { exit 1 }
$enc = [IO.File]::ReadAllBytes($path)
$bytes = [Security.Cryptography.ProtectedData]::Unprotect($enc, $null, 'CurrentUser')
[Console]::Out.Write([Text.Encoding]::UTF8.GetString($bytes))
"""

_PS_DELETE = r"""
$path = Join-Path $env:LOCALAPPDATA 'Gigasheet\%s.bin'
if (Test-Path $path) { Remove-Item $path -Force }
"""


def _ps(script, stdin_data=None, check=True):
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        stdin_data=stdin_data,
        check=check,
    )


def _windows_set(account, secret):
    _ps(_PS_STORE % account, stdin_data=secret)


def _windows_get(account):
    proc = _ps(_PS_LOAD % account, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _windows_delete(account):
    _ps(_PS_DELETE % account, check=False)


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

_BACKENDS = {
    "darwin": (_darwin_set, _darwin_get, _darwin_delete),
    "linux": (_linux_set, _linux_get, _linux_delete),
    "win32": (_windows_set, _windows_get, _windows_delete),
}


def _backend():
    for prefix, funcs in _BACKENDS.items():
        if sys.platform.startswith(prefix):
            return funcs
    raise KeychainError("no keychain backend for platform %r" % sys.platform)


def set_secret(account, secret):
    _backend()[0](account, secret)


def get_secret(account):
    """Returns the stored secret, or None if absent."""
    return _backend()[1](account)


def delete_secret(account):
    _backend()[2](account)


def available():
    """True if this platform's keychain is usable right now."""
    try:
        _backend()
    except KeychainError:
        return False
    probe = "__availability_probe__"
    try:
        set_secret(probe, "ok")
        result = get_secret(probe) == "ok"
        delete_secret(probe)
        return result
    except KeychainError:
        return False
