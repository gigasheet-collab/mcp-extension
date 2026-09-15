'use strict';

/**
 * Cross-platform secret storage backed by the OS keychain.
 *
 * Refresh tokens are long-lived credentials and must not sit in a plaintext
 * file. Each platform gets its native store; if none is reachable we throw
 * rather than silently degrading to disk. Node standard library only.
 *
 * Caveat on macOS: the `security` CLI takes the secret as an argument, so it
 * is briefly visible in `ps` output on a multi-user machine. The Linux and
 * Windows backends both pass secrets over stdin and do not have this exposure.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const { cleanEnv } = require('./env');

/**
 * Resolve a helper binary to an absolute path when we know where it lives.
 * Claude Desktop's Code/Cowork session hosts run this bridge with a stripped
 * environment in which PATH is missing, so a bare `spawn('security')` fails
 * with ENOENT there — every keychain read then looks like "no credentials"
 * and every start triggers a fresh sign-in.
 */
function resolveBinary(name) {
  const known = {
    security: ['/usr/bin/security'],
    osascript: ['/usr/bin/osascript'],
    open: ['/usr/bin/open'],
    'secret-tool': ['/usr/bin/secret-tool', '/usr/local/bin/secret-tool'],
    powershell: [
      `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`,
    ],
  };
  for (const candidate of known[name] || []) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch (_) { /* try the next */ }
  }
  return name; // fall back to PATH lookup
}

// Overridable so tests can use a throwaway service instead of the real one.
const SERVICE = cleanEnv('GIGASHEET_KEYCHAIN_SERVICE', 'com.gigasheet.claude-extension');

class KeychainError extends Error {}

function run(cmd, args, { stdin = null, check = true, timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };

    let child;
    try {
      child = spawn(resolveBinary(cmd), args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    } catch (err) {
      reject(new KeychainError(`${cmd} could not be started: ${err.message}`));
      return;
    }

    const timer = setTimeout(() => {
      child.kill();
      finish(reject, new KeychainError(`${cmd} timed out`));
    }, timeoutMs);

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => {
      finish(reject, new KeychainError(
        err.code === 'ENOENT' ? `${cmd} is not installed` : `${cmd} failed: ${err.message}`
      ));
    });
    child.on('close', (code) => {
      if (check && code !== 0) {
        finish(reject, new KeychainError(
          `${cmd} failed (exit ${code}): ${stderr.trim().slice(0, 200)}`
        ));
      } else {
        finish(resolve, { code, stdout, stderr });
      }
    });

    child.stdin.on('error', () => {});
    child.stdin.end(stdin === null ? undefined : stdin);
  });
}

// --------------------------------------------------------------------------
// macOS
// --------------------------------------------------------------------------

const darwin = {
  async set(account, secret) {
    await run('security', [
      'add-generic-password',
      '-U', // update if it already exists
      '-a', account,
      '-s', SERVICE,
      '-w', secret,
    ]);
  },
  async get(account) {
    const r = await run('security', [
      'find-generic-password', '-a', account, '-s', SERVICE, '-w',
    ], { check: false });
    if (r.code !== 0) return null; // not found is the common case, not an error
    return r.stdout.trim() || null;
  },
  async del(account) {
    await run('security', [
      'delete-generic-password', '-a', account, '-s', SERVICE,
    ], { check: false });
  },
};

// --------------------------------------------------------------------------
// Linux (libsecret)
// --------------------------------------------------------------------------

const linux = {
  async set(account, secret) {
    await run('secret-tool', [
      'store', '--label=Gigasheet Claude extension',
      'service', SERVICE, 'account', account,
    ], { stdin: secret });
  },
  async get(account) {
    const r = await run('secret-tool', [
      'lookup', 'service', SERVICE, 'account', account,
    ], { check: false });
    if (r.code !== 0) return null;
    return r.stdout.trim() || null;
  },
  async del(account) {
    await run('secret-tool', [
      'clear', 'service', SERVICE, 'account', account,
    ], { check: false });
  },
};

// --------------------------------------------------------------------------
// Windows (DPAPI via PowerShell, scoped to the current user)
// --------------------------------------------------------------------------

const PS_STORE = (account) => `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$secret = [Console]::In.ReadToEnd()
$bytes = [Text.Encoding]::UTF8.GetBytes($secret)
$enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')
$dir = Join-Path $env:LOCALAPPDATA 'Gigasheet'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
[IO.File]::WriteAllBytes((Join-Path $dir '${account}.bin'), $enc)
`;

const PS_LOAD = (account) => `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$path = Join-Path $env:LOCALAPPDATA 'Gigasheet\\${account}.bin'
if (-not (Test-Path $path)) { exit 1 }
$enc = [IO.File]::ReadAllBytes($path)
$bytes = [Security.Cryptography.ProtectedData]::Unprotect($enc, $null, 'CurrentUser')
[Console]::Out.Write([Text.Encoding]::UTF8.GetString($bytes))
`;

const PS_DELETE = (account) => `
$path = Join-Path $env:LOCALAPPDATA 'Gigasheet\\${account}.bin'
if (Test-Path $path) { Remove-Item $path -Force }
`;

function ps(script, opts = {}) {
  return run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], opts);
}

const win32 = {
  async set(account, secret) { await ps(PS_STORE(account), { stdin: secret }); },
  async get(account) {
    const r = await ps(PS_LOAD(account), { check: false });
    if (r.code !== 0) return null;
    return r.stdout.trim() || null;
  },
  async del(account) { await ps(PS_DELETE(account), { check: false }); },
};

// --------------------------------------------------------------------------
// Dispatch
// --------------------------------------------------------------------------

function backend() {
  switch (process.platform) {
    case 'darwin': return darwin;
    case 'linux': return linux;
    case 'win32': return win32;
    default: throw new KeychainError(`no keychain backend for platform ${process.platform}`);
  }
}

// Account names are fixed strings we control, never user input; they end up
// inside shell-free spawn args (and, on Windows, a file name), so keep them
// to a conservative character set anyway.
function checkAccount(account) {
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(account)) {
    throw new KeychainError(`invalid account name ${JSON.stringify(account)}`);
  }
}

async function setSecret(account, secret) {
  checkAccount(account);
  await backend().set(account, secret);
}

/** Resolves to the stored secret, or null if absent. */
async function getSecret(account) {
  checkAccount(account);
  return backend().get(account);
}

async function deleteSecret(account) {
  checkAccount(account);
  await backend().del(account);
}

/**
 * Check that this platform's keychain is usable right now. Resolves to null
 * when it is, or a short reason string when it is not.
 */
async function unavailableReason() {
  try {
    backend();
  } catch (err) {
    return err.message;
  }
  // Per-process name: Desktop launches two instances a second apart, and a
  // shared probe item let one delete the other's mid-check.
  const probe = `availability_probe_${process.pid}`;
  try {
    await setSecret(probe, 'ok');
    const ok = (await getSecret(probe)) === 'ok';
    await deleteSecret(probe);
    return ok ? null : 'probe value did not round-trip';
  } catch (err) {
    return err.message;
  }
}

/** True if this platform's keychain is usable right now. */
async function available() {
  return (await unavailableReason()) === null;
}

module.exports = {
  setSecret, getSecret, deleteSecret, available, unavailableReason, resolveBinary, KeychainError, SERVICE,
};
