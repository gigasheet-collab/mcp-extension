'use strict';

/**
 * Read an env var, treating unexpanded ${user_config.*} templates as unset.
 *
 * When an optional field is left blank, Claude Desktop can pass the manifest's
 * literal template string through instead of an empty value. Taking that at
 * face value once sent "${user_config.api_token}" upstream as an API token,
 * and the resulting 401 on initialize killed the whole connection.
 */
function cleanEnv(name, fallback = '') {
  const value = (process.env[name] || '').trim();
  if (!value || (value.startsWith('${') && value.endsWith('}'))) return fallback;
  return value;
}

function cleanNumberEnv(name, fallback) {
  const n = Number(cleanEnv(name, String(fallback)));
  return Number.isFinite(n) ? n : fallback;
}

/** Claude Desktop surfaces stderr in the extension logs. */
function log(message) {
  process.stderr.write(`[gigasheet] ${message}\n`);
}

module.exports = { cleanEnv, cleanNumberEnv, log };
