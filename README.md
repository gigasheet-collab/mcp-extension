# Gigasheet extension for Claude Desktop

Lets Claude query datasets you already have in Gigasheet — filtering, grouping,
and aggregating sheets far larger than Claude could read directly, and getting
back only the matching rows.

## Install

1. Download `gigasheet.mcpb`.
2. Double-click it, or drag it onto Claude Desktop.
3. Start a conversation and ask about one of your sheets. Claude will say
   sign-in is needed and give you a short code plus a link.
4. Open the link, approve the code, and sign in with your normal Gigasheet
   account — SSO, Google, or email.

No API keys to find or paste, and no terminal. You stay signed in across
restarts; the credential lives in your operating system's keychain.

Nothing else to install: the extension runs on the Node.js runtime that ships
inside Claude Desktop.

## Use

Give Claude a sheet URL and ask in plain language:

> Using [https://app.gigasheet.com/spreadsheet/claims/a1b2c3d4_5e6f_7890_abcd_ef1234567890](https://app.gigasheet.com/spreadsheet/Hospital-MRF--Limited-Preview-/84daf2fd_cfaa_4252_bc9e_3df4ea2b07a1?referrerId=https%3A%2F%2Fwww.gigasheet.com%2Fsample-data%2Fsample-machine-readable-file-mrf&_gl=1*vi48wb*_gcl_au*MTQ5NDk0MzI2Ni4xNzg3NTk0Nzg2LjEwNDQ2ODk2ODIuMTc4OTM5MjkzOS4xNzg5MzkyOTQ0LjEyMDM2MDY1ODkuMTc4OTM5MjkzOS4xNzg5MzkyOTQ0#a0cb25fd_9ce0_4463_8f20_d817781ae15f),
> how many CPT codes have a gross charge?

Claude pulls the `sheet_id` out of the URL and translates the question into the
query grammar.

## What it can and can't do

Reads and analyzes datasets you have access to in Gigasheet. It cannot create, upload, 
modify, or delete them, and it cannot join two sheets — combine those in Gigasheet first, then query the result.

Each call is independent: the sheet resets before every query, so there is no
incremental refinement. Claude issues one complete query per question.

## Permissions

You act as yourself. Queries carry your own Gigasheet identity, so you see
exactly the sheets you can see in the web app and nothing more. A sheet you
cannot open in Gigasheet will report its id as invalid here. Sharing a sheet URL
with a colleague does not grant them access — it has to be shared in Gigasheet.

To sign out, or to switch accounts, just ask Claude to sign out of Gigasheet.
That erases the stored credential from this computer. Revoking the session in
Auth0 also takes effect immediately.

## Privacy Policy

This extension runs entirely on your computer and connects only to Gigasheet's
own services (`api.gigasheet.com` for queries, `login.gigasheet.com` for
sign-in). It sends your queries and receives the matching rows; it does not
collect analytics, and it stores nothing on disk except the sign-in credential
held in your operating system's keychain. Query results are returned to Claude
and are subject to Anthropic's data handling for your Claude plan.

How Gigasheet handles your account and data is covered by the Gigasheet Privacy
Policy: https://www.gigasheet.com/privacy

Questions: support@gigasheet.com

## Troubleshooting

Extension logs are in Claude Desktop under **Settings > Extensions >
Gigasheet**; the bridge writes diagnostics there.

| Symptom | Cause |
|---|---|
| "Sign-in to Gigasheet is required" | Normal on first use, or after signing out. Ask Claude to sign in. |
| "Sign-in did not complete" | The code was not approved in time. Ask to sign in again. |
| "Invalid sheet_id parameter" | The id is wrong, or your account lacks access to that sheet. |
| "Could not reach Gigasheet" | Network or VPN blocking `api.gigasheet.com`. |
| Signed out on every restart | The system keychain is not reachable; check the logs. |
| "Gigasheet's network protection temporarily blocked this request" | Cloudflare bot mitigation in front of `api.gigasheet.com`. Not a sign-in problem; retry in a minute. |
| Passkey prompt fails during sign-in | The approval page opened inside an app window. Paste the URL into Chrome or Safari. |

## Configuration

Nothing is required. Three optional settings:

- **API token** — leave blank. Only for service accounts that have been issued a
  static token; it bypasses sign-in when set.
- **API endpoint** — only change for a dedicated or self-hosted instance.
- **Query timeout** — seconds to wait before giving up. Raise for very large sheets.

## Authentication

Sign-in uses the OAuth 2.0 Device Authorization Grant (RFC 8628) against
`login.gigasheet.com`, rather than the browser redirect flow the Gigasheet web
app uses. A desktop extension has no browser origin and no callback URL, and
device flow avoids opening a local HTTP listener to receive one.

The bundle embeds only an Auth0 **client ID**, which is public by design. No
client secret ships with the extension, and none is needed for this grant.

Access tokens are held in memory and refreshed silently. The refresh token goes
to the OS keychain — Keychain on macOS, libsecret on Linux, DPAPI on Windows. If
the keychain cannot be reached, the extension re-prompts for sign-in rather than
writing a long-lived credential to disk.

## Building from source

```bash
./build.sh
```

Produces `dist/gigasheet.mcpb`. The server is Node standard library only, so
there are no dependencies to vendor. `build.sh` uses `mcpb pack` when the CLI
is installed (`npm i -g @anthropic-ai/mcpb`) and falls back to a plain zip.

`python-reference/` holds the original Python implementation of the same
bridge. It is not part of the bundle; it is kept as a second reading of the
protocol behaviour.

## How it works

`server/index.js` bridges MCP over stdio to Gigasheet's remote MCP endpoint
over HTTPS. The remote is stateless — plain JSON, no SSE, no session id — so
the bridge is request/response. It exists rather than piping raw bytes because:

- Auth failures return a non-JSON-RPC body (`{"Success":false,...}`) with HTTP
  401. Forwarded verbatim, that lands in the protocol stream without an `id` and
  wedges the client. The bridge converts it to a real JSON-RPC error.
- A **missing** credential is not rejected by the remote. Requests proceed
  unauthenticated and fail downstream as "Invalid sheet_id parameter" for every
  sheet, which reads as a bad id rather than an auth problem. The bridge starts
  a sign-in instead and says so.
- Cloudflare bot mitigation in front of the API returns 403 pages that look
  like auth failures. The bridge tells them apart and never asks the user to
  re-authenticate for a network block.
- Notifications must not be answered. The bridge suppresses replies to messages
  with no `id`.
- Requests are handled concurrently, so a slow query doesn't block the session.
- The upstream `Analyze` description omits the instruction grammar entirely. The
  bridge substitutes full documentation so the model doesn't guess at syntax.
