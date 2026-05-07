# Postroom — Implementation State

**Last updated:** batch 4 complete (PR client)
**Conversation context:** Design and partial build by an earlier Claude (foundation libraries). Implementation continued by Claude Code.

## 1. Quick status

| Phase | Status |
|---|---|
| Design specification | ✅ Complete (`DESIGN.md`) |
| Foundation libraries | ✅ Complete and tested (133/133 tests passing) |
| `NNA_REG` registry server | ✅ Complete and tested (67/67 tests passing) |
| `NMAIL_SRV` / `COMMON_SRV` mail servers | ✅ Complete and tested (60/60 tests passing) |
| `PR` mail client | ✅ Complete (6/6 smoke tests passing) |
| Generic domain server + installer floppy | ⏳ Not started |
| `NNA_STAFF` terminal | ⏳ Not started |
| Final installer scripts (6 pastebins) | ⏳ Not started |
| Visual / graphics-mode UI layer | ⏳ Explicitly deferred to a separate phase after the system works in text mode |

## 2. What exists right now

These files are complete, tested, and should not need changes during the next phases. They live in `src/lib/`:

### `src/lib/crypto.lua` (522 lines)

Cryptographic primitives used by every other component.

**Public API:**

```lua
local crypto = require("crypto")

-- Hashing
crypto.sha256(msg) -> binary string (32 bytes)
crypto.sha256hex(msg) -> hex string (64 chars)

-- HMAC
crypto.hmac_sha256(key, msg) -> binary string
crypto.hmac_sha256_hex(key, msg) -> hex string

-- AES-128-CBC (raw)
crypto.aes128_cbc_encrypt(plaintext, key16, iv16) -> binary
crypto.aes128_cbc_decrypt(ciphertext, key16, iv16) -> binary, err

-- High-level encrypt/decrypt with key derivation
crypto.encrypt(plaintext, secret, context) -> hex ciphertext
crypto.decrypt(hexCiphertext, secret, context) -> plaintext, err
crypto.deriveKey(secret, context) -> 16 bytes
crypto.deriveIV(secret, context) -> 16 bytes

-- Hex helpers
crypto.toHex(bin) -> hex
crypto.fromHex(hex) -> bin

-- Random
crypto.randomBytes(n) -> binary
crypto.randomHex(n) -> hex (2n chars)
crypto.randomToken(length) -> friendly alphabet token (no ambiguous chars)
crypto.formatToken(t) -> "XXXX-XXXX-XXXX-XXXX" (only for length-16 tokens)
crypto.unformatToken(t) -> strips dashes

-- Password hashing (case-insensitive on domain/username)
crypto.hashPassword(domain, username, password) -> hex (64 chars)
```

**Validation:** `tests/crypto_test.lua` — 31 tests, all passing. Includes:
- FIPS 180-4 SHA-256 known-answer vectors (empty, "abc", 56-char, 1M "a")
- RFC 4231 HMAC-SHA256 test cases 1, 2, 3
- FIPS 197 AES-128 reference vector (Appendix C.1)
- CBC roundtrip with edge cases (empty, exactly-block-size, 17 bytes, NUL bytes, long messages)
- High-level encrypt/decrypt with derived keys and contexts
- Password hashing case-insensitivity and domain-isolation

**Notes for the maintainer:**
- Bit operations: prefers `bit32` (CC default), falls back to native bitops via `load()` for Lua 5.3+. Should not need changes.
- `os.epoch("utc")` is preferred for randomness seeding; falls back to `os.time()` outside CC.
- AES-128-CBC is slow (~0.5s for ~2KB on a CC computer). Acceptable for mail volumes; a concern only if you start encrypting bulk data.

### `src/lib/wire.lua` (295 lines)

Network message format. Canonical serialization, signing/verification, request/response builders, nonce-based replay protection.

**Public API:**

```lua
local wire = require("wire")

wire.PROTOCOL = "POSTROOM_NET"  -- the rednet protocol name

-- Canonical serialization (deterministic regardless of insertion order)
wire.canonical(value) -> string

-- Signing
wire.sign(message, secret) -> hex sig
wire.verify(message, secret) -> true | false

-- Build messages
wire.buildRequest(station, proto, action, payload, secret, opts) -> table
wire.buildResponse(station, request, ok, dataOrError, secret, opts) -> table

-- Validation
wire.validateRequest(msg) -> true | false, err
wire.validateResponse(msg) -> true | false, err

-- Nonce store (replay protection)
wire.newNonceStore(maxEntries) -> store
wire.checkNonce(store, station, nonce) -> true | false (false = replay)

-- Send a request and wait for response (CC only)
wire.sendRequest(hostId, station, proto, action, payload, secret, timeout, opts)
  -> data, err, response

-- Modem helper
wire.openModem(preferredSide) -> ok, side
```

**Sub-protocols** (the `proto` field on messages):
- `POSTROOM/REG` — server-to-registry, server-to-server federation
- `POSTROOM/USR` — client-to-server (user actions)

**Encrypted bodies:** Pass `opts = { body = "...", encrypted_body = true, body_context = "ctx" }` to `buildRequest`/`buildResponse` to AES-encrypt the body field. The receiver decrypts with `crypto.decrypt(msg.body, secret, ctx)`.

**Validation:** `tests/wire_test.lua` — 50 tests, all passing.

**Notes for the maintainer:**
- Canonical sort: numeric keys first (sorted), then string keys (alphabetical). Same data produces same canonical string.
- Nonces are unique per `(station, nonce)` pair — same nonce string across different stations is allowed. Store auto-prunes when over `maxEntries`.
- The signature covers everything except the `sig` field itself.

### `src/lib/common.lua` (391 lines)

Shared constants, validators, address parsing, persistence, UI helpers.

**Public API:**

```lua
local C = require("common")

-- Constants
C.RESERVED_DOMAIN_NAMES   -- list
C.RESERVED_LOCAL_PARTS    -- list
C.MAX_USERNAME_LEN, C.MIN_USERNAME_LEN
C.MAX_DOMAIN_LEN, C.MIN_DOMAIN_LEN
C.MAX_PASSWORD_LEN, C.MIN_PASSWORD_LEN
C.MAX_SUBJECT_LEN  -- 100
C.MAX_BODY_LEN     -- 2500
C.FEES = { application=8, registration=48, renewal=12, transfer=8, nna_share=3 }
C.LIFECYCLE = { domain_validity_days, install_token_days, ... }

-- String helpers
C.trim(s), C.lower(s), C.upper(s), C.pad(s, w), C.rpad(s, w), C.truncate(s, n)
C.splitCsv(s) -> { ... }

-- Address parsing
C.parseAddress("alice@nmail") -> "alice", "nmail" (lowercased) or nil, err
C.buildAddress(user, domain) -> "alice@nmail"

-- Validators
C.isReservedDomain(name), C.isReservedLocalPart(name)
C.validateDomainName(name, allowReserved?) -> ok, err
C.validateUsername(name, allowReserved?) -> ok, err
C.validatePassword(pw) -> ok, err
C.validateSubject(s), C.validateBody(s)

-- Persistence (atomic via tmp + fs.move)
C.saveTable(path, tbl) -> ok, err
C.loadTable(path) -> tbl, err

-- Time
C.currentDay() -> os.day() or 0
C.now() -> ms epoch
C.nowSec() -> sec epoch

-- IDs
C.nextId(state, counterKey, prefix, width?) -> e.g. "MSG-0001"

-- Logs
C.appendLog(list, entry, maxEntries)  -- in-place, O(n) trim

-- Money formatting
C.formatMoney(n) -> "12f"

-- UI helpers (text mode)
C.clear(), C.setColor(c), C.resetColor(), C.printColored(c, s), C.printHeader(t)
C.pause(prompt?), C.ask(prompt, hidden?), C.askNonEmpty(prompt, hidden?)
C.askNumber(prompt, default?), C.askYN(prompt, default), C.confirmDanger(prompt)
C.selectFromList(items, labelFn, title, allowBack) -> item, idx
```

**Validation:** `tests/common_test.lua` — 52 tests, all passing.

**Notes for the maintainer:**
- The `allowReserved` flag on validators exists so that system-account creation (`op`, `pm`, `abuse`, `noreply`) bypasses the reserved-name check. User-facing flows always pass `allowReserved=false` (or omit the arg).
- `saveTable` and `loadTable` only work in CC (require `fs` and `textutils`). They use atomic `tmp + fs.move` semantics.

## 3. What's pending

Six remaining batches, in this order:

### ~~Batch 2: `src/nna_reg.lua` — Registry server~~ ✅ Done

`src/nna_reg.lua` (921 lines) + `tests/nna_reg_test.lua` (67 tests).

**Implemented actions:**
- Server-bound: `heartbeat`, `route_mail`, `consume_install_token`, `update_branding`
- Server-issued (called from registry to domain servers): `deliver_mail` (via `notifyServer`), `notify_revoked`, `notify_renewal`, `notify_suspended`
- Staff-bound: `staff_login`, `staff_logout`, `register_domain`, `renew_domain`, `transfer_domain`, `revoke_domain`, `list_domains`, `list_pending_apps`, `audit_query`
- Public (unsigned): `domain_status`, `list_public_domains`

**State persisted at `/postroom/state.txt`** with the shape from `DESIGN.md` § 4.1.

**Module shape:** the file is a Lua module returning `M`. `M.dispatch(req)` is the test-friendly entry point — it validates, verifies HMAC, checks the nonce store, and routes to a handler. `M.run()` is the rednet main loop. The bottom of the file calls `M.run()` automatically unless `_G._POSTROOM_NO_AUTORUN = true` is set first (used by tests).

**Routing/encryption decision (resolves design ambiguity):** for cross-domain mail the registry **decrypts the body with the sender's domain secret and re-encrypts with the destination's secret** before calling `deliver_mail`. This matches `DESIGN.md` § 5.5's per-message-id key derivation. The registry seeing bodies in transit is an accepted limitation per § 5.9. Earlier `STATE.md` text saying "the registry never decrypts" was incorrect — that wording would only be true with per-pair derived keys, which were explicitly deferred.

**Auth model details:**
- Domain server → registry: HMAC keyed on the domain's `shared_secret`. Sender station name (`<UPPERDOMAIN>_SRV`) selects the secret.
- Staff terminal → registry: HMAC keyed on a single staff-terminal secret stored at `/postroom/staff_secret` (auto-generated on first boot, printed once). Plus a `session_token` in the payload identifies which staff member is logged in.
- `consume_install_token`: special — the install token *itself* is the HMAC key for that one bootstrap call, since the new computer has no shared secret yet. Once consumed, the token route is disabled (status flips to CONSUMED).
- Public actions (`domain_status`, `list_public_domains`): unsigned. Responses are signed with the sentinel string `"PUBLIC"`; clients should not verify these.

**Daily tick:** runs `M.dailyTick()` on boot and then every 30 s of wall time (`M.MAIN_TICK_INTERVAL`). Idempotent on `state.last_tick_day`. Handles renewal warnings at -4/-2/0 days, ACTIVE→SUSPENDED at +grace, SUSPENDED→REVOKED at +30 days, install-token expiry, and revoked-domain purge after 60 days.

**Bootstrap admin:** on first boot the registry creates a default `admin / changeme` staff account (logged in audit). Change immediately.

### ~~Batch 3: mail server core + public wrappers~~ ✅ Done

`src/lib/mail_server.lua` (1090 lines) is the shared core. `src/nmail_srv.lua` and `src/common_srv.lua` are thin wrappers (~20 lines each) that call `mail_server.run({ ... })` with their domain config. The same core is what batch 5's private domain server will use with `is_public_server = false`.

**Implemented actions:**
- USR (client-facing): `register`, `login`, `logout`, `change_password`, `account_info`, `list_inbox`, `read_message`, `mark_read`, `delete_message`, `send`, `search`, `list_local_users`
- USR (op-only): `admin_create_user`, `admin_delete_user`, `admin_reset_password`, `admin_view_user_inbox`, `admin_view_message`, `admin_set_branding`, `admin_domain_stats`
- REG (server-bound, sent from registry): `deliver_mail`, `notify_revoked`, `notify_renewal`, `notify_suspended`, `admin_op_reset` (transfer)
- Heartbeat sent every 60 s; trash auto-purge every day at first tick

**Auth model (POSTROOM/USR):**
- `register` and `login` are unsigned (no session yet). Server validates the payload; on success, response is signed with the new session token so the client can verify.
- All other USR actions: HMAC keyed on the **session token**. Client and server both hold the token; replay-protected via the nonce store.

**Auth model (POSTROOM/REG):**
- All inbound from registry is signed with this server's `shared_secret`, station must equal `registry_station` (default `NNA_REG`).
- Outbound (heartbeat, route_mail, update_branding) is signed with the same secret.

**Body encryption on routing:** sender mail server AES-encrypts the body with `crypto.encrypt(body, shared_secret, "mail:<msg_id>")` and passes it to the registry's `route_mail`. The registry decrypts with the sender's secret and re-encrypts with the destination's secret before calling `deliver_mail`. The destination decrypts with its own secret using the same `mail:<msg_id>` context. Plaintext bodies are stored at rest on each mail server (no benefit to encrypting at rest within the same machine).

**Sessions:** 7-day TTL refreshed on every authenticated request. Max 3 concurrent sessions per user; oldest evicted on a 4th login. `admin_reset_password` and `admin_op_reset` invalidate the target's sessions.

**Bouncing:** any per-recipient outcome that isn't `DELIVERED` or `LOCAL` produces a system message from `pm@<this_domain>` in the original sender's inbox (if the sender is local). Bounces never bounce.

**System accounts** (op, pm, abuse, noreply) are seeded on first boot via `ensureSystemAccounts()`. The op account's password is set during install (batch 5) — for the public servers, the operator sets it manually in the registry's bootstrap flow (TBD in batch 6 staff terminal, or via a CLI helper before then).

### ~~Batch 4: PR client~~ ✅ Done

`src/pr_client.lua` (718 lines), text-mode only per §11 (graphics deferred to phase 8).

**Flow:** boot → login (sign in / create account / quit) → inbox loop. Inbox screen has key-driven menu: digit reads message N, `c` compose, `r` refresh, `i/s/t` switch folders (inbox/sent/trash), `/` search, `a` admin overlay (op only), `l` logout, `q` quit. Read view supports `r` reply (with quoted original), `d` delete, `q` back. Compose accepts comma-separated `to:`, subject, multi-line body terminated by a single `.` on its own line.

**Op admin overlay:** create/delete/reset users, view a user's inbox, update branding, see domain stats. Visible only when `account_info` returns `is_op=true`.

**Persistence:** `/postroom/client.txt` holds `session` and `remembered_servers` only (cache stays in memory, per §4.4). Login auto-suggests up to 5 remembered addresses.

**Auth on the wire:**
- `domain_status`, `list_public_domains`: signed with `"PUBLIC"`
- `register`, `login`: payload-only — server signs response with `"PUBLIC"` (per the dispatch refinement in this batch); client passes `"PUBLIC"` to `wire.sendRequest` so it can verify
- All other USR actions: HMAC keyed on `session_token`

**No background polling in v1.** The user presses `r` to refresh. Adding a parallel timer + read loop is straightforward later but adds enough complexity (CC's `parallel.waitForAny` on `read()` is awkward) that I've left it out for now. Easy to revisit when we polish the UI in phase 8.

**Tests:** `tests/pr_client_test.lua` is a smoke test only. The client is interactive UI; meaningful tests need to drive it end-to-end against running registry + mail servers in CraftOS-PC.

### Batch 5: `src/domain_srv.lua` and `src/install_disk.lua` (~400 lines)

The generic private domain server (e.g. `@sundown`). Mostly the same code as the public mail servers but with `is_public_server = false`, plus initial bootstrapping from an install floppy.

`install_disk.lua` is the script that runs on a fresh computer when the install floppy is inserted. It reads the install token, calls `consume_install_token` on the registry, sets up the local files, and bootstraps the server.

### Batch 6: `src/nna_staff.lua` — Staff terminal (~500 lines)

The clerk's workstation at the N.N.A. office. Staff login, main menu, all counter operations: new registration, renewal, transfer, revocation, domain lookup, audit query. Writes install floppies. Prints certificates and receipts.

**Office-closed screen** when no staff is logged in.

### Final: 6 installer scripts (~80 lines each)

After the system works end-to-end, produce six dedicated installer pastes (one per role). Each fetches its files from the GitHub raw URL hardcoded in the script. Plus an `update` command for in-place updates.

The user uploads each installer once to pastebin; from then on, deploying a new computer is a single `pastebin get <id> install && install` command.

## 4. Conventions and decisions

These were settled during design and should not be re-litigated:

### Architectural
- **Centralized registry, distributed delivery.** Mail bodies live on destination servers, not the registry.
- **Bounce immediately on offline destination.** No retry queue. Sender gets a bounce in real-time.
- **Domain owners can read user mail.** Disclosed at signup. Users wanting privacy use `@nmail`/`@common`.
- **Single staff terminal in the office** (no separate public kiosk).
- **Single concurrent staff session** at any time.

### Cryptographic
- HMAC-SHA256 for authentication, AES-128-CBC for body encryption. Pure Lua.
- Shared secret per domain server, issued at install. Stored in `/postroom/secret` (file, not in source code).
- Session tokens are 32-byte hex, derived from password hash, expire after 7 days inactivity.
- Replay protection via nonce store (5-min window, 250-entry cap with prune-to-half).

### Pricing (in fluorin, displayed as `f`)
- Application: 8ƒ + 3ƒ N.N.A. share = **11ƒ**
- Registration: 48ƒ + 3ƒ = **51ƒ** (covers first 2 seasons)
- Renewal: 12ƒ + 3ƒ = **15ƒ** (every 2 seasons / 48 days)
- Transfer: 8ƒ + 3ƒ = **11ƒ**
- New domain total at counter: **62ƒ**

### Lifecycle
- Domain valid for 48 days at a time
- Renewal warnings at 4, 2, 0 days before expiry
- Grace period: 4 days after expiry (still active, daily warnings)
- Suspension: days 4–29 after expiry (mail bounces)
- Revocation: day 30 after expiry (server shut down, name held 30 days before pool release)
- Install token valid for 7 days

### Limits
- No per-mailbox cap
- Subject 100 chars, body 2500 chars
- Unlimited recipients per send
- Audit log: 1000 (registry), 500 (mail server)
- Trash retention: 14 days

### Issued domains at v1 launch
`gov`, `nna`, `nta`, `nga`, `nmail`, `common`. (`@wbia` for the airport project will be added later, separate project.)

### What's intentionally not in v1
- Drafts, threading, reply-all, read receipts, address book, display names
- Pocket clients
- Attachments
- Domain deputies (multiple admins per domain)
- Auto-responders
- Graphics-mode UI (deferred to its own phase after text-mode system works)

## 5. Workflow assumptions for the next phase

The previous Claude was working in CC: Tweaked targeting CraftOS-PC for fast iteration. The user has:
- CraftOS-PC installed and working
- All hardware acquired in-game (computers, modems, printers, disk drives, floppies)
- HTTP API enabled on their server
- The N.N.A. office and other physical buildings already constructed

The user's preferred build approach:
- **Build the entire system in one extended session, then hand off.**
- Test each batch in CraftOS-PC before moving to the next.
- Final hosting: GitHub repo + 6 pastebin installers (one per role).

## 6. Known issues, considerations, and open questions

### Crypto performance
AES-128-CBC in pure Lua takes ~0.5s for a 2KB body on a typical CC computer. Acceptable for mail (a user sends one message at a time). Becomes a concern only if traffic is bursty. Profile before optimizing.

### Heartbeat at scale
With many domains, the registry receives a heartbeat every 60s × N domains. At 50 domains that's roughly 1 heartbeat/sec. Should be fine. Monitor if it becomes an issue.

### Body encryption: pair keys vs single secret
Currently the design uses *the destination's shared secret* for body encryption when routing through the registry. This means the registry could decrypt bodies if it wanted to. An alternative is per-pair derived keys (sender + recipient domain) negotiated separately, which would prevent the registry from reading bodies. This is more complex and was deferred. Per `DESIGN.md` § 5.9, this is an accepted limitation.

### `pr` shortcut command
The client installer writes `/pr.lua` which `shell.run`s the actual client. Make sure this is on the shell path or document `pr` as the launch command.

### Forgot password
Not implemented in v1. `op@<domain>` password recovery requires N.N.A. office visit. Regular users on private domains contact their domain owner. Public-domain users (`@nmail`, `@common`) lose their account if they lose the password. Document this clearly in user-facing copy.

### CraftOS-PC vs in-game testing
Tests in `tests/` are written for standard Lua 5.3+. They use `require()` which CC handles differently. To run in CraftOS-PC, use its standard Lua mode, OR add CC-flavored test runners that use `dofile("/postroom/lib/crypto.lua")` and assign to globals.

## 7. Repo setup checklist

When the maintainer takes over:

1. Initialize git repo from the files provided
2. Push to GitHub (public if you want pastebin installers to work via raw URLs)
3. Verify `crypto_test.lua`, `wire_test.lua`, `common_test.lua` all pass under standalone Lua 5.3
4. Drop libraries into a CraftOS-PC computer to confirm they run there too
5. Begin batch 2: `src/nna_reg.lua`

## 8. Style guide for new code

To match existing libraries:

- Plain procedural Lua. No classes, no metatables for inheritance.
- One `M = {}` table per module, return at end.
- `local function` for internal helpers, `M.functionName` for public API.
- Error returns: `nil, "ERROR_CODE"` for recoverable; `error("...")` only for programmer errors.
- All cross-computer messages signed via `wire.sign`. No exceptions.
- Persistent state: load on boot, save after every mutation, atomic via `C.saveTable`.
- Use `C.appendLog` for any bounded log structure (don't reinvent rotation).
- UI: text-mode only. Use `C.clear`, `C.printHeader`, `C.askYN`, `C.selectFromList` etc. consistently.
- Comments: explain *why*, not *what*.

## 9. Test expectations

When new modules are written, they should ship with tests in `tests/`. Recommended pattern:

```lua
package.path = package.path .. ";./src/?.lua;./src/lib/?.lua"
local M = require("the_module")

local total, failed = 0, 0
local function check(name, expected, actual)
  total = total + 1
  if expected == actual then print("[PASS] " .. name)
  else failed = failed + 1; print("[FAIL] " .. name) end
end

-- ... tests ...

print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
```

Network-dependent tests can use mock rednet by stubbing `rednet.send` and feeding `os.pullEvent` results.

---

**The previous Claude is now exiting the conversation. The next maintainer (Claude Code or other) takes over from here using `HANDOFF_PROMPT.md` as their starting context.**
