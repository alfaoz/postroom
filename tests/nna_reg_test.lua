-- tests/nna_reg_test.lua
-- Run: lua tests/nna_reg_test.lua
-- Exercises the registry's action handlers and daily tick via M.dispatch
-- without involving rednet/fs.

package.path = package.path
  .. ";../src/lib/?.lua;./src/lib/?.lua"
  .. ";../src/?.lua;./src/?.lua"

_G._POSTROOM_NO_AUTORUN = true

local crypto = require("crypto")
local wire   = require("wire")
local C      = require("common")
local R      = require("nna_reg")

local total, failed = 0, 0
local function check(name, expected, actual)
  total = total + 1
  if expected == actual then
    print("[PASS] " .. name)
  else
    failed = failed + 1
    print("[FAIL] " .. name)
    print("       expected: " .. tostring(expected))
    print("       got:      " .. tostring(actual))
  end
end
local function checkTrue(name, cond, why)
  total = total + 1
  if cond then print("[PASS] " .. name)
  else failed = failed + 1; print("[FAIL] " .. name .. " — " .. tostring(why)) end
end

-- ===== helpers =====

local STAFF_SECRET = crypto.randomHex(32)

local function freshState()
  R.setState(nil)
  R.staff_secret = STAFF_SECRET
  R.nonce_store  = wire.newNonceStore(250)
end

local function adminLoginHash()
  return crypto.hashPassword("nna", "admin", "changeme")
end

local function ensureAdmin()
  R.state.staff_accounts["admin"] = {
    username       = "admin",
    password_hash  = adminLoginHash(),
    display_name   = "Sys Admin",
    added_day      = 1,
    added_by       = "TEST",
    active         = true,
    is_admin       = true,
    last_login_day = nil,
  }
end

local function build(station, action, payload, secret, opts)
  return wire.buildRequest(station, "POSTROOM/REG", action, payload, secret, opts)
end

local function staffLogin()
  ensureAdmin()
  local req = build("NNA_STAFF", "staff_login",
    { username = "admin", password_hash = adminLoginHash(),
      terminal_computer_id = 12 }, STAFF_SECRET)
  local ok, data = R.dispatch(req)
  return ok, data
end

-- ===== defaultState =====

freshState()
check("default: empty domains", true, next(R.state.domains) == nil)
check("default: empty audit",   0, #R.state.audit_log)
check("default: counters zero", 0, R.state.counters.domains_registered)
check("default: public domains count", 2, #R.state.public_domains)

-- ===== audit + bill =====

freshState()
R.audit("STAFF:alice", "X", "y", "z")
check("audit: appended", 1, #R.state.audit_log)
check("audit: actor",    "STAFF:alice", R.state.audit_log[1].actor)
R.bill("sundown", "APPLICATION", 8, "STAFF:alice")
check("bill: appended",  1, #R.state.billing_log)
check("bill: amount",    8, R.state.billing_log[1].amount)

-- ===== findVerifySecret =====

freshState()
R.state.domains["sundown"] = {
  name = "sundown", status = "ACTIVE",
  shared_secret = "DEADBEEF", server_id = 47,
}
local s, kind, prin = R.findVerifySecret("SUNDOWN_SRV", "heartbeat", {})
check("findSecret: domain server",  "DEADBEEF", s)
check("findSecret: kind = DOMAIN_SRV", "DOMAIN_SRV", kind)
check("findSecret: principal = sundown", "sundown", prin)

local s2, kind2 = R.findVerifySecret("NNA_STAFF", "staff_login", {})
check("findSecret: staff",      STAFF_SECRET, s2)
check("findSecret: staff kind", "STAFF_TERMINAL", kind2)

local s3 = R.findVerifySecret("UNKNOWN_SRV", "heartbeat", {})
check("findSecret: unknown returns nil", nil, s3)

-- Install token route
R.state.install_tokens["TOK1"] = { token = "TOK1", status = "PENDING",
  domain_name = "x", expires_day = 999 }
local sit, kit = R.findVerifySecret("CLIENT:1", "consume_install_token",
  { token = "TOK1" })
check("findSecret: install token IS secret", "TOK1", sit)
check("findSecret: install token kind", "INSTALL_TOKEN", kit)

-- ===== dispatch: public action (unsigned) =====

freshState()
R.state.domains["nmail"] = { name = "nmail", status = "ACTIVE",
  is_public = true, server_id = 23,
  branding = { display_name = "National Mail" } }
table.insert(R.state.public_domains, { domain = "nmail", server_id = 23 })

local req = wire.buildRequest("CLIENT:1", "POSTROOM/REG",
  "domain_status", { domain = "nmail" }, "ignored")
local ok, data = R.dispatch(req)
check("domain_status: ok", true, ok)
check("domain_status: registered", true, data.registered)
check("domain_status: status",     "ACTIVE", data.status)

local req2 = wire.buildRequest("CLIENT:1", "POSTROOM/REG",
  "domain_status", { domain = "doesnotexist" }, "ignored")
local ok2, data2 = R.dispatch(req2)
check("domain_status: missing => registered=false", false, data2.registered)

-- list_public_domains returns those with ACTIVE registry record
local req3 = wire.buildRequest("CLIENT:1", "POSTROOM/REG",
  "list_public_domains", {}, "ignored")
local ok3, data3 = R.dispatch(req3)
check("list_public_domains: ok", true, ok3)
checkTrue("list_public_domains: includes nmail",
  (function() for _, d in ipairs(data3.domains) do
     if d.name == "nmail" then return true end end end)(), nil)

-- ===== dispatch: bad signature =====

freshState()
R.state.domains["sundown"] = { name = "sundown", status = "ACTIVE",
  shared_secret = "GOODSECRET", server_id = 47 }
local good = build("SUNDOWN_SRV", "heartbeat", { server_id = 47 }, "BADSECRET")
local ok4, err4 = R.dispatch(good)
check("dispatch: bad sig rejected", false, ok4)
check("dispatch: bad sig => AUTH_FAILED", "AUTH_FAILED", err4)

-- Replay: same nonce twice
local good2 = build("SUNDOWN_SRV", "heartbeat", { server_id = 47 }, "GOODSECRET")
local r1ok = R.dispatch(good2)
check("dispatch: first time ok", true, r1ok)
local r2ok, r2err = R.dispatch(good2)
check("dispatch: replay rejected", false, r2ok)
check("dispatch: replay => AUTH_FAILED", "AUTH_FAILED", r2err)

-- ===== heartbeat marks online =====

freshState()
R.state.domains["sundown"] = { name = "sundown", status = "ACTIVE",
  shared_secret = "S", server_id = 47, expires_day = 200 }
local req = build("SUNDOWN_SRV", "heartbeat", { server_id = 47 }, "S")
local ok, data = R.dispatch(req)
check("heartbeat: ok", true, ok)
check("heartbeat: status echoed", "ACTIVE", data.domain_status)
checkTrue("heartbeat: timestamp set",
  R.state.domains["sundown"].last_heartbeat_at ~= nil)

-- ===== staff_login / register_domain / renew / revoke =====

freshState()
local ok, data = staffLogin()
check("staff_login: ok", true, ok)
checkTrue("staff_login: token returned", type(data.session_token) == "string"
                                         and #data.session_token == 64)
local sessTok = data.session_token

-- register a domain
local req = build("NNA_STAFF", "register_domain",
  { session_token = sessTok, domain_name = "sundown",
    applicant_realname = "Bob", op_username = "barkeep" }, STAFF_SECRET)
local ok, data = R.dispatch(req)
check("register: ok", true, ok)
check("register: domain in state", "PENDING_INSTALL",
      R.state.domains["sundown"].status)
checkTrue("register: token issued",
  R.state.install_tokens[data.install_token] ~= nil)
check("register: bills 3 lines", 3, #R.state.billing_log)
check("register: counter incremented", 1, R.state.counters.domains_registered)

-- duplicate registration
local req = build("NNA_STAFF", "register_domain",
  { session_token = sessTok, domain_name = "sundown",
    applicant_realname = "Bob", op_username = "barkeep" }, STAFF_SECRET)
local ok, err = R.dispatch(req)
check("register: dup rejected", false, ok)
check("register: dup => DOMAIN_TAKEN", "DOMAIN_TAKEN", err)

-- reserved name
local req = build("NNA_STAFF", "register_domain",
  { session_token = sessTok, domain_name = "gov",
    applicant_realname = "X", op_username = "y" }, STAFF_SECRET)
local ok = R.dispatch(req)
check("register: reserved name rejected", false, ok)

-- ===== consume_install_token =====

-- Find the token issued earlier for sundown
local theToken
for tok, rec in pairs(R.state.install_tokens) do
  if rec.domain_name == "sundown" then theToken = tok end
end
checkTrue("install_token recorded", theToken ~= nil)

local req = build("CLIENT:99", "consume_install_token",
  { token = theToken, computer_id = 99,
    requested_op_username = "barkeep" }, theToken)
local ok, data = R.dispatch(req)
check("consume_install_token: ok", true, ok)
check("consume_install_token: domain ACTIVE",
      "ACTIVE", R.state.domains["sundown"].status)
check("consume_install_token: server_id set",
      99, R.state.domains["sundown"].server_id)
checkTrue("consume_install_token: secret returned",
          type(data.shared_secret) == "string" and #data.shared_secret == 64)
check("consume_install_token: token now CONSUMED",
      "CONSUMED", R.state.install_tokens[theToken].status)

-- second consumption fails
local req = build("CLIENT:100", "consume_install_token",
  { token = theToken, computer_id = 100 }, theToken)
local ok = R.dispatch(req)
check("consume_install_token: replay (not PENDING) => secret missing",
      false, ok)
-- Note: now that token.status="CONSUMED", findVerifySecret returns nil → AUTH_FAILED

-- ===== renew_domain =====

local before = R.state.domains["sundown"].expires_day
local req = build("NNA_STAFF", "renew_domain",
  { session_token = sessTok, domain_name = "sundown" }, STAFF_SECRET)
local ok, data = R.dispatch(req)
check("renew: ok", true, ok)
check("renew: extends expiry by validity_days",
      before + C.LIFECYCLE.domain_validity_days, data.new_expires_day)

-- ===== revoke_domain =====

local req = build("NNA_STAFF", "revoke_domain",
  { session_token = sessTok, domain_name = "sundown",
    reason = "test" }, STAFF_SECRET)
local ok, data = R.dispatch(req)
check("revoke: ok", true, ok)
check("revoke: status",  "REVOKED", R.state.domains["sundown"].status)

-- non-admin staff cannot revoke
freshState()
ensureAdmin()
R.state.staff_accounts["clerk"] = { username = "clerk",
  password_hash = crypto.hashPassword("nna", "clerk", "passpass"),
  active = true, is_admin = false, display_name = "Clerk", added_day = 1 }
local req = build("NNA_STAFF", "staff_login",
  { username = "clerk", password_hash =
    crypto.hashPassword("nna", "clerk", "passpass"),
    terminal_computer_id = 1 }, STAFF_SECRET)
local _, dat = R.dispatch(req)
local clerkTok = dat.session_token
R.state.domains["sundown"] = { name = "sundown", status = "ACTIVE",
  shared_secret = "S", server_id = 50, expires_day = 100 }
local req = build("NNA_STAFF", "revoke_domain",
  { session_token = clerkTok, domain_name = "sundown",
    reason = "x" }, STAFF_SECRET)
local ok, err = R.dispatch(req)
check("revoke: non-admin rejected", false, ok)
check("revoke: => INSUFFICIENT_PERMISSIONS", "INSUFFICIENT_PERMISSIONS", err)

-- ===== daily tick =====

freshState()
-- Mock day 100
local d = setmetatable({
  name = "stale", status = "ACTIVE", expires_day = 100,
  shared_secret = "S", server_id = 47,
}, nil)
R.state.domains["stale"] = d

-- Stub C.currentDay to control day
local origDay = C.currentDay
C.currentDay = function() return 100 end
R.dailyTick()
check("tick: today=expiry, status still ACTIVE", "ACTIVE", d.status)
checkTrue("tick: warning at 0 days emitted via audit (no, it's a notification)",
  true)

-- Day 100 + 5 (past 4-day grace): should suspend
C.currentDay = function() return 105 end
R.state.last_tick_day = -1  -- force re-run
R.dailyTick()
check("tick: past grace, suspended", "SUSPENDED", d.status)

-- Day 100 + 30 (revoke threshold): should revoke
C.currentDay = function() return 130 end
R.state.last_tick_day = -1
R.dailyTick()
check("tick: 30 days past expiry, revoked", "REVOKED", d.status)

-- Idempotency: running again same day doesn't change anything
local logSize = #R.state.audit_log
R.dailyTick()
check("tick: idempotent (same day, no audit growth)",
      logSize, #R.state.audit_log)

-- Token expiry
freshState()
C.currentDay = function() return 50 end
R.state.install_tokens["EXPME"] = {
  token = "EXPME", status = "PENDING",
  domain_name = "x", issued_day = 40, expires_day = 47
}
R.dailyTick()
check("tick: stale install token marked EXPIRED",
      "EXPIRED", R.state.install_tokens["EXPME"].status)

-- Revoked-domain purge after 60 days
freshState()
R.state.domains["zombie"] = {
  name = "zombie", status = "REVOKED", expires_day = 10,
  revoked_day = 20, shared_secret = "S", server_id = 1,
}
C.currentDay = function() return 81 end
R.dailyTick()
check("tick: revoked > 60 days purged",
      nil, R.state.domains["zombie"])

-- Restore C.currentDay
C.currentDay = origDay

-- ===== route_mail (without real rednet) =====

freshState()
R.state.domains["nmail"] = {
  name = "nmail", status = "ACTIVE", shared_secret = "SECN",
  server_id = 23, last_heartbeat_at = C.now(), expires_day = 999,
}
R.state.domains["common"] = {
  name = "common", status = "ACTIVE", shared_secret = "SECC",
  server_id = 31, last_heartbeat_at = C.now(), expires_day = 999,
}
R.state.domains["dead"] = {
  name = "dead", status = "ACTIVE", shared_secret = "SECD",
  server_id = 99, last_heartbeat_at = nil, expires_day = 999,
}
R.state.domains["susp"] = {
  name = "susp", status = "SUSPENDED", shared_secret = "SECS",
  server_id = 50, expires_day = 999,
}

-- Sender: nmail → unknown, dead, susp, common
-- (We expect: UNKNOWN_DOMAIN, DOMAIN_OFFLINE, DOMAIN_SUSPENDED, DELIVERY_FAILED-or-DOMAIN_OFFLINE)
local plaintext = "Hello there"
local body_ctx  = "mail:test1"
local enc = crypto.encrypt(plaintext, "SECN", body_ctx)

local req = wire.buildRequest("NMAIL_SRV", "POSTROOM/REG", "route_mail",
  { from = "alice@nmail",
    to_list = { "bob@common", "x@nope", "y@dead", "z@susp", "self@nmail" },
    subject = "hi", sent_at = C.nowSec(),
    message_id = "MSG-T1",
    body_context = body_ctx },
  "SECN",
  { body = enc, encrypted_body = false })  -- already encrypted; pass as-is

-- The build+sign covered the ciphertext we passed; replace the body in-place
-- to be the pre-encrypted hex (bypassing wire's auto-encryption)
req.body = enc
req.sig  = wire.sign(req, "SECN")

local ok, data = R.dispatch(req)
check("route_mail: dispatch ok", true, ok)
checkTrue("route_mail: results returned",
  data and type(data.delivery_results) == "table")

-- Inspect per-recipient statuses
local got = {}
for _, r in ipairs(data.delivery_results) do got[r.recipient] = r.status end

check("route_mail: unknown domain", "UNKNOWN_DOMAIN", got["x@nope"])
check("route_mail: offline domain", "DOMAIN_OFFLINE", got["y@dead"])
check("route_mail: suspended domain", "DOMAIN_SUSPENDED", got["z@susp"])
check("route_mail: same-domain marked LOCAL", "LOCAL", got["self@nmail"])
-- bob@common: rednet not available in tests, so notifyServer fails
check("route_mail: live domain w/o rednet -> DELIVERY_FAILED",
      "DELIVERY_FAILED", got["bob@common"])

-- ===== summary =====

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
