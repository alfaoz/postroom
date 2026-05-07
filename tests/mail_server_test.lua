-- tests/mail_server_test.lua
-- Run: lua tests/mail_server_test.lua

package.path = package.path
  .. ";../src/lib/?.lua;./src/lib/?.lua"
  .. ";../src/?.lua;./src/?.lua"

local crypto = require("crypto")
local wire   = require("wire")
local C      = require("common")
local M      = require("mail_server")

local total, failed = 0, 0
local function check(name, expected, actual)
  total = total + 1
  if expected == actual then print("[PASS] " .. name)
  else failed = failed + 1
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

local function fresh(public)
  M.init({
    station = "NMAIL_SRV", domain = "nmail",
    is_public_server = public ~= false,
    branding = { display_name = "National Mail" },
  })
  M.shared_secret = "TESTSECRET"
  M.nonce_store  = wire.newNonceStore(250)
  M.domain_status = "ACTIVE"
  M.setState(nil)
  M.ensureSystemAccounts()
end

local function buildUSR(action, payload, secret)
  return wire.buildRequest("CLIENT:1", "POSTROOM/USR",
    action, payload, secret or "ignored")
end

local function buildREG(action, payload, body_opts)
  -- Always signed with the server's shared_secret
  return wire.buildRequest("NNA_REG", "POSTROOM/REG",
    action, payload, M.shared_secret, body_opts)
end

local function pwh(domain, user, pw)
  return crypto.hashPassword(domain, user, pw)
end

-- ===== register / login / logout =====

fresh(true)
-- After ensureSystemAccounts: op + pm + abuse + noreply
check("init: 4 system accounts seeded", 4, M.state.counters.total_users)

local req = buildUSR("register", {
  username = "alice", password_hash = pwh("nmail", "alice", "hunter22"),
  computer_id = 1,
})
local ok, data = M.dispatch(req)
check("register: ok",                   true,  ok)
checkTrue("register: token returned",   type(data.session_token) == "string"
                                        and #data.session_token == 64)
check("register: alice exists",         true,  M.state.users["alice"] ~= nil)
check("register: welcome in inbox",     1,     #M.state.mailboxes["alice"].inbox)

local aliceTok = data.session_token

-- duplicate
local ok2, err2 = M.dispatch(buildUSR("register", {
  username = "alice", password_hash = pwh("nmail", "alice", "x123456"),
}))
check("register: dup => USERNAME_TAKEN", "USERNAME_TAKEN", err2)

-- private server rejects register
fresh(false)
local ok3, err3 = M.dispatch(buildUSR("register", {
  username = "alice", password_hash = pwh("nmail", "alice", "hunter22"),
}))
check("register: private server => DOMAIN_CLOSED", "DOMAIN_CLOSED", err3)

-- login on public
fresh(true)
M.dispatch(buildUSR("register", {
  username = "alice", password_hash = pwh("nmail", "alice", "hunter22"),
}))

local req = buildUSR("login", {
  username = "alice", password_hash = pwh("nmail", "alice", "hunter22"),
  computer_id = 7,
})
local ok, data = M.dispatch(req)
check("login: ok",   true, ok)
local aliceTok = data.session_token
checkTrue("login: returns token",  type(aliceTok) == "string" and #aliceTok == 64)

-- bad password
local ok, err = M.dispatch(buildUSR("login", {
  username = "alice", password_hash = pwh("nmail", "alice", "wrongpw"),
}))
check("login: bad password",  "BAD_CREDENTIALS", err)

-- nonexistent user
local ok, err = M.dispatch(buildUSR("login", {
  username = "ghost", password_hash = pwh("nmail", "ghost", "x123456"),
}))
check("login: ghost => BAD_CREDENTIALS",  "BAD_CREDENTIALS", err)

-- ===== authenticated USR requires HMAC keyed on session token =====

-- Wrong secret rejected
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR",
  "account_info", { session_token = aliceTok }, "WRONGKEY")
local ok, err = M.dispatch(req)
check("auth: wrong sig => AUTH_FAILED", "AUTH_FAILED", err)

-- Correct secret accepted
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR",
  "account_info", { session_token = aliceTok }, aliceTok)
local ok, data = M.dispatch(req)
check("account_info: ok",        true,    ok)
check("account_info: username",  "alice", data.username)
check("account_info: domain",    "nmail", data.domain)

-- ===== change_password =====

local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR",
  "change_password", {
    session_token = aliceTok,
    current_password_hash = pwh("nmail", "alice", "hunter22"),
    new_password_hash     = pwh("nmail", "alice", "newpasswd"),
  }, aliceTok)
local ok = M.dispatch(req)
check("change_password: ok", true, ok)
-- Old password no longer works
local _, err = M.dispatch(buildUSR("login", {
  username = "alice", password_hash = pwh("nmail", "alice", "hunter22"),
}))
check("change_password: old pw rejected", "BAD_CREDENTIALS", err)

-- New password works (and refreshes token)
local _, data = M.dispatch(buildUSR("login", {
  username = "alice", password_hash = pwh("nmail", "alice", "newpasswd"),
}))
aliceTok = data.session_token

-- ===== send (local within @nmail) =====

-- Add a second user, bob
M.dispatch(buildUSR("register", {
  username = "bob", password_hash = pwh("nmail", "bob", "bobsecret"),
}))

local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "send", {
  session_token = aliceTok,
  to            = { "bob@nmail" },
  subject       = "hello",
  body          = "Hi bob, how are you?",
}, aliceTok)
local ok, data = M.dispatch(req)
check("send: ok",                          true,         ok)
check("send: 1 result",                    1,            #data.delivery_results)
check("send: local delivery",              "DELIVERED",  data.delivery_results[1].status)
check("send: bob inbox has 2 (welcome+sent)", 2, #M.state.mailboxes["bob"].inbox)
check("send: alice sent has 1",            1, #M.state.mailboxes["alice"].sent)

-- send to unknown local user => UNKNOWN_RECIPIENT (also creates a bounce)
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "send", {
  session_token = aliceTok,
  to            = { "nobody@nmail" },
  subject       = "missing",
  body          = "you don't exist",
}, aliceTok)
local ok, data = M.dispatch(req)
check("send: unknown local recipient",
      "UNKNOWN_RECIPIENT", data.delivery_results[1].status)
checkTrue("send: bounce in alice inbox",
  (function()
    for _, e in ipairs(M.state.mailboxes["alice"].inbox) do
      local m = M.state.messages[e.msg_id]
      if m and m.is_bounce then return true end
    end
  end)())

-- send to remote without rednet => REGISTRY_UNREACHABLE bounce
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "send", {
  session_token = aliceTok,
  to            = { "carol@common" },
  subject       = "remote",
  body          = "test cross",
}, aliceTok)
local ok, data = M.dispatch(req)
check("send: remote w/o registry => REGISTRY_UNREACHABLE",
  "REGISTRY_UNREACHABLE", data.delivery_results[1].status)

-- ===== list_inbox + read_message + mark_read + delete_message =====

local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "list_inbox",
  { session_token = aliceTok, folder = "inbox" }, aliceTok)
local ok, data = M.dispatch(req)
check("list_inbox: ok", true, ok)
checkTrue("list_inbox: at least the welcome message", #data.messages >= 1)

local firstId = data.messages[1].id
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "read_message",
  { session_token = aliceTok, id = firstId }, aliceTok)
local ok, data = M.dispatch(req)
check("read_message: ok", true, ok)
check("read_message: id matches", firstId, data.message.id)

-- read should have flipped unread to false
local _, data = M.dispatch(wire.buildRequest("CLIENT:1", "POSTROOM/USR",
  "list_inbox", { session_token = aliceTok }, aliceTok))
local matched = false
for _, m in ipairs(data.messages) do
  if m.id == firstId then matched = true; check("read_message: marked read",
    false, m.unread) end
end
checkTrue("read_message: still in inbox", matched)

-- mark unread
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "mark_read",
  { session_token = aliceTok, id = firstId, read = false }, aliceTok)
M.dispatch(req)

-- delete
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "delete_message",
  { session_token = aliceTok, id = firstId }, aliceTok)
local ok = M.dispatch(req); check("delete_message: ok", true, ok)
-- not in inbox anymore, in trash
local mb = M.state.mailboxes["alice"]
local stillThere = false
for _, e in ipairs(mb.inbox) do
  if e.msg_id == firstId then stillThere = true end
end
check("delete_message: removed from inbox", false, stillThere)
local inTrash = false
for _, e in ipairs(mb.trash) do
  if e.msg_id == firstId then inTrash = true end
end
check("delete_message: in trash", true, inTrash)

-- ===== search =====

local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "search",
  { session_token = aliceTok, query = "hello", folder = "sent" }, aliceTok)
local ok, data = M.dispatch(req)
check("search: ok", true, ok)
checkTrue("search: matches sent 'hello'", #data.messages >= 1)

-- ===== list_local_users =====

local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "list_local_users",
  { session_token = aliceTok, prefix = "" }, aliceTok)
local ok, data = M.dispatch(req)
check("list_local_users: ok", true, ok)
-- op is a real mailbox; only pm/abuse/noreply (is_system=true) are filtered.
checkTrue("list_local_users: alice + bob + op present, pm filtered",
  (function()
    local set = {}
    for _, u in ipairs(data.users) do set[u] = true end
    return set.alice and set.bob and set.op and not set.pm
  end)())

-- ===== admin actions: only op can do them =====

-- alice tries admin_create_user — fails (not op)
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "admin_create_user",
  { session_token = aliceTok, username = "carol",
    initial_password_hash = pwh("nmail", "carol", "carolpass") }, aliceTok)
local ok, err = M.dispatch(req)
check("admin: alice can't create",  "INSUFFICIENT_PERMISSIONS", err)

-- Make op log in (give op a password manually)
M.state.users["op"].password_hash = pwh("nmail", "op", "ophunter")
M.state.users["op"].is_op = true
local _, data = M.dispatch(buildUSR("login", {
  username = "op", password_hash = pwh("nmail", "op", "ophunter"),
}))
local opTok = data.session_token

local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "admin_create_user",
  { session_token = opTok, username = "carol",
    initial_password_hash = pwh("nmail", "carol", "carolpass") }, opTok)
local ok = M.dispatch(req)
check("admin_create_user: op can",  true, ok)
checkTrue("admin_create_user: carol exists",  M.state.users["carol"] ~= nil)
check("admin_create_user: must_change_password set",
      true, M.state.users["carol"].must_change_password)

-- admin_reset_password
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "admin_reset_password",
  { session_token = opTok, username = "carol",
    new_password_hash = pwh("nmail", "carol", "newcarol") }, opTok)
local ok = M.dispatch(req)
check("admin_reset_password: ok", true, ok)
check("admin_reset_password: hash updated",
      pwh("nmail", "carol", "newcarol"), M.state.users["carol"].password_hash)

-- admin_delete_user (wrong confirm)
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "admin_delete_user",
  { session_token = opTok, username = "carol", confirm = "DEL" }, opTok)
local ok, err = M.dispatch(req)
check("admin_delete_user: bad confirm", "INVALID_REQUEST", err)

-- admin_delete_user (correct)
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "admin_delete_user",
  { session_token = opTok, username = "carol", confirm = "DELETE" }, opTok)
local ok = M.dispatch(req)
check("admin_delete_user: ok", true, ok)
check("admin_delete_user: gone", nil, M.state.users["carol"])

-- admin can't delete op or system accounts
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "admin_delete_user",
  { session_token = opTok, username = "op", confirm = "DELETE" }, opTok)
local ok, err = M.dispatch(req)
check("admin_delete_user: can't delete op",
      "INSUFFICIENT_PERMISSIONS", err)

-- admin_set_branding
local req = wire.buildRequest("CLIENT:1", "POSTROOM/USR", "admin_set_branding",
  { session_token = opTok,
    branding = { display_name = "Niomail Beta", sign_off = "— Beta" } }, opTok)
local ok = M.dispatch(req)
check("admin_set_branding: ok", true, ok)
check("admin_set_branding: display_name updated",
      "Niomail Beta", M.state.domain_meta.branding.display_name)

-- ===== Server-bound: deliver_mail signed with shared_secret =====

fresh(true)
M.dispatch(buildUSR("register", {
  username = "alice", password_hash = pwh("nmail", "alice", "hunter22"),
}))

-- Encrypt body with our shared_secret + msg_id context
local plain = "Hi from cross-domain!"
local body_ctx = "mail:R-MSG-1"
local enc = crypto.encrypt(plain, M.shared_secret, body_ctx)
local req = buildREG("deliver_mail", {
  from = "carol@common",
  to_list = { "alice@nmail", "ghost@nmail" },
  subject = "remote",
  sent_at = C.nowSec(),
  message_id = "R-MSG-1",
})
req.body = enc
req.sig  = wire.sign(req, M.shared_secret)

local ok, data = M.dispatch(req)
check("deliver_mail: ok", true, ok)
check("deliver_mail: 1 accepted (alice; ghost rejected)",
      1, #data.accepted_recipients)
check("deliver_mail: alice inbox has remote", true,
      (function()
        for _, e in ipairs(M.state.mailboxes["alice"].inbox) do
          local m = M.state.messages[e.msg_id]
          if m and m.from == "carol@common" then return true end
        end
      end)())

-- Body decrypts correctly: pull the message back out
local found
for _, e in ipairs(M.state.mailboxes["alice"].inbox) do
  local m = M.state.messages[e.msg_id]
  if m and m.from == "carol@common" then found = m end
end
checkTrue("deliver_mail: body matches",  found and found.body == plain)

-- bad signature on REG actions => AUTH_FAILED
local bad = wire.buildRequest("NNA_REG", "POSTROOM/REG",
  "deliver_mail", { from = "x@y", to_list = {}, subject = "x" }, "WRONGKEY")
local ok, err = M.dispatch(bad)
check("deliver_mail: bad sig => AUTH_FAILED", "AUTH_FAILED", err)

-- wrong sender station => AUTH_FAILED
local bad = wire.buildRequest("NOTREG", "POSTROOM/REG",
  "deliver_mail", { from = "x@y", to_list = {}, subject = "x" }, M.shared_secret)
local ok, err = M.dispatch(bad)
check("deliver_mail: wrong station => AUTH_FAILED", "AUTH_FAILED", err)

-- ===== notify_revoked / notify_renewal / notify_suspended =====

fresh(true)
M.state.users["op"].password_hash = pwh("nmail", "op", "ophunter")
M.state.users["op"].is_op = true

local req = buildREG("notify_renewal",
  { domain = "nmail", days_until_expiry = 4, fee_due = 15 })
local ok = M.dispatch(req)
check("notify_renewal: ok", true, ok)
checkTrue("notify_renewal: op got system mail",
  #M.state.mailboxes["op"].inbox >= 1)

local req = buildREG("notify_revoked", { domain = "nmail", reason = "test" })
M.dispatch(req)
check("notify_revoked: domain_status flipped", "REVOKED", M.domain_status)

-- After REVOKED, login should fail
local _, err = M.dispatch(buildUSR("login", {
  username = "op", password_hash = pwh("nmail", "op", "ophunter"),
}))
check("login after REVOKED => DOMAIN_REVOKED", "DOMAIN_REVOKED", err)

-- ===== summary =====

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
