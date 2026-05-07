-- /postroom/lib/mail_server.lua
-- Shared mail-server core. Used by:
--   src/nmail_srv.lua       (@nmail)   is_public_server = true
--   src/common_srv.lua      (@common)  is_public_server = true
--   src/domain_srv.lua      (private)  is_public_server = false
--
-- The wrapper passes a config table to M.run({...}) or M.init({...}).
-- Tests use M.init() then drive M.dispatch(req) directly.

local crypto = require("crypto")
local wire   = require("wire")
local C      = require("common")

local M = {}

-- =============================================================
-- Defaults & paths
-- =============================================================

M.STATE_PATH    = "/postroom/state.txt"
M.SECRET_PATH   = "/postroom/secret"
M.AUDIT_MAX     = 500
M.SESSION_TTL_MS         = C.LIFECYCLE.session_max_age_days * 24 * 60 * 60 * 1000
M.MAX_PER_USER_SESSIONS  = 3
M.HEARTBEAT_INTERVAL_SEC = C.LIFECYCLE.heartbeat_interval_sec
M.MAIN_TICK_SEC          = 30
M.SEND_TIMEOUT_SEC       = 5
M.SENT_FOLDER_CAP        = 500
M.TRASH_RETENTION_DAYS   = C.LIFECYCLE.trash_retention_days

-- =============================================================
-- Config and state
-- =============================================================

-- Config (set by init):
--   { station, domain, is_public_server, registry_station, branding }
M.config       = nil
M.state        = nil
M.shared_secret = nil
M.nonce_store  = wire.newNonceStore(250)
M.domain_status = "ACTIVE"   -- as last reported by registry

local function defaultBranding(domain)
  return {
    display_name  = domain,
    sign_off      = nil,
    theme_palette = nil,
  }
end

local function defaultState(config)
  return {
    domain_meta = {
      domain_name      = config.domain,
      server_id        = nil,
      is_public_server = config.is_public_server and true or false,
      registry_station = config.registry_station or "NNA_REG",
      branding         = config.branding or defaultBranding(config.domain),
      install = {
        installed_day = C.currentDay(),
      },
    },
    users      = {},
    messages   = {},
    mailboxes  = {},
    sessions   = {},
    audit_log  = {},
    counters   = {
      next_msg_id    = 1,
      total_messages = 0,
      total_users    = 0,
    },
    last_trash_purge_day = -1,
  }
end

local function mergeDefaults(s, config)
  local d = defaultState(config)
  for k, v in pairs(d) do
    if s[k] == nil then s[k] = v end
  end
  s.domain_meta = s.domain_meta or d.domain_meta
  for k, v in pairs(d.domain_meta) do
    if s.domain_meta[k] == nil then s.domain_meta[k] = v end
  end
  return s
end

-- =============================================================
-- Persistence
-- =============================================================

function M.loadState()
  local s = nil
  if fs and fs.exists and fs.exists(M.STATE_PATH) then
    s = C.loadTable(M.STATE_PATH)
  end
  M.state = mergeDefaults(s or defaultState(M.config), M.config)
  return M.state
end

function M.saveState()
  if fs then C.saveTable(M.STATE_PATH, M.state) end
end

function M.loadSecret()
  if not fs then return nil end
  if not fs.exists(M.SECRET_PATH) then return nil end
  local f = fs.open(M.SECRET_PATH, "r")
  local s = C.trim(f.readAll() or "")
  f.close()
  if s == "" then return nil end
  M.shared_secret = s
  return s
end

function M.writeSecret(secret)
  if not fs then return end
  local dir = fs.getDir(M.SECRET_PATH)
  if dir ~= "" and not fs.exists(dir) then fs.makeDir(dir) end
  local f = fs.open(M.SECRET_PATH, "w")
  f.write(secret); f.close()
  M.shared_secret = secret
end

-- For tests: bypass disk and seed in-memory state.
function M.setState(s)
  M.state = mergeDefaults(s or defaultState(M.config), M.config)
end

-- =============================================================
-- Audit
-- =============================================================

local function audit(actor, action, target, details)
  C.appendLog(M.state.audit_log, {
    day = C.currentDay(), time = C.nowSec(),
    actor = actor, action = action, target = target, details = details,
  }, M.AUDIT_MAX)
end
M.audit = audit

-- =============================================================
-- System account bootstrap
-- =============================================================

local function ensureMailbox(username)
  M.state.mailboxes[username] = M.state.mailboxes[username] or
    { inbox = {}, sent = {}, trash = {} }
end

local function createSystemUser(username, opts)
  opts = opts or {}
  if M.state.users[username] then return M.state.users[username] end
  M.state.users[username] = {
    username       = username,
    password_hash  = opts.password_hash,   -- nil for system-only senders
    created_day    = C.currentDay(),
    last_login_day = nil,
    must_change_password = opts.must_change_password or false,
    is_op          = opts.is_op or false,
    is_deputy      = false,
    is_system      = opts.is_system or false,
  }
  ensureMailbox(username)
  M.state.counters.total_users = (M.state.counters.total_users or 0) + 1
  return M.state.users[username]
end
M.createSystemUser = createSystemUser

-- Called once on first boot. Seeds op/pm/abuse/noreply.
-- op_password (plaintext) optional: if given, sets op's hash + must_change.
function M.ensureSystemAccounts(opUsername, opPassword)
  opUsername = opUsername or "op"
  if not M.state.users["pm"] then
    createSystemUser("pm", { is_system = true })
  end
  if not M.state.users["abuse"] then
    createSystemUser("abuse", { is_system = true })
  end
  if not M.state.users["noreply"] then
    createSystemUser("noreply", { is_system = true })
  end
  if not M.state.users[opUsername] then
    local hash = opPassword and crypto.hashPassword(M.config.domain, opUsername, opPassword) or nil
    createSystemUser(opUsername, {
      is_op = true,
      password_hash = hash,
      must_change_password = (opPassword ~= nil),
    })
  end
end

-- =============================================================
-- Sessions
-- =============================================================

local function newSession(username, computer_id)
  -- Boot oldest sessions for this user above the cap.
  local mine = {}
  for tok, s in pairs(M.state.sessions) do
    if s.username == username then mine[#mine + 1] = { tok = tok, s = s } end
  end
  table.sort(mine, function(a, b) return a.s.last_used_at < b.s.last_used_at end)
  while #mine >= M.MAX_PER_USER_SESSIONS do
    M.state.sessions[mine[1].tok] = nil
    table.remove(mine, 1)
  end
  local now = C.now()
  local token = crypto.randomHex(32)
  M.state.sessions[token] = {
    token       = token,
    username    = username,
    computer_id = computer_id,
    created_at  = now,
    last_used_at = now,
    expires_at  = now + M.SESSION_TTL_MS,
  }
  return token
end

local function checkSession(token)
  if type(token) ~= "string" then return nil, "AUTH_FAILED" end
  local s = M.state.sessions[token]
  if not s then return nil, "AUTH_FAILED" end
  local now = C.now()
  if s.expires_at and now > s.expires_at then
    M.state.sessions[token] = nil
    return nil, "AUTH_FAILED"
  end
  s.last_used_at = now
  s.expires_at   = now + M.SESSION_TTL_MS
  return s
end
M.checkSession = checkSession

-- =============================================================
-- Inbox helpers
-- =============================================================

local function nextMsgId()
  return C.nextId(M.state, "next_msg_id", "MSG", 4)
end

local function addToInbox(username, msg_id, opts)
  ensureMailbox(username)
  local mb = M.state.mailboxes[username]
  table.insert(mb.inbox, 1, {
    msg_id      = msg_id,
    unread      = (opts and opts.unread ~= false),
    received_at = (opts and opts.received_at) or C.now(),
  })
end

local function addToSent(username, msg_id)
  ensureMailbox(username)
  local mb = M.state.mailboxes[username]
  table.insert(mb.sent, 1, { msg_id = msg_id, sent_at = C.now() })
  while #mb.sent > M.SENT_FOLDER_CAP do
    -- prune oldest (end of list)
    local entry = table.remove(mb.sent)
    -- Caller may want the message GC'd later; we leave the message in
    -- state.messages (it could still be in someone's inbox).
    if entry then audit("SYSTEM", "PRUNE_SENT", username, entry.msg_id) end
  end
end

local function moveToTrash(username, msg_id)
  local mb = M.state.mailboxes[username]
  if not mb then return false end
  for i, e in ipairs(mb.inbox) do
    if e.msg_id == msg_id then
      table.remove(mb.inbox, i)
      table.insert(mb.trash, 1, { msg_id = msg_id, deleted_at = C.now() })
      return true
    end
  end
  for i, e in ipairs(mb.sent) do
    if e.msg_id == msg_id then
      table.remove(mb.sent, i)
      table.insert(mb.trash, 1, { msg_id = msg_id, deleted_at = C.now() })
      return true
    end
  end
  return false
end

local function findInFolder(folder, msg_id)
  for i, e in ipairs(folder) do
    if e.msg_id == msg_id then return i, e end
  end
  return nil
end

-- =============================================================
-- Sending: bounce helper
-- =============================================================

local function makeBounce(originalMsg, recipient, reason)
  local id = nextMsgId()
  local text = ("The message you sent could not be delivered to %s.\n\nReason: %s\n\n--- Original subject ---\n%s\n")
    :format(recipient, reason or "Unknown error", originalMsg.subject or "")
  M.state.messages[id] = {
    id        = id,
    from      = "pm@" .. M.config.domain,
    to        = { originalMsg.from },
    subject   = "Undeliverable: " .. tostring(originalMsg.subject or ""),
    body      = text,
    sent_at   = C.now(),
    sent_day  = C.currentDay(),
    is_bounce = true,
  }
  M.state.counters.total_messages = (M.state.counters.total_messages or 0) + 1
  -- Drop into the original sender's local inbox if they're on this domain.
  local user, dom = C.parseAddress(originalMsg.from)
  if dom == M.config.domain and M.state.users[user] then
    addToInbox(user, id, { unread = true })
  end
  return id
end

-- =============================================================
-- Outbound: heartbeat + route_mail to registry
-- =============================================================

local function sendToRegistry(action, payload, opts)
  if not rednet or not M.shared_secret then
    return nil, "no_registry"
  end
  local registryId = rednet.lookup(wire.PROTOCOL, M.config.registry_station)
  if not registryId then return nil, "registry_not_found" end
  return wire.sendRequest(
    registryId, M.config.station, "POSTROOM/REG", action,
    payload, M.shared_secret, M.SEND_TIMEOUT_SEC, opts)
end
M.sendToRegistry = sendToRegistry

function M.heartbeatTick()
  local data, err = sendToRegistry("heartbeat", {
    server_id        = (os and os.getComputerID and os.getComputerID()) or 0,
    domain           = M.config.domain,
    last_activity_at = C.nowSec(),
  })
  if data then
    M.domain_status = data.domain_status or M.domain_status
  end
  return data, err
end

-- =============================================================
-- Daily housekeeping (trash purge, sent cap is event-driven above)
-- =============================================================

function M.dailyTick()
  local today = C.currentDay()
  if M.state.last_trash_purge_day == today then return end
  local cutoffMs = C.now() - M.TRASH_RETENTION_DAYS * 24 * 60 * 60 * 1000
  for username, mb in pairs(M.state.mailboxes) do
    local kept = {}
    for _, e in ipairs(mb.trash) do
      if (e.deleted_at or 0) >= cutoffMs then
        kept[#kept + 1] = e
      end
    end
    mb.trash = kept
  end
  M.state.last_trash_purge_day = today
  M.saveState()
end

-- =============================================================
-- Action handlers (POSTROOM/USR)
-- ctx: { kind = "USR", session = <session_table or nil>, request = req }
-- =============================================================

local handlers = {}

handlers.register = function(payload, ctx)
  if not M.config.is_public_server then return false, "DOMAIN_CLOSED" end
  if M.domain_status ~= "ACTIVE" then return false, "DOMAIN_SUSPENDED" end
  local username = string.lower(C.trim(payload.username or ""))
  local ok, err = C.validateUsername(username)
  if not ok then return false, "INVALID_USERNAME:" .. (err or "") end
  if M.state.users[username] then return false, "USERNAME_TAKEN" end
  if type(payload.password_hash) ~= "string" or #payload.password_hash ~= 64 then
    return false, "INVALID_REQUEST"
  end

  M.state.users[username] = {
    username       = username,
    password_hash  = payload.password_hash,
    created_day    = C.currentDay(),
    last_login_day = C.currentDay(),
    must_change_password = false,
    is_op = false, is_deputy = false, is_system = false,
  }
  ensureMailbox(username)
  M.state.counters.total_users = (M.state.counters.total_users or 0) + 1

  -- Welcome message from pm@<domain>
  local id = nextMsgId()
  M.state.messages[id] = {
    id      = id,
    from    = "pm@" .. M.config.domain,
    to      = { username .. "@" .. M.config.domain },
    subject = "Welcome to " .. (M.config.branding.display_name or M.config.domain),
    body    = "You're now signed up as " .. username .. "@" .. M.config.domain ..
              ".\n\nSend your first message any time. Need help? Contact pm@nna.\n" ..
              (M.config.branding.sign_off or ""),
    sent_at = C.now(), sent_day = C.currentDay(),
  }
  M.state.counters.total_messages = (M.state.counters.total_messages or 0) + 1
  addToInbox(username, id, { unread = true })

  audit("USER", "REGISTER", username, nil)
  local token = newSession(username, payload.computer_id)
  M.saveState()
  return true, {
    session_token = token,
    expires_at    = M.state.sessions[token].expires_at,
  }
end

handlers.login = function(payload, ctx)
  if M.domain_status == "REVOKED" then return false, "DOMAIN_REVOKED" end
  local username = string.lower(C.trim(payload.username or ""))
  local u = M.state.users[username]
  if not u or u.is_system or not u.password_hash then
    return false, "BAD_CREDENTIALS"
  end
  if type(payload.password_hash) ~= "string" then return false, "INVALID_REQUEST" end
  if u.password_hash ~= payload.password_hash then return false, "BAD_CREDENTIALS" end

  u.last_login_day = C.currentDay()
  local token = newSession(username, payload.computer_id)
  audit("USER", "LOGIN", username, "computer_id=" .. tostring(payload.computer_id))
  M.saveState()
  return true, {
    session_token         = token,
    expires_at            = M.state.sessions[token].expires_at,
    must_change_password  = u.must_change_password or false,
    is_op                 = u.is_op or false,
  }
end

local function requireSession(payload)
  return checkSession(payload.session_token)
end

handlers.logout = function(payload, ctx)
  local s = M.state.sessions[payload.session_token]
  if s then
    M.state.sessions[payload.session_token] = nil
    audit("USER", "LOGOUT", s.username, nil)
    M.saveState()
  end
  return true, { ok = true }
end

handlers.change_password = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  local u = M.state.users[s.username]
  if not u then return false, "BAD_CREDENTIALS" end
  if u.password_hash ~= payload.current_password_hash then
    return false, "BAD_CREDENTIALS"
  end
  if type(payload.new_password_hash) ~= "string" or #payload.new_password_hash ~= 64 then
    return false, "WEAK_PASSWORD"
  end
  u.password_hash = payload.new_password_hash
  u.must_change_password = false
  audit("USER", "CHANGE_PASSWORD", s.username, nil)
  M.saveState()
  return true, { ok = true }
end

handlers.account_info = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  local u = M.state.users[s.username]
  local mb = M.state.mailboxes[s.username] or { inbox = {}, sent = {}, trash = {} }
  local unread = 0
  for _, e in ipairs(mb.inbox) do if e.unread then unread = unread + 1 end end
  return true, {
    username        = u.username,
    domain          = M.config.domain,
    created_day     = u.created_day,
    last_login_day  = u.last_login_day,
    msg_count       = #mb.inbox + #mb.sent,
    unread_count    = unread,
    is_op           = u.is_op or false,
    must_change_password = u.must_change_password or false,
  }
end

local function summarize(entry, msg)
  return {
    id        = msg.id,
    from      = msg.from,
    subject   = msg.subject,
    sent_day  = msg.sent_day,
    sent_at   = msg.sent_at,
    unread    = entry.unread,
    is_bounce = msg.is_bounce or false,
  }
end

handlers.list_inbox = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  local mb = M.state.mailboxes[s.username] or { inbox = {}, sent = {}, trash = {} }
  local folder = payload.folder or "inbox"
  local list = mb[folder]
  if not list then return false, "INVALID_REQUEST" end
  local limit = math.min(tonumber(payload.limit) or 50, 200)
  local out = {}
  for i = 1, math.min(limit, #list) do
    local e = list[i]
    local m = M.state.messages[e.msg_id]
    if m then out[#out + 1] = summarize(e, m) end
  end
  return true, { messages = out, folder = folder, total = #list }
end

handlers.read_message = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  local m = M.state.messages[payload.id]
  if not m then return false, "UNKNOWN_RECIPIENT" end
  local mb = M.state.mailboxes[s.username]
  if not mb then return false, "AUTH_FAILED" end
  local idx, e = findInFolder(mb.inbox, payload.id)
  if e then e.unread = false
  else
    -- Allow reading from sent or trash, too.
    if not findInFolder(mb.sent, payload.id) and not findInFolder(mb.trash, payload.id) then
      return false, "UNKNOWN_RECIPIENT"
    end
  end
  M.saveState()
  return true, {
    message = {
      id       = m.id,    from     = m.from,
      to       = m.to,
      subject  = m.subject,
      body     = m.body,
      sent_at  = m.sent_at,
      sent_day = m.sent_day,
    },
  }
end

handlers.mark_read = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  local mb = M.state.mailboxes[s.username]
  if not mb then return false, "AUTH_FAILED" end
  local _, e = findInFolder(mb.inbox, payload.id)
  if not e then return false, "UNKNOWN_RECIPIENT" end
  e.unread = (payload.read == false)
  M.saveState()
  return true, { ok = true }
end

handlers.delete_message = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  if not moveToTrash(s.username, payload.id) then
    return false, "UNKNOWN_RECIPIENT"
  end
  M.saveState()
  return true, { ok = true }
end

handlers.search = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  local mb = M.state.mailboxes[s.username] or { inbox = {}, sent = {}, trash = {} }
  local folder = payload.folder or "inbox"
  local list = mb[folder]; if not list then return false, "INVALID_REQUEST" end
  local q = string.lower(C.trim(tostring(payload.query or "")))
  if q == "" then return true, { messages = {} } end
  local out = {}
  for _, e in ipairs(list) do
    local m = M.state.messages[e.msg_id]
    if m and (string.find(string.lower(m.subject or ""), q, 1, true)
           or string.find(string.lower(m.from    or ""), q, 1, true)
           or string.find(string.lower(m.body   or ""), q, 1, true)) then
      out[#out + 1] = summarize(e, m)
    end
  end
  return true, { messages = out }
end

handlers.list_local_users = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  local prefix = string.lower(C.trim(tostring(payload.prefix or "")))
  local out = {}
  for username, u in pairs(M.state.users) do
    if not u.is_system and (prefix == "" or username:sub(1, #prefix) == prefix) then
      out[#out + 1] = username
    end
  end
  table.sort(out)
  return true, { users = out }
end

handlers.send = function(payload, ctx)
  local s, err = requireSession(payload); if not s then return false, err end
  if M.domain_status ~= "ACTIVE" then return false, "DOMAIN_SUSPENDED" end
  if type(payload.to) ~= "table" or #payload.to == 0 then return false, "INVALID_REQUEST" end
  local subject = tostring(payload.subject or "")
  local body    = tostring(payload.body or "")
  local oks, serr = C.validateSubject(subject); if not oks then return false, "INVALID_REQUEST" end
  local okb, berr = C.validateBody(body);       if not okb then return false, "INVALID_REQUEST" end

  local fromAddr = s.username .. "@" .. M.config.domain
  local id = nextMsgId()
  local now = C.now()
  M.state.messages[id] = {
    id = id, from = fromAddr,
    to = payload.to,
    subject = subject, body = body,
    sent_at = now, sent_day = C.currentDay(),
  }
  M.state.counters.total_messages = (M.state.counters.total_messages or 0) + 1
  addToSent(s.username, id)

  -- Split recipients local vs cross-domain
  local results = {}
  local crossDomain = {}
  for _, addr in ipairs(payload.to) do
    local user, dom = C.parseAddress(addr)
    if not user or not dom then
      results[#results + 1] = { recipient = addr, status = "INVALID_ADDRESS" }
    elseif dom == M.config.domain then
      if M.state.users[user] then
        addToInbox(user, id, { unread = true })
        results[#results + 1] = { recipient = addr, status = "DELIVERED" }
      else
        results[#results + 1] = { recipient = addr, status = "UNKNOWN_RECIPIENT" }
      end
    else
      crossDomain[#crossDomain + 1] = addr
    end
  end

  if #crossDomain > 0 then
    local body_ctx = "mail:" .. id
    local data, rerr = sendToRegistry("route_mail", {
      from         = fromAddr,
      to_list      = crossDomain,
      subject      = subject,
      sent_at      = M.state.messages[id].sent_at,
      message_id   = id,
      body_context = body_ctx,
    }, { body = body, encrypted_body = true, body_context = body_ctx })

    if data and data.delivery_results then
      for _, r in ipairs(data.delivery_results) do
        results[#results + 1] = r
      end
    else
      -- Registry unreachable: treat all cross-domain as offline
      for _, addr in ipairs(crossDomain) do
        results[#results + 1] = {
          recipient = addr,
          status    = "REGISTRY_UNREACHABLE",
          reason    = rerr,
        }
      end
    end
  end

  -- Bounce on every non-DELIVERED, non-LOCAL outcome
  for _, r in ipairs(results) do
    if r.status ~= "DELIVERED" and r.status ~= "LOCAL" then
      makeBounce(M.state.messages[id], r.recipient,
                 r.status .. (r.reason and (" (" .. r.reason .. ")") or ""))
    end
  end

  audit("USER", "SEND", s.username,
        "id=" .. id .. " to=" .. tostring(#payload.to))
  M.saveState()
  return true, { message_id = id, delivery_results = results }
end

-- ===== Domain admin actions ================================================

local function requireOp(payload)
  local s, err = requireSession(payload); if not s then return nil, err end
  local u = M.state.users[s.username]
  if not u or not (u.is_op or u.is_deputy) then
    return nil, "INSUFFICIENT_PERMISSIONS"
  end
  return s
end

handlers.admin_create_user = function(payload, ctx)
  local s, err = requireOp(payload); if not s then return false, err end
  local username = string.lower(C.trim(payload.username or ""))
  local ok, verr = C.validateUsername(username)
  if not ok then return false, "INVALID_USERNAME:" .. (verr or "") end
  if M.state.users[username] then return false, "USERNAME_TAKEN" end
  if type(payload.initial_password_hash) ~= "string" or #payload.initial_password_hash ~= 64 then
    return false, "INVALID_REQUEST"
  end
  M.state.users[username] = {
    username             = username,
    password_hash        = payload.initial_password_hash,
    created_day          = C.currentDay(),
    last_login_day       = nil,
    must_change_password = true,
    is_op = false, is_deputy = false, is_system = false,
  }
  ensureMailbox(username)
  M.state.counters.total_users = (M.state.counters.total_users or 0) + 1

  -- Welcome message
  local id = nextMsgId()
  M.state.messages[id] = {
    id = id, from = "pm@" .. M.config.domain,
    to = { username .. "@" .. M.config.domain },
    subject = "Welcome — change your password on first login",
    body = "Your account " .. username .. "@" .. M.config.domain
        .. " was created by the domain operator. Change your password on first login.",
    sent_at = C.now(), sent_day = C.currentDay(),
  }
  addToInbox(username, id, { unread = true })

  audit("OP:" .. s.username, "ADMIN_CREATE_USER", username, nil)
  M.saveState()
  return true, { username = username }
end

handlers.admin_delete_user = function(payload, ctx)
  local s, err = requireOp(payload); if not s then return false, err end
  if payload.confirm ~= "DELETE" then return false, "INVALID_REQUEST" end
  local target = string.lower(C.trim(payload.username or ""))
  local u = M.state.users[target]
  if not u then return false, "UNKNOWN_RECIPIENT" end
  if u.is_op or u.is_system then return false, "INSUFFICIENT_PERMISSIONS" end
  M.state.users[target] = nil
  M.state.mailboxes[target] = nil
  -- Drop their sessions
  for tok, sess in pairs(M.state.sessions) do
    if sess.username == target then M.state.sessions[tok] = nil end
  end
  M.state.counters.total_users = math.max(0, (M.state.counters.total_users or 0) - 1)
  audit("OP:" .. s.username, "ADMIN_DELETE_USER", target, nil)
  M.saveState()
  return true, { ok = true }
end

handlers.admin_reset_password = function(payload, ctx)
  local s, err = requireOp(payload); if not s then return false, err end
  local target = string.lower(C.trim(payload.username or ""))
  local u = M.state.users[target]
  if not u then return false, "UNKNOWN_RECIPIENT" end
  if u.is_system then return false, "INSUFFICIENT_PERMISSIONS" end
  if type(payload.new_password_hash) ~= "string" or #payload.new_password_hash ~= 64 then
    return false, "INVALID_REQUEST"
  end
  u.password_hash = payload.new_password_hash
  u.must_change_password = true
  -- Drop user's sessions
  for tok, sess in pairs(M.state.sessions) do
    if sess.username == target then M.state.sessions[tok] = nil end
  end
  audit("OP:" .. s.username, "ADMIN_RESET_PASSWORD", target, nil)
  M.saveState()
  return true, { ok = true }
end

handlers.admin_view_user_inbox = function(payload, ctx)
  local s, err = requireOp(payload); if not s then return false, err end
  local target = string.lower(C.trim(payload.username or ""))
  local mb = M.state.mailboxes[target]
  if not mb then return false, "UNKNOWN_RECIPIENT" end
  local folder = payload.folder or "inbox"
  local list = mb[folder]; if not list then return false, "INVALID_REQUEST" end
  local out = {}
  for i = 1, math.min(tonumber(payload.limit) or 50, #list) do
    local m = M.state.messages[list[i].msg_id]
    if m then out[#out + 1] = summarize(list[i], m) end
  end
  audit("OP:" .. s.username, "ADMIN_VIEW_INBOX", target,
        "n=" .. tostring(#out))
  return true, { messages = out }
end

handlers.admin_view_message = function(payload, ctx)
  local s, err = requireOp(payload); if not s then return false, err end
  local m = M.state.messages[payload.message_id]
  if not m then return false, "UNKNOWN_RECIPIENT" end
  audit("OP:" .. s.username, "ADMIN_VIEW_MESSAGE",
        payload.username or "?", "id=" .. payload.message_id)
  return true, { message = m }
end

handlers.admin_set_branding = function(payload, ctx)
  local s, err = requireOp(payload); if not s then return false, err end
  if type(payload.branding) ~= "table" then return false, "INVALID_REQUEST" end
  M.state.domain_meta.branding = {
    display_name  = tostring(payload.branding.display_name or M.config.domain),
    sign_off      = payload.branding.sign_off,
    theme_palette = payload.branding.theme_palette,
  }
  M.config.branding = M.state.domain_meta.branding
  -- Best-effort propagate to registry
  sendToRegistry("update_branding", {
    branding = M.state.domain_meta.branding,
  })
  audit("OP:" .. s.username, "ADMIN_SET_BRANDING", M.config.domain, nil)
  M.saveState()
  return true, { ok = true }
end

handlers.admin_domain_stats = function(payload, ctx)
  local s, err = requireOp(payload); if not s then return false, err end
  local users, msgs = 0, 0
  for _ in pairs(M.state.users) do users = users + 1 end
  for _ in pairs(M.state.messages) do msgs = msgs + 1 end
  local recent = {}
  for i = math.max(1, #M.state.audit_log - 19), #M.state.audit_log do
    recent[#recent + 1] = M.state.audit_log[i]
  end
  return true, {
    user_count       = users,
    msg_count        = msgs,
    storage_used     = msgs,
    recent_activity  = recent,
    domain_status    = M.domain_status,
  }
end

-- ===== Server-bound (POSTROOM/REG, from registry) ==========================

handlers.deliver_mail = function(payload, ctx, request)
  -- Verified by dispatch with shared_secret
  if ctx.kind ~= "REGISTRY" then return false, "AUTH_FAILED" end
  if M.domain_status == "REVOKED" then return false, "DOMAIN_REVOKED" end
  if type(payload.to_list) ~= "table" then return false, "INVALID_REQUEST" end

  local body = ""
  if request.body and request.body ~= "" then
    local ctxKey = "mail:" .. (payload.message_id or "?")
    local pt, derr = crypto.decrypt(request.body, M.shared_secret, ctxKey)
    if not pt then return false, "INVALID_REQUEST" end
    body = pt
  end

  local localId = nextMsgId()
  M.state.messages[localId] = {
    id = localId,
    from         = payload.from,
    to           = payload.to_list,
    subject      = payload.subject,
    body         = body,
    sent_at      = payload.sent_at or C.now(),
    sent_day     = C.currentDay(),
    origin_server = payload.origin,
  }
  M.state.counters.total_messages = (M.state.counters.total_messages or 0) + 1

  local accepted = {}
  for _, addr in ipairs(payload.to_list) do
    local user, dom = C.parseAddress(addr)
    if dom == M.config.domain and M.state.users[user] then
      addToInbox(user, localId, { unread = true })
      accepted[#accepted + 1] = addr
    end
  end
  audit("REGISTRY", "DELIVER_MAIL", localId,
        "from=" .. payload.from .. " accepted=" .. #accepted)
  M.saveState()
  return true, { accepted_recipients = accepted }
end

handlers.notify_revoked = function(payload, ctx)
  if ctx.kind ~= "REGISTRY" then return false, "AUTH_FAILED" end
  M.domain_status = "REVOKED"
  -- System mail to op
  for username, u in pairs(M.state.users) do
    if u.is_op then
      local id = nextMsgId()
      M.state.messages[id] = {
        id = id, from = "pm@nna",
        to = { username .. "@" .. M.config.domain },
        subject  = "Notice of Revocation — @" .. M.config.domain,
        body     = ("Your domain @%s has been revoked.\nReason: %s\n"):format(
                   M.config.domain, payload.reason or "(unspecified)"),
        sent_at  = C.now(), sent_day = C.currentDay(),
      }
      addToInbox(username, id, { unread = true })
    end
  end
  audit("REGISTRY", "NOTIFY_REVOKED", M.config.domain, payload.reason)
  M.saveState()
  return true, { ok = true }
end

handlers.notify_renewal = function(payload, ctx)
  if ctx.kind ~= "REGISTRY" then return false, "AUTH_FAILED" end
  for username, u in pairs(M.state.users) do
    if u.is_op then
      local id = nextMsgId()
      M.state.messages[id] = {
        id = id, from = "pm@nna",
        to = { username .. "@" .. M.config.domain },
        subject = "Notice of Renewal — @" .. M.config.domain,
        body = ("Your domain @%s is due for renewal.\nDays remaining: %s\nFee: %sƒ\n"):format(
               M.config.domain, tostring(payload.days_until_expiry),
               tostring(payload.fee_due)),
        sent_at = C.now(), sent_day = C.currentDay(),
      }
      addToInbox(username, id, { unread = true })
    end
  end
  audit("REGISTRY", "NOTIFY_RENEWAL", M.config.domain,
        "days=" .. tostring(payload.days_until_expiry))
  M.saveState()
  return true, { ok = true }
end

handlers.notify_suspended = function(payload, ctx)
  if ctx.kind ~= "REGISTRY" then return false, "AUTH_FAILED" end
  M.domain_status = "SUSPENDED"
  for username, u in pairs(M.state.users) do
    if u.is_op then
      local id = nextMsgId()
      M.state.messages[id] = {
        id = id, from = "pm@nna",
        to = { username .. "@" .. M.config.domain },
        subject = "Notice of Suspension — @" .. M.config.domain,
        body = ("Your domain @%s has been suspended.\nReason: %s\n"):format(
               M.config.domain, payload.reason or "(unspecified)"),
        sent_at = C.now(), sent_day = C.currentDay(),
      }
      addToInbox(username, id, { unread = true })
    end
  end
  audit("REGISTRY", "NOTIFY_SUSPENDED", M.config.domain, payload.reason)
  M.saveState()
  return true, { ok = true }
end

-- Triggered by registry on transfer: replace op's password hash.
handlers.admin_op_reset = function(payload, ctx)
  if ctx.kind ~= "REGISTRY" then return false, "AUTH_FAILED" end
  if type(payload.new_password_hash) ~= "string" or #payload.new_password_hash ~= 64 then
    return false, "INVALID_REQUEST"
  end
  for username, u in pairs(M.state.users) do
    if u.is_op then
      u.password_hash = payload.new_password_hash
      u.must_change_password = true
      -- Drop op's sessions
      for tok, sess in pairs(M.state.sessions) do
        if sess.username == username then M.state.sessions[tok] = nil end
      end
      audit("REGISTRY", "ADMIN_OP_RESET", username, nil)
      M.saveState()
      return true, { ok = true }
    end
  end
  return false, "UNKNOWN_RECIPIENT"
end

M.handlers = handlers

-- =============================================================
-- Dispatch
-- =============================================================

-- POSTROOM/USR actions that are pre-session (no HMAC sig verification).
local UNSIGNED_USR = { register = true, login = true }

function M.dispatch(req)
  local ok, err = wire.validateRequest(req)
  if not ok then return false, "INVALID_REQUEST", nil end

  local action = req.action
  local h = handlers[action]
  if not h then return false, "UNKNOWN_ACTION", nil end

  if req.proto == "POSTROOM/REG" then
    -- Server-bound from registry. Sender must be NNA_REG, signed with our secret.
    if req.station ~= M.config.registry_station then
      return false, "AUTH_FAILED", nil
    end
    if not M.shared_secret or not wire.verify(req, M.shared_secret) then
      return false, "AUTH_FAILED", nil
    end
    if not wire.checkNonce(M.nonce_store, req.station, req.nonce) then
      return false, "AUTH_FAILED", nil
    end
    local rok, rdata = h(req.payload or {}, { kind = "REGISTRY", request = req }, req)
    return rok, rdata, { sign_with = M.shared_secret }
  end

  if req.proto == "POSTROOM/USR" then
    if UNSIGNED_USR[action] then
      -- Pre-session: no sig check, no nonce store usage
      local rok, rdata = h(req.payload or {}, { kind = "USR", request = req }, req)
      -- Sign response with the new session token (if any) so the client can verify.
      local respSecret = nil
      if rok and rdata and rdata.session_token then
        respSecret = rdata.session_token
      end
      return rok, rdata, { sign_with = respSecret }
    end
    -- Authenticated USR: HMAC keyed on session token
    local token = req.payload and req.payload.session_token
    if type(token) ~= "string" then return false, "AUTH_FAILED", nil end
    local s = M.state.sessions[token]
    if not s then return false, "AUTH_FAILED", nil end
    if not wire.verify(req, token) then return false, "AUTH_FAILED", nil end
    if not wire.checkNonce(M.nonce_store, req.station, req.nonce) then
      return false, "AUTH_FAILED", nil
    end
    local rok, rdata = h(req.payload or {}, { kind = "USR", session = s, request = req }, req)
    return rok, rdata, { sign_with = token }
  end

  return false, "INVALID_REQUEST", nil
end

-- =============================================================
-- Init + main loop
-- =============================================================

-- Initialize: load config, state, secret. Does not open modems.
function M.init(config)
  assert(config and config.station and config.domain,
         "mail_server.init: need { station, domain, ... }")
  M.config = {
    station          = config.station,
    domain           = config.domain,
    is_public_server = config.is_public_server and true or false,
    registry_station = config.registry_station or "NNA_REG",
    branding         = config.branding or defaultBranding(config.domain),
  }
  M.loadState()
  M.loadSecret()
  -- Persist branding into state (in case wrapper passed updated branding)
  M.state.domain_meta.branding = M.state.domain_meta.branding or M.config.branding
  return M
end

function M.run(config)
  M.init(config)
  if not rednet then
    print("[boot] rednet unavailable — exiting")
    return
  end
  if not M.shared_secret then
    print("[boot] no shared secret at " .. M.SECRET_PATH ..
          " — server cannot federate. Set up first via install or admin tooling.")
  end
  M.ensureSystemAccounts()
  local ok, side = wire.openModem()
  if not ok then
    print("[boot] no modem found — exiting"); return
  end
  rednet.host(wire.PROTOCOL, M.config.station)
  print(("[boot] %s online (@%s) on %s"):format(
        M.config.station, M.config.domain, side))
  M.heartbeatTick()
  M.dailyTick()

  local hbTimer  = os.startTimer(M.HEARTBEAT_INTERVAL_SEC)
  local houseTimer = os.startTimer(M.MAIN_TICK_SEC)
  while true do
    local ev, a, b, c = os.pullEvent()
    if ev == "rednet_message" then
      local sender, msg, proto = a, b, c
      if proto == wire.PROTOCOL and type(msg) == "table" and msg.type == "req" then
        local rok, rdata, opts = M.dispatch(msg)
        opts = opts or {}
        local secret = opts.sign_with or M.shared_secret or "PUBLIC"
        local response = wire.buildResponse(M.config.station, msg, rok, rdata, secret)
        rednet.send(sender, response, wire.PROTOCOL)
      end
    elseif ev == "timer" and a == hbTimer then
      M.heartbeatTick()
      hbTimer = os.startTimer(M.HEARTBEAT_INTERVAL_SEC)
    elseif ev == "timer" and a == houseTimer then
      M.dailyTick()
      houseTimer = os.startTimer(M.MAIN_TICK_SEC)
    end
  end
end

return M
