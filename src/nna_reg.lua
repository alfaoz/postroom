-- /postroom/nna_reg.lua
-- N.N.A. Registry server.
-- Holds the domain registry, install tokens, staff accounts, audit + billing
-- logs. Routes mail between domain servers. Runs the daily lifecycle tick.
--
-- This file is a Lua module: require()ing it gives you the handler table for
-- testing without starting the rednet loop. Running it directly (via CC shell
-- or `lua nna_reg.lua`) also calls M.run() at the bottom.

package.path = package.path
  .. ";/postroom/lib/?.lua"
  .. ";./src/lib/?.lua"
  .. ";./?.lua"

local crypto = require("crypto")
local wire   = require("wire")
local C      = require("common")

local M = {}

-- =============================================================
-- Constants
-- =============================================================

M.STATION              = "NNA_REG"
M.STATE_PATH           = "/postroom/state.txt"
M.STAFF_SECRET_PATH    = "/postroom/staff_secret"
M.AUDIT_MAX            = 1000

M.STAFF_SESSION_TTL_MS = 60 * 60 * 1000          -- 1 hour idle
M.HEARTBEAT_OFFLINE_MS = 180 * 1000              -- 3 minutes
M.SEND_TIMEOUT_SEC     = 5
M.MAIN_TICK_INTERVAL   = 30                       -- run housekeeping every 30s

M.WARN_DAYS            = { 4, 2, 0 }
M.GRACE_DAYS           = 4
M.SUSPEND_TO_REVOKE    = 30                       -- days from expiry → revocation
M.REVOKED_HOLD_DAYS    = 30                       -- days name is held after revocation
M.REVOKED_PURGE_DAYS   = 60                       -- days then domain record purged

-- =============================================================
-- Module-level state (loaded on boot)
-- =============================================================

M.state        = nil
M.staff_secret = nil
M.nonce_store  = wire.newNonceStore(250)

local function defaultState()
  return {
    domains          = {},
    install_tokens   = {},
    staff_accounts   = {},
    staff_sessions   = {},
    public_domains   = {
      -- @nmail and @common populate server_id when their server installs
      { domain = "nmail",  server_id = nil },
      { domain = "common", server_id = nil },
    },
    audit_log        = {},
    billing_log      = {},
    counters         = {
      domains_registered    = 0,
      install_tokens_issued = 0,
      messages_routed       = 0,
    },
    last_tick_day    = -1,
  }
end

local function mergeDefaults(s)
  local d = defaultState()
  for k, v in pairs(d) do
    if s[k] == nil then s[k] = v end
  end
  return s
end

function M.loadState()
  local s = nil
  if fs and fs.exists and fs.exists(M.STATE_PATH) then
    s = C.loadTable(M.STATE_PATH)
  end
  M.state = mergeDefaults(s or defaultState())
  return M.state
end

function M.saveState()
  if fs then C.saveTable(M.STATE_PATH, M.state) end
end

-- For tests: bypass disk and seed in-memory state.
function M.setState(s)
  M.state = mergeDefaults(s or defaultState())
end

-- =============================================================
-- Audit, billing, IDs
-- =============================================================

local function audit(actor, action, target, details)
  local entry = {
    day     = C.currentDay(),
    time    = C.nowSec(),
    actor   = actor,
    action  = action,
    target  = target,
    details = details,
  }
  C.appendLog(M.state.audit_log, entry, M.AUDIT_MAX)
  return entry
end
M.audit = audit

local function bill(domain, fee_type, amount, processed_by)
  local entry = {
    day          = C.currentDay(),
    domain       = domain,
    fee_type     = fee_type,
    amount       = amount,
    processed_by = processed_by,
  }
  M.state.billing_log[#M.state.billing_log + 1] = entry
  return entry
end
M.bill = bill

-- =============================================================
-- Staff secret + bootstrap
-- =============================================================

function M.loadStaffSecret()
  if not fs then return nil end
  if not fs.exists(M.STAFF_SECRET_PATH) then return nil end
  local f = fs.open(M.STAFF_SECRET_PATH, "r")
  local s = C.trim(f.readAll() or "")
  f.close()
  if s == "" then return nil end
  return s
end

function M.ensureStaffSecret()
  if not fs then return nil end
  local s = M.loadStaffSecret()
  if s then return s end
  s = crypto.randomHex(32)
  local dir = fs.getDir(M.STAFF_SECRET_PATH)
  if dir ~= "" and not fs.exists(dir) then fs.makeDir(dir) end
  local f = fs.open(M.STAFF_SECRET_PATH, "w")
  f.write(s); f.close()
  print("[boot] generated staff secret at " .. M.STAFF_SECRET_PATH)
  print("[boot] copy this to NNA_STAFF: " .. s)
  return s
end

function M.ensureBootstrapAdmin()
  if next(M.state.staff_accounts) ~= nil then return end
  local pw = crypto.hashPassword("nna", "admin", "changeme")
  M.state.staff_accounts["admin"] = {
    username       = "admin",
    password_hash  = pw,
    display_name   = "System Administrator",
    added_day      = C.currentDay(),
    added_by       = "BOOTSTRAP",
    active         = true,
    is_admin       = true,
    last_login_day = nil,
  }
  audit("BOOTSTRAP", "CREATE_STAFF", "admin", "default password 'changeme'")
  M.saveState()
end

-- =============================================================
-- Auth helpers
-- =============================================================

-- Look up the secret used to verify HMAC for a given station + action.
-- Returns secret, principal_kind, principal_id  -- or nil if unverifiable.
function M.findVerifySecret(station, action, payload)
  -- Public unsigned actions (handled separately, no secret needed)
  if action == "domain_status" or action == "list_public_domains" then
    return nil, "PUBLIC", nil
  end
  -- Install bootstrap: HMAC keyed on the install token
  if action == "consume_install_token" then
    local token = payload and payload.token
    if type(token) ~= "string" then return nil end
    local rec = M.state.install_tokens[token]
    if rec and rec.status == "PENDING" then
      return token, "INSTALL_TOKEN", token
    end
    return nil
  end
  -- Staff terminal
  if station == "NNA_STAFF" then
    return M.staff_secret, "STAFF_TERMINAL", "NNA_STAFF"
  end
  -- Domain server: station name must be <UPPERDOMAIN>_SRV
  local upper = station and station:match("^(.-)_SRV$")
  if upper then
    local domainName = string.lower(upper)
    local d = M.state.domains[domainName]
    if d and d.shared_secret then
      return d.shared_secret, "DOMAIN_SRV", domainName
    end
  end
  return nil
end

-- Verify and consume a staff session_token from a payload field.
-- Returns the session table on success, or nil + error code.
function M.checkStaffSession(token)
  if type(token) ~= "string" then return nil, "AUTH_FAILED" end
  local s = M.state.staff_sessions[token]
  if not s then return nil, "AUTH_FAILED" end
  local now = C.now()
  if s.expires_at and now > s.expires_at then
    M.state.staff_sessions[token] = nil
    return nil, "AUTH_FAILED"
  end
  s.last_used_at = now
  s.expires_at   = now + M.STAFF_SESSION_TTL_MS
  return s
end

-- =============================================================
-- Daily tick (idempotent)
-- =============================================================

local function notifyServer(domainRec, action, payload, body, body_context)
  if not domainRec or not domainRec.server_id or not domainRec.shared_secret then
    return nil, "no_server_id"
  end
  if not rednet then return nil, "rednet_unavailable" end
  local opts = nil
  if body then
    opts = { body = body, encrypted_body = true,
             body_context = body_context or "notify:" .. action }
  end
  local data, err = wire.sendRequest(
    domainRec.server_id, M.STATION, "POSTROOM/REG", action,
    payload, domainRec.shared_secret, M.SEND_TIMEOUT_SEC, opts)
  return data, err
end
M.notifyServer = notifyServer

-- Run the daily lifecycle pass. Idempotent: re-running on same day is a no-op
-- past the first run unless `force` is true.
function M.dailyTick(force)
  local today = C.currentDay()
  if not force and M.state.last_tick_day == today then return end

  local notifications = {}  -- collected; sent after state mutations + save

  for name, d in pairs(M.state.domains) do
    if d.status == "ACTIVE" or d.status == "SUSPENDED" then
      local daysToExpiry = d.expires_day - today

      -- 1. Renewal warnings: ACTIVE only, at -4, -2, 0 days
      if d.status == "ACTIVE" then
        for _, w in ipairs(M.WARN_DAYS) do
          if daysToExpiry == w then
            notifications[#notifications + 1] = {
              kind = "renewal", domain = name,
              days = w, fee = C.FEES.renewal + C.FEES.nna_share,
            }
          end
        end
      end

      -- 2. Suspension transition: expired more than GRACE_DAYS, still ACTIVE
      if d.status == "ACTIVE" and (today - d.expires_day) > M.GRACE_DAYS then
        d.status = "SUSPENDED"
        d.suspended_day = today
        audit("SYSTEM", "SUSPEND_DOMAIN", name,
              "auto-suspended after " .. M.GRACE_DAYS .. "-day grace")
        notifications[#notifications + 1] = {
          kind = "suspended", domain = name, reason = "non-payment",
        }
      end

      -- 3. Revocation transition: expired more than SUSPEND_TO_REVOKE days
      if d.status == "SUSPENDED" and (today - d.expires_day) >= M.SUSPEND_TO_REVOKE then
        d.status = "REVOKED"
        d.revoked_day = today
        audit("SYSTEM", "REVOKE_DOMAIN", name, "auto-revoked after non-payment")
        notifications[#notifications + 1] = {
          kind = "revoked", domain = name, reason = "non-payment",
        }
      end
    end
  end

  -- 4. Expire install tokens past their issued_day + lifecycle
  for token, rec in pairs(M.state.install_tokens) do
    if rec.status == "PENDING" and rec.expires_day and today > rec.expires_day then
      rec.status = "EXPIRED"
      audit("SYSTEM", "EXPIRE_INSTALL_TOKEN", rec.domain_name,
            "token unused past day " .. rec.expires_day)
    end
  end

  -- 5. Cleanup: revoked domains older than REVOKED_PURGE_DAYS, name returns to pool
  local toPurge = {}
  for name, d in pairs(M.state.domains) do
    if d.status == "REVOKED" and d.revoked_day
       and (today - d.revoked_day) >= M.REVOKED_PURGE_DAYS then
      toPurge[#toPurge + 1] = name
    end
  end
  for _, name in ipairs(toPurge) do
    M.state.domains[name] = nil
    audit("SYSTEM", "PURGE_DOMAIN", name, "name returned to pool")
  end

  M.state.last_tick_day = today
  M.saveState()

  -- Now send notifications. These can fail silently — receivers may be offline.
  for _, n in ipairs(notifications) do
    local d = M.state.domains[n.domain]
    if d then
      if n.kind == "renewal" then
        notifyServer(d, "notify_renewal",
          { domain = n.domain, days_until_expiry = n.days, fee_due = n.fee })
      elseif n.kind == "suspended" then
        notifyServer(d, "notify_suspended",
          { domain = n.domain, reason = n.reason })
      elseif n.kind == "revoked" then
        notifyServer(d, "notify_revoked",
          { domain = n.domain, reason = n.reason })
      end
    end
  end
end

-- =============================================================
-- Helpers used by handlers
-- =============================================================

local function isDomainOnline(d)
  if not d.last_heartbeat_at then return false end
  return (C.now() - d.last_heartbeat_at) < M.HEARTBEAT_OFFLINE_MS
end

local function publicView(d)
  return {
    name           = d.name,
    status         = d.status,
    server_id      = d.server_id,
    server_online  = isDomainOnline(d),
    branding       = d.branding,
    expires_day    = d.expires_day,
    is_public      = d.is_public,
  }
end

local function staffView(d)
  return {
    name              = d.name,
    owner_realname    = d.owner_realname,
    owner_username    = d.owner_username,
    registered_day    = d.registered_day,
    expires_day       = d.expires_day,
    status            = d.status,
    server_id         = d.server_id,
    server_online     = isDomainOnline(d),
    last_heartbeat_at = d.last_heartbeat_at,
    branding          = d.branding,
    revoked_day       = d.revoked_day,
    suspended_day     = d.suspended_day,
  }
end

-- =============================================================
-- Action handlers
-- Each: function(payload, ctx) -> ok, dataOrError
-- ctx = { kind, principal, station, request }
-- =============================================================

local handlers = {}

-- Domain server → registry --------------------------------------------------

handlers.heartbeat = function(payload, ctx)
  if ctx.kind ~= "DOMAIN_SRV" then return false, "AUTH_FAILED" end
  local d = M.state.domains[ctx.principal]
  if not d then return false, "UNKNOWN_DOMAIN" end
  if d.status == "REVOKED" then return false, "DOMAIN_REVOKED" end
  d.last_heartbeat_at  = C.now()
  d.last_heartbeat_day = C.currentDay()
  -- Domain server's reported server_id keeps us aligned if it changed
  if payload.server_id and not d.server_id then
    d.server_id = payload.server_id
  end
  return true, {
    registry_time   = C.nowSec(),
    registry_day    = C.currentDay(),
    domain_status   = d.status,
    expires_day     = d.expires_day,
  }
end

handlers.route_mail = function(payload, ctx, request)
  if ctx.kind ~= "DOMAIN_SRV" then return false, "AUTH_FAILED" end
  local senderDomain = M.state.domains[ctx.principal]
  if not senderDomain then return false, "UNKNOWN_DOMAIN" end
  if senderDomain.status ~= "ACTIVE" then return false, "DOMAIN_SUSPENDED" end

  if type(payload.to_list) ~= "table" or #payload.to_list == 0 then
    return false, "INVALID_REQUEST"
  end
  if type(payload.from) ~= "string" or type(payload.subject) ~= "string" then
    return false, "INVALID_REQUEST"
  end

  -- Decrypt body using sender-domain secret + the sender's body context
  local plainBody = ""
  if request.body and request.body ~= "" then
    local body_ctx = payload.body_context or ("mail:" .. (payload.message_id or "?"))
    local pt, err = crypto.decrypt(request.body, senderDomain.shared_secret, body_ctx)
    if not pt then
      return false, "INVALID_REQUEST"  -- body did not decrypt
    end
    plainBody = pt
  end

  local results = {}
  for _, addr in ipairs(payload.to_list) do
    local user, dom = C.parseAddress(addr)
    if not user or not dom then
      results[#results + 1] = { recipient = addr, status = "INVALID_ADDRESS" }
    elseif dom == ctx.principal then
      -- Same-domain delivery should be handled locally on the sender's server,
      -- not routed. Return a notice; the mail server will drop it.
      results[#results + 1] = { recipient = addr, status = "LOCAL" }
    else
      local destDomain = M.state.domains[dom]
      if not destDomain then
        results[#results + 1] = { recipient = addr, status = "UNKNOWN_DOMAIN" }
      elseif destDomain.status == "REVOKED" then
        results[#results + 1] = { recipient = addr, status = "DOMAIN_REVOKED" }
      elseif destDomain.status == "SUSPENDED" then
        results[#results + 1] = { recipient = addr, status = "DOMAIN_SUSPENDED" }
      elseif not isDomainOnline(destDomain) then
        results[#results + 1] = { recipient = addr, status = "DOMAIN_OFFLINE" }
      else
        -- Re-encrypt body with destination's secret + a fresh per-message context
        local msgId = payload.message_id or
          (("ROUTE-" .. tostring(C.now()) .. "-" .. crypto.randomHex(4)))
        local destCtx = "mail:" .. msgId
        local data, err = notifyServer(destDomain, "deliver_mail", {
          from        = payload.from,
          to_list     = { addr },
          subject     = payload.subject,
          sent_at     = payload.sent_at,
          message_id  = msgId,
          origin      = ctx.principal,
        }, plainBody, destCtx)
        if data then
          results[#results + 1] = { recipient = addr, status = "DELIVERED" }
        else
          local code = (err == "timeout") and "DOMAIN_OFFLINE" or "DELIVERY_FAILED"
          results[#results + 1] = { recipient = addr, status = code, reason = err }
        end
      end
    end
  end

  M.state.counters.messages_routed = (M.state.counters.messages_routed or 0) + 1
  M.saveState()
  return true, { delivery_results = results }
end

handlers.consume_install_token = function(payload, ctx)
  if ctx.kind ~= "INSTALL_TOKEN" then return false, "AUTH_FAILED" end
  local token = payload.token
  local rec = M.state.install_tokens[token]
  if not rec or rec.status ~= "PENDING" then return false, "INVALID_TOKEN" end
  if rec.expires_day and C.currentDay() > rec.expires_day then
    rec.status = "EXPIRED"
    M.saveState()
    return false, "INVALID_TOKEN"
  end
  if type(payload.computer_id) ~= "number" then return false, "INVALID_REQUEST" end

  local d = M.state.domains[rec.domain_name]
  if not d then return false, "UNKNOWN_DOMAIN" end
  if d.status ~= "PENDING_INSTALL" then return false, "DOMAIN_ALREADY_ACTIVE" end

  local secret = crypto.randomHex(32)
  local opTempPw = crypto.formatToken(crypto.randomToken(16))

  rec.status        = "CONSUMED"
  rec.consumed_by_id = payload.computer_id
  rec.consumed_day  = C.currentDay()

  d.status        = "ACTIVE"
  d.server_id     = payload.computer_id
  d.shared_secret = secret
  d.activated_day = C.currentDay()

  audit("INSTALL", "CONSUME_TOKEN", rec.domain_name,
        "computer_id=" .. tostring(payload.computer_id))
  M.saveState()

  return true, {
    shared_secret      = secret,
    domain             = rec.domain_name,
    op_username        = rec.requested_op,
    op_initial_password = opTempPw,
    registry_settings  = {
      station         = M.STATION,
      heartbeat_secs  = 60,
    },
  }
end

handlers.update_branding = function(payload, ctx)
  if ctx.kind ~= "DOMAIN_SRV" then return false, "AUTH_FAILED" end
  local d = M.state.domains[ctx.principal]
  if not d then return false, "UNKNOWN_DOMAIN" end
  if type(payload.branding) ~= "table" then return false, "INVALID_REQUEST" end
  d.branding = {
    display_name  = tostring(payload.branding.display_name or d.name),
    theme_palette = payload.branding.theme_palette,
    sign_off      = payload.branding.sign_off,
  }
  M.saveState()
  return true, { ok = true }
end

-- Staff → registry ----------------------------------------------------------

handlers.staff_login = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  if type(payload.username) ~= "string" or type(payload.password_hash) ~= "string" then
    return false, "INVALID_REQUEST"
  end
  local acct = M.state.staff_accounts[string.lower(payload.username)]
  if not acct or not acct.active then return false, "BAD_CREDENTIALS" end
  if acct.password_hash ~= payload.password_hash then
    return false, "BAD_CREDENTIALS"
  end

  -- Single concurrent session: boot any prior session
  for tok, s in pairs(M.state.staff_sessions) do
    if s.username == acct.username then M.state.staff_sessions[tok] = nil end
  end

  local token = crypto.randomHex(32)
  local now = C.now()
  M.state.staff_sessions[token] = {
    token        = token,
    username     = acct.username,
    terminal_id  = payload.terminal_computer_id,
    created_at   = now,
    last_used_at = now,
    expires_at   = now + M.STAFF_SESSION_TTL_MS,
    is_admin     = acct.is_admin or false,
  }
  acct.last_login_day = C.currentDay()
  audit("STAFF:" .. acct.username, "LOGIN", acct.username,
        "terminal=" .. tostring(payload.terminal_computer_id))
  M.saveState()
  return true, {
    session_token     = token,
    staff_display_name = acct.display_name,
    is_admin          = acct.is_admin or false,
  }
end

handlers.staff_logout = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s = M.state.staff_sessions[payload.session_token]
  if s then
    M.state.staff_sessions[payload.session_token] = nil
    audit("STAFF:" .. s.username, "LOGOUT", s.username, nil)
    M.saveState()
  end
  return true, { ok = true }
end

-- Names the N.N.A. itself is meant to issue (per DESIGN §0.2 / §8.6). Admin
-- staff can register these; non-admin staff and customers cannot.
M.ISSUABLE_BY_ADMIN = {
  gov = true, nna = true, nta = true, nga = true,
  nmail = true, common = true,
}

handlers.register_domain = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s, err = M.checkStaffSession(payload.session_token)
  if not s then return false, err end

  local name = string.lower(C.trim(payload.domain_name or ""))
  local allowReserved = s.is_admin and M.ISSUABLE_BY_ADMIN[name] or false
  local ok, verr = C.validateDomainName(name, allowReserved)
  if not ok then return false, "INVALID_DOMAIN:" .. (verr or "") end
  if M.state.domains[name] then return false, "DOMAIN_TAKEN" end

  local opUser = string.lower(C.trim(payload.op_username or ""))
  local oku, uerr = C.validateUsername(opUser, allowReserved)
  if not oku then return false, "INVALID_USERNAME:" .. (uerr or "") end

  if not payload.applicant_realname or payload.applicant_realname == "" then
    return false, "INVALID_REQUEST"
  end

  local today = C.currentDay()
  local expiresDay = today + C.LIFECYCLE.domain_validity_days
  local tokenStr = crypto.randomToken(16)

  M.state.domains[name] = {
    name              = name,
    owner_username    = opUser,
    owner_realname    = payload.applicant_realname,
    registered_day    = today,
    expires_day       = expiresDay,
    status            = "PENDING_INSTALL",
    server_id         = nil,
    shared_secret     = nil,
    branding          = { display_name = name, sign_off = nil },
    last_heartbeat_at = nil,
    created_by_staff  = s.username,
    is_public         = false,
  }
  M.state.install_tokens[tokenStr] = {
    token            = tokenStr,
    domain_name      = name,
    requested_op     = opUser,
    issued_day       = today,
    expires_day      = today + C.LIFECYCLE.install_token_days,
    status           = "PENDING",
    issued_by_staff  = s.username,
  }
  M.state.counters.domains_registered    = (M.state.counters.domains_registered or 0) + 1
  M.state.counters.install_tokens_issued = (M.state.counters.install_tokens_issued or 0) + 1

  bill(name, "APPLICATION",  C.FEES.application,  "STAFF:" .. s.username)
  bill(name, "REGISTRATION", C.FEES.registration, "STAFF:" .. s.username)
  bill(name, "NNA_SHARE",    C.FEES.nna_share * 2,"STAFF:" .. s.username)

  audit("STAFF:" .. s.username, "REGISTER_DOMAIN", name,
        "owner=" .. payload.applicant_realname .. " op=" .. opUser)
  M.saveState()
  return true, {
    install_token = tokenStr,
    formatted_token = crypto.formatToken(tokenStr),
    expires_day   = today + C.LIFECYCLE.install_token_days,
    domain        = name,
    op_username   = opUser,
  }
end

handlers.renew_domain = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s, err = M.checkStaffSession(payload.session_token)
  if not s then return false, err end

  local name = string.lower(C.trim(payload.domain_name or ""))
  local d = M.state.domains[name]
  if not d then return false, "UNKNOWN_DOMAIN" end
  if d.status == "REVOKED" then return false, "DOMAIN_REVOKED" end

  local today = C.currentDay()
  -- Renewal extends from whichever is later: today, or current expires_day.
  local base = math.max(today, d.expires_day or today)
  d.expires_day = base + C.LIFECYCLE.domain_validity_days
  -- If they were SUSPENDED, return them to ACTIVE (reinstatement)
  local wasSuspended = (d.status == "SUSPENDED")
  if wasSuspended then
    d.status = "ACTIVE"
    d.suspended_day = nil
  end

  bill(name, "RENEWAL",  C.FEES.renewal,   "STAFF:" .. s.username)
  bill(name, "NNA_SHARE", C.FEES.nna_share, "STAFF:" .. s.username)
  if wasSuspended then
    bill(name, "REINSTATEMENT", 8, "STAFF:" .. s.username)
  end
  audit("STAFF:" .. s.username, "RENEW_DOMAIN", name,
        "new expiry day=" .. d.expires_day .. (wasSuspended and " (reinstated)" or ""))
  M.saveState()
  return true, { new_expires_day = d.expires_day, status = d.status }
end

handlers.transfer_domain = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s, err = M.checkStaffSession(payload.session_token)
  if not s then return false, err end

  local name = string.lower(C.trim(payload.domain_name or ""))
  local d = M.state.domains[name]
  if not d then return false, "UNKNOWN_DOMAIN" end
  if d.status == "REVOKED" then return false, "DOMAIN_REVOKED" end
  if not payload.new_owner_realname or payload.new_owner_realname == "" then
    return false, "INVALID_REQUEST"
  end
  if not payload.new_op_password_hash then return false, "INVALID_REQUEST" end

  local oldOwner = d.owner_realname
  d.owner_realname = payload.new_owner_realname

  -- Push a password reset to the destination server (best-effort).
  -- The actual op@<domain> password hash is set on the mail server, not here.
  -- We forward the new hash via a special server-bound action.
  if d.server_id and d.shared_secret and rednet then
    wire.sendRequest(d.server_id, M.STATION, "POSTROOM/REG",
      "admin_op_reset",
      { domain = name, new_password_hash = payload.new_op_password_hash },
      d.shared_secret, M.SEND_TIMEOUT_SEC)
  end

  bill(name, "TRANSFER", C.FEES.transfer,  "STAFF:" .. s.username)
  bill(name, "NNA_SHARE", C.FEES.nna_share, "STAFF:" .. s.username)
  audit("STAFF:" .. s.username, "TRANSFER_DOMAIN", name,
        oldOwner .. " -> " .. payload.new_owner_realname)
  M.saveState()
  return true, { ok = true }
end

handlers.revoke_domain = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s, err = M.checkStaffSession(payload.session_token)
  if not s then return false, err end
  if not s.is_admin then return false, "INSUFFICIENT_PERMISSIONS" end

  local name = string.lower(C.trim(payload.domain_name or ""))
  local d = M.state.domains[name]
  if not d then return false, "UNKNOWN_DOMAIN" end
  local reason = payload.reason or ""

  d.status      = "REVOKED"
  d.revoked_day = C.currentDay()
  d.revoke_reason = reason

  audit("STAFF:" .. s.username, "REVOKE_DOMAIN", name, "reason=" .. reason)
  M.saveState()

  -- Notify the server (best-effort).
  if d.server_id and d.shared_secret then
    notifyServer(d, "notify_revoked",
      { domain = name, reason = reason })
  end
  return true, { ok = true, revoked_day = d.revoked_day }
end

handlers.list_domains = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local _, err = M.checkStaffSession(payload.session_token)
  if err then return false, err end
  local out = {}
  local filter = payload.filter
  for _, d in pairs(M.state.domains) do
    if not filter or d.status == filter then
      out[#out + 1] = staffView(d)
    end
  end
  table.sort(out, function(a, b) return a.name < b.name end)
  return true, { domains = out }
end

handlers.list_pending_apps = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local _, err = M.checkStaffSession(payload.session_token)
  if err then return false, err end
  -- Reserved for future: we don't queue applications, registration is direct.
  return true, { pending = {} }
end

handlers.audit_query = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local _, err = M.checkStaffSession(payload.session_token)
  if err then return false, err end
  local since = payload.since_day
  local kind  = payload.kind
  local out = {}
  for _, e in ipairs(M.state.audit_log) do
    if (not since or e.day >= since) and (not kind or e.action == kind) then
      out[#out + 1] = e
    end
  end
  return true, { entries = out }
end

-- Admin: reset the op@<domain> password. Generates a fresh temp password,
-- pushes it to the mail server via admin_op_reset, returns it to the staff
-- terminal for printing on a slip.
handlers.reset_op_password = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s, err = M.checkStaffSession(payload.session_token)
  if not s then return false, err end
  if not s.is_admin then return false, "INSUFFICIENT_PERMISSIONS" end

  local name = string.lower(C.trim(payload.domain_name or ""))
  local d = M.state.domains[name]
  if not d then return false, "UNKNOWN_DOMAIN" end
  if d.status == "REVOKED" then return false, "DOMAIN_REVOKED" end
  if not d.server_id or not d.shared_secret then return false, "DOMAIN_OFFLINE" end

  local newPw = crypto.formatToken(crypto.randomToken(16))
  local opUser = d.owner_username or "op"
  local hash = crypto.hashPassword(name, opUser, newPw)

  local _, derr
  if rednet then
    _, derr = wire.sendRequest(d.server_id, M.STATION, "POSTROOM/REG",
      "admin_op_reset",
      { domain = name, new_password_hash = hash },
      d.shared_secret, M.SEND_TIMEOUT_SEC)
  else
    derr = "rednet_unavailable"
  end

  audit("STAFF:" .. s.username, "RESET_OP_PASSWORD", name,
        "delivery=" .. (derr and "FAILED:" .. tostring(derr) or "OK"))
  M.saveState()
  return true, {
    op_username    = opUser,
    new_password   = newPw,
    delivery_ok    = (derr == nil),
    delivery_error = derr,
  }
end

-- Admin: immediately purge a REVOKED domain record so the name returns to
-- the pool without waiting the full 60-day cooldown.
handlers.purge_domain = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s, err = M.checkStaffSession(payload.session_token)
  if not s then return false, err end
  if not s.is_admin then return false, "INSUFFICIENT_PERMISSIONS" end

  local name = string.lower(C.trim(payload.domain_name or ""))
  local d = M.state.domains[name]
  if not d then return false, "UNKNOWN_DOMAIN" end
  if d.status ~= "REVOKED" then return false, "DOMAIN_NOT_REVOKED" end

  M.state.domains[name] = nil
  audit("STAFF:" .. s.username, "PURGE_DOMAIN", name, "manual purge")
  M.saveState()
  return true, { ok = true }
end

-- Admin: run the daily lifecycle tick on demand. Useful when /time set
-- or other day-skipping leaves domains in a stale state.
handlers.force_tick = function(payload, ctx)
  if ctx.kind ~= "STAFF_TERMINAL" then return false, "AUTH_FAILED" end
  local s, err = M.checkStaffSession(payload.session_token)
  if not s then return false, err end
  if not s.is_admin then return false, "INSUFFICIENT_PERMISSIONS" end

  local before = {}
  for n, d in pairs(M.state.domains) do before[n] = d.status end
  M.dailyTick(true)
  local changes = {}
  for n, d in pairs(M.state.domains) do
    if before[n] and before[n] ~= d.status then
      changes[#changes + 1] = ("@%s: %s -> %s"):format(n, before[n], d.status)
    end
  end
  audit("STAFF:" .. s.username, "FORCE_TICK", "registry",
        "day=" .. C.currentDay() .. " changes=" .. #changes)
  return true, {
    day     = C.currentDay(),
    changes = changes,
  }
end

-- Public actions ------------------------------------------------------------

handlers.domain_status = function(payload, ctx)
  local name = string.lower(C.trim(payload.domain or ""))
  if name == "" then return false, "INVALID_REQUEST" end
  local d = M.state.domains[name]
  if not d then
    return true, { registered = false }
  end
  return true, {
    registered    = true,
    status        = d.status,
    server_id     = d.server_id,
    server_online = isDomainOnline(d),
    branding      = d.branding,
    is_public     = d.is_public,
  }
end

handlers.list_public_domains = function(payload, ctx)
  local out = {}
  for _, p in ipairs(M.state.public_domains) do
    local d = M.state.domains[p.domain]
    if d and d.status == "ACTIVE" then
      out[#out + 1] = {
        name      = d.name,
        server_id = d.server_id,
        branding  = d.branding,
      }
    elseif p.server_id then
      -- Listed in registry but no full domain record yet (early bootstrap)
      out[#out + 1] = { name = p.domain, server_id = p.server_id }
    end
  end
  return true, { domains = out }
end

M.handlers = handlers

-- =============================================================
-- Dispatch
-- =============================================================

local PUBLIC_ACTIONS = {
  domain_status        = true,
  list_public_domains  = true,
}

-- Dispatch a single decoded request. Returns (ok, dataOrError, opts).
-- opts may include { sign_with = secret } so the response is signed with the
-- right key. Caller is responsible for building the wire-format response.
function M.dispatch(req)
  local ok, err = wire.validateRequest(req)
  if not ok then return false, "INVALID_REQUEST", nil end

  local action = req.action
  local h = handlers[action]
  if not h then return false, "UNKNOWN_ACTION", nil end

  -- Public actions: skip HMAC entirely; respond unsigned.
  if PUBLIC_ACTIONS[action] then
    local rok, rdata = h(req.payload or {}, { kind = "PUBLIC" }, req)
    return rok, rdata, { sign_with = nil }
  end

  -- Find verify-secret based on station + action
  local secret, kind, principal = M.findVerifySecret(req.station, action, req.payload)
  if not secret then return false, "AUTH_FAILED", nil end

  if not wire.verify(req, secret) then
    return false, "AUTH_FAILED", nil
  end
  if not wire.checkNonce(M.nonce_store, req.station, req.nonce) then
    return false, "AUTH_FAILED", nil
  end

  local ctx = { kind = kind, principal = principal,
                station = req.station, request = req }
  local rok, rdata = h(req.payload or {}, ctx, req)
  return rok, rdata, { sign_with = secret }
end

-- =============================================================
-- Main loop (CC only)
-- =============================================================

function M.run()
  M.loadState()
  if fs then
    M.staff_secret = M.ensureStaffSecret()
    M.ensureBootstrapAdmin()
  end

  if not rednet then
    print("[boot] rednet not available — exiting")
    return
  end

  local ok, side = wire.openModem()
  if not ok then
    print("[boot] no modem found — exiting")
    return
  end
  rednet.host(wire.PROTOCOL, M.STATION)
  print("[boot] NNA_REG online on " .. side .. " (modem)")
  print("[boot] day " .. C.currentDay() .. ", domains: " ..
        tostring(M.state.counters.domains_registered or 0))

  M.dailyTick()

  local tickTimer = os.startTimer(M.MAIN_TICK_INTERVAL)
  while true do
    local ev, a, b, c = os.pullEvent()
    if ev == "rednet_message" then
      local sender, msg, proto = a, b, c
      if proto == wire.PROTOCOL and type(msg) == "table" and msg.type == "req" then
        local rok, rdata, opts = M.dispatch(msg)
        opts = opts or {}
        local respSecret = opts.sign_with
        local response
        if respSecret then
          response = wire.buildResponse(M.STATION, msg, rok, rdata, respSecret)
        else
          -- Public action: sign with a placeholder; clients won't verify.
          -- We still produce a valid signed-shape message using a public marker key.
          response = wire.buildResponse(M.STATION, msg, rok, rdata, "PUBLIC")
        end
        rednet.send(sender, response, wire.PROTOCOL)
      end
    elseif ev == "timer" and a == tickTimer then
      M.dailyTick()
      tickTimer = os.startTimer(M.MAIN_TICK_INTERVAL)
    end
  end
end

-- Auto-run when invoked directly (CC shell, `lua nna_reg.lua`).
-- Tests set _G._POSTROOM_NO_AUTORUN = true before requiring this module.
if not _G._POSTROOM_NO_AUTORUN then
  M.run()
end

return M
