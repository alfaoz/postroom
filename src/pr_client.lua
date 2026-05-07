-- /postroom/pr_client.lua
-- PR — Postroom mail client. Text-mode UI for v1.
-- Run: pr  (or pr.lua). Talks to whichever mail server hosts the user's domain.

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

M.STATE_PATH        = "/postroom/client.txt"
M.REGISTRY_STATION  = "NNA_REG"
M.REQUEST_TIMEOUT   = 5
M.INBOX_PAGE        = 9     -- max messages shown per page (1-9 keys)

-- =============================================================
-- Local state (persisted) + cache (in-memory)
-- =============================================================

M.state = {
  session            = nil,      -- { username, domain, server_id, token, expires_at }
  remembered_servers = {},
}
M.cache = {
  inbox          = {},
  current_folder = "inbox",
  registry_id    = nil,
  server_id      = nil,
  branding       = nil,
  is_op          = false,
}

local function loadState()
  if not fs then return end
  if not fs.exists(M.STATE_PATH) then return end
  local s = C.loadTable(M.STATE_PATH)
  if s then
    M.state.session            = s.session
    M.state.remembered_servers = s.remembered_servers or {}
  end
end

local function saveState()
  if not fs then return end
  C.saveTable(M.STATE_PATH, {
    session            = M.state.session,
    remembered_servers = M.state.remembered_servers,
  })
end

-- =============================================================
-- Network helpers
-- =============================================================

local function clientStation()
  local id = (os and os.getComputerID and os.getComputerID()) or 0
  return "CLIENT:" .. tostring(id)
end

local function lookupRegistry()
  if M.cache.registry_id then return M.cache.registry_id end
  if not rednet or not rednet.lookup then return nil end
  local id = rednet.lookup(wire.PROTOCOL, M.REGISTRY_STATION)
  M.cache.registry_id = id
  return id
end

-- Public-action call: signed with "PUBLIC" sentinel.
local function callPublic(host, action, payload)
  if not host then return nil, "no_host" end
  return wire.sendRequest(host, clientStation(), "POSTROOM/REG",
    action, payload, "PUBLIC", M.REQUEST_TIMEOUT)
end

-- USR call before login (register/login). Server signs response with "PUBLIC".
local function callPreSession(host, action, payload)
  if not host then return nil, "no_host" end
  return wire.sendRequest(host, clientStation(), "POSTROOM/USR",
    action, payload, "PUBLIC", M.REQUEST_TIMEOUT)
end

-- USR call with session: HMAC keyed on session token.
local function callUSR(action, payload)
  local sess = M.state.session
  if not sess then return nil, "AUTH_FAILED" end
  if not M.cache.server_id then return nil, "NO_SERVER" end
  payload = payload or {}
  payload.session_token = sess.token
  return wire.sendRequest(M.cache.server_id, clientStation(),
    "POSTROOM/USR", action, payload, sess.token, M.REQUEST_TIMEOUT)
end
M.callUSR = callUSR

local function resolveDomain(domain)
  local reg = lookupRegistry()
  if not reg then return nil, "REGISTRY_NOT_FOUND" end
  local data, err = callPublic(reg, "domain_status", { domain = domain })
  if not data then return nil, err end
  if not data.registered then return nil, "UNKNOWN_DOMAIN" end
  if not data.server_online then return nil, "DOMAIN_OFFLINE" end
  return data
end

local function listPublicDomains()
  local reg = lookupRegistry()
  if not reg then return nil, "REGISTRY_NOT_FOUND" end
  local data, err = callPublic(reg, "list_public_domains", {})
  if not data then return nil, err end
  return data.domains or {}
end

-- =============================================================
-- UI primitives
-- =============================================================

local function header(title)
  C.clear()
  C.printHeader(title)
end

local function info(s)  C.printColored("white", s)  end
local function warn(s)  C.printColored("yellow", s) end
local function err(s)   C.printColored("red", s)    end
local function ok(s)    C.printColored("green", s)  end
local function dim(s)   C.printColored("gray", s)   end

-- Read multi-line input, terminated by "." on a line of its own.
local function readMultiline()
  print("(Type your message. End with a single '.' on its own line.)")
  local lines = {}
  while true do
    local s = io.read()
    if not s then break end
    if s == "." then break end
    lines[#lines + 1] = s
  end
  return table.concat(lines, "\n")
end

-- =============================================================
-- Boot screen
-- =============================================================

local function bootScreen()
  C.clear()
  print("")
  C.printColored("yellow", "       POSTROOM · NIO Mail")
  C.printColored("gray",   "       ─────────────────────")
  print("")
  if rednet then
    local reg = lookupRegistry()
    if reg then
      ok(("       Registered with N.N.A. (id=%d)"):format(reg))
    else
      warn("       Registry not found on the network")
    end
  else
    err("       Rednet unavailable. Cannot continue.")
  end
  print("")
  C.pause("Press Enter to continue...")
end

-- =============================================================
-- Sign-in / register
-- =============================================================

local function signInFlow()
  header("Sign In")
  -- Suggest remembered addresses
  if #M.state.remembered_servers > 0 then
    print("Remembered:")
    for i, r in ipairs(M.state.remembered_servers) do
      print(("  %d. %s@%s"):format(i, r.username, r.domain))
    end
    print("  0. Enter a different address")
    local n = C.askNumber("Pick", 0)
    if n > 0 and M.state.remembered_servers[n] then
      io.write("Password: ")
      local pw = read and read("*") or io.read()
      pw = C.trim(pw or "")
      local r = M.state.remembered_servers[n]
      return r.username, r.domain, pw
    end
  end
  local addr = C.askNonEmpty("Address (e.g. alice@nmail)")
  local user, dom = C.parseAddress(addr)
  if not user then err("Invalid address."); C.pause(); return nil end
  io.write("Password: ")
  local pw = read and read("*") or io.read()
  pw = C.trim(pw or "")
  return user, dom, pw
end

local function tryLogin()
  local user, dom, pw = signInFlow()
  if not user then return false end

  local d, derr = resolveDomain(dom)
  if not d then
    err("Couldn't reach @" .. dom .. ": " .. tostring(derr))
    C.pause(); return false
  end
  M.cache.server_id = d.server_id
  M.cache.branding  = d.branding

  local hash = crypto.hashPassword(dom, user, pw)
  local data, lerr = callPreSession(d.server_id, "login", {
    username      = user,
    password_hash = hash,
    computer_id   = (os and os.getComputerID and os.getComputerID()) or 0,
  })
  if not data then
    err("Login failed: " .. tostring(lerr))
    C.pause(); return false
  end

  M.state.session = {
    username   = user,
    domain     = dom,
    server_id  = d.server_id,
    token      = data.session_token,
    expires_at = data.expires_at,
  }
  M.cache.is_op = data.is_op or false

  -- Remember
  local found
  for _, r in ipairs(M.state.remembered_servers) do
    if r.username == user and r.domain == dom then found = true end
  end
  if not found then
    table.insert(M.state.remembered_servers, 1,
      { username = user, domain = dom, server_id = d.server_id })
    while #M.state.remembered_servers > 5 do
      table.remove(M.state.remembered_servers)
    end
  end
  saveState()

  if data.must_change_password then
    info("You must change your password before continuing.")
    return changePasswordFlow(user, dom, hash)
  end
  return true
end

function changePasswordFlow(user, dom, currentHash)
  while true do
    header("Change Password")
    io.write("New password (min " .. C.MIN_PASSWORD_LEN .. "): ")
    local p1 = read and read("*") or io.read()
    p1 = C.trim(p1 or "")
    io.write("Confirm:       ")
    local p2 = read and read("*") or io.read()
    p2 = C.trim(p2 or "")
    if p1 ~= p2 then
      err("Passwords don't match. Try again.")
    elseif #p1 < C.MIN_PASSWORD_LEN then
      err("Too short.")
    else
      local newHash = crypto.hashPassword(dom, user, p1)
      local data, cerr = M.callUSR("change_password",
        { current_password_hash = currentHash, new_password_hash = newHash })
      if not data then
        err("Change failed: " .. tostring(cerr)); C.pause(); return false
      end
      ok("Password changed.")
      C.pause()
      return true
    end
  end
end

local function tryRegister()
  header("Create Account")
  local doms, derr = listPublicDomains()
  if not doms or #doms == 0 then
    err("No public domains available right now.")
    C.pause(); return false
  end
  local picked = C.selectFromList(doms,
    function(d) return "@" .. d.name ..
      ((d.branding and d.branding.display_name)
       and "  (" .. d.branding.display_name .. ")"
       or "") end,
    "Pick a domain", true)
  if not picked then return false end

  local d, dStatus = resolveDomain(picked.name)
  if not d then
    err("@" .. picked.name .. " is unreachable: " .. tostring(dStatus))
    C.pause(); return false
  end

  local user
  while true do
    user = C.askNonEmpty("Choose a username (2-16, lowercase a-z, 0-9, _)")
    user = string.lower(user)
    local okv, ev = C.validateUsername(user)
    if okv then break else err("Invalid: " .. ev) end
  end

  local pw
  while true do
    io.write("Password (min " .. C.MIN_PASSWORD_LEN .. "): ")
    local p1 = read and read("*") or io.read()
    p1 = C.trim(p1 or "")
    io.write("Confirm:           ")
    local p2 = read and read("*") or io.read()
    p2 = C.trim(p2 or "")
    if p1 ~= p2 then err("Passwords don't match.")
    elseif #p1 < C.MIN_PASSWORD_LEN then err("Too short.")
    else pw = p1; break end
  end

  local hash = crypto.hashPassword(picked.name, user, pw)
  M.cache.server_id = d.server_id
  M.cache.branding  = d.branding

  local data, rerr = callPreSession(d.server_id, "register", {
    username = user, password_hash = hash,
    computer_id = (os and os.getComputerID and os.getComputerID()) or 0,
  })
  if not data then
    err("Registration failed: " .. tostring(rerr))
    C.pause(); return false
  end

  M.state.session = {
    username   = user,
    domain     = picked.name,
    server_id  = d.server_id,
    token      = data.session_token,
    expires_at = data.expires_at,
  }
  M.cache.is_op = false
  table.insert(M.state.remembered_servers, 1,
    { username = user, domain = picked.name, server_id = d.server_id })
  saveState()
  ok("Welcome, " .. user .. "@" .. picked.name .. ".")
  C.pause()
  return true
end

-- =============================================================
-- Inbox view
-- =============================================================

local function refreshInbox()
  local data, ferr = M.callUSR("list_inbox",
    { folder = M.cache.current_folder, limit = M.INBOX_PAGE * 4 })
  if data then
    M.cache.inbox = data.messages or {}
  else
    M.cache.inbox = {}
    err("Refresh failed: " .. tostring(ferr))
    C.pause()
  end
end

local function drawInbox()
  header(string.upper(M.cache.current_folder)
    .. " · " .. M.state.session.username .. "@" .. M.state.session.domain)
  if M.cache.branding and M.cache.branding.display_name then
    dim("(" .. M.cache.branding.display_name .. ")")
  end
  if #M.cache.inbox == 0 then
    print("")
    dim("(empty)")
  else
    for i = 1, math.min(M.INBOX_PAGE, #M.cache.inbox) do
      local m = M.cache.inbox[i]
      local mark = m.unread and "●" or "○"
      local label = string.format("%d. %s %-18s %-30s d%s",
        i, mark,
        C.truncate(m.from or "?", 18),
        C.truncate(m.subject or "(no subject)", 30),
        tostring(m.sent_day or "?"))
      if m.unread then
        C.printColored("white", label)
      else
        dim(label)
      end
    end
    if #M.cache.inbox > M.INBOX_PAGE then
      dim(("... and %d more"):format(#M.cache.inbox - M.INBOX_PAGE))
    end
  end
  print("")
  local hints = "[1-9] read  [c] compose  [r] refresh  [i] inbox  [s] sent  [t] trash  [/] search"
  if M.cache.is_op then
    hints = hints .. "  [a] admin"
  end
  hints = hints .. "  [l] logout  [q] quit"
  C.printColored("yellow", hints)
  io.write("> ")
end

-- =============================================================
-- Read / reply / delete
-- =============================================================

local function readView(msgId)
  local data, rerr = M.callUSR("read_message", { id = msgId })
  if not data then
    err("Couldn't read: " .. tostring(rerr)); C.pause(); return
  end
  local m = data.message
  while true do
    header("MESSAGE")
    print("FROM:    " .. (m.from or "?"))
    print("TO:      " .. table.concat(m.to or {}, ", "))
    print("SUBJECT: " .. (m.subject or ""))
    print("DAY:     " .. tostring(m.sent_day or "?"))
    print(string.rep("-", 50))
    print(m.body or "")
    print(string.rep("-", 50))
    C.printColored("yellow", "[r] reply  [d] delete  [q] back")
    io.write("> ")
    local k = string.lower(C.trim(io.read() or ""))
    if k == "q" or k == "" then return
    elseif k == "d" then
      local _, derr = M.callUSR("delete_message", { id = m.id })
      if derr then err("Delete failed: " .. derr); C.pause()
      else ok("Deleted."); C.pause(); return end
    elseif k == "r" then
      composeView({
        prefill_to = m.from,
        prefill_subject = (m.subject or ""):find("^[Rr][Ee]:") and m.subject
                          or ("Re: " .. (m.subject or "")),
        prefill_body = "\n\n--- On day " .. tostring(m.sent_day) .. ", "
                       .. (m.from or "?") .. " wrote: ---\n"
                       .. C.truncate(m.body or "", 500),
      })
      return
    end
  end
end

function composeView(opts)
  opts = opts or {}
  header("COMPOSE")
  local to = opts.prefill_to or C.askNonEmpty("To (comma-separated addresses)")
  local toList = {}
  for _, a in ipairs(C.splitCsv(to)) do
    toList[#toList + 1] = a
  end
  if #toList == 0 then err("No recipients."); C.pause(); return end

  local subject = opts.prefill_subject
  if not subject then
    io.write("Subject: ")
    subject = C.trim(io.read() or "")
  end
  if #subject > C.MAX_SUBJECT_LEN then
    subject = C.truncate(subject, C.MAX_SUBJECT_LEN)
  end

  print("")
  local body
  if opts.prefill_body then
    print("(Quoted original below — add your reply on top.)")
    body = readMultiline() .. opts.prefill_body
  else
    body = readMultiline()
  end
  if #body > C.MAX_BODY_LEN then
    err("Body too long (" .. #body .. " > " .. C.MAX_BODY_LEN .. " chars).")
    C.pause(); return
  end

  print("")
  if not C.askYN("Send to " .. table.concat(toList, ", ") .. "?", true) then
    return
  end

  local data, serr = M.callUSR("send",
    { to = toList, subject = subject, body = body })
  if not data then
    err("Send failed: " .. tostring(serr)); C.pause(); return
  end
  local sent, bounced = 0, 0
  for _, r in ipairs(data.delivery_results or {}) do
    if r.status == "DELIVERED" or r.status == "LOCAL" then sent = sent + 1
    else bounced = bounced + 1 end
  end
  if bounced == 0 then
    ok(("Sent. (%d delivered)"):format(sent))
  else
    warn(("Sent. (%d delivered, %d bounced)"):format(sent, bounced))
    for _, r in ipairs(data.delivery_results or {}) do
      if r.status ~= "DELIVERED" and r.status ~= "LOCAL" then
        dim("  - " .. r.recipient .. ": " .. r.status
            .. (r.reason and (" (" .. r.reason .. ")") or ""))
      end
    end
  end
  C.pause()
end

local function searchView()
  header("SEARCH")
  local q = C.askNonEmpty("Query")
  local data, serr = M.callUSR("search",
    { query = q, folder = M.cache.current_folder })
  if not data then err("Search failed: " .. tostring(serr)); C.pause(); return end
  if #data.messages == 0 then dim("(no matches)"); C.pause(); return end
  for i, m in ipairs(data.messages) do
    print(string.format("%d. %s · %s · d%s", i,
      C.truncate(m.from, 18), C.truncate(m.subject, 30),
      tostring(m.sent_day)))
  end
  io.write("Open which? (Enter to skip): ")
  local n = tonumber(io.read() or "")
  if n and data.messages[n] then readView(data.messages[n].id) end
end

-- =============================================================
-- Admin overlay (op only)
-- =============================================================

local function adminMenu()
  while true do
    header("DOMAIN ADMIN — @" .. M.state.session.domain)
    local opts = {
      "Create user",
      "Reset user password",
      "Delete user",
      "View user inbox",
      "Update branding",
      "Domain stats",
    }
    for i, o in ipairs(opts) do print(i .. ". " .. o) end
    print("0. Back")
    local n = C.askNumber("Pick", 0)
    if n == 0 then return
    elseif n == 1 then
      local u = C.askNonEmpty("New username")
      io.write("Initial password: ")
      local p = read and read("*") or io.read()
      p = C.trim(p or "")
      if #p < C.MIN_PASSWORD_LEN then err("Too short."); C.pause()
      else
        local hash = crypto.hashPassword(M.state.session.domain,
                                         string.lower(u), p)
        local _, e = M.callUSR("admin_create_user",
          { username = u, initial_password_hash = hash })
        if e then err("Failed: " .. e) else ok("Created.") end
        C.pause()
      end
    elseif n == 2 then
      local u = C.askNonEmpty("Username")
      io.write("New password: ")
      local p = read and read("*") or io.read()
      p = C.trim(p or "")
      local hash = crypto.hashPassword(M.state.session.domain,
                                       string.lower(u), p)
      local _, e = M.callUSR("admin_reset_password",
        { username = u, new_password_hash = hash })
      if e then err("Failed: " .. e) else ok("Reset. User must change at next login.") end
      C.pause()
    elseif n == 3 then
      local u = C.askNonEmpty("Username to delete")
      if C.confirmDanger("This will delete @" .. u .. " permanently.") then
        local _, e = M.callUSR("admin_delete_user",
          { username = u, confirm = "DELETE" })
        if e then err("Failed: " .. e) else ok("Deleted.") end
        C.pause()
      end
    elseif n == 4 then
      local u = C.askNonEmpty("Username to view")
      local data, e = M.callUSR("admin_view_user_inbox",
        { username = u, folder = "inbox", limit = 20 })
      if e then err("Failed: " .. e); C.pause()
      elseif not data.messages or #data.messages == 0 then
        dim("(empty)"); C.pause()
      else
        for i, m in ipairs(data.messages) do
          print(string.format("%d. %s · %s · d%s",
            i, C.truncate(m.from, 18), C.truncate(m.subject, 30),
            tostring(m.sent_day)))
        end
        C.pause()
      end
    elseif n == 5 then
      local dn = C.askNonEmpty("Display name")
      io.write("Sign-off (optional): ")
      local so = C.trim(io.read() or "")
      local _, e = M.callUSR("admin_set_branding",
        { branding = { display_name = dn, sign_off = so ~= "" and so or nil } })
      if e then err("Failed: " .. e) else ok("Branding updated.") end
      C.pause()
    elseif n == 6 then
      local data, e = M.callUSR("admin_domain_stats", {})
      if e then err("Failed: " .. e); C.pause()
      else
        print("Users:    " .. data.user_count)
        print("Messages: " .. data.msg_count)
        print("Status:   " .. (data.domain_status or "?"))
        print("")
        info("Recent activity:")
        for _, a in ipairs(data.recent_activity or {}) do
          dim(string.format("  d%s  %s  %s  %s",
            tostring(a.day), a.actor or "?", a.action or "?", a.target or ""))
        end
        C.pause()
      end
    end
  end
end

-- =============================================================
-- Main inbox loop
-- =============================================================

local function inboxLoop()
  refreshInbox()
  while M.state.session do
    drawInbox()
    local k = C.lower(C.trim(io.read() or ""))
    if k == "q" then return "quit"
    elseif k == "l" then
      M.callUSR("logout", {})
      M.state.session = nil
      saveState()
      return "login"
    elseif k == "r" then refreshInbox()
    elseif k == "i" then M.cache.current_folder = "inbox";  refreshInbox()
    elseif k == "s" then M.cache.current_folder = "sent";   refreshInbox()
    elseif k == "t" then M.cache.current_folder = "trash";  refreshInbox()
    elseif k == "c" then composeView()
    elseif k == "/" then searchView()
    elseif k == "a" and M.cache.is_op then adminMenu()
    else
      local n = tonumber(k)
      if n and M.cache.inbox[n] then
        readView(M.cache.inbox[n].id)
        refreshInbox()
      end
    end
  end
  return "login"
end

-- =============================================================
-- Top-level loop
-- =============================================================

local function loginScreen()
  while true do
    header("POSTROOM")
    print("1. Sign in")
    print("2. Create account")
    print("3. Quit")
    local n = C.askNumber("Pick")
    if n == 1 then
      if tryLogin() then
        -- Pull account_info to detect is_op
        local data = M.callUSR("account_info", {})
        if data then
          M.cache.is_op = data.is_op or false
        end
        return "inbox"
      end
    elseif n == 2 then
      if tryRegister() then
        local data = M.callUSR("account_info", {})
        if data then M.cache.is_op = data.is_op or false end
        return "inbox"
      end
    elseif n == 3 then
      return "quit"
    end
  end
end

function M.run()
  loadState()
  if not rednet then
    print("rednet not available — exiting.")
    return
  end
  local _, side = wire.openModem()
  if not side then
    print("No modem found. Attach a wireless modem and try again.")
    return
  end
  bootScreen()
  local s = "login"
  while s ~= "quit" do
    if s == "login" then s = loginScreen()
    elseif s == "inbox" then
      -- If we have a cached session that's still valid locally, try to use it
      if M.state.session and not M.cache.server_id then
        M.cache.server_id = M.state.session.server_id
      end
      s = inboxLoop()
    end
  end
  C.clear()
  print("Goodbye.")
end

if not _G._POSTROOM_NO_AUTORUN then
  M.run()
end

return M
