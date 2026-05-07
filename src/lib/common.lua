-- /postroom/lib/common.lua
-- Postroom shared utilities: UI helpers, persistence, address parsing, validation.

local M = {}

M.VERSION = "1.0.0"

-- =============================================================
-- Constants
-- =============================================================

M.RESERVED_DOMAIN_NAMES = {
  -- Government domains (issued and reserved)
  "gov", "nna", "nta", "nga", "nhsa",
  "nfa", "nra", "nwa", "nea", "nba", "nja",
  "nma", "nca", "mil", "court", "treasury",
  -- Public mail brands
  "nmail", "common",
  -- System reserved
  "admin", "system", "abuse", "postmaster",
  "root", "public", "noreply", "op", "pm",
}

M.RESERVED_LOCAL_PARTS = {
  "op", "pm", "abuse", "noreply", "postmaster",
}

-- Maximum lengths
M.MAX_USERNAME_LEN = 16
M.MIN_USERNAME_LEN = 2
M.MAX_DOMAIN_LEN   = 16
M.MIN_DOMAIN_LEN   = 2
M.MAX_PASSWORD_LEN = 64
M.MIN_PASSWORD_LEN = 6
M.MAX_SUBJECT_LEN  = 100
M.MAX_BODY_LEN     = 2500

-- Pricing (in fluorin)
M.FEES = {
  application       = 8,
  registration      = 48,
  renewal           = 12,
  transfer          = 8,
  nna_share         = 3,    -- added to every fee line
}

-- Lifecycle (in days)
M.LIFECYCLE = {
  domain_validity_days     = 48,    -- bi-seasonal
  install_token_days       = 7,
  warning_days             = { 4, 2, 0 },
  grace_days               = 4,
  suspension_to_revocation = 26,    -- days from suspension start to revocation
  revoked_cooldown         = 30,    -- days revoked name is held before pool
  heartbeat_interval_sec   = 60,
  heartbeat_offline_sec    = 180,
  session_max_age_days     = 7,
  trash_retention_days     = 14,
}

-- =============================================================
-- String helpers
-- =============================================================

function M.trim(s)
  return tostring(s or ""):match("^%s*(.-)%s*$")
end

function M.lower(s)
  return string.lower(tostring(s or ""))
end

function M.upper(s)
  return string.upper(M.trim(s or ""))
end

-- Pad string s to width w (truncate or right-pad with spaces).
function M.pad(s, w)
  s = tostring(s or "")
  if #s >= w then return s:sub(1, w) end
  return s .. string.rep(" ", w - #s)
end

-- Right-pad to width on the left (for right-justified columns).
function M.rpad(s, w)
  s = tostring(s or "")
  if #s >= w then return s:sub(1, w) end
  return string.rep(" ", w - #s) .. s
end

-- Truncate s to n chars, appending ".." if truncated.
function M.truncate(s, n)
  s = tostring(s or "")
  if #s <= n then return s end
  if n <= 2 then return s:sub(1, n) end
  return s:sub(1, n - 2) .. ".."
end

-- Split a comma-separated address list, trim each.
function M.splitCsv(s)
  local out = {}
  for part in string.gmatch(tostring(s or ""), "[^,]+") do
    local t = M.trim(part)
    if t ~= "" then out[#out + 1] = t end
  end
  return out
end

-- =============================================================
-- Address parsing
-- =============================================================

-- Parse "username@domain". Returns user, domain (both lowercase) or nil, err.
function M.parseAddress(s)
  if type(s) ~= "string" then return nil, "not a string" end
  local user, domain = s:match("^([%w_]+)@([%w]+)$")
  if not user or not domain then return nil, "INVALID_ADDRESS" end
  return string.lower(user), string.lower(domain)
end

-- Build address from parts.
function M.buildAddress(user, domain)
  return string.lower(tostring(user)) .. "@" .. string.lower(tostring(domain))
end

-- =============================================================
-- Validation
-- =============================================================

local function isReservedDomain(name)
  name = string.lower(name or "")
  for _, r in ipairs(M.RESERVED_DOMAIN_NAMES) do
    if r == name then return true end
  end
  return false
end

local function isReservedLocalPart(name)
  name = string.lower(name or "")
  for _, r in ipairs(M.RESERVED_LOCAL_PARTS) do
    if r == name then return true end
  end
  return false
end

M.isReservedDomain = isReservedDomain
M.isReservedLocalPart = isReservedLocalPart

-- Validate domain name format only (does NOT check registry).
-- Returns ok, err.
function M.validateDomainName(name, allowReserved)
  if type(name) ~= "string" then return false, "INVALID_TYPE" end
  if #name < M.MIN_DOMAIN_LEN then return false, "TOO_SHORT" end
  if #name > M.MAX_DOMAIN_LEN then return false, "TOO_LONG" end
  if not name:match("^[%l%d]+$") then return false, "INVALID_CHARS" end
  if not allowReserved and isReservedDomain(name) then return false, "RESERVED" end
  return true
end

-- Validate username format (within a domain). Reserved local-parts excluded
-- unless allowReserved=true (used by domain server for system accounts).
function M.validateUsername(name, allowReserved)
  if type(name) ~= "string" then return false, "INVALID_TYPE" end
  if #name < M.MIN_USERNAME_LEN then return false, "TOO_SHORT" end
  if #name > M.MAX_USERNAME_LEN then return false, "TOO_LONG" end
  if not name:match("^[%l%d_]+$") then return false, "INVALID_CHARS" end
  if not allowReserved and isReservedLocalPart(name) then return false, "RESERVED" end
  return true
end

-- Validate plaintext password length (we don't enforce complexity).
function M.validatePassword(pw)
  if type(pw) ~= "string" then return false, "INVALID_TYPE" end
  if #pw < M.MIN_PASSWORD_LEN then return false, "TOO_SHORT" end
  if #pw > M.MAX_PASSWORD_LEN then return false, "TOO_LONG" end
  return true
end

function M.validateSubject(s)
  if type(s) ~= "string" then return false, "INVALID_TYPE" end
  if #s > M.MAX_SUBJECT_LEN then return false, "TOO_LONG" end
  return true
end

function M.validateBody(s)
  if type(s) ~= "string" then return false, "INVALID_TYPE" end
  if #s > M.MAX_BODY_LEN then return false, "TOO_LONG" end
  return true
end

-- =============================================================
-- Persistence (atomic writes)
-- Only available when fs and textutils are present (CC).
-- =============================================================

function M.saveTable(path, tbl)
  if not fs or not textutils then return false, "no fs/textutils" end
  local dir = fs.getDir(path)
  if dir ~= "" and not fs.exists(dir) then fs.makeDir(dir) end
  local tmp = path .. ".tmp"
  local f, err = fs.open(tmp, "w")
  if not f then return false, err end
  f.write(textutils.serialize(tbl))
  f.close()
  if fs.exists(path) then fs.delete(path) end
  fs.move(tmp, path)
  return true
end

function M.loadTable(path)
  if not fs or not textutils then return nil, "no fs/textutils" end
  if not fs.exists(path) then return nil, "not found" end
  local f, err = fs.open(path, "r")
  if not f then return nil, err end
  local txt = f.readAll()
  f.close()
  local data = textutils.unserialize(txt)
  if type(data) ~= "table" then return nil, "corrupt" end
  return data
end

-- =============================================================
-- UI helpers (text-mode)
-- =============================================================

function M.clear()
  if term then
    term.clear()
    term.setCursorPos(1, 1)
  end
end

function M.setColor(c)
  if term and term.setTextColor and colors then
    term.setTextColor(colors[c] or colors.white)
  end
end

function M.resetColor()
  M.setColor("white")
end

function M.printColored(c, s)
  M.setColor(c)
  print(s)
  M.resetColor()
end

function M.printHeader(title)
  M.printColored("yellow", title)
  M.printColored("gray", string.rep("-", math.min(#title, 40)))
end

function M.pause(prompt)
  print("")
  io.write(prompt or "Press Enter...")
  io.read()
end

function M.ask(prompt, hidden)
  io.write(prompt .. ": ")
  if hidden and read then
    return M.trim(read("*"))
  end
  return M.trim(io.read() or "")
end

function M.askNonEmpty(prompt, hidden)
  while true do
    local s = M.ask(prompt, hidden)
    if s ~= "" then return s end
    M.printColored("red", "Required field.")
  end
end

function M.askNumber(prompt, default)
  while true do
    if default ~= nil then
      io.write(prompt .. " [" .. tostring(default) .. "]: ")
    else
      io.write(prompt .. ": ")
    end
    local s = M.trim(io.read() or "")
    if s == "" and default ~= nil then return default end
    local n = tonumber(s)
    if n then return n end
    M.printColored("red", "Enter a number.")
  end
end

function M.askYN(prompt, default)
  local suffix = default and " [Y/n]: " or " [y/N]: "
  io.write(prompt .. suffix)
  local s = M.lower(M.trim(io.read() or ""))
  if s == "" then return default end
  return s:sub(1, 1) == "y"
end

function M.confirmDanger(prompt)
  print("")
  M.printColored("yellow", prompt)
  io.write("Type CONFIRM to continue: ")
  return M.trim(io.read() or "") == "CONFIRM"
end

-- Display a numbered menu and return the selected item (or nil for back).
function M.selectFromList(items, labelFn, title, allowBack)
  M.clear()
  if title then M.printHeader(title) end
  if #items == 0 then
    print("(none)")
    M.pause()
    return nil
  end
  for i, item in ipairs(items) do
    print(i .. ". " .. labelFn(item))
  end
  if allowBack then print("0. Back") end
  while true do
    local n = M.askNumber("Select")
    if allowBack and n == 0 then return nil end
    if items[n] then return items[n], n end
    M.printColored("red", "Invalid selection.")
  end
end

-- =============================================================
-- Time helpers
-- =============================================================

-- Current world day. Falls back to a counter for non-CC environments.
function M.currentDay()
  if os and os.day then return os.day() end
  return 0
end

-- Current epoch in ms.
function M.now()
  if os and os.epoch then return os.epoch("utc") end
  return os.time() * 1000
end

-- Seconds since epoch.
function M.nowSec()
  return math.floor(M.now() / 1000)
end

-- =============================================================
-- ID generation (per-server counters)
-- =============================================================

function M.nextId(state, counterKey, prefix, width)
  state.counters = state.counters or {}
  state.counters[counterKey] = (state.counters[counterKey] or 0) + 1
  return prefix .. "-" .. string.format("%0" .. (width or 4) .. "d", state.counters[counterKey])
end

-- =============================================================
-- Logging helpers
-- =============================================================

-- Append a log entry to a bounded list. Trims to max in chunks.
function M.appendLog(list, entry, maxEntries)
  list[#list + 1] = entry
  if #list > maxEntries then
    -- Rebuild keeping last maxEntries (chunked, O(n))
    local keep = math.floor(maxEntries / 2)
    local startIdx = #list - keep + 1
    local out = {}
    for i = startIdx, #list do out[#out + 1] = list[i] end
    -- Replace contents in place
    for i = #list, 1, -1 do list[i] = nil end
    for i, v in ipairs(out) do list[i] = v end
  end
end

-- =============================================================
-- Money formatting
-- =============================================================

-- Format an amount in fluorin for display (e.g. "12f").
function M.formatMoney(n)
  return tostring(math.floor(n)) .. "f"
end

-- =============================================================
-- Currency tender — for parity with airport's printed-receipt format.
-- For Postroom we just show the f amount; servers don't take payment.
-- =============================================================

return M
