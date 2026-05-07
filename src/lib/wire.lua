-- /postroom/lib/wire.lua
-- Postroom wire format: canonical serialization, signing, request/response helpers
-- Depends on: crypto.lua

local crypto = require("crypto")

local M = {}

M.VERSION = "1.0.0"
M.PROTOCOL = "POSTROOM_NET"

-- =============================================================
-- Canonical serialization
-- Produces a deterministic string for any Lua value, used as
-- the input to HMAC. Same input -> same string -> same signature.
-- Handles: nil, boolean, number, string, table (string-keyed only).
-- =============================================================

local function canonical(v)
  local tv = type(v)
  if tv == "nil" then
    return "n"
  elseif tv == "boolean" then
    return v and "t" or "f"
  elseif tv == "number" then
    -- Integers and floats both formatted via %.14g for reproducibility
    if v ~= v then return "NaN" end                       -- NaN guard
    if v == math.huge then return "Inf" end
    if v == -math.huge then return "-Inf" end
    if math.type and math.type(v) == "integer" then
      return "i" .. tostring(v)
    end
    if v == math.floor(v) and math.abs(v) < 1e15 then
      return "i" .. string.format("%d", v)
    end
    return "d" .. string.format("%.14g", v)
  elseif tv == "string" then
    return "s" .. #v .. ":" .. v
  elseif tv == "table" then
    -- Collect string keys (we forbid mixed/numeric keys for simplicity)
    local keys = {}
    for k in pairs(v) do
      if type(k) == "string" then
        keys[#keys + 1] = k
      elseif type(k) == "number" then
        keys[#keys + 1] = k
      else
        error("canonical: unsupported key type: " .. type(k))
      end
    end
    -- Sort: numbers first (by value), then strings (alphabetical)
    table.sort(keys, function(a, b)
      local ta, tb = type(a), type(b)
      if ta == tb then return a < b end
      return ta == "number"
    end)
    local parts = { "{" }
    for i, k in ipairs(keys) do
      if i > 1 then parts[#parts + 1] = "," end
      parts[#parts + 1] = canonical(k)
      parts[#parts + 1] = "="
      parts[#parts + 1] = canonical(v[k])
    end
    parts[#parts + 1] = "}"
    return table.concat(parts)
  else
    error("canonical: unsupported type: " .. tv)
  end
end

M.canonical = canonical

-- =============================================================
-- Signing and verification
-- A signed message is: { ...fields, sig = HMAC(secret, canonical(fields_minus_sig)) }
-- =============================================================

-- Compute signature over a message (excluding the sig field).
function M.sign(message, secret)
  local copy = {}
  for k, v in pairs(message) do
    if k ~= "sig" then copy[k] = v end
  end
  return crypto.hmac_sha256_hex(secret, canonical(copy))
end

-- Verify a message's signature. Returns true if valid.
function M.verify(message, secret)
  if type(message) ~= "table" or type(message.sig) ~= "string" then
    return false
  end
  local expected = M.sign(message, secret)
  -- Constant-ish time compare (CC has no timing side channels worth caring about)
  if #expected ~= #message.sig then return false end
  return expected == message.sig
end

-- =============================================================
-- Building requests and responses
-- =============================================================

-- Build a signed request message.
-- station: who's sending (e.g. "SUNDOWN_SRV", "CLIENT:42")
-- proto:   "POSTROOM/REG" or "POSTROOM/USR"
-- action:  action name string
-- payload: plaintext metadata table
-- secret:  HMAC key
-- opts:    { body = string, encrypted_body = bool, body_context = string }
function M.buildRequest(station, proto, action, payload, secret, opts)
  opts = opts or {}
  local rid = (os.epoch and tostring(os.epoch("utc")) or tostring(os.time()))
              .. "-" .. tostring(math.random(100000, 999999))
  local nonce = (os.epoch and tostring(os.epoch("utc")) or tostring(os.time()))
                .. "-" .. crypto.randomHex(8)

  local msg = {
    type    = "req",
    proto   = proto,
    station = station,
    rid     = rid,
    nonce   = nonce,
    action  = action,
    payload = payload or {},
  }

  if opts.body then
    if opts.encrypted_body then
      assert(opts.body_context, "encrypted_body requires body_context")
      msg.body = crypto.encrypt(opts.body, secret, opts.body_context)
    else
      msg.body = opts.body
    end
  end

  msg.sig = M.sign(msg, secret)
  return msg
end

-- Build a signed response message corresponding to a request.
function M.buildResponse(station, request, ok, dataOrError, secret, opts)
  opts = opts or {}
  local msg = {
    type    = "resp",
    proto   = request.proto,
    station = station,
    rid     = request.rid,
    nonce   = (os.epoch and tostring(os.epoch("utc")) or tostring(os.time()))
              .. "-" .. crypto.randomHex(8),
    ok      = ok and true or false,
  }
  if ok then
    msg.data = dataOrError or {}
  else
    msg.error = dataOrError or "UNKNOWN"
  end

  if opts.body then
    if opts.encrypted_body then
      assert(opts.body_context, "encrypted_body requires body_context")
      msg.body = crypto.encrypt(opts.body, secret, opts.body_context)
    else
      msg.body = opts.body
    end
  end

  msg.sig = M.sign(msg, secret)
  return msg
end

-- =============================================================
-- Validation
-- =============================================================

-- Check that a message has the required structural fields.
function M.validateRequest(msg)
  if type(msg) ~= "table" then return false, "not a table" end
  if msg.type ~= "req" then return false, "not a request" end
  if type(msg.proto) ~= "string" then return false, "missing proto" end
  if type(msg.station) ~= "string" then return false, "missing station" end
  if type(msg.rid) ~= "string" then return false, "missing rid" end
  if type(msg.nonce) ~= "string" then return false, "missing nonce" end
  if type(msg.action) ~= "string" then return false, "missing action" end
  if type(msg.sig) ~= "string" then return false, "missing sig" end
  return true
end

function M.validateResponse(msg)
  if type(msg) ~= "table" then return false, "not a table" end
  if msg.type ~= "resp" then return false, "not a response" end
  if type(msg.proto) ~= "string" then return false, "missing proto" end
  if type(msg.station) ~= "string" then return false, "missing station" end
  if type(msg.rid) ~= "string" then return false, "missing rid" end
  if type(msg.nonce) ~= "string" then return false, "missing nonce" end
  if type(msg.ok) ~= "boolean" then return false, "missing ok flag" end
  if type(msg.sig) ~= "string" then return false, "missing sig" end
  return true
end

-- =============================================================
-- Nonce store (replay protection)
-- =============================================================

-- Create a new nonce store. Tracks nonces seen per station.
-- maxEntries: cap on total entries before pruning oldest.
function M.newNonceStore(maxEntries)
  return {
    seen = {},          -- key: station ":" nonce, value: timestamp
    maxEntries = maxEntries or 250,
    count = 0,
  }
end

-- Check and record a nonce. Returns true if new (request should be processed),
-- false if it's a replay.
function M.checkNonce(store, station, nonce)
  local key = station .. ":" .. nonce
  if store.seen[key] then
    return false, "REPLAY"
  end
  local now = os.epoch and os.epoch("utc") or os.time() * 1000
  store.seen[key] = now
  store.count = store.count + 1

  -- Prune if oversized
  if store.count > store.maxEntries then
    local entries = {}
    for k, v in pairs(store.seen) do entries[#entries + 1] = { k = k, v = v } end
    table.sort(entries, function(a, b) return a.v > b.v end)
    -- Keep the newest half
    local keep = math.floor(store.maxEntries / 2)
    store.seen = {}
    store.count = 0
    for i = 1, math.min(keep, #entries) do
      store.seen[entries[i].k] = entries[i].v
      store.count = store.count + 1
    end
  end

  return true
end

-- =============================================================
-- Rednet send/receive helpers
-- These wrap rednet.send/receive with signing and verification.
-- Only available when running inside CC (rednet present).
-- =============================================================

-- Send a request and wait for a response. Returns (data, err).
-- timeout in seconds.
function M.sendRequest(hostId, station, proto, action, payload, secret, timeout, opts)
  if not rednet then return nil, "rednet not available" end
  local msg = M.buildRequest(station, proto, action, payload, secret, opts)
  rednet.send(hostId, msg, M.PROTOCOL)

  local timer = os.startTimer(timeout or 5)
  while true do
    local e, a, b, c = os.pullEvent()
    if e == "rednet_message" then
      local sender, response, p = a, b, c
      if sender == hostId and p == M.PROTOCOL
         and type(response) == "table"
         and response.type == "resp"
         and response.rid == msg.rid then
        if not M.verify(response, secret) then
          return nil, "BAD_RESPONSE_SIGNATURE"
        end
        if response.ok then
          return response.data, nil, response
        else
          return nil, response.error or "UNKNOWN_ERROR", response
        end
      end
    elseif e == "timer" and a == timer then
      return nil, "timeout"
    end
  end
end

-- Open a modem on any side or by name.
function M.openModem(preferredSide)
  if not peripheral then return false, "no peripheral api" end
  if preferredSide and peripheral.getType(preferredSide) == "modem" then
    rednet.open(preferredSide)
    return true, preferredSide
  end
  for _, side in ipairs(peripheral.getNames()) do
    if peripheral.getType(side) == "modem" then
      rednet.open(side)
      return true, side
    end
  end
  return false, "no modem found"
end

return M
