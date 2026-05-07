-- Test wire.lua
package.path = package.path .. ";../src/lib/?.lua;./src/lib/?.lua"
local wire = require("wire")
local crypto = require("crypto")

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

-- ===== Canonical serialization =====

check("canonical(nil)", "n", wire.canonical(nil))
check("canonical(true)", "t", wire.canonical(true))
check("canonical(false)", "f", wire.canonical(false))
check("canonical(42)", "i42", wire.canonical(42))
check("canonical(0)", "i0", wire.canonical(0))
check("canonical(-1)", "i-1", wire.canonical(-1))
check("canonical('hi')", "s2:hi", wire.canonical("hi"))
check("canonical(empty string)", "s0:", wire.canonical(""))
check("canonical(empty table)", "{}", wire.canonical({}))

-- Determinism: same data, same string regardless of insertion order
local t1 = { a = 1, b = 2, c = 3 }
local t2 = { c = 3, b = 2, a = 1 }
check("canonical determinism", wire.canonical(t1), wire.canonical(t2))

-- Different data, different string
local t3 = { a = 1, b = 2, c = 4 }
check("canonical differs on diff data", true, wire.canonical(t1) ~= wire.canonical(t3))

-- Nested tables
local nested = { user = "alice", meta = { day = 141, tags = { "x", "y" } } }
local serialized = wire.canonical(nested)
check("canonical nested produces string", "string", type(serialized))

-- ===== Signing =====

local secret = "shared-secret-for-tests"
local msg = {
  type = "req",
  proto = "POSTROOM/USR",
  station = "CLIENT:42",
  rid = "test-1",
  nonce = "nonce-1",
  action = "login",
  payload = { username = "alice", password_hash = "deadbeef" },
}

local sig = wire.sign(msg, secret)
check("sig is string", "string", type(sig))
check("sig is 64 hex chars", 64, #sig)

-- Same input -> same signature
local sig2 = wire.sign(msg, secret)
check("sig deterministic", sig, sig2)

-- Different secret -> different signature
local sig3 = wire.sign(msg, "different-secret")
check("sig differs with different secret", true, sig ~= sig3)

-- Different payload -> different signature
local msg2 = {
  type = "req", proto = "POSTROOM/USR", station = "CLIENT:42",
  rid = "test-1", nonce = "nonce-1", action = "login",
  payload = { username = "alice", password_hash = "different" },
}
check("sig differs with different payload", true, sig ~= wire.sign(msg2, secret))

-- ===== Verification =====

msg.sig = sig
check("verify good signature", true, wire.verify(msg, secret))
check("verify bad secret", false, wire.verify(msg, "wrong-secret"))

msg.sig = "bad-signature"
check("verify bad signature", false, wire.verify(msg, secret))

msg.sig = nil
check("verify missing signature", false, wire.verify(msg, secret))

-- ===== buildRequest / buildResponse =====

-- buildRequest needs no rednet/os.epoch, but uses os.time fallback
local req = wire.buildRequest("CLIENT:42", "POSTROOM/USR", "login",
  { username = "alice" }, secret)
check("buildRequest type", "req", req.type)
check("buildRequest proto", "POSTROOM/USR", req.proto)
check("buildRequest station", "CLIENT:42", req.station)
check("buildRequest action", "login", req.action)
check("buildRequest has rid", "string", type(req.rid))
check("buildRequest has nonce", "string", type(req.nonce))
check("buildRequest has sig", "string", type(req.sig))
check("buildRequest verifies", true, wire.verify(req, secret))

-- Two requests have different rids and nonces
local req2 = wire.buildRequest("CLIENT:42", "POSTROOM/USR", "login",
  { username = "alice" }, secret)
check("requests differ in rid", true, req.rid ~= req2.rid)
check("requests differ in nonce", true, req.nonce ~= req2.nonce)

-- buildResponse
local resp = wire.buildResponse("NMAIL_SRV", req, true,
  { token = "session-token" }, secret)
check("response type", "resp", resp.type)
check("response rid matches req", req.rid, resp.rid)
check("response ok", true, resp.ok)
check("response data", "session-token", resp.data.token)
check("response verifies", true, wire.verify(resp, secret))

-- Error response
local errResp = wire.buildResponse("NMAIL_SRV", req, false, "BAD_CREDENTIALS", secret)
check("error response ok", false, errResp.ok)
check("error response error", "BAD_CREDENTIALS", errResp.error)
check("error response verifies", true, wire.verify(errResp, secret))

-- ===== Encrypted body =====

local req3 = wire.buildRequest("SUNDOWN_SRV", "POSTROOM/REG", "route_mail",
  { from = "bob@sundown", to = "alice@nmail" }, secret,
  { body = "secret message body", encrypted_body = true, body_context = "msg-1" })
check("body is encrypted", true, req3.body ~= "secret message body")
check("body is hex", true, req3.body:match("^[0-9a-f]+$") ~= nil)

-- Decrypt
local decrypted = crypto.decrypt(req3.body, secret, "msg-1")
check("body decrypts back", "secret message body", decrypted)

-- ===== Validation =====

local ok, err = wire.validateRequest(req)
check("validate good request", true, ok)

local ok2 = wire.validateRequest({ type = "req" })
check("validate missing fields", false, ok2)

local ok3 = wire.validateResponse(resp)
check("validate good response", true, ok3)

-- ===== Nonce store =====

local store = wire.newNonceStore(10)
local nok1 = wire.checkNonce(store, "CLIENT:42", "nonce-A")
check("nonce A first time", true, nok1)

local nok2 = wire.checkNonce(store, "CLIENT:42", "nonce-A")
check("nonce A replay rejected", false, nok2)

local nok3 = wire.checkNonce(store, "CLIENT:42", "nonce-B")
check("nonce B first time", true, nok3)

-- Different stations can use same nonce string
local nok4 = wire.checkNonce(store, "CLIENT:99", "nonce-A")
check("same nonce, different station OK", true, nok4)

-- ===== Pruning behavior =====

local pruning_store = wire.newNonceStore(10)
for i = 1, 20 do
  wire.checkNonce(pruning_store, "CLIENT:1", "nonce-" .. i)
end
-- After 20 inserts with cap 10, store should be pruned
check("nonce store pruned", true, pruning_store.count <= 10)

-- ===== Summary =====

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then
  print("FAILURES: " .. failed)
  os.exit(1)
end
