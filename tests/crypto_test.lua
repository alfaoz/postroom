-- /postroom/lib/crypto_test.lua
-- Run: lua crypto_test.lua  (or paste into a CC computer alongside crypto.lua)
-- Verifies SHA256, HMAC-SHA256, and AES-128-CBC against known-answer tests.

package.path = package.path .. ";../src/lib/?.lua;./src/lib/?.lua"
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

-- ===== SHA-256 known-answer tests (FIPS 180-4 / RFC 6234) =====

check("sha256(empty)",
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  crypto.sha256hex(""))

check("sha256('abc')",
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  crypto.sha256hex("abc"))

check("sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')",
  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  crypto.sha256hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))

check("sha256(million 'a')",
  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
  crypto.sha256hex(string.rep("a", 1000000)))

-- ===== HMAC-SHA256 known-answer tests (RFC 4231) =====

check("hmac(0x0b*20, 'Hi There')",
  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  crypto.hmac_sha256_hex(string.rep(string.char(0x0b), 20), "Hi There"))

check("hmac('Jefe', 'what do ya want for nothing?')",
  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  crypto.hmac_sha256_hex("Jefe", "what do ya want for nothing?"))

check("hmac(0xaa*20, 0xdd*50)",
  "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
  crypto.hmac_sha256_hex(string.rep(string.char(0xaa), 20), string.rep(string.char(0xdd), 50)))

-- ===== AES-128 known-answer test (FIPS 197 Appendix C.1) =====

local key = crypto.fromHex("000102030405060708090a0b0c0d0e0f")
local plaintext = crypto.fromHex("00112233445566778899aabbccddeeff")
local expected_ciphertext = "69c4e0d86a7b0430d8cdb78070b4c55a"

-- We test the raw block cipher via CBC with all-zero IV, then strip pkcs7
local iv_zero = string.rep("\0", 16)
local ct = crypto.aes128_cbc_encrypt(plaintext, key, iv_zero)
-- ct is 32 bytes: 16 ciphertext + 16 padding
check("aes128 raw block (FIPS 197 C.1)", expected_ciphertext, crypto.toHex(ct:sub(1, 16)))

-- ===== AES-128-CBC roundtrip =====

local k = crypto.fromHex("2b7e151628aed2a6abf7158809cf4f3c")
local iv = crypto.fromHex("000102030405060708090a0b0c0d0e0f")

local function roundtrip(name, msg)
  local enc = crypto.aes128_cbc_encrypt(msg, k, iv)
  local dec, err = crypto.aes128_cbc_decrypt(enc, k, iv)
  if dec == msg then
    total = total + 1
    print("[PASS] cbc roundtrip: " .. name)
  else
    total = total + 1; failed = failed + 1
    print("[FAIL] cbc roundtrip: " .. name)
    print("       err: " .. tostring(err))
  end
end

roundtrip("empty", "")
roundtrip("one byte", "X")
roundtrip("exactly 16 bytes", "abcdefghijklmnop")
roundtrip("17 bytes", "abcdefghijklmnopq")
roundtrip("100 bytes", string.rep("Hello, world! ", 8):sub(1, 100))
roundtrip("with nul bytes", "before\0\0\0after")
roundtrip("long message", string.rep("The quick brown fox jumps over the lazy dog. ", 50))

-- ===== High-level encrypt/decrypt =====

local secret = "shared-secret-32-bytes-long-here"
local function highlevel(name, msg, ctx)
  local enc = crypto.encrypt(msg, secret, ctx)
  local dec = crypto.decrypt(enc, secret, ctx)
  if dec == msg then
    total = total + 1
    print("[PASS] high-level: " .. name)
  else
    total = total + 1; failed = failed + 1
    print("[FAIL] high-level: " .. name)
  end
end

highlevel("simple", "hello world", "ctx-1")
highlevel("empty", "", "ctx-2")
highlevel("long", string.rep("abc", 1000), "ctx-3")

-- Different contexts produce different ciphertexts
local e1 = crypto.encrypt("same plaintext", secret, "ctx-A")
local e2 = crypto.encrypt("same plaintext", secret, "ctx-B")
check("contexts produce different ciphertext", true, e1 ~= e2)

-- Wrong secret fails decryption
local wrong = crypto.decrypt(e1, "different-secret", "ctx-A")
check("wrong secret fails", true, wrong == nil)

-- ===== Hex helpers =====

check("hex roundtrip", "hello", crypto.fromHex(crypto.toHex("hello")))
check("hex of 0x00 0xff", "00ff", crypto.toHex("\0\255"))

-- ===== Random helpers =====

local r1 = crypto.randomHex(16)
local r2 = crypto.randomHex(16)
check("random hex length", 32, #r1)
check("random hex differs", true, r1 ~= r2)

local tok = crypto.randomToken(16)
check("token length", 16, #tok)
check("token formatted", "ABCD-EFGH-JKLM-NPQR", crypto.formatToken("ABCDEFGHJKLMNPQR")) -- 16 chars from alphabet

-- ===== Password hashing =====

local h1 = crypto.hashPassword("nmail", "alice", "secret123")
local h2 = crypto.hashPassword("nmail", "alice", "secret123")
local h3 = crypto.hashPassword("nmail", "alice", "wrong")
local h4 = crypto.hashPassword("common", "alice", "secret123")
check("password hash deterministic", h1, h2)
check("password hash differs on wrong pw", true, h1 ~= h3)
check("password hash differs across domains", true, h1 ~= h4)
check("password hash is 64 hex chars", 64, #h1)

-- Case insensitivity of domain/username in password hash
local h5 = crypto.hashPassword("NMAIL", "ALICE", "secret123")
check("password hash case-insensitive", h1, h5)

-- ===== Summary =====

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then
  print("FAILURES: " .. failed)
  os.exit(1)
end
