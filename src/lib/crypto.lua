-- /postroom/lib/crypto.lua
-- Postroom cryptography primitives
-- Provides: SHA256, HMAC-SHA256, AES-128-CBC, hex/base64 helpers
-- Pure Lua. No external dependencies.

local M = {}

M.VERSION = "1.0.0"

-- =============================================================
-- Bit operations: prefer bit32 (CC default), fall back to native
-- =============================================================

local band, bor, bxor, bnot, lshift, rshift, rrotate

if bit32 then
  band   = bit32.band
  bor    = bit32.bor
  bxor   = bit32.bxor
  bnot   = bit32.bnot
  lshift = bit32.lshift
  rshift = bit32.rshift
  rrotate = bit32.rrotate
else
  -- Lua 5.3+ fallback using native bitwise operators
  -- We wrap in load() so this file still parses on 5.2/CC
  local ok, ops = pcall(load([[
    local function vfold(op, a, ...)
      local n = select("#", ...)
      for i = 1, n do a = op(a, (select(i, ...))) end
      return a & 0xffffffff
    end
    return {
      band   = function(...) return vfold(function(x,y) return x & y end, ...) end,
      bor    = function(...) return vfold(function(x,y) return x | y end, ...) end,
      bxor   = function(...) return vfold(function(x,y) return x ~ y end, ...) end,
      bnot   = function(a) return (~a) & 0xffffffff end,
      lshift = function(a, n) return (a << n) & 0xffffffff end,
      rshift = function(a, n) return (a & 0xffffffff) >> n end,
      rrotate = function(a, n)
        a = a & 0xffffffff
        return ((a >> n) | (a << (32 - n))) & 0xffffffff
      end,
    }
  ]]))
  if not ok or type(ops) ~= "table" then
    error("Postroom crypto: no bit32 and no native bitops available")
  end
  band, bor, bxor, bnot = ops.band, ops.bor, ops.bxor, ops.bnot
  lshift, rshift, rrotate = ops.lshift, ops.rshift, ops.rrotate
end

-- =============================================================
-- Hex utilities
-- =============================================================

local function toHex(s)
  return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function fromHex(s)
  return (s:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
end

M.toHex = toHex
M.fromHex = fromHex

-- =============================================================
-- SHA-256
-- Reference: FIPS 180-4
-- =============================================================

local SHA256_K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function sha256_pad(msg)
  local len = #msg
  local bits = len * 8
  local pad = "\128"
  local extra = (56 - (len + 1)) % 64
  pad = pad .. string.rep("\0", extra)
  -- 64-bit big-endian length
  pad = pad .. "\0\0\0\0"
  pad = pad .. string.char(
    band(rshift(bits, 24), 0xff),
    band(rshift(bits, 16), 0xff),
    band(rshift(bits, 8), 0xff),
    band(bits, 0xff)
  )
  return msg .. pad
end

local function sha256_words(msg)
  local words = {}
  local n = #msg / 4
  for i = 1, n do
    local p = (i - 1) * 4
    local b1, b2, b3, b4 = string.byte(msg, p + 1, p + 4)
    words[i] = lshift(b1, 24) + lshift(b2, 16) + lshift(b3, 8) + b4
  end
  return words
end

function M.sha256(msg)
  local padded = sha256_pad(msg)
  local words = sha256_words(padded)
  local nblocks = #words / 16

  local h = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  }

  local w = {}

  for block = 0, nblocks - 1 do
    -- Load message schedule
    for t = 1, 16 do
      w[t] = words[block * 16 + t]
    end
    for t = 17, 64 do
      local s0 = bxor(rrotate(w[t-15], 7), rrotate(w[t-15], 18), rshift(w[t-15], 3))
      local s1 = bxor(rrotate(w[t-2], 17), rrotate(w[t-2], 19), rshift(w[t-2], 10))
      w[t] = band(w[t-16] + s0 + w[t-7] + s1, 0xffffffff)
    end

    local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]

    for t = 1, 64 do
      local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local temp1 = band(hh + S1 + ch + SHA256_K[t] + w[t], 0xffffffff)
      local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local temp2 = band(S0 + maj, 0xffffffff)

      hh = g
      g = f
      f = e
      e = band(d + temp1, 0xffffffff)
      d = c
      c = b
      b = a
      a = band(temp1 + temp2, 0xffffffff)
    end

    h[1] = band(h[1] + a, 0xffffffff)
    h[2] = band(h[2] + b, 0xffffffff)
    h[3] = band(h[3] + c, 0xffffffff)
    h[4] = band(h[4] + d, 0xffffffff)
    h[5] = band(h[5] + e, 0xffffffff)
    h[6] = band(h[6] + f, 0xffffffff)
    h[7] = band(h[7] + g, 0xffffffff)
    h[8] = band(h[8] + hh, 0xffffffff)
  end

  local out = {}
  for i = 1, 8 do
    local v = h[i]
    out[i] = string.char(
      band(rshift(v, 24), 0xff),
      band(rshift(v, 16), 0xff),
      band(rshift(v, 8), 0xff),
      band(v, 0xff)
    )
  end
  return table.concat(out)
end

function M.sha256hex(msg)
  return toHex(M.sha256(msg))
end

-- =============================================================
-- HMAC-SHA256
-- =============================================================

local SHA256_BLOCK = 64

function M.hmac_sha256(key, msg)
  if #key > SHA256_BLOCK then
    key = M.sha256(key)
  end
  if #key < SHA256_BLOCK then
    key = key .. string.rep("\0", SHA256_BLOCK - #key)
  end

  local opad, ipad = {}, {}
  for i = 1, SHA256_BLOCK do
    local b = string.byte(key, i)
    opad[i] = string.char(bxor(b, 0x5c))
    ipad[i] = string.char(bxor(b, 0x36))
  end
  opad = table.concat(opad)
  ipad = table.concat(ipad)

  return M.sha256(opad .. M.sha256(ipad .. msg))
end

function M.hmac_sha256_hex(key, msg)
  return toHex(M.hmac_sha256(key, msg))
end

-- =============================================================
-- AES-128 (CBC mode)
-- Reference: FIPS 197
-- Key schedule + encrypt + decrypt
-- =============================================================

local AES_SBOX = {
  [0]=0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

local AES_INV_SBOX = {}
for i = 0, 255 do AES_INV_SBOX[AES_SBOX[i]] = i end

local AES_RCON = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }

-- GF(2^8) multiplication by 2
local function xtime(b)
  if band(b, 0x80) ~= 0 then
    return band(bxor(lshift(b, 1), 0x1b), 0xff)
  else
    return band(lshift(b, 1), 0xff)
  end
end

-- Multiply a by b in GF(2^8)
local function gmul(a, b)
  local p = 0
  for _ = 1, 8 do
    if band(b, 1) ~= 0 then p = bxor(p, a) end
    local hi = band(a, 0x80)
    a = band(lshift(a, 1), 0xff)
    if hi ~= 0 then a = bxor(a, 0x1b) end
    b = rshift(b, 1)
  end
  return p
end

-- Expand 16-byte key to 11 round keys (176 bytes)
local function aes_key_expand(key)
  assert(#key == 16, "AES-128 requires 16-byte key")
  local rk = {}
  for i = 1, 16 do rk[i] = string.byte(key, i) end

  for i = 5, 44 do
    local idx = (i - 1) * 4
    local t1, t2, t3, t4 = rk[idx-3], rk[idx-2], rk[idx-1], rk[idx]
    if (i - 1) % 4 == 0 then
      -- RotWord + SubWord + Rcon
      local n1, n2, n3, n4 = t2, t3, t4, t1
      t1 = bxor(AES_SBOX[n1], AES_RCON[(i - 1) / 4])
      t2 = AES_SBOX[n2]
      t3 = AES_SBOX[n3]
      t4 = AES_SBOX[n4]
    end
    local prev = (i - 5) * 4
    rk[idx+1] = bxor(rk[prev+1], t1)
    rk[idx+2] = bxor(rk[prev+2], t2)
    rk[idx+3] = bxor(rk[prev+3], t3)
    rk[idx+4] = bxor(rk[prev+4], t4)
  end

  return rk
end

local function aes_add_round_key(s, rk, round)
  local off = round * 16
  for i = 1, 16 do s[i] = bxor(s[i], rk[off + i]) end
end

local function aes_sub_bytes(s)
  for i = 1, 16 do s[i] = AES_SBOX[s[i]] end
end

local function aes_inv_sub_bytes(s)
  for i = 1, 16 do s[i] = AES_INV_SBOX[s[i]] end
end

local function aes_shift_rows(s)
  local t = s[2]; s[2] = s[6]; s[6] = s[10]; s[10] = s[14]; s[14] = t
  local u = s[3]; local v = s[7]; s[3] = s[11]; s[7] = s[15]; s[11] = u; s[15] = v
  local w = s[4]; s[4] = s[16]; s[16] = s[12]; s[12] = s[8]; s[8] = w
end

local function aes_inv_shift_rows(s)
  local t = s[14]; s[14] = s[10]; s[10] = s[6]; s[6] = s[2]; s[2] = t
  local u = s[3]; local v = s[7]; s[3] = s[11]; s[7] = s[15]; s[11] = u; s[15] = v
  local w = s[8]; s[8] = s[12]; s[12] = s[16]; s[16] = s[4]; s[4] = w
end

local function aes_mix_columns(s)
  for c = 0, 3 do
    local i = c * 4
    local s0, s1, s2, s3 = s[i+1], s[i+2], s[i+3], s[i+4]
    local t = bxor(s0, s1, s2, s3)
    s[i+1] = bxor(s0, t, xtime(bxor(s0, s1)))
    s[i+2] = bxor(s1, t, xtime(bxor(s1, s2)))
    s[i+3] = bxor(s2, t, xtime(bxor(s2, s3)))
    s[i+4] = bxor(s3, t, xtime(bxor(s3, s0)))
  end
end

local function aes_inv_mix_columns(s)
  for c = 0, 3 do
    local i = c * 4
    local s0, s1, s2, s3 = s[i+1], s[i+2], s[i+3], s[i+4]
    s[i+1] = bxor(gmul(s0, 0x0e), gmul(s1, 0x0b), gmul(s2, 0x0d), gmul(s3, 0x09))
    s[i+2] = bxor(gmul(s0, 0x09), gmul(s1, 0x0e), gmul(s2, 0x0b), gmul(s3, 0x0d))
    s[i+3] = bxor(gmul(s0, 0x0d), gmul(s1, 0x09), gmul(s2, 0x0e), gmul(s3, 0x0b))
    s[i+4] = bxor(gmul(s0, 0x0b), gmul(s1, 0x0d), gmul(s2, 0x09), gmul(s3, 0x0e))
  end
end

local function aes_encrypt_block(block, rk)
  local s = {}
  for i = 1, 16 do s[i] = string.byte(block, i) end
  aes_add_round_key(s, rk, 0)
  for round = 1, 9 do
    aes_sub_bytes(s)
    aes_shift_rows(s)
    aes_mix_columns(s)
    aes_add_round_key(s, rk, round)
  end
  aes_sub_bytes(s)
  aes_shift_rows(s)
  aes_add_round_key(s, rk, 10)
  return string.char(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8],
                     s[9], s[10], s[11], s[12], s[13], s[14], s[15], s[16])
end

local function aes_decrypt_block(block, rk)
  local s = {}
  for i = 1, 16 do s[i] = string.byte(block, i) end
  aes_add_round_key(s, rk, 10)
  for round = 9, 1, -1 do
    aes_inv_shift_rows(s)
    aes_inv_sub_bytes(s)
    aes_add_round_key(s, rk, round)
    aes_inv_mix_columns(s)
  end
  aes_inv_shift_rows(s)
  aes_inv_sub_bytes(s)
  aes_add_round_key(s, rk, 0)
  return string.char(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8],
                     s[9], s[10], s[11], s[12], s[13], s[14], s[15], s[16])
end

-- PKCS#7 padding
local function pkcs7_pad(data, block)
  local pad = block - (#data % block)
  return data .. string.rep(string.char(pad), pad)
end

local function pkcs7_unpad(data)
  if #data == 0 then return nil, "empty" end
  local pad = string.byte(data, #data)
  if pad == 0 or pad > 16 then return nil, "bad padding" end
  if #data < pad then return nil, "bad padding length" end
  for i = #data - pad + 1, #data do
    if string.byte(data, i) ~= pad then return nil, "bad padding bytes" end
  end
  return data:sub(1, #data - pad)
end

-- AES-128-CBC encrypt. key and iv must be 16 bytes raw.
function M.aes128_cbc_encrypt(plaintext, key, iv)
  assert(#key == 16, "key must be 16 bytes")
  assert(#iv == 16, "iv must be 16 bytes")

  local rk = aes_key_expand(key)
  local padded = pkcs7_pad(plaintext, 16)
  local out = {}
  local prev = iv

  for i = 1, #padded, 16 do
    local block = padded:sub(i, i + 15)
    local xored = {}
    for j = 1, 16 do
      xored[j] = string.char(bxor(string.byte(block, j), string.byte(prev, j)))
    end
    local cipher = aes_encrypt_block(table.concat(xored), rk)
    out[#out + 1] = cipher
    prev = cipher
  end

  return table.concat(out)
end

function M.aes128_cbc_decrypt(ciphertext, key, iv)
  assert(#key == 16, "key must be 16 bytes")
  assert(#iv == 16, "iv must be 16 bytes")
  assert(#ciphertext % 16 == 0, "ciphertext must be multiple of 16 bytes")
  if #ciphertext == 0 then return "" end

  local rk = aes_key_expand(key)
  local out = {}
  local prev = iv

  for i = 1, #ciphertext, 16 do
    local block = ciphertext:sub(i, i + 15)
    local plain = aes_decrypt_block(block, rk)
    local xored = {}
    for j = 1, 16 do
      xored[j] = string.char(bxor(string.byte(plain, j), string.byte(prev, j)))
    end
    out[#out + 1] = table.concat(xored)
    prev = block
  end

  local result = table.concat(out)
  local unpadded, err = pkcs7_unpad(result)
  if not unpadded then return nil, err end
  return unpadded
end

-- =============================================================
-- High-level encrypt/decrypt with key derivation
-- These are what the rest of the system uses.
-- =============================================================

-- Derive 16-byte AES key from a shared secret (any length) and a context tag.
function M.deriveKey(secret, context)
  return M.hmac_sha256(secret, "key:" .. tostring(context)):sub(1, 16)
end

-- Derive 16-byte IV from a shared secret and a context tag.
function M.deriveIV(secret, context)
  return M.hmac_sha256(secret, "iv:" .. tostring(context)):sub(1, 16)
end

-- High-level encrypt: returns hex-encoded ciphertext.
function M.encrypt(plaintext, secret, context)
  local key = M.deriveKey(secret, context)
  local iv = M.deriveIV(secret, context)
  local ct = M.aes128_cbc_encrypt(plaintext, key, iv)
  return toHex(ct)
end

-- High-level decrypt: takes hex, returns plaintext.
function M.decrypt(hexCiphertext, secret, context)
  if not hexCiphertext or hexCiphertext == "" then return "" end
  local ct = fromHex(hexCiphertext)
  local key = M.deriveKey(secret, context)
  local iv = M.deriveIV(secret, context)
  local pt, err = M.aes128_cbc_decrypt(ct, key, iv)
  if not pt then return nil, err end
  return pt
end

-- =============================================================
-- Random helpers
-- =============================================================

-- Seed once at module load
math.randomseed(os.epoch and os.epoch("utc") or os.time())

-- Returns n random bytes as a binary string.
function M.randomBytes(n)
  local out = {}
  for i = 1, n do out[i] = string.char(math.random(0, 255)) end
  return table.concat(out)
end

-- Returns hex-encoded random bytes.
function M.randomHex(nBytes)
  return toHex(M.randomBytes(nBytes))
end

-- Returns a token from a friendly alphabet (no ambiguous chars).
local TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
function M.randomToken(length)
  local out = {}
  for i = 1, length do
    local idx = math.random(1, #TOKEN_ALPHABET)
    out[i] = TOKEN_ALPHABET:sub(idx, idx)
  end
  return table.concat(out)
end

-- Format a token like XXXX-XXXX-XXXX-XXXX from a 16-char token.
function M.formatToken(token)
  if #token ~= 16 then return token end
  return token:sub(1,4) .. "-" .. token:sub(5,8) .. "-" .. token:sub(9,12) .. "-" .. token:sub(13,16)
end

-- Strip dashes from a formatted token.
function M.unformatToken(token)
  return (token:gsub("%-", ""))
end

-- =============================================================
-- Password hashing
-- Client-side hash: SHA256(domain : username : password)
-- Server stores this directly. We treat it as the credential.
-- =============================================================

function M.hashPassword(domain, username, password)
  return M.sha256hex(string.lower(domain) .. ":" .. string.lower(username) .. ":" .. password)
end

return M
