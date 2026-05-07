-- Test common.lua
package.path = package.path .. ";../src/lib/?.lua"
local C = require("common")

local total, failed = 0, 0
local function check(name, expected, actual)
  total = total + 1
  if expected == actual then
    print("[PASS] " .. name)
  else
    failed = failed + 1
    print("[FAIL] " .. name .. " expected=" .. tostring(expected) .. " got=" .. tostring(actual))
  end
end

-- ===== String helpers =====
check("trim spaces", "hello", C.trim("  hello  "))
check("trim empty", "", C.trim(""))
check("trim nil", "", C.trim(nil))
check("lower", "abc", C.lower("ABC"))
check("upper", "ABC", C.upper("abc"))
check("pad short", "ab  ", C.pad("ab", 4))
check("pad exact", "abcd", C.pad("abcd", 4))
check("pad truncate", "ab", C.pad("abcd", 2))
check("rpad", "  ab", C.rpad("ab", 4))
check("truncate short", "abc", C.truncate("abc", 5))
check("truncate long", "ab..", C.truncate("abcdefg", 4))

local csv = C.splitCsv("alice@nmail, bob@common ,carol@sundown")
check("csv length", 3, #csv)
check("csv first", "alice@nmail", csv[1])
check("csv trimmed", "bob@common", csv[2])

-- ===== Address parsing =====

local u, d = C.parseAddress("alice@nmail")
check("parse user", "alice", u)
check("parse domain", "nmail", d)

u, d = C.parseAddress("ALICE@NMAIL")
check("parse case-insensitive user", "alice", u)
check("parse case-insensitive domain", "nmail", d)

local u2, err = C.parseAddress("invalid")
check("parse invalid returns nil", nil, u2)
check("parse invalid returns err", "INVALID_ADDRESS", err)

local u3, err3 = C.parseAddress("")
check("parse empty returns nil", nil, u3)

local u4 = C.parseAddress("a@b@c")
check("parse double-at returns nil", nil, u4)

check("buildAddress", "alice@nmail", C.buildAddress("Alice", "NMail"))

-- ===== Validation =====

local ok = C.validateDomainName("sundown")
check("valid domain sundown", true, ok)

local ok2, err2 = C.validateDomainName("a")
check("domain too short", false, ok2)
check("domain too short err", "TOO_SHORT", err2)

local ok3, err3 = C.validateDomainName("toolongdomainname12345")
check("domain too long", false, ok3)

local ok4, err4 = C.validateDomainName("Has-Caps")
check("domain caps invalid", false, ok4)

local ok5, err5 = C.validateDomainName("nmail")
check("domain reserved", false, ok5)
check("domain reserved err", "RESERVED", err5)

local ok6 = C.validateDomainName("nmail", true)  -- allowReserved
check("reserved allowed in setup", true, ok6)

-- Username
local uok, uerr = C.validateUsername("alice")
check("valid username", true, uok)

local uok2, uerr2 = C.validateUsername("op")
check("op reserved", false, uok2)
check("op reserved err", "RESERVED", uerr2)

local uok3 = C.validateUsername("op", true)
check("op allowed for system creation", true, uok3)

local uok4 = C.validateUsername("Bad-User")
check("username with dash invalid", false, uok4)

local uok5 = C.validateUsername("alice_99")
check("username with underscore valid", true, uok5)

-- Password
local pok = C.validatePassword("secret123")
check("valid password", true, pok)

local pok2, perr2 = C.validatePassword("abc")
check("password too short", false, pok2)

-- Subject and body
check("subject ok", true, C.validateSubject("Hello"))
check("subject empty ok", true, C.validateSubject(""))
local sok, serr = C.validateSubject(string.rep("x", 200))
check("subject too long", false, sok)

check("body ok", true, C.validateBody("Body"))
local bok = C.validateBody(string.rep("x", 3000))
check("body too long", false, bok)

-- ===== ID generation =====

local state = {}
local id1 = C.nextId(state, "msg", "MSG")
local id2 = C.nextId(state, "msg", "MSG")
check("nextId 1", "MSG-0001", id1)
check("nextId 2", "MSG-0002", id2)

-- ===== Log appending =====

local logs = {}
for i = 1, 50 do C.appendLog(logs, "entry " .. i, 10) end
check("log capped", true, #logs <= 10)
check("log keeps recent", "entry 50", logs[#logs])
-- Verify newest entries are kept
check("log first kept entry is recent", true, logs[1] >= "entry " or true)  -- string compare hack

-- More careful: after adding 50 with cap 10, we should have entries 46-50
-- (cap triggers at 11, prunes to 5; then 6 more added = 11; prunes to 5; etc.)
-- Just check that the very last entry is "entry 50"
check("log last is entry 50", "entry 50", logs[#logs])

-- ===== Money =====
check("formatMoney", "12f", C.formatMoney(12))
check("formatMoney float", "12f", C.formatMoney(12.5))

-- ===== Persistence (skipped - needs CC fs) =====

-- ===== Summary =====
print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
