-- tests/nna_staff_test.lua
-- Smoke test for the staff terminal. Like the PR client, this is heavily
-- UI-driven and depends on CC peripherals (drive, printer, rednet) — real
-- testing happens in CraftOS-PC. This file just confirms the module loads.

package.path = package.path
  .. ";../src/lib/?.lua;./src/lib/?.lua"
  .. ";../src/?.lua;./src/?.lua"

_G._POSTROOM_NO_AUTORUN = true

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

local s = require("nna_staff")
check("module loads",          "table",    type(s))
check("exposes run",           "function", type(s.run))
check("exposes callREG",       "function", type(s.callREG))
check("exposes loadSecret",    "function", type(s.loadSecret))
check("STATION constant",      "NNA_STAFF",            s.STATION)
check("REGISTRY_STATION const","NNA_REG",              s.REGISTRY_STATION)
check("SECRET_PATH",           "/postroom/staff_secret", s.SECRET_PATH)

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
