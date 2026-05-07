-- tests/pr_client_test.lua
-- Smoke test for the PR client. The client is UI-driven so we don't unit-test
-- screens or network calls here — that happens end-to-end in CraftOS-PC.
-- This file just confirms the module compiles, defines its public API, and
-- doesn't crash on require.

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
    print("       got:      " .. tostring(actual)) end
end

local pr = require("pr_client")
check("module loads", "table", type(pr))
check("exposes run",  "function", type(pr.run))
check("exposes callUSR", "function", type(pr.callUSR))
check("has STATE_PATH",  "string", type(pr.STATE_PATH))
check("default state present",  "table", type(pr.state))
check("default cache present",  "table", type(pr.cache))

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
