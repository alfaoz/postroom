-- tests/installers_test.lua
-- Syntax check for the six pastebin installer scripts. They depend on CC
-- APIs (http, fs, rednet, os.reboot) so they can't be EXECUTED in standalone
-- Lua, but loadfile() catches all syntax errors without executing — which
-- catches typos and unmatched parens before pastebin'ing.

local total, failed = 0, 0
local function check(name, expected, actual, extra)
  total = total + 1
  if expected == actual then print("[PASS] " .. name)
  else failed = failed + 1
    print("[FAIL] " .. name)
    if extra then print("       " .. extra) end
  end
end

local INSTALLERS = {
  "installers/install_registry.lua",
  "installers/install_nmail.lua",
  "installers/install_common.lua",
  "installers/install_domain.lua",
  "installers/install_client.lua",
  "installers/install_staff.lua",
}

for _, path in ipairs(INSTALLERS) do
  local f, err = loadfile(path)
  if f then
    check(path .. ": loads", true, true)
  else
    check(path .. ": loads", true, false, err or "(unknown)")
  end
end

-- Verify each installer points at the canonical GitHub raw URL.
local EXPECTED_BASE = "https://raw.githubusercontent.com/alfaoz/postroom/main"
for _, path in ipairs(INSTALLERS) do
  local f = io.open(path, "r")
  local body = f:read("*a"); f:close()
  if body:find(EXPECTED_BASE, 1, true) then
    check(path .. ": uses canonical BASE", true, true)
  else
    check(path .. ": uses canonical BASE", true, false,
          "did not find " .. EXPECTED_BASE)
  end
end

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
