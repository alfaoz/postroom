-- tests/install_test.lua
-- Smoke tests for domain_srv.lua and install_disk.lua.
-- Both files run side-effects on load and depend on CC APIs (fs, rednet,
-- os.reboot) — we don't try to exercise those here, just confirm the pure
-- helpers in install_disk produce the right shape, and that both modules
-- compile and expose their public API.

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
local function checkTrue(name, cond, why)
  total = total + 1
  if cond then print("[PASS] " .. name)
  else failed = failed + 1; print("[FAIL] " .. name .. " — " .. tostring(why)) end
end

-- ===== domain_srv loads cleanly =====

local ds = require("domain_srv")
check("domain_srv: loads",     "table",    type(ds))
check("domain_srv: has run",   "function", type(ds.run))
check("domain_srv: config path","string",   type(ds.CONFIG_PATH))

-- ===== install_disk loads + exposes helpers =====

local id = require("install_disk")
check("install_disk: loads",   "table",    type(id))
check("install_disk: has run", "function", type(id.run))
check("install_disk: buildConfig",       "function", type(id.buildConfig))
check("install_disk: buildInitialState", "function", type(id.buildInitialState))
check("install_disk: buildStartup",      "function", type(id.buildStartup))
check("install_disk: verifySources",     "function", type(id.verifySources))

-- ===== buildConfig produces the right shape =====

local cfg = id.buildConfig({
  domain = "sundown",
  registry_station = "NNA_REG",
})
check("buildConfig: domain",   "sundown",     cfg.domain)
check("buildConfig: station",  "SUNDOWN_SRV", cfg.station)
check("buildConfig: registry", "NNA_REG",     cfg.registry_station)
checkTrue("buildConfig: branding has display_name",
  cfg.branding and cfg.branding.display_name == "sundown")

-- ===== buildInitialState seeds op + system accounts with hashed temp pw =====

local crypto = require("crypto")
local meta = {
  domain           = "sundown",
  op_username      = "barkeep",
  registry_station = "NNA_REG",
}
local response = {
  shared_secret      = crypto.randomHex(32),
  op_username        = "barkeep",
  op_initial_password = "TX7K-9PQR-12AB-34CD",
}
local s = id.buildInitialState(meta, response)
check("state: domain set",        "sundown", s.domain_meta.domain_name)
check("state: not public",        false,     s.domain_meta.is_public_server)
check("state: registry station",  "NNA_REG", s.domain_meta.registry_station)
checkTrue("state: op exists",     s.users["barkeep"] ~= nil)
check("state: op is_op",          true,      s.users["barkeep"].is_op)
check("state: op must_change",    true,      s.users["barkeep"].must_change_password)
check("state: op password hashed",
  crypto.hashPassword("sundown", "barkeep", "TX7K-9PQR-12AB-34CD"),
  s.users["barkeep"].password_hash)
check("state: pm exists",         true,      s.users["pm"] ~= nil)
check("state: abuse exists",      true,      s.users["abuse"] ~= nil)
check("state: noreply exists",    true,      s.users["noreply"] ~= nil)
checkTrue("state: op mailbox seeded",
  s.mailboxes["barkeep"] ~= nil and type(s.mailboxes["barkeep"].inbox) == "table")
check("state: total_users 4",     4,         s.counters.total_users)
check("state: counters.next_msg_id", 1,      s.counters.next_msg_id)
checkTrue("state: audit log seeded with bootstrap", #s.audit_log == 1
                                  and s.audit_log[1].action == "BOOTSTRAP")

-- ===== buildStartup looks runnable =====

local startup = id.buildStartup()
check("startup: type", "string", type(startup))
checkTrue("startup: refers to domain_srv",
  string.find(startup, id.SERVER_SCRIPT, 1, true) ~= nil)

-- ===== summary =====

print("")
print(string.format("%d/%d tests passed", total - failed, total))
if failed > 0 then os.exit(1) end
