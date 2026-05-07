-- /postroom/domain_srv.lua
-- Generic private domain server. Reads its domain config from disk
-- (written by install_disk.lua during the install ceremony) and runs
-- the shared mail_server core with is_public_server = false.

package.path = package.path
  .. ";/postroom/lib/?.lua"
  .. ";./src/lib/?.lua"
  .. ";./?.lua"

local C    = require("common")
local mail = require("mail_server")

local M = {}

M.CONFIG_PATH = "/postroom/config.txt"

local function bail(msg)
  print("")
  print("[domain_srv] " .. msg)
  print("[domain_srv] If this is a fresh computer, insert your install")
  print("             floppy and run the installer first.")
end

function M.run()
  if not fs then bail("fs API unavailable — exiting."); return end
  if not fs.exists(M.CONFIG_PATH) then
    bail("missing " .. M.CONFIG_PATH); return
  end
  local cfg = C.loadTable(M.CONFIG_PATH)
  if not cfg or type(cfg.domain) ~= "string" or type(cfg.station) ~= "string" then
    bail("config is corrupt or incomplete."); return
  end
  mail.run({
    station          = cfg.station,
    domain           = cfg.domain,
    is_public_server = false,
    registry_station = cfg.registry_station or "NNA_REG",
    branding         = cfg.branding or { display_name = cfg.domain },
  })
end

if not _G._POSTROOM_NO_AUTORUN then
  M.run()
end

return M
