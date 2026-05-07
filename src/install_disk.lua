-- /postroom/install_disk.lua
-- Install ceremony for a private domain server. Run from a CC computer
-- with the install floppy inserted. Reads disk/postroom_install for the
-- token, contacts NNA_REG, consumes the token, writes local config and
-- credentials, sets up startup.lua to launch the domain server on boot.
--
-- Prereq: the source files (lib/*.lua, domain_srv.lua) must already be
-- present at /postroom/. The pastebin-distributed installer (final phase)
-- handles the source-fetch step before invoking this script.

package.path = package.path
  .. ";/postroom/lib/?.lua"
  .. ";./src/lib/?.lua"
  .. ";./?.lua"

local crypto = require("crypto")
local wire   = require("wire")
local C      = require("common")

local INSTALL_FILE_NAMES = {
  "disk/postroom_install",
  "disk1/postroom_install",  -- dual-disk-drive setups
  "disk2/postroom_install",
  "disk3/postroom_install",
}

local STATE_PATH      = "/postroom/state.txt"
local SECRET_PATH     = "/postroom/secret"
local CONFIG_PATH     = "/postroom/config.txt"
local STARTUP_PATH    = "/startup.lua"
local SERVER_SCRIPT   = "/postroom/domain_srv.lua"

-- =============================================================
-- Locate and read the install floppy
-- =============================================================

local function findInstallFile()
  if not fs then return nil end
  for _, p in ipairs(INSTALL_FILE_NAMES) do
    if fs.exists(p) then return p end
  end
  return nil
end

local function readInstallFile(path)
  local f = fs.open(path, "r")
  if not f then return nil, "cannot open" end
  local txt = f.readAll(); f.close()
  local data = textutils.unserialize(txt)
  if type(data) ~= "table" then return nil, "corrupt" end
  if data.type ~= "POSTROOM_INSTALL" then return nil, "wrong file type" end
  for _, k in ipairs({ "domain", "token", "op_username", "registry_station" }) do
    if type(data[k]) ~= "string" then return nil, "missing field: " .. k end
  end
  return data
end

-- =============================================================
-- UI
-- =============================================================

local function banner(meta)
  C.clear()
  C.printColored("yellow", "POSTROOM Domain Server Installer")
  C.printColored("gray",   "--------------------------------")
  print("")
  print("  Domain:           @" .. meta.domain)
  print("  Op username:      " .. meta.op_username)
  print("  Issued day:       " .. tostring(meta.issued_day or "?"))
  print("  Token expires:    day " .. tostring(meta.expires_day or "?"))
  print("  Registry station: " .. meta.registry_station)
  print("")
  return C.askYN("Proceed with installation?", true)
end

-- =============================================================
-- Network: consume install token
-- =============================================================

local function consumeToken(meta)
  if not rednet then return nil, "rednet unavailable" end
  local _, side = wire.openModem()
  if not side then return nil, "no modem found" end
  rednet.host(wire.PROTOCOL, "INSTALL:" .. tostring(os.getComputerID()))

  local registryId = rednet.lookup(wire.PROTOCOL, meta.registry_station)
  if not registryId then return nil, "registry not found" end

  local cid = os.getComputerID()
  print("[install] contacting " .. meta.registry_station
        .. " (id=" .. registryId .. ")...")

  -- HMAC keyed on the install token itself
  local data, err = wire.sendRequest(
    registryId,
    "INSTALL:" .. tostring(cid),
    "POSTROOM/REG", "consume_install_token",
    { token = meta.token, computer_id = cid,
      requested_op_username = meta.op_username },
    meta.token, 8)
  return data, err
end

-- =============================================================
-- Filesystem setup
-- =============================================================

local function ensureDir(path)
  if not fs.exists(path) then fs.makeDir(path) end
end

local function writeFile(path, contents)
  local dir = fs.getDir(path)
  if dir ~= "" then ensureDir(dir) end
  local f = fs.open(path, "w")
  f.write(contents); f.close()
end

local function buildInitialState(meta, regResponse)
  local opName = regResponse.op_username or meta.op_username
  local hash = crypto.hashPassword(meta.domain, opName, regResponse.op_initial_password)
  local today = (os and os.day and os.day()) or 0
  return {
    domain_meta = {
      domain_name      = meta.domain,
      server_id        = (os and os.getComputerID and os.getComputerID()) or 0,
      is_public_server = false,
      registry_station = meta.registry_station,
      branding         = { display_name = meta.domain },
      install = {
        installed_day = today,
        install_token = "(consumed)",
        registry_id   = meta.registry_station,
      },
    },
    users = {
      [opName] = {
        username             = opName,
        password_hash        = hash,
        created_day          = today,
        last_login_day       = nil,
        must_change_password = true,
        is_op                = true,
        is_deputy            = false,
        is_system            = false,
      },
      pm = { username = "pm", is_system = true, created_day = today },
      abuse = { username = "abuse", is_system = true, created_day = today },
      noreply = { username = "noreply", is_system = true, created_day = today },
    },
    mailboxes = {
      [opName] = { inbox = {}, sent = {}, trash = {} },
      pm      = { inbox = {}, sent = {}, trash = {} },
      abuse   = { inbox = {}, sent = {}, trash = {} },
      noreply = { inbox = {}, sent = {}, trash = {} },
    },
    messages  = {},
    sessions  = {},
    audit_log = { {
      day = today, time = (os and os.epoch and os.epoch("utc"))
                          or (os.time() and os.time() * 1000) or 0,
      actor = "INSTALL", action = "BOOTSTRAP",
      target = meta.domain, details = "domain server installed",
    } },
    counters  = {
      next_msg_id    = 1,
      total_messages = 0,
      total_users    = 4,
    },
    last_trash_purge_day = -1,
  }
end

local function buildConfig(meta)
  local upper = string.upper(meta.domain)
  return {
    domain           = meta.domain,
    station          = upper .. "_SRV",
    registry_station = meta.registry_station,
    branding         = { display_name = meta.domain },
  }
end

local function buildStartup()
  return ([[-- generated by postroom installer
shell.run("%s")
]]):format(SERVER_SCRIPT)
end

-- =============================================================
-- Verify source files are in place
-- =============================================================

local function verifySources()
  local required = {
    "/postroom/lib/crypto.lua",
    "/postroom/lib/wire.lua",
    "/postroom/lib/common.lua",
    "/postroom/lib/mail_server.lua",
    SERVER_SCRIPT,
  }
  local missing = {}
  for _, p in ipairs(required) do
    if not fs.exists(p) then missing[#missing + 1] = p end
  end
  return missing
end

-- =============================================================
-- Main
-- =============================================================

local function main()
  if not fs then print("fs API unavailable."); return end
  if not rednet then print("rednet API unavailable."); return end

  local missing = verifySources()
  if #missing > 0 then
    C.printColored("red", "The Postroom server source is not installed yet:")
    for _, p in ipairs(missing) do print("  - missing: " .. p) end
    print("")
    print("Run the pastebin installer to fetch the source first, then")
    print("re-insert the floppy and run this installer again.")
    return
  end

  local installPath = findInstallFile()
  if not installPath then
    C.printColored("red",
      "No install floppy detected. Insert the floppy you received from")
    C.printColored("red",
      "the N.N.A. office and try again. Looked for:")
    for _, p in ipairs(INSTALL_FILE_NAMES) do print("  - " .. p) end
    return
  end

  local meta, ferr = readInstallFile(installPath)
  if not meta then
    C.printColored("red", "Floppy unreadable: " .. tostring(ferr))
    return
  end

  if not banner(meta) then
    print("Cancelled."); return
  end

  print("")
  local response, err = consumeToken(meta)
  if not response then
    C.printColored("red", "Install failed: " .. tostring(err))
    print("If the token is expired or already consumed, return to the")
    print("N.N.A. office for a new one.")
    return
  end

  -- Write secret + config + initial state + startup
  writeFile(SECRET_PATH, response.shared_secret)
  C.saveTable(CONFIG_PATH, buildConfig(meta))
  C.saveTable(STATE_PATH, buildInitialState(meta, response))
  writeFile(STARTUP_PATH, buildStartup())

  C.clear()
  C.printColored("yellow", "INSTALLATION COMPLETE")
  C.printColored("gray",   "---------------------")
  print("")
  print("  Domain:            @" .. meta.domain)
  print("  Op account:        " ..
        (response.op_username or meta.op_username) .. "@" .. meta.domain)
  print("")
  C.printColored("yellow", "  Temporary password: " ..
                          tostring(response.op_initial_password))
  C.printColored("red",    "  *** WRITE THIS DOWN ***")
  print("")
  print("  You will be required to change this password on first login.")
  print("")
  print("  Reboot to start the server. From then on, the server will")
  print("  launch automatically every time the computer powers on.")
  print("")
  if C.askYN("Reboot now?", true) then
    if os and os.reboot then os.reboot() end
  end
end

-- Expose internals for tests; run unless the test harness sets the flag.
local M = {
  findInstallFile   = findInstallFile,
  readInstallFile   = readInstallFile,
  buildInitialState = buildInitialState,
  buildConfig       = buildConfig,
  buildStartup      = buildStartup,
  verifySources     = verifySources,
  run               = main,
  STATE_PATH        = STATE_PATH,
  SECRET_PATH       = SECRET_PATH,
  CONFIG_PATH       = CONFIG_PATH,
  STARTUP_PATH      = STARTUP_PATH,
  SERVER_SCRIPT     = SERVER_SCRIPT,
}

if not _G._POSTROOM_NO_AUTORUN then
  main()
end

return M
