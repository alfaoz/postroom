-- /postroom/nna_staff.lua
-- N.N.A. Office Operations Terminal.
-- Staff workstation: registers new domains, processes renewals/transfers/
-- revocations, looks up records, queries the audit log, writes install
-- floppies via the disk drive, and prints certificates and receipts.
--
-- Authenticates to NNA_REG with a per-terminal secret stored at
-- /postroom/staff_secret. The operator pastes the secret in once at
-- install time (printed by the registry on its first boot).

package.path = package.path
  .. ";/postroom/lib/?.lua"
  .. ";./src/lib/?.lua"
  .. ";./?.lua"

local crypto = require("crypto")
local wire   = require("wire")
local C      = require("common")

local M = {}

-- =============================================================
-- Constants
-- =============================================================

M.STATION         = "NNA_STAFF"
M.SECRET_PATH     = "/postroom/staff_secret"
M.REGISTRY_STATION = "NNA_REG"
M.REQUEST_TIMEOUT = 8

M.session = nil          -- { token, username, display_name, is_admin }

-- =============================================================
-- Secret loading
-- =============================================================

function M.loadSecret()
  if not fs then return nil end
  if not fs.exists(M.SECRET_PATH) then return nil end
  local f = fs.open(M.SECRET_PATH, "r")
  local s = C.trim(f.readAll() or ""); f.close()
  if s == "" then return nil end
  return s
end

function M.firstRunSecretSetup()
  -- Interactive setup: paste in the staff_secret printed by NNA_REG on its
  -- first boot. Stored at /postroom/staff_secret.
  C.clear()
  C.printColored("yellow", "Staff terminal setup")
  C.printColored("gray",   "--------------------")
  print("")
  print("This terminal is not yet paired with the registry.")
  print("On NNA_REG's first boot, the registry printed a 64-character")
  print("hex string. Paste it here to pair the terminal.")
  print("")
  io.write("Staff secret: ")
  local s = C.trim(io.read() or "")
  if #s ~= 64 or not s:match("^[0-9a-fA-F]+$") then
    C.printColored("red", "That doesn't look like a 32-byte hex secret.")
    return nil
  end
  if not fs then return s end
  local dir = fs.getDir(M.SECRET_PATH)
  if dir ~= "" and not fs.exists(dir) then fs.makeDir(dir) end
  local f = fs.open(M.SECRET_PATH, "w"); f.write(s); f.close()
  C.printColored("green", "Saved.")
  C.pause()
  return s
end

-- =============================================================
-- Network
-- =============================================================

local registryId

local function lookupRegistry()
  if registryId then return registryId end
  if not rednet or not rednet.lookup then return nil end
  registryId = rednet.lookup(wire.PROTOCOL, M.REGISTRY_STATION)
  return registryId
end

local function callREG(action, payload, secret)
  if not rednet then return nil, "no_rednet" end
  local id = lookupRegistry()
  if not id then return nil, "REGISTRY_NOT_FOUND" end
  return wire.sendRequest(id, M.STATION, "POSTROOM/REG",
    action, payload, secret, M.REQUEST_TIMEOUT)
end
M.callREG = callREG

-- =============================================================
-- UI
-- =============================================================

local function header(title)
  C.clear()
  C.printColored("yellow", "N.N.A. OFFICE TERMINAL")
  C.printColored("gray",   "----------------------")
  if M.session then
    print(("Staff: %s   Day: %d"):format(M.session.username, C.currentDay()))
  end
  print("")
  if title then C.printColored("white", title); print("") end
end

local function info(s)  C.printColored("white", s)  end
local function warn(s)  C.printColored("yellow", s) end
local function err(s)   C.printColored("red", s)    end
local function ok(s)    C.printColored("green", s)  end
local function dim(s)   C.printColored("gray", s)   end

-- Office-closed screen
local function officeClosedScreen()
  C.clear()
  print("")
  print("")
  C.printColored("yellow", "       N.N.A. OFFICE")
  print("")
  C.printColored("red",    "       --- CLOSED ---")
  print("")
  print("       Please return when staff is on duty.")
  print("")
  print("       Domain registrations, renewals, and transfers")
  print("            require an attendant on duty.")
  print("")
  C.printColored("gray",   "       Press Enter for staff login.")
  io.read()
end

-- =============================================================
-- Login / logout
-- =============================================================

local function staffLogin(staffSecret)
  while true do
    header("Staff Sign In")
    local user = C.askNonEmpty("Username")
    io.write("Password: ")
    local pw = read and read("*") or io.read()
    pw = C.trim(pw or "")
    local hash = crypto.hashPassword("nna", string.lower(user), pw)
    local data, e = callREG("staff_login", {
      username             = user,
      password_hash        = hash,
      terminal_computer_id = (os and os.getComputerID and os.getComputerID()) or 0,
    }, staffSecret)
    if data and data.session_token then
      M.session = {
        token        = data.session_token,
        username     = string.lower(user),
        display_name = data.staff_display_name,
        is_admin     = data.is_admin or false,
      }
      ok("Welcome, " .. (data.staff_display_name or user) .. ".")
      C.pause()
      return true
    else
      err("Login failed: " .. tostring(e))
      if not C.askYN("Try again?", true) then return false end
    end
  end
end

local function staffLogout(staffSecret)
  if not M.session then return end
  callREG("staff_logout", { session_token = M.session.token }, staffSecret)
  M.session = nil
end

-- =============================================================
-- Peripherals: floppy and printer
-- =============================================================

local function findDrive()
  if not peripheral then return nil end
  return peripheral.find("drive")
end

local function findPrinter()
  if not peripheral then return nil end
  return peripheral.find("printer")
end

local function writeInstallFloppy(meta)
  local drive = findDrive()
  if not drive then return false, "no disk drive attached" end
  if not drive.isDiskPresent() then return false, "no floppy in the drive" end
  local mount = drive.getMountPath()
  if not mount then return false, "drive has no mount path" end
  local path = mount .. "/postroom_install"
  local f = fs.open(path, "w")
  if not f then return false, "cannot write to floppy" end
  f.write(textutils.serialize(meta))
  f.close()
  -- Set a label so it's easy to identify
  if drive.setDiskLabel then
    drive.setDiskLabel("@" .. meta.domain .. " install")
  end
  return true
end

local function printOnPaper(title, lines)
  local printer = findPrinter()
  if not printer then return false, "no printer attached" end
  if not printer.newPage() then
    return false, "printer is out of paper or ink"
  end
  printer.setPageTitle(title)
  for i, line in ipairs(lines) do
    printer.setCursorPos(1, i)
    printer.write(line)
  end
  printer.endPage()
  return true
end

-- =============================================================
-- Operations
-- =============================================================

local function newRegistration(staffSecret)
  header("New Domain Registration")
  print("Step 1 of 4: Take down the application details.")
  print("")
  local applicant = C.askNonEmpty("Applicant real name (player name)")

  -- Admin staff can register the N.N.A.-operated public brands
  -- (gov / nna / nta / nga / nmail / common); regular staff can't.
  -- Let admin type any name and let the registry be the final gatekeeper.
  local allowReserved = M.session and M.session.is_admin or false
  local domain
  while true do
    domain = string.lower(C.askNonEmpty("Domain name (no @)"))
    local okv, e = C.validateDomainName(domain, allowReserved)
    if okv then break else err("Invalid: " .. e) end
  end

  local opUser
  while true do
    opUser = string.lower(C.askNonEmpty("Op username (e.g. 'barkeep')"))
    local oku, e = C.validateUsername(opUser, allowReserved)
    if oku then break else err("Invalid: " .. e) end
  end

  print("")
  info("Step 2 of 4: Confirm fees collected.")
  local appFee  = C.FEES.application + C.FEES.nna_share
  local regFee  = C.FEES.registration + C.FEES.nna_share
  local total   = appFee + regFee
  print(("  Application fee:  %sƒ"):format(C.formatMoney(appFee):gsub("f$", "")))
  print(("  Registration fee: %sƒ"):format(C.formatMoney(regFee):gsub("f$", "")))
  print(("  Total:            %sƒ"):format(C.formatMoney(total):gsub("f$", "")))
  print("")
  if not C.askYN("All fees collected from applicant?", false) then
    warn("Cancelled (fees not collected).")
    C.pause()
    return
  end

  -- Submit
  local data, e = callREG("register_domain", {
    session_token       = M.session.token,
    domain_name         = domain,
    applicant_realname  = applicant,
    op_username         = opUser,
    fee_paid            = total,
  }, staffSecret)
  if not data then
    err("Registry rejected the registration: " .. tostring(e))
    C.pause()
    return
  end

  print("")
  ok("Registry accepted. Install token issued.")
  print("  Token: " .. (data.formatted_token or data.install_token))
  print("  Expires: day " .. tostring(data.expires_day))
  print("")

  -- Step 3: write floppy
  info("Step 3 of 4: Insert a blank floppy in the disk drive.")
  C.pause()
  local floppyMeta = {
    type             = "POSTROOM_INSTALL",
    domain           = domain,
    token            = data.install_token,
    op_username      = opUser,
    registry_station = M.REGISTRY_STATION,
    issued_day       = C.currentDay(),
    expires_day      = data.expires_day,
  }
  local wok, werr = writeInstallFloppy(floppyMeta)
  if not wok then
    err("Couldn't write the floppy: " .. tostring(werr))
    warn("The token is still valid. You can write the floppy later by")
    warn("re-running this flow with the same token.")
  else
    ok("Floppy written.")
  end

  -- Step 4: print certificate + receipt
  info("Step 4 of 4: Print the certificate and receipt.")
  print("")
  local certLines = {
    "DOMAIN OF RECORD",
    "----------------",
    "",
    "  @" .. domain,
    "",
    "Issued to:  " .. applicant,
    "Op account: " .. opUser .. "@" .. domain,
    "Issued day: " .. tostring(C.currentDay()),
    "Token exp.: day " .. tostring(data.expires_day),
    "",
    "Token:      " .. (data.formatted_token or data.install_token),
    "",
    "Issued by:  " .. M.session.username,
    "            N.N.A. Office",
  }
  local cok, cerr = printOnPaper("@" .. domain .. " certificate", certLines)
  if cok then ok("Certificate printed.") else warn("Certificate print failed: " .. tostring(cerr)) end

  local rxLines = {
    "RECEIPT",
    "-------",
    "",
    "  Day: " .. tostring(C.currentDay()),
    "  @" .. domain,
    "",
    "  Application fee:  " .. tostring(appFee) .. "f",
    "  Registration fee: " .. tostring(regFee) .. "f",
    "  Total:            " .. tostring(total) .. "f",
    "",
    "  Received by: " .. M.session.username,
    "               N.N.A. Office",
  }
  local rok, rerr = printOnPaper("Receipt @" .. domain, rxLines)
  if rok then ok("Receipt printed.") else warn("Receipt print failed: " .. tostring(rerr)) end

  print("")
  info("Hand the floppy, certificate, and receipt to the applicant.")
  info("Tell them to install within " .. C.LIFECYCLE.install_token_days .. " days.")
  C.pause()
end

local function processRenewal(staffSecret)
  header("Process Renewal")
  local domain = string.lower(C.askNonEmpty("Domain to renew"))
  local fee = C.FEES.renewal + C.FEES.nna_share
  print(("Renewal fee: %dƒ"):format(fee))
  if not C.askYN("Fee collected?", false) then warn("Cancelled."); C.pause(); return end
  local data, e = callREG("renew_domain", {
    session_token = M.session.token, domain_name = domain, fee_paid = fee,
  }, staffSecret)
  if not data then err("Renewal failed: " .. tostring(e)); C.pause(); return end
  ok("Renewed. New expiry: day " .. tostring(data.new_expires_day) ..
     ", status: " .. tostring(data.status))
  printOnPaper("Renewal @" .. domain, {
    "RENEWAL RECEIPT",
    "---------------",
    "",
    "  @" .. domain,
    "  Day: " .. tostring(C.currentDay()),
    "  Renewal fee: " .. tostring(fee) .. "f",
    "  New expires: day " .. tostring(data.new_expires_day),
    "",
    "  Processed by: " .. M.session.username,
    "                N.N.A. Office",
  })
  C.pause()
end

local function processTransfer(staffSecret)
  header("Domain Transfer")
  local domain = string.lower(C.askNonEmpty("Domain to transfer"))
  local newOwner = C.askNonEmpty("New owner real name")
  io.write("New op password (printed for handover): ")
  local pw = read and read("*") or io.read()
  pw = C.trim(pw or "")
  if #pw < C.MIN_PASSWORD_LEN then
    err("Password too short.")
    C.pause(); return
  end
  -- Look up domain to find the actual op username
  local listData = callREG("list_domains",
    { session_token = M.session.token, filter = nil }, staffSecret)
  local domRec
  if listData then
    for _, d in ipairs(listData.domains or {}) do
      if d.name == domain then domRec = d end
    end
  end
  if not domRec then err("Domain not found."); C.pause(); return end

  local newHash = crypto.hashPassword(domain, domRec.owner_username or "op", pw)
  local data, e = callREG("transfer_domain", {
    session_token         = M.session.token,
    domain_name           = domain,
    new_owner_realname    = newOwner,
    new_op_password_hash  = newHash,
  }, staffSecret)
  if not data then err("Transfer failed: " .. tostring(e)); C.pause(); return end
  ok("Ownership transferred.")
  printOnPaper("Transfer @" .. domain, {
    "DOMAIN TRANSFER",
    "---------------",
    "",
    "  @" .. domain,
    "  Day: " .. tostring(C.currentDay()),
    "  New owner:  " .. newOwner,
    "  Op account: " .. (domRec.owner_username or "op") .. "@" .. domain,
    "  Temp pw:    " .. pw,
    "",
    "  *** New owner must change password on first login ***",
    "",
    "  Processed by: " .. M.session.username,
  })
  ok("Slip printed for new owner.")
  C.pause()
end

local function revokeDomain(staffSecret)
  header("Revoke Domain (Admin Only)")
  if not M.session.is_admin then
    err("Revocation requires admin privileges. End shift and have an")
    err("admin sign in.")
    C.pause(); return
  end
  local domain = string.lower(C.askNonEmpty("Domain to revoke"))
  local reason = C.askNonEmpty("Reason (recorded in audit)")
  if not C.confirmDanger("Revoking @" .. domain
                         .. " will shut down its server.") then
    warn("Cancelled."); C.pause(); return
  end
  local data, e = callREG("revoke_domain", {
    session_token = M.session.token,
    domain_name   = domain,
    reason        = reason,
  }, staffSecret)
  if not data then err("Revocation failed: " .. tostring(e)); C.pause(); return end
  ok("Revoked. Server notified.")
  C.pause()
end

local function lookupDomain(staffSecret)
  header("Domain Lookup")
  local domain = string.lower(C.askNonEmpty("Domain"))
  local data, e = callREG("list_domains",
    { session_token = M.session.token }, staffSecret)
  if not data then err("Failed: " .. tostring(e)); C.pause(); return end
  for _, d in ipairs(data.domains or {}) do
    if d.name == domain then
      print(string.rep("-", 50))
      print("Domain:           @" .. d.name)
      print("Status:           " .. d.status)
      print("Owner:            " .. (d.owner_realname or "?"))
      print("Op username:      " .. (d.owner_username or "?"))
      print("Registered day:   " .. tostring(d.registered_day or "?"))
      print("Expires day:      " .. tostring(d.expires_day or "?"))
      print("Server id:        " .. tostring(d.server_id or "(no install)"))
      print("Online:           " .. tostring(d.server_online))
      if d.revoked_day then
        print("Revoked day:      " .. tostring(d.revoked_day))
      end
      print(string.rep("-", 50))
      C.pause()
      return
    end
  end
  err("No record of @" .. domain .. ".")
  C.pause()
end

local function browseAll(staffSecret)
  header("All Domains")
  local data, e = callREG("list_domains",
    { session_token = M.session.token }, staffSecret)
  if not data then err("Failed: " .. tostring(e)); C.pause(); return end
  if #data.domains == 0 then dim("(no domains registered)"); C.pause(); return end
  for _, d in ipairs(data.domains) do
    local status_color = "white"
    if d.status == "REVOKED" then status_color = "red"
    elseif d.status == "SUSPENDED" then status_color = "yellow"
    elseif d.status == "PENDING_INSTALL" then status_color = "gray"
    end
    C.printColored(status_color, string.format("  @%-16s %-16s  exp d%-5s  %s",
      d.name, d.status,
      tostring(d.expires_day or "?"),
      d.server_online and "online" or "offline"))
  end
  print("")
  C.pause()
end

local function todayTransactions(staffSecret)
  header("Today's Activity")
  local data, e = callREG("audit_query",
    { session_token = M.session.token, since_day = C.currentDay() }, staffSecret)
  if not data then err("Failed: " .. tostring(e)); C.pause(); return end
  if #data.entries == 0 then dim("(no entries today)"); C.pause(); return end
  for _, en in ipairs(data.entries) do
    print(string.format("  %s  %s  %-22s %s",
      tostring(en.day), en.actor or "?", en.action or "?",
      tostring(en.target or "")))
    if en.details then dim("    " .. en.details) end
  end
  print("")
  C.pause()
end

local function resetOpPassword(staffSecret)
  header("Reset Op Password (Admin Only)")
  if not M.session.is_admin then
    err("Admin privileges required.")
    C.pause(); return
  end
  local domain = string.lower(C.askNonEmpty("Domain"))
  if not C.askYN("Generate a fresh temp password for op@" .. domain .. "?", true) then
    warn("Cancelled."); C.pause(); return
  end
  local data, e = callREG("reset_op_password",
    { session_token = M.session.token, domain_name = domain }, staffSecret)
  if not data then err("Failed: " .. tostring(e)); C.pause(); return end
  ok("Password reset.")
  print("")
  print("  Op account:  " .. data.op_username .. "@" .. domain)
  C.printColored("yellow", "  New password: " .. data.new_password)
  C.printColored("red",    "  *** WRITE THIS DOWN ***")
  if not data.delivery_ok then
    warn("Server delivery failed: " .. tostring(data.delivery_error))
    warn("The password was generated but the mail server didn't acknowledge.")
    warn("If the server is offline, retry after it comes back up.")
  end
  printOnPaper("Op pw reset @" .. domain, {
    "OP PASSWORD RESET",
    "-----------------",
    "",
    "  @" .. domain,
    "  Day: " .. tostring(C.currentDay()),
    "  Op account:  " .. data.op_username .. "@" .. domain,
    "  Temp pw:     " .. data.new_password,
    "",
    "  *** Op must change this password on first login ***",
    "",
    "  Issued by: " .. M.session.username,
  })
  C.pause()
end

local function purgeRevokedDomain(staffSecret)
  header("Purge Revoked Domain (Admin Only)")
  if not M.session.is_admin then
    err("Admin privileges required.")
    C.pause(); return
  end
  local domain = string.lower(C.askNonEmpty("Domain to purge"))
  if not C.confirmDanger("This permanently deletes the @" .. domain ..
                         " record. The name returns to the pool.") then
    warn("Cancelled."); C.pause(); return
  end
  local data, e = callREG("purge_domain",
    { session_token = M.session.token, domain_name = domain }, staffSecret)
  if not data then err("Failed: " .. tostring(e)); C.pause(); return end
  ok("Purged. @" .. domain .. " is available for re-registration.")
  C.pause()
end

local function forceTick(staffSecret)
  header("Force Lifecycle Tick (Admin Only)")
  if not M.session.is_admin then
    err("Admin privileges required.")
    C.pause(); return
  end
  if not C.askYN("Run the daily tick now? (Useful after /time set jumps.)", true) then
    warn("Cancelled."); C.pause(); return
  end
  local data, e = callREG("force_tick",
    { session_token = M.session.token }, staffSecret)
  if not data then err("Failed: " .. tostring(e)); C.pause(); return end
  ok(("Tick run for day %d."):format(data.day))
  if #data.changes == 0 then
    dim("No status changes.")
  else
    info("Status changes:")
    for _, c in ipairs(data.changes) do print("  " .. c) end
  end
  C.pause()
end

local function viewAuditLog(staffSecret)
  header("Audit Log")
  io.write("Since day (blank = all): ")
  local s = C.trim(io.read() or "")
  local since = tonumber(s)
  io.write("Action filter (e.g. REGISTER_DOMAIN, blank = all): ")
  local kind = C.trim(io.read() or "")
  if kind == "" then kind = nil end
  local data, e = callREG("audit_query",
    { session_token = M.session.token, since_day = since, kind = kind },
    staffSecret)
  if not data then err("Failed: " .. tostring(e)); C.pause(); return end
  if #data.entries == 0 then dim("(no matches)"); C.pause(); return end
  for _, en in ipairs(data.entries) do
    print(string.format("  d%-4s  %-14s  %-22s %s",
      tostring(en.day), en.actor or "?", en.action or "?",
      tostring(en.target or "")))
    if en.details then dim("        " .. en.details) end
  end
  print("")
  C.pause()
end

-- =============================================================
-- Main menu
-- =============================================================

local function mainMenu(staffSecret)
  while M.session do
    C.clear()
    C.printColored("yellow", "N.N.A. OFFICE TERMINAL")
    print(("Staff: %s    Day %d"):format(M.session.username, C.currentDay()))
    if M.session.is_admin then dim("(admin)") end
    print("")
    print(" 1. New domain registration")
    print(" 2. Process renewal")
    print(" 3. Domain transfer")
    print(" 4. Look up domain")
    print(" 5. Browse all domains")
    print(" 6. Revoke domain (admin)")
    print(" 7. Today's activity")
    print(" 8. Audit log")
    print(" 9. Reset op password (admin)")
    print("10. Purge revoked domain (admin)")
    print("11. Force lifecycle tick (admin)")
    print("")
    print(" 0. End shift (logout)")
    print("")
    local n = C.askNumber("Pick", 0)
    if     n == 1  then newRegistration(staffSecret)
    elseif n == 2  then processRenewal(staffSecret)
    elseif n == 3  then processTransfer(staffSecret)
    elseif n == 4  then lookupDomain(staffSecret)
    elseif n == 5  then browseAll(staffSecret)
    elseif n == 6  then revokeDomain(staffSecret)
    elseif n == 7  then todayTransactions(staffSecret)
    elseif n == 8  then viewAuditLog(staffSecret)
    elseif n == 9  then resetOpPassword(staffSecret)
    elseif n == 10 then purgeRevokedDomain(staffSecret)
    elseif n == 11 then forceTick(staffSecret)
    elseif n == 0  then
      staffLogout(staffSecret)
      ok("Shift ended."); C.pause()
      return
    end
  end
end

-- =============================================================
-- Top-level loop
-- =============================================================

function M.run()
  if not rednet then print("rednet unavailable — exiting"); return end
  local _, side = wire.openModem()
  if not side then print("No modem found — exiting"); return end

  local secret = M.loadSecret()
  if not secret then
    secret = M.firstRunSecretSetup()
    if not secret then return end
  end

  while true do
    if not M.session then
      officeClosedScreen()
      if not staffLogin(secret) then
        -- Login refused: back to closed screen
      end
    else
      mainMenu(secret)
    end
  end
end

if not _G._POSTROOM_NO_AUTORUN then
  M.run()
end

return M
