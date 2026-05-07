-- install_client.lua
-- Pastebin installer for the PR mail client.
-- Run on any modemmed CC computer:
--   pastebin get <id> install
--   install
-- Then run `pr` to launch the client.

local BASE = "https://raw.githubusercontent.com/alfaoz/postroom/main"

local FILES = {
  { src = "src/lib/crypto.lua",  dst = "/postroom/lib/crypto.lua"  },
  { src = "src/lib/wire.lua",    dst = "/postroom/lib/wire.lua"    },
  { src = "src/lib/common.lua",  dst = "/postroom/lib/common.lua"  },
  { src = "src/pr_client.lua",   dst = "/postroom/pr_client.lua"   },
}

local PR_LAUNCHER = '-- pr launcher\nshell.run("/postroom/pr_client.lua")\n'

local function fail(msg) print("[install] " .. msg); error(msg, 0) end

local function ensureDir(p)
  if p == "" or fs.exists(p) then return end
  fs.makeDir(p)
end

local function fetch(srcRel, dst)
  local url = BASE .. "/" .. srcRel
  io.write("  " .. dst .. " ... ")
  local h, err = http.get(url)
  if not h then print("FAIL"); fail("http.get failed: " .. tostring(err)) end
  local body = h.readAll(); h.close()
  ensureDir(fs.getDir(dst))
  local f = fs.open(dst, "w")
  if not f then print("FAIL"); fail("cannot write " .. dst) end
  f.write(body); f.close()
  print("OK")
end

print("Postroom — PR mail client installer")
print(string.rep("-", 38))
if not http then fail("HTTP API disabled. Enable it and try again.") end

local mode = ({ ... })[1] or "install"
if mode == "update" then
  print("Update mode: re-fetching client...")
end

for _, f in ipairs(FILES) do fetch(f.src, f.dst) end

local lf = fs.open("/pr.lua", "w")
lf.write(PR_LAUNCHER); lf.close()
print("  /pr.lua ... OK")

print("")
print("Done. Run `pr` to launch the client.")
print("If you don't see a modem, attach a wireless modem first.")
