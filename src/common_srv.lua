-- /postroom/common_srv.lua
-- @common public mail server. Operated by the N.N.A.

package.path = package.path
  .. ";/postroom/lib/?.lua"
  .. ";./src/lib/?.lua"
  .. ";./?.lua"

local mail = require("mail_server")

mail.run({
  station          = "COMMON_SRV",
  domain           = "common",
  is_public_server = true,
  registry_station = "NNA_REG",
  branding = {
    display_name = "Common",
    sign_off     = "— Common Mail",
  },
})
