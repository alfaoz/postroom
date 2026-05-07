-- /postroom/nmail_srv.lua
-- @nmail public mail server. Operated by the N.N.A.

package.path = package.path
  .. ";/postroom/lib/?.lua"
  .. ";./src/lib/?.lua"
  .. ";./?.lua"

local mail = require("mail_server")

mail.run({
  station          = "NMAIL_SRV",
  domain           = "nmail",
  is_public_server = true,
  registry_station = "NNA_REG",
  branding = {
    display_name = "National Mail",
    sign_off     = "— NIO Mail Service",
  },
})
