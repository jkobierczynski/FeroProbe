-- NSE compatibility layer: the `irc` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local shortport = require "shortport"
local irc = {}

-- True for a port that is likely IRC: one of the common IRC ports, or a
-- service detected as IRC.
irc.portrule = shortport.port_or_service(
  { 194, 529, 994, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 7000, 8067 },
  { "irc", "ircs", "ircs-u", "ircd", "irc-serv" },
  "tcp"
)

return irc
