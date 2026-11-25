-- NSE compatibility layer: the `smbauth` module, the part that reads what
-- a server says about itself in its NTLM challenge, before any login.
-- Written for FeroProbe from nmap's public API documentation and
-- [MS-NLMP] (not from nselib), over fero.ntlm; GPL-3.0-or-later, like
-- FeroProbe.
--
-- Logins (password hashes, challenge responses, accounts, signing) are
-- not here: each of those functions raises an error naming itself.
local fero = ...
local smbauth = {}

---
-- smbauth.get_security_blob(security_blob, ...): with no blob from the
-- server, true and the first NTLM message (NEGOTIATE). It is always
-- FeroProbe's own NEGOTIATE, naming workstation FEROPROBE (IDS rules
-- 9100016/9100017), whatever flags the script asks for. A blob from the
-- server would start a login, which FeroProbe does not do.
function smbauth.get_security_blob(security_blob)
  if security_blob == nil then
    return true, fero.ntlm.negotiate_message()
  end
  error("smbauth.get_security_blob: answering an NTLM challenge (a login) is not available in FeroProbe", 2)
end

---
-- smbauth.get_host_info_from_security_blob(blob): what the NTLM
-- CHALLENGE in blob says: target_realm, netbios_computer_name,
-- netbios_domain_name, fqdn, dns_domain_name, dns_forest_name, timestamp
-- (Windows FILETIME, 100 ns since 1601) and os_major_version,
-- os_minor_version, os_build; nil when blob holds no challenge.
function smbauth.get_host_info_from_security_blob(security_blob)
  if type(security_blob) ~= "string" then return nil end
  local c = fero.ntlm.parse_challenge(security_blob)
  if not c then return nil end
  local info = {
    target_realm = c.target_name,
    netbios_computer_name = c.netbios_computer,
    netbios_domain_name = c.netbios_domain,
    fqdn = c.dns_computer,
    dns_domain_name = c.dns_domain,
    dns_forest_name = c.dns_tree,
  }
  if c.timestamp then
    info.timestamp = (c.timestamp + 11644473600) * 10000000
  end
  if c.version then
    local major, minor, build = c.version:match("^(%d+)%.(%d+)%.(%d+)$")
    info.os_major_version = tonumber(major)
    info.os_minor_version = tonumber(minor)
    info.os_build = tonumber(build)
  end
  return info
end

for _, name in ipairs({
  "add_account", "calculate_signature", "get_account", "get_password_response",
  "init_account", "lm_create_mac_key", "lm_create_response", "lmv2_create_response",
  "next_account", "ntlm_create_hash", "ntlm_create_mac_key", "ntlm_create_response",
  "ntlmv2_create_hash", "ntlmv2_create_response", "ntlmv2_session_response",
}) do
  smbauth[name] = function()
    error("smbauth." .. name .. " is not available in FeroProbe (no logins)", 2)
  end
end

return smbauth
