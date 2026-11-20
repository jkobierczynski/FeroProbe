-- FeroProbe script: smb-security-mode
-- Written for FeroProbe from scratch, from [MS-CIFS] 2.2.4.52 (NEGOTIATE);
-- GPL-3.0-or-later.

description = [[
Shows the security an SMB1 server asks for, from its answer to one NT LM
0.12 NEGOTIATE on TCP 445 (or 139, after a NetBIOS session request):

  authentication_level  user (each user logs in with their own password)
                        or share (one password per share, sent in plain
                        text: dangerous)
  challenge_response    supported, or plaintext-only (dangerous)
  message_signing       required, supported, or disabled (dangerous, but
                        the default): without required signing a
                        man-in-the-middle or SMB relay is possible

Servers that no longer speak SMB1 give no output; smb2-security-mode
covers SMB2 and SMB3. Logs in to nothing, so unlike nmap it names no
account. How far the server's clock is from the scanner's is noted for
clock-skew.

Script arguments:
  smbport          The port to use instead of 445 and 139.
  smb-security-mode.timeout
                   How long to wait for each answer, in milliseconds
                   (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

hostrule = function(host)
  return fero.smb.port(host) ~= nil
end

action = function(host)
  local port = fero.smb.port(host)
  if not port then return nil end
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local n = fero.smb.negotiate_v1(host, port, timeout, true)
  if not n then return nil end
  if n.time then fero.record_skew(n.time) end

  local mode = n.security_mode
  local out, warn = fero.output_table(), {}
  if mode & 1 ~= 0 then
    out.authentication_level = "user"
  else
    out.authentication_level = "share"
    warn.authentication_level = "dangerous"
  end
  if mode & 2 ~= 0 then
    out.challenge_response = "supported"
  else
    out.challenge_response = "plaintext-only"
    warn.challenge_response = "dangerous"
  end
  if mode & 8 ~= 0 then
    out.message_signing = "required"
  elseif mode & 4 ~= 0 then
    out.message_signing = "supported"
  else
    out.message_signing = "disabled"
    warn.message_signing = "dangerous, but default"
  end

  local lines = {}
  for _, k in ipairs({ "authentication_level", "challenge_response", "message_signing" }) do
    lines[#lines + 1] = string.format("\n  %s: %s%s", k, out[k],
      warn[k] and (" (" .. warn[k] .. ")") or "")
  end
  return out, table.concat(lines)
end
