-- NSE compatibility layer: the `base32` module (RFC 4648 base32 and its
-- "extended hex" alphabet). Written for FeroProbe from nmap's public API
-- documentation (not from nselib); GPL-3.0-or-later, like FeroProbe.
local base32 = {}

local STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
local HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

-- base32.enc(p [, hexExtend]): p in base32, padded with "=" to a multiple
-- of 8 characters; with hexExtend the extended hex alphabet.
function base32.enc(p, hexExtend)
  p = tostring(p or "")
  local alpha = hexExtend and HEX or STD
  local out = {}
  for i = 1, #p, 5 do
    local chunk = p:sub(i, i + 4)
    local n = #chunk
    chunk = chunk .. string.rep("\0", 5 - n)
    local v = 0
    for j = 1, 5 do v = (v << 8) | chunk:byte(j) end
    -- 1..5 bytes give 2, 4, 5, 7, 8 characters.
    local chars = ({ 2, 4, 5, 7, 8 })[n]
    for k = 1, 8 do
      if k <= chars then
        local idx = (v >> (40 - 5 * k)) & 31
        out[#out + 1] = alpha:sub(idx + 1, idx + 1)
      else
        out[#out + 1] = "="
      end
    end
  end
  return table.concat(out)
end

-- base32.dec(e [, hexExtend]): the bytes of e; characters outside the
-- alphabet (padding, white space) are skipped. Letters of either case.
function base32.dec(e, hexExtend)
  e = tostring(e or ""):upper()
  local alpha = hexExtend and HEX or STD
  local rev = {}
  for i = 1, 32 do rev[alpha:byte(i)] = i - 1 end
  local out = {}
  local acc, bits = 0, 0
  for i = 1, #e do
    local v = rev[e:byte(i)]
    if v then
      acc = ((acc << 5) | v) & 0xffff
      bits = bits + 5
      if bits >= 8 then
        bits = bits - 8
        out[#out + 1] = string.char((acc >> bits) & 0xff)
      end
    end
  end
  return table.concat(out)
end

return base32
