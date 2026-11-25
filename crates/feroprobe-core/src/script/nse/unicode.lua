-- NSE compatibility layer: the `unicode` module (UTF-8, UTF-16, CP437).
-- Written for FeroProbe from nmap's public API documentation, RFC 3629,
-- RFC 2781 and the CP437 code page (not from nselib); GPL-3.0-or-later,
-- like FeroProbe.
local unicode = {}

---
-- unicode.utf8_enc(cp): cp in UTF-8 (surrogates are not refused).
function unicode.utf8_enc(cp)
  if cp < 0x80 then return string.char(cp) end
  if cp < 0x800 then
    return string.char(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f))
  end
  if cp < 0x10000 then
    return string.char(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f))
  end
  return string.char(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f),
    0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f))
end

---
-- unicode.utf8_dec(buf, pos): the position after the character at pos and
-- its code point, or nil and an error.
function unicode.utf8_dec(buf, pos)
  pos = pos or 1
  local b = buf:byte(pos)
  if not b then return nil, "End of string" end
  local n, cp
  if b < 0x80 then return pos + 1, b
  elseif b & 0xe0 == 0xc0 then n, cp = 1, b & 0x1f
  elseif b & 0xf0 == 0xe0 then n, cp = 2, b & 0x0f
  elseif b & 0xf8 == 0xf0 then n, cp = 3, b & 0x07
  else return nil, "Invalid UTF-8 lead byte" end
  for i = 1, n do
    local c = buf:byte(pos + i)
    if not c or c & 0xc0 ~= 0x80 then return nil, "Invalid UTF-8 sequence" end
    cp = (cp << 6) | (c & 0x3f)
  end
  return pos + n + 1, cp
end

---
-- unicode.utf16_enc(cp, bigendian): cp in UTF-16 (little-endian unless
-- bigendian), with a surrogate pair above 0xFFFF.
function unicode.utf16_enc(cp, bigendian)
  local fmt = bigendian and ">I2" or "<I2"
  if cp < 0x10000 then return string.pack(fmt, cp) end
  cp = cp - 0x10000
  return string.pack(fmt, 0xd800 | (cp >> 10)) .. string.pack(fmt, 0xdc00 | (cp & 0x3ff))
end

---
-- unicode.utf16_dec(buf, pos, bigendian): the position after the
-- character at pos and its code point.
function unicode.utf16_dec(buf, pos, bigendian)
  pos = pos or 1
  local fmt = bigendian and ">I2" or "<I2"
  local cp
  cp, pos = string.unpack(fmt, buf, pos)
  if cp >= 0xd800 and cp <= 0xdbff and pos + 1 <= #buf then
    local lo = string.unpack(fmt, buf, pos)
    if lo >= 0xdc00 and lo <= 0xdfff then
      cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00)
      pos = pos + 2
    end
  end
  return pos, cp
end

-- CP437 bytes 0x80 to 0xFF as code points.
local CP437 = {
  0xc7, 0xfc, 0xe9, 0xe2, 0xe4, 0xe0, 0xe5, 0xe7, 0xea, 0xeb, 0xe8, 0xef, 0xee, 0xec, 0xc4, 0xc5,
  0xc9, 0xe6, 0xc6, 0xf4, 0xf6, 0xf2, 0xfb, 0xf9, 0xff, 0xd6, 0xdc, 0xa2, 0xa3, 0xa5, 0x20a7, 0x192,
  0xe1, 0xed, 0xf3, 0xfa, 0xf1, 0xd1, 0xaa, 0xba, 0xbf, 0x2310, 0xac, 0xbd, 0xbc, 0xa1, 0xab, 0xbb,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
  0x255d, 0x255c, 0x255b, 0x2510,
  0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566,
  0x2560, 0x2550, 0x256c, 0x2567,
  0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588,
  0x2584, 0x258c, 0x2590, 0x2580,
  0x3b1, 0xdf, 0x393, 0x3c0, 0x3a3, 0x3c3, 0xb5, 0x3c4, 0x3a6, 0x398, 0x3a9, 0x3b4, 0x221e, 0x3c6,
  0x3b5, 0x2229,
  0x2261, 0xb1, 0x2265, 0x2264, 0x2320, 0x2321, 0xf7, 0x2248, 0xb0, 0x2219, 0xb7, 0x221a, 0x207f,
  0xb2, 0x25a0, 0xa0,
}
local CP437_REV = {}
for i, cp in ipairs(CP437) do CP437_REV[cp] = 0x7f + i end

-- unicode.cp437_dec(buf, pos) and unicode.cp437_enc(cp): CP437 (bytes
-- below 0x80 as ASCII); cp437_enc gives nil for what CP437 lacks.
function unicode.cp437_dec(buf, pos)
  pos = pos or 1
  local b = buf:byte(pos)
  if b < 0x80 then return pos + 1, b end
  return pos + 1, CP437[b - 0x7f]
end

function unicode.cp437_enc(cp)
  if cp < 0x80 then return string.char(cp) end
  local b = CP437_REV[cp]
  return b and string.char(b) or nil
end

---
-- unicode.decode(buf, decoder, bigendian): the code points of buf.
function unicode.decode(buf, decoder, bigendian)
  local out, pos = {}, 1
  while pos <= #buf do
    local cp
    pos, cp = decoder(buf, pos, bigendian)
    if not pos then break end
    out[#out + 1] = cp
  end
  return out
end

---
-- unicode.encode(list, encoder, bigendian): the code points encoded.
function unicode.encode(list, encoder, bigendian)
  local out = {}
  for i, cp in ipairs(list) do out[i] = encoder(cp, bigendian) or "" end
  return table.concat(out)
end

---
-- unicode.transcode(buf, decoder, encoder, bigendian_dec, bigendian_enc):
-- buf decoded and encoded again.
function unicode.transcode(buf, decoder, encoder, bigendian_dec, bigendian_enc)
  local out, pos = {}, 1
  while pos <= #buf do
    local ok, npos, cp = pcall(decoder, buf, pos, bigendian_dec)
    if not ok or not npos then break end
    pos = npos
    out[#out + 1] = encoder(cp, bigendian_enc) or ""
  end
  return table.concat(out)
end

-- unicode.utf16to8(from) and unicode.utf8to16(from): little-endian UTF-16
-- to UTF-8 and back.
function unicode.utf16to8(from)
  return unicode.transcode(from, unicode.utf16_dec, unicode.utf8_enc, false, nil)
end

function unicode.utf8to16(from)
  return unicode.transcode(from, unicode.utf8_dec, unicode.utf16_enc, nil, false)
end

---
-- unicode.chardet(buf, len): a guess at buf's encoding from its first len
-- bytes (100): "ascii", "utf-8", "utf-16be", "utf-16le" or "other".
function unicode.chardet(buf, len)
  buf = buf:sub(1, len or 100)
  if buf:sub(1, 3) == "\xef\xbb\xbf" then return "utf-8" end
  if buf:sub(1, 2) == "\xfe\xff" then return "utf-16be" end
  if buf:sub(1, 2) == "\xff\xfe" then return "utf-16le" end
  local z = buf:find("\0", 1, true)
  if z then return z % 2 == 1 and "utf-16be" or "utf-16le" end
  if not buf:find("[\x80-\xff]") then return "ascii" end
  local pos = 1
  while pos <= #buf do
    local npos = unicode.utf8_dec(buf, pos)
    if not npos then
      -- A character cut off by len still counts as UTF-8.
      if #buf - pos < 3 and buf:find("^[\xc0-\xf7][\x80-\xbf]*$", pos) then
        return "utf-8"
      end
      return "other"
    end
    pos = npos
  end
  return "utf-8"
end

return unicode
