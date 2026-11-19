-- FeroProbe script: http-date
-- Written for FeroProbe from scratch, from RFC 9110 5.6.7 (HTTP-date)
-- and 6.6.1 (Date); GPL-3.0-or-later.

description = [[
Shows a web server's clock, from the Date header of its answer to one
GET request for /, and how far it is from the scanner's clock. The
difference is also noted for clock-skew.

The request carries FeroProbe's User-Agent, as every script HTTP
request does.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe" }

portrule = fero.portrule.http

local MONTHS = {
  jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6,
  jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12,
}

-- Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
local function days_from_civil(y, m, d)
  if m <= 2 then y = y - 1 end
  local era = y // 400
  local yoe = y - era * 400
  local mp = (m + 9) % 12
  local doy = (153 * mp + 2) // 5 + d - 1
  local doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
  return era * 146097 + doe - 719468
end

-- An HTTP-date in any of its three forms as Unix seconds, or nil.
local function parse_date(s)
  local d, mon, y, H, M, S
  -- IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
  d, mon, y, H, M, S = s:match("^%a+,%s+(%d%d?)%s+(%a%a%a)%s+(%d%d%d%d)%s+(%d%d):(%d%d):(%d%d)%s+GMT%s*$")
  if not d then
    -- RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
    d, mon, y, H, M, S = s:match("^%a+,%s+(%d%d?)%-(%a%a%a)%-(%d%d)%s+(%d%d):(%d%d):(%d%d)%s+GMT%s*$")
    if y then
      -- RFC 9110: a two-digit year more than 50 years ahead is in the past.
      y = tonumber(y) + 2000
      if y > tonumber(os.date("!%Y")) + 50 then y = y - 100 end
    end
  end
  if not d then
    -- asctime: Sun Nov  6 08:49:37 1994
    mon, d, H, M, S, y = s:match("^%a+%s+(%a%a%a)%s+(%d%d?)%s+(%d%d):(%d%d):(%d%d)%s+(%d%d%d%d)%s*$")
  end
  if not d then return nil end
  local m = MONTHS[mon:lower()]
  d, y, H, M, S = tonumber(d), tonumber(y), tonumber(H), tonumber(M), tonumber(S)
  if not m or d < 1 or d > 31 or H > 23 or M > 59 or S > 60 then return nil end
  return days_from_civil(y, m, d) * 86400 + H * 3600 + M * 60 + S
end

action = function(host, port)
  -- No body is read (max_body_size 0), so the scanner's time is taken
  -- when the headers came, not after a slow body.
  local resp, err = fero.http.get(host, port, "/",
    { truncated_ok = true, redirect_ok = false, max_body_size = 0 })
  local now = os.time()
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  local raw = resp.header and resp.header.date
  if not raw then return nil end
  local t = parse_date(raw)
  if not t then
    fero.debug(1, "cannot read the Date header: " .. raw)
    return nil
  end
  local d = t - now
  fero.record_skew(t, now)
  local out = fero.output_table()
  out.date = os.date("!%Y-%m-%dT%H:%M:%S+00:00", t)
  out.delta = d
  return out, string.format("%s; %s%s from local time.", raw, d > 0 and "+" or "", fero.format_time(d))
end
