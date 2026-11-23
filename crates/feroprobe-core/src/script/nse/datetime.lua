-- NSE compatibility layer: the `datetime` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
local datetime = {}

-- Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
local function days_from_civil(y, m, d)
  y = m <= 2 and y - 1 or y
  local era = (y >= 0 and y or y - 399) // 400
  local yoe = y - era * 400
  local doy = (153 * (m + (m > 2 and -3 or 9)) + 2) // 5 + d - 1
  local doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
  return era * 146097 + doe - 719468
end

-- A date table (year, month, day, hour, min, sec) as Unix seconds, the
-- table being in UTC plus offset seconds.
datetime.date_to_timestamp = function(date, offset)
  local t = days_from_civil(date.year, date.month, date.day) * 86400
    + (date.hour or 12) * 3600 + (date.min or 0) * 60 + (date.sec or 0)
  return t - (offset or 0)
end

local function offset_text(offset)
  local sign = offset < 0 and "-" or "+"
  offset = math.abs(offset)
  return string.format("%s%02d:%02d", sign, offset // 3600, offset // 60 % 60)
end

-- "2026-11-23T12:00:00" (UTC, or with "+hh:mm" when offset is given);
-- t is Unix seconds or a date table.
datetime.format_timestamp = function(t, offset)
  if type(t) == "table" then
    local s = string.format("%04d-%02d-%02dT%02d:%02d:%02d",
      t.year, t.month, t.day, t.hour or 0, t.min or 0, math.floor(t.sec or 0))
    if offset then s = s .. offset_text(offset) end
    return s
  end
  local secs = math.floor(tonumber(t) or 0)
  local frac = (tonumber(t) or 0) - secs
  local s = os.date("!%Y-%m-%dT%H:%M:%S", secs + (offset or 0))
  if frac > 0 then s = s .. string.format("%.6f", frac):sub(2):gsub("0+$", "") end
  if offset then s = s .. offset_text(offset) end
  return s
end

-- format_time(interval, unit): interval in units of 1/unit seconds.
datetime.format_time = function(interval, unit)
  return fero.format_time((tonumber(interval) or 0) / (unit or 1))
end

datetime.format_difftime = function(t2, t1)
  local d = os.difftime(os.time(t2), os.time(t1))
  local s = fero.format_time(d)
  if d > 0 then s = "+" .. s end
  return s
end

datetime.record_skew = function(host, timestamp, received)
  fero.record_skew(timestamp, received)
end

return datetime
