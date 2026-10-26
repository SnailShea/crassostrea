-- Detectors of the outbound data loss prevention rules (dofile from
-- rspamd.local.lua). Each returns the different values it found in a text.
-- data/web/crassostrea/services/dlp.py has the same detectors, for the
-- rule test of the web UI; keep them alike.
local exports = {}

-- IBAN length by country
local IBAN_LENGTHS = {
  AD = 24, AE = 23, AL = 28, AT = 20, AZ = 28, BA = 20, BE = 16, BG = 22, BH = 22, BR = 29, CH = 21, CR = 22,
  CY = 28, CZ = 24, DE = 22, DK = 18, DO = 28, EE = 20, EG = 29, ES = 24, FI = 18, FO = 18, FR = 27, GB = 22,
  GE = 22, GI = 23, GL = 18, GR = 27, GT = 28, HR = 21, HU = 28, IE = 22, IL = 23, IQ = 23, IS = 26, IT = 27,
  JO = 30, KW = 30, KZ = 20, LB = 28, LC = 32, LI = 21, LT = 20, LU = 20, LV = 21, MC = 27, MD = 24, ME = 22,
  MK = 19, MR = 27, MT = 31, MU = 30, NL = 18, NO = 15, PK = 24, PL = 28, PS = 29, PT = 25, QA = 29, RO = 24,
  RS = 22, SA = 24, SC = 31, SE = 24, SI = 19, SK = 24, SM = 27, TL = 23, TN = 24, TR = 26, UA = 29, VA = 22,
  VG = 24, XK = 20,
}

local function luhn(digits)
  local sum, double = 0, false
  for i = #digits, 1, -1 do
    local d = tonumber(digits:sub(i, i))
    if double then
      d = d * 2
      if d > 9 then
        d = d - 9
      end
    end
    sum = sum + d
    double = not double
  end
  return sum % 10 == 0
end

-- Card numbers: 13 to 19 digits, single spaces or dashes between them, a
-- known first digit (2 to 6) and a valid Luhn check digit
function exports.credit_card(text)
  local found = {}
  for run in text:gmatch('[%d %-]+') do
    for piece in (run:gsub('[ %-][ %-]+', '|') .. '|'):gmatch('([^|]*)|') do
      local digits = piece:gsub('^[ %-]+', ''):gsub('[ %-]+$', ''):gsub('[ %-]', '')
      if #digits >= 13 and #digits <= 19 and digits:match('^[2-6]') and luhn(digits) then
        found[digits] = true
      end
    end
  end
  return found
end

local function iban_valid(iban)
  local rearranged = iban:sub(5) .. iban:sub(1, 4)
  local remainder = 0
  for c in rearranged:gmatch('.') do
    local value = c:match('%d') and c or tostring(c:byte() - 55)
    for d in value:gmatch('%d') do
      remainder = (remainder * 10 + tonumber(d)) % 97
    end
  end
  return remainder == 1
end

-- IBANs: country code, check digits and the country's length of letters and
-- digits (single spaces allowed), with a valid mod-97 checksum
function exports.iban(text)
  local found = {}
  local upper = text:upper()
  local start = 1
  while true do
    local s, e, country = upper:find('%f[%w](%u%u)%d%d', start)
    if not s then
      break
    end
    local length = IBAN_LENGTHS[country]
    if length then
      local chars, i = {}, s
      while #chars < length and i <= #upper do
        local c = upper:sub(i, i)
        if c:match('%w') then
          chars[#chars + 1] = c
        elseif not (c == ' ' and upper:sub(i + 1, i + 1):match('%w') and #chars > 0) then
          break
        end
        i = i + 1
      end
      local iban = table.concat(chars)
      if #iban == length and not upper:sub(i, i):match('%w') and iban_valid(iban) then
        found[iban] = true
      end
    end
    start = e + 1
  end
  return found
end

-- US social security numbers written as 123-45-6789 (not area 000, 666 or
-- 9xx, group 00 or serial 0000)
function exports.us_ssn(text)
  local found = {}
  for area, group, serial in text:gmatch('%f[%d](%d%d%d)%-(%d%d)%-(%d%d%d%d)%f[%D]') do
    if area ~= '000' and area ~= '666' and area:sub(1, 1) ~= '9' and group ~= '00' and serial ~= '0000' then
      found[area .. '-' .. group .. '-' .. serial] = true
    end
  end
  return found
end

-- Keywords and phrases, anywhere, ignoring case (ASCII)
function exports.keywords(text, words)
  local found = {}
  local lower = text:lower()
  for _, word in ipairs(words) do
    if lower:find(word:lower(), 1, true) then
      found[word:lower()] = true
    end
  end
  return found
end

-- A regular expression (rspamd_regexp, compiled by the caller)
function exports.regex(text, re)
  local found = {}
  local matches = re:search(text, false, true)
  for _, match in ipairs(matches or {}) do
    found[type(match) == 'table' and match[1] or match] = true
  end
  return found
end

return exports
