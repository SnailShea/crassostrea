-- Detectors of the impersonation checks (dofile from rspamd.local.lua).
-- data/web/crassostrea/services/impersonation.py has the same functions, for
-- the test of the web UI; keep them alike. Only ASCII is case-folded.
local exports = {}

-- Look-alike characters, mapped to what they imitate (applied after lower
-- casing): digits, letter pairs and Cyrillic/Greek letters
local CONFUSABLES = {
  {'rn', 'm'}, {'vv', 'w'}, {'cl', 'd'}, {'0', 'o'}, {'1', 'l'}, {'i', 'l'}, {'3', 'e'}, {'5', 's'}, {'7', 't'},
  {'\208\176', 'a'}, {'\208\181', 'e'}, {'\208\190', 'o'}, {'\209\128', 'p'}, {'\209\129', 'c'},
  {'\209\133', 'x'}, {'\209\131', 'y'}, {'\209\150', 'l'}, {'\206\191', 'o'}, {'\206\177', 'a'},
}

-- "Smith, John (CEO)" -> "smith john ceo"
function exports.normalize_name(value)
  local s = tostring(value or ''):lower():gsub('[%p%c]', ' '):gsub('%s+', ' ')
  return (s:gsub('^ ', ''):gsub(' $', ''))
end

-- Whether a display name contains a protected name as whole words, also
-- written "Last, First"
function exports.name_matches(display, name)
  local wanted = exports.normalize_name(name)
  if wanted == '' then
    return false
  end
  local haystack = ' ' .. exports.normalize_name(display) .. ' '
  if haystack:find(' ' .. wanted .. ' ', 1, true) then
    return true
  end
  local last, first = tostring(display or ''):match('^%s*([^,]+),%s*(.+)$')
  if last then
    local swapped = ' ' .. exports.normalize_name(first .. ' ' .. last) .. ' '
    return swapped:find(' ' .. wanted .. ' ', 1, true) ~= nil
  end
  return false
end

-- The label that identifies a domain: example of mail.example.com, of
-- example.co.uk (a two-letter country code under a short second level)
function exports.core(domain)
  local labels = {}
  for label in tostring(domain or ''):lower():gsub('%.$', ''):gmatch('[^%.]+') do
    labels[#labels + 1] = label
  end
  local n = #labels
  if n >= 3 and #labels[n] == 2 and #labels[n - 1] <= 3 then
    return labels[n - 2]
  end
  return labels[n - 1] or labels[n] or ''
end

function exports.skeleton(value)
  local s = tostring(value or ''):lower()
  for _, pair in ipairs(CONFUSABLES) do
    s = s:gsub(pair[1]:gsub('%p', '%%%0'), pair[2])
  end
  return s
end

-- Damerau-Levenshtein distance (adjacent transpositions), bytes
function exports.distance(a, b)
  local la, lb = #a, #b
  local d = {}
  for i = 0, la do
    d[i] = {[0] = i}
  end
  for j = 0, lb do
    d[0][j] = j
  end
  for i = 1, la do
    for j = 1, lb do
      local cost = a:sub(i, i) == b:sub(j, j) and 0 or 1
      d[i][j] = math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
      if i > 1 and j > 1 and a:sub(i, i) == b:sub(j - 1, j - 1) and a:sub(i - 1, i - 1) == b:sub(j, j) then
        d[i][j] = math.min(d[i][j], d[i - 2][j - 2] + 1)
      end
    end
  end
  return d[la][lb]
end

local function own(domain, protected)
  return domain == protected or domain:sub(-(#protected + 1)) == '.' .. protected
end

-- The protected domain that ``domain`` imitates, or nil: one with the protected
-- domain in front (example.com.evil.example), the name as a part joined with
-- hyphens (example-secure.example), the same name under
-- another suffix, the same skeleton, or a name at most 1 (5 to 8
-- characters) or 2 (longer) edits away. Short names are only compared by
-- skeleton.
function exports.lookalike(domain, protected_domains, exempt)
  domain = tostring(domain or ''):lower():gsub('%.$', '')
  if domain == '' or (exempt or {})[domain] then
    return nil
  end
  for _, protected in ipairs(protected_domains) do
    if own(domain, protected) then
      return nil
    end
  end
  local core = exports.core(domain)
  local skeleton = exports.skeleton(core)
  for _, protected in ipairs(protected_domains) do
    -- example.com.evil.example
    if domain:sub(1, #protected + 1) == protected .. '.' or domain:find('.' .. protected .. '.', 1, true) then
      return protected
    end
    local pcore = exports.core(protected)
    local pskeleton = exports.skeleton(pcore)
    if #pcore >= 3 then
      if core == pcore or skeleton == pskeleton then
        return protected
      end
      -- bigbank-secure.com
      if #pcore >= 4 and core:find('-', 1, true) then
        for token in core:gmatch('[^%-]+') do
          if token == pcore or exports.skeleton(token) == pskeleton then
            return protected
          end
        end
      end
      local limit = #pcore >= 9 and 2 or (#pcore >= 5 and 1 or 0)
      if limit > 0 and math.abs(#skeleton - #pskeleton) <= limit
          and exports.distance(skeleton, pskeleton) <= limit then
        return protected
      end
    end
  end
  return nil
end

return exports
