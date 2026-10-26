-- Before the hash lookups of a message (EVALSHA from rspamd.local.lua; the
-- web UI's tests run it too): the API keys, the cached verdicts and a
-- VirusTotal request reserved within the per-minute limit.
--
-- ARGV     minute (unix time / 60), VirusTotal requests per minute, then the
--          SHA-256 of each attachment
-- Returns  MalwareBazaar key, VirusTotal key, then per hash the cached
--          verdicts of mhr, mb and vt ('' if none) and '1' if a VirusTotal
--          request may be made
local mb = redis.call('HGET', 'sf_hashcheck_keys', 'malwarebazaar') or ''
local vt = redis.call('HGET', 'sf_hashcheck_keys', 'virustotal') or ''
local out = {mb, vt}
for i = 3, #ARGV do
  local hash = ARGV[i]
  for _, source in ipairs({'mhr', 'mb', 'vt'}) do
    out[#out + 1] = redis.call('GET', 'sf_hash:' .. source .. ':' .. hash) or ''
  end
  local allowed = '0'
  if vt ~= '' and not redis.call('GET', 'sf_hash:vt:' .. hash) then
    local key = 'sf_vt_rate:' .. ARGV[1]
    local count = redis.call('INCR', key)
    if count == 1 then
      redis.call('EXPIRE', key, 120)
    end
    if count <= tonumber(ARGV[2]) then
      allowed = '1'
    end
  end
  out[#out + 1] = allowed
end
return out
