-- Inbound rate limit check in Valkey (EVALSHA from rspamd.local.lua; the web
-- UI's tests run it too). Fixed windows: the messages of a sending IP, a
-- recipient or bounces to a recipient in the current period. A refused
-- message counts nowhere, and is recorded for the Rate limits page
-- (sf_irl_hits, sf_irl_hit:<label>; kept 7 days).
--
-- KEYS     counters sf_irl:<kind>:<seconds>:<key>:<window>, one per limit
-- ARGV[1]  now (unix time); then for each key: limit, seconds, label (<kind>:<key>)
-- Returns {1} if the message is within every limit (and counted once in
-- each), {0, i} if the counter KEYS[i] is full.
local now = tonumber(ARGV[1])
for i, key in ipairs(KEYS) do
  local base = 2 + (i - 1) * 3
  local limit = tonumber(ARGV[base])
  local count = tonumber(redis.call('GET', key) or '0')
  if count + 1 > limit then
    local label = ARGV[base + 2]
    local hit = 'sf_irl_hit:' .. label
    redis.call('HINCRBY', hit, 'count', 1)
    redis.call('HSET', hit, 'at', now, 'limit', limit, 'seconds', ARGV[base + 1])
    redis.call('EXPIRE', hit, 604800)
    redis.call('ZADD', 'sf_irl_hits', now, label)
    redis.call('ZREMRANGEBYSCORE', 'sf_irl_hits', '-inf', now - 604800)
    return {0, i}
  end
end
for i, key in ipairs(KEYS) do
  if redis.call('INCR', key) == 1 then
    redis.call('EXPIRE', key, tonumber(ARGV[3 + (i - 1) * 3]))
  end
end
return {1}
