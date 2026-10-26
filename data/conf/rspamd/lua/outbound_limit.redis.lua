-- Outbound limit check in Valkey (EVALSHA from rspamd.local.lua; the web UI's
-- tests run it too). Fixed windows: the recipients a sender had in the
-- current period. A refused message is not counted, and is recorded for the
-- Outbound limits page (sf_rl_hits, sf_rl_hit:<sender>; kept 7 days).
--
-- KEYS[1]  counter sf_rl:<seconds>:<sender>:<window>
-- ARGV     recipients, limit, seconds, sender, now (unix time)
-- Returns {1, count} if the message is within the limit (and counted),
-- {0, count} if not.
local n = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count + n > limit then
  local hit = 'sf_rl_hit:' .. ARGV[4]
  redis.call('HINCRBY', hit, 'count', 1)
  redis.call('HSET', hit, 'at', ARGV[5], 'limit', ARGV[2], 'seconds', ARGV[3])
  redis.call('EXPIRE', hit, 604800)
  redis.call('ZADD', 'sf_rl_hits', ARGV[5], ARGV[4])
  redis.call('ZREMRANGEBYSCORE', 'sf_rl_hits', '-inf', tonumber(ARGV[5]) - 604800)
  return {0, count}
end
count = redis.call('INCRBY', KEYS[1], n)
if count == n then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
end
return {1, count}
