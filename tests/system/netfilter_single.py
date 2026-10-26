"""netfilter on a single gateway, run by netfilter.sh inside `unshare -rn`:
the ban logic (main.py) with fakeredis and the real nftables backend.

    python3 netfilter_single.py NETFILTER_DIR
"""
import json
import subprocess
import sys

sys.path.insert(0, sys.argv[1])
import fakeredis  # noqa: E402

import main  # noqa: E402
from modules.HostNFTables import HostNFTables  # noqa: E402
from modules.Logger import Logger  # noqa: E402


def ruleset():
  return subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, check=True).stdout


checks = []


def check(name, ok):
  checks.append(ok)
  print('ok  ' if ok else 'FAIL', name)


main.logger = Logger()
main.r = fakeredis.FakeRedis(decode_responses=True)
main.r.set('F2B_OPTIONS', json.dumps({'max_attempts': 3, 'netban_ipv4': 24, 'netban_ipv6': 64}))
main.tables = HostNFTables(main.chain_name, main.logger)
main.clear()
main.tables.initChainIPv4()

for _ in range(2):
  main.ban('45.33.32.7')
check('not banned before max_attempts', '45.33.32.0/24' not in ruleset())
main.ban('45.33.32.8')
check('banned as /24 after 3 attempts', 'ip saddr 45.33.32.0/24' in ruleset())
check('F2B_ACTIVE_BANS set', '45.33.32.0/24' in main.r.hgetall('F2B_ACTIVE_BANS'))

main.ban('10.1.2.3')
main.ban('::ffff:127.0.0.1')
check('private/loopback never banned', '10.1.2' not in ruleset())

main.WHITELIST = ['93.184.216.0/24']
for _ in range(3):
  main.ban('93.184.216.20')
check('allowlisted not banned', '93.184.216' not in ruleset())

for _ in range(3):
  main.ban('2a01:4f8:5:6::1')
check('ipv6 banned as /64', 'ip6 saddr 2a01:4f8:5:6::/64' in ruleset())

main.r.hset('F2B_QUEUE_UNBAN', '45.33.32.0/24', 1)
main.unban('45.33.32.0/24')
check('queued unban removes rule and keys', '45.33.32.0/24' not in ruleset()
      and '45.33.32.0/24' not in main.r.hgetall('F2B_ACTIVE_BANS') and not main.r.hgetall('F2B_QUEUE_UNBAN'))

main.permBan('192.0.2.0/24')
check('perm ban', 'ip saddr 192.0.2.0/24' in ruleset() and '192.0.2.0/24' in main.r.hgetall('F2B_PERM_BANS'))
main.permBan('192.0.2.0/24', unban=True)
check('perm unban', '192.0.2.0/24' not in ruleset() and not main.r.hgetall('F2B_PERM_BANS'))

main.clear()
check('clear removes the table', 'crassostrea' not in ruleset())
print('failures:', checks.count(False))
sys.exit(1 if False in checks else 0)
