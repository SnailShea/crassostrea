"""netfilter on a cluster node, run by netfilter.sh: each step runs in a new
network namespace (its own nftables, like a separate node) against a valkey
that keeps the shared state between the steps.

    python3 netfilter_cluster.py NETFILTER_DIR STEP

Steps: node1-bans, node2-starts, node2-reconciles, expired. VALKEY_PORT is
the port of the shared valkey on 127.0.0.1.
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, sys.argv[1])
os.environ['HA_NODES'] = 'mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2'
os.environ['HA_WITNESS'] = 'witness.example.com=10.0.0.3'
import redis  # noqa: E402

import main  # noqa: E402
from modules.HostNFTables import HostNFTables  # noqa: E402
from modules.Logger import Logger  # noqa: E402

step = sys.argv[2]


def ruleset():
    return subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, check=True).stdout


def check(name, ok):
    print(('ok   ' if ok else 'FAIL ') + name)
    return ok


main.logger = Logger()
main.r = redis.Redis(host='127.0.0.1', port=int(os.environ['VALKEY_PORT']), decode_responses=True)
main.tables = HostNFTables(main.chain_name, main.logger)
main.refreshF2boptions()
ok = check('cluster mode detected', main.SHARED_STATE and '10.0.0.3' in main.CLUSTER)

if step == 'node1-bans':
    main.r.set('F2B_OPTIONS', json.dumps({'max_attempts': 3, 'netban_ipv4': 24, 'netban_ipv6': 64}))
    main.refreshF2boptions()
    main.clear()
    main.tables.initChainIPv4()
    for _ in range(3):
        main.ban('45.33.32.7')
    ok &= check('node 1 bans', 'ip saddr 45.33.32.0/24' in ruleset())
    main.WHITELIST = list(main.CLUSTER)
    for _ in range(3):
        main.ban('10.0.0.2')
    ok &= check('peer address never banned', '10.0.0.' not in ruleset())
    # node 1 restarts: clear() must not wipe the shared list
    main.clear()
    ok &= check('stopping node 1 keeps the shared bans', '45.33.32.0/24' in main.r.hgetall('F2B_ACTIVE_BANS'))

elif step == 'node2-starts':
    main.clear()
    main.tables.initChainIPv4()
    main.restoreBans()
    ok &= check('node 2 restores the shared ban on start', 'ip saddr 45.33.32.0/24' in ruleset())

elif step == 'node2-reconciles':
    main.tables.initChainIPv4()
    main.restoreBans()
    # another node processed the UI's unban: the entry is gone
    main.r.hdel('F2B_ACTIVE_BANS', '45.33.32.0/24')
    main.quit_now = False
    # one round of autopurge (its loop ends when quit_now is set)
    original_sleep = time.sleep
    time.sleep = lambda seconds: setattr(main, 'quit_now', True)
    main.autopurge()
    time.sleep = original_sleep
    ok &= check('node 2 lifts a ban removed by another node', '45.33.32.0/24' not in ruleset())

elif step == 'expired':
    main.tables.initChainIPv4()
    main.r.hset('F2B_ACTIVE_BANS', '198.51.100.0/24', int(time.time()) - 5)
    main.restoreBans()
    ok &= check('expired shared bans are dropped, not applied',
                '198.51.100.0/24' not in ruleset() and '198.51.100.0/24' not in main.r.hgetall('F2B_ACTIVE_BANS'))

sys.exit(0 if ok else 1)
