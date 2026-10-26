#!/usr/bin/env python3

DEBUG = False

import re
import os
import sys
import time
import atexit
import signal
import ipaddress
from collections import Counter
from random import randint
from threading import Thread
from threading import Lock
import redis
import json
import dns.resolver
import dns.exception
import uuid
from modules.Logger import Logger
from modules.HostNFTables import HostNFTables

def logdebug(msg):
  if DEBUG:
    logger.logInfo("DEBUG: %s" % msg)

def cluster_addresses():
  """Addresses of the cluster members (HA_NODES, HA_WITNESS: name=address)."""
  entries = os.getenv('HA_NODES', '').split(',') + os.getenv('HA_WITNESS', '').split(',')
  return [e.split('=', 1)[1].strip() for e in entries if '=' in e]

# Globals
WHITELIST = []
BLACKLIST = []
bans = {}
# Networks banned in this host's nftables
banned = set()
# In a cluster all nodes share valkey: every node bans what the logs of all
# nodes report, F2B_ACTIVE_BANS is the shared list and a node lifts its own
# ban when the entry disappears (expired or unbanned in the UI on any node).
# The shared keys are therefore never cleared when one node starts or stops.
CLUSTER = cluster_addresses()
SHARED_STATE = bool(CLUSTER)
quit_now = False
exit_code = 0
lock = Lock()
chain_name = "input"
r = None
pubsub = None
clear_before_quit = False

def refreshF2boptions():
  global f2boptions
  global quit_now
  global exit_code
  f2boptions = {}

  if not r.get('F2B_OPTIONS'):
    f2boptions['ban_time'] = r.get('F2B_BAN_TIME')
    f2boptions['max_ban_time'] = r.get('F2B_MAX_BAN_TIME')
    f2boptions['ban_time_increment'] = r.get('F2B_BAN_TIME_INCREMENT')
    f2boptions['max_attempts'] = r.get('F2B_MAX_ATTEMPTS')
    f2boptions['retry_window'] = r.get('F2B_RETRY_WINDOW')
    f2boptions['netban_ipv4'] = r.get('F2B_NETBAN_IPV4')
    f2boptions['netban_ipv6'] = r.get('F2B_NETBAN_IPV6')
  else:
    try:
      f2boptions = json.loads(r.get('F2B_OPTIONS'))
    except ValueError as e:
      logger.logCrit(
        'Error loading F2B options: F2B_OPTIONS is not json. Exception: %s' % e)
      quit_now = True
      exit_code = 2

  verifyF2boptions(f2boptions)
  r.set('F2B_OPTIONS', json.dumps(f2boptions, ensure_ascii=False))

def verifyF2boptions(f2boptions):
  verifyF2boption(f2boptions, 'ban_time', 1800)
  verifyF2boption(f2boptions, 'max_ban_time', 10000)
  verifyF2boption(f2boptions, 'ban_time_increment', True)
  verifyF2boption(f2boptions, 'max_attempts', 10)
  verifyF2boption(f2boptions, 'retry_window', 600)
  verifyF2boption(f2boptions, 'netban_ipv4', 32)
  verifyF2boption(f2boptions, 'netban_ipv6', 128)
  verifyF2boption(f2boptions, 'banlist_id', str(uuid.uuid4()))
  verifyF2boption(f2boptions, 'manage_external', 0)

def verifyF2boption(f2boptions, f2boption, f2bdefault):
  f2boptions[f2boption] = f2boptions[f2boption] if f2boption in f2boptions and f2boptions[f2boption] is not None else f2bdefault

def refreshF2bregex():
  global f2bregex
  global quit_now
  global exit_code
  if not r.get('F2B_REGEX'):
    # the rules of the web UI (data/web/crassostrea/services/store.py F2B_REGEX)
    f2bregex = {}
    f2bregex[1] = r'Crassostrea UI: Invalid password for .+ by ([0-9a-f\.:]+)'
    f2bregex[2] = r'warning: non-SMTP command from .*\[([0-9a-f\.:]+)]:.+'
    f2bregex[3] = r'NOQUEUE: reject: RCPT from \[([0-9a-f\.:]+)].+Protocol error.+'
    f2bregex[4] = r'Crassostrea API: Invalid API key by ([0-9a-f\.:]+)'
    r.set('F2B_REGEX', json.dumps(f2bregex, ensure_ascii=False))
  else:
    try:
      f2bregex = {}
      f2bregex = json.loads(r.get('F2B_REGEX'))
    except ValueError:
      logger.logCrit('Error loading F2B options: F2B_REGEX is not json')
      quit_now = True
      exit_code = 2

def get_ip(address):
  ip = ipaddress.ip_address(address)
  if type(ip) is ipaddress.IPv6Address and ip.ipv4_mapped:
    ip = ip.ipv4_mapped
  if ip.is_private or ip.is_loopback:
    return False

  return ip

def ban(address):
  global f2boptions
  global lock
  logdebug("ban() called with address=%s" % address)
  refreshF2boptions()
  MAX_ATTEMPTS = int(f2boptions['max_attempts'])
  RETRY_WINDOW = int(f2boptions['retry_window'])
  NETBAN_IPV4 = '/' + str(f2boptions['netban_ipv4'])
  NETBAN_IPV6 = '/' + str(f2boptions['netban_ipv6'])

  ip = get_ip(address)
  if not ip:
    logdebug("No valid IP -- skipping ban()")
    return
  address = str(ip)
  self_network = ipaddress.ip_network(address)

  with lock:
    temp_whitelist = set(WHITELIST)
    logdebug("Checking if %s overlaps with any WHITELIST entries" % self_network)
    if temp_whitelist:
      for wl_key in temp_whitelist:
        wl_net = ipaddress.ip_network(wl_key, False)
        logdebug("Checking overlap between %s and %s" % (self_network, wl_net))
        if wl_net.overlaps(self_network):
          logger.logInfo(
            'Address %s is allowlisted by rule %s' % (self_network, wl_net))
          return

  net = ipaddress.ip_network(
    (address + (NETBAN_IPV4 if type(ip) is ipaddress.IPv4Address else NETBAN_IPV6)), strict=False)
  net = str(net)
  logdebug("Ban net: %s" % net)

  if not net in bans:
    bans[net] = {'attempts': 0, 'last_attempt': 0, 'ban_counter': 0}
    logdebug("Initing new ban counter for %s" % net)

  current_attempt = time.time()
  logdebug("Current attempt ts=%s, previous: %s, retry_window: %s" %
           (current_attempt, bans[net]['last_attempt'], RETRY_WINDOW))
  if current_attempt - bans[net]['last_attempt'] > RETRY_WINDOW:
    bans[net]['attempts'] = 0
    logdebug("Ban counter for %s reset as window expired" % net)

  bans[net]['attempts'] += 1
  bans[net]['last_attempt'] = current_attempt
  logdebug("%s attempts now %d" % (net, bans[net]['attempts']))

  if bans[net]['attempts'] >= MAX_ATTEMPTS:
    cur_time = int(round(time.time()))
    NET_BAN_TIME = calcNetBanTime(bans[net]['ban_counter'])
    logger.logCrit('Banning %s for %d minutes' % (net, NET_BAN_TIME / 60 ))
    if type(ip) is ipaddress.IPv4Address and int(f2boptions['manage_external']) != 1:
      with lock:
        logdebug("Calling tables.banIPv4(%s)" % net)
        tables.banIPv4(net)
    elif int(f2boptions['manage_external']) != 1:
      with lock:
        logdebug("Calling tables.banIPv6(%s)" % net)
        tables.banIPv6(net)

    logdebug("Updating F2B_ACTIVE_BANS[%s]=%d" %
              (net, cur_time + NET_BAN_TIME))
    r.hset('F2B_ACTIVE_BANS', '%s' % net, cur_time + NET_BAN_TIME)
    banned.add(net)
  else:
    logger.logWarn('%d more attempts in the next %d seconds until %s is banned' % (
      MAX_ATTEMPTS - bans[net]['attempts'], RETRY_WINDOW, net))

def unban(net):
  global lock
  logdebug("Calling unban() with net=%s" % net)
  if not net in bans:
    logger.logInfo(
      '%s is not banned, skipping unban and deleting from queue (if any)' % net)
    r.hdel('F2B_QUEUE_UNBAN', '%s' % net)
    # banned by another node of a cluster
    r.hdel('F2B_ACTIVE_BANS', '%s' % net)
    return
  logger.logInfo('Unbanning %s' % net)
  if type(ipaddress.ip_network(net)) is ipaddress.IPv4Network:
    with lock:
      logdebug("Calling tables.unbanIPv4(%s)" % net)
      tables.unbanIPv4(net)
  else:
    with lock:
      logdebug("Calling tables.unbanIPv6(%s)" % net)
      tables.unbanIPv6(net)
  r.hdel('F2B_ACTIVE_BANS', '%s' % net)
  r.hdel('F2B_QUEUE_UNBAN', '%s' % net)
  banned.discard(net)
  if net in bans:
    logdebug("Unban for %s, setting attempts=0, ban_counter+=1" % net)
    bans[net]['attempts'] = 0
    bans[net]['ban_counter'] += 1

def permBan(net, unban=False):
  global f2boptions
  global lock

  is_unbanned = False
  is_banned = False
  if type(ipaddress.ip_network(net, strict=False)) is ipaddress.IPv4Network:
    with lock:
      if unban:
        is_unbanned = tables.unbanIPv4(net)
      elif int(f2boptions['manage_external']) != 1:
        is_banned = tables.banIPv4(net)
  else:
    with lock:
      if unban:
        is_unbanned = tables.unbanIPv6(net)
      elif int(f2boptions['manage_external']) != 1:
        is_banned = tables.banIPv6(net)


  if is_unbanned:
    r.hdel('F2B_PERM_BANS', '%s' % net)
    logger.logCrit('Removed host/network %s from denylist' % net)
  elif is_banned:
    r.hset('F2B_PERM_BANS', '%s' % net, int(round(time.time())))
    logger.logCrit('Added host/network %s to denylist' % net)

def clear():
  global lock
  logger.logInfo('Clearing all bans')
  # In a cluster the bans stay in force on the other nodes: only this
  # host's rules are removed, unban() would delete the shared entries
  if not SHARED_STATE:
    for net in bans.copy():
      logdebug("Unbanning net: %s" % net)
      unban(net)
  with lock:
    logdebug("Clearing IPv4/IPv6 table")
    tables.clearIPv4Table()
    tables.clearIPv6Table()
    banned.clear()
    try:
      if r is not None and not SHARED_STATE:
        r.delete('F2B_ACTIVE_BANS')
        r.delete('F2B_PERM_BANS')
    except Exception as ex:
      logger.logWarn('Error clearing redis keys F2B_ACTIVE_BANS and F2B_PERM_BANS: %s' % ex)

def watch():
  global pubsub
  global quit_now
  global exit_code

  logger.logInfo('Watching Redis channel F2B_CHANNEL')
  pubsub.subscribe('F2B_CHANNEL')

  while not quit_now:
    try:
      for item in pubsub.listen():
        refreshF2bregex()
        for rule_id, rule_regex in f2bregex.items():
          if item['data'] and item['type'] == 'message':
            try:
              result = re.search(rule_regex, item['data'])
            except re.error:
              result = False
            if result:
              addr = result.group(1)
              ip = ipaddress.ip_address(addr)
              if ip.is_private or ip.is_loopback:
                continue
              logger.logWarn('%s matched rule id %s (%s)' % (addr, rule_id, item['data']))
              ban(addr)
    except Exception as ex:
      logger.logWarn('Error reading log line from pubsub: %s' % ex)
      pubsub = None
      quit_now = True
      exit_code = 2

def autopurge():
  global f2boptions
  logdebug("autopurge thread started")
  while not quit_now:
    logdebug("autopurge tick")
    time.sleep(10)
    refreshF2boptions()
    MAX_ATTEMPTS = int(f2boptions['max_attempts'])
    QUEUE_UNBAN = r.hgetall('F2B_QUEUE_UNBAN')
    logdebug("QUEUE_UNBAN: %s" % QUEUE_UNBAN)
    if QUEUE_UNBAN:
      for net in QUEUE_UNBAN:
        logdebug("Autopurge: unbanning queued net: %s" % net)
        unban(str(net))
    # Only check expiry for actively banned IPs:
    active_bans = r.hgetall('F2B_ACTIVE_BANS')
    now = time.time()
    for net_str, expire_str in active_bans.items():
      logdebug("Checking ban expiry for (actively banned): %s" % net_str)
      # Defensive: always process if timer missing or expired
      try:
        expire = float(expire_str)
      except Exception:
        logdebug("Invalid expire time for %s; unbanning" % net_str)
        unban(net_str)
        continue
      time_left = expire - now
      logdebug("Time left for %s: %.1f seconds" % (net_str, time_left))
      if time_left <= 0:
        logdebug("Ban expired for %s" % net_str)
        unban(net_str)
    # Bans lifted elsewhere (another node of a cluster)
    for net in list(banned):
      if not r.hexists('F2B_ACTIVE_BANS', net):
        logdebug("%s is no longer in F2B_ACTIVE_BANS" % net)
        unban(net)

def restoreBans():
  """Apply the shared bans of a cluster after a start."""
  now = time.time()
  for net, expire in r.hgetall('F2B_ACTIVE_BANS').items():
    try:
      if float(expire) <= now:
        r.hdel('F2B_ACTIVE_BANS', net)
        continue
    except ValueError:
      continue
    if int(f2boptions['manage_external']) != 1:
      with lock:
        if type(ipaddress.ip_network(net, strict=False)) is ipaddress.IPv4Network:
          tables.banIPv4(net)
        else:
          tables.banIPv6(net)
    bans[net] = {'attempts': 0, 'last_attempt': 0, 'ban_counter': 0}
    banned.add(net)
  if banned:
    logger.logInfo('Restored %d ban(s) of the cluster' % len(banned))

def crassostreaChainOrder():
  global lock
  global quit_now
  global exit_code
  while not quit_now:
    time.sleep(10)
    with lock:
      quit_now, exit_code = tables.checkIPv4ChainOrder()
      if quit_now: return
      quit_now, exit_code = tables.checkIPv6ChainOrder()

def calcNetBanTime(ban_counter):
  global f2boptions

  BAN_TIME = int(f2boptions['ban_time'])
  MAX_BAN_TIME = int(f2boptions['max_ban_time'])
  BAN_TIME_INCREMENT = bool(f2boptions['ban_time_increment'])
  NET_BAN_TIME = BAN_TIME if not BAN_TIME_INCREMENT else BAN_TIME * 2 ** ban_counter
  NET_BAN_TIME = max([BAN_TIME, min([NET_BAN_TIME, MAX_BAN_TIME])])
  return NET_BAN_TIME

def isIpNetwork(address):
  try:
    ipaddress.ip_network(address, False)
  except ValueError:
    return False
  return True

def genNetworkList(list):
  resolver = dns.resolver.Resolver()
  hostnames = []
  networks = []
  for key in list:
    if isIpNetwork(key):
      networks.append(key)
    else:
      hostnames.append(key)
  for hostname in hostnames:
    hostname_ips = []
    for rdtype in ['A', 'AAAA']:
      try:
        answer = resolver.resolve(qname=hostname, rdtype=rdtype, lifetime=3)
      except dns.exception.Timeout:
        logger.logInfo('Hostname %s timedout on resolve' % hostname)
        break
      except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        continue
      except dns.exception.DNSException as dnsexception:
        logger.logInfo('%s' % dnsexception)
        continue
      for rdata in answer:
        hostname_ips.append(rdata.to_text())
    networks.extend(hostname_ips)
  return set(networks)

def whitelistUpdate():
  global lock
  global quit_now
  global WHITELIST
  while not quit_now:
    start_time = time.time()
    list = r.hgetall('F2B_WHITELIST')
    new_whitelist = set(CLUSTER)
    if list:
      new_whitelist |= genNetworkList(list)
    with lock:
      if Counter(new_whitelist) != Counter(WHITELIST):
        WHITELIST = new_whitelist
        logger.logInfo('Allowlist was changed, it has %s entries' % len(WHITELIST))
    time.sleep(60.0 - ((time.time() - start_time) % 60.0))

def blacklistUpdate():
  global quit_now
  global BLACKLIST
  while not quit_now:
    start_time = time.time()
    list = r.hgetall('F2B_BLACKLIST')
    new_blacklist = []
    if list:
      new_blacklist = genNetworkList(list)
    if Counter(new_blacklist) != Counter(BLACKLIST):
      addban = set(new_blacklist).difference(BLACKLIST)
      delban = set(BLACKLIST).difference(new_blacklist)
      BLACKLIST = new_blacklist
      logger.logInfo('Denylist was changed, it has %s entries' % len(BLACKLIST))
      if addban:
        for net in addban:
          permBan(net=net)
      if delban:
        for net in delban:
          permBan(net=net, unban=True)
    time.sleep(60.0 - ((time.time() - start_time) % 60.0))

def sigterm_quit(signum, frame):
  global clear_before_quit
  logdebug("SIGTERM received, setting clear_before_quit to True and exiting")
  clear_before_quit = True
  sys.exit(exit_code)

def before_quit():
  logdebug("before_quit called, clear_before_quit=%s" % clear_before_quit)
  if clear_before_quit:
    clear()
  if pubsub is not None:
    pubsub.unsubscribe()

if __name__ == '__main__':
  logger = Logger()
  logdebug("Sys.argv: %s" % sys.argv)
  atexit.register(before_quit)
  signal.signal(signal.SIGTERM, sigterm_quit)

  tables = HostNFTables(chain_name, logger)

  clear()
  logger.logInfo("Initializing netfilter chain")
  tables.initChainIPv4()
  tables.initChainIPv6()

  # connect to redis (valkey)
  while True:
    try:
      redis_host = os.getenv('REDIS_HOST', '127.0.0.1')
      redis_port = int(os.getenv('REDIS_PORT_INTERNAL', '6379'))
      logdebug("Connecting redis (%s:%s)" % (redis_host, redis_port))
      r = redis.StrictRedis(
        host=redis_host, decode_responses=True, port=redis_port, db=0, password=os.environ['REDISPASS'])
      r.ping()
      pubsub = r.pubsub()
    except Exception as ex:
      logdebug(
        'Redis connection failed: %s - trying again in 3 seconds' % (ex))
      time.sleep(3)
    else:
      break
  logger.set_redis(r)
  logdebug("Redis connection established, setting up F2B keys")

  if r.exists('F2B_LOG'):
    logdebug("Renaming F2B_LOG to NETFILTER_LOG")
    r.rename('F2B_LOG', 'NETFILTER_LOG')
  if not SHARED_STATE:
    r.delete('F2B_ACTIVE_BANS')
    r.delete('F2B_PERM_BANS')

  refreshF2boptions()
  if SHARED_STATE:
    restoreBans()

  watch_thread = Thread(target=watch)
  watch_thread.daemon = True
  watch_thread.start()

  autopurge_thread = Thread(target=autopurge)
  autopurge_thread.daemon = True
  autopurge_thread.start()

  crassostreachainwatch_thread = Thread(target=crassostreaChainOrder)
  crassostreachainwatch_thread.daemon = True
  crassostreachainwatch_thread.start()

  blacklistupdate_thread = Thread(target=blacklistUpdate)
  blacklistupdate_thread.daemon = True
  blacklistupdate_thread.start()

  whitelistupdate_thread = Thread(target=whitelistUpdate)
  whitelistupdate_thread.daemon = True
  whitelistupdate_thread.start()

  while not quit_now:
    time.sleep(0.5)

  logdebug("Exiting with code %s" % exit_code)
  sys.exit(exit_code)