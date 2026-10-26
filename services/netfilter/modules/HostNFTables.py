import ipaddress

import nftables


class HostNFTables:
  """Ban rules in an nftables table of their own.

  ``table inet crassostrea`` has one base chain on the input hook with a
  priority before firewalld's (filter = 0), so a banned network is dropped
  whatever the host firewall allows. firewalld only flushes its own table,
  this one survives its reloads. Every ban is a rule ``saddr <net> drop``
  whose comment names the network, which is how unban finds it.
  """

  FAMILY = 'inet'
  PRIORITY = -10

  def __init__(self, chain_name, logger, table='crassostrea'):
    self.table = table
    self.chain_name = chain_name
    self.logger = logger
    self.nft = nftables.Nftables()
    self.nft.set_json_output(True)
    self.nft.set_handle_output(True)

  def _run(self, *commands, quiet=False):
    """Output of the JSON commands, True if there is none, False on errors."""
    query = {'nftables': [{'metainfo': {'json_schema_version': 1}}] + list(commands)}
    rc, output, error = self.nft.json_cmd(query)
    if rc != 0:
      if not quiet:
        self.logger.logWarn('nftables: %s' % (error or 'command failed').strip())
      return False
    return output or True

  def _table(self):
    return {'family': self.FAMILY, 'name': self.table}

  def _chain(self):
    return {'family': self.FAMILY, 'table': self.table, 'name': self.chain_name}

  def _comment(self, net):
    return 'crassostrea ban %s' % net

  def _rules(self):
    output = self._run({'list': {'chain': self._chain()}}, quiet=True)
    if not isinstance(output, dict):
      return []
    return [o['rule'] for o in output.get('nftables', []) if 'rule' in o]

  def initChainIPv4(self):
    chain = dict(self._chain(), type='filter', hook='input', prio=self.PRIORITY, policy='accept')
    if self._run({'add': {'table': self._table()}}, {'add': {'chain': chain}}):
      self.logger.logInfo('Ban rules are in table %s %s, chain %s' % (self.FAMILY, self.table, self.chain_name))

  def initChainIPv6(self):
    # the inet table covers both families
    pass

  def checkIPv4ChainOrder(self):
    # The chain has its own hook and priority, nothing can be inserted before
    # it. If the table was deleted (e.g. "nft flush ruleset"), exit so that
    # systemd restarts the service and the bans are rebuilt.
    if self._run({'list': {'chain': self._chain()}}, quiet=True) is False:
      self.logger.logCrit('Table %s %s is gone, exiting to rebuild it' % (self.FAMILY, self.table))
      return True, 2
    return False, 0

  def checkIPv6ChainOrder(self):
    return False, 0

  def clearIPv4Table(self):
    if self._run({'list': {'table': self._table()}}, quiet=True) is not False:
      self._run({'delete': {'table': self._table()}})
      self.logger.logInfo('Removed table %s %s' % (self.FAMILY, self.table))

  def clearIPv6Table(self):
    pass

  def _ban(self, source, protocol):
    net = ipaddress.ip_network(source, strict=False)
    if any(rule.get('comment') == self._comment(net) for rule in self._rules()):
      return True
    match = {'op': '==', 'left': {'payload': {'protocol': protocol, 'field': 'saddr'}},
             'right': {'prefix': {'addr': str(net.network_address), 'len': net.prefixlen}}}
    rule = {'family': self.FAMILY, 'table': self.table, 'chain': self.chain_name,
            'expr': [{'match': match}, {'counter': None}, {'drop': None}], 'comment': self._comment(net)}
    return self._run({'insert': {'rule': rule}}) is not False

  def _unban(self, source):
    net = ipaddress.ip_network(source, strict=False)
    removed = False
    for rule in self._rules():
      if rule.get('comment') == self._comment(net):
        target = {'family': self.FAMILY, 'table': self.table, 'chain': self.chain_name, 'handle': rule['handle']}
        removed = self._run({'delete': {'rule': target}}) is not False or removed
    return removed

  def banIPv4(self, source):
    return self._ban(source, 'ip')

  def banIPv6(self, source):
    return self._ban(source, 'ip6')

  def unbanIPv4(self, source):
    return self._unban(source)

  def unbanIPv6(self, source):
    return self._unban(source)
