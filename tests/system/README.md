# System tests

These tests run the configuration that `system/configure.sh` renders with the
real EL10 binaries, without installing anything and without root: the
binaries are downloaded with `dnf download` and extracted into a work
directory, and every test runs in an unprivileged user and network namespace,
where the cluster members get their own loopback addresses (10.0.0.x); the
`keepalived` test gives each node its own network namespace.

```bash
tests/system/run.sh              # everything
tests/system/run.sh valkey acme  # selected tests
```

| Test | What it checks |
| --- | --- |
| `render` | `setup.sh --ha --config-only`, join bundles, and a dry run of `configure.sh` for two nodes and a witness |
| `valkey` | Replication over mutual TLS, Sentinel failover, haproxy following the master, pub/sub, `valkey-role` bringing a returning master back as a replica, the read-only main configuration |
| `galera` | Bootstrap, the arbitrator, a full state transfer with mariabackup over TLS, multi-master writes, refusal of a node with a foreign certificate, node failure and rejoin, loss of quorum |
| `keepalived` | The floating address on a public network, VRRP on the cluster network, a router following failovers by gratuitous ARP; failovers on a failed health check and on the public interface going down, `nopreempt`, a split cluster network |
| `acme` | nginx of two nodes answering each other's ACME challenges, without loops |
| `netfilter` | Bans with real nftables on a single gateway, and shared bans of two cluster nodes |
| `js` | `static/app.js` in jsdom: in-place forms, confirmation, no periodic refresh, error handling |

Requirements: an EL10 host with dnf access to the distribution repositories,
unprivileged user namespaces, `nft`, `curl`, `openssl`, `python3` with
`python3-nftables`, and `node`/`npm` for the `js` test. Work files and logs
go to `$SF_TEST_WORK` (default `${TMPDIR:-/tmp}/crassostrea-system-tests`);
delete it to start from scratch.

Not covered here (a real cluster is needed): systemd units, SELinux,
firewalld, keepalived's real health check (keepalived cannot run scripts in a
user namespace, the test uses a file), and the installation itself.
