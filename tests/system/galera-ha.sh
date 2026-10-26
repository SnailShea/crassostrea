#!/usr/bin/env bash
# MariaDB Galera, run by run.sh inside `unshare -rnm`: two nodes and the
# arbitrator with the Galera settings rendered by configure.sh (TLS with the
# cluster CA, mariabackup state transfer with encrypt=4). A new node joins
# with a full copy, writes on either node replicate, a node with a
# certificate of another CA is refused, the cluster survives the failure of a
# node, the node rejoins, and an isolated node stops accepting queries. A
# cluster of one node (the solo render) starts without --wsrep-new-cluster, as
# mariadb.service starts it at every boot: also after a crash.
#
# Differences to a real cluster: all members on one host (each binds its own
# address, gmcast.listen_addr set accordingly); the servers run as root in the
# namespace, so the state transfer donor authenticates as root instead of the
# mysql system user (unix_socket in both cases).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=${PKG}/usr/bin:${PKG}/usr/sbin:${PKG}/usr/libexec:${PATH}
export LD_LIBRARY_PATH=${PKG}/usr/lib64

cluster_addresses 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.9
# unix socket paths are limited to 107 characters: sockets in a private tmpfs
mount -t tmpfs tmpfs /mnt
G=${WORK}/galera
rm -rf "${G}"
mkdir -p "${G}"
declare -A ROOT=([n1]=${NODES}/mx1 [n2]=${NODES}/mx2 [w]=${NODES}/witness [rogue]=${G}/rogue-node [solo]=${NODES}/solo)
declare -A ADDR=([n1]=10.0.0.1 [n2]=10.0.0.2 [w]=10.0.0.3 [rogue]=10.0.0.4 [solo]=10.0.0.9)

# my.cnf of member n, read like the server reads /etc/my.cnf.d: the package's
# files (galera.cnf, mariadb-server.cnf, ...), the rendered zz-crassostrea.cnf
# under its own name, and last the paths of this test
cnf() {
  local n=$1 d=${G}/$1
  mkdir -p "${d}/data" "${d}/tmp" "${d}/my.cnf.d"
  cp "${PKG}"/etc/my.cnf.d/*.cnf "${d}/my.cnf.d/"
  sed -e "s#/usr/lib64/galera#${PKG}/usr/lib64/galera#" \
      -e "s#/etc/pki/crassostrea#${ROOT[$n]}/etc/pki/crassostrea#g" \
      -e "s#gcache.size=512M\"#gcache.size=64M;gmcast.listen_addr=tcp://${ADDR[$n]}:4567\"#" \
      -e "s#^wsrep_sst_auth = mysql:#wsrep_sst_auth = root:#" "${ROOT[$n]}/etc/my.cnf.d/zz-crassostrea.cnf" \
      > "${d}/my.cnf.d/zz-crassostrea.cnf"
  # galera.cnf of the package points at the system's library
  sed -i "s#/usr/lib64/galera#${PKG}/usr/lib64/galera#" "${d}/my.cnf.d/galera.cnf"
  cat > "${d}/my.cnf.d/zzz-test.cnf" <<EOF
[mysqld]
user = root
basedir = ${PKG}/usr
lc-messages-dir = ${PKG}/usr/share/mariadb
plugin-dir = ${PKG}/usr/lib64/mariadb/plugin
datadir = ${d}/data
tmpdir = ${d}/tmp
socket = /mnt/${n}.sock
pid-file = ${d}/mysqld.pid
log-error = ${d}/error.log
bind-address = ${ADDR[$n]}
innodb_buffer_pool_size = 16M
innodb_log_file_size = 16M
[client]
socket = /mnt/${n}.sock
user = root
EOF
  printf '!includedir %s\n' "${d}/my.cnf.d" > "${d}/my.cnf"
}
sql() {
  local n=$1
  shift
  mariadb --defaults-file="${G}/${n}/my.cnf" -N -B -e "$*" 2>> "${G}/${n}/client.err"
}
status() { sql "$1" "SHOW GLOBAL STATUS LIKE '$2'" | cut -f2; }
start() {
  mariadbd --defaults-file="${G}/$1/my.cnf" "${@:2}" > "${G}/$1/stdout.log" 2>&1 &
  echo $! > "${G}/$1/pid"
  # killed on purpose later: no job notices
  disown
}

cnf n1
cnf n2
mariadb-install-db --defaults-file="${G}/n1/my.cnf" --basedir="${PKG}/usr" --auth-root-authentication-method=socket \
  --skip-test-db > "${G}/n1/install.log" 2>&1 || { echo "FAIL mariadb-install-db, see ${G}/n1/install.log"; exit 1; }

# node 1 creates the cluster (setup.sh --ha: galera_new_cluster)
start n1 --wsrep-new-cluster
check "node 1 bootstraps a new cluster" "wait_for \"[[ \\\$(status n1 wsrep_cluster_status) == Primary ]]\" 60"
sql n1 "CREATE DATABASE crassostrea; CREATE TABLE crassostrea.t (id INT PRIMARY KEY, v VARCHAR(20));
        INSERT INTO crassostrea.t VALUES (1, 'before-join')"

# the witness: arbitrator with the options rendered into /etc/sysconfig/garb
pki=${ROOT[w]}/etc/pki/crassostrea
garbd -a "gcomm://10.0.0.1:4567,10.0.0.2:4567" -g crassostrea -w "${G}" -l "${G}/garbd.log" \
  -o "socket.ssl_ca=${pki}/ca.crt;socket.ssl_cert=${pki}/node.crt;socket.ssl_key=${pki}/node.key;gmcast.listen_addr=tcp://10.0.0.3:4567" \
  > /dev/null 2>&1 &
echo $! > "${G}/garbd.pid"
disown
check "arbitrator joins" "wait_for \"[[ \\\$(status n1 wsrep_cluster_size) == 2 ]]\" 30"

# node 2 joins with an empty data directory: full state transfer
start n2
check "node 2 joins and is Synced" "wait_for \"[[ \\\$(status n2 wsrep_local_state_comment) == Synced ]]\" 120"
check "cluster has 3 members" "[[ \$(status n1 wsrep_cluster_size) == 3 ]]"
check "state transfer used mariabackup over TLS" \
  "grep -q 'Using openssl based encryption with socat: with key and crt' ${G}/n2/error.log"
check "Galera links of node 2 are TLS" \
  "grep -q 'connection established to .* ssl://10.0.0.1:4567' ${G}/n2/error.log && grep -q 'connection established to .* ssl://10.0.0.3:4567' ${G}/n2/error.log && ! grep -q 'tcp://10.0.0' ${G}/n2/error.log"
check "node 2 received the data" "[[ \$(sql n2 'SELECT v FROM crassostrea.t WHERE id=1') == before-join ]]"
sql n2 "INSERT INTO crassostrea.t VALUES (2, 'written-on-2')"
check "writes on node 2 reach node 1" "wait_for \"[[ \\\$(sql n1 'SELECT v FROM crassostrea.t WHERE id=2') == written-on-2 ]]\" 10"

# a node with a certificate of another CA (and the right cluster name)
mkdir -p "${ROOT[rogue]}/etc/pki/crassostrea" "${ROOT[rogue]}/etc/my.cnf.d"
(
  cd "${ROOT[rogue]}/etc/pki/crassostrea" || exit 1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=rogue-ca \
    -keyout ca.key -out ca.crt 2> /dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=rogue -keyout node.key -out node.csr 2> /dev/null
  openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key -days 30 -out node.crt 2> /dev/null
)
sed -e "s/^wsrep_node_name = .*/wsrep_node_name = rogue/" -e "s/^wsrep_node_address = .*/wsrep_node_address = 10.0.0.4/" \
  "${ROOT[n2]}/etc/my.cnf.d/zz-crassostrea.cnf" > "${ROOT[rogue]}/etc/my.cnf.d/zz-crassostrea.cnf"
cnf rogue
start rogue
sleep 15
check "node with a foreign certificate cannot join" \
  "[[ \$(status n1 wsrep_cluster_size) == 3 && \$(status rogue wsrep_local_state_comment) != Synced ]]"
kill -9 "$(cat "${G}/rogue/pid")" 2> /dev/null

# node 1 fails: node 2 and the arbitrator keep the majority
kill -9 "$(cat "${G}/n1/pid")"
check "node 2 stays Primary after node 1 fails" \
  "wait_for \"[[ \\\$(status n2 wsrep_cluster_size) == 2 && \\\$(status n2 wsrep_cluster_status) == Primary ]]\" 30"
sql n2 "INSERT INTO crassostrea.t VALUES (3, 'while-1-down')"
check "node 2 accepts writes" "[[ \$(sql n2 'SELECT v FROM crassostrea.t WHERE id=3') == while-1-down ]]"

# node 1 returns (normal start, as mariadb.service does)
start n1
check "node 1 rejoins and is Synced" "wait_for \"[[ \\\$(status n1 wsrep_local_state_comment) == Synced ]]\" 120"
check "node 1 has the write made during its absence" \
  "[[ \$(sql n1 'SELECT v FROM crassostrea.t WHERE id=3') == while-1-down ]]"

# node 1 isolated: 1 of 3 votes, it must stop accepting queries
kill -9 "$(cat "${G}/garbd.pid")" "$(cat "${G}/n2/pid")"
check "isolated node 1 becomes non-Primary" "wait_for \"[[ \\\$(status n1 wsrep_cluster_status) == non-Primary ]]\" 30"
check "isolated node 1 refuses queries" "! sql n1 'SELECT v FROM crassostrea.t WHERE id=1' > /dev/null"

kill "$(cat "${G}/n1/pid")" 2> /dev/null

# A cluster of one node: mariadb.service starts it like any node, without
# --wsrep-new-cluster (at every boot, and when configure.sh restarts it)
stopped() { ! kill -0 "$(cat "${G}/$1/pid")" 2> /dev/null; }
cnf solo
mariadb-install-db --defaults-file="${G}/solo/my.cnf" --basedir="${PKG}/usr" --auth-root-authentication-method=socket \
  --skip-test-db > "${G}/solo/install.log" 2>&1 || { echo "FAIL mariadb-install-db, see ${G}/solo/install.log"; exit 1; }
start solo
check "the only node forms the cluster at a normal start" \
  "wait_for \"[[ \\\$(status solo wsrep_cluster_status) == Primary ]]\" 60"
sql solo "CREATE DATABASE crassostrea; CREATE TABLE crassostrea.t (id INT PRIMARY KEY);
          INSERT INTO crassostrea.t VALUES (1)"
kill "$(cat "${G}/solo/pid")"
wait_for "stopped solo" 60
start solo
check "and again after a clean restart" \
  "wait_for \"[[ \\\$(status solo wsrep_cluster_status) == Primary && \\\$(sql solo 'SELECT id FROM crassostrea.t') == 1 ]]\" 60"
kill -9 "$(cat "${G}/solo/pid")"
wait_for "stopped solo" 10
# Galera keeps a lone member safe to bootstrap; a node that crashed while it
# had peers (the cluster shrank to it later) is marked unsafe
check "a crash of the lone member keeps it safe to bootstrap" "grep -q '^safe_to_bootstrap: 1' ${G}/solo/data/grastate.dat"
sed -i 's/^safe_to_bootstrap: 1/safe_to_bootstrap: 0/' "${G}/solo/data/grastate.dat"
# the ExecStartPre of the rendered drop-in, on this data directory
pre=$(sed -n 's/^ExecStartPre=-//p' "${ROOT[solo]}/etc/systemd/system/mariadb.service.d/crassostrea-cluster.conf" \
  | sed -e 's/\$\$/$/g' -e "s#/var/lib/mysql#${G}/solo/data#")
check "the drop-in of a one-node cluster has its ExecStartPre" "[[ -n \${pre} ]]"
eval "${pre}"
start solo
check "the drop-in lets it form the cluster also when marked unsafe" \
  "wait_for \"[[ \\\$(status solo wsrep_cluster_status) == Primary && \\\$(sql solo 'SELECT id FROM crassostrea.t') == 1 ]]\" 60"
check "the cluster of several nodes has no such ExecStartPre" \
  "! grep -q ExecStartPre ${ROOT[n1]}/etc/systemd/system/mariadb.service.d/crassostrea-cluster.conf"
kill "$(cat "${G}/solo/pid")" 2> /dev/null
sleep 2
finish
