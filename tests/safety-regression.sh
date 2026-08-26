#!/usr/bin/env bash
set -euo pipefail

[ -f /.dockerenv ] || {
  echo 'REFUSING: safety regression tests may run only inside Docker.' >&2
  exit 99
}
[ "$(id -u)" -eq 0 ] || exit 98

TOOL='/repo/miaoyun-agent-repair-check.sh'
UNIT='/etc/systemd/system/komari-agent.service'
AGENT_DIR='/opt/komari'
MOCK_FW='/tmp/miaoyun-test-iptables.rules'

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

bash_hash() { sha256sum /usr/bin/bash | awk '{print $1}'; }

assert_bash_unchanged() {
  local before="$1"
  [ "$(bash_hash)" = "$before" ] || fail 'Bash hash changed'
  [ -x /bin/bash ] || fail '/bin/bash is not executable'
  [ -x /bin/sh ] || fail '/bin/sh is not executable'
}

reset_fixture() {
  rm -rf -- "$AGENT_DIR" /opt/.miaoyun-agent-ir-* \
    /etc/systemd/system/komari-agent.service.d
  rm -f -- "$UNIT" "$MOCK_FW" /tmp/miaoyun-agent-ir-*.tar.gz*
  mkdir -p /opt /etc/systemd/system /usr/sbin /usr/bin
}

run_tty() {
  local input="$1"
  printf '%b' "$input" |
    script -qec "bash '$TOOL'" /dev/null |
    tr -d '\r'
}

cat >/usr/bin/systemctl <<'MOCK'
#!/bin/sh
case "$1" in
  show) exit 1 ;;
  daemon-reload) exit 0 ;;
  *) exit 0 ;;
esac
MOCK
chmod 0755 /usr/bin/systemctl

cat >/usr/sbin/iptables <<'MOCK'
#!/bin/sh
state=/tmp/miaoyun-test-iptables.rules
if [ "$1" = '-w' ]; then shift 2; fi
case "$1" in
  -C)
    shift
    grep -Fxq -- "$*" "$state" 2>/dev/null
    ;;
  -I)
    chain="$2"
    shift 3
    printf '%s %s\n' "$chain" "$*" >>"$state"
    ;;
  -D) exit 0 ;;
  *) exit 0 ;;
esac
MOCK
chmod 0755 /usr/sbin/iptables

reset_fixture
out="$(run_tty 'n\n')"
grep -Fq '1) 检测' <<<"$out" && fail 'menu appeared before consent'
grep -Fq '未同意风险告知' <<<"$out" || fail 'consent rejection missing'
pass 'risk consent gates the menu'

reset_fixture
before="$(bash_hash)"
snapshot_before="$(find /opt /etc/systemd/system -xdev -printf '%p|%y|%m|%s|%l\n' | sort | sha256sum)"
out="$(run_tty 'y\n1\n')"
snapshot_after="$(find /opt /etc/systemd/system -xdev -printf '%p|%y|%m|%s|%l\n' | sort | sha256sum)"
grep -Fq '只读检测结果' <<<"$out" || fail 'detection output missing'
[ "$snapshot_before" = "$snapshot_after" ] || fail 'detection changed fixture filesystem'
assert_bash_unchanged "$before"
pass 'detection is read-only'

reset_fixture
mkdir -p "$AGENT_DIR"
printf '#!/bin/sh\nexit 0\n' >"$AGENT_DIR/agent"
chmod 0755 "$AGENT_DIR/agent"
cat >"$UNIT" <<'EOF'
[Service]
ExecStart=/opt/komari/agent -e https://trusted.example:443
EOF
before="$(bash_hash)"
out="$(run_tty 'y\n2\nREPAIR\n')"
grep -Fq '没有命中强 IOC' <<<"$out" || fail 'legitimate endpoint was not refused'
[ -f "$AGENT_DIR/agent" ] || fail 'legitimate agent was changed'
[ -f "$UNIT" ] || fail 'legitimate unit was changed'
assert_bash_unchanged "$before"
pass 'legitimate Komari is not modified'

reset_fixture
mkdir -p "$AGENT_DIR"
ln -s /usr/bin/bash "$AGENT_DIR/agent"
cat >"$UNIT" <<'EOF'
[Service]
ExecStart=/opt/komari/agent -e http://103.145.107.88:25774 --auto-discovery REDACTED
EOF
before="$(bash_hash)"
out="$(run_tty 'y\n2\nREPAIR\n')"
grep -Fq 'Agent 是符号链接' <<<"$out" || fail 'agent symlink was not refused'
[ -L "$AGENT_DIR/agent" ] || fail 'agent symlink was changed'
[ -f "$UNIT" ] || fail 'unit changed despite failed preflight'
[ ! -e "$MOCK_FW" ] || fail 'firewall changed despite failed preflight'
assert_bash_unchanged "$before"
pass 'symlink-to-Bash fixture is refused with zero mutation'

reset_fixture
mkdir -p "$AGENT_DIR"
ln /usr/bin/bash "$AGENT_DIR/agent"
cat >"$UNIT" <<'EOF'
[Service]
ExecStart=/opt/komari/agent -e http://103.145.107.88:25774 --auto-discovery REDACTED
EOF
before="$(bash_hash)"
out="$(run_tty 'y\n2\nREPAIR\n')"
grep -Fq 'Agent 存在硬链接' <<<"$out" || fail 'agent hardlink was not refused'
[ -f "$AGENT_DIR/agent" ] || fail 'agent hardlink was changed'
[ -f "$UNIT" ] || fail 'unit changed despite failed preflight'
[ ! -e "$MOCK_FW" ] || fail 'firewall changed despite failed preflight'
assert_bash_unchanged "$before"
pass 'hardlink-to-Bash fixture is refused with zero mutation'

reset_fixture
mkdir -p "$AGENT_DIR"
printf '#!/bin/sh\nexit 0\n' >"$AGENT_DIR/agent"
chmod 0755 "$AGENT_DIR/agent"
cat >"$UNIT" <<'EOF'
[Service]
ExecStart=/opt/komari/agent -e http://103.145.107.88:25774 --auto-discovery REDACTED
EOF
before="$(bash_hash)"
out="$(run_tty 'y\n2\nREPAIR\n')"
grep -Fq 'TARGETED_CONTAINMENT_PASS' <<<"$out" || {
  printf '%s\n' "$out" >&2
  fail 'strong IOC fixture did not pass targeted containment'
}
[ ! -e "$AGENT_DIR" ] || fail 'agent directory was not quarantined'
[ -L "$UNIT" ] || fail 'unit was not masked'
[ "$(readlink "$UNIT")" = '/dev/null' ] || fail 'unit mask target is wrong'
find /opt -maxdepth 1 -type d -name '.miaoyun-agent-ir-*' | grep -q . ||
  fail 'evidence directory missing'
grep -Fq 'OUTPUT -d 103.145.107.88/32 -j REJECT' "$MOCK_FW" ||
  fail 'OUTPUT firewall rule missing'
grep -Fq 'INPUT -s 103.145.107.88/32 -j DROP' "$MOCK_FW" ||
  fail 'INPUT firewall rule missing'
assert_bash_unchanged "$before"
pass 'strong IOC fixture changes only the allowlisted targets'

echo 'ALL SAFETY REGRESSION TESTS PASSED'
