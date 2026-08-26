#!/usr/bin/env bash
# 喵云Agent修复检测
# Incident-specific detector and containment tool for the unauthorized Komari
# deployment connected to 103.145.107.88:25774.
#
# Safety model:
# - Detection is read-only and writes no report file.
# - Repair requires a strong IOC, root, y consent, menu choice 2, and REPAIR.
# - No hash-based or cmdline-only process/file removal.
# - Only three literal paths may be moved into quarantine.
# - Nothing is deleted, and core system executable directories are never targets.

set -u -o pipefail
umask 077
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

PROGRAM_NAME='喵云Agent修复检测'
VERSION='2.1.0'
SERVICE='komari-agent.service'
AGENT_DIR='/opt/komari'
AGENT_PATH='/opt/komari/agent'
SYSTEM_UNIT='/etc/systemd/system/komari-agent.service'
DROPIN_DIR='/etc/systemd/system/komari-agent.service.d'
IOC_IP='103.145.107.88'
IOC_PORT='25774'
IOC_ENDPOINT="${IOC_IP}:${IOC_PORT}"
LOCK_FILE='/run/lock/miaoyun-agent-repair-check.lock'

STRONG_IOC=0
STRONG_REASON='none'
IR_DIR=''
EVIDENCE=''
QUARANTINE=''
ACTION_LOG=''
STATUS='NOT_RUN'
FIREWALL_ADDED_INPUT=0
FIREWALL_ADDED_OUTPUT=0

have() { command -v "$1" >/dev/null 2>&1; }

now() { date '+%F %T%z'; }

say() { printf '%s\n' "$*"; }

log() {
  local line
  line="[$(now)] $*"
  printf '%s\n' "$line"
  if [ -n "$ACTION_LOG" ]; then
    printf '%s\n' "$line" >>"$ACTION_LOG"
  fi
}

show_risk_notice() {
  printf '\n%s v%s\n' "$PROGRAM_NAME" "$VERSION"
  cat <<'NOTICE'
============================================================
                        风险告知
============================================================

【重要风险告知】

本工具只针对本次已知事件指标进行检测和定向遏制。

修复操作会：
- 屏蔽 komari-agent.service；
- 终止“可执行路径和攻击端点同时匹配”的进程；
- 将 /opt/komari 和精确的 systemd 配置移入隔离区；
- 尝试添加针对已知攻击 IP 的临时 INPUT/OUTPUT 规则。

可能风险：
- 如果这套 Komari 是你主动部署的合法监控，修复会使其离线；
- 临时防火墙规则可能影响与该地址有关的现有网络连接；
- 防火墙规则默认不持久，服务器重启后可能消失；
- 证据包可能包含进程参数、注册 Token 和服务器信息，严禁公开上传；
- 主机曾被 root 控制时，定向清理不能重新建立系统可信性；
- 最终仍建议从可信镜像重建，并轮换密码、密钥和后台会话。

安全边界：
- 不删除隔离证据；
- 不修改 Bash、SSH、PAM、密码、账号、sudoers 或 authorized_keys；
- 不扫描后按哈希自动移动文件；
- 不执行可疑 unit 的 ExecStop、init 脚本或可疑二进制。

禁止使用 curl | bash。请先下载到本地、核对固定 commit 和 SHA-256，
再通过云厂商 VNC/串口控制台操作，并保持一个现有会话不要退出。
只有输入小写 y 表示理解上述风险后，程序才会继续。
NOTICE
}

read_from_tty() {
  local prompt="$1" value
  if [ ! -r /dev/tty ]; then
    say '错误：需要交互式终端。禁止使用 curl | bash。'
    return 1
  fi
  printf '%s' "$prompt" >/dev/tty
  IFS= read -r value </dev/tty || return 1
  printf '%s' "$value"
}

path_type() {
  local p="$1"
  if [ -L "$p" ]; then
    printf 'symbolic-link -> %s' "$(readlink -- "$p" 2>/dev/null || printf '?')"
  elif [ -f "$p" ]; then
    printf 'regular-file'
  elif [ -d "$p" ]; then
    printf 'directory'
  elif [ -e "$p" ]; then
    printf 'other'
  else
    printf 'absent'
  fi
}

unit_has_strong_ioc() {
  local unit="$1"
  [ -f "$unit" ] || return 1
  [ ! -L "$unit" ] || return 1
  # Require both values on the effective ExecStart line. A comment containing
  # an IOC is evidence for review, but is never enough to authorize repair.
  awk -v agent="$AGENT_PATH" -v endpoint="$IOC_ENDPOINT" '
    /^[[:space:]]*[#;]/ { next }
    /^[[:space:]]*ExecStart[[:space:]]*=/ &&
      index($0, agent) && index($0, endpoint) { found=1 }
    END { exit !found }
  ' "$unit" 2>/dev/null
}

proc_exe_is_exact_agent() {
  local pid="$1" exe
  [ "$pid" -gt 1 ] 2>/dev/null || return 1
  [ -d "/proc/$pid" ] || return 1
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  case "$exe" in
    "$AGENT_PATH"|"$AGENT_PATH (deleted)") return 0 ;;
    *) return 1 ;;
  esac
}

proc_argv_has_endpoint() {
  local pid="$1"
  [ -r "/proc/$pid/cmdline" ] || return 1
  grep -aFq -- "$IOC_ENDPOINT" "/proc/$pid/cmdline" 2>/dev/null
}

proc_starttime() {
  local pid="$1" line tail
  local -a fields
  [ -r "/proc/$pid/stat" ] || return 1
  IFS= read -r line <"/proc/$pid/stat" || return 1
  tail="${line##*) }"
  read -r -a fields <<<"$tail"
  [ "${#fields[@]}" -ge 20 ] || return 1
  printf '%s' "${fields[19]}"
}

capture_identity() {
  local pid="$1" exe start devino
  proc_exe_is_exact_agent "$pid" || return 1
  start="$(proc_starttime "$pid")" || return 1
  devino="$(stat -Lc '%d:%i' -- "/proc/$pid/exe" 2>/dev/null)" || return 1
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || return 1
  printf '%s|%s|%s|%s\n' "$pid" "$start" "$devino" "$exe"
}

identity_still_matches() {
  local identity="$1" pid old_start old_devino old_exe new_start new_devino new_exe
  IFS='|' read -r pid old_start old_devino old_exe <<<"$identity"
  [ "$pid" -ne 1 ] 2>/dev/null || return 1
  [ "$pid" -ne "$$" ] 2>/dev/null || return 1
  [ "$pid" -ne "$PPID" ] 2>/dev/null || return 1
  proc_exe_is_exact_agent "$pid" || return 1
  proc_argv_has_endpoint "$pid" || return 1
  new_start="$(proc_starttime "$pid")" || return 1
  new_devino="$(stat -Lc '%d:%i' -- "/proc/$pid/exe" 2>/dev/null)" || return 1
  new_exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || return 1
  [ "$new_start" = "$old_start" ] || return 1
  [ "$new_devino" = "$old_devino" ] || return 1
  [ "$new_exe" = "$old_exe" ] || return 1
  return 0
}

exact_agent_pids() {
  local proc pid
  for proc in /proc/[0-9]*; do
    pid="${proc##*/}"
    if proc_exe_is_exact_agent "$pid"; then
      printf '%s\n' "$pid"
    fi
  done
}

refresh_strong_ioc() {
  local unit dir pid identity
  STRONG_IOC=0
  STRONG_REASON='none'

  for unit in \
    "$SYSTEM_UNIT" \
    /usr/lib/systemd/system/komari-agent.service \
    /lib/systemd/system/komari-agent.service; do
    if unit_has_strong_ioc "$unit"; then
      STRONG_IOC=1
      STRONG_REASON="unit:${unit}"
      return 0
    fi
  done

  for dir in \
    /etc/systemd/system/komari-agent.service.d \
    /run/systemd/system/komari-agent.service.d \
    /usr/lib/systemd/system/komari-agent.service.d \
    /lib/systemd/system/komari-agent.service.d; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' unit; do
      if unit_has_strong_ioc "$unit"; then
        STRONG_IOC=1
        STRONG_REASON="drop-in:${unit}"
        return 0
      fi
    done < <(find -P "$dir" -xdev -maxdepth 1 -type f -print0 2>/dev/null)
  done

  # Also recognize a manually launched or renamed service instance, but only
  # when both its executable path and its endpoint are exact incident matches.
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    if proc_argv_has_endpoint "$pid"; then
      identity="$(capture_identity "$pid")" || return 0
      STRONG_IOC=1
      STRONG_REASON='process+exact-exe+endpoint'
      return 0
    fi
  done < <(exact_agent_pids)
}

count_network_ioc() {
  if have ss; then
    (ss -H -tunap 2>/dev/null || true) |
      grep -Ec "${IOC_IP//./[.]}|:${IOC_PORT}([[:space:]]|$)" || true
  else
    printf '0\n'
  fi
}

list_ioc_reference_paths() {
  local f d
  for f in /etc/crontab /etc/rc.local /etc/rc.d/rc.local; do
    [ -f "$f" ] || continue
    if grep -IqE -- '103[.]145[.]107[.]88|/opt/komari/agent|komari-agent' "$f" 2>/dev/null; then
      printf '%s\n' "$f"
    fi
  done
  for d in /etc/cron.d /etc/systemd/system /root/.config/systemd/user; do
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do
      if grep -IqE -- '103[.]145[.]107[.]88|/opt/komari/agent|komari-agent' "$f" 2>/dev/null; then
        printf '%s\n' "$f"
      fi
    done < <(find -P "$d" -xdev -type f -size -8M -print0 2>/dev/null)
  done
  while IFS= read -r -d '' f; do
    if grep -IqE -- '103[.]145[.]107[.]88|/opt/komari/agent|komari-agent' "$f" 2>/dev/null; then
      printf '%s\n' "$f"
    fi
  done < <(find -P /home -xdev -type f \
    -path '*/.config/systemd/user/*' -size -8M -print0 2>/dev/null)
}

run_detection() {
  local p pid exact_count=0 endpoint_count=0 network_count refs unit_state='unavailable'
  refresh_strong_ioc

  say
  say '========== 只读检测结果 =========='
  say "工具版本：$VERSION"
  if [ "$(id -u)" -ne 0 ]; then
    say '权限提示：当前不是 root，进程和网络信息可能不完整。'
  fi

  for p in "$AGENT_DIR" "$AGENT_PATH" "$SYSTEM_UNIT" "$DROPIN_DIR"; do
    printf '%s : %s\n' "$p" "$(path_type "$p")"
  done

  if have systemctl; then
    unit_state="$(systemctl show "$SERVICE" \
      -p LoadState -p ActiveState -p UnitFileState -p MainPID \
      --value 2>/dev/null | paste -sd '/' - || true)"
  fi
  say "服务状态：${unit_state:-unknown}"

  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    exact_count=$((exact_count + 1))
    if proc_argv_has_endpoint "$pid"; then
      endpoint_count=$((endpoint_count + 1))
    fi
  done < <(exact_agent_pids)
  say "精确 Agent 可执行路径进程数：$exact_count"
  say "其中同时包含攻击端点参数的进程数：$endpoint_count"

  network_count="$(count_network_ioc)"
  say "攻击 IP/端口相关连接数：${network_count:-0}"

  refs="$(list_ioc_reference_paths || true)"
  if [ -n "$refs" ]; then
    say '发现引用 IOC 的配置路径（仅报告，绝不自动修改）：'
    printf '%s\n' "$refs"
  else
    say '未在限定配置范围发现额外 IOC 引用。'
  fi

  if [ "$STRONG_IOC" -eq 1 ]; then
    say "强 IOC 判定：命中（${STRONG_REASON}）"
    say '结论：满足定向修复门槛。'
  else
    say '强 IOC 判定：未命中。'
    say '结论：不会允许自动修复；服务名、目录名或同哈希本身不足以定罪。'
  fi
  say '=================================='
}

critical_snapshot() {
  local p kind target hash mode owner
  for p in \
    /bin/bash /usr/bin/bash /bin/sh \
    /etc/passwd /etc/shadow /etc/ssh/sshd_config; do
    if [ -L "$p" ]; then
      kind='link'
      target="$(readlink -- "$p" 2>/dev/null || true)"
    elif [ -f "$p" ]; then
      kind='file'
      target='-'
    elif [ -e "$p" ]; then
      kind='other'
      target='-'
    else
      printf '%s|absent\n' "$p"
      continue
    fi
    hash='-'
    if [ -f "$p" ]; then
      hash="$(sha256sum -- "$p" 2>/dev/null | awk 'NR==1 {print $1}')"
    fi
    mode="$(stat -Lc '%a' -- "$p" 2>/dev/null || printf '?')"
    owner="$(stat -Lc '%u:%g' -- "$p" 2>/dev/null || printf '?')"
    printf '%s|%s|%s|%s|%s|%s\n' "$p" "$kind" "$target" "$hash" "$mode" "$owner"
  done
}

directory_has_mount() {
  local p="$1"
  [ -d "$p" ] || return 1
  have findmnt || return 0
  findmnt -rn -o TARGET 2>/dev/null |
    awk -v p="$p" '$0 == p || index($0, p "/") == 1 {found=1} END {exit !found}'
}

inode_matches_critical() {
  local candidate="$1" c_inode p p_inode
  [ -f "$candidate" ] || return 1
  c_inode="$(stat -Lc '%d:%i' -- "$candidate" 2>/dev/null)" || return 1
  for p in /bin/bash /usr/bin/bash /bin/sh /usr/bin/sh /usr/sbin/sshd /usr/bin/sudo; do
    [ -e "$p" ] || continue
    p_inode="$(stat -Lc '%d:%i' -- "$p" 2>/dev/null || true)"
    [ -n "$p_inode" ] || continue
    [ "$c_inode" != "$p_inode" ] || return 0
  done
  return 1
}

preflight_repair() {
  local issues=0 nlink real_parent agent_real avail_kb size_kb need_kb unit p c

  [ "$(id -u)" -eq 0 ] || {
    say '拒绝修复：必须以 root 运行。'
    return 1
  }
  for p in /bin/bash /bin/sh; do
    if [ ! -x "$p" ]; then
      say "拒绝修复：关键 Shell 缺失或不可执行：$p"
      issues=1
    fi
  done
  for c in stat readlink sha256sum mv tar gzip find awk grep cp chmod chown \
           mkdir mktemp ln cmp df du hostname date; do
    if ! have "$c"; then
      say "拒绝修复：缺少必要命令：$c"
      issues=1
    fi
  done
  if ! have findmnt; then
    say '拒绝修复：缺少 findmnt，无法安全排除挂载点。'
    issues=1
  fi
  if [ "$(readlink -f /opt 2>/dev/null || true)" != '/opt' ]; then
    say '拒绝修复：/opt 不是预期的真实目录。'
    issues=1
  fi
  real_parent="$(readlink -f /etc/systemd/system 2>/dev/null || true)"
  if [ "$real_parent" != '/etc/systemd/system' ]; then
    say '拒绝修复：/etc/systemd/system 路径异常。'
    issues=1
  fi

  refresh_strong_ioc
  if [ "$STRONG_IOC" -ne 1 ]; then
    say '拒绝修复：没有命中强 IOC。合法或不确定的 Komari 不会被自动处理。'
    issues=1
  fi

  if [ -L "$AGENT_DIR" ]; then
    say '拒绝修复：/opt/komari 是符号链接，必须人工复核。'
    issues=1
  elif [ -e "$AGENT_DIR" ] && [ ! -d "$AGENT_DIR" ]; then
    say '拒绝修复：/opt/komari 不是普通目录。'
    issues=1
  elif [ -d "$AGENT_DIR" ]; then
    if directory_has_mount "$AGENT_DIR"; then
      say '拒绝修复：/opt/komari 本身或内部包含挂载点。'
      issues=1
    fi
    if [ -L "$AGENT_PATH" ]; then
      say '拒绝修复：Agent 是符号链接，绝不跟随或自动处理。'
      issues=1
    elif [ -e "$AGENT_PATH" ]; then
      if [ ! -f "$AGENT_PATH" ]; then
        say '拒绝修复：Agent 不是普通文件。'
        issues=1
      else
        nlink="$(stat -Lc '%h' -- "$AGENT_PATH" 2>/dev/null || printf '0')"
        if [ "$nlink" -ne 1 ] 2>/dev/null; then
          say '拒绝修复：Agent 存在硬链接，必须人工复核。'
          issues=1
        fi
        agent_real="$(readlink -f "$AGENT_PATH" 2>/dev/null || true)"
        if [ "$agent_real" != "$AGENT_PATH" ]; then
          say '拒绝修复：Agent 的规范路径异常。'
          issues=1
        fi
        if inode_matches_critical "$AGENT_PATH"; then
          say '拒绝修复：Agent 与系统关键程序共享 inode。'
          issues=1
        fi
      fi
    fi
  fi

  if [ -L "$SYSTEM_UNIT" ]; then
    if [ "$(readlink -- "$SYSTEM_UNIT" 2>/dev/null || true)" != '/dev/null' ]; then
      say '拒绝修复：systemd unit 是异常符号链接。'
      issues=1
    fi
  elif [ -f "$SYSTEM_UNIT" ]; then
    nlink="$(stat -Lc '%h' -- "$SYSTEM_UNIT" 2>/dev/null || printf '0')"
    if [ "$nlink" -ne 1 ] 2>/dev/null; then
      say '拒绝修复：systemd unit 存在硬链接。'
      issues=1
    fi
  elif [ -e "$SYSTEM_UNIT" ]; then
    say '拒绝修复：systemd unit 类型异常。'
    issues=1
  fi

  if [ -L "$DROPIN_DIR" ]; then
    say '拒绝修复：systemd drop-in 目录是符号链接。'
    issues=1
  elif [ -e "$DROPIN_DIR" ] && [ ! -d "$DROPIN_DIR" ]; then
    say '拒绝修复：systemd drop-in 路径类型异常。'
    issues=1
  elif [ -d "$DROPIN_DIR" ] && directory_has_mount "$DROPIN_DIR"; then
    say '拒绝修复：systemd drop-in 目录包含挂载点。'
    issues=1
  fi

  size_kb=0
  if [ -d "$AGENT_DIR" ]; then
    size_kb="$(du -skx -- "$AGENT_DIR" 2>/dev/null | awk 'NR==1 {print $1}')"
    case "$size_kb" in ''|*[!0-9]*) size_kb=0 ;; esac
  fi
  avail_kb="$(df -Pk /tmp 2>/dev/null | awk 'NR==2 {print $4}')"
  case "$avail_kb" in ''|*[!0-9]*) avail_kb=0 ;; esac
  need_kb=$((size_kb + 16384))
  if [ "$avail_kb" -lt "$need_kb" ]; then
    say "拒绝修复：/tmp 可用空间不足，需要至少 ${need_kb} KiB。"
    issues=1
  fi

  [ "$issues" -eq 0 ]
}

create_ir_area() {
  local host stamp canonical
  host="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-60)"
  [ -n "$host" ] || host='unknown-host'
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  IR_DIR="$(mktemp -d "/opt/.miaoyun-agent-ir-${host}-${stamp}.XXXXXXXX")" || return 1
  canonical="$(readlink -f "$IR_DIR" 2>/dev/null || true)"
  case "$canonical" in
    /opt/.miaoyun-agent-ir-*) ;;
    *) say '证据目录规范路径异常，拒绝继续。'; return 1 ;;
  esac
  chown root:root "$IR_DIR" || return 1
  chmod 700 "$IR_DIR" || return 1
  EVIDENCE="$IR_DIR/evidence"
  QUARANTINE="$IR_DIR/quarantine"
  mkdir -m 700 "$EVIDENCE" "$QUARANTINE" || return 1
  ACTION_LOG="$IR_DIR/actions.log"
  : >"$ACTION_LOG" || return 1
  chmod 600 "$ACTION_LOG"
}

collect_evidence_before() {
  local unit dir pid identity index=0
  critical_snapshot >"$EVIDENCE/critical.before"
  {
    printf 'version=%s\n' "$VERSION"
    printf 'started=%s\n' "$(now)"
    printf 'strong_ioc=%s\n' "$STRONG_IOC"
    printf 'strong_reason=%s\n' "$STRONG_REASON"
    printf 'agent_dir_type=%s\n' "$(path_type "$AGENT_DIR")"
    printf 'agent_path_type=%s\n' "$(path_type "$AGENT_PATH")"
    printf 'unit_type=%s\n' "$(path_type "$SYSTEM_UNIT")"
  } >"$EVIDENCE/scope.txt"

  for unit in \
    "$SYSTEM_UNIT" \
    /usr/lib/systemd/system/komari-agent.service \
    /lib/systemd/system/komari-agent.service; do
    if [ -f "$unit" ] && [ ! -L "$unit" ]; then
      index=$((index + 1))
      cp -a -- "$unit" "$EVIDENCE/unit-${index}.conf" || return 1
      printf '%s\n' "$unit" >"$EVIDENCE/unit-${index}.source"
    fi
  done
  for dir in \
    /etc/systemd/system/komari-agent.service.d \
    /run/systemd/system/komari-agent.service.d \
    /usr/lib/systemd/system/komari-agent.service.d \
    /lib/systemd/system/komari-agent.service.d; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' unit; do
      [ -f "$unit" ] && [ ! -L "$unit" ] || continue
      index=$((index + 1))
      cp -a -- "$unit" "$EVIDENCE/unit-${index}.conf" || return 1
      printf '%s\n' "$unit" >"$EVIDENCE/unit-${index}.source"
    done < <(find -P "$dir" -xdev -maxdepth 1 -type f -print0 2>/dev/null)
  done

  if have systemctl; then
    systemctl show "$SERVICE" \
      -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState \
      -p FragmentPath -p MainPID >"$EVIDENCE/systemd.before" 2>&1 || true
  fi
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    identity="$(capture_identity "$pid" 2>/dev/null || true)"
    [ -n "$identity" ] || continue
    printf '%s\n' "$identity" >>"$EVIDENCE/process-identities.before"
    if [ -r "/proc/$pid/cmdline" ]; then
      cp -- "/proc/$pid/cmdline" "$EVIDENCE/process-${pid}.cmdline.bin" 2>/dev/null || true
    fi
  done < <(exact_agent_pids)
  if have ss; then
    (ss -H -tunap 2>/dev/null || true) |
      grep -E "${IOC_IP//./[.]}|:${IOC_PORT}([[:space:]]|$)" \
      >"$EVIDENCE/network-ioc.before" || true
  fi
  list_ioc_reference_paths >"$EVIDENCE/ioc-reference-paths.txt" || true
  if have iptables-save; then
    iptables-save >"$EVIDENCE/iptables.before" 2>&1 || true
  fi
  chmod -R go-rwx "$IR_DIR"
}

quarantine_exact() {
  local src="$1" label="$2" dst
  case "$src" in
    "$AGENT_DIR"|"$SYSTEM_UNIT"|"$DROPIN_DIR") ;;
    *) log "SAFETY REFUSAL: path is not on the quarantine allowlist: $src"; return 1 ;;
  esac
  if [ ! -e "$src" ] && [ ! -L "$src" ]; then
    return 0
  fi
  dst="$QUARANTINE/$label"
  if [ -e "$dst" ] || [ -L "$dst" ]; then
    log "SAFETY REFUSAL: quarantine destination already exists: $dst"
    return 1
  fi
  if mv -T -- "$src" "$dst"; then
    printf '%s\t%s\n' "$src" "$dst" >>"$EVIDENCE/quarantine-map.tsv"
    log "QUARANTINED $src -> $dst"
    return 0
  fi
  log "ERROR: could not quarantine $src"
  return 1
}

install_service_mask() {
  if [ -L "$SYSTEM_UNIT" ] && [ "$(readlink -- "$SYSTEM_UNIT" 2>/dev/null || true)" = '/dev/null' ]; then
    log 'Service is already persistently masked'
    return 0
  fi
  if [ -e "$SYSTEM_UNIT" ] || [ -L "$SYSTEM_UNIT" ]; then
    log 'ERROR: unit path is occupied after quarantine attempt; refusing to overwrite'
    return 1
  fi
  if ln -s /dev/null "$SYSTEM_UNIT"; then
    log "Created persistent mask: $SYSTEM_UNIT -> /dev/null"
    return 0
  fi
  log 'ERROR: could not create persistent service mask'
  return 1
}

terminate_confirmed_processes() {
  local pass pid identity signal found identities
  # Re-scan on every pass so an automatic restart cannot evade containment by
  # receiving a new PID. Every signal is still gated by start time, inode,
  # exact executable path and the exact incident endpoint.
  for pass in 1 2 3 4 5 6 7 8; do
    identities=()
    while IFS= read -r pid; do
      [ -n "$pid" ] || continue
      proc_argv_has_endpoint "$pid" || continue
      identity="$(capture_identity "$pid" 2>/dev/null || true)"
      [ -n "$identity" ] || continue
      identities+=("$identity")
    done < <(exact_agent_pids)

    [ "${#identities[@]}" -gt 0 ] || return 0
    signal='TERM'
    [ "$pass" -le 3 ] || signal='KILL'
    found=0
    for identity in "${identities[@]}"; do
      IFS='|' read -r pid _ <<<"$identity"
      if identity_still_matches "$identity"; then
        found=1
        log "Sending $signal to confirmed Agent PID $pid (pass $pass)"
        kill -"$signal" "$pid" 2>/dev/null || true
      fi
    done
    [ "$found" -eq 1 ] || return 0
    sleep 1
  done

  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    if proc_argv_has_endpoint "$pid"; then
      log "ERROR: confirmed Agent process survived repeated containment: PID $pid"
      return 1
    fi
  done < <(exact_agent_pids)
  return 0
}

add_firewall_rules() {
  if ! have iptables; then
    log 'WARNING: iptables is unavailable; attacker IP was not blocked by this tool'
    return 1
  fi
  if ! iptables -w 5 -C OUTPUT -d "$IOC_IP/32" -j REJECT >/dev/null 2>&1; then
    if iptables -w 5 -I OUTPUT 1 -d "$IOC_IP/32" -j REJECT; then
      FIREWALL_ADDED_OUTPUT=1
      log "Added temporary OUTPUT reject rule for $IOC_IP"
    else
      log 'ERROR: could not add OUTPUT rule'
      return 1
    fi
  else
    log 'Equivalent OUTPUT rule already exists'
  fi
  if ! iptables -w 5 -C INPUT -s "$IOC_IP/32" -j DROP >/dev/null 2>&1; then
    if iptables -w 5 -I INPUT 1 -s "$IOC_IP/32" -j DROP; then
      FIREWALL_ADDED_INPUT=1
      log "Added temporary INPUT drop rule for $IOC_IP"
    else
      log 'ERROR: could not add INPUT rule'
      return 1
    fi
  else
    log 'Equivalent INPUT rule already exists'
  fi
  return 0
}

write_rollback_notes() {
  cat >"$IR_DIR/ROLLBACK-READ-ME.txt" <<EOF
This directory contains quarantined incident artifacts and may contain secrets.
Do not publish it and do not extract its archive as root on another production host.

The tool did not delete quarantined files and never automatically restores or
restarts the confirmed malicious Agent.

Review this exact mapping before any manual rollback:
  $EVIDENCE/quarantine-map.tsv

Only restore an item if its original path is still absent. Never overwrite a
new file. The persistent mask is:
  $SYSTEM_UNIT -> /dev/null

Firewall rules added by this run:
  INPUT=$FIREWALL_ADDED_INPUT
  OUTPUT=$FIREWALL_ADDED_OUTPUT

If appropriate, remove only rules added by this run with:
  iptables -w 5 -D OUTPUT -d $IOC_IP/32 -j REJECT
  iptables -w 5 -D INPUT -s $IOC_IP/32 -j DROP

Do not re-enable this Agent. A root-compromised host should be rebuilt.
EOF
  chmod 600 "$IR_DIR/ROLLBACK-READ-ME.txt"
}

archive_evidence() {
  local parent base archive
  parent="${IR_DIR%/*}"
  base="${IR_DIR##*/}"
  archive="$(mktemp -p /tmp "${base#.}.XXXXXXXX.tar.gz")" || {
    log 'ERROR: could not reserve a unique archive path in /tmp'
    return 1
  }
  if ! tar -C "$parent" -czf "$archive" -- "$base"; then
    log "ERROR: evidence archive creation failed; original remains at $IR_DIR"
    return 1
  fi
  chmod 600 "$archive"
  if ! gzip -t "$archive"; then
    log "ERROR: gzip verification failed; original remains at $IR_DIR"
    return 1
  fi
  sha256sum -- "$archive" >"$archive.sha256" || return 1
  chmod 600 "$archive.sha256"
  log "Evidence archive: $archive"
  log "Checksum file: $archive.sha256"
  return 0
}

verify_after() {
  local failed=0 pid
  critical_snapshot >"$EVIDENCE/critical.after"
  if ! cmp -s "$EVIDENCE/critical.before" "$EVIDENCE/critical.after"; then
    log 'CRITICAL FAILURE: Bash/account/SSH invariants changed during repair'
    failed=1
  fi
  if [ ! -x /bin/bash ] || [ ! -x /bin/sh ]; then
    log 'CRITICAL FAILURE: a required system shell is unavailable'
    failed=1
  fi
  if [ ! -L "$SYSTEM_UNIT" ] || [ "$(readlink -- "$SYSTEM_UNIT" 2>/dev/null || true)" != '/dev/null' ]; then
    log 'ERROR: service is not persistently masked'
    failed=1
  fi
  if [ -e "$AGENT_DIR" ] || [ -L "$AGENT_DIR" ]; then
    log 'ERROR: exact Agent directory remains at its original path'
    failed=1
  fi
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    if proc_argv_has_endpoint "$pid"; then
      log "ERROR: confirmed Agent process remains: PID $pid"
      failed=1
    fi
  done < <(exact_agent_pids)
  if have iptables; then
    iptables -w 5 -C OUTPUT -d "$IOC_IP/32" -j REJECT >/dev/null 2>&1 || failed=1
    iptables -w 5 -C INPUT -s "$IOC_IP/32" -j DROP >/dev/null 2>&1 || failed=1
  else
    failed=1
  fi
  [ "$failed" -eq 0 ]
}

run_repair() {
  local confirm mutation_ok=1 verify_ok=0

  say
  say '即将执行的精确变更计划：'
  say "- 隔离：$AGENT_DIR"
  say "- 隔离并屏蔽：$SYSTEM_UNIT"
  say "- 隔离：$DROPIN_DIR"
  say "- 仅终止 exe=$AGENT_PATH 且参数包含已知攻击端点的进程"
  say "- 仅为 $IOC_IP 添加两条临时防火墙规则"
  say '- 不处理任何同哈希副本，不修改 cron/SSH/Bash/账号文件'
  say
  confirm="$(read_from_tty '请输入大写 REPAIR 执行；其他输入取消：')" || {
    say '未确认，已取消。'
    return 1
  }
  if [ "$confirm" != 'REPAIR' ]; then
    say '未输入 REPAIR，零变更退出。'
    return 0
  fi

  if ! preflight_repair; then
    say '预检失败，未修改服务、进程、防火墙或业务文件。'
    return 1
  fi
  if ! have flock; then
    say '拒绝修复：缺少 flock，无法防止并发执行。'
    return 1
  fi
  exec 9>"$LOCK_FILE" || {
    say '拒绝修复：无法建立锁文件。'
    return 1
  }
  if ! flock -n 9; then
    say '拒绝修复：另一份修复程序正在运行。'
    return 1
  fi

  if ! create_ir_area; then
    say '无法创建安全证据目录，未执行修复。'
    return 1
  fi
  log "Starting targeted containment, version $VERSION"
  log "Evidence directory: $IR_DIR"

  if ! collect_evidence_before; then
    log 'Evidence collection failed before mutation; refusing to continue'
    return 1
  fi

  # Cut the known controller path before changing service files. Failure is
  # recorded, but does not prevent quarantining a confirmed malicious Agent.
  add_firewall_rules || mutation_ok=0

  # Never call systemctl stop/mask --now or an init script: their ExecStop may
  # be attacker-controlled. Quarantine the exact local unit, mask it, reload,
  # then signal only fully revalidated Agent identities.
  if [ -e "$SYSTEM_UNIT" ] && [ ! -L "$SYSTEM_UNIT" ]; then
    quarantine_exact "$SYSTEM_UNIT" 'etc-systemd-system-komari-agent.service' || mutation_ok=0
  fi
  if [ -d "$DROPIN_DIR" ]; then
    quarantine_exact "$DROPIN_DIR" 'etc-systemd-system-komari-agent.service.d' || mutation_ok=0
  fi
  install_service_mask || mutation_ok=0
  if have systemctl; then
    systemctl daemon-reload >>"$ACTION_LOG" 2>&1 || {
      log 'ERROR: systemctl daemon-reload failed'
      mutation_ok=0
    }
  fi

  terminate_confirmed_processes || mutation_ok=0

  if [ -d "$AGENT_DIR" ]; then
    quarantine_exact "$AGENT_DIR" 'opt-komari' || mutation_ok=0
  fi
  write_rollback_notes
  if verify_after; then
    verify_ok=1
  fi
  if [ "$mutation_ok" -eq 1 ] && [ "$verify_ok" -eq 1 ]; then
    STATUS='TARGETED_CONTAINMENT_PASS'
  else
    STATUS='PARTIAL_OR_FAILED_REVIEW_REQUIRED'
  fi
  printf 'status=%s\n' "$STATUS" >"$IR_DIR/STATUS.txt"
  chmod 600 "$IR_DIR/STATUS.txt"

  if ! archive_evidence; then
    STATUS='PARTIAL_OR_FAILED_REVIEW_REQUIRED'
    printf 'status=%s\n' "$STATUS" >"$IR_DIR/STATUS.txt"
  fi

  say
  say "结果：$STATUS"
  say "证据与隔离目录：$IR_DIR"
  say '注意：这里只表示已知 IOC 的定向遏制结果，不代表主机重新可信。'
  say '请从可信镜像重建主机，并轮换密码、密钥、Token 和后台会话。'
}

main() {
  local consent choice
  if [ "$#" -ne 0 ]; then
    say '本工具不接受命令行操作参数；请下载、校验后交互运行。'
    return 2
  fi
  show_risk_notice
  consent="$(read_from_tty '请输入小写 y 同意并继续：')" || {
    say
    say '未获得交互确认，安全退出。'
    return 0
  }
  say
  if [ "$consent" != 'y' ]; then
    say '未同意风险告知，安全退出，未执行检测或修复。'
    return 0
  fi

  while true; do
    cat <<'MENU'

请选择操作：
  1) 检测（只读，不修改系统）
  2) 修复（先检测，强 IOC 命中后才允许隔离）
  可按 Ctrl+C 退出
MENU
    choice="$(read_from_tty '请输入 1 或 2：')" || {
      say
      say '输入中断，安全退出。'
      return 0
    }
    say
    case "$choice" in
      1) run_detection; return 0 ;;
      2) run_detection; run_repair; return $? ;;
      *) say '无效选择，请重新输入。' ;;
    esac
  done
}

main "$@"
