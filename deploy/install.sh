#!/bin/sh
# 观澜 NetScope · 路由器安装脚本（幂等，可重复执行）
#
# 用法：
#   sh install.sh                       # 使用 /tmp/guanlan.new 作为二进制来源
#   sh install.sh /path/to/guanlan      # 指定二进制来源
#   GL_APPLY=0 sh install.sh            # 零风险干跑：只打印将要执行的命令，不实际执行
#
# 特性：
#   * 幂等：可重复运行，已安装时覆盖升级，不破坏用户改过的密码
#   * 安全：二进制先落 /tmp 校验再原子 mv 到 /usr/sbin，避免 overlay 写一半断电损坏
#   * 可回滚：DNS 旁挂失败自动还原并恢复 dnsmasq，服务本体安装不受影响
#   * 最小改动：安装时不改 dnsmasq 配置（旁挂由设置页开关控制）；
#     不改上游 DNS / 网络接口 / lan 区配置
#
# DNS 旁挂机制（与后端 app/dns.go ApplyDNSTap 完全一致）：
#   开启：uci set dhcp.@dnsmasq[0].logqueries=1 → uci commit dhcp
#         把 /etc/dnsmasq.conf 的 log-facility 行改成 /tmp/guanlan/dnsmasq.log
#         （原值备份到 /tmp/guanlan/logfacility.orig）→ stop + start dnsmasq
#   关闭：uci delete logqueries + 把 log-facility 行写回原值 → stop + start dnsmasq
#   该固件 ubus call dnsmasq reload 不存在；/etc/init.d/dnsmasq reload 有 bug
#   （停得掉起不来 → 全网 DNS 中断），故只用 stop + start。
#
# 安装脚本本身不启用旁挂、不改 dnsmasq 配置，只做一件事：
#   把 /etc/dnsmasq.conf 的 log-facility 原值备份到持久目录
#   $DATA_DIR/logfacility.orig —— 供 uninstall.sh / rollback.sh 还原用
#   （/tmp/guanlan 是 tmpfs，重启即失，不能只存在那里）。
#
set -u

# ---------------------------------------------------------------------------
# 干跑开关：GL_APPLY=0 时只打印步骤，不做任何写操作（用于脚本评审）
# ---------------------------------------------------------------------------
APPLY="${GL_APPLY:-1}"
DRY=0
case "$APPLY" in
  0|false|no|off|DRY|dry) DRY=1 ;;
esac

APP_NAME="guanlan"
BIN_SRC="${1:-/tmp/guanlan.new}"
BIN_DST="/usr/sbin/${APP_NAME}"
DATA_DIR="/mnt/mmcblk2p4/${APP_NAME}"
DATA_SUBDIRS="data logs"
CONF_DIR="/etc/${APP_NAME}"
CONF_FILE="${CONF_DIR}/config.json"
INIT_SCRIPT="/etc/init.d/${APP_NAME}"
RUN_DIR="/tmp/${APP_NAME}"
PID_FILE="/var/run/${APP_NAME}.pid"
PORT="${GUANLAN_PORT:-8088}"
LISTEN_ADDR="0.0.0.0:${PORT}"
DATA_PATH="${DATA_DIR}/data"
LOG_DIR="${DATA_DIR}/logs"

# --- DNS 旁挂（与后端 ApplyDNSTap 一致：改写 /etc/dnsmasq.conf 的 log-facility） ---
DNS_LOG_DIR="/tmp/${APP_NAME}"
DNS_LOG="${DNS_LOG_DIR}/dnsmasq.log"
DNS_CONF="/etc/dnsmasq.conf"
# log-facility 原值的持久备份（卸载/回退时按它还原；/tmp 是 tmpfs，重启即失）
LOGFAC_ORIG_FILE="${DATA_DIR}/logfacility.orig"
UCI_SECTION="dhcp.@dnsmasq[0]"
UCI_OPT_LOGQUERIES="logqueries"

DEFAULT_PASSWORD="${GUANLAN_DEFAULT_PASSWORD:-guanlan2026}"
LAN_IP="${GUANLAN_LAN_IP:-192.168.1.254}"

BACKUP_DIR="/tmp/${APP_NAME}-backup"
DNS_FAIL=0

# --- 用户自助回退（rollback.sh）的位置 ---
# /tmp 重启会丢，因此在持久化分区留一份备份
ROLLBACK_SH_SRC="${GL_ROLLBACK_SH:-}"          # 可选：指定 rollback.sh 来源
ROLLBACK_SH_TMP="/tmp/rollback.sh"              # 守器上的位置（用户可直接用）
ROLLBACK_SH_KEEP="${DATA_DIR}/rollback.sh"      # 持久化位置（跨重启保留）

log()  { echo "[install] $*"; }
warn() { echo "[install][WARN] $*" >&2; }
die()  { echo "[install][ERROR] $*" >&2; exit 1; }

# --- 干跑支持的命令执行器 -------------------------------------------------
# 所有会改变路由器状态的写操作都必须经过 run()/run_sh()/run_in()，
# 以便 GL_APPLY=0 下完整呈现流程而不实际执行。
run() {
  if [ "$DRY" = "1" ]; then
    echo "[DRY] $*"
    return 0
  fi
  "$@"
}

run_sh() {
  if [ "$DRY" = "1" ]; then
    echo "[DRY] sh -c: $1"
    return 0
  fi
  sh -c "$1"
}

run_in() {
  if [ "$DRY" = "1" ]; then
    echo "[DRY] sh -c: $1"
    return 0
  fi
  sh -c "$1" 2>&1
}

# ---------------------------------------------------------------------------
# dnsmasq.conf 的 log-facility 读写（与后端 app/dns.go 同一套语义）
# ---------------------------------------------------------------------------

# --- 读取当前 log-facility 取值（只读） ---
current_logfacility() {
  [ -f "$DNS_CONF" ] || return 0
  grep -m1 '^[[:space:]]*log-facility[[:space:]]*=' "$DNS_CONF" 2>/dev/null \
    | sed -e 's/^[^=]*=//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# --- 取原值（只接受路径/设备名字符，非法值回退 /dev/null） ---
original_logfacility() {
  V=""
  if [ -s "$LOGFAC_ORIG_FILE" ]; then
    V=$(head -n1 "$LOGFAC_ORIG_FILE" 2>/dev/null | tr -d '\r')
  fi
  case "$V" in
    ""|*[!A-Za-z0-9_./-]*) echo "/dev/null" ;;
    *) echo "$V" ;;
  esac
}

# --- 把 log-facility 行写回指定值 ---
write_logfacility() {
  V="$1"
  if [ "$DRY" = "1" ]; then
    echo "[DRY] 写回 $DNS_CONF 的 log-facility → $V"
    return 0
  fi
  [ -f "$DNS_CONF" ] || return 1
  sed -i 's#^[[:space:]]*log-facility[[:space:]]*=.*#log-facility='"$V"'#' "$DNS_CONF" 2>/dev/null || return 1
  grep -q '^[[:space:]]*log-facility[[:space:]]*=' "$DNS_CONF" 2>/dev/null \
    || echo "log-facility=$V" >> "$DNS_CONF"
  return 0
}

# ===========================================================================
# 0. 前置检查
# ===========================================================================
log "开始安装 ${APP_NAME} ..."

if [ "$DRY" = "1" ]; then
  log "干跑模式（GL_APPLY=0）：只打印命令，不做任何写操作"
else
  if [ "$(id -u)" != "0" ]; then
    die "需要 root 权限（请以 root 执行）"
  fi
  # procd 环境判断：/etc/rc.common 提供 procd_open_instance 等；start_stop_daemon
  # 是 busybox 可选组件，flippy 固件没有也不影响 procd 服务，不强制要求。
  [ -f /etc/rc.common ] || die "系统缺少 /etc/rc.common（非 OpenWrt procd 环境）"
  [ -f /lib/functions/service.sh ] || warn "系统缺少 service.sh，procd 服务可能异常"
  command -v uci >/dev/null 2>&1 || warn "系统缺少 uci，DNS 旁挂不可用（服务本体不受影响）"
fi

# ===========================================================================
# 1. 记录部署前基线（内存/磁盘/UCI），便于验收对比
# ===========================================================================
BASELINE_FILE="${RUN_DIR}/baseline.txt"
mkdir -p "$RUN_DIR" 2>/dev/null || true
{
  echo "=== deploy baseline @ $(date '+%Y-%m-%d %H:%M:%S') ==="
  echo "--- free -m ---"
  free -m 2>/dev/null || echo "n/a"
  echo "--- df -h / ---"
  df -h / 2>/dev/null || echo "n/a"
  echo "--- df -h /mnt/mmcblk2p4 ---"
  df -h /mnt/mmcblk2p4 2>/dev/null || echo "n/a"
  echo "--- uci dnsmasq log 选项（部署前应为空）---"
  uci show dhcp 2>/dev/null | grep -E 'logqueries|logfacility' || echo "(空)"
  echo "--- /etc/dnsmasq.conf log-facility（部署前应为 /dev/null）---"
  grep -n 'log-facility' /etc/dnsmasq.conf 2>/dev/null || echo "(无)"
  echo "--- /tmp/dnsmasq.d ---"
  ls -l /tmp/dnsmasq.d 2>/dev/null || echo "n/a"
} > "$BASELINE_FILE" 2>&1
log "部署前基线记录：$BASELINE_FILE"

# 路由现状快照（回滚依据）
run_sh "iptables-save > /tmp/ubm-iptables-before.txt 2>/dev/null || true"
run_sh "uci show dhcp > /tmp/ubm-dhcp-before.txt 2>/dev/null || true"

# ===========================================================================
# 2. 目录
# ===========================================================================
log "创建数据与配置目录"
run_sh "mkdir -p $DATA_DIR $CONF_DIR" || die "创建目录失败：$DATA_DIR $CONF_DIR"
for d in $DATA_SUBDIRS; do
  run_sh "mkdir -p ${DATA_DIR}/${d}" || warn "创建 ${DATA_DIR}/${d} 失败"
done
run_sh "mkdir -p $RUN_DIR $DNS_LOG_DIR" || warn "创建运行目录失败"
# dnsmasq 以 dnsmasq 用户运行，必须能写入 DNS 日志目录（否则日志文件创建失败、
# 轮转后变成 *.log.old 且新文件缺失，域名归因随之失效）
run_sh "chown dnsmasq:dnsmasq $DNS_LOG_DIR 2>/dev/null || chmod 0777 $DNS_LOG_DIR" || warn "设置 DNS 日志目录权限失败"

# ---------------------------------------------------------------------------
# 2.5 备份 /etc/dnsmasq.conf 的 log-facility 原值（供卸载/回退还原）
#
#   后端开启 DNS 旁挂时改写的就是这一行，原值必须留底，否则还原不回来。
#   /tmp/guanlan/logfacility.orig 是 tmpfs（重启即失），所以这里另存一份到
#   持久分区 $DATA_DIR/logfacility.orig。
#
#   只在「还没有备份」且「当前值不是旁挂路径」时写备份：
#   重装时若 /etc/dnsmasq.conf 已被旁挂改写，绝不能把旁挂路径当成原值。
# ---------------------------------------------------------------------------
if [ "$DRY" = "1" ]; then
  run_sh "echo '[DRY] 将把 /etc/dnsmasq.conf 的 log-facility 原值备份到 ${LOGFAC_ORIG_FILE}'"
elif [ -s "$LOGFAC_ORIG_FILE" ]; then
  log "log-facility 原值备份已存在：$LOGFAC_ORIG_FILE（保持不变）"
else
  CUR_LOGFAC=$(current_logfacility)
  case "$CUR_LOGFAC" in
    "$DNS_LOG")
      log "检测到 $DNS_CONF 已被旁挂改写（$DNS_LOG），跳过备份以免覆盖原值"
      ;;
    ""|*[!A-Za-z0-9_./-]*)
      # 没有该行或取值异常：dnsmasq 默认走 /dev/null
      printf '%s\n' "/dev/null" > "$LOGFAC_ORIG_FILE" 2>/dev/null \
        && log "log-facility 原值备份（默认 /dev/null）→ $LOGFAC_ORIG_FILE"
      ;;
    *)
      printf '%s\n' "$CUR_LOGFAC" > "$LOGFAC_ORIG_FILE" 2>/dev/null \
        && log "log-facility 原值备份：$CUR_LOGFAC → $LOGFAC_ORIG_FILE"
      ;;
  esac
fi

# ===========================================================================
# 3. 安装二进制（先校验，再原子替换）
# ===========================================================================
if [ "$DRY" != "1" ] && [ ! -f "$BIN_SRC" ]; then
  die "找不到二进制来源：$BIN_SRC（请先 scp 上传，或用 'sh install.sh <path>' 指定）"
fi

SRC_SIZE=0
if [ -f "$BIN_SRC" ]; then
  SRC_SIZE=$(wc -c < "$BIN_SRC" 2>/dev/null | tr -d ' ')
fi
log "二进制来源：$BIN_SRC (${SRC_SIZE:-0} bytes)"

if [ "$DRY" != "1" ]; then
  if [ "${SRC_SIZE:-0}" -lt 100000 ]; then
    die "二进制大小异常（$SRC_SIZE bytes），疑似传输不完整，请重新上传"
  fi

  # ELF 头校验（magic + machine=aarch64）；busybox 无 od，用 hexdump 兜底
  MAGIC=""
  MACHINE=""
  if command -v od >/dev/null 2>&1; then
    MAGIC=$(dd if="$BIN_SRC" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
    MACHINE=$(od -An -tu2 -j18 -N2 "$BIN_SRC" 2>/dev/null | tr -d ' \n')
  elif command -v hexdump >/dev/null 2>&1; then
    MAGIC=$(dd if="$BIN_SRC" bs=1 count=4 2>/dev/null | hexdump -v -e '1/1 "%02x"' 2>/dev/null)
    MACHINE=$(dd if="$BIN_SRC" bs=1 skip=18 count=2 2>/dev/null | hexdump -v -e '1/1 "%02x"' 2>/dev/null)
    case "$MACHINE" in
      b700|0000b7) MACHINE=183 ;;
    esac
  fi

  if [ -z "$MAGIC" ]; then
    warn "无法解析 ELF 头（缺少 od/hexdump），跳过架构校验"
  elif [ "$MAGIC" != "7f454c46" ]; then
    die "来源文件不是有效的 ELF 可执行文件（magic=$MAGIC），拒绝安装"
  elif [ "$MACHINE" != "183" ]; then
    die "来源文件架构不是 aarch64（machine=$MACHINE），拒绝安装"
  else
    log "ELF 校验通过（aarch64 静态可执行文件）"
  fi
else
  run_sh "echo '[DRY] 将校验 ELF 头（magic=7f454c46, machine=183/aarch64）'"
fi

# 备份旧二进制（回滚用）
run_sh "mkdir -p $BACKUP_DIR"
if [ -f "$BIN_DST" ]; then
  run_sh "cp -f $BIN_DST ${BACKUP_DIR}/${APP_NAME}.bak 2>/dev/null" && log "已备份旧二进制到 ${BACKUP_DIR}/${APP_NAME}.bak"
else
  run_sh "rm -f ${BACKUP_DIR}/${APP_NAME}.bak"
fi

# 原子替换：先拷到同目录临时文件（overlay 内），chmod 后 mv
TMP_DST="/usr/sbin/.${APP_NAME}.new"
log "安装二进制 → $BIN_DST"
run_sh "cp -f $BIN_SRC $TMP_DST" || die "复制二进制到 $TMP_DST 失败"
run_sh "chmod 0755 $TMP_DST" || die "设置执行权限失败"

if [ "$DRY" != "1" ]; then
  DST_SIZE=$(wc -c < "$TMP_DST" | tr -d ' ')
  if [ "$DST_SIZE" != "$SRC_SIZE" ]; then
    rm -f "$TMP_DST"
    die "安装后大小不一致（源 $SRC_SIZE / 目标 $DST_SIZE），已回滚"
  fi
  if [ ! -x "$TMP_DST" ]; then
    rm -f "$TMP_DST"
    die "安装后文件不可执行，已回滚"
  fi
fi
run_sh "mv -f $TMP_DST $BIN_DST" || { run_sh "rm -f $TMP_DST"; die "mv 失败"; }
log "二进制安装完成"

# --- 复制用户自助回退脚本（只复制，绝不执行） ---
if [ -n "$ROLLBACK_SH_SRC" ] && [ -f "$ROLLBACK_SH_SRC" ]; then
  log "复制回退脚本：$ROLLBACK_SH_SRC"
  run_sh "cp -f $ROLLBACK_SH_SRC $ROLLBACK_SH_TMP && chmod 0755 $ROLLBACK_SH_TMP"
  run_sh "cp -f $ROLLBACK_SH_SRC $ROLLBACK_SH_KEEP && chmod 0755 $ROLLBACK_SH_KEEP"
  log "回退脚本已放到 $ROLLBACK_SH_TMP 与 $ROLLBACK_SH_KEEP"
else
  log "未提供 rollback.sh，跳过回退脚本复制（安装不受影响）"
fi

# ===========================================================================
# 4. 配置文件
# ===========================================================================
NEW_PASSWORD=""
if [ -f "$CONF_FILE" ]; then
  log "检测到已有配置 $CONF_FILE —— 保留（不覆盖用户改过的密码）"
  if ! grep -q '"passwordHash"' "$CONF_FILE" 2>/dev/null && ! grep -q '"password"' "$CONF_FILE" 2>/dev/null; then
    warn "已有配置缺少密码字段，追加默认密码哈希"
    if [ "$DRY" = "1" ]; then
      CONF_TMP="/tmp/${APP_NAME}-config.json.new"
    else
      CONF_TMP="${CONF_FILE}.new"
    fi
    # 哈希必须是 sha256(salt + password)，与 app/config.go 的 hashPassword 一致
    SALT="guanlan-$(date '+%Y%m%d%H%M%S')"
    {
      echo '{'
      echo "  \"salt\": \"$SALT\","
      echo "  \"passwordHash\": \"$(printf '%s' "$SALT$DEFAULT_PASSWORD" | sha256sum | cut -d' ' -f1)\","
      echo "  \"listen\": \"$LISTEN_ADDR\","
      echo "  \"dataDir\": \"$DATA_PATH\""
      echo '}'
    } > "${CONF_TMP}" && run_sh "mv -f $CONF_TMP $CONF_FILE"
  fi
else
  log "生成初始配置 $CONF_FILE"
  SALT="guanlan-$(date '+%Y%m%d%H%M%S')"
  # 干跑模式下写到 /tmp（不会触碰真实路径）；真实模式写同目录 .new 再原子映移
  if [ "$DRY" = "1" ]; then
    CONF_TMP="/tmp/${APP_NAME}-config.json.new"
  else
    CONF_TMP="${CONF_FILE}.new"
  fi
  # passwordHash = sha256(salt + password)，与 app/config.go hashPassword(salt, pwd) 一致
  cat > "$CONF_TMP" <<EOF
{
  "salt": "$SALT",
  "passwordHash": "$(printf '%s' "$SALT$DEFAULT_PASSWORD" | sha256sum | cut -d' ' -f1)",
  "listen": "$LISTEN_ADDR",
  "dataDir": "$DATA_PATH",
  "logDir": "$LOG_DIR",
  "port": $PORT,
  "createdAt": "$(date '+%Y-%m-%dT%H:%M:%S%z')"
}
EOF
  run_sh "mv -f $CONF_TMP $CONF_FILE"
  run_sh "chmod 0600 $CONF_FILE 2>/dev/null || true"
  NEW_PASSWORD="$DEFAULT_PASSWORD"
fi

# ===========================================================================
# 5. procd init 脚本
# ===========================================================================
log "写入 init 脚本 $INIT_SCRIPT"
if [ "$DRY" = "1" ]; then
  INIT_TMP="/tmp/${APP_NAME}-init.new"
else
  INIT_TMP="${INIT_SCRIPT}.new"
fi
cat > "$INIT_TMP" <<EOF
#!/bin/sh /etc/rc.common
# 观澜 NetScope 服务（procd）
USE_PROCD=1
START=99
STOP=10
PROG="${APP_NAME}"

APP_BIN="/usr/sbin/${APP_NAME}"
APP_DATA="${DATA_PATH}"
APP_LOG_DIR="${LOG_DIR}"
APP_LOG_FILE="${LOG_DIR}/guanlan.log"
APP_RUNDIR="${RUN_DIR}"
DNS_LOG_DIR="${DNS_LOG_DIR}"
APP_ADDR="${LISTEN_ADDR}"

start_service() {
    # /tmp 是 tmpfs，重启即失，每次启动都要确保目录存在
    mkdir -p "\$APP_RUNDIR" "\$DNS_LOG_DIR" "\$APP_LOG_DIR" 2>/dev/null
    # dnsmasq 以 dnsmasq 用户运行：必须能写入 DNS 日志目录，否则日志文件创建失败
    # （表现为日志变成 *.log.old、域名归因失效）
    chown dnsmasq:dnsmasq "\$DNS_LOG_DIR" 2>/dev/null || chmod 0777 "\$DNS_LOG_DIR" 2>/dev/null

    # 日志文件限量：超过 4MB 只保留最后 2000 行，避免长期运行撑爆存储分区
    if [ -f "\$APP_LOG_FILE" ]; then
        LOGSZ=\$(wc -c < "\$APP_LOG_FILE" 2>/dev/null || echo 0)
        if [ "\$LOGSZ" -gt 4194304 ] 2>/dev/null; then
            tail -n 2000 "\$APP_LOG_FILE" > "\$APP_LOG_FILE.tmp" 2>/dev/null && mv -f "\$APP_LOG_FILE.tmp" "\$APP_LOG_FILE"
        fi
    fi

    procd_open_instance
    procd_set_param command "\$APP_BIN" \\
        -addr "\$APP_ADDR" \\
        -data "\$APP_DATA"
    procd_set_param pidfile "${PID_FILE}"
    # 崩溃自动重启：3600 秒窗口内最多重启 5 次，间隔 5 秒
    procd_set_param respawn 3600 5 5
    procd_set_param limits nofile="4096 4096"
    # 日志真正落盘：procd 的 stdout/stderr 写文件路径；
    # 写 "1" 是转发到 procd 的 stdout（进 syslog），文件永远不会被创建
    procd_set_param stdout "\$APP_LOG_FILE"
    procd_set_param stderr "\$APP_LOG_FILE"
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger "${CONF_FILE}"
}
EOF
run_sh "chmod 0755 $INIT_TMP" || warn "设置 init 脚本权限失败"
run_sh "mv -f $INIT_TMP $INIT_SCRIPT" || die "写入 init 脚本失败"

# ===========================================================================
# 6. DNS 查询日志旁挂（安装时不启用，机制与后端 ApplyDNSTap 一致）
#
#   用户在设置页打开 dnsTap 后，后端才会：
#     uci set dhcp.@dnsmasq[0].logqueries='1' → uci commit dhcp
#     把 /etc/dnsmasq.conf 的 log-facility 行改成 /tmp/guanlan/dnsmasq.log
#     （原值备份到 /tmp/guanlan/logfacility.orig）→ stop + start dnsmasq
#
#   * 不在 /tmp/dnsmasq.d/ 新增 conf-dir 文件
#     （conf-dir 里若再写 log-facility → dnsmasq 启动失败 illegal repeated keyword）
#   * 不写 UCI logfacility（与 /etc/dnsmasq.conf 自带的 log-facility 重复 → 启动失败）
#   * 该固件 ubus call dnsmasq reload 不存在；/etc/init.d/dnsmasq reload 有 bug
#     （停得掉起不来 → 全网 DNS 中断），故只用 stop + start
#
# 失败时：清除 UCI logqueries + 还原 log-facility + 再次 stop/start + 复查；
#         服务本体安装不受影响。
# ===========================================================================

# --- DNS 健康检查 ---
dns_health_check() {
  if pidof dnsmasq >/dev/null 2>&1; then
    return 0
  fi
  if command -v nslookup >/dev/null 2>&1; then
    nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1 && return 0
  fi
  return 1
}

# --- 安全重启 dnsmasq：stop → sleep → start → nslookup 健康检查 ---
dns_restart_safe() {
  log "重启 dnsmasq（stop + start；该固件 reload 有 bug，禁止使用 reload）"
  run_sh "/etc/init.d/dnsmasq stop >/dev/null 2>&1"
  run_sh "sleep 1"
  run_sh "/etc/init.d/dnsmasq start >/dev/null 2>&1"
  run_sh "sleep 2"

  if [ "$DRY" = "1" ]; then
    run_sh "nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1 && echo '[DRY] nslookup 成功' || echo '[DRY] nslookup 失败（将触发回滚分支）'"
    return 0
  fi

  if dns_health_check; then
    log "dnsmasq 健康检查通过（进程存活 / nslookup 成功）"
    return 0
  fi

  warn "dnsmasq 健康检查失败！执行紧急回滚：清除 UCI 旁挂 + 还原 log-facility → 再次 stop/start → 复查"
  uci delete "${UCI_SECTION}.${UCI_OPT_LOGQUERIES}" 2>/dev/null
  uci commit dhcp 2>/dev/null
  # 后端改的是 /etc/dnsmasq.conf 的 log-facility（不是 UCI logfacility），
  # 这里按同一机制还原，避免留下半改状态。
  write_logfacility "$(original_logfacility)" || warn "还原 $DNS_CONF 的 log-facility 失败"
  /etc/init.d/dnsmasq stop >/dev/null 2>&1
  sleep 1
  /etc/init.d/dnsmasq start >/dev/null 2>&1
  sleep 2

  if dns_health_check; then
    warn "回滚后 dnsmasq 已恢复正常（DNS 旁挂关闭，服务本体继续安装）"
    DNS_FAIL=1
    return 1
  fi

  warn "回滚后 dnsmasq 仍未恢复！请立即人工检查："
  warn "  /etc/init.d/dnsmasq status ; logread | grep -i dnsmasq | tail -20"
  warn "  手动恢复：/etc/init.d/dnsmasq stop && /etc/init.d/dnsmasq start"
  DNS_FAIL=1
  return 1
}

# 设计意图（与 app/main.go 启动逻辑、app/dns.go ApplyDNSTap 一致）：
#   * DNS 旁挂由 dnsTap 功能开关控制，**安装时不预置**任何 UCI 选项；
#   * 用户开启 dnsTap → 后端 ApplyDNSTap(true) 才会 uci set + 改写
#     /etc/dnsmasq.conf 的 log-facility + stop/start + 健康检查；
#   * 用户关闭 dnsTap → 后端 ApplyDNSTap(false) 会 uci delete + 还原
#     log-facility（原值备份在 /tmp/guanlan/logfacility.orig）；
#   * 因此安装后 dnsmasq 保持原状：logqueries 为空、log-facility 不变，
#     不重启 dnsmasq、不加 /tmp/dnsmasq.d/ 文件 ——
#     满足「开关不打开不影响任何现有功能」。
#   * 安装脚本只把 log-facility 原值另存一份到持久目录，供卸载/回退还原。
log "DNS 旁挂：由 dnsTap 功能开关控制，安装时未启用（dnsmasq 保持原状）"
DNS_TAP_OK=0

# ===========================================================================
# 7. 启动服务
# ===========================================================================
log "注册并启动服务"
run_sh "$INIT_SCRIPT enable >/dev/null 2>&1" && log "已设置开机自启 (enable)" || warn "enable 失败（可能非 procd 环境）"
run_sh "$INIT_SCRIPT restart >/dev/null 2>&1 || { $INIT_SCRIPT stop >/dev/null 2>&1; $INIT_SCRIPT start >/dev/null 2>&1; }"

# --- 打印服务日志：优先日志文件，其次 syslog（logread -e guanlan） ---
dump_service_log() {
  N="${1:-40}"
  LOGF="${LOG_DIR}/guanlan.log"
  if [ -s "$LOGF" ]; then
    echo "--- $LOGF（最后 $N 行）---" >&2
    tail -n "$N" "$LOGF" >&2
    return 0
  fi
  if command -v logread >/dev/null 2>&1; then
    echo "--- logread -e guanlan（最后 $N 行）---" >&2
    logread -e guanlan 2>/dev/null | tail -n "$N" >&2
    return 0
  fi
  echo "（没有日志文件 $LOGF，也没有 logread）" >&2
}

# 等待进程起来
if [ "$DRY" = "1" ]; then
  run_sh "sleep 2"
else
  WAITED=0
  while [ $WAITED -lt 15 ]; do
    if pidof "$APP_NAME" >/dev/null 2>&1; then break; fi
    sleep 1
    WAITED=$((WAITED + 1))
  done

  if ! pidof "$APP_NAME" >/dev/null 2>&1; then
    warn "服务进程未启动，打印日志："
    dump_service_log 40
    exit 1
  fi
  log "服务进程已启动 (pid=$(pidof "$APP_NAME"))"
fi

# ===========================================================================
# 8. 健康检查（10 次重试）
# ===========================================================================
log "健康检查 http://127.0.0.1:${PORT}/healthz"
if [ "$DRY" = "1" ]; then
  run_sh "curl -s -m 3 http://127.0.0.1:${PORT}/healthz"
else
  HEALTH_OK=0
  i=1
  while [ $i -le 10 ]; do
    if command -v curl >/dev/null 2>&1; then
      BODY=$(curl -s -m 3 "http://127.0.0.1:${PORT}/healthz" 2>/dev/null)
    else
      BODY=$(wget -qO- -T 3 "http://127.0.0.1:${PORT}/healthz" 2>/dev/null)
    fi
    case "$BODY" in
      *'"ok"'*)
        HEALTH_OK=1
        log "健康检查通过（第 $i 次）：$BODY"
        break
        ;;
    esac
    sleep 1
    i=$((i + 1))
  done

  if [ "$HEALTH_OK" != "1" ]; then
    warn "健康检查失败，打印服务日志："
    dump_service_log 60
    echo "--- 服务状态 ---" >&2
    "$INIT_SCRIPT" status >&2 2>/dev/null || true
    exit 1
  fi
fi

# ===========================================================================
# 9. 结果输出
# ===========================================================================
echo ""
echo "============================================================"
echo " 观澜 NetScope 安装完成"
echo "============================================================"
echo " 访问地址   : http://${LAN_IP}:${PORT}"
echo " 本机自检   : http://127.0.0.1:${PORT}/healthz"
echo " 二进制     : $BIN_DST"
echo " 数据目录   : $DATA_DIR"
echo " 配置       : $CONF_FILE"
echo " 运行日志   : $LOG_DIR/guanlan.log"
echo " 系统日志   : logread -e guanlan"
if [ "$DNS_TAP_OK" = "1" ]; then
  echo " DNS 旁挂   : 已启用"
  echo "   uci 选项 : ${UCI_SECTION}.${UCI_OPT_LOGQUERIES}=1"
  echo "   日志去向 : $DNS_LOG (tmpfs，不占 overlay)"
  echo "   配置改动 : $DNS_CONF 的 log-facility（原值备份 $LOGFAC_ORIG_FILE）"
else
  echo " DNS 旁挂   : 未启用（由 dnsTap 功能开关控制；安装时未预置，dnsmasq 保持原状）"
  echo "   原值备份 : $LOGFAC_ORIG_FILE（供卸载/回退还原 log-facility）"
fi
if [ -n "$NEW_PASSWORD" ]; then
  echo ""
  echo " 管理员账号 : admin"
  echo " 初始密码   : $NEW_PASSWORD"
  echo " （首次安装生成，请登录后在设置页修改）"
fi
echo ""
echo " 开机自启   : 已 enable"
echo " 常用命令   : $INIT_SCRIPT {start|stop|restart|status}"
echo " 卸载       : sh uninstall.sh [--purge]"
echo "============================================================"
echo ""
echo "如需完全移除本服务（随时可执行）："
echo "  Windows : .\deploy\rollback.ps1"
echo "  路由器 : sh /tmp/rollback.sh"
echo "  路由器 : sh ${ROLLBACK_SH_KEEP} --purge   # 连数据目录一起删"
echo ""

# 退出前最终保险：DNS 必须处于可解析状态
if [ "$DRY" != "1" ]; then
  if ! dns_health_check; then
    warn "退出前最终检查：dnsmasq 不可解析！执行紧急恢复。"
    /etc/init.d/dnsmasq stop >/dev/null 2>&1
    sleep 1
    /etc/init.d/dnsmasq start >/dev/null 2>&1
    sleep 2
    if dns_health_check; then
      warn "dnsmasq 已恢复。"
    else
      echo "[install][ERROR] dnsmasq 仍异常，请人工介入！" >&2
      exit 2
    fi
  fi
fi

exit 0
