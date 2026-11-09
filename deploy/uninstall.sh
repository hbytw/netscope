#!/bin/sh
# 观澜 NetScope · 卸载脚本（幂等，可重复执行）
#
# 用法：
#   sh uninstall.sh            # 保留数据目录（探测/记录得到，如 /mnt/sda1/guanlan）
#   sh uninstall.sh --purge    # 同时删除数据目录
#   GL_APPLY=0 sh uninstall.sh # 零风险干跑：只打印命令，不实际执行
#
# 数据目录不写死：优先读 /etc/guanlan/datadir（install.sh 写入），其次探测
# 已存在的 <挂载点>/guanlan 与 /mnt 下可用分区，最后兜底 /etc/guanlan；
# GUANLAN_DATA=/绝对路径 可显式指定。切勿假设 /mnt/mmcblk2p4。
#
# 安全性：
#   * 只清理本项目自建的 iptables 链（UBM_*）与 tc 规则，不触碰他人规则
#   * DNS 旁挂与后端 ApplyDNSTap 机制一致：改写的是 /etc/dnsmasq.conf 的
#     log-facility 行（原值备份在 $DATA_DIR/logfacility.orig），还原时写回该行
#   * 不改动网络接口、DNS 上游、lan 区配置；不重启路由器
#   * dnsmasq 只在确实改动过配置时才 stop + start（该固件 reload 有 bug），
#     且每次启停后都做 nslookup 健康检查
#   * 任何一步失败均记录并继续；脚本退出前确保 DNS 可解析
#
set -u

# ---------------------------------------------------------------------------
# 干跑开关：GL_APPLY=0 时只打印步骤，不做任何写操作
# ---------------------------------------------------------------------------
APPLY="${GL_APPLY:-1}"
DRY=0
case "$APPLY" in
  0|false|no|off|DRY|dry) DRY=1 ;;
esac

APP_NAME="guanlan"
BIN_DST="/usr/sbin/${APP_NAME}"
CONF_DIR="/etc/${APP_NAME}"
INIT_SCRIPT="/etc/init.d/${APP_NAME}"
PID_FILE="/var/run/${APP_NAME}.pid"
PORT="${GUANLAN_PORT:-8088}"
RUN_DIR="/tmp/${APP_NAME}"

# 数据目录不假设固定分区（不同路由器可能是 /mnt/sda1、/mnt/nvme0n1p1，
# 甚至没有外挂存储）：由下面 data_dir_detect 现场探测，与 install.sh 同一套逻辑。
DATA_DIR=""
DATA_RECORD="${CONF_DIR}/datadir"   # install.sh 写入的数据目录记录

# --- DNS 旁挂（与后端 ApplyDNSTap 一致：改写 /etc/dnsmasq.conf 的 log-facility） ---
DNS_CONF="/etc/dnsmasq.conf"
# 原值备份：install.sh 写在持久目录（跨重启保留），后端运行时另存 <dataDir>/logfacility.orig
LOGFAC_ORIG_FILE=""
LOGFAC_ORIG_TMP="/tmp/${APP_NAME}/logfacility.orig"
UCI_SECTION="dhcp.@dnsmasq[0]"
UCI_OPT_LOGQUERIES="logqueries"

# --- tc：本项目只使用 br-lan（root handle 1: htb / ingress handle ffff:）与 ifb0（root handle 2: htb） ---
TC_DEV_MAIN="br-lan"
TC_DEV_IFB="ifb0"

PURGE=0
for a in "$@"; do
  case "$a" in
    --purge|-p) PURGE=1 ;;
    *) echo "[uninstall][WARN] 未知参数：$a" >&2 ;;
  esac
done

log()  { echo "[uninstall] $*"; }
warn() { echo "[uninstall][WARN] $*" >&2; }

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

# ===========================================================================
# 数据目录探测（install.sh / rollback.sh / uninstall.sh 三处保持同一套逻辑）
#
# 不假设固定分区（/mnt/mmcblk2p4 只是部分机器恰好如此，也可能是 /mnt/sda1、
# /mnt/nvme0n1p1，甚至没有外挂存储）。
#
# 优先级：
#   ① 环境变量 GUANLAN_DATA（显式指定，最高）
#   ② /etc/guanlan/datadir（install.sh 写入；保证回滚/卸载删的是同一处）
#   ③ 已存在的 <挂载点>/guanlan（重装/卸载时优先复用旧数据目录）
#   ④ /mnt 下可写且剩余 ≥200MB 的挂载点（mmcblk/sd/nvme/ssd 优先，其次任意）
#   ⑤ /etc/guanlan（overlay 兜底，空间可能很小，但保证能装）
#
# 结果写入全局 DATA_DIR / DATA_SRC（不用 echo，避免 $(...) 子 shell 丢变量）。
# ===========================================================================
DATA_MIN_FREE_KB=204800   # 200 MB

# 合法数据目录：绝对路径、至少两级目录（避免 "/"、"/mnt" 这类会被整目录误删），
# 且不含空白/shell 元字符（后续要拼进 sh -c）
_data_path_ok() {
  case "$1" in
    /?*/?*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[!A-Za-z0-9_./-]*) return 1 ;;
    *..*) return 1 ;;
  esac
  return 0
}

# 去掉末尾多余的 "/"，避免同一路径两种写法（/etc/guanlan 与 /etc/guanlan/）
_data_trim_slash() {
  _dp="$1"
  while [ "$_dp" != "/" ] && [ "${_dp%/}" != "$_dp" ]; do
    _dp="${_dp%/}"
  done
  printf '%s\n' "$_dp"
}

# 可用空间（KB）；df 不支持 -P 时退回 -k；失败输出空
_data_free_kb() {
  _df="$(df -kP "$1" 2>/dev/null)" || _df="$(df -k "$1" 2>/dev/null)"
  [ -n "$_df" ] || return 1
  echo "$_df" | awk 'NR > 1 { print $4; exit }'
}

# 目录可写（目录不存在则要求父目录可写）。root 下 [ -w ] 对只读挂载也可能为真，
# 所以真实写一个临时文件确认；干跑模式不落盘。
_data_writable() {
  if [ -d "$1" ]; then
    if [ "${DRY:-0}" = "1" ]; then
      [ -w "$1" ]
      return $?
    fi
    _wt="$1/.guanlan-write-test.$$"
    if ( : > "$_wt" ) 2>/dev/null; then
      rm -f "$_wt" 2>/dev/null
      return 0
    fi
    return 1
  fi
  _dparent="$(dirname "$1")"
  [ -d "$_dparent" ] && _data_writable "$_dparent"
}

# /mnt 下已挂载且非只读的分区：每行「设备<TAB>挂载点」
_data_mnt_list() {
  [ -r /proc/mounts ] || return 1
  awk '
    $2 == "/mnt" || index($2, "/mnt/") == 1 {
      if ($4 ~ /(^|,)ro(,|$)/) next;
      print $1 "\t" $2;
    }' /proc/mounts
}

# 设备名/挂载点名像内置存储（仅用于排序优先级，不影响可用性判断）
_data_storage_hint() {
  case "$1" in
    *mmcblk*|*nvme*|*mmc*|*ssd*|*/sd[a-z]*) return 0 ;;
  esac
  return 1
}

# ③ 已存在的 <挂载点>/guanlan（里面有历史数据），取剩余空间最大的一处
_data_pick_existing() {
  _best=""
  _best_kb=-1
  while IFS="$(printf '\t')" read -r _mdev _mmp; do
    [ -n "$_mmp" ] || continue
    [ -d "$_mmp/${APP_NAME}" ] || continue
    _kb="$(_data_free_kb "$_mmp" 2>/dev/null)"
    [ -n "$_kb" ] || _kb=0
    if [ "$_kb" -gt "$_best_kb" ] 2>/dev/null; then
      _best="$_mmp/${APP_NAME}"
      _best_kb="$_kb"
    fi
  done <<EOF
$(_data_mnt_list)
EOF
  [ -n "$_best" ] && { echo "$_best"; return 0; }
  return 1
}

# ④ 新建数据目录的挂载点：可写、剩余 ≥200MB；存储类优先，其次任意
_data_pick_mount() {
  for _tier in storage any; do
    _best=""
    _best_kb=-1
    while IFS="$(printf '\t')" read -r _mdev _mmp; do
      [ -n "$_mmp" ] || continue
      if [ "$_tier" = "storage" ]; then
        _data_storage_hint "$_mdev $_mmp" || continue
      fi
      _data_writable "$_mmp/${APP_NAME}" || continue
      _kb="$(_data_free_kb "$_mmp" 2>/dev/null)"
      # 空间已知但不足 200MB → 跳过；df 不可用（未知）时按可用处理
      if [ -n "$_kb" ] && [ "$_kb" -lt "$DATA_MIN_FREE_KB" ] 2>/dev/null; then
        continue
      fi
      [ -n "$_kb" ] || _kb=0
      if [ "$_kb" -gt "$_best_kb" ] 2>/dev/null; then
        _best="$_mmp/${APP_NAME}"
        _best_kb="$_kb"
      fi
    done <<EOF
$(_data_mnt_list)
EOF
    [ -n "$_best" ] && { echo "$_best"; return 0; }
  done
  return 1
}

# ② 读记录；记录指向的挂载点已不存在则视为无效（避免删错地方）
_data_pick_recorded() {
  [ -s "$DATA_RECORD" ] || return 1
  _rec=""
  IFS= read -r _rec < "$DATA_RECORD" 2>/dev/null || true
  _rec="$(_data_trim_slash "$(printf '%s' "$_rec" | tr -d '\r')")"
  _data_path_ok "$_rec" || return 1
  if [ -d "$_rec" ] || [ -d "$(dirname "$_rec")" ]; then
    echo "$_rec"
    return 0
  fi
  return 1
}

data_dir_detect() {
  DATA_DIR=""
  DATA_SRC=""

  # ① 环境变量
  if [ -n "${GUANLAN_DATA:-}" ]; then
    if _data_path_ok "$(_data_trim_slash "$GUANLAN_DATA")"; then
      DATA_DIR="$(_data_trim_slash "$GUANLAN_DATA")"
      DATA_SRC="环境变量 GUANLAN_DATA"
      return 0
    fi
    warn "忽略非法的 GUANLAN_DATA=${GUANLAN_DATA}（需为至少两级、不含空白的绝对路径）"
  fi

  # ② 安装时记录的路径
  if _rec="$(_data_pick_recorded)"; then
    if [ -n "${GUANLAN_DATA:-}" ] && [ "$_rec" != "$GUANLAN_DATA" ]; then
      warn "记录的旧数据目录为 $_rec（与 GUANLAN_DATA 不同），旧数据不会自动迁移"
    fi
    DATA_DIR="$_rec"
    DATA_SRC="记录文件 $DATA_RECORD"
    return 0
  fi

  # ③ 已存在的 <挂载点>/guanlan
  if _dir="$(_data_pick_existing)"; then
    DATA_DIR="$_dir"
    DATA_SRC="已存在的 /mnt 数据目录"
    return 0
  fi

  # ④ /mnt 可写且空间充足的分区
  if _dir="$(_data_pick_mount)"; then
    DATA_DIR="$_dir"
    DATA_SRC="/mnt 分区探测"
    return 0
  fi

  # ⑤ overlay 兜底
  DATA_DIR="/etc/${APP_NAME}"
  DATA_SRC="overlay 兜底（/etc，未找到可用的 /mnt 分区）"
  if ! _data_writable "$DATA_DIR"; then
    warn "overlay 兜底路径 $DATA_DIR 不可写，安装/卸载可能失败，请设置 GUANLAN_DATA"
  fi
  return 0
}

# --- 现场探测（结果必须与 install.sh 一致，才能删掉它放的东西） ---
data_dir_detect
LOGFAC_ORIG_FILE="${DATA_DIR}/logfacility.orig"

if [ "$DRY" = "1" ]; then
  log "干跑模式（GL_APPLY=0）：只打印命令，不做任何写操作"
else
  if [ "$(id -u)" != "0" ]; then
    echo "[uninstall][ERROR] 需要 root 权限" >&2
    exit 1
  fi
fi
log "数据目录：$DATA_DIR（来源：$DATA_SRC）"

# ===========================================================================
# 1. 停止服务
# ===========================================================================
log "停止服务"
if [ -x "$INIT_SCRIPT" ]; then
  run_sh "$INIT_SCRIPT stop >/dev/null 2>&1" && log "init 脚本 stop 完成" || warn "init 脚本 stop 返回非零（继续）"
  run_sh "$INIT_SCRIPT disable >/dev/null 2>&1" && log "已取消开机自启 (disable)" || warn "disable 返回非零（继续）"
else
  warn "未找到 init 脚本 $INIT_SCRIPT，跳过 stop"
fi

# 兜底：直接杀进程
if [ "$DRY" != "1" ] && pidof "$APP_NAME" >/dev/null 2>&1; then
  PIDS=$(pidof "$APP_NAME")
  log "仍有进程存活：$PIDS，发送 TERM"
  kill $PIDS 2>/dev/null || true
  W=0
  while [ $W -lt 8 ] && pidof "$APP_NAME" >/dev/null 2>&1; do
    sleep 1
    W=$((W + 1))
  done
  if pidof "$APP_NAME" >/dev/null 2>&1; then
    warn "进程未响应 TERM，发送 KILL"
    kill -9 $(pidof "$APP_NAME") 2>/dev/null || true
    sleep 1
  fi
fi
run_sh "rm -f $PID_FILE"

# ===========================================================================
# 2. 删除 init 脚本与二进制
# ===========================================================================
log "删除 init 脚本与二进制"
run_sh "rm -f $INIT_SCRIPT" && log "已删除 $INIT_SCRIPT" || warn "删除 $INIT_SCRIPT 失败"
run_sh "rm -f $BIN_DST" && log "已删除 $BIN_DST" || warn "删除 $BIN_DST 失败"
run_sh "rm -f /usr/sbin/.${APP_NAME}.new"

# ===========================================================================
# 3. 删除配置目录
# ===========================================================================
log "删除配置目录 $CONF_DIR"
if [ -d "$CONF_DIR" ]; then
  if [ "$CONF_DIR" = "$DATA_DIR" ]; then
    # 数据目录与配置目录重合（overlay 兜底路径）：只删程序配置与记录，
    # 数据、logs 与 logfacility.orig 保留（§8 按 --purge 决定是否删除）。
    for _f in config.json config.json.new datadir rollback.sh; do
      run_sh "rm -f $CONF_DIR/$_f"
    done
    log "已清理 $CONF_DIR 下的程序配置（数据目录与配置目录重合，数据保留到 --purge）"
  else
    run_sh "rm -rf $CONF_DIR" && log "已删除 $CONF_DIR" || warn "删除 $CONF_DIR 失败"
  fi
else
  log "$CONF_DIR 不存在，跳过"
fi

# ===========================================================================
# 4. 还原 DNS 旁挂（与后端 ApplyDNSTap 机制完全一致）
#
#   后端开启旁挂时做的是：
#     uci set dhcp.@dnsmasq[0].logqueries='1' → uci commit dhcp
#     把 /etc/dnsmasq.conf 的 log-facility 行改成 /var/run/dnsmasq/guanlan-dns.log
#     （原值备份在 <dataDir>/logfacility.orig）→ stop + start dnsmasq
#   关闭旁挂时：uci delete logqueries + 把 log-facility 行写回原值 + stop + start。
#
#   所以卸载脚本必须还原的是「/etc/dnsmasq.conf 的 log-facility 行」，
#   而不是 uci delete logfacility —— 后端从不写 UCI logfacility（写了会与
#   /etc/dnsmasq.conf 自带的 log-facility 重复 → dnsmasq 报 illegal repeated
#   keyword 启动失败）。
#
#   原值来源（优先级从高到低）：
#     1) $DATA_DIR/logfacility.orig —— install.sh 写入的持久备份
#     2) <dataDir>/logfacility.orig —— 后端运行时备份（tmpfs，重启即失）
#     3) /dev/null —— dnsmasq 默认值
#
#   只有确实改动过 dnsmasq 配置（log-facility 被改过 / logqueries 仍存在）时才重启 dnsmasq。
# ===========================================================================
log "还原 DNS 查询日志旁挂（/etc/dnsmasq.conf log-facility）"

# --- 读取 /etc/dnsmasq.conf 当前的 log-facility 取值（只读） ---
current_logfacility() {
  [ -f "$DNS_CONF" ] || return 0
  grep -m1 '^[[:space:]]*log-facility[[:space:]]*=' "$DNS_CONF" 2>/dev/null \
    | sed -e 's/^[^=]*=//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# --- 取原值（只接受路径/设备名字符，非法值一律回退 /dev/null） ---
original_logfacility() {
  V=""
  if [ -s "$LOGFAC_ORIG_FILE" ]; then
    V=$(head -n1 "$LOGFAC_ORIG_FILE" 2>/dev/null | tr -d '\r')
  fi
  if [ -z "$V" ] && [ -s "$LOGFAC_ORIG_TMP" ]; then
    V=$(head -n1 "$LOGFAC_ORIG_TMP" 2>/dev/null | tr -d '\r')
  fi
  case "$V" in
    ""|*[!A-Za-z0-9_./-]*) echo "/dev/null" ;;
    *) echo "$V" ;;
  esac
}

# --- 把 log-facility 行写回指定值 ---
write_logfacility() {
  V="$1"
  [ -f "$DNS_CONF" ] || return 1
  sed -i 's#^[[:space:]]*log-facility[[:space:]]*=.*#log-facility='"$V"'#' "$DNS_CONF" 2>/dev/null || return 1
  grep -q '^[[:space:]]*log-facility[[:space:]]*=' "$DNS_CONF" 2>/dev/null \
    || echo "log-facility=$V" >> "$DNS_CONF"
  return 0
}

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

# --- 安全重启 dnsmasq（stop → sleep → start → nslookup 检查 → 失败回滚重试） ---
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

  warn "dnsmasq 健康检查失败！执行紧急恢复：再次 stop/start → 复查"
  /etc/init.d/dnsmasq stop >/dev/null 2>&1
  sleep 1
  /etc/init.d/dnsmasq start >/dev/null 2>&1
  sleep 2

  if dns_health_check; then
    warn "恢复后 dnsmasq 已正常"
    return 0
  fi

  warn "dnsmasq 仍未恢复！请立即人工检查："
  warn "  /etc/init.d/dnsmasq status ; logread | grep -i dnsmasq | tail -20"
  warn "  手动恢复：/etc/init.d/dnsmasq stop && /etc/init.d/dnsmasq start"
  return 1
}

# --- 判断是否真的改动过 dnsmasq 配置 ---
DNS_TOUCHED=0
CUR_LOGFAC=$(current_logfacility)
ORIG_LOGFAC=$(original_logfacility)

if [ -n "$CUR_LOGFAC" ] && [ "$CUR_LOGFAC" != "$ORIG_LOGFAC" ]; then
  DNS_TOUCHED=1
  log "检测到 log-facility 被改为 $CUR_LOGFAC（原值 $ORIG_LOGFAC），需要还原"
else
  log "log-facility 未被改动（当前：${CUR_LOGFAC:-无该行}，原值：$ORIG_LOGFAC）"
fi

if command -v uci >/dev/null 2>&1; then
  if uci get "${UCI_SECTION}.${UCI_OPT_LOGQUERIES}" >/dev/null 2>&1; then
    DNS_TOUCHED=1
    log "检测到 UCI ${UCI_SECTION}.${UCI_OPT_LOGQUERIES} 仍存在，需要清除"
  fi
else
  warn "系统缺少 uci，跳过 UCI 还原"
fi

if [ "$DRY" = "1" ]; then
  run_sh "sed -i 's#^[[:space:]]*log-facility[[:space:]]*=.*#log-facility=${ORIG_LOGFAC}#' ${DNS_CONF}"
  run_sh "uci delete ${UCI_SECTION}.${UCI_OPT_LOGQUERIES} 2>/dev/null; uci commit dhcp"
  if [ "$DNS_TOUCHED" = "1" ]; then
    run_sh "/etc/init.d/dnsmasq stop >/dev/null 2>&1; sleep 1; /etc/init.d/dnsmasq start >/dev/null 2>&1"
  fi
  DNS_HEALTH_RC=0
elif [ "$DNS_TOUCHED" = "1" ]; then
  # 还原 log-facility（先写回原值，再重启 dnsmasq 让其生效）
  if write_logfacility "$ORIG_LOGFAC"; then
    log "已还原 $DNS_CONF 的 log-facility → $ORIG_LOGFAC"
    # 备份已用完，删除（避免下次误用陈旧原值）
    run_sh "rm -f $LOGFAC_ORIG_FILE"
  else
    warn "还原 $DNS_CONF 的 log-facility 失败，请人工检查（备份文件已保留：$LOGFAC_ORIG_FILE）"
  fi
  if command -v uci >/dev/null 2>&1; then
    run_sh "uci delete ${UCI_SECTION}.${UCI_OPT_LOGQUERIES} 2>/dev/null"
    run_sh "uci commit dhcp"
  fi

  dns_restart_safe
  DNS_HEALTH_RC=$?
else
  log "未启用过 DNS 旁挂（dnsmasq 配置未被改动），不重启 dnsmasq"
  DNS_HEALTH_RC=0
fi

# ===========================================================================
# 5. 清理 iptables 自有链（UBM_*）——只删本项目的链
# ===========================================================================
log "清理 iptables UBM_* 链"
if command -v iptables >/dev/null 2>&1; then
  CHAINS=$(iptables -S 2>/dev/null | awk '/^-N /{print $2}' | grep '^UBM_' || true)
  if [ -z "$CHAINS" ]; then
    log "未发现 UBM_* 链，跳过"
  else
    for CH in $CHAINS; do
      # 先删除链内规则
      for TBL in filter mangle nat raw; do
        iptables -t "$TBL" -D "$CH" 2>/dev/null || true
      done
      # 删除顶层链上的跳转
      for TBL in filter mangle nat raw; do
        for FROM in FORWARD INPUT OUTPUT PREROUTING POSTROUTING; do
          iptables -t "$TBL" -D "$FROM" -j "$CH" 2>/dev/null || true
        done
      done
      # flush 并删除链
      for TBL in filter mangle nat raw; do
        iptables -t "$TBL" -F "$CH" 2>/dev/null || true
        iptables -t "$TBL" -X "$CH" 2>/dev/null || true
      done
      if iptables -S 2>/dev/null | grep -q "^-N $CH"; then
        warn "链 $CH 仍存在（可能仍被引用）"
      else
        log "已清理链 $CH"
      fi
    done
  fi
else
  warn "无 iptables，跳过"
fi

# ===========================================================================
# 6. 清理 tc 限速规则（只处理本项目用过的那几个，且先比对句柄）
#
#   本项目只创建过：
#     br-lan  root    handle 1: htb   （下行限速）
#     br-lan  ingress handle ffff:    （上行重定向到 ifb0）
#     ifb0    root    handle 2: htb   （上行限速）
#
#   绝不能对所有网卡执行 tc qdisc del root/ingress —— 那会抹掉用户自己的
#   SQM/QoS 队列（例如 WAN 口上的 cake）。所以先 tc qdisc show 比对句柄与类型，
#   确认是本项目创建的才删除；不是就跳过并保留用户配置。
# ===========================================================================
log "清理 tc 限速规则（只处理 br-lan / ifb0，且先比对句柄）"
if command -v tc >/dev/null 2>&1; then
  # --- br-lan root：必须是 htb 且句柄为 1: 才认定为本项目的 ---
  ROOT_OURS=0
  if tc qdisc show dev "$TC_DEV_MAIN" 2>/dev/null | grep -q 'qdisc htb 1:'; then
    ROOT_OURS=1
    tc qdisc del dev "$TC_DEV_MAIN" root 2>/dev/null \
      && log "已删除 $TC_DEV_MAIN root qdisc（htb 1:）" \
      || warn "删除 $TC_DEV_MAIN root qdisc 失败"
  else
    log "跳过 $TC_DEV_MAIN root qdisc（非本项目的 htb 1:，保留用户自己的 QoS）"
  fi

  # --- br-lan ingress：只有在本项目的 root 队列存在、且过滤器把流量重定向到 ifb0 时才删 ---
  if [ "$ROOT_OURS" = "1" ] && \
     tc filter show dev "$TC_DEV_MAIN" parent ffff: 2>/dev/null | grep -qi 'redirect.*ifb0'; then
    tc qdisc del dev "$TC_DEV_MAIN" handle ffff: ingress 2>/dev/null \
      && log "已删除 $TC_DEV_MAIN ingress qdisc" \
      || warn "删除 $TC_DEV_MAIN ingress qdisc 失败"
  else
    log "跳过 $TC_DEV_MAIN ingress qdisc（未确认是本项目创建，保留用户自己的 QoS）"
  fi

  # --- ifb0：只删句柄 2: 的 htb；设备上还有别的队列（如用户 SQM）就整台保留 ---
  if ip link show "$TC_DEV_IFB" >/dev/null 2>&1; then
    if tc qdisc show dev "$TC_DEV_IFB" 2>/dev/null | grep -q 'qdisc htb 2:'; then
      tc qdisc del dev "$TC_DEV_IFB" root 2>/dev/null \
        && log "已删除 $TC_DEV_IFB root qdisc（htb 2:）" \
        || warn "删除 $TC_DEV_IFB root qdisc 失败"
    fi
    if tc qdisc show dev "$TC_DEV_IFB" 2>/dev/null | grep -q .; then
      log "$TC_DEV_IFB 上仍有其它队列（可能是用户自己的 SQM/QoS），保留该设备"
    else
      ip link del "$TC_DEV_IFB" 2>/dev/null && log "已删除 $TC_DEV_IFB" || warn "删除 $TC_DEV_IFB 失败"
    fi
  else
    log "$TC_DEV_IFB 不存在，跳过"
  fi
else
  warn "无 tc，跳过"
fi

# ===========================================================================
# 7. 清理运行时临时目录
#
#   /tmp/guanlan 里可能有后端运行时写的 logfacility.orig（tmpfs，重启即失）。
#   先把它转存到持久目录，再删运行目录 —— 否则原值备份会跟着一起消失。
# ===========================================================================
log "清理运行目录 $RUN_DIR"
if [ "$DRY" != "1" ] && [ -s "$LOGFAC_ORIG_TMP" ] && [ ! -s "$LOGFAC_ORIG_FILE" ]; then
  NOW_LOGFAC=$(current_logfacility)
  if [ -n "$NOW_LOGFAC" ] && [ "$NOW_LOGFAC" != "$ORIG_LOGFAC" ]; then
    # 还原尚未生效（失败）：把原值备份转存到持久目录，别让它随 /tmp 一起消失
    cp -f "$LOGFAC_ORIG_TMP" "$LOGFAC_ORIG_FILE" 2>/dev/null \
      && log "已把 log-facility 原值转存到 $LOGFAC_ORIG_FILE"
  fi
fi
run_sh "rm -rf $RUN_DIR 2>/dev/null" && log "已删除 $RUN_DIR" || warn "删除 $RUN_DIR 失败"

# ===========================================================================
# 8. 数据目录（可选 purge）
# ===========================================================================
if [ "$PURGE" = "1" ]; then
  log "删除数据目录 $DATA_DIR（--purge）"
  run_sh "rm -rf $DATA_DIR" && log "已删除 $DATA_DIR" || warn "删除 $DATA_DIR 失败"
else
  if [ -d "$DATA_DIR" ]; then
    log "保留数据目录 $DATA_DIR（如需彻底删除请加 --purge）"
  fi
fi

# ===========================================================================
# 9. 残留检查
# ===========================================================================
echo ""
echo "============================================================"
echo " 卸载结果检查"
echo "============================================================"

FAIL=0

if [ "$DRY" = "1" ]; then
  run_sh "netstat -lnt 2>/dev/null | grep ':${PORT} ' || echo '[DRY] 端口 ${PORT} 未监听'"
  run_sh "pidof $APP_NAME || echo '[DRY] 无 $APP_NAME 进程'"
  run_sh "ls -l $BIN_DST $INIT_SCRIPT $CONF_DIR 2>&1 || true"
  run_sh "ls -ld $DATA_DIR 2>&1 || true"
  run_sh "uci get ${UCI_SECTION}.${UCI_OPT_LOGQUERIES} 2>/dev/null || echo '[DRY] logqueries 已为空'"
  run_sh "grep -n 'log-facility' ${DNS_CONF} 2>/dev/null || echo '[DRY] 无 log-facility 行'"
  run_sh "iptables -S 2>/dev/null | grep '^UBM_' || echo '[DRY] 无 UBM_* 链'"
  run_sh "nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1 && echo '[DRY] nslookup 正常' || echo '[DRY] nslookup 失败'"
  echo "============================================================"
  echo " 干跑结束（未做任何修改）。"
  exit 0
fi

# 端口
if netstat -lnt 2>/dev/null | grep -q ":${PORT} "; then
  echo "  [FAIL] 端口 ${PORT} 仍在监听"
  FAIL=1
else
  echo "  [ OK ] 端口 ${PORT} 已关闭"
fi

# 进程
if pidof "$APP_NAME" >/dev/null 2>&1; then
  echo "  [FAIL] 仍有 ${APP_NAME} 进程：$(pidof "$APP_NAME")"
  FAIL=1
else
  echo "  [ OK ] 无 ${APP_NAME} 进程"
fi

# 文件
for F in "$BIN_DST" "$INIT_SCRIPT" "$CONF_DIR"; do
  if [ -e "$F" ]; then
    echo "  [FAIL] 残留：$F"
    FAIL=1
  else
    echo "  [ OK ] 已移除：$F"
  fi
done

# iptables 链
if command -v iptables >/dev/null 2>&1; then
  LEFT=$(iptables -S 2>/dev/null | awk '/^-N /{print $2}' | grep '^UBM_' || true)
  if [ -n "$LEFT" ]; then
    echo "  [FAIL] 残留 iptables 链：$(echo $LEFT)"
    FAIL=1
  else
    echo "  [ OK ] 无 UBM_* iptables 链"
  fi
fi

# UCI 旁挂选项还原确认
if command -v uci >/dev/null 2>&1; then
  Q=$(uci get "${UCI_SECTION}.${UCI_OPT_LOGQUERIES}" 2>/dev/null)
  if [ -n "$Q" ]; then
    echo "  [FAIL] UCI logqueries 仍存在：$Q"
    FAIL=1
  else
    echo "  [ OK ] UCI logqueries 已清除"
  fi
fi

# /etc/dnsmasq.conf 的 log-facility 还原确认（后端旁挂改的就是这一行）
NOW_LOGFAC=$(current_logfacility)
if [ -n "$NOW_LOGFAC" ] && [ "$NOW_LOGFAC" != "$ORIG_LOGFAC" ]; then
  echo "  [FAIL] log-facility 未还原：当前 $NOW_LOGFAC（原值 $ORIG_LOGFAC）"
  FAIL=1
else
  echo "  [ OK ] log-facility 已还原（${NOW_LOGFAC:-无该行}）"
fi

# dnsmasq 健康与解析验证
if pidof dnsmasq >/dev/null 2>&1; then
  echo "  [ OK ] dnsmasq 进程存活"
else
  echo "  [FAIL] dnsmasq 进程不存在"
  FAIL=1
fi
if command -v nslookup >/dev/null 2>&1; then
  if nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1; then
    echo "  [ OK ] nslookup www.baidu.com 127.0.0.1 解析正常"
  else
    echo "  [FAIL] nslookup 解析失败，DNS 可能异常"
    FAIL=1
  fi
else
  echo "  [SKIP] 无 nslookup，跳过解析验证"
fi

# dnsmasq 重启后的健康检查退出码必须纳入最终判定（此前被丢弃）
if [ "$DNS_HEALTH_RC" != "0" ]; then
  echo "  [FAIL] dnsmasq 重启后健康检查未通过（已做过紧急恢复，仍异常）"
  FAIL=1
fi

echo "============================================================"
if [ "$FAIL" = "0" ]; then
  echo " 卸载完成，路由器无残留。"
  echo " DNS 旁挂已还原：UCI logqueries 已清除，/etc/dnsmasq.conf 的 log-facility 已回到原值。"
  exit 0
else
  echo " 存在残留，请检查上面的 [FAIL] 项。"
  exit 1
fi
