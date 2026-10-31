#!/bin/sh
# 观澜 NetScope · 卸载脚本（幂等，可重复执行）
#
# 用法：
#   sh uninstall.sh            # 保留数据目录 /mnt/mmcblk2p4/guanlan
#   sh uninstall.sh --purge    # 同时删除数据目录
#   GL_APPLY=0 sh uninstall.sh # 零风险干跑：只打印命令，不实际执行
#
# 安全性：
#   * 只清理本项目自建的 iptables 链（UBM_*）与 tc 规则，不触碰他人规则
#   * DNS 旁挂通过 uci delete 还原 dnsmasq 原生选项，可完全逆变
#   * 不改动网络接口、DNS 上游、lan 区配置；不重启路由器
#   * dnsmasq 只做 stop + start（该固件 reload 有 bug），且每次都做 nslookup 健康检查
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
DATA_DIR="/mnt/mmcblk2p4/${APP_NAME}"
CONF_DIR="/etc/${APP_NAME}"
INIT_SCRIPT="/etc/init.d/${APP_NAME}"
PID_FILE="/var/run/${APP_NAME}.pid"
PORT="${GUANLAN_PORT:-8088}"
RUN_DIR="/tmp/${APP_NAME}"

# --- DNS 旁挂（UCI 原生选项） ---
UCI_SECTION="dhcp.@dnsmasq[0]"
UCI_OPT_LOGQUERIES="logqueries"
UCI_OPT_LOGFACILITY="logfacility"

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

if [ "$DRY" = "1" ]; then
  log "干跑模式（GL_APPLY=0）：只打印命令，不做任何写操作"
else
  if [ "$(id -u)" != "0" ]; then
    echo "[uninstall][ERROR] 需要 root 权限" >&2
    exit 1
  fi
fi

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
  run_sh "rm -rf $CONF_DIR" && log "已删除 $CONF_DIR" || warn "删除 $CONF_DIR 失败"
else
  log "$CONF_DIR 不存在，跳过"
fi

# ===========================================================================
# 4. DNS 旁挂还原（UCI 原生选项，完全可逆）
#
#   uci delete dhcp.@dnsmasq[0].logqueries
#   uci delete dhcp.@dnsmasq[0].logfacility
#   uci commit dhcp
#   /etc/init.d/dnsmasq stop ; sleep 1 ; /etc/init.d/dnsmasq start
#   nslookup 健康检查
#
#   该固件 ubus call dnsmasq reload 不存在；/etc/init.d/dnsmasq reload 有 bug
#   （停得掉起不来 → 全网 DNS 中断），故只用 stop + start。
# ===========================================================================
log "还原 DNS 查询日志旁挂（uci delete）"

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

if command -v uci >/dev/null 2>&1; then
  run_sh "uci delete ${UCI_SECTION}.${UCI_OPT_LOGQUERIES} 2>/dev/null"
  run_sh "uci delete ${UCI_SECTION}.${UCI_OPT_LOGFACILITY} 2>/dev/null"
  run_sh "uci commit dhcp"
  log "已删除 UCI 旁挂选项并提交"
else
  warn "系统缺少 uci，跳过 UCI 还原"
fi

dns_restart_safe
DNS_HEALTH_RC=$?

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
# 6. 清理 tc 限速规则（尽力而为）
# ===========================================================================
log "清理 tc 限速规则（尽力而为）"
if command -v tc >/dev/null 2>&1; then
  for DEV in $(ls /sys/class/net 2>/dev/null); do
    tc qdisc del dev "$DEV" root 2>/dev/null && log "已删除 $DEV root qdisc" || true
    tc qdisc del dev "$DEV" handle ffff: ingress 2>/dev/null || true
  done
  if ip link show ifb0 >/dev/null 2>&1; then
    ip link del ifb0 2>/dev/null && log "已删除 ifb0" || warn "删除 ifb0 失败"
  else
    log "ifb0 不存在，跳过"
  fi
else
  warn "无 tc，跳过"
fi

# ===========================================================================
# 7. 清理运行时临时目录
# ===========================================================================
log "清理运行目录 $RUN_DIR"
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
  run_sh "uci get ${UCI_SECTION}.${UCI_OPT_LOGQUERIES} 2>/dev/null || echo '[DRY] logqueries 已为空'"
  run_sh "uci get ${UCI_SECTION}.${UCI_OPT_LOGFACILITY} 2>/dev/null || echo '[DRY] logfacility 已为空'"
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
  F=$(uci get "${UCI_SECTION}.${UCI_OPT_LOGFACILITY}" 2>/dev/null)
  if [ -n "$F" ]; then
    echo "  [FAIL] UCI logfacility 仍存在：$F"
    FAIL=1
  else
    echo "  [ OK ] UCI logfacility 已清除"
  fi
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

echo "============================================================"
if [ "$FAIL" = "0" ]; then
  echo " 卸载完成，路由器无残留。"
  echo " DNS 旁挂选项已清除，dnsmasq 日志去向恢复为系统默认（/dev/null）。"
  exit 0
else
  echo " 存在残留，请检查上面的 [FAIL] 项。"
  exit 1
fi
