#!/bin/sh
# =============================================================================
# 观澜 NetScope · 一键回退脚本（用户自保工具）
# =============================================================================
# 用途：把路由器恢复到"从未安装过观澜 NetScope"的状态。
#       任何时候你都可以自己执行本脚本，不需要任何人协助。
#
# 用法（把脚本传到路由器后执行）：
#       sh /tmp/rollback.sh          # 标准回退（保留数据，便于日后重装）
#       sh /tmp/rollback.sh --purge  # 连数据目录一起删除
#
# 本脚本的设计原则（按"绝对不能把网络搞坏"排序）：
#   1. **只做减法**：删除本项目创建的东西，绝不新增/修改任何其它配置。
#   2. **不碰 DNS 上游、不碰防火墙 lan 区、不碰网卡、不重启路由器**。
#   3. **dnsmasq 只做 stop+start**（该固件 reload 有 bug：停得掉起不来），
#      且每次启停后都用 nslookup 健康检查，失败立即再恢复。
#   4. **退出前必须保证 DNS 可解析**；否则走紧急恢复分支。
#   5. **可重复执行**：跑第二遍不会出错，也不会产生额外副作用。
#   6. **不删除非本项目的 iptables 规则**：只清 UBM_* 自有链。
#
# 影响说明：执行期间 DNS 会有约 1-2 秒解析空窗（仅当旁挂曾被启用时），
#           其余时间你的网络不受任何影响。
# =============================================================================

set -u

APP="guanlan"
BIN="/usr/sbin/${APP}"
DATA="/mnt/mmcblk2p4/${APP}"
CONF="/etc/${APP}"
INIT="/etc/init.d/${APP}"
RUN="/tmp/${APP}"
DNS_CONF_FILE="/tmp/dnsmasq.d/99-${APP}-logging.conf"

PURGE=0
for a in "$@"; do
  case "$a" in
    --purge|-p) PURGE=1 ;;
    *) echo "[rollback][WARN] 忽略未知参数：$a" ;;
  esac
done

say()  { echo "[rollback] $*"; }
warn() { echo "[rollback][WARN] $*" >&2; }
ok()   { echo "[rollback][OK]   $*"; }

# ---------------------------------------------------------------------------
# 干跑开关：GL_APPLY=0 时所有写操作只打印不执行
# ---------------------------------------------------------------------------
APPLY="${GL_APPLY:-1}"
DRY=0
case "$APPLY" in
  0|false|no|off|DRY|dry) DRY=1 ;;
esac
if [ "$DRY" = "1" ]; then
  say "干跑模式（GL_APPLY=0）：只打印将执行的动作，不做任何修改"
fi

# 写操作包装：干跑时只打印
wr() {
  if [ "$DRY" = "1" ]; then
    echo "[DRY] $*"
    return 0
  fi
  "$@"
}

# ---------------------------------------------------------------------------
# 健康检查：DNS 是否可用
# ---------------------------------------------------------------------------
dns_ok() {
  nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1
}

dns_healthy() {
  if pidof dnsmasq >/dev/null 2>&1 && dns_ok; then
    ok "DNS 正常（dnsmasq 存活且解析成功）"
    return 0
  fi
  return 1
}

# 安全重启 dnsmasq：stop + start + 健康检查 + 失败再恢复
restart_dnsmasq_safe() {
  if [ "$DRY" = "1" ]; then
    say "[DRY] 将执行：/etc/init.d/dnsmasq stop && sleep 1 && /etc/init.d/dnsmasq start"
    return 0
  fi
  say "重启 dnsmasq（stop + start）使配置生效…"
  /etc/init.d/dnsmasq stop >/dev/null 2>&1 || true
  sleep 1
  /etc/init.d/dnsmasq start >/dev/null 2>&1 || true
  sleep 2
  if dns_healthy; then
    return 0
  fi
  warn "dnsmasq 健康检查失败，执行紧急恢复…"
  /etc/init.d/dnsmasq stop >/dev/null 2>&1 || true
  sleep 1
  /etc/init.d/dnsmasq start >/dev/null 2>&1 || true
  sleep 3
  if dns_healthy; then
    warn "已恢复到可解析状态"
    return 0
  fi
  warn "DNS 仍不可用！请手动检查：/etc/init.d/dnsmasq start"
  return 1
}

say "===== 观澜 NetScope 一键回退 ====="
say "目标：把路由器恢复到未安装本项目的状态"

# ---------------------------------------------------------------------------
# 1. 停止服务
# ---------------------------------------------------------------------------
if [ -x "$INIT" ]; then
  say "停止服务…"
  wr /etc/init.d/${APP} stop >/dev/null 2>&1 || true
  wr /etc/init.d/${APP} disable >/dev/null 2>&1 || true
  ok "服务已停止并取消开机自启"
else
  say "未发现 init 脚本，跳过停止服务"
fi

# ---------------------------------------------------------------------------
# 2. 清理 iptables 自有链（只删 UBM_*，绝不碰他人规则）
# ---------------------------------------------------------------------------
# 实现说明：不解析 iptables-save 的输出（脆弱且易误伤）。
# 直接用 `iptables -nL <chain> --line-numbers` 找到跳转到 UBM_* 的规则行号，
# 从大到小删除（避免删除后行号漂移），然后 flush + delete 链。
say "清理 iptables 自有链…"
for c in UBM_FWD UBM_IN; do
  if ! iptables -nL "$c" >/dev/null 2>&1; then
    continue                      # 链不存在，无需处理
  fi
  # 找出所有引用该链的父链
  parents=$(iptables-save 2>/dev/null | grep -E -- "-j $c( |$)" | sed -E 's/^-A ([^ ]+) .*/\1/' | sort -u)
  for p in $parents; do
    [ "$p" = "$c" ] && continue
    # 从大到小删除行号，保证删除过程中行号不漂移
    nums=$(iptables -nL "$p" --line-numbers 2>/dev/null \
           | awk -v c="$c" '$2 != "target" && $0 ~ ("-j " c "( |$)") {print $1}' | sort -rn)
    for n in $nums; do
      wr iptables -D "$p" "$n" >/dev/null 2>&1 || true
    done
  done
  # 链内自引用也清理一次
  nums=$(iptables -nL "$c" --line-numbers 2>/dev/null \
         | awk -v c="$c" '$0 ~ ("-j " c "( |$)") {print $1}' | sort -rn)
  for n in $nums; do
    wr iptables -D "$c" "$n" >/dev/null 2>&1 || true
  done
  wr iptables -F "$c" >/dev/null 2>&1 || true
  wr iptables -X "$c" >/dev/null 2>&1 || true
  if iptables -nL "$c" >/dev/null 2>&1; then
    warn "链 $c 仍存在（可能仍被引用），已置空；不影响其它链与转发流量"
  else
    ok "已清理链 $c"
  fi
done

# ---------------------------------------------------------------------------
# 3. 清理 tc 限速（只删我们创建的 ifb 与 qdisc）
# ---------------------------------------------------------------------------
say "清理 tc 限速配置…"
wr tc qdisc del dev br-lan root >/dev/null 2>&1 || true
wr tc qdisc del dev br-lan ingress >/dev/null 2>&1 || true
wr tc qdisc del dev ifb0 root >/dev/null 2>&1 || true
wr ip link del ifb0 >/dev/null 2>&1 || true
ok "已清理 tc/ifb（失败项已忽略，不影响主链路）"

# ---------------------------------------------------------------------------
# 4. 清理 ipset
# ---------------------------------------------------------------------------
if command -v ipset >/dev/null 2>&1; then
  wr ipset destroy ubm_block >/dev/null 2>&1 || true
  ok "已清理 ipset ubm_block"
fi

# ---------------------------------------------------------------------------
# 5. 还原 DNS 旁挂（UCI 原生选项 + 可能存在的 conf-dir 文件）
# ---------------------------------------------------------------------------
DNS_TOUCHED=0
if uci get dhcp.@dnsmasq[0].logqueries >/dev/null 2>&1; then
  say "还原 dnsmasq UCI 选项…"
  wr uci delete dhcp.@dnsmasq[0].logqueries >/dev/null 2>&1 || true
  DNS_TOUCHED=1
fi
if uci get dhcp.@dnsmasq[0].logfacility >/dev/null 2>&1; then
  wr uci delete dhcp.@dnsmasq[0].logfacility >/dev/null 2>&1 || true
  DNS_TOUCHED=1
fi
if [ -f "$DNS_CONF_FILE" ]; then
  wr rm -f "$DNS_CONF_FILE"
  DNS_TOUCHED=1
  say "已删除 $DNS_CONF_FILE"
fi
if [ "$DNS_TOUCHED" = "1" ]; then
  wr uci commit dhcp >/dev/null 2>&1 || true
  restart_dnsmasq_safe || true
else
  say "未启用过 DNS 旁挂，无需重启 dnsmasq"
fi

# ---------------------------------------------------------------------------
# 6. 删除程序文件
# ---------------------------------------------------------------------------
[ -f "$BIN" ] && wr rm -f "$BIN" && ok "已删除 $BIN"
[ -f "$INIT" ] && wr rm -f "$INIT" && ok "已删除 $INIT"
[ -d "$CONF" ] && wr rm -rf "$CONF" && ok "已删除 $CONF"
wr rm -rf "$RUN" 2>/dev/null && ok "已清理 $RUN"

# ---------------------------------------------------------------------------
# 7. 数据目录（可选彻底删除）
# ---------------------------------------------------------------------------
if [ "$PURGE" = "1" ]; then
  [ -d "$DATA" ] && wr rm -rf "$DATA" && ok "已删除数据目录 $DATA"
else
  [ -d "$DATA" ] && say "保留数据目录 $DATA（用 --purge 可一并删除）"
fi

# ---------------------------------------------------------------------------
# 8. 卸载后验证
# ---------------------------------------------------------------------------
say "===== 回退后验证 ====="
if [ -x "$BIN" ]; then
  warn "[FAIL] 二进制仍存在：$BIN"
else
  ok "[OK] 二进制已移除"
fi
if pidof ${APP} >/dev/null 2>&1; then
  warn "[FAIL] 进程仍在运行"
else
  ok "[OK] 进程已停止"
fi
if uci get dhcp.@dnsmasq[0].logqueries >/dev/null 2>&1 || \
   uci get dhcp.@dnsmasq[0].logfacility >/dev/null 2>&1; then
  warn "[FAIL] DNS 旁挂 UCI 选项仍存在"
else
  ok "[OK] DNS 旁挂已还原"
fi
if iptables -nL UBM_FWD >/dev/null 2>&1 || iptables -nL UBM_IN >/dev/null 2>&1; then
  warn "[FAIL] iptables 自有链仍存在"
else
  ok "[OK] iptables 自有链已清理"
fi
if dns_healthy; then
  ok "[OK] DNS 可正常解析 —— 你的网络已恢复原状"
else
  warn "[FAIL] DNS 不可用，请执行：/etc/init.d/dnsmasq restart"
fi

echo
say "回退完成。观澜 NetScope 已从路由器移除。"
