#!/bin/sh
# 观澜 NetScope · 路由器端资源采样（可复用）
#
# 用法（在路由器上执行）：
#   sh rusage.sh [guanlan]
#
# 输出键值行：
#   PID=..
#   RSS_MB=..
#   VM_SIZE_MB=..
#   CPU_PCT_IDLE=..
#   CPU_CORES=..
#   UPTIME_SEC=..
#
# CPU_PCT_IDLE 采样方式：空闲区间内两次读取 /proc/<pid>/stat 的 utime+stime，
# 按 /proc/stat 的实际 CPU 频数换算整机占用率（%），而非单核百分比。
# 退出码：0 成功；2 未找到进程。

APP_NAME="${1:-guanlan}"
PID=""
for p in $(pidof "$APP_NAME" 2>/dev/null) $(pgrep -f "/usr/sbin/$APP_NAME" 2>/dev/null); do
  if [ -r "/proc/$p/stat" ]; then PID="$p"; break; fi
done
if [ -z "$PID" ]; then
  echo "PID=" >&2
  echo "ERROR=process_not_found:$APP_NAME" >&2
  exit 2
fi

STAT="/proc/$PID/stat"
if [ ! -r "$STAT" ]; then
  echo "ERROR=stat_not_readable:$STAT" >&2
  exit 2
fi

# --- 内存 ---
RSS_KB=$(awk '/^VmRSS:/ {print $2}' "/proc/$PID/status" 2>/dev/null)
VSZ_KB=$(awk '/^VmSize:/ {print $2}' "/proc/$PID/status" 2>/dev/null)
[ -z "$RSS_KB" ] && RSS_KB=0
[ -z "$VSZ_KB" ] && VSZ_KB=0

# --- CPU 采样 ---
CLK=$(getconf CLK_TCK 2>/dev/null || echo 100)
SAMPLE_SEC="${RUSAGE_SAMPLE_SEC:-10}"

read_utime_stime() {
  # /proc/<pid>/stat 第 14/15 字段为 utime/stime；但 comm 字段可能含空格，用 ) 截断
  awk '{ n=split($0, a, ") "); f=a[n]; split(f, b, " "); print b[12], b[13] }' "$STAT"
}

T0=$(read_utime_stime)
sleep "$SAMPLE_SEC"
T1=$(read_utime_stime)

U0=$(echo "$T0" | awk '{print $1+0}')
S0=$(echo "$T0" | awk '{print $2+0}')
U1=$(echo "$T1" | awk '{print $1+0}')
S1=$(echo "$T1" | awk '{print $2+0}')
DELTA_TICKS=$(( (U1 - U0) + (S1 - S0) ))

CPU_CORES=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)
[ -z "$CPU_CORES" ] || [ "$CPU_CORES" -lt 1 ] && CPU_CORES=1

# 整机占用率：ticks / (CLK * sample_sec * cores) * 100
CPU_PCT=$(awk -v d="$DELTA_TICKS" -v c="$CLK" -v s="$SAMPLE_SEC" -v n="$CPU_CORES" \
  'BEGIN { if (c*s*n<=0) { print "0.00" } else { printf "%.2f", (d/(c*s*n))*100 } }')

# 单核等效占用率（参考值）
CPU_PCT_CORE=$(awk -v d="$DELTA_TICKS" -v c="$CLK" -v s="$SAMPLE_SEC" \
  'BEGIN { if (c*s<=0) { print "0.00" } else { printf "%.2f", (d/(c*s))*100 } }')

UPTIME_SEC=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
THREADS=$(awk '/^Threads:/ {print $2}' "/proc/$PID/status" 2>/dev/null || echo 0)

echo "PID=$PID"
echo "RSS_MB=$(awk -v k="$RSS_KB" 'BEGIN{printf "%.2f", k/1024}')"
echo "VM_SIZE_MB=$(awk -v k="$VSZ_KB" 'BEGIN{printf "%.2f", k/1024}')"
echo "RSS_KB=$RSS_KB"
echo "CPU_PCT_IDLE=$CPU_PCT"
echo "CPU_PCT_CORE=$CPU_PCT_CORE"
echo "CPU_CORES=$CPU_CORES"
echo "SAMPLE_SEC=$SAMPLE_SEC"
echo "THREADS=$THREADS"
echo "UPTIME_SEC=$UPTIME_SEC"
exit 0
