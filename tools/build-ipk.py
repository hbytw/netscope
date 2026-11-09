#!/usr/bin/env python3
"""构建 OpenWrt .ipk 安装包（纯 Python，无需 Linux ar 工具）。

支持两个目标架构（其余架构明确拒绝，不做"打错标签"的包）：
    aarch64_generic  ← ELF machine 183（arm64 / armv8）
    x86_64           ← ELF machine 62 （x86-64 / amd64，x86 软路由）

用法：
    python tools/build-ipk.py                          # 默认 dist/guanlan，架构按 ELF 头自动推断
    python tools/build-ipk.py --bin dist/guanlan-amd64 # 指定二进制（架构仍自动推断）
    python tools/build-ipk.py --arch x86_64 --bin dist/guanlan-amd64
    python tools/build-ipk.py --arch aarch64_generic --bin dist/guanlan-arm64

    # 一条命令产出两架构包（内部 go 交叉编译，CGO_ENABLED=0，静态单文件）
    python tools/build-ipk.py --arch both --build

    # 已有两个二进制时（不重新编译）
    python tools/build-ipk.py --arch both \\
        --bin aarch64_generic=dist/guanlan-arm64 \\
        --bin x86_64=dist/guanlan-amd64

    # 等价的手工循环（不依赖 --build 的写法）
    foreach ($a in @{aarch64_generic='arm64'; x86_64='amd64'}.GetEnumerator()) {
        $env:GOOS='linux'; $env:GOARCH=$a.Value; $env:CGO_ENABLED='0'
        go build -trimpath -o "dist/guanlan-$($a.Key)" ./app
        python tools/build-ipk.py --arch $a.Key --bin "dist/guanlan-$($a.Key)"
    }

产物：
    <out>/guanlan_<version>_<arch>.ipk        （opkg install 用）
    <out>/guanlan_<version>_<arch>.tar.gz     （便携包：二进制 + install.sh + rollback.sh）

安装脚本里的路径/网段探测（init 与 postinst 共用同一段 POSIX sh 库）：
    * 数据目录：GUANLAN_DATA → /etc/guanlan/datadir 记录 → /mnt 下可写且有剩余空间的
      持久挂载点（排除 tmpfs/ramfs）→ /etc/guanlan（overlay 兜底）。
      记录的是「数据根目录」，与 deploy/install.sh、rollback.sh、uninstall.sh 同一套约定：
      根目录=<盘>/guanlan → 程序 -data 用 <根>/data、日志用 <根>/logs；
      兜底根目录=/etc/guanlan → -data 用 /etc/guanlan/data。
      init 启动时重新读这条记录（用其派生 -data），文件不存在/分区缺失才现场探测。
    * LAN 网段：uci network.lan（若地址确实在线）→ br-lan → 默认网关所在网段（旁路由）
      → 首个私网段；WAN/隧道/容器接口一律排除。探测失败写空字符串，
      由程序启动后按真实接口自探（不写死任何网段）
"""
import argparse
import io
import os
import shutil
import struct
import subprocess
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ===========================================================================
# 架构：OpenWrt 包架构名 ←→ ELF e_machine ←→ Go GOARCH
# ===========================================================================
ARCH_AARCH64 = "aarch64_generic"
ARCH_X86_64 = "x86_64"
ALL_ARCHES = (ARCH_AARCH64, ARCH_X86_64)

# ELF e_machine（偏移 18，2 字节）→ OpenWrt 架构名
ELF_MACHINE_TO_ARCH = {183: ARCH_AARCH64, 62: ARCH_X86_64}
ARCH_TO_ELF_MACHINE = {v: k for k, v in ELF_MACHINE_TO_ARCH.items()}

# OpenWrt 包架构名 → Go GOARCH
ARCH_TO_GOARCH = {ARCH_AARCH64: "arm64", ARCH_X86_64: "amd64"}

# 命令行/环境变量里可能出现的别名 → 标准包架构名
ARCH_ALIASES = {
    "aarch64_generic": ARCH_AARCH64,
    "aarch64": ARCH_AARCH64,
    "arm64": ARCH_AARCH64,
    "arm64_generic": ARCH_AARCH64,
    "armv8": ARCH_AARCH64,
    "aarch64_cortex-a53": ARCH_AARCH64,
    "x86_64": ARCH_X86_64,
    "x86-64": ARCH_X86_64,
    "x86_64_generic": ARCH_X86_64,
    "x64": ARCH_X86_64,
    "amd64": ARCH_X86_64,
}


def normalize_arch(value):
    """把 --arch 的取值归一化为 auto / both / aarch64_generic / x86_64。"""
    key = (value or "").strip().lower()
    if key in ("", "auto", "infer"):
        return "auto"
    if key in ("both", "all", "*"):
        return "both"
    if key in ARCH_ALIASES:
        return ARCH_ALIASES[key]
    raise SystemExit(
        "未知架构：%s\n"
        "  只支持：auto（按 ELF 头推断）/ aarch64_generic（ELF 183）/ "
        "x86_64（ELF 62）/ both" % value
    )


def read_elf_header(path):
    """读 ELF 头；返回 (machine, bits, little_endian)，非 ELF 返回 (None, None, None)。"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
    except OSError:
        return None, None, None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None, None, None
    bits = {1: 32, 2: 64}.get(head[4])
    endian = head[5]
    if endian == 2:
        machine = struct.unpack(">H", head[18:20])[0]
        little = False
    else:
        machine = struct.unpack("<H", head[18:20])[0]
        little = True
    return machine, bits, little


def arch_from_bin(path):
    """按 ELF 头推断 OpenWrt 架构名（183→aarch64_generic，62→x86_64）。"""
    machine, bits, _ = read_elf_header(path)
    if machine is None:
        raise SystemExit(
            "不是有效的 ELF 文件：%s\n"
            "  观澜二进制必须是为 Linux 交叉编译的静态 ELF（GOOS=linux CGO_ENABLED=0）。" % path
        )
    if bits != 64:
        raise SystemExit(
            "ELF 是 %s 位（%s），本项目只发布 64 位包（aarch64_generic / x86_64）。"
            % (bits, path)
        )
    arch = ELF_MACHINE_TO_ARCH.get(machine)
    if not arch:
        raise SystemExit(
            "不支持的 ELF machine=%d（%s）。\n"
            "  只支持 183（aarch64_generic）与 62（x86_64）；"
            "其它架构需要先扩展 ELF_MACHINE_TO_ARCH。" % (machine, path)
        )
    return arch


def verify_bin_arch(path, want_arch):
    """校验二进制真的是目标架构（防止 arm64 二进制被打成 x86_64 包）。"""
    got = arch_from_bin(path)
    machine, _, _ = read_elf_header(path)
    want_machine = ARCH_TO_ELF_MACHINE[want_arch]
    if got != want_arch:
        raise SystemExit(
            "架构不匹配：%s 实际是 %s（ELF machine=%d），但要求打成 %s（ELF machine=%d）。\n"
            "  做法一：--arch auto 让脚本按 ELF 头推断；\n"
            "  做法二：为该架构重新交叉编译（GOARCH=%s），再用 --bin 指定。"
            % (path, got, machine, want_arch, want_machine, ARCH_TO_GOARCH[want_arch])
        )
    return machine


# ===========================================================================
# 运行期探测库（init / postinst / postrm 共用）
#
# 全部 POSIX sh，OpenWrt busybox ash 兼容。不假设任何固定网段或存储分区：
#   * 数据目录优先级：环境变量 GUANLAN_DATA → /etc/guanlan/datadir 记录 →
#     /mnt 下「可写 + 剩余空间达标 + 非 tmpfs/ramfs」的持久挂载点
#     （优先 ≥200MB 的分区，没有大分区才用小的持久分区）→
#     /etc/guanlan（overlay 兜底：宁可空间小，也不拒绝启动）
#     记录的是「根目录」，与 deploy/install.sh / rollback.sh / uninstall.sh 同一套约定：
#     根目录=/mnt/sda1/guanlan → -data 用 <根>/data，日志用 <根>/logs；
#     兜底根目录=/etc/guanlan → -data 用 /etc/guanlan/data。
#   * LAN 网段优先级：uci network.lan（地址确实在线时）→ br-lan →
#     默认网关所在网段（旁路由场景）→ 首个私网段；WAN/隧道/容器接口一律排除。
#     探测失败输出空串，由程序运行时自行探测（绝不写死 192.168.1.0/24）
#   * 运行期临时文件固定 /tmp/guanlan（tmpfs，重启即失，不占存储）
# ===========================================================================
SH_LIB = r"""
GL_DATADIR_FILE="${GL_DATADIR_FILE:-/etc/guanlan/datadir}"
GL_DATA_FALLBACK="${GL_DATA_FALLBACK:-/etc/guanlan}"
GL_MNT_SCAN="${GL_MNT_SCAN:-/mnt/* /srv /opt /data /usr/share}"
GL_MIN_DATA_KB="${GL_MIN_DATA_KB:-20480}"          # 低于 20MB 视为不可用
GL_PREFER_DATA_KB="${GL_PREFER_DATA_KB:-204800}"    # 优先选 ≥200MB 的挂载点（同 install.sh）
GL_MOUNT_WAIT="${GL_MOUNT_WAIT:-5}"                 # 记录在 /mnt 但分区未挂上时最多等几秒

gl_warn() { echo "[guanlan][WARN] $*" >&2; }

# 挂载点剩余空间（KB）。读不到时输出空串（调用方按"未知"处理）
gl_avail_kb() {
    df -k "$1" 2>/dev/null | awk 'NR > 1 { v = $4 } END { print v }'
}

# 0 = 持久介质；1 = tmpfs/devtmpfs/ramfs/rootfs（重启即失，不能当数据目录）
gl_persistent_fs() {
    _fs="$(df -k "$1" 2>/dev/null | awk 'NR > 1 { v = $1 } END { print v }')"
    case "$_fs" in
        tmpfs|devtmpfs|ramfs|rootfs|none) return 1 ;;
    esac
    return 0
}

# 0 = 目录可用（绝对路径、可创建、可写、剩余空间 ≥ GL_MIN_DATA_KB）
gl_dir_ok() {
    [ -n "$1" ] || return 1
    case "$1" in /*) ;; *) return 1 ;; esac
    [ -d "$1" ] || mkdir -p "$1" 2>/dev/null || return 1
    [ -w "$1" ] || return 1
    _kb="$(gl_avail_kb "$1")"
    case "$_kb" in
        ''|*[!0-9]*) return 0 ;;   # 读不到空间：放行（可用优先，绝不拒绝启动）
    esac
    [ "$_kb" -ge "$GL_MIN_DATA_KB" ] 2>/dev/null && return 0
    return 1
}

# 打印 /etc/guanlan/datadir 记录的「数据根目录」（去 CR/引号/空白）；无记录返回 1
# 根目录不是 -data 本身：<根>/data 才是程序 -data，<根>/logs 是运行日志。
# 这条约定与 deploy/install.sh、rollback.sh、uninstall.sh 完全一致。
gl_recorded_data_root() {
    [ -s "$GL_DATADIR_FILE" ] || return 1
    _v="$(head -n 1 "$GL_DATADIR_FILE" 2>/dev/null | tr -d '\r')"
    _v="$(printf '%s' "$_v" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
        -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
    case "$_v" in /*) printf '%s\n' "$_v"; return 0 ;; esac
    return 1
}

# 写入数据根目录记录（供 install.sh / rollback.sh / uninstall.sh 与下次启动复用）
gl_record_data_root() {
    [ -n "$1" ] || return 1
    _d="$(dirname "$GL_DATADIR_FILE" 2>/dev/null)"
    if [ -n "$_d" ] && [ "$_d" != "." ] && [ ! -d "$_d" ]; then
        mkdir -p "$_d" 2>/dev/null || return 1
    fi
    printf '%s\n' "$1" > "$GL_DATADIR_FILE" 2>/dev/null || return 1
    chmod 0644 "$GL_DATADIR_FILE" 2>/dev/null || true
    return 0
}

# 记录路径所在的 /mnt 挂载点是否还在（避免分区没挂上时把数据写进 overlay 假目录）
gl_storage_present() {
    case "$1" in
        /mnt/*)
            _rel="${1#/mnt/}"
            _mp="/mnt/${_rel%%/*}"
            [ -d "$_mp" ] || return 1
            ;;
    esac
    return 0
}

# 打印数据「根目录」。永不失败：最差返回 GL_DATA_FALLBACK（默认 /etc/guanlan）
gl_resolve_data_root() {
    # 1) 环境变量显式指定（GUANLAN_DATA 与 deploy/install.sh 同名，取第一个可用者）
    for _v in "${GUANLAN_DATA:-}" "${GUANLAN_DATA_DIR:-}" "${GL_DATA_DIR:-}"; do
        [ -n "$_v" ] || continue
        if gl_dir_ok "$_v"; then
            printf '%s\n' "$_v"
            return 0
        fi
        gl_warn "环境变量指定的数据目录不可用，已忽略：$_v"
    done
    # 2) 安装期记录：优先复用，保证跨重启 / 跨工具数据不漂移
    if _v="$(gl_recorded_data_root)"; then
        if gl_storage_present "$_v" && gl_dir_ok "$_v"; then
            printf '%s\n' "$_v"
            return 0
        fi
        gl_warn "记录的数据目录不可用（$GL_DATADIR_FILE → $_v），改为重新探测"
    fi
    # 3) /mnt 等持久挂载点：可写 + 非 tmpfs + 空间达标，优先 ≥200MB 的分区
    #    （与 deploy/install.sh 的偏好一致），没有大分区时退而用小的持久分区。
    _tried=" "
    _round=0
    while [ "$_round" -lt 8 ]; do
        _round=$((_round + 1))
        _best=""
        _bestkb=0
        _alt=""
        _altkb=0
        for _m in $GL_MNT_SCAN; do
            [ -d "$_m" ] || continue
            [ -w "$_m" ] || continue
            case "$_tried" in *" $_m "*) continue ;; esac
            gl_persistent_fs "$_m" || continue
            _kb="$(gl_avail_kb "$_m")"
            case "$_kb" in ''|*[!0-9]*) _kb=0 ;; esac
            [ "$_kb" -ge "$GL_MIN_DATA_KB" ] 2>/dev/null || continue
            if [ "$_kb" -ge "$GL_PREFER_DATA_KB" ] 2>/dev/null && [ "$_kb" -gt "$_bestkb" ]; then
                _best="$_m"
                _bestkb="$_kb"
            fi
            if [ "$_kb" -gt "$_altkb" ]; then
                _alt="$_m"
                _altkb="$_kb"
            fi
        done
        _pick="${_best:-$_alt}"
        [ -n "$_pick" ] || break
        _tried="$_tried$_pick "
        if gl_dir_ok "$_pick/guanlan/data"; then
            printf '%s\n' "$_pick/guanlan"
            return 0
        fi
        gl_warn "挂载点 $_pick 下无法创建数据目录，尝试下一个"
    done
    # 4) overlay 兜底：空间可能很小，但保证服务能启动
    printf '%s\n' "$GL_DATA_FALLBACK"
}

# 根目录 → 程序 -data 参数（<根>/data，与 install.sh 的 DATA_PATH 完全一致）
gl_data_dir() {
    [ -n "$1" ] || return 1
    printf '%s\n' "$1/data"
}

# 根目录 → 运行日志目录（<根>/logs；建不出来就退回 <根>/data/logs）
gl_log_dir() {
    _root="$1"
    [ -n "$_root" ] || return 1
    [ -d "$_root/logs" ] || mkdir -p "$_root/logs" 2>/dev/null
    if [ -d "$_root/logs" ] && [ -w "$_root/logs" ]; then
        printf '%s\n' "$_root/logs"
        return 0
    fi
    printf '%s\n' "$_root/data/logs"
}

# 把 "地址/前缀" 归零成网段（192.168.8.4/24 → 192.168.8.0/24；/32 保持原地址）
gl_mask_cidr() {
    awk -F/ 'NF >= 1 {
        split($1, o, ".")
        if (o[1] == "" || o[2] == "" || o[3] == "" || o[4] == "") next
        bits = ($2 == "") ? 24 : $2 + 0
        if (bits < 0 || bits > 32) bits = 24
        block = 1
        for (i = 0; i < 32 - bits; i++) block = block * 2
        addr = o[1] * 16777216 + o[2] * 65536 + o[3] * 256 + o[4]
        net = int(addr / block) * block
        printf "%d.%d.%d.%d/%d\n", int(net / 16777216) % 256, int(net / 65536) % 256, int(net / 256) % 256, net % 256, bits
    }'
}

# 点分掩码 → 前缀位数（255.255.255.0 → 24）；非法值输出空串
gl_mask_to_bits() {
    awk -F. 'NF == 4 {
        n = 0
        for (i = 1; i <= 4; i++) {
            v = $i + 0
            if (v < 0 || v > 255) { print ""; exit }
            while (v > 0) { n += v % 2; v = int(v / 2) }
        }
        print n
    }'
}

# 打印 uci 里显式配置的 LAN 网段（OpenWrt 的 network.lan 是最权威的来源）。
# 没有 uci / 没有静态地址（LAN 走 DHCP 客户端的旁路由）时返回 1。
gl_uci_lan_cidr() {
    command -v uci >/dev/null 2>&1 || return 1
    for _key in network.lan.ipaddr network.lan.ipaddrs; do
        _ip="$(uci -q get "$_key" 2>/dev/null)" || continue
        [ -n "$_ip" ] || continue
        set -- $_ip
        _ip="$1"
        case "$_ip" in
            ''|*[!0-9.]*) continue ;;
        esac
        _mask="$(uci -q get network.lan.netmask 2>/dev/null)"
        case "$_mask" in
            ''|*[!0-9]*) _bits="$(printf '%s' "$_mask" | gl_mask_to_bits)" ;;
            *) _bits="$_mask" ;;
        esac
        case "$_bits" in ''|*[!0-9]*) _bits=24 ;; esac
        _cidr="$(printf '%s/%s\n' "$_ip" "$_bits" | gl_mask_cidr)"
        [ -n "$_cidr" ] || continue
        printf '%s\n' "$_cidr"
        return 0
    done
    return 1
}

# 打印 LAN 网段（已按前缀归零，如 192.168.8.4/24 → 192.168.8.0/24）
# 顺序：uci network.lan（且地址确实在在线接口上）→ 接口打分 → 失败返回 1 不输出
gl_detect_lan_cidr() {
    if _c="$(gl_uci_lan_cidr)"; then
        _a="${_c%/*}"
        if ip -4 -o addr show 2>/dev/null | grep -q "inet ${_a}/"; then
            printf '%s\n' "$_c"
            return 0
        fi
        gl_warn "uci 的 network.lan 地址 $_a 不在任何在线接口上，改用接口探测"
    fi

    _addr="$(ip -4 -o addr show 2>/dev/null)"
    [ -n "$_addr" ] || return 1
    _gw="$(ip route show default 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++) if ($i == "via") { print $(i + 1); exit }
    }')"
    _best="$(
        printf '%s\n' "$_addr" | awk -v gw="$_gw" '
        {
            iface = $2
            sub(/@.*/, "", iface)
            cidr = ""
            for (i = 1; i <= NF; i++) if ($i == "inet") cidr = $(i + 1)
            if (cidr == "" || iface == "" || iface == "lo") next
            # WAN / 隧道 / 容器接口不是内网段：直接排除（避免公网或 CGNAT 段被当 LAN）
            if (iface ~ /^(wan|wwan|pppoe|ppp|usb|tun|tap|wg|zt|tailscale|vpn|docker|ifb|veth|virbr|sit|gre|ip6tnl|dummy)/) next
            if (iface ~ /^br-[0-9a-f]+$/) next   # docker 的 br-<hash> 不是 LAN 桥
            n = split(cidr, p, "/")
            bits = (n < 2 || p[2] == "") ? 24 : p[2] + 0
            if (bits < 0 || bits > 32) bits = 24
            split(p[1], o, ".")
            if (o[1] == "" || o[2] == "" || o[3] == "" || o[4] == "") next
            if (o[1] == 0 || (o[1] == 169 && o[2] == 254)) next   # 无效源/链路本地
            block = 1
            for (i = 0; i < 32 - bits; i++) block = block * 2
            addr = o[1] * 16777216 + o[2] * 65536 + o[3] * 256 + o[4]
            net = int(addr / block) * block
            score = 0
            if (iface == "br-lan") score += 1000
            else if (iface ~ /^br-lan\./) score += 900
            else if (iface ~ /^br-/) score += 300
            # 私网段是强证据：WAN 通常不是 RFC1918，避免"名字不叫 wan 的口"抢走 LAN
            if (o[1] == 10 || (o[1] == 172 && o[2] >= 16 && o[2] <= 31) || (o[1] == 192 && o[2] == 168)) score += 400
            if (iface ~ /^eth[0-9]+$/) score += 50
            # 默认网关落在本网段：旁路由场景（LAN 承载默认路由）的佐证
            if (gw != "") {
                split(gw, g, ".")
                if (g[4] != "") {
                    gaddr = g[1] * 16777216 + g[2] * 65536 + g[3] * 256 + g[4]
                    if (int(gaddr / block) == int(addr / block)) score += 200
                }
            }
            if (score < 0) next
            printf "%d\t%s\t%d.%d.%d.%d/%d\n", score, iface, int(net / 16777216) % 256, int(net / 65536) % 256, int(net / 256) % 256, net % 256, bits
        }' | sort -rn | head -n 1 | cut -f3
    )"
    [ -n "$_best" ] || return 1
    printf '%s\n' "$_best"
}
"""

INIT_SCRIPT = "#!/bin/sh /etc/rc.common\n" + SH_LIB + r"""
# 观澜 NetScope 服务（procd）
USE_PROCD=1
START=99
STOP=10
PROG="guanlan"

APP_BIN="/usr/sbin/guanlan"
# 运行期临时目录固定 tmpfs，重启即失，不占存储
APP_RUNDIR="/tmp/guanlan"
DNS_LOG_DIR="/var/run/dnsmasq"

start_service() {
    # 数据根目录每次启动现场解析（procd 拉起时环境是干净的）：
    #   /etc/guanlan/datadir 记录（安装期写入，rollback 也读它）→ 探测 → /etc/guanlan
    # 记录文件不存在（或分区没挂上）时现场探测，并把结果回写记录。
    #
    # 记录在 /mnt 但分区此刻还没挂上（USB 卡/SSD 枚举慢）时先等几秒：
    # 否则启动早一拍就会把数据永久改写到 overlay，导致数据"分裂"。
    _rec="$(gl_recorded_data_root 2>/dev/null)"
    if [ -n "$_rec" ]; then
        case "$_rec" in
            /mnt/*)
                _wait=0
                while [ "$_wait" -lt "$GL_MOUNT_WAIT" ] && ! gl_storage_present "$_rec"; do
                    [ "$_wait" -eq 0 ] \
                        && gl_warn "记录的数据分区还没挂上，最多等 ${GL_MOUNT_WAIT}s：$_rec"
                    sleep 1
                    _wait=$((_wait + 1))
                done
                ;;
        esac
    fi
    APP_DATA_ROOT="$(gl_resolve_data_root)"
    APP_DATA="$(gl_data_dir "$APP_DATA_ROOT")"
    APP_LOG_DIR="$(gl_log_dir "$APP_DATA_ROOT")"
    APP_LOG_FILE="$APP_LOG_DIR/guanlan.log"
    gl_record_data_root "$APP_DATA_ROOT" 2>/dev/null \
        || gl_warn "数据目录记录写入失败：$GL_DATADIR_FILE（不影响启动）"

    # 监听地址：默认全接口 8088，可用环境变量覆盖（不假设某个固定网段）
    APP_ADDR="${GUANLAN_ADDR:-}"
    if [ -z "$APP_ADDR" ]; then
        APP_PORT="${GUANLAN_PORT:-8088}"
        case "$APP_PORT" in ''|*[!0-9]*) APP_PORT=8088 ;; esac
        APP_ADDR="0.0.0.0:${APP_PORT}"
    fi

    # /tmp 是 tmpfs，重启即失，每次启动都要确保目录存在
    mkdir -p "$APP_RUNDIR" "$DNS_LOG_DIR" "$APP_DATA_ROOT" "$APP_DATA" "$APP_LOG_DIR" 2>/dev/null || true
    # dnsmasq 以 dnsmasq 用户运行，必须能写入 DNS 日志目录
    chown dnsmasq:dnsmasq "$DNS_LOG_DIR" 2>/dev/null || chmod 0777 "$DNS_LOG_DIR" 2>/dev/null || true

    # 日志限量：超过 4MB 只保留最后 2000 行，避免长期运行撑爆存储分区
    if [ -f "$APP_LOG_FILE" ]; then
        LOGSZ=$(wc -c < "$APP_LOG_FILE" 2>/dev/null || echo 0)
        if [ "$LOGSZ" -gt 4194304 ] 2>/dev/null; then
            tail -n 2000 "$APP_LOG_FILE" > "$APP_LOG_FILE.tmp" 2>/dev/null \
                && mv -f "$APP_LOG_FILE.tmp" "$APP_LOG_FILE"
        fi
    fi

    procd_open_instance
    procd_set_param command "$APP_BIN" -addr "$APP_ADDR" -data "$APP_DATA"
    procd_set_param pidfile "/var/run/guanlan.pid"
    # 崩溃自动重启：3600 秒窗口内最多重启 5 次，间隔 5 秒
    procd_set_param respawn 3600 5 5
    procd_set_param limits nofile="4096 4096"
    procd_set_param stdout "$APP_LOG_FILE"
    procd_set_param stderr "$APP_LOG_FILE"
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger "/etc/guanlan/config.json"
}
"""

POSTINST = "#!/bin/sh\n" + SH_LIB + r"""
# 安装后：探测数据目录与 LAN 网段 → 生成默认配置 → 启用并启动服务
CONF="/etc/guanlan/config.json"
PORT="${GUANLAN_PORT:-8088}"
case "$PORT" in ''|*[!0-9]*) PORT=8088 ;; esac
LISTEN="0.0.0.0:${PORT}"

# --- 数据目录：现场探测（优先级与 deploy/install.sh 一致），并写入记录供 rollback 使用 ---
# 记录的是「根目录」：<根>/data 给程序 -data，<根>/logs 放运行日志
DATA_ROOT="$(gl_resolve_data_root)"
DATA="$(gl_data_dir "$DATA_ROOT")"
LOG="$(gl_log_dir "$DATA_ROOT")"
if gl_record_data_root "$DATA_ROOT"; then
    echo "[guanlan] 数据目录：$DATA（根目录记录到 $GL_DATADIR_FILE）"
else
    gl_warn "写入 $GL_DATADIR_FILE 失败：下次启动会重新探测"
fi

mkdir -p /etc/guanlan "$DATA_ROOT" "$DATA" "$LOG" /tmp/guanlan 2>/dev/null || true
chown dnsmasq:dnsmasq /tmp/guanlan 2>/dev/null || chmod 0777 /tmp/guanlan 2>/dev/null || true

# --- 本机 LAN 网段（192.168.8.4/24 → 192.168.8.0/24） ---
# 单网口 eth0 / x86 软路由 / 旁路由都能探测；探测失败留空字符串，
# 由程序启动后按真实接口自探 —— 绝不写死某个网段。
LAN_CIDR="$(gl_detect_lan_cidr 2>/dev/null)"
if [ -z "$LAN_CIDR" ]; then
    gl_warn "LAN 网段探测失败（无 ip 命令或接口无 IPv4），lanCidr 留空由程序自探"
fi

# --- 访问地址提示用的本机 LAN IP（探测不到就用占位符，不影响功能） ---
LAN_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{
    for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }
}')"
[ -n "$LAN_IP" ] || LAN_IP="<路由器IP>"

if [ ! -f "$CONF" ]; then
    SALT="guanlan-$(date '+%Y%m%d%H%M%S')"
    HASH=$(printf '%s' "${SALT}guanlan2026" | sha256sum | cut -d' ' -f1)
    cat > "$CONF" <<EOF
{
  "salt": "$SALT",
  "passwordHash": "$HASH",
  "listen": "$LISTEN",
  "dataDir": "$DATA",
  "logDir": "$LOG",
  "port": $PORT,
  "lanCidr": "$LAN_CIDR",
  "createdAt": "$(date '+%Y-%m-%dT%H:%M:%S%z')"
}
EOF
    chmod 0600 "$CONF" 2>/dev/null || true
    echo "[guanlan] 已生成默认配置：$CONF（默认密码 guanlan2026，请登录后立即修改）"
else
    echo "[guanlan] 检测到已有配置：$CONF（保留，不覆盖用户改过的密码）"
    # 配置里的 dataDir 只是展示用：真正生效的是 init 传的 -data（来自 datadir 记录）
    grep -q "\"dataDir\": \"$DATA\"" "$CONF" 2>/dev/null \
        || gl_warn "配置里的 dataDir 与当前数据目录不同（实际生效：$DATA，由 init 的 -data 决定）"
fi

/etc/init.d/guanlan enable 2>/dev/null || true
/etc/init.d/guanlan start 2>/dev/null || true
echo "[guanlan] 安装完成：http://${LAN_IP}:${PORT}  （默认账号 admin / guanlan2026）"
echo "[guanlan] 数据目录：$DATA"
echo "[guanlan] 运行日志：$LOG/guanlan.log"
exit 0
"""

PRERM = """#!/bin/sh
# 卸载前：停止服务（保留配置与数据，便于重装/回退）
/etc/init.d/guanlan stop 2>/dev/null || true
/etc/init.d/guanlan disable 2>/dev/null || true
exit 0
"""

POSTRM = "#!/bin/sh\n" + SH_LIB + r"""
# 卸载后：清理运行时文件；保留 /etc/guanlan（配置 + 数据目录记录）与数据根目录
rm -f /var/run/guanlan.pid 2>/dev/null || true
rm -rf /tmp/guanlan 2>/dev/null || true
DATA_ROOT="$(gl_recorded_data_root 2>/dev/null)"
[ -n "$DATA_ROOT" ] || DATA_ROOT="$GL_DATA_FALLBACK"
echo "[guanlan] 已卸载；配置保留在 /etc/guanlan（数据根目录记录：$GL_DATADIR_FILE）"
echo "[guanlan] 数据保留在 $DATA_ROOT（-data 用 $DATA_ROOT/data；彻底清理：sh rollback.sh --purge）"
exit 0
"""


def build_mtime():
    """包内 mtime：支持 SOURCE_DATE_EPOCH（可复现构建），否则取当前时间。"""
    v = (os.environ.get("SOURCE_DATE_EPOCH") or "").strip()
    if v.isdigit():
        return int(v)
    return int(time.time())


def make_tar_gz(entries, out_path, mtime=None):
    """entries: list of (name, data(bytes), mode)。使用 ustar 格式，兼容 opkg 解析。"""
    mtime = mtime or build_mtime()
    with tarfile.open(out_path, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = mtime
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            tf.addfile(info, io.BytesIO(data))
    return out_path


def ar_member(name, data, mtime=None):
    """构造 ar 成员（System V 格式，OpenWrt opkg/libarchive 兼容）"""
    mtime = mtime or build_mtime()
    hdr = struct.pack(
        "16s12s6s6s8s10s2s",
        (name + "/").encode()[:16].ljust(16, b" "),
        str(int(mtime)).encode().ljust(12, b" "),
        b"0".ljust(6, b" "),
        b"0".ljust(6, b" "),
        b"100644".ljust(8, b" "),
        str(len(data)).encode().ljust(10, b" "),
        b"`\n",
    )
    body = data if len(data) % 2 == 0 else data + b"\n"
    return hdr + body


def write_ar(path, members, mtime=None):
    """纯 Python 写 ar 归档；系统 tar 不可用/不支持 --format=ar 时的兜底。"""
    mtime = mtime or build_mtime()
    with open(path, "wb") as fh:
        fh.write(b"!<arch>\n")
        for name, data in members:
            fh.write(ar_member(name, data, mtime))
    return path


def read_ar_members(path):
    """解析 ar 归档 → [(name, offset, size)]（用于产物自检）。"""
    out = []
    with open(path, "rb") as fh:
        if fh.read(8) != b"!<arch>\n":
            raise SystemExit("%s 不是 ar 归档（缺少 !<arch> 魔数）" % path)
        while True:
            hdr = fh.read(60)
            if len(hdr) < 60:
                break
            name = hdr[:16].decode("utf-8", "replace").strip().rstrip("/")
            raw_size = hdr[48:58].decode("utf-8", "replace").strip()
            if not raw_size.isdigit():
                break
            size = int(raw_size)
            out.append((name, fh.tell(), size))
            fh.seek(size + (size % 2), os.SEEK_CUR)
    return out


def _member_data(path, offset, size):
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read(size)


def _tar_member_names(tgz_bytes):
    names = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
            for info in tf.getmembers():
                names.add(info.name.lstrip("./").lstrip("/"))
    except (tarfile.TarError, OSError) as exc:
        raise SystemExit("包内 tar.gz 损坏：%s" % exc)
    return names


def verify_ipk(ipk_path, version, arch):
    """产物自检：ar 成员齐全、control 的 Architecture/Version 正确、脚本与二进制都在。"""
    members = read_ar_members(ipk_path)
    names = [m[0] for m in members]
    for need in ("debian-binary", "control.tar.gz", "data.tar.gz"):
        if need not in names:
            raise SystemExit("%s 缺少成员 %s（实际：%s）" % (ipk_path, need, ", ".join(names)))

    by_name = {m[0]: (m[1], m[2]) for m in members}
    ctrl_bytes = _member_data(ipk_path, *by_name["control.tar.gz"])
    data_bytes = _member_data(ipk_path, *by_name["data.tar.gz"])

    ctrl_names = _tar_member_names(ctrl_bytes)
    for need in ("control", "postinst", "prerm", "postrm"):
        if need not in ctrl_names:
            raise SystemExit("%s 的 control.tar.gz 缺少 %s（实际：%s）" % (ipk_path, need, ", ".join(sorted(ctrl_names))))
    data_names = _tar_member_names(data_bytes)
    for need in ("usr/sbin/guanlan", "etc/init.d/guanlan"):
        if need not in data_names:
            raise SystemExit("%s 的 data.tar.gz 缺少 %s（实际：%s）" % (ipk_path, need, ", ".join(sorted(data_names))))

    with tarfile.open(fileobj=io.BytesIO(ctrl_bytes), mode="r:gz") as tf:
        control = tf.extractfile("./control").read().decode("utf-8", "replace")
    for line in control.splitlines():
        if line.startswith("Architecture:"):
            got = line.split(":", 1)[1].strip()
            if got != arch:
                raise SystemExit("%s 的 control Architecture=%s，期望 %s" % (ipk_path, got, arch))
            break
    else:
        raise SystemExit("%s 的 control 缺少 Architecture 字段" % ipk_path)
    if ("Version: %s" % version) not in control:
        raise SystemExit("%s 的 control 中 Version 不是 %s" % (ipk_path, version))
    return True


def build_ipk(bin_path, version, arch, out_dir):
    """打一个架构的 ipk + 便携 tar.gz。返回 (ipk_path, tgz_path)。"""
    if arch not in ARCH_TO_ELF_MACHINE:
        raise SystemExit("内部错误：未知目标架构 %s" % arch)
    machine = verify_bin_arch(bin_path, arch)

    os.makedirs(out_dir, exist_ok=True)
    tmp = os.path.join(out_dir, ".ipk-tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)

    with open(bin_path, "rb") as fh:
        bin_data = fh.read()
    if not bin_data:
        raise SystemExit("二进制是空文件：%s" % bin_path)
    size_kb = max(1, (len(bin_data) + 1023) // 1024)
    mtime = build_mtime()

    control = (
        "Package: guanlan\n"
        "Version: %s\n"
        "Depends: \n"
        "Source: https://github.com/hbytw/netscope\n"
        "SourceName: guanlan\n"
        "Section: net\n"
        "Priority: optional\n"
        "Architecture: %s\n"
        "Installed-Size: %d\n"
        "Maintainer: hbytw <hbytw@vip.qq.com>\n"
        "Description: 观澜 NetScope - OpenWrt 用户上网行为态势感知\n"
        " 上网行为管理 + 3D 态势大屏 + 流量分析 + 安全告警。\n"
        " 默认两级开关全关，不采集不管控，不影响路由器现有功能。\n"
    ) % (version, arch, size_kb)

    control_tgz = os.path.join(tmp, "control.tar.gz")
    make_tar_gz([
        ("./control", control.encode(), 0o644),
        ("./postinst", POSTINST.encode(), 0o755),
        ("./prerm", PRERM.encode(), 0o755),
        ("./postrm", POSTRM.encode(), 0o755),
    ], control_tgz, mtime)

    data_tgz = os.path.join(tmp, "data.tar.gz")
    make_tar_gz([
        ("./usr/sbin/guanlan", bin_data, 0o755),
        ("./etc/init.d/guanlan", INIT_SCRIPT.encode(), 0o755),
    ], data_tgz, mtime)

    with open(os.path.join(tmp, "debian-binary"), "wb") as fh:
        fh.write(b"2.0\n")

    ipk_name = "guanlan_%s_%s.ipk" % (version, arch)
    ipk_path = os.path.join(out_dir, ipk_name)
    if os.path.exists(ipk_path):
        os.remove(ipk_path)

    # 首选 bsdtar（libarchive）：与 opkg 的 libarchive 解析同源，格式必然兼容。
    # 无 tar / 不支持 --format=ar 时，退回纯 Python ar 写入（同样的 System V 布局）。
    # 注意：tar 以 tmp 为工作目录，产物路径必须转成绝对路径，否则 --out 用相对路径时打不开。
    ipk_abs = os.path.abspath(ipk_path)
    tar_ok = False
    try:
        proc = subprocess.run(
            ["tar", "--format=ar", "-cf", ipk_abs,
             "debian-binary", "control.tar.gz", "data.tar.gz"],
            cwd=tmp, capture_output=True, text=True,
        )
        tar_ok = proc.returncode == 0 and os.path.exists(ipk_path)
        if not tar_ok:
            print("[warn] tar --format=ar 不可用（%s），改用脚本自带的 ar 写入"
                  % (proc.stderr or proc.stdout).strip()[:200])
    except OSError:
        print("[warn] 未找到 tar 命令，改用纯 Python 写 ar 归档")
    if not tar_ok:
        if os.path.exists(ipk_path):
            os.remove(ipk_path)
        with open(control_tgz, "rb") as f:
            ctrl_data = f.read()
        with open(data_tgz, "rb") as f:
            data_data = f.read()
        write_ar(ipk_path, [
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", ctrl_data),
            ("data.tar.gz", data_data),
        ], mtime)

    verify_ipk(ipk_path, version, arch)

    # 便携 tar.gz（不依赖 opkg：解压后手动执行 install.sh）
    tgz_name = "guanlan_%s_%s.tar.gz" % (version, arch)
    tgz_path = os.path.join(out_dir, tgz_name)
    install_sh = os.path.join(ROOT, "deploy", "install.sh")
    rollback_sh = os.path.join(ROOT, "deploy", "rollback.sh")
    entries = [("./guanlan", bin_data, 0o755)]
    if os.path.exists(install_sh):
        with open(install_sh, "rb") as f:
            entries.append(("./install.sh", f.read(), 0o755))
    if os.path.exists(rollback_sh):
        with open(rollback_sh, "rb") as f:
            entries.append(("./rollback.sh", f.read(), 0o755))
    make_tar_gz(entries, tgz_path, mtime)

    print("[ok] %s → %s（ELF machine=%d）" % (arch, os.path.basename(ipk_path), machine))
    return ipk_path, tgz_path


# ===========================================================================
# 二进制定位：显式 --bin / 文件名约定 / 扫描 ELF 头
# ===========================================================================
def parse_bin_args(values):
    """--bin 支持 'PATH' 与 'ARCH=PATH'。返回 (explicit_pairs, plain_paths)。"""
    pairs, plain = [], []
    for raw in values:
        v = (raw or "").strip()
        if not v:
            continue
        left, sep, right = v.partition("=")
        key = left.strip().lower()
        if sep and right.strip() and key in ("auto", "both", "all", "infer"):
            raise SystemExit("--bin 不支持 arch=auto/both：%s（请用 --arch 指定）" % v)
        if sep and right.strip() and key in ARCH_ALIASES:
            pairs.append((ARCH_ALIASES[key], right.strip()))
        else:
            plain.append(v)
    return pairs, plain


def arch_name_hints(arch):
    """文件名里可能出现该架构的写法（用于自动发现第二个二进制）。"""
    return {
        ARCH_AARCH64: ("aarch64_generic", "aarch64", "arm64", "armv8"),
        ARCH_X86_64: ("x86_64", "x86-64", "amd64", "x64"),
    }[arch]


def search_dirs(paths, out_dir):
    dirs = []
    for p in list(paths) + [out_dir, os.path.join(ROOT, "dist")]:
        d = os.path.abspath(os.path.dirname(p) or ".")
        if d not in dirs:
            dirs.append(d)
    return dirs


def discover_bin(arch, dirs):
    """在若干目录里找一个真正是目标架构的二进制（先按命名约定，再按 ELF 头扫描）。"""
    candidates = []
    for d in dirs:
        for hint in arch_name_hints(arch):
            for pattern in ("guanlan-%s", "guanlan_%s", "guanlan.%s"):
                candidates.append(os.path.join(d, pattern % hint))
        candidates.append(os.path.join(d, "guanlan"))
    for path in candidates:
        if os.path.isfile(path):
            machine, bits, _ = read_elf_header(path)
            if machine == ARCH_TO_ELF_MACHINE[arch] and bits == 64:
                return path
    for d in dirs:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            if name.endswith((".ipk", ".gz", ".json", ".log", ".md", ".sha256")):
                continue
            path = os.path.join(d, name)
            if not os.path.isfile(path):
                continue
            machine, bits, _ = read_elf_header(path)
            if machine == ARCH_TO_ELF_MACHINE[arch] and bits == 64:
                return path
    return None


def missing_bin_msg(arch, dirs):
    goarch = ARCH_TO_GOARCH[arch]
    return (
        "找不到 %s 架构的二进制（已搜索：%s）。\n"
        "  先交叉编译它（app/ 目录下，CGO_ENABLED=0 静态单文件）：\n"
        "    set GOOS=linux & set GOARCH=%s & set CGO_ENABLED=0 & go build -trimpath -o dist\\guanlan-%s .\n"
        "  再打包：python tools/build-ipk.py --arch both --bin %s=dist/guanlan-%s\n"
        "  或者一条命令搞定（本脚本自己调用 go build）：\n"
        "    python tools/build-ipk.py --arch both --build"
        % (arch, ", ".join(dirs), goarch, arch, arch, arch)
    )


def resolve_bins(mode, pairs, plain, out_dir):
    """确定要打包的 (arch, path) 列表，逐个校验 ELF 架构。"""
    bins = {}
    for arch, path in pairs:
        if not os.path.isfile(path):
            raise SystemExit("--bin 指定的二进制不存在：%s" % path)
        verify_bin_arch(path, arch)
        bins.setdefault(arch, path)
    for path in plain:
        if not os.path.isfile(path):
            raise SystemExit("二进制不存在：%s（先构建，或用 --bin 指定）" % path)
        arch = arch_from_bin(path)
        prev = bins.get(arch)
        if prev and os.path.abspath(prev) != os.path.abspath(path):
            raise SystemExit("--bin 给了两个都是 %s 的二进制：%s 与 %s" % (arch, prev, path))
        bins.setdefault(arch, path)

    dirs = search_dirs(plain, out_dir)

    if mode == "auto":
        if not bins:
            raise SystemExit(missing_bin_msg(ARCH_AARCH64, dirs))
        return sorted(bins.items())

    if mode == "both":
        for arch in ALL_ARCHES:
            if arch in bins:
                continue
            found = discover_bin(arch, dirs)
            if not found:
                raise SystemExit(missing_bin_msg(arch, dirs))
            bins[arch] = found
        return [(arch, bins[arch]) for arch in ALL_ARCHES]

    if mode in bins:
        return [(mode, bins[mode])]
    if bins:
        got, path = next(iter(bins.items()))
        raise SystemExit(
            "架构不匹配：%s 是 %s（ELF machine=%d），但 --arch 要求 %s（ELF machine=%d）。\n"
            "  做法一：--arch auto 让脚本按 ELF 头推断（当前会打成 %s 包）；\n"
            "  做法二：GOARCH=%s 重新交叉编译后 --bin 指定。"
            % (path, got, ARCH_TO_ELF_MACHINE[got], mode, ARCH_TO_ELF_MACHINE[mode],
               got, ARCH_TO_GOARCH[mode])
        )
    found = discover_bin(mode, dirs)
    if found:
        return [(mode, found)]
    raise SystemExit(missing_bin_msg(mode, dirs))


def build_binaries(go, version, arches, out_dir):
    """用 go 交叉编译静态单文件（GOOS=linux, CGO_ENABLED=0），返回 {arch: path}。"""
    app_dir = os.path.join(ROOT, "app")
    if not os.path.isdir(app_dir):
        raise SystemExit("找不到 app 源码目录：%s" % app_dir)
    os.makedirs(out_dir, exist_ok=True)
    built = {}
    for arch in arches:
        goarch = ARCH_TO_GOARCH[arch]
        out = os.path.abspath(os.path.join(out_dir, "guanlan-%s" % arch))
        env = dict(os.environ, GOOS="linux", GOARCH=goarch, CGO_ENABLED="0")
        ldflags = "-s -w -X main.buildVersion=%s" % version
        print("[build] GOOS=linux GOARCH=%s CGO_ENABLED=0 → %s" % (goarch, out))
        try:
            proc = subprocess.run(
                [go, "build", "-trimpath", "-ldflags", ldflags, "-o", out, "."],
                cwd=app_dir, env=env, capture_output=True, text=True,
            )
        except OSError as exc:
            raise SystemExit("无法执行 %s：%s（用 --go 指定 go 路径）" % (go, exc))
        if proc.returncode != 0 or not os.path.exists(out):
            raise SystemExit(
                "go build 失败（GOARCH=%s，退出码 %d）：\n%s\n%s"
                % (goarch, proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip())
            )
        verify_bin_arch(out, arch)
        built[arch] = out
    return built


def default_version():
    """版本号单一来源：app/version.txt（构建时读取）。"""
    vf = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "version.txt")
    try:
        with open(vf, "r", encoding="utf-8") as f:
            v = f.read().strip()
            if v:
                return v
    except OSError:
        pass
    return "1.0.0"


def main():
    ap = argparse.ArgumentParser(
        description="构建观澜 NetScope 的 OpenWrt .ipk / 便携 .tar.gz"
                    "（aarch64_generic = ELF 183，x86_64 = ELF 62）",
        epilog=(
            "示例：\n"
            "  python tools/build-ipk.py                                   # 默认 dist/guanlan，架构按 ELF 推断\n"
            "  python tools/build-ipk.py --arch x86_64 --bin dist/guanlan-amd64\n"
            "  python tools/build-ipk.py --arch both --build               # 一条命令产出两架构包\n"
            "  python tools/build-ipk.py --arch both --bin aarch64_generic=dist/guanlan-arm64 "
            "--bin x86_64=dist/guanlan-amd64\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--bin", action="append", default=[], metavar="[ARCH=]PATH",
                    help="二进制路径，可重复；可写成 ARCH=PATH 显式指定架构")
    ap.add_argument("--arch", default="auto",
                    help="auto（按 ELF 头推断，默认）/ aarch64_generic / x86_64 / both")
    ap.add_argument("--version", default=default_version())
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--build", action="store_true",
                    help="先用 go 交叉编译（GOOS=linux CGO_ENABLED=0）再打包；"
                         "--arch auto 时编译两架构")
    ap.add_argument("--go", default=os.environ.get("GO") or "go", help="go 可执行文件（默认 go）")
    a = ap.parse_args()

    mode = normalize_arch(a.arch)
    pairs, plain = parse_bin_args(a.bin)
    if not a.bin:
        plain = [] if a.build else [os.path.join(ROOT, "dist", "guanlan")]

    if a.build:
        archs = list(ALL_ARCHES) if mode in ("auto", "both") else [mode]
        built = build_binaries(a.go, a.version, archs, a.out)
        for arch, path in built.items():
            pairs = [(x, y) for (x, y) in pairs if x != arch]
            pairs.append((arch, path))
        # 刚编译出来的二进制优先：同架构的手工 --bin 让位，避免"两个都是 X"的歧义报错
        kept = []
        for p in plain:
            if os.path.isfile(p) and arch_from_bin(p) in built:
                continue
            kept.append(p)
        plain = kept
        if mode == "auto":
            mode = "both" if len(archs) > 1 else archs[0]

    targets = resolve_bins(mode, pairs, plain, a.out)
    if not targets:
        raise SystemExit("没有要打包的目标架构")

    print("==> guanlan %s，目标架构：%s" % (a.version, ", ".join(t for t, _ in targets)))
    results = []
    for arch, path in targets:
        ipk, tgz = build_ipk(path, a.version, arch, a.out)
        results.append((arch, ipk, tgz))
        print("IPK : %s (%d bytes)" % (ipk, os.path.getsize(ipk)))
        print("TGZ : %s (%d bytes)" % (tgz, os.path.getsize(tgz)))

    if len(results) > 1:
        print("==> 两架构产物就绪：%s" % "  ".join(os.path.basename(r[1]) for r in results))
    print("提示：opkg install <ipk>；卸载/回退见 deploy/rollback.sh（--purge 连数据一起删）")


if __name__ == "__main__":
    main()
