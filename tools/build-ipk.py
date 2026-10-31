#!/usr/bin/env python3
"""构建 OpenWrt .ipk 安装包（纯 Python，无需 Linux ar 工具）。

用法：
    python tools/build-ipk.py [--bin dist/guanlan] [--version 1.0.0] [--arch aarch64_generic] [--out dist]

产物：
    dist/guanlan_<version>_<arch>.ipk
    dist/guanlan_<version>_<arch>.tar.gz   （便携包：二进制 + install.sh + rollback.sh）
"""
import argparse
import gzip
import io
import os
import shutil
import struct
import subprocess
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INIT_SCRIPT = """#!/bin/sh /etc/rc.common
# 观澜 NetScope 服务（procd）
USE_PROCD=1
START=99
STOP=10
PROG="guanlan"

APP_BIN="/usr/sbin/guanlan"
# 数据目录：优先使用持久分区（N1 常见 mmcblk2p4 挂载点），否则回退 overlay
APP_DATA="/etc/guanlan/data"
if [ -d /mnt/mmcblk2p4 ]; then
    APP_DATA="/mnt/mmcblk2p4/guanlan/data"
fi
APP_LOG_DIR="$APP_DATA/../logs"
APP_RUNDIR="/tmp/guanlan"
DNS_LOG_DIR="/tmp/guanlan"
APP_ADDR="0.0.0.0:8088"

start_service() {
    # /tmp 是 tmpfs，重启即失，每次启动都要确保目录存在
    mkdir -p "$APP_RUNDIR" "$DNS_LOG_DIR" "$APP_DATA" "$APP_LOG_DIR" 2>/dev/null

    procd_open_instance
    procd_set_param command "$APP_BIN" \\
        -addr "$APP_ADDR" \\
        -data "$APP_DATA"
    procd_set_param pidfile "/var/run/guanlan.pid"
    # 崩溃自动重启：3600 秒窗口内最多重启 5 次，间隔 5 秒
    procd_set_param respawn 3600 5 5
    procd_set_param limits nofile="4096 4096"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger "/etc/guanlan/config.json"
}
"""

POSTINST = """#!/bin/sh
# 安装后：建目录 + 生成默认配置 + 启用并启动服务
CONF="/etc/guanlan/config.json"

# 数据目录：优先持久分区，否则 overlay
DATA="/etc/guanlan/data"
LOG="/etc/guanlan/logs"
if [ -d /mnt/mmcblk2p4 ]; then
    DATA="/mnt/mmcblk2p4/guanlan/data"
    LOG="/mnt/mmcblk2p4/guanlan/logs"
fi

mkdir -p /etc/guanlan "$DATA" "$LOG" /tmp/guanlan 2>/dev/null

if [ ! -f "$CONF" ]; then
    SALT="guanlan-$(date '+%Y%m%d%H%M%S')"
    HASH=$(printf '%s' "${SALT}guanlan2026" | sha256sum | cut -d' ' -f1)
    cat > "$CONF" <<EOF
{
  "salt": "$SALT",
  "passwordHash": "$HASH",
  "listen": "0.0.0.0:8088",
  "dataDir": "$DATA",
  "logDir": "$LOG",
  "port": 8088,
  "createdAt": "$(date '+%Y-%m-%dT%H:%M:%S%z')"
}
EOF
    chmod 0600 "$CONF" 2>/dev/null || true
    echo "[guanlan] 已生成默认配置：$CONF（默认密码 guanlan2026，请登录后立即修改）"
fi

/etc/init.d/guanlan enable 2>/dev/null || true
/etc/init.d/guanlan start 2>/dev/null || true
echo "[guanlan] 安装完成：http://<路由器IP>:8088  （默认账号 admin / guanlan2026）"
exit 0
"""

PRERM = """#!/bin/sh
# 卸载前：停止服务
/etc/init.d/guanlan stop 2>/dev/null || true
/etc/init.d/guanlan disable 2>/dev/null || true
exit 0
"""

POSTRM = """#!/bin/sh
# 卸载后：清理运行时文件（保留 /etc/guanlan 配置与数据，便于重装/备份）
rm -f /var/run/guanlan.pid 2>/dev/null || true
rm -rf /tmp/guanlan 2>/dev/null || true
echo "[guanlan] 已卸载；配置与数据保留在 /etc/guanlan（如需彻底清理请手动删除）"
exit 0
"""


def make_tar_gz(entries, out_path, mtime=None):
    """entries: list of (name, data(bytes), mode)。使用 ustar 格式，兼容 opkg 解析。"""
    mtime = mtime or int(time.time())
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


def ar_member(name, data):
    """构造 ar 成员（System V 格式，OpenWrt opkg 兼容）"""
    hdr = struct.pack(
        "16s12s6s6s8s10s2s",
        (name + "/").encode()[:16].ljust(16, b" "),
        str(int(time.time())).encode().ljust(12, b" "),
        b"0".ljust(6, b" "),
        b"0".ljust(6, b" "),
        b"100644".ljust(8, b" "),
        str(len(data)).encode().ljust(10, b" "),
        b"`\n",
    )
    body = data if len(data) % 2 == 0 else data + b"\n"
    return hdr + body


def build_ipk(bin_path, version, arch, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    tmp = os.path.join(out_dir, ".ipk-tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)

    with open(bin_path, "rb") as fh:
        bin_data = fh.read()
    size_kb = max(1, len(bin_data) // 1024)

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
    ], control_tgz)

    data_tgz = os.path.join(tmp, "data.tar.gz")
    make_tar_gz([
        ("./usr/sbin/guanlan", bin_data, 0o755),
        ("./etc/init.d/guanlan", INIT_SCRIPT.encode(), 0o755),
    ], data_tgz)

    with open(os.path.join(tmp, "debian-binary"), "wb") as fh:
        fh.write(b"2.0\n")

    # 用 bsdtar（libarchive）生成 ar 归档 —— 与 opkg 的 libarchive 解析同源，格式必然兼容
    ipk_name = "guanlan_%s_%s.ipk" % (version, arch)
    ipk_path = os.path.join(out_dir, ipk_name)
    if os.path.exists(ipk_path):
        os.remove(ipk_path)
    proc = subprocess.run(
        ["tar", "--format=ar", "-cf", ipk_path, "debian-binary", "control.tar.gz", "data.tar.gz"],
        cwd=tmp, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SystemExit("tar --format=ar 失败：%s %s" % (proc.stdout, proc.stderr))

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
    make_tar_gz(entries, tgz_path)

    return ipk_path, tgz_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(ROOT, "dist", "guanlan"))
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--arch", default="aarch64_generic")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    a = ap.parse_args()
    if not os.path.exists(a.bin):
        raise SystemExit("二进制不存在：%s（先构建 dist/guanlan）" % a.bin)
    ipk, tgz = build_ipk(a.bin, a.version, a.arch, a.out)
    print("IPK : %s (%d bytes)" % (ipk, os.path.getsize(ipk)))
    print("TGZ : %s (%d bytes)" % (tgz, os.path.getsize(tgz)))


if __name__ == "__main__":
    main()
