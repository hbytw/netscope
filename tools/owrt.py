#!/usr/bin/env python3
"""Minimal SSH runner for the OpenWrt side-router.

Usage:
  OWRT_HOST=192.168.8.4 OWRT_PASS=... python owrt.py --cmd "uname -a"
  python owrt.py --host 192.168.8.4 --cmd "uname -a" [--timeout 60]

目标地址不内置默认值：不同路由器网段不同，默认到某个 IP 会把命令和口令发给错误的设备。
OWRT_HOST 未设置且未传 --host 时直接报错并打印用法（退出码 2）。

主机密钥策略（连接携带 root 口令，必须防中间人）：
  * 首次连接：取回服务器主机密钥，把 SHA256 指纹打印到日志（请人工核对），
    公钥写入本地 known_hosts 文件，指纹另存一份便于比对；
  * 之后每次连接：严格校验（RejectPolicy + known_hosts），
    密钥不一致直接报错中止，绝不自动放行；
  * 新设备显式登记（opt-in）：OWRT_ACCEPT_HOSTKEY=1 才登记未知主机并打印指纹；
  * known_hosts 路径：$OWRT_KNOWN_HOSTS，默认 ~/.ssh/guanlan_known_hosts。

口令策略：只使用环境变量 OWRT_PASS / 调用方传入的口令；
          登录失败即报错，绝不回退到任何公开的默认口令。
"""
import sys, os, argparse, base64, hashlib, socket
import paramiko
from paramiko.hostkeys import HostKeys

HOST = os.environ.get("OWRT_HOST", "").strip()
USER = os.environ.get("OWRT_USER", "root")
PASS = os.environ.get("OWRT_PASS", "")
PORT = int(os.environ.get("OWRT_PORT", "22"))

KNOWN_HOSTS = os.environ.get("OWRT_KNOWN_HOSTS") or os.path.join(
    os.path.expanduser("~"), ".ssh", "guanlan_known_hosts")
FINGERPRINT_FILE = KNOWN_HOSTS + ".fingerprints"

HOST_USAGE = """错误：未指定路由器地址（OWRT_HOST 为空）。
本脚本不内置任何默认 IP —— 不同路由器网段不同，默认到某个地址会把命令和口令发给错误的设备。
用法：
    OWRT_HOST=192.168.8.4 OWRT_PASS='***' python tools/owrt.py --cmd "uname -a"
    python tools/owrt.py --host 192.168.8.4 --cmd "uname -a"

其他环境变量（可选）：
    OWRT_USER     SSH 用户，默认 root
    OWRT_PASS     SSH 口令（必须设置，无任何内置默认口令）
    OWRT_PORT     SSH 端口，默认 22
    OWRT_KNOWN_HOSTS        known_hosts 路径，默认 ~/.ssh/guanlan_known_hosts
    OWRT_ACCEPT_HOSTKEY=1   新设备首次登记主机密钥（默认拒绝未知主机）
"""


def resolve_host(host=None):
    """解析目标主机：显式参数 > 环境变量 > 导入时的值；都没有就明确报错退出。"""
    h = (host or os.environ.get("OWRT_HOST") or HOST or "").strip()
    if not h:
        sys.stderr.write(HOST_USAGE)
        raise SystemExit(2)
    return h


def host_key_name(host, port):
    """known_hosts 里的主机名（非 22 端口用 [host]:port 形式，与 paramiko 一致）。"""
    if port == 22:
        return host
    return "[%s]:%d" % (host, port)


def key_fingerprint(key):
    """主机密钥指纹（OpenSSH 风格 SHA256:xxx）。"""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def fetch_host_key(host, port, timeout):
    """握手取回服务器主机密钥（只做密钥交换，不认证）。"""
    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        try:
            transport.close()
        except Exception:
            pass


def save_host_key(host, port, key):
    """把主机公钥写入 known_hosts，并记录指纹（首次连接登记）。"""
    name = host_key_name(host, port)
    try:
        parent = os.path.dirname(os.path.abspath(KNOWN_HOSTS))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    hk = HostKeys()
    if os.path.exists(KNOWN_HOSTS):
        try:
            hk.load(KNOWN_HOSTS)
        except (IOError, OSError):
            pass
    hk.add(name, key.get_name(), key)
    hk.save(KNOWN_HOSTS)
    try:
        with open(FINGERPRINT_FILE, "a", encoding="utf-8") as fh:
            fh.write("%s %s %s\n" % (name, key_fingerprint(key), key.get_name()))
    except OSError:
        pass


def recorded_fingerprint(name):
    """读取已登记的指纹（供打印比对）。"""
    try:
        with open(FINGERPRINT_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == name:
                    return parts[1]
    except OSError:
        pass
    return ""


def connect(timeout=15, host=None):
    """连接路由器并严格校验主机密钥。

    host 为空时读 OWRT_HOST；两者都没有则明确报错（不默认任何 IP）。
    """
    host = resolve_host(host)
    name = host_key_name(host, PORT)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    if os.path.exists(KNOWN_HOSTS):
        client.load_host_keys(KNOWN_HOSTS)
        fp = recorded_fingerprint(name)
        if fp:
            sys.stderr.write("[hostkey] %s registered fingerprint: %s\n" % (name, fp))
        elif os.environ.get("OWRT_ACCEPT_HOSTKEY") == "1":
            # 新设备显式登记（opt-in）：默认仍拒绝未知主机，避免中间人；
            # 只有用户明确同意（OWRT_ACCEPT_HOSTKEY=1）才登记并打印指纹供核对。
            key = fetch_host_key(host, PORT, timeout)
            kfp = key_fingerprint(key)
            sys.stderr.write("[hostkey] new device %s, registering (OWRT_ACCEPT_HOSTKEY=1)\n" % name)
            sys.stderr.write("[hostkey] host key fingerprint: %s (%s)\n" % (kfp, key.get_name()))
            save_host_key(host, PORT, key)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.load_host_keys(KNOWN_HOSTS)
    else:
        # 首次连接：登记主机密钥（打印指纹供人工核对）
        key = fetch_host_key(host, PORT, timeout)
        fp = key_fingerprint(key)
        sys.stderr.write("[hostkey] first connection to %s\n" % name)
        sys.stderr.write("[hostkey] host key fingerprint: %s (%s)\n" % (fp, key.get_name()))
        sys.stderr.write("[hostkey] please verify this fingerprint manually, then it is saved to %s\n" % KNOWN_HOSTS)
        save_host_key(host, PORT, key)
        client.load_host_keys(KNOWN_HOSTS)

    try:
        client.connect(
            host, port=PORT, username=USER, password=PASS,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
    except paramiko.ssh_exception.SSHException as e:
        msg = str(e)
        if "not found in known_hosts" in msg:
            sys.stderr.write(
                "[hostkey] host key of %s is not in known_hosts, refusing to connect: %s\n" % (name, msg))
            sys.stderr.write(
                "[hostkey] if this is really a new device, set OWRT_ACCEPT_HOSTKEY=1 to register it "
                "(the fingerprint is printed for manual verification); if its key changed, remove the "
                "stale entry from %s and retry\n" % KNOWN_HOSTS)
        elif "does not match" in msg or "Host key" in msg:
            sys.stderr.write(
                "[hostkey] host key mismatch (possible MITM), aborted: %s\n" % msg)
            sys.stderr.write("[hostkey] registered fingerprints: %s\n" % FINGERPRINT_FILE)
        else:
            sys.stderr.write("[hostkey] connection failed: %s\n" % msg)
        raise
    return client


def run(cmd, timeout=60):
    c = connect()
    try:
        stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    finally:
        c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", required=True, help="remote command to execute")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--host", default=None,
                    help="router address; overrides OWRT_HOST (no built-in default)")
    a = ap.parse_args()
    if a.host:
        os.environ["OWRT_HOST"] = a.host.strip()
    try:
        rc, out, err = run(a.cmd, a.timeout)
    except Exception as e:
        print("CONNECT_ERROR: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 99
    sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return rc


if __name__ == "__main__":
    sys.exit(main())
