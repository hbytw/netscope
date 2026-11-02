#!/usr/bin/env python3
"""Run a shell script on the router over SSH.

Usage:
  OWRT_HOST=192.168.8.4 OWRT_PASS=... python tools/owssh.py -c "uname -a"
  python tools/owssh.py --host 192.168.8.4 -c "uname -a"
  python tools/owssh.py -f local.sh          # run local script file on router
  python tools/owssh.py -c "cmd" --upload local.sh:/tmp/x.sh

目标地址不内置默认值：不同路由器网段不同，默认到某个 IP 会把命令和口令发给错误的设备。
OWRT_HOST 未设置且未传 --host 时由 owrt.resolve_host() 明确报错（退出码 2）。

--upload 的路径解析用 rsplit(':', 1)：Windows 本地路径带盘符
（如 D:\\code\\openwrt\\deploy\\rollback.sh:/tmp/rollback.sh），
用 split(':') 会被切成 3 段抛 ValueError，导致一键回退必然失败。

主机密钥校验与指纹登记复用同目录的 owrt.py（两处实现保持一致）：
首次连接打印指纹供人工核对并登记，之后严格校验，密钥不符即中止；
新设备需要显式登记时设置 OWRT_ACCEPT_HOSTKEY=1。

口令策略：只使用环境变量 OWRT_PASS；登录失败即报错，
          绝不回退到任何公开的默认口令。
"""
import sys, os, argparse, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import owrt
except ImportError as e:  # owrt.py 与本文件同目录，必须一起分发
    sys.stderr.write("错误：无法导入同目录的 owrt.py（%s）\n" % e)
    raise SystemExit(2)

HOST = owrt.HOST
USER = owrt.USER
PASS = owrt.PASS


def connect(timeout=15):
    if not PASS:
        sys.stderr.write("错误：请先设置环境变量 OWRT_PASS（路由器 root 密码）\n")
        raise SystemExit(2)
    # resolve_host 在没有 OWRT_HOST / --host 时报错并打印用法，不默认任何 IP
    return owrt.connect(timeout=timeout, host=owrt.resolve_host())


def split_upload(spec):
    """解析 --upload 的 local:remote。

    必须从右往左切（rsplit(':', 1)），否则 Windows 盘符路径会被切坏。
    """
    if ":" not in spec:
        raise ValueError("--upload 需要 local:remote 两个路径：%s" % spec)
    local, remote = spec.rsplit(":", 1)
    local = local.strip()
    remote = remote.strip()
    if not local or not remote:
        raise ValueError("--upload 参数不完整（本地或远端路径为空）：%s" % spec)
    return local, remote


def _remote_sha256(c, remote):
    rc, out, _ = run(c, "sha256sum %s 2>/dev/null | cut -d' ' -f1" % shquote(remote))
    return out.strip() if rc == 0 else ""


def upload_sftp(c, local, remote, timeout=300):
    """SFTP 上传（首选）。"""
    sftp = c.open_sftp()
    try:
        sftp.put(local, remote)
    finally:
        sftp.close()


def upload_stream(c, local, remote, timeout=600):
    """exec + stdin 流式上传（兜底）。

    某些固件的 sftp-server 在写大文件时会被 dropbear 断开，而 exec 通道稳定，
    因此失败时改用 `cat > remote` 把本地字节流写进去，并用 sha256 校验。
    """
    import hashlib
    with open(local, "rb") as fh:
        data = fh.read()
    want = hashlib.sha256(data).hexdigest()
    stdin, stdout, stderr = c.exec_command("cat > %s" % shquote(remote), timeout=timeout)
    stdin.write(data)
    stdin.flush()
    stdin.channel.shutdown_write()
    rc = stdout.channel.recv_exit_status()
    err = stderr.read().decode("utf-8", "replace")
    if rc != 0:
        raise RuntimeError("流式写入失败（rc=%d）%s" % (rc, err.strip()))
    got = _remote_sha256(c, remote)
    if got != want:
        raise RuntimeError("上传校验失败：本地 %s 远端 %s" % (want[:16], (got or "空")[:16]))


def do_upload(c, local, remote, timeout=600):
    """上传并按优先级尝试多种传输方式，最后校验内容一致。"""
    import os
    if not os.path.isfile(local):
        raise RuntimeError("本地文件不存在：%s" % local)
    size = os.path.getsize(local)
    if size == 0:
        raise RuntimeError("本地文件为 0 字节，拒绝上传：%s" % local)
    errors = []
    for name, fn in (("sftp", upload_sftp), ("stream", upload_stream)):
        try:
            fn(c, local, remote, timeout=timeout)
            # 统一校验大小，避免"传输成功但文件未落盘"的假成功
            rc, out, _ = run(c, "wc -c < %s 2>/dev/null" % shquote(remote))
            got = out.strip()
            if got.isdigit() and int(got) == size:
                return name
            errors.append("%s: 大小不符（远端 %s / 本地 %d）" % (name, got or "?", size))
        except Exception as e:  # 传输层异常：记录后尝试下一种
            errors.append("%s: %s" % (name, e))
    raise RuntimeError("上传失败：%s" % "；".join(errors))


def shquote(s):
    """POSIX 单引号转义，避免路径中的特殊字符被 shell 解释。"""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _relay_addr(relay_conn, prefer):
    """取中转主机上目标机可达的地址：优先虚拟网卡（zt/tailscale）IPv4，其次用户传入的地址。"""
    rc, out, _ = run(relay_conn, "ip -4 -o addr show 2>/dev/null")
    cands = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        dev, cidr = parts[1], parts[3]
        ip = cidr.split("/")[0]
        if ip.startswith("127."):
            continue
        if dev.startswith(("zt", "tailscale")):
            cands.insert(0, ip)
        else:
            cands.append(ip)
    return cands[0] if cands else prefer


def relay_upload(target_conn, local, remote, relay_host, timeout=900):
    """经中转主机（同网段/同虚拟网络）用 HTTP 把文件推到目标机。

    适用场景：本机到目标机的链路（如 ZeroTier）大流量不稳，而中转主机到目标机稳定。
    步骤：本机 → 中转（SFTP）→ 中转起临时 HTTP 服务 → 目标机 curl 拉取 → 校验 sha256 → 清理。
    """
    import hashlib
    import os
    import time

    with open(local, "rb") as fh:
        data = fh.read()
    want = hashlib.sha256(data).hexdigest()
    name = "glrelay-%s-%s" % (hashlib.sha256(data).hexdigest()[:8], os.path.basename(local))
    rdir = "/tmp/_glrelay"
    rpath = rdir + "/" + name
    port = 19000 + (int(time.time()) % 200)

    rc_c = c_connect(relay_host)
    try:
        run(rc_c, "mkdir -p %s" % rdir)
        upload_sftp(rc_c, local, rpath, timeout=timeout)
        got = _remote_sha256(rc_c, rpath)
        if got != want:
            raise RuntimeError("中转上传校验失败（%s）" % (got or "空"))
        # 起临时 HTTP 服务（nohup 后台 + 全部 fd 重定向，避免读通道阻塞）
        start = ("pkill -f 'http.server %d' >/dev/null 2>&1; "
                 "cd %s && nohup python3 -m http.server %d --bind 0.0.0.0 "
                 ">/tmp/_glrelay.log 2>&1 </dev/null & echo started") % (port, rdir, port)
        try:
            run(rc_c, start, timeout=8)
        except Exception:
            pass  # 后台进程可能未及时返回 EOF，忽略；下面用 HTTP 探测确认就绪
        ready = False
        for _ in range(20):
            rc, out, _ = run(rc_c, "curl -s -o /dev/null -w '%%{http_code}' -m 3 http://127.0.0.1:%d/%s"
                             % (port, name), timeout=10)
            if out.strip() == "200":
                ready = True
                break
            time.sleep(1)
        if not ready:
            rc, log, _ = run(rc_c, "tail -3 /tmp/_glrelay.log 2>/dev/null; ls -l %s 2>/dev/null" % rpath)
            raise RuntimeError("中转 HTTP 服务未就绪（端口 %d）%s" % (port, log.strip()[:200]))
        reach = _relay_addr(rc_c, relay_host)
        url = "http://%s:%d/%s" % (reach, port, name)
        cmd = ("rm -f %s; curl -sS -m %d --retry 3 --retry-delay 2 --retry-all-errors -o %s %s; wc -c < %s"
               % (shquote(remote), timeout, shquote(remote), shquote(url), shquote(remote)))
        rc, out, err = run(target_conn, cmd, timeout=timeout)
        size = out.strip().splitlines()[-1] if out.strip() else ""
        if not size.isdigit() or int(size) != len(data):
            raise RuntimeError("目标机下载大小不符（%s / %d）%s" % (size or "?", len(data), err.strip()[:120]))
        got = _remote_sha256(target_conn, remote)
        if got != want:
            raise RuntimeError("目标机校验失败（%s）" % (got or "空"))
        return "relay(%s)" % reach
    finally:
        try:
            run(rc_c, "pkill -f 'http.server %d' 2>/dev/null; rm -f %s" % (port, rpath))
        except Exception:
            pass
        try:
            rc_c.close()
        except Exception:
            pass


def c_connect(host):
    """连接指定主机（中转用）。"""
    return owrt.connect(timeout=20, host=host)


def run(c, cmd, timeout=120):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", dest="cmd")
    ap.add_argument("-f", dest="file")
    ap.add_argument("--upload", dest="upload", help="local:remote")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--host", default=None,
                    help="router address; overrides OWRT_HOST (no built-in default)")
    ap.add_argument("--relay", default=None,
                    help="relay host used when direct transfer is unstable (e.g. ZeroTier link)")
    a = ap.parse_args()

    if a.host:
        os.environ["OWRT_HOST"] = a.host.strip()

    c = connect()
    try:
        if a.upload:
            try:
                local, remote = split_upload(a.upload)
            except ValueError as e:
                sys.stderr.write("错误：%s\n" % e)
                return 2
            try:
                if a.relay:
                    how = relay_upload(c, local, remote, a.relay, timeout=max(a.timeout, 600))
                else:
                    how = do_upload(c, local, remote, timeout=max(a.timeout, 300))
            except Exception as e:
                sys.stderr.write("上传失败：%s\n" % e)
                return 1
            print("uploaded %s -> %s (%s)" % (local, remote, how))
            if not a.cmd:
                return 0
        cmd = a.cmd
        if a.file:
            with open(a.file, "r", encoding="utf-8") as fh:
                body = fh.read()
            remote = "/tmp/_owssh_%d.sh" % int(time.time())
            # 脚本同样走统一上传通道（sftp 不可用时自动流式写入）
            tmp_local = remote.replace("/", "_") + ".local"
            with open(tmp_local, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(body)
            try:
                do_upload(c, tmp_local, remote, timeout=max(a.timeout, 120))
            finally:
                try:
                    os.remove(tmp_local)
                except OSError:
                    pass
            cmd = "sh %s" % remote
        rc, out, err = run(c, cmd, a.timeout)
    finally:
        c.close()
    sys.stdout.write(out)
    if err.strip():
        sys.stderr.write(err)
    return rc


if __name__ == "__main__":
    sys.exit(main())
