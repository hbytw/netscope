#!/usr/bin/env python3
"""Run a shell script on the router over SSH.

Usage:
  python tools/owssh.py -c "uname -a"
  python tools/owssh.py -f local.sh          # run local script file on router
  python tools/owssh.py -c "cmd" --upload local.sh:/tmp/x.sh

--upload 的路径解析用 rsplit(':', 1)：Windows 本地路径带盘符
（如 D:\\code\\openwrt\\deploy\\rollback.sh:/tmp/rollback.sh），
用 split(':') 会被切成 3 段抛 ValueError，导致一键回退必然失败。

主机密钥校验与指纹登记复用同目录的 owrt.py（两处实现保持一致）：
首次连接打印指纹供人工核对并登记，之后严格校验，密钥不符即中止。

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
    return owrt.connect(timeout=timeout)


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
    a = ap.parse_args()

    c = connect()
    try:
        if a.upload:
            try:
                local, remote = split_upload(a.upload)
            except ValueError as e:
                sys.stderr.write("错误：%s\n" % e)
                return 2
            sftp = c.open_sftp()
            sftp.put(local, remote)
            sftp.close()
            print("uploaded %s -> %s" % (local, remote))
            if not a.cmd:
                return 0
        cmd = a.cmd
        if a.file:
            with open(a.file, "r", encoding="utf-8") as fh:
                body = fh.read()
            remote = "/tmp/_owssh_%d.sh" % int(time.time())
            sftp = c.open_sftp()
            with sftp.file(remote, "w") as fh:
                fh.write(body)
            sftp.close()
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
