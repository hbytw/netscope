#!/usr/bin/env python3
"""Run a shell script on the router over SSH.

Usage:
  python tools/owssh.py -c "uname -a"
  python tools/owssh.py -f local.sh          # run local script file on router
  python tools/owssh.py -c "cmd" --upload local.sh:/tmp/x.sh
"""
import sys, os, argparse, time
import paramiko

HOST = os.environ.get("OWRT_HOST", "192.168.1.254")
USER = os.environ.get("OWRT_USER", "root")
PASS = os.environ.get("OWRT_PASS", "")


def connect(timeout=15):
    if not PASS:
        sys.stderr.write("错误：请先设置环境变量 OWRT_PASS（路由器 root 密码）\n")
        raise SystemExit(2)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=timeout,
              banner_timeout=timeout, auth_timeout=timeout,
              look_for_keys=False, allow_agent=False)
    return c


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
            local, remote = a.upload.split(":")
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
