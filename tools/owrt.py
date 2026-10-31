#!/usr/bin/env python3
"""Minimal SSH runner for the OpenWrt side-router.

Usage: python owrt.py --cmd "uname -a" [--timeout 60]
"""
import sys, os, argparse
import paramiko

HOST = os.environ.get("OWRT_HOST", "192.168.1.254")
USER = os.environ.get("OWRT_USER", "root")
PASS = os.environ.get("OWRT_PASS", "")
PORT = int(os.environ.get("OWRT_PORT", "22"))


def connect(timeout=12):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        HOST, port=PORT, username=USER, password=PASS,
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
        look_for_keys=False, allow_agent=False,
    )
    return c


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
    a = ap.parse_args()
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
