#!/usr/bin/env python3
"""Run a batch of shell commands on the router over one SSH session."""
import sys, os, json
import paramiko

HOST = os.environ.get("OWRT_HOST", "192.168.1.254")
USER = os.environ.get("OWRT_USER", "root")
PASS = os.environ.get("OWRT_PASS", "")

CMDS = [
    ("dhcp-opts", "uci show dhcp.@dnsmasq[0].logqueries; echo '--'; uci show dhcp.lan.dhcp_option 2>/dev/null; echo '--'; uci show network.lan.gateway; echo '--'; uci show dhcp.lan.router 2>/dev/null"),
    ("logging", "ls -la /tmp/dnscache* /var/log/dnscache* 2>/dev/null; echo '--'; cat /etc/dnscache/config 2>/dev/null | head; echo '--ps--'; ps w | grep -E 'dnscache|adbyby|koolproxy|dnsmasq' | grep -v grep"),
    ("account", "iptables -m account -h 2>&1 | head -15; echo '--'; ls /usr/lib/iptables 2>/dev/null | head -30"),
    ("fstab", "cat /etc/config/fstab 2>/dev/null; echo '--mounts--'; mount | grep -E 'mmcblk|overlay|mnt'"),
    ("time", "date; date -u; cat /etc/TZ 2>/dev/null; uci get system.@system[0].timezone 2>/dev/null"),
    ("ctacct", "cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null; cat /proc/sys/net/netfilter/nf_conntrack_timestamp 2>/dev/null; echo '--'; cat /proc/sys/net/netfilter/nf_conntrack_events 2>/dev/null"),
    ("tc", "tc qdisc show 2>&1 | head; echo '--'; ls /sys/module | grep -E 'ifb|sch_|nf_conn' | head -20"),
    ("luci-apps", "opkg list-installed | grep -c '^luci'; opkg list-installed | grep '^luci-app' | awk '{print $1}' | head -40"),
    ("mangle", "iptables -t mangle -L -n -v 2>&1 | head -25; echo '--rules--'; ip rule show"),
    ("php", "php -v 2>&1 | head -3; echo '--'; ls /usr/bin/php* 2>/dev/null"),
]

def main():
    sel = sys.argv[1:] or None
    # 复用 owrt.connect：带主机密钥指纹校验（首次连接登记，后续严格比对）
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import owrt
    c = owrt.connect()
    for name, cmd in CMDS:
        if sel and name not in sel:
            continue
        print("="*20, name, "="*20)
        stdin, stdout, stderr = c.exec_command(cmd, timeout=90)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        print(out.rstrip())
        if err.strip():
            print("[stderr]", err.strip())
    c.close()

if __name__ == "__main__":
    main()
