#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pve_fw_export.py — export the raw Proxmox VE firewall configuration as a JSON
bundle for PVE Flow Explorer (https://pxe-fw-audit.w00tw00t.me).

The script does not interpret anything: it only collects files as they are.
All resolution (aliases, IPSets, security groups, macros, IP -> guest mapping)
happens in the web app, in your browser.

Bundle content:
  files   raw text of:
            firewall/cluster.fw, firewall/<vmid>.fw, nodes/<node>/host.fw,
            sdn/firewall/<vnet>.fw, sdn/vnets.cfg, sdn/subnets.cfg, sdn/zones.cfg
  guests  for each VM/CT: node, type and the relevant lines of its .conf
          (name, hostname, net*, ipconfig*, tags only: no cloud-init passwords,
          SSH keys or descriptions)
  live    (--live) power state and real IP addresses via pvesh / qemu-guest-agent

Usage:
  python3 pve_fw_export.py                       # writes ./pve-fw-<cluster>-<date>.json
  python3 pve_fw_export.py --live                # + IPs reported by the guest agent
  python3 pve_fw_export.py --pve-dir ./etc-pve -o bundle.json
  python3 pve_fw_export.py -o -                  # print the JSON (to copy and paste it into the web app)
  python3 pve_fw_export.py -o - | gzip > bundle.json.gz
  ssh root@pve1 python3 - --live -o - < pve_fw_export.py > pve-fw-export.json

Python 3.6+, standard library only. Run it on any node of the cluster
(as root, or as a member of the www-data group to read /etc/pve).

Project: https://github.com/mrwazaby/pxe-fw-audit
"""
import argparse
import datetime
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys

FORMAT = "pve-fw-raw"
VERSION = 1
CONF_KEEP = re.compile(r"^(name|hostname|net\d+|ipconfig\d+|tags|template):")


def warn(msg):
    print("[!] " + msg, file=sys.stderr)


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        warn("cannot read %s: %s" % (path, exc))
        return None


def rel(pve, path):
    return os.path.relpath(path, pve).replace(os.sep, "/")


def filtered_conf(text):
    """Keep the current section of a guest .conf (not snapshots) and the useful keys only."""
    out = []
    for line in text.splitlines():
        if line.startswith("["):
            break
        if CONF_KEEP.match(line):
            out.append(line)
    return "\n".join(out)


def collect(pve):
    files, guests, nodes = {}, {}, []
    patterns = ["firewall/*.fw", "nodes/*/host.fw", "sdn/firewall/*.fw",
                "sdn/vnets.cfg", "sdn/subnets.cfg", "sdn/zones.cfg"]
    for pat in patterns:
        for p in sorted(glob.glob(os.path.join(pve, pat))):
            txt = read(p)
            if txt is not None:
                files[rel(pve, p)] = txt

    for p in sorted(glob.glob(os.path.join(pve, "nodes", "*"))):
        if os.path.isdir(p):
            nodes.append(os.path.basename(p))

    for kind in ("qemu-server", "lxc"):
        for p in sorted(glob.glob(os.path.join(pve, "nodes", "*", kind, "*.conf"))):
            vmid = os.path.basename(p)[:-5]
            txt = read(p)
            if txt is None:
                continue
            guests[vmid] = {"node": p.split(os.sep)[-3],
                            "type": "lxc" if kind == "lxc" else "qemu",
                            "conf": filtered_conf(txt)}
    return files, guests, nodes


def cluster_name(pve):
    path = os.path.join(pve, "corosync.conf")
    txt = read(path) if os.path.exists(path) else None
    m = re.search(r"cluster_name:\s*(\S+)", txt or "")
    return m.group(1) if m else None


def pvesh(path, timeout=8):
    try:
        r = subprocess.run(["pvesh", "get", path, "--output-format", "json"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout, check=False)
        return json.loads(r.stdout.decode() or "null") if r.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def usable_ip(ip):
    ip = ip.split("/")[0]
    return ip and not ip.startswith(("127.", "fe80", "::1", "169.254."))


def collect_live():
    """Real guest IPs (guest agent / LXC interfaces) and node IPs."""
    if not shutil.which("pvesh"):
        warn("pvesh not found: --live ignored")
        return None
    live = {"resources": [], "ips": {}, "nodeIps": {}}
    for r in pvesh("/cluster/resources") or []:
        if r.get("type") in ("qemu", "lxc"):
            live["resources"].append({k: r.get(k) for k in ("vmid", "name", "node", "type", "status")})
        elif r.get("type") == "node":
            net = pvesh("/nodes/%s/network" % r["node"]) or []
            ips = [i.get("address") for i in net if i.get("address")]
            ips += [i.get("address6") for i in net if i.get("address6")]
            live["nodeIps"][r["node"]] = [i for i in ips if usable_ip(i)]

    for r in live["resources"]:
        if r.get("status") != "running":
            continue
        vmid, node = str(r["vmid"]), r["node"]
        ips = []
        if r["type"] == "qemu":
            data = pvesh("/nodes/%s/qemu/%s/agent/network-get-interfaces" % (node, vmid), 5)
            for iface in data.get("result", []) if isinstance(data, dict) else []:
                for a in iface.get("ip-addresses", []):
                    ips.append(a.get("ip-address", ""))
        else:
            for iface in pvesh("/nodes/%s/lxc/%s/interfaces" % (node, vmid), 5) or []:
                for k in ("inet", "inet6"):
                    if iface.get(k):
                        ips.append(iface[k])
        ips = sorted({i.split("/")[0] for i in ips if usable_ip(i)})
        if ips:
            live["ips"][vmid] = ips
    print("[i] live: %d guests, %d with reported IPs" % (
        len(live["resources"]), len(live["ips"])), file=sys.stderr)
    return live


def main():
    ap = argparse.ArgumentParser(description="Raw Proxmox VE firewall export (JSON bundle for PVE Flow Explorer)")
    ap.add_argument("--pve-dir", default="/etc/pve", help="PVE config root (default: /etc/pve)")
    ap.add_argument("-o", "--output", help="output file ('-' for stdout)")
    ap.add_argument("--live", action="store_true",
                    help="add power state and real IPs via pvesh / qemu-guest-agent")
    args = ap.parse_args()

    if not os.path.isdir(args.pve_dir):
        sys.exit("Directory not found: %s" % args.pve_dir)

    files, guests, nodes = collect(args.pve_dir)
    if "firewall/cluster.fw" not in files:
        warn("firewall/cluster.fw is missing: was the datacenter firewall ever configured?")

    name = cluster_name(args.pve_dir) or socket.gethostname()
    now = datetime.datetime.now().astimezone()
    pve_version = None
    if shutil.which("pveversion"):
        try:
            pve_version = subprocess.run(["pveversion"], stdout=subprocess.PIPE,
                                         timeout=5).stdout.decode().strip()
        except (OSError, subprocess.TimeoutExpired):
            pass

    bundle = {
        "format": FORMAT, "version": VERSION,
        "meta": {"cluster": name, "host": socket.gethostname(), "generated": now.isoformat(),
                 "pveVersion": pve_version, "source": os.path.abspath(args.pve_dir)},
        "nodes": nodes, "files": files, "guests": guests,
        "live": collect_live() if args.live else None,
    }

    out = args.output or "pve-fw-%s-%s.json" % (re.sub(r"[^\w.-]", "_", name), now.strftime("%Y%m%d-%H%M"))
    data = json.dumps(bundle, ensure_ascii=False, indent=1)
    if out == "-":
        sys.stdout.write(data + "\n")
    else:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(data)
        n_fw = sum(1 for k in files if k.endswith(".fw"))
        print("Bundle written: %s (%d firewall files, %d guests, %d nodes)" % (
            os.path.abspath(out), n_fw, len(guests), len(nodes)))
        print("Open https://pxe-fw-audit.w00tw00t.me and import it.")


if __name__ == "__main__":
    main()
