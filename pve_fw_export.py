#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pve_fw_export.py — export the raw Proxmox VE firewall configuration as a JSON
bundle for PVE Flow Explorer (https://pve-flow-explorer.w00tw00t.me).

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
  live    power state and real IP addresses via pvesh / qemu-guest-agent
          (only when reading /etc/pve on a node where pvesh is available;
          the calls run in parallel and give up after about a minute)

Usage:
  python3 pve_fw_export.py                       # writes ./pve-fw-<cluster>-<date>.json
  python3 pve_fw_export.py --pve-dir ./etc-pve -o bundle.json
  python3 pve_fw_export.py -o -                  # print the JSON (to copy and paste it into the web app)
  python3 pve_fw_export.py -o - | gzip > bundle.json.gz
  ssh root@pve1 python3 - -o - < pve_fw_export.py > pve-fw-export.json

Python 3.6+, standard library only. Run it on any node of the cluster
(as root, or as a member of the www-data group to read /etc/pve).

Project: https://github.com/mrwazaby/pve-flow-explorer
"""
import argparse
import datetime
import glob
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

FORMAT = "pve-fw-raw"
VERSION = 1
CONF_KEEP = re.compile(r"^(name|hostname|net\d+|ipconfig\d+|tags|template):")

# pvesh is slow to start (Perl) and goes through SSH for anything on another
# node, so the live calls run a few at a time, each with its own timeout, and
# all of them together within a fixed budget.
LIVE_WORKERS = 6
LIVE_CALL_TIMEOUT = 15
LIVE_BUDGET = 60


def warn(msg):
    print("[!] " + msg, file=sys.stderr)


def info(msg):
    print("[i] " + msg, file=sys.stderr)


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        warn("cannot read %s: %s" % (path, exc))
        return None


def rel(pve, path):
    return os.path.relpath(path, pve).replace(os.sep, "/")


def current_section(text):
    """Lines of a guest .conf before the first snapshot section."""
    out = []
    for line in text.splitlines():
        if line.startswith("["):
            break
        out.append(line)
    return out


def agent_enabled(lines):
    """True if the VM config has the QEMU guest agent enabled ('agent: 1' or 'agent: enabled=1,...')."""
    for line in lines:
        if line.startswith("agent:"):
            for part in line[6:].split(","):
                key, _, val = part.strip().rpartition("=")
                if key in ("", "enabled"):
                    return val.strip().lower() in ("1", "yes", "on", "true")
    return False


def collect(pve):
    """Raw files, filtered guest configs, node names and the VMIDs with the guest agent enabled."""
    files, guests, nodes, agents = {}, {}, [], set()
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
            lines = current_section(txt)
            guests[vmid] = {"node": p.split(os.sep)[-3],
                            "type": "lxc" if kind == "lxc" else "qemu",
                            "conf": "\n".join(l for l in lines if CONF_KEEP.match(l))}
            if kind == "qemu-server" and agent_enabled(lines):
                agents.add(vmid)
    return files, guests, nodes, agents


def cluster_name(pve):
    path = os.path.join(pve, "corosync.conf")
    txt = read(path) if os.path.exists(path) else None
    m = re.search(r"cluster_name:\s*(\S+)", txt or "")
    return m.group(1) if m else None


class Pvesh:
    """Runs 'pvesh get' calls, several at a time, within an overall time budget.

    Each call runs in its own process group, so that killing it also kills the
    SSH session pvesh opens to reach another node.
    """

    def __init__(self):
        self.workers, self.call_timeout, self.budget = LIVE_WORKERS, LIVE_CALL_TIMEOUT, LIVE_BUDGET
        self.lock = threading.Lock()
        self.procs = set()
        self.stopped = False

    @staticmethod
    def kill(proc):
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass

    def get(self, path, timeout=None):
        """Decoded JSON answer, or None on error, timeout or once the budget is spent."""
        cmd = ["pvesh", "get", path, "--output-format", "json"]
        with self.lock:
            if self.stopped:
                return None
            try:
                proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, start_new_session=True)
            except OSError:
                return None
            self.procs.add(proc)
        try:
            out, _ = proc.communicate(timeout=timeout or self.call_timeout)
        except subprocess.TimeoutExpired:
            self.kill(proc)
            proc.stdout.close()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                pass
            return None
        finally:
            with self.lock:
                self.procs.discard(proc)
        if proc.returncode != 0:
            return None
        try:
            return json.loads(out.decode("utf-8", "replace") or "null")
        except ValueError:
            return None

    def get_all(self, paths):
        """Answers for each path, in order; None where the call failed or did not run in time."""
        results = [None] * len(paths)
        todo = queue.Queue()
        for item in enumerate(paths):
            todo.put(item)

        def worker():
            while not self.stopped:
                try:
                    i, path = todo.get_nowait()
                except queue.Empty:
                    return
                results[i] = self.get(path)

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(self.workers, len(paths)))]
        for t in threads:
            t.start()
        deadline = time.monotonic() + self.budget
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
        if any(t.is_alive() for t in threads):
            with self.lock:
                self.stopped = True
                running = list(self.procs)
            for proc in running:
                self.kill(proc)
            for t in threads:
                t.join(5)
            warn("live: stopped after %ds, %d of %d calls answered; the other guests keep "
                 "the IPs from their config" % (self.budget, sum(r is not None for r in results), len(paths)))
        return results


def usable_ip(ip):
    ip = ip.split("/")[0]
    return ip and not ip.startswith(("127.", "fe80", "::1", "169.254."))


def reported_ips(data):
    """IPs from a guest agent answer ({"result": [...]}) or an LXC interface list."""
    ifaces = data.get("result") if isinstance(data, dict) else data
    ips = []
    for iface in ifaces if isinstance(ifaces, list) else []:
        if not isinstance(iface, dict):
            continue
        for a in iface.get("ip-addresses") or []:
            if isinstance(a, dict):
                ips.append(a.get("ip-address") or "")
        for k in ("inet", "inet6"):
            if isinstance(iface.get(k), str):
                ips.append(iface[k])
    return sorted({i.split("/")[0] for i in ips if usable_ip(i)})


def collect_live(agents):
    """Power states, node IPs, and the IPs running guests report (guest agent / LXC interfaces).

    Only VMs with the guest agent enabled are asked: for the others the call can only fail.
    """
    if not shutil.which("pvesh"):
        info("pvesh not found: power states and guest-agent IPs skipped")
        return None
    sh = Pvesh()
    resources = sh.get("/cluster/resources", timeout=30)
    if not isinstance(resources, list):
        warn("pvesh get /cluster/resources failed: power states and guest-agent IPs skipped")
        return None

    live = {"resources": [], "ips": {}, "nodeIps": {}}
    jobs = []  # (kind, key, path)
    for r in resources:
        if r.get("type") in ("qemu", "lxc"):
            live["resources"].append({k: r.get(k) for k in ("vmid", "name", "node", "type", "status")})
            vmid, node = str(r.get("vmid")), r.get("node")
            if r.get("status") != "running":
                continue
            if r["type"] == "lxc":
                jobs.append(("guest", vmid, "/nodes/%s/lxc/%s/interfaces" % (node, vmid)))
            elif vmid in agents:
                jobs.append(("guest", vmid, "/nodes/%s/qemu/%s/agent/network-get-interfaces" % (node, vmid)))
        elif r.get("type") == "node" and r.get("status") == "online":
            jobs.append(("node", r["node"], "/nodes/%s/network" % r["node"]))

    n_guests = sum(1 for j in jobs if j[0] == "guest")
    if jobs:
        info("live: asking %d running guests and %d nodes for their IPs (at most %ds)..." % (
            n_guests, len(jobs) - n_guests, sh.budget))
    for (kind, key, _), data in zip(jobs, sh.get_all([j[2] for j in jobs])):
        if kind == "node":
            if isinstance(data, list):
                ips = [i.get(k) for i in data if isinstance(i, dict)
                       for k in ("address", "address6") if isinstance(i.get(k), str)]
                live["nodeIps"][key] = [i for i in ips if usable_ip(i)]
        else:
            ips = reported_ips(data)
            if ips:
                live["ips"][key] = ips
    info("live: %d guests, %d running guests asked, %d reported IPs" % (
        len(live["resources"]), n_guests, len(live["ips"])))
    return live


def main():
    ap = argparse.ArgumentParser(description="Raw Proxmox VE firewall export (JSON bundle for PVE Flow Explorer)")
    ap.add_argument("--pve-dir", default="/etc/pve", help="PVE config root (default: /etc/pve)")
    ap.add_argument("-o", "--output", help="output file ('-' for stdout)")
    args = ap.parse_args()

    if not os.path.isdir(args.pve_dir):
        sys.exit("Directory not found: %s" % args.pve_dir)

    files, guests, nodes, agents = collect(args.pve_dir)
    if "firewall/cluster.fw" not in files:
        warn("firewall/cluster.fw is missing: was the datacenter firewall ever configured?")

    name = cluster_name(args.pve_dir) or socket.gethostname()
    now = datetime.datetime.now().astimezone()
    pve_version = None
    if shutil.which("pveversion"):
        try:
            pve_version = subprocess.run(["pveversion"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         timeout=5).stdout.decode().strip()
        except (OSError, subprocess.TimeoutExpired):
            pass

    bundle = {
        "format": FORMAT, "version": VERSION,
        "meta": {"cluster": name, "host": socket.gethostname(), "generated": now.isoformat(),
                 "pveVersion": pve_version, "source": os.path.abspath(args.pve_dir)},
        "nodes": nodes, "files": files, "guests": guests,
        # pvesh queries the local cluster, so it only matches a live /etc/pve
        "live": collect_live(agents) if os.path.realpath(args.pve_dir) == "/etc/pve" else None,
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
        print("Open https://pve-flow-explorer.w00tw00t.me and import it.")


if __name__ == "__main__":
    main()
