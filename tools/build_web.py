#!/usr/bin/env python3
"""Build web/index.html: inject the sample bundle into web/src/app.html and wrap it in a full HTML document.

Usage:
  python3 tools/build_web.py                 # writes web/index.html
  python3 tools/build_web.py --fragment X    # also writes the bare page (no <html>/<head>) to X
"""
import argparse
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="Explore Proxmox VE firewall rules as a service map: import a bundle from pve_fw_export.py, filter flows and inspect every rule. Runs entirely in your browser.">
<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0;font:14px system-ui,sans-serif}img{max-width:100%}[hidden]{display:none!important}</style>
</head>
<body>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fragment", help="also write the bare page body to this path")
    args = ap.parse_args()
    src = open(os.path.join(ROOT, "web", "src", "app.html"), encoding="utf-8").read()
    demo = json.load(open(os.path.join(ROOT, "examples", "demo-bundle.json"), encoding="utf-8"))
    data = json.dumps(demo, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    assert "/*__DEMO__*/null" in src, "placeholder not found in web/src/app.html"
    page = src.replace("/*__DEMO__*/null", data)
    out = os.path.join(ROOT, "web", "index.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(HEAD + page + "\n</body>\n</html>\n")
    print("wrote", out)
    if args.fragment:
        with open(args.fragment, "w", encoding="utf-8") as fh:
            fh.write(page)
        print("wrote", args.fragment)


if __name__ == "__main__":
    main()
