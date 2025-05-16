#!/usr/bin/env python3

import argparse
from core import recon, vulns, ai_analyzer
from core.utils import run_script_yaml

def main():
    parser = argparse.ArgumentParser(prog="webphantom", description="Pentest Web CLI - Kali Linux")
    subparsers = parser.add_subparsers(dest="command")

    recon_cmd = subparsers.add_parser("recon")
    recon_cmd.add_argument("url")

    scan_cmd = subparsers.add_parser("scan")
    scan_cmd.add_argument("url")

    ai_cmd = subparsers.add_parser("ai")
    ai_cmd.add_argument("url")

    run_cmd = subparsers.add_parser("run")
    run_cmd.add_argument("file")

    args = parser.parse_args()

    if args.command == "recon":
        recon.run(args.url)
    elif args.command == "scan":
        vulns.run(args.url)
    elif args.command == "ai":
        ai_analyzer.run(args.url)
    elif args.command == "run":
        run_script_yaml(args.file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()