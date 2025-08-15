#!/usr/bin/env python3
import argparse
import logging
from core import recon, vulns, ai_analyzer, ip_scanner
from core.utils import run_script_yaml

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(prog="webphantom", description="Web Pentest CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    # Reconnaissance command
    recon_cmd = subparsers.add_parser("recon", help="Run reconnaissance on a target URL")
    recon_cmd.add_argument("url", help="Target URL")
    
    # Basic vulnerability scan
    scan_cmd = subparsers.add_parser("scan", help="Run basic vulnerability tests on a target URL")
    scan_cmd.add_argument("url", help="Target URL")
    
    # AI analysis
    ai_cmd = subparsers.add_parser("ai", help="Run AI-assisted analysis on a target URL")
    ai_cmd.add_argument("url", help="Target URL")
    
    # YAML scenario runner
    run_cmd = subparsers.add_parser("run", help="Execute a YAML scenario")
    run_cmd.add_argument("file", help="YAML script to execute")
    run_cmd.add_argument("--target", help="Target URL to override the one in YAML")
    run_cmd.add_argument("url", nargs="?", help="Target URL (alternative to --target)")
    
    # IP scan
    ip_scan_cmd = subparsers.add_parser("ip-scan", help="Scan an IP or CIDR range")
    ip_scan_cmd.add_argument("target", help="IP address or CIDR to scan (e.g., 192.168.1.1 or 192.168.1.0/24)")
    ip_scan_cmd.add_argument("--tools", nargs="+", help="Specific tools to use for the scan")
    ip_scan_cmd.add_argument("--output-dir", help="Output directory for results")
    
    # Run all tools
    all_tools_cmd = subparsers.add_parser("all-tools", help="Run all scan tools on a target")
    all_tools_cmd.add_argument("target", help="IP, CIDR or URL to scan")
    all_tools_cmd.add_argument("--output-dir", help="Output directory for results")
    
    # Install external tools
    install_cmd = subparsers.add_parser("install-tools", help="Install all required external tools")
    
    args = parser.parse_args()
    
    if args.command == "recon":
        recon.run(args.url)
    elif args.command == "scan":
        vulns.run(args.url)
    elif args.command == "ai":
        ai_analyzer.run(args.url)
    elif args.command == "run":
        target_url = None
        if hasattr(args, 'target') and args.target:
            target_url = args.target
        elif hasattr(args, 'url') and args.url:
            target_url = args.url
        run_script_yaml(args.file, target_url)
    elif args.command == "ip-scan":
        ip_scanner.scan_ip(args.target, args.output_dir, args.tools)
    elif args.command == "all-tools":
        logger.info(f"Running all scan tools on target: {args.target}")
        ip_scanner.run_all_tools(args.target, args.output_dir)
    elif args.command == "install-tools":
        logger.info("Installing all required tools...")
        from core.ip_scanner import ensure_all_tools_installed
        ensure_all_tools_installed()
        logger.info("Installation complete.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
