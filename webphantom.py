#!/usr/bin/env python3
import argparse
import logging
from core import recon, vulns, ai_analyzer, ip_scanner
from core.utils import run_script_yaml

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(prog="webphantom", description="Pentest Web CLI - Kali Linux")
    subparsers = parser.add_subparsers(dest="command")
    
    # Commande de reconnaissance
    recon_cmd = subparsers.add_parser("recon", help="Effectuer une reconnaissance sur une URL cible")
    recon_cmd.add_argument("url", help="URL cible")
    
    # Commande de scan de vulnérabilités
    scan_cmd = subparsers.add_parser("scan", help="Scanner les vulnérabilités d'une URL cible")
    scan_cmd.add_argument("url", help="URL cible")
    
    # Commande d'analyse IA
    ai_cmd = subparsers.add_parser("ai", help="Effectuer une analyse IA sur une URL cible")
    ai_cmd.add_argument("url", help="URL cible")
    
    # Commande d'exécution de script YAML
    run_cmd = subparsers.add_parser("run", help="Exécuter un script YAML")
    run_cmd.add_argument("file", help="Fichier script YAML à exécuter")
    run_cmd.add_argument("--target", help="URL cible pour remplacer celle dans le fichier YAML")
    run_cmd.add_argument("url", nargs="?", help="URL cible (alternative à --target)")
    
    # Commande de scan IP
    ip_scan_cmd = subparsers.add_parser("ip-scan", help="Scanner une adresse IP ou une plage d'adresses IP")
    ip_scan_cmd.add_argument("target", help="Adresse IP ou plage d'adresses IP à scanner (ex: 192.168.1.1 ou 192.168.1.0/24)")
    ip_scan_cmd.add_argument("--tools", nargs="+", help="Outils spécifiques à utiliser pour le scan")
    ip_scan_cmd.add_argument("--output-dir", help="Répertoire de sortie pour les résultats")
    
    # Commande pour exécuter tous les outils
    all_tools_cmd = subparsers.add_parser("all-tools", help="Exécuter tous les outils de scan sur une cible")
    all_tools_cmd.add_argument("target", help="Adresse IP, plage d'adresses IP ou URL à scanner")
    all_tools_cmd.add_argument("--output-dir", help="Répertoire de sortie pour les résultats")
    
    # Commande d'installation des outils
    install_cmd = subparsers.add_parser("install-tools", help="Installer tous les outils nécessaires")
    
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
        logger.info(f"Exécution de tous les outils de scan sur la cible: {args.target}")
        ip_scanner.run_all_tools(args.target, args.output_dir)
    elif args.command == "install-tools":
        logger.info("Installation de tous les outils nécessaires...")
        from core.ip_scanner import ensure_all_tools_installed
        ensure_all_tools_installed()
        logger.info("Installation terminée.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
