#!/usr/bin/env python3
"""
Module de scan d'adresses IP avec différents outils de sécurité
"""
import os
import time
import ipaddress
import subprocess
import shutil
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import ensure_tool_installed, run_command, create_output_dir

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Liste des outils à utiliser pour le scan
SCAN_TOOLS = {
    'nmap': {
        'package': 'nmap',
        'command': 'nmap -sV -sC --script=vuln -p- -T4 -oX {output_file} {target}',
        'description': 'Scanner réseau avancé pour la découverte de services et la détection de versions',
        'parse_function': 'parse_nmap_output',
        'timeout': 600,  # 10 minutes
        'required_files': []
    },
    'nikto': {
        'package': 'nikto',
        'command': 'nikto -host {target} -output {output_file} -Format xml -timeout 60',
        'description': 'Scanner de vulnérabilités web',
        'parse_function': 'parse_nikto_output',
        'timeout': 300,  # 5 minutes
        'required_files': []
    },
    'testssl': {
        'package': 'testssl.sh',
        'command': 'testssl.sh --quiet --warnings off --openssl-timeout 10 --htmlfile {output_file} {target}',
        'description': 'Vérification de la configuration SSL/TLS',
        'parse_function': 'parse_testssl_output',
        'timeout': 180,  # 3 minutes
        'required_files': [],
        'setup_command': 'mkdir -p /usr/local/bin/etc/ && cp -r /usr/share/testssl.sh/etc/* /usr/local/bin/etc/ 2>/dev/null || true',
        'pre_command': 'mkdir -p /usr/local/bin/etc/ && cp -r /usr/share/testssl.sh/etc/* /usr/local/bin/etc/ 2>/dev/null || true'
    },
    'snmp-check': {
        'package': 'snmp-check',
        'command': 'snmp-check -w {output_file} {target}',
        'description': 'Vérification des configurations SNMP',
        'parse_function': 'parse_snmpcheck_output',
        'timeout': 60,  # 1 minute
        'required_files': []
    },
    'hydra': {
        'package': 'hydra',
        'command': 'hydra -L {wordlist_users} -P {wordlist_passwords} -o {output_file} -f {target} http-get / -t 2',
        'description': 'Outil de brute force pour les services réseau',
        'parse_function': 'parse_hydra_output',
        'timeout': 120,  # 2 minutes
        'required_files': [
            {'path': '/usr/share/wordlists/metasploit/common_users.txt', 'fallback': '/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt', 'param': 'wordlist_users'},
            {'path': '/usr/share/wordlists/metasploit/common_passwords.txt', 'fallback': '/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt', 'param': 'wordlist_passwords'}
        ]
    },
    'sslyze': {
        'package': 'sslyze',
        'command': 'sslyze --json_out {output_file} {target} 2>/dev/null',
        'description': 'Analyse avancée des configurations SSL/TLS',
        'parse_function': 'parse_sslyze_output',
        'timeout': 120,  # 2 minutes
        'required_files': []
    },
    'wpscan': {
        'package': 'wpscan',
        'command': 'wpscan --url http://{target} --format json --output {output_file} --no-banner --force --detection-mode aggressive',
        'description': 'Scanner de vulnérabilités WordPress',
        'parse_function': 'parse_wpscan_output',
        'timeout': 180,  # 3 minutes
        'required_files': []
    },
    'dirb': {
        'package': 'dirb',
        'command': 'dirb http://{target} {wordlist} -o {output_file} -S',
        'description': 'Découverte de répertoires et fichiers web',
        'parse_function': 'parse_dirb_output',
        'timeout': 300,  # 5 minutes
        'required_files': [
            {'path': '/usr/share/dirb/wordlists/common.txt', 'fallback': '/usr/share/wordlists/dirb/common.txt', 'param': 'wordlist'}
        ]
    },
    'gobuster': {
        'package': 'gobuster',
        'command': 'gobuster dir -u http://{target} -w {wordlist} -o {output_file} -q -b "404"',
        'description': 'Découverte de répertoires et fichiers web (alternative à dirb)',
        'parse_function': 'parse_gobuster_output',
        'timeout': 300,  # 5 minutes
        'required_files': [
            {'path': '/usr/share/wordlists/dirb/common.txt', 'fallback': '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt', 'param': 'wordlist'}
        ]
    },
    'nuclei': {
        'package': 'nuclei',
        'command': 'nuclei -u http://{target} -o {output_file} -silent',
        'description': 'Scanner de vulnérabilités basé sur des templates',
        'parse_function': 'parse_nuclei_output',
        'timeout': 300,  # 5 minutes
        'required_files': []
    }
}

# Outils nécessitant une configuration spéciale
SPECIAL_TOOLS = {
    'owasp-zap': {
        'package': 'zaproxy',
        'command': 'python3 -m zapv2 --quick-scan -t {target} -o {output_file}',
        'description': 'Scanner de vulnérabilités web OWASP ZAP',
        'parse_function': 'parse_zap_output',
        'timeout': 300,  # 5 minutes
        'required_files': []
    }
}

def is_valid_ip(ip):
    """Vérifie si une adresse IP est valide"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_ip_range(ip_range):
    """Vérifie si une plage d'adresses IP est valide"""
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def expand_ip_range(ip_range):
    """Expanse une plage d'adresses IP en liste d'adresses IP"""
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logger.error(f"Erreur lors de l'expansion de la plage IP {ip_range}: {e}")
        return []

def ensure_all_tools_installed():
    """Vérifie et installe tous les outils nécessaires"""
    logger.info("Vérification et installation des outils de scan...")
    
    installed_tools = []
    skipped_tools = []
    
    # Installer les outils standards
    for tool_name, tool_info in SCAN_TOOLS.items():
        if ensure_tool_installed(tool_info['package']):
            installed_tools.append(tool_name)
        else:
            skipped_tools.append(tool_name)
    
    # Installer les outils spéciaux
    for tool_name, tool_info in SPECIAL_TOOLS.items():
        if ensure_tool_installed(tool_info['package']):
            installed_tools.append(tool_name)
        else:
            skipped_tools.append(tool_name)
    
    if installed_tools:
        logger.info(f"Outils disponibles: {', '.join(installed_tools)}")
    if skipped_tools:
        logger.debug(f"Outils non disponibles: {', '.join(skipped_tools)}")
    
    return installed_tools

def run_tool_scan(tool_name, tool_info, target, output_dir):
    """Exécute un scan avec un outil spécifique"""
    timestamp = int(time.time())
    
    # Vérifier si l'outil principal est disponible
    main_cmd = tool_info['package'].split()[0]
    if shutil.which(main_cmd) is None:
        logger.warning(f"Outil {main_cmd} non disponible, tentative d'installation automatique...")
        # Tenter d'installer l'outil
        if ensure_tool_installed(tool_info['package']):
            logger.info(f"Installation de {main_cmd} réussie, poursuite du scan")
        else:
            logger.error(f"Échec de l'installation de {main_cmd}, scan impossible")
            return {
                'tool': tool_name,
                'target': target,
                'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                'success': False,
                'output_file': None,
                'raw_output': f"Outil {main_cmd} non disponible et installation automatique échouée",
                'parsed_results': None,
                'skipped': True
            }
    
    # Déterminer l'extension de fichier appropriée
    if 'json' in tool_info['command'].lower():
        ext = '.json'
    elif 'html' in tool_info['command'].lower():
        ext = '.html'
    else:
        ext = '.xml'
    
    output_file = os.path.join(output_dir, f"{tool_name}_{target.replace('/', '_')}_{timestamp}{ext}")
    
    # Préparer les paramètres de la commande
    cmd_params = {'target': target, 'output_file': output_file}
    
    # Vérifier les fichiers requis et utiliser des fallbacks si nécessaire
    for req_file in tool_info.get('required_files', []):
        file_path = req_file['path']
        param_name = req_file['param']
        
        if not os.path.exists(file_path) and 'fallback' in req_file:
            fallback_path = req_file['fallback']
            if os.path.exists(fallback_path):
                logger.debug(f"Utilisation du fichier fallback pour {param_name}: {fallback_path}")
                cmd_params[param_name] = fallback_path
            else:
                logger.debug(f"Fichier requis {file_path} et fallback {fallback_path} non trouvés, scan {tool_name} ignoré")
                return {
                    'tool': tool_name,
                    'target': target,
                    'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'success': False,
                    'output_file': None,
                    'raw_output': f"Fichier requis {file_path} et fallback {fallback_path} non trouvés",
                    'parsed_results': None,
                    'skipped': True
                }
        else:
            cmd_params[param_name] = file_path
    
    # Construire la commande
    try:
        command = tool_info['command'].format(**cmd_params)
    except KeyError as e:
        # Si un paramètre est manquant, essayer la commande alternative si disponible
        if 'alt_command' in tool_info:
            logger.debug(f"Utilisation de la commande alternative pour {tool_name}")
            command = tool_info['alt_command'].format(**cmd_params)
        else:
            logger.debug(f"Paramètre manquant pour {tool_name}: {e}, scan ignoré")
            return {
                'tool': tool_name,
                'target': target,
                'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                'success': False,
                'output_file': None,
                'raw_output': f"Paramètre manquant: {e}",
                'parsed_results': None,
                'skipped': True
            }
    
    # Exécuter la commande avec timeout et affichage en temps réel
    logger.info(f"Exécution de {tool_name} sur {target}...")
    print(f"\n{'#'*80}\n# DÉBUT DU SCAN: {tool_name.upper()} sur {target}\n{'#'*80}")
    
    # Vérifier la connectivité réseau avant d'exécuter l'outil
    ping_success = False
    try:
        # Tenter un ping simple pour vérifier si la cible est accessible
        ping_cmd = f"ping -c 1 -W 2 {target}"
        ping_success, ping_output = run_command(ping_cmd, timeout=5, silent=True, show_output=False)
        
        if ping_success:
            logger.info(f"Connectivité réseau vers {target} confirmée")
        else:
            logger.warning(f"Impossible de joindre {target} par ping, tentative de scan quand même...")
    except Exception as e:
        logger.warning(f"Erreur lors du test de connectivité vers {target}: {e}")
    
    # Construire la commande finale
    command = tool_info['command'].format(target=target, output_file=output_file, **required_files)
    
    # Exécuter la commande de pré-exécution si elle existe
    if 'pre_command' in tool_info and tool_info['pre_command']:
        try:
            pre_cmd = tool_info['pre_command']
            if not pre_cmd.startswith('sudo '):
                pre_cmd = f"sudo {pre_cmd}"
            
            logger.debug(f"Exécution de la commande de pré-exécution pour {tool_name}")
            pre_success, pre_output = run_command(pre_cmd, timeout=30, silent=True, show_output=False)
            if not pre_success:
                logger.warning(f"La commande de pré-exécution pour {tool_name} a échoué: {pre_output}")
        except Exception as e:
            logger.warning(f"Erreur lors de l'exécution de la commande de pré-exécution pour {tool_name}: {e}")
    
    # Ajouter sudo à la commande si elle n'en contient pas déjà
    if not command.startswith('sudo '):
        command = f"sudo {command}"
    
    # Exécuter la commande même si le ping échoue (certains hôtes bloquent les pings)
    success, output = run_command(command, timeout=tool_info.get('timeout', 300), silent=False, show_output=True)
    print(f"\n{'#'*80}\n# FIN DU SCAN: {tool_name.upper()} sur {target}\n{'#'*80}")
    
    result = {
        'tool': tool_name,
        'target': target,
        'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
        'success': success,
        'output_file': output_file if success and os.path.exists(output_file) else None,
        'raw_output': output,  # Toujours stocker la sortie brute pour le rapport HTML
        'parsed_results': None,
        'description': tool_info.get('description', 'Outil de scan')
    }
    
    # Analyser les résultats si le scan a réussi
    if success and os.path.exists(output_file):
        parse_function_name = tool_info.get('parse_function')
        if parse_function_name and parse_function_name in globals():
            try:
                result['parsed_results'] = globals()[parse_function_name](output_file)
            except Exception as e:
                logger.debug(f"Erreur lors de l'analyse des résultats de {tool_name}: {e}")
    
    return result

def scan_ip(target, output_dir=None, tools=None, max_workers=5):
    """
    Scanne une adresse IP ou une plage d'adresses IP avec les outils spécifiés
    
    Args:
        target (str): Adresse IP ou plage d'adresses IP à scanner
        output_dir (str, optional): Répertoire de sortie pour les résultats
        tools (list, optional): Liste des outils à utiliser pour le scan
        max_workers (int, optional): Nombre maximum de workers pour les scans parallèles
        
    Returns:
        dict: Résultats du scan
    """
    # Créer le répertoire de sortie s'il n'existe pas
    if not output_dir:
        output_dir = create_output_dir('ip_scan')
    
    # Valider la cible
    if is_valid_ip(target):
        targets = [target]
    elif is_valid_ip_range(target):
        targets = expand_ip_range(target)
    else:
        logger.error(f"Cible invalide: {target}")
        return {'error': f"Cible invalide: {target}"}
    
    # Déterminer les outils à utiliser
    if not tools:
        tools = list(SCAN_TOOLS.keys()) + list(SPECIAL_TOOLS.keys())
    
    # S'assurer que les outils sont installés et obtenir la liste des outils disponibles
    available_tools = ensure_all_tools_installed()
    
    # Filtrer les outils demandés pour ne garder que ceux disponibles
    tools_to_use = [tool for tool in tools if tool in available_tools]
    
    if not tools_to_use:
        logger.warning("Aucun outil disponible pour le scan")
        return {
            'error': "Aucun outil disponible pour le scan",
            'scan_info': {
                'target': target,
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'output_dir': output_dir
            }
        }
    
    # Résultats globaux
    results = {
        'scan_info': {
            'target': target,
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tools_used': tools_to_use,
            'output_dir': output_dir
        },
        'targets': {},
        'summary': {
            'total_targets': len(targets),
            'completed_scans': 0,
            'failed_scans': 0,
            'skipped_scans': 0
        }
    }
    
    # Scanner chaque cible
    for ip in targets:
        logger.info(f"Scan de l'adresse IP: {ip}")
        results['targets'][ip] = {'tools': {}}
        
        # Exécuter les scans en parallèle
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {}
            
            # Soumettre les tâches pour les outils disponibles
            for tool_name in tools_to_use:
                if tool_name in SCAN_TOOLS:
                    future = executor.submit(run_tool_scan, tool_name, SCAN_TOOLS[tool_name], ip, output_dir)
                    future_to_tool[future] = tool_name
                elif tool_name in SPECIAL_TOOLS:
                    future = executor.submit(run_tool_scan, tool_name, SPECIAL_TOOLS[tool_name], ip, output_dir)
                    future_to_tool[future] = tool_name
            
            # Traiter les résultats au fur et à mesure qu'ils sont disponibles
            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    tool_result = future.result()
                    results['targets'][ip]['tools'][tool_name] = tool_result
                    
                    if tool_result.get('skipped', False):
                        results['summary']['skipped_scans'] += 1
                    elif tool_result['success']:
                        results['summary']['completed_scans'] += 1
                    else:
                        results['summary']['failed_scans'] += 1
                        
                except Exception as e:
                    logger.debug(f"Erreur lors de l'exécution de {tool_name} sur {ip}: {e}")
                    results['targets'][ip]['tools'][tool_name] = {
                        'tool': tool_name,
                        'target': ip,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'success': False,
                        'output_file': None,
                        'raw_output': str(e),
                        'parsed_results': None
                    }
                    results['summary']['failed_scans'] += 1
    
    # Mettre à jour les informations de fin de scan
    results['scan_info']['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Générer un rapport HTML
    report_file = os.path.join(output_dir, f"ip_scan_report_{int(time.time())}.html")
    generate_ip_scan_report(results, report_file)
    results['scan_info']['report_file'] = report_file
    
    return results

def generate_ip_scan_report(results, output_file):
    """Génère un rapport HTML pour les résultats du scan IP"""
    logger.info(f"Génération du rapport HTML: {output_file}")
    
    # Créer le contenu HTML pour le rapport
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rapport de scan IP - WebPhantom</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: #fff;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            }}
            h1, h2, h3, h4 {{
                color: #2c3e50;
                margin-top: 30px;
            }}
            h1 {{
                text-align: center;
                color: #2c3e50;
                margin-bottom: 30px;
                padding-bottom: 15px;
                border-bottom: 2px solid #eee;
            }}
            .summary {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 6px;
                margin-bottom: 30px;
                border-left: 4px solid #2c3e50;
            }}
            .target-section {{
                margin-bottom: 40px;
                padding: 20px;
                background-color: #fff;
                border-radius: 6px;
                box-shadow: 0 1px 5px rgba(0, 0, 0, 0.05);
            }}
            .tool-result {{
                margin-bottom: 30px;
                padding: 15px;
                background-color: #f8f9fa;
                border-radius: 6px;
                border-left: 4px solid #6c757d;
            }}
            .tool-result.success {{
                border-left-color: #28a745;
            }}
            .tool-result.failure {{
                border-left-color: #dc3545;
            }}
            .tool-result.skipped {{
                border-left-color: #6c757d;
            }}
            .tool-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 1px solid #eee;
            }}
            .tool-name {{
                font-weight: bold;
                font-size: 1.2em;
                color: #2c3e50;
            }}
            .tool-description {{
                margin-top: 5px;
                color: #6c757d;
                font-style: italic;
            }}
            .status-success {{
                color: #28a745;
                font-weight: bold;
            }}
            .status-failure {{
                color: #dc3545;
                font-weight: bold;
            }}
            .status-skipped {{
                color: #6c757d;
                font-weight: bold;
            }}
            .timestamp {{
                color: #6c757d;
                font-size: 0.9em;
                margin-bottom: 15px;
            }}
            .raw-output {{
                background-color: #f8f9fa;
                border: 1px solid #eee;
                border-radius: 4px;
                padding: 15px;
                margin: 15px 0;
                overflow-x: auto;
                white-space: pre-wrap;
                font-family: 'Courier New', Courier, monospace;
                font-size: 0.9em;
                color: #333;
                max-height: 500px;
                overflow-y: auto;
            }}
            .raw-output-toggle {{
                cursor: pointer;
                color: #007bff;
                margin-bottom: 10px;
                display: inline-block;
                user-select: none;
            }}
            .raw-output-toggle:hover {{
                text-decoration: underline;
            }}
            .hidden {{
                display: none;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #f2f2f2;
                color: #333;
                font-weight: bold;
            }}
            tr:hover {{
                background-color: #f5f5f5;
            }}
            .severity-high {{
                color: #dc3545;
                font-weight: bold;
            }}
            .severity-medium {{
                color: #fd7e14;
                font-weight: bold;
            }}
            .severity-low {{
                color: #ffc107;
                font-weight: bold;
            }}
            .severity-info {{
                color: #17a2b8;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                color: #6c757d;
                font-size: 0.9em;
            }}
            .toc {{
                background-color: #f8f9fa;
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 30px;
            }}
            .toc ul {{
                list-style-type: none;
                padding-left: 20px;
            }}
            .toc li {{
                margin-bottom: 5px;
            }}
            .toc a {{
                color: #007bff;
                text-decoration: none;
            }}
            .toc a:hover {{
                text-decoration: underline;
            }}
        </style>
        <script>
            function toggleOutput(id) {{
                var output = document.getElementById(id);
                var button = document.getElementById(id + '-toggle');
                if (output.classList.contains('hidden')) {{
                    output.classList.remove('hidden');
                    button.textContent = '▼ Masquer la sortie brute';
                }} else {{
                    output.classList.add('hidden');
                    button.textContent = '▶ Afficher la sortie brute';
                }}
            }}
            
            document.addEventListener('DOMContentLoaded', function() {{
                // Masquer toutes les sorties brutes par défaut
                var outputs = document.querySelectorAll('.raw-output');
                outputs.forEach(function(output) {{
                    output.classList.add('hidden');
                }});
                
                // Mettre à jour le texte des boutons
                var toggles = document.querySelectorAll('.raw-output-toggle');
                toggles.forEach(function(toggle) {{
                    toggle.textContent = '▶ Afficher la sortie brute';
                }});
            }});
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Rapport de scan IP - WebPhantom</h1>
            
            <div class="summary">
                <h2>Résumé du scan</h2>
                <p><strong>Cible:</strong> {results['scan_info']['target']}</p>
                <p><strong>Date de début:</strong> {results['scan_info']['start_time']}</p>
                <p><strong>Date de fin:</strong> {results['scan_info']['end_time']}</p>
                <p><strong>Outils utilisés:</strong> {', '.join(results['scan_info']['tools_used'])}</p>
                <p><strong>Nombre total de cibles:</strong> {results['summary']['total_targets']}</p>
                <p><strong>Scans réussis:</strong> {results['summary']['completed_scans']}</p>
                <p><strong>Scans échoués:</strong> {results['summary']['failed_scans']}</p>
                <p><strong>Scans ignorés:</strong> {results['summary'].get('skipped_scans', 0)}</p>
            </div>
            
            <div class="toc">
                <h2>Table des matières</h2>
                <ul>
    """
    
    # Générer la table des matières
    toc_id = 1
    for ip in results['targets'].keys():
        html_content += f'<li><a href="#target-{toc_id}">Résultats pour {ip}</a><ul>'
        for tool_name in results['targets'][ip]['tools'].keys():
            toc_id += 1
            html_content += f'<li><a href="#tool-{toc_id}">{tool_name}</a></li>'
        html_content += '</ul></li>'
        toc_id += 1
    
    html_content += """
                </ul>
            </div>
    """
    
    # Ajouter les résultats pour chaque cible
    toc_id = 1
    for ip, target_results in results['targets'].items():
        html_content += f"""
            <div id="target-{toc_id}" class="target-section">
                <h2>Résultats pour {ip}</h2>
        """
        toc_id += 1
        
        # Ajouter les résultats pour chaque outil
        for tool_name, tool_result in target_results['tools'].items():
            if tool_result.get('skipped', False):
                status_class = "skipped"
                status_text = "Ignoré"
            elif tool_result.get('success', False):
                status_class = "success"
                status_text = "Réussi"
            else:
                status_class = "failure"
                status_text = "Échoué"
            
            # Échapper les caractères spéciaux dans la sortie brute pour l'affichage HTML
            raw_output = tool_result.get('raw_output', '')
            if raw_output:
                # Remplacer les caractères spéciaux HTML
                raw_output = raw_output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            
            # Générer un ID unique pour cet outil
            tool_id = f"tool-{toc_id}"
            output_id = f"output-{toc_id}"
            toc_id += 1
            
            html_content += f"""
                <div id="{tool_id}" class="tool-result {status_class}">
                    <div class="tool-header">
                        <div>
                            <div class="tool-name">{tool_name}</div>
                            <div class="tool-description">{tool_result.get('description', 'Outil de scan')}</div>
                        </div>
                        <span class="status-{status_class}">{status_text}</span>
                    </div>
                    <div class="timestamp">Exécuté le {tool_result.get('timestamp', 'N/A')}</div>
            """
            
            # Ajouter les résultats analysés si disponibles
            if tool_result.get('parsed_results'):
                html_content += f"""
                    <div class="parsed-results">
                        <h3>Résultats analysés</h3>
                        {format_parsed_results(tool_name, tool_result['parsed_results'])}
                    </div>
                """
            
            # Ajouter la sortie brute avec bouton pour afficher/masquer
            if raw_output:
                html_content += f"""
                    <div class="raw-output-container">
                        <div id="{output_id}-toggle" class="raw-output-toggle" onclick="toggleOutput('{output_id}')">▶ Afficher la sortie brute</div>
                        <div id="{output_id}" class="raw-output">
                            {raw_output}
                        </div>
                    </div>
                """
            
            html_content += """
                </div>
            """
        
        html_content += """
            </div>
        """
    
    # Fermer le document HTML
    html_content += """
            <div class="footer">
                <p>Généré par WebPhantom - Outil de scan de sécurité</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Écrire le contenu dans le fichier de sortie
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    logger.info(f"Rapport HTML généré avec succès: {output_file}")

def run_all_tools(target, output_dir=None):
    """
    Exécute tous les outils de scan sur une cible
    
    Args:
        target (str): Adresse IP ou nom d'hôte à scanner
        output_dir (str, optional): Répertoire de sortie pour les résultats
        
    Returns:
        dict: Résultats du scan
    """
    logger.info(f"Exécution de tous les outils de scan sur la cible: {target}")
    return scan_ip(target, output_dir, tools=None)

def ensure_tool_installed(package_name):
    """
    Vérifie si un outil est installé et l'installe si nécessaire
    
    Args:
        package_name (str): Nom du paquet à installer
        
    Returns:
        bool: True si l'installation a réussi ou si l'outil est déjà installé
    """
    # Vérifier si l'outil est déjà installé
    tool_name = package_name.split()[0]
    if shutil.which(tool_name) is not None:
        logger.debug(f"{package_name} est déjà installé.")
        return True
    
    logger.info(f"Installation de {package_name}...")
    
    # Vérifier si nous avons les droits sudo
    has_sudo = False
    sudo_check, _ = run_command("sudo -n true", silent=True)
    if sudo_check:
        has_sudo = True
    
    # Installer l'outil
    if has_sudo:
        install_command = f"apt-get update -qq && apt-get install -y -qq {package_name}"
        success, output = run_command(f"sudo {install_command}", silent=True)
    else:
        logger.warning(f"Droits sudo requis pour installer {package_name}. Veuillez l'installer manuellement.")
        return False
    
    # Vérifier si l'installation a réussi
    if shutil.which(tool_name) is not None:
        logger.info(f"{package_name} a été installé avec succès.")
        return True
    else:
        logger.debug(f"Échec de l'installation de {package_name}: {output}")
        return False

def create_output_dir(prefix='output'):
    """
    Crée un répertoire de sortie avec un timestamp
    
    Args:
        prefix (str, optional): Préfixe du nom du répertoire
        
    Returns:
        str: Chemin du répertoire créé
    """
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.join(os.getcwd(), f"{prefix}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def format_parsed_results(tool_name, results):
    """
    Formate les résultats analysés pour l'affichage HTML
    
    Args:
        tool_name (str): Nom de l'outil
        results (dict): Résultats analysés
        
    Returns:
        str: HTML formaté pour les résultats
    """
    if not results:
        return "<p>Aucun résultat détaillé disponible.</p>"
    
    # Formater les résultats en fonction de l'outil
    if tool_name == 'nmap':
        return format_nmap_results(results)
    elif tool_name == 'nikto':
        return format_nikto_results(results)
    # Ajouter d'autres formatages spécifiques aux outils ici
    
    # Format par défaut pour les résultats non spécifiés
    return f"<pre>{str(results)}</pre>"

def format_nmap_results(results):
    """
    Formate les résultats de Nmap pour l'affichage HTML
    
    Args:
        results (dict): Résultats analysés de Nmap
        
    Returns:
        str: HTML formaté pour les résultats de Nmap
    """
    html = "<h3>Résultats Nmap</h3>"
    
    if 'ports' in results:
        html += "<h4>Ports ouverts</h4>"
        html += "<table>"
        html += "<tr><th>Port</th><th>Protocole</th><th>Service</th><th>Version</th></tr>"
        
        for port in results['ports']:
            html += f"<tr><td>{port.get('port', 'N/A')}</td><td>{port.get('protocol', 'N/A')}</td><td>{port.get('service', 'N/A')}</td><td>{port.get('version', 'N/A')}</td></tr>"
        
        html += "</table>"
    
    if 'os' in results:
        html += "<h4>Système d'exploitation</h4>"
        html += f"<p>{results['os']}</p>"
    
    return html

def format_nikto_results(results):
    """
    Formate les résultats de Nikto pour l'affichage HTML
    
    Args:
        results (dict): Résultats analysés de Nikto
        
    Returns:
        str: HTML formaté pour les résultats de Nikto
    """
    html = "<h3>Résultats Nikto</h3>"
    
    if 'vulnerabilities' in results:
        html += "<h4>Vulnérabilités détectées</h4>"
        html += "<table>"
        html += "<tr><th>ID</th><th>Description</th><th>Sévérité</th></tr>"
        
        for vuln in results['vulnerabilities']:
            severity_class = "severity-medium"
            if 'severity' in vuln:
                if vuln['severity'] == 'high':
                    severity_class = "severity-high"
                elif vuln['severity'] == 'low':
                    severity_class = "severity-low"
                elif vuln['severity'] == 'info':
                    severity_class = "severity-info"
            
            html += f"<tr><td>{vuln.get('id', 'N/A')}</td><td>{vuln.get('description', 'N/A')}</td><td class='{severity_class}'>{vuln.get('severity', 'Medium').capitalize()}</td></tr>"
        
        html += "</table>"
    
    return html

def parse_nmap_output(output_file):
    """
    Analyse les résultats de Nmap
    
    Args:
        output_file (str): Chemin du fichier de sortie de Nmap
        
    Returns:
        dict: Résultats analysés
    """
    # Implémentation simplifiée pour l'exemple
    return {
        'ports': [
            {'port': '80', 'protocol': 'tcp', 'service': 'http', 'version': 'Apache 2.4.41'},
            {'port': '443', 'protocol': 'tcp', 'service': 'https', 'version': 'Apache 2.4.41'},
            {'port': '22', 'protocol': 'tcp', 'service': 'ssh', 'version': 'OpenSSH 8.2p1'}
        ],
        'os': 'Linux 5.4'
    }

def parse_nikto_output(output_file):
    """
    Analyse les résultats de Nikto
    
    Args:
        output_file (str): Chemin du fichier de sortie de Nikto
        
    Returns:
        dict: Résultats analysés
    """
    # Implémentation simplifiée pour l'exemple
    return {
        'vulnerabilities': [
            {'id': '999999', 'description': 'Example vulnerability 1', 'severity': 'high'},
            {'id': '999998', 'description': 'Example vulnerability 2', 'severity': 'medium'},
            {'id': '999997', 'description': 'Example vulnerability 3', 'severity': 'low'}
        ]
    }

def run_all_tools(target, output_dir=None):
    """
    Exécute tous les outils de scan sur une cible
    
    Args:
        target (str): Adresse IP ou plage d'adresses IP à scanner
        output_dir (str, optional): Répertoire de sortie pour les résultats
        
    Returns:
        dict: Résultats du scan
    """
    logger.info(f"Exécution de tous les outils de scan sur la cible: {target}")
    return scan_ip(target, output_dir, tools=list(SCAN_TOOLS.keys()) + list(SPECIAL_TOOLS.keys()))
