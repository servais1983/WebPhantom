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
        'timeout': 600  # 10 minutes
    },
    'nikto': {
        'package': 'nikto',
        'command': 'nikto -host {target} -output {output_file} -Format xml -timeout 60',
        'description': 'Scanner de vulnérabilités web',
        'parse_function': 'parse_nikto_output',
        'timeout': 300  # 5 minutes
    },
    'testssl': {
        'package': 'testssl.sh',
        'command': 'testssl.sh --quiet --warnings off --openssl-timeout 10 --htmlfile {output_file} {target} || echo "TestSSL scan completed with warnings"',
        'description': 'Analyse de la configuration SSL/TLS',
        'parse_function': 'parse_testssl_output',
        'timeout': 300,  # 5 minutes
        'pre_command': 'mkdir -p /usr/local/bin/etc/ && cp -r /usr/share/testssl.sh/etc/* /usr/local/bin/etc/ 2>/dev/null || echo "TestSSL config files not found"'
    },
    'snmp-check': {
        'package': 'snmp-check',
        'command': 'snmp-check -w {output_file} {target}',
        'description': 'Vérification des configurations SNMP',
        'parse_function': 'parse_snmpcheck_output',
        'timeout': 60  # 1 minute
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
        'timeout': 120  # 2 minutes
    },
    'wpscan': {
        'package': 'wpscan',
        'command': 'wpscan --url http://{target} --format json --output {output_file} --no-banner --force --detection-mode aggressive',
        'description': 'Scanner de vulnérabilités WordPress',
        'parse_function': 'parse_wpscan_output',
        'timeout': 180  # 3 minutes
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
        'command': 'gobuster dir -u http://{target} -w {wordlist} -o {output_file} -q -k -b "404" || echo "Gobuster scan completed with warnings"',
        'description': 'Scanner de répertoires et fichiers',
        'parse_function': 'parse_gobuster_output',
        'timeout': 300,  # 5 minutes
        'required_files': [
            {'path': '/usr/share/wordlists/dirb/common.txt', 'fallback': '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt', 'param': 'wordlist'}
        ]
    },
    'nuclei': {
        'package': 'nuclei',
        'command': 'nuclei -u http://{target} -o {output_file} -silent -mc 200,201,202,203,204,301,302,307,401,403,405,500 || echo "Nuclei scan completed with warnings"',
        'description': 'Scanner de vulnérabilités Nuclei',
        'parse_function': 'parse_nuclei_output',
        'timeout': 300  # 5 minutes
    }
}

# Outils nécessitant une configuration spéciale
SPECIAL_TOOLS = {
    'owasp-zap': {
        'package': 'python3-zapv2',
        'command': 'python3 -c "from zapv2 import ZAPv2; zap = ZAPv2(); print(\'Scan ZAP démarré\'); zap.urlopen(\'http://{target}\'); zap.spider.scan(\'http://{target}\'); print(\'Scan ZAP terminé\'); with open(\'{output_file}\', \'w\') as f: f.write(str(zap.core.alerts()))" || echo "ZAP scan skipped - install python3-zapv2"',
        'description': 'Scanner de vulnérabilités web OWASP ZAP',
        'parse_function': 'parse_zap_output',
        'timeout': 300  # 5 minutes
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
                'skipped': True,
                'description': tool_info.get('description', 'Outil de scan')
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
                    'skipped': True,
                    'description': tool_info.get('description', 'Outil de scan')
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
                'skipped': True,
                'description': tool_info.get('description', 'Outil de scan')
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
    # Utiliser un timeout plus strict pour éviter les blocages
    actual_timeout = min(tool_info.get('timeout', 300), 300)  # Maximum 5 minutes par outil
    success, output = run_command(command, timeout=actual_timeout, silent=False, show_output=True)
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
        'results': []
    }
    
    # Scanner chaque cible avec chaque outil
    for target_ip in targets:
        logger.info(f"Scan de l'adresse IP: {target_ip}")
        
        # Utiliser ThreadPoolExecutor pour exécuter les scans en parallèle
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Soumettre les tâches
            future_to_tool = {}
            for tool_name in tools_to_use:
                if tool_name in SCAN_TOOLS:
                    tool_info = SCAN_TOOLS[tool_name]
                elif tool_name in SPECIAL_TOOLS:
                    tool_info = SPECIAL_TOOLS[tool_name]
                else:
                    continue
                
                future = executor.submit(run_tool_scan, tool_name, tool_info, target_ip, output_dir)
                future_to_tool[future] = tool_name
            
            # Récupérer les résultats au fur et à mesure qu'ils sont disponibles
            # Ajouter un timeout global pour éviter les blocages
            global_timeout = 1800  # 30 minutes maximum pour tous les scans
            start_time = time.time()
            
            # Utiliser une liste pour suivre les futures terminés
            completed_futures = []
            
            # Boucle principale avec timeout global
            while len(completed_futures) < len(future_to_tool) and time.time() - start_time < global_timeout:
                try:
                    # Attendre le prochain future avec un timeout court pour pouvoir vérifier le timeout global
                    for future in as_completed(
                        [f for f in future_to_tool.keys() if f not in completed_futures], 
                        timeout=10
                    ):
                        if future not in completed_futures:
                            completed_futures.append(future)
                            tool_name = future_to_tool[future]
                            try:
                                result = future.result()
                                results['results'].append(result)
                            except Exception as e:
                                logger.error(f"Erreur lors du scan avec {tool_name}: {e}")
                                results['results'].append({
                                    'tool': tool_name,
                                    'target': target_ip,
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'success': False,
                                    'output_file': None,
                                    'raw_output': f"Erreur: {e}",
                                    'parsed_results': None,
                                    'skipped': True,
                                    'description': "Erreur lors de l'exécution"
                                })
                except Exception as e:
                    # Gérer les erreurs de timeout ou autres exceptions dans as_completed
                    logger.warning(f"Erreur lors de l'attente des résultats: {e}")
                    # Continuer la boucle pour vérifier à nouveau les futures
                    continue
            
            # Gérer les futures qui n'ont pas été complétés (timeout)
            for future, tool_name in future_to_tool.items():
                if future not in completed_futures:
                    # Annuler le future s'il est toujours en cours
                    future.cancel()
                    logger.warning(f"Timeout global atteint pour {tool_name}, scan annulé")
                    
                    # Récupérer l'info de l'outil pour la description
                    tool_description = "Outil de scan"
                    if tool_name in SCAN_TOOLS:
                        tool_description = SCAN_TOOLS[tool_name].get('description', tool_description)
                    elif tool_name in SPECIAL_TOOLS:
                        tool_description = SPECIAL_TOOLS[tool_name].get('description', tool_description)
                    
                    results['results'].append({
                        'tool': tool_name,
                        'target': target_ip,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'success': False,
                        'output_file': None,
                        'raw_output': "Timeout global atteint, scan annulé",
                        'parsed_results': None,
                        'skipped': True,
                        'description': tool_description
                    })
    
    # Générer le rapport HTML
    report_file = generate_ip_scan_report(results, output_dir)
    results['scan_info']['report_file'] = report_file
    results['scan_info']['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return results

def generate_ip_scan_report(results, output_dir):
    """
    Génère un rapport HTML pour les résultats du scan IP
    
    Args:
        results (dict): Résultats du scan
        output_dir (str): Répertoire de sortie pour le rapport
        
    Returns:
        str: Chemin du fichier de rapport
    """
    timestamp = int(time.time())
    report_file = os.path.join(output_dir, f"ip_scan_report_{timestamp}.html")
    
    # Compter les scans réussis, échoués et ignorés
    scan_results = results.get('results', [])
    success_count = sum(1 for r in scan_results if r.get('success', False))
    failed_count = sum(1 for r in scan_results if not r.get('success', False) and not r.get('skipped', False))
    skipped_count = sum(1 for r in scan_results if r.get('skipped', False))
    
    # Créer le contenu HTML
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de scan IP - WebPhantom</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary-item {{
            margin-bottom: 10px;
        }}
        .tool-section {{
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
        }}
        .tool-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: #f8f9fa;
            padding: 10px;
            margin: -15px -15px 15px -15px;
            border-bottom: 1px solid #ddd;
            border-radius: 5px 5px 0 0;
        }}
        .tool-title {{
            margin: 0;
            font-size: 1.2em;
        }}
        .success {{
            color: #28a745;
        }}
        .failed {{
            color: #dc3545;
        }}
        .skipped {{
            color: #ffc107;
        }}
        .output {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 0.9em;
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #ddd;
        }}
        .toggle-btn {{
            background-color: #3498db;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
        }}
        .toggle-btn:hover {{
            background-color: #2980b9;
        }}
        .hidden {{
            display: none;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .target-section {{
            margin-bottom: 30px;
            padding: 15px;
            background-color: #e9ecef;
            border-radius: 5px;
        }}
        .toc {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .toc ul {{
            list-style-type: none;
            padding-left: 20px;
        }}
        .toc li {{
            margin-bottom: 5px;
        }}
        .toc a {{
            text-decoration: none;
            color: #3498db;
        }}
        .toc a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport de scan IP - WebPhantom</h1>
        
        <div class="summary">
            <h2>Résumé</h2>
            <div class="summary-item"><strong>Cible:</strong> {results['scan_info']['target']}</div>
            <div class="summary-item"><strong>Date de début:</strong> {results['scan_info']['start_time']}</div>
            <div class="summary-item"><strong>Date de fin:</strong> {results['scan_info'].get('end_time', 'En cours...')}</div>
            <div class="summary-item"><strong>Outils utilisés:</strong> {', '.join(results['scan_info']['tools_used'])}</div>
            <div class="summary-item"><strong>Scans réussis:</strong> <span class="success">{success_count}</span></div>
            <div class="summary-item"><strong>Scans échoués:</strong> <span class="failed">{failed_count}</span></div>
            <div class="summary-item"><strong>Scans ignorés:</strong> <span class="skipped">{skipped_count}</span></div>
        </div>
        
        <div class="toc">
            <h2>Table des matières</h2>
            <ul>
"""
    
    # Ajouter les entrées de la table des matières
    for result in scan_results:
        tool_name = result.get('tool', 'Inconnu')
        status_class = "success" if result.get('success', False) else "failed" if not result.get('skipped', False) else "skipped"
        status_text = "Réussi" if result.get('success', False) else "Échoué" if not result.get('skipped', False) else "Ignoré"
        html_content += f'                <li><a href="#{tool_name}">{tool_name}</a> - <span class="{status_class}">{status_text}</span></li>\n'
    
    html_content += """            </ul>
        </div>
        
        <h2>Résultats détaillés</h2>
"""
    
    # Ajouter les sections pour chaque outil
    for result in scan_results:
        tool_name = result.get('tool', 'Inconnu')
        target = result.get('target', 'Inconnu')
        timestamp = result.get('timestamp', 'Inconnu')
        success = result.get('success', False)
        skipped = result.get('skipped', False)
        output_file = result.get('output_file', None)
        raw_output = result.get('raw_output', 'Aucune sortie')
        description = result.get('description', 'Aucune description')
        
        status_class = "success" if success else "failed" if not skipped else "skipped"
        status_text = "Réussi" if success else "Échoué" if not skipped else "Ignoré"
        
        html_content += f"""
        <div class="tool-section" id="{tool_name}">
            <div class="tool-header">
                <h3 class="tool-title">{tool_name}</h3>
                <span class="{status_class}">{status_text}</span>
            </div>
            <div class="summary-item"><strong>Description:</strong> {description}</div>
            <div class="summary-item"><strong>Cible:</strong> {target}</div>
            <div class="summary-item"><strong>Horodatage:</strong> {timestamp}</div>
            <div class="summary-item"><strong>Fichier de sortie:</strong> {output_file if output_file else 'Aucun'}</div>
            
            <h4>Sortie brute <button class="toggle-btn" onclick="toggleOutput('{tool_name}_output')">Afficher/Masquer</button></h4>
            <div id="{tool_name}_output" class="output hidden">{raw_output}</div>
        </div>
"""
    
    # Fermer le HTML
    html_content += """
        <script>
            function toggleOutput(id) {
                var element = document.getElementById(id);
                if (element.classList.contains('hidden')) {
                    element.classList.remove('hidden');
                } else {
                    element.classList.add('hidden');
                }
            }
        </script>
    </div>
</body>
</html>
"""
    
    # Écrire le contenu dans le fichier
    with open(report_file, 'w') as f:
        f.write(html_content)
    
    return report_file

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

# Fonctions d'analyse des résultats pour chaque outil
def parse_nmap_output(output_file):
    """Analyse les résultats de Nmap"""
    # Implémentation à venir
    return None

def parse_nikto_output(output_file):
    """Analyse les résultats de Nikto"""
    # Implémentation à venir
    return None

def parse_testssl_output(output_file):
    """Analyse les résultats de TestSSL"""
    # Implémentation à venir
    return None

def parse_snmpcheck_output(output_file):
    """Analyse les résultats de SNMP-Check"""
    # Implémentation à venir
    return None

def parse_hydra_output(output_file):
    """Analyse les résultats de Hydra"""
    # Implémentation à venir
    return None

def parse_sslyze_output(output_file):
    """Analyse les résultats de SSLyze"""
    # Implémentation à venir
    return None

def parse_wpscan_output(output_file):
    """Analyse les résultats de WPScan"""
    # Implémentation à venir
    return None

def parse_dirb_output(output_file):
    """Analyse les résultats de Dirb"""
    # Implémentation à venir
    return None

def parse_gobuster_output(output_file):
    """Analyse les résultats de Gobuster"""
    # Implémentation à venir
    return None

def parse_nuclei_output(output_file):
    """Analyse les résultats de Nuclei"""
    # Implémentation à venir
    return None

def parse_zap_output(output_file):
    """Analyse les résultats de OWASP ZAP"""
    # Implémentation à venir
    return None
