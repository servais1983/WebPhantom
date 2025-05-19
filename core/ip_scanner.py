#!/usr/bin/env python3
"""
Module de scan IP pour WebPhantom
Permet de scanner des plages d'adresses IP complètes avec différents outils
"""

import os
import re
import subprocess
import ipaddress
import json
import time
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
        'command': 'nmap -A -T4 -oX {output_file} {target}',
        'description': 'Scanner réseau avancé pour la découverte de services et la détection de versions',
        'parse_function': 'parse_nmap_output'
    },
    'nikto': {
        'package': 'nikto',
        'command': 'nikto -h {target} -output {output_file} -Format xml',
        'description': 'Scanner de vulnérabilités web',
        'parse_function': 'parse_nikto_output'
    },
    'testssl': {
        'package': 'testssl.sh',
        'command': 'testssl --quiet --warnings off --openssl-timeout 10 --html {output_file} {target}',
        'description': 'Vérification de la configuration SSL/TLS',
        'parse_function': 'parse_testssl_output'
    },
    'snmp-check': {
        'package': 'snmp-check',
        'command': 'snmp-check -w {output_file} {target}',
        'description': 'Vérification des configurations SNMP',
        'parse_function': 'parse_snmpcheck_output'
    },
    'hydra': {
        'package': 'hydra',
        'command': 'hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt -o {output_file} -f {target} ssh',
        'description': 'Outil de brute force pour les services réseau',
        'parse_function': 'parse_hydra_output'
    },
    'sslyze': {
        'package': 'sslyze',
        'command': 'sslyze --json_out {output_file} {target}',
        'description': 'Analyse avancée des configurations SSL/TLS',
        'parse_function': 'parse_sslyze_output'
    },
    'wpscan': {
        'package': 'wpscan',
        'command': 'wpscan --url http://{target} --format json --output {output_file}',
        'description': 'Scanner de vulnérabilités WordPress',
        'parse_function': 'parse_wpscan_output'
    },
    'dirb': {
        'package': 'dirb',
        'command': 'dirb http://{target} /usr/share/dirb/wordlists/common.txt -o {output_file}',
        'description': 'Découverte de répertoires et fichiers web',
        'parse_function': 'parse_dirb_output'
    },
    'gobuster': {
        'package': 'gobuster',
        'command': 'gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -o {output_file}',
        'description': 'Découverte de répertoires et fichiers web (alternative à dirb)',
        'parse_function': 'parse_gobuster_output'
    },
    'nuclei': {
        'package': 'nuclei',
        'command': 'nuclei -u http://{target} -o {output_file}',
        'description': 'Scanner de vulnérabilités basé sur des templates',
        'parse_function': 'parse_nuclei_output'
    }
}

# Outils nécessitant une configuration spéciale
SPECIAL_TOOLS = {
    'openvas': {
        'package': 'openvas',
        'setup_command': 'gvm-setup',
        'start_command': 'gvm-start',
        'scan_command': 'gvm-cli --gmp-username admin --gmp-password admin socket --xml "<create_task><name>WebPhantom-{timestamp}</name><target id=\'{target_id}\'></target><scanner id=\'08b69003-5fc2-4037-a479-93b440211c73\'></scanner><config id=\'daba56c8-73ec-11df-a475-002264764cea\'></config></create_task>"',
        'description': 'Scanner de vulnérabilités complet',
        'parse_function': 'parse_openvas_output'
    },
    'owasp-zap': {
        'package': 'zaproxy',
        'command': 'zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" -o {output_file} {target}',
        'description': 'Scanner de vulnérabilités web OWASP ZAP',
        'parse_function': 'parse_zap_output'
    },

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
    """Convertit une plage d'adresses IP en liste d'adresses IP individuelles"""
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logger.error(f"Erreur lors de l'expansion de la plage IP {ip_range}: {e}")
        return []

def ensure_all_tools_installed():
    """Vérifie et installe tous les outils nécessaires"""
    logger.info("Vérification et installation des outils de scan...")
    
    # Installer les outils standards
    for tool_name, tool_info in SCAN_TOOLS.items():
        ensure_tool_installed(tool_info['package'])
    
    # Installer les outils spéciaux
    for tool_name, tool_info in SPECIAL_TOOLS.items():
        ensure_tool_installed(tool_info['package'])
        
        # Configuration spéciale pour OpenVAS
        if tool_name == 'openvas' and tool_info.get('setup_command'):
            try:
                logger.info(f"Configuration de {tool_name}...")
                subprocess.run(tool_info['setup_command'], shell=True, check=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Erreur lors de la configuration de {tool_name}: {e}")

def run_tool_scan(tool_name, tool_info, target, output_dir):
    """Exécute un scan avec un outil spécifique"""
    timestamp = int(time.time())
    output_file = os.path.join(output_dir, f"{tool_name}_{target.replace('/', '_')}_{timestamp}.xml")
    
    command = tool_info['command'].format(target=target, output_file=output_file)
    
    logger.info(f"Exécution de {tool_name} sur {target}...")
    success, output = run_command(command)
    
    result = {
        'tool': tool_name,
        'target': target,
        'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
        'success': success,
        'output_file': output_file if success else None,
        'raw_output': output,
        'parsed_results': None
    }
    
    # Analyser les résultats si le scan a réussi
    if success and os.path.exists(output_file):
        parse_function_name = tool_info.get('parse_function')
        if parse_function_name and parse_function_name in globals():
            try:
                result['parsed_results'] = globals()[parse_function_name](output_file)
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des résultats de {tool_name}: {e}")
    
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
    
    # S'assurer que tous les outils sont installés
    ensure_all_tools_installed()
    
    # Résultats globaux
    results = {
        'scan_info': {
            'target': target,
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tools_used': tools,
            'output_dir': output_dir
        },
        'targets': {},
        'summary': {
            'total_targets': len(targets),
            'completed_scans': 0,
            'failed_scans': 0
        }
    }
    
    # Scanner chaque cible
    for ip in targets:
        logger.info(f"Scan de l'adresse IP: {ip}")
        results['targets'][ip] = {'tools': {}}
        
        # Exécuter les scans en parallèle
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {}
            
            # Soumettre les tâches pour les outils standards
            for tool_name in tools:
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
                    
                    if tool_result['success']:
                        results['summary']['completed_scans'] += 1
                    else:
                        results['summary']['failed_scans'] += 1
                        
                except Exception as e:
                    logger.error(f"Erreur lors de l'exécution de {tool_name} sur {ip}: {e}")
                    results['targets'][ip]['tools'][tool_name] = {
                        'tool': tool_name,
                        'target': ip,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'success': False,
                        'error': str(e)
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
                margin-bottom: 20px;
                padding: 15px;
                background-color: #f8f9fa;
                border-radius: 6px;
            }}
            .tool-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }}
            .tool-name {{
                font-weight: bold;
                color: #2c3e50;
            }}
            .success {{
                color: #28a745;
                font-weight: bold;
            }}
            .failure {{
                color: #dc3545;
                font-weight: bold;
            }}
            .timestamp {{
                color: #6c757d;
                font-size: 0.9em;
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
        </style>
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
            </div>
    """
    
    # Ajouter les résultats pour chaque cible
    for ip, target_results in results['targets'].items():
        html_content += f"""
            <div class="target-section">
                <h2>Résultats pour {ip}</h2>
        """
        
        # Ajouter les résultats pour chaque outil
        for tool_name, tool_result in target_results['tools'].items():
            status_class = "success" if tool_result.get('success', False) else "failure"
            status_text = "Réussi" if tool_result.get('success', False) else "Échoué"
            
            html_content += f"""
                <div class="tool-result">
                    <div class="tool-header">
                        <span class="tool-name">{tool_name}</span>
                        <span class="{status_class}">{status_text}</span>
                    </div>
                    <div class="timestamp">Exécuté le {tool_result.get('timestamp', 'N/A')}</div>
            """
            
            # Ajouter les résultats analysés si disponibles
            if tool_result.get('parsed_results'):
                html_content += f"""
                    <div class="parsed-results">
                        {format_parsed_results(tool_name, tool_result['parsed_results'])}
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

def format_parsed_results(tool_name, parsed_results):
    """Formate les résultats analysés pour l'affichage HTML"""
    if not parsed_results:
        return "<p>Aucun résultat analysé disponible.</p>"
    
    # Format spécifique pour chaque outil
    if tool_name == 'nmap':
        return format_nmap_results(parsed_results)
    elif tool_name == 'nikto':
        return format_nikto_results(parsed_results)
    # Ajouter d'autres formatages spécifiques ici
    
    # Format générique pour les autres outils
    result_html = "<h4>Résultats détaillés:</h4>"
    
    if isinstance(parsed_results, dict):
        result_html += "<table>"
        for key, value in parsed_results.items():
            result_html += f"<tr><th>{key}</th><td>{value}</td></tr>"
        result_html += "</table>"
    elif isinstance(parsed_results, list):
        result_html += "<ul>"
        for item in parsed_results:
            if isinstance(item, dict):
                result_html += "<li><table>"
                for k, v in item.items():
                    result_html += f"<tr><th>{k}</th><td>{v}</td></tr>"
                result_html += "</table></li>"
            else:
                result_html += f"<li>{item}</li>"
        result_html += "</ul>"
    else:
        result_html += f"<pre>{parsed_results}</pre>"
    
    return result_html

def format_nmap_results(parsed_results):
    """Formate les résultats de Nmap pour l'affichage HTML"""
    result_html = "<h4>Résultats Nmap:</h4>"
    
    # Informations sur l'hôte
    if 'host' in parsed_results:
        result_html += f"<p><strong>Hôte:</strong> {parsed_results['host'].get('ip', 'N/A')}</p>"
        if 'hostnames' in parsed_results['host']:
            result_html += "<p><strong>Noms d'hôte:</strong> "
            result_html += ", ".join(parsed_results['host']['hostnames'])
            result_html += "</p>"
    
    # Ports ouverts
    if 'ports' in parsed_results:
        result_html += "<h5>Ports ouverts:</h5>"
        result_html += "<table>"
        result_html += "<tr><th>Port</th><th>Protocole</th><th>Service</th><th>Version</th></tr>"
        
        for port in parsed_results['ports']:
            result_html += f"<tr>"
            result_html += f"<td>{port.get('port', 'N/A')}</td>"
            result_html += f"<td>{port.get('protocol', 'N/A')}</td>"
            result_html += f"<td>{port.get('service', 'N/A')}</td>"
            result_html += f"<td>{port.get('version', 'N/A')}</td>"
            result_html += f"</tr>"
        
        result_html += "</table>"
    
    # OS Detection
    if 'os' in parsed_results:
        result_html += "<h5>Détection de système d'exploitation:</h5>"
        result_html += "<ul>"
        for os_match in parsed_results['os']:
            result_html += f"<li>{os_match.get('name', 'N/A')} ({os_match.get('accuracy', 'N/A')}%)</li>"
        result_html += "</ul>"
    
    return result_html

def format_nikto_results(parsed_results):
    """Formate les résultats de Nikto pour l'affichage HTML"""
    result_html = "<h4>Résultats Nikto:</h4>"
    
    if 'vulnerabilities' in parsed_results:
        result_html += "<table>"
        result_html += "<tr><th>ID</th><th>Description</th><th>Sévérité</th></tr>"
        
        for vuln in parsed_results['vulnerabilities']:
            severity_class = "severity-info"
            if 'severity' in vuln:
                if vuln['severity'] == 'high':
                    severity_class = "severity-high"
                elif vuln['severity'] == 'medium':
                    severity_class = "severity-medium"
                elif vuln['severity'] == 'low':
                    severity_class = "severity-low"
            
            result_html += f"<tr>"
            result_html += f"<td>{vuln.get('id', 'N/A')}</td>"
            result_html += f"<td>{vuln.get('description', 'N/A')}</td>"
            result_html += f"<td class='{severity_class}'>{vuln.get('severity', 'Info').capitalize()}</td>"
            result_html += f"</tr>"
        
        result_html += "</table>"
    else:
        result_html += "<p>Aucune vulnérabilité détectée.</p>"
    
    return result_html

# Fonctions d'analyse des résultats pour chaque outil
def parse_nmap_output(output_file):
    """Analyse les résultats de Nmap au format XML"""
    try:
        import xml.etree.ElementTree as ET
        
        tree = ET.parse(output_file)
        root = tree.getroot()
        
        results = {'host': {}, 'ports': [], 'os': []}
        
        # Informations sur l'hôte
        host_elem = root.find('.//host')
        if host_elem is not None:
            addr_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            if addr_elem is not None:
                results['host']['ip'] = addr_elem.get('addr')
            
            hostnames = []
            for hostname in host_elem.findall('.//hostname'):
                hostnames.append(hostname.get('name'))
            results['host']['hostnames'] = hostnames
        
        # Ports ouverts
        for port_elem in root.findall('.//port'):
            state_elem = port_elem.find('state')
            if state_elem is not None and state_elem.get('state') == 'open':
                port_info = {
                    'port': port_elem.get('portid'),
                    'protocol': port_elem.get('protocol')
                }
                
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    port_info['service'] = service_elem.get('name', 'unknown')
                    port_info['version'] = service_elem.get('product', '') + ' ' + service_elem.get('version', '')
                
                results['ports'].append(port_info)
        
        # OS Detection
        for os_elem in root.findall('.//osmatch'):
            os_info = {
                'name': os_elem.get('name'),
                'accuracy': os_elem.get('accuracy')
            }
            results['os'].append(os_info)
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de Nmap: {e}")
        return None

def parse_nikto_output(output_file):
    """Analyse les résultats de Nikto au format XML"""
    try:
        import xml.etree.ElementTree as ET
        
        tree = ET.parse(output_file)
        root = tree.getroot()
        
        results = {'vulnerabilities': []}
        
        for item in root.findall('.//item'):
            vuln_info = {
                'id': item.find('id').text if item.find('id') is not None else 'N/A',
                'description': item.find('description').text if item.find('description') is not None else 'N/A'
            }
            
            # Déterminer la sévérité en fonction de la description
            description = vuln_info['description'].lower()
            if any(word in description for word in ['critical', 'remote code execution', 'rce', 'sql injection']):
                vuln_info['severity'] = 'high'
            elif any(word in description for word in ['xss', 'cross-site', 'directory traversal', 'information disclosure']):
                vuln_info['severity'] = 'medium'
            elif any(word in description for word in ['deprecated', 'outdated', 'version']):
                vuln_info['severity'] = 'low'
            else:
                vuln_info['severity'] = 'info'
            
            results['vulnerabilities'].append(vuln_info)
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de Nikto: {e}")
        return None

def parse_testssl_output(output_file):
    """Analyse les résultats de TestSSL au format HTML"""
    try:
        from bs4 import BeautifulSoup
        
        with open(output_file, 'r') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
        
        results = {'vulnerabilities': []}
        
        # Extraire les vulnérabilités
        for row in soup.select('table.overview tr'):
            cells = row.find_all('td')
            if len(cells) >= 2:
                finding = cells[0].get_text(strip=True)
                rating = cells[1].get_text(strip=True)
                
                severity = 'info'
                if rating in ['CRITICAL', 'HIGH']:
                    severity = 'high'
                elif rating == 'MEDIUM':
                    severity = 'medium'
                elif rating == 'LOW':
                    severity = 'low'
                
                results['vulnerabilities'].append({
                    'finding': finding,
                    'rating': rating,
                    'severity': severity
                })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de TestSSL: {e}")
        return None

def parse_snmpcheck_output(output_file):
    """Analyse les résultats de SNMP-Check"""
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        results = {'info': {}}
        
        # Extraire les informations SNMP
        system_match = re.search(r'System information:\s+(.+)', content)
        if system_match:
            results['info']['system'] = system_match.group(1)
        
        # Extraire les utilisateurs
        users = []
        user_section = re.search(r'User accounts:\s+(.+?)(?=\n\n)', content, re.DOTALL)
        if user_section:
            for line in user_section.group(1).split('\n'):
                if line.strip():
                    users.append(line.strip())
            results['info']['users'] = users
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de SNMP-Check: {e}")
        return None

def parse_hydra_output(output_file):
    """Analyse les résultats de Hydra"""
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        results = {'credentials': []}
        
        # Extraire les identifiants trouvés
        for line in content.split('\n'):
            if 'login:' in line and 'password:' in line:
                match = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', line)
                if match:
                    results['credentials'].append({
                        'username': match.group(1),
                        'password': match.group(2)
                    })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de Hydra: {e}")
        return None

def parse_sslyze_output(output_file):
    """Analyse les résultats de SSLyze au format JSON"""
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        results = {'vulnerabilities': []}
        
        # Extraire les vulnérabilités SSL/TLS
        if 'server_scan_results' in data:
            for scan_result in data['server_scan_results']:
                if 'scan_commands_results' in scan_result:
                    for command, command_result in scan_result['scan_commands_results'].items():
                        if command == 'ssl_2_0_cipher_suites' and command_result.get('is_protocol_supported', False):
                            results['vulnerabilities'].append({
                                'finding': 'SSLv2 est activé',
                                'severity': 'high'
                            })
                        elif command == 'ssl_3_0_cipher_suites' and command_result.get('is_protocol_supported', False):
                            results['vulnerabilities'].append({
                                'finding': 'SSLv3 est activé (vulnérable à POODLE)',
                                'severity': 'high'
                            })
                        elif command == 'heartbleed' and command_result.get('is_vulnerable_to_heartbleed', False):
                            results['vulnerabilities'].append({
                                'finding': 'Vulnérable à Heartbleed',
                                'severity': 'high'
                            })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de SSLyze: {e}")
        return None

def parse_wpscan_output(output_file):
    """Analyse les résultats de WPScan au format JSON"""
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        results = {'vulnerabilities': []}
        
        # Extraire les vulnérabilités WordPress
        if 'version' in data and 'vulnerabilities' in data['version']:
            for vuln in data['version']['vulnerabilities']:
                results['vulnerabilities'].append({
                    'title': vuln.get('title', 'N/A'),
                    'fixed_in': vuln.get('fixed_in', 'N/A'),
                    'severity': determine_severity(vuln)
                })
        
        # Extraire les vulnérabilités des plugins
        if 'plugins' in data:
            for plugin_name, plugin_data in data['plugins'].items():
                if 'vulnerabilities' in plugin_data:
                    for vuln in plugin_data['vulnerabilities']:
                        results['vulnerabilities'].append({
                            'plugin': plugin_name,
                            'title': vuln.get('title', 'N/A'),
                            'fixed_in': vuln.get('fixed_in', 'N/A'),
                            'severity': determine_severity(vuln)
                        })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de WPScan: {e}")
        return None

def determine_severity(vuln):
    """Détermine la sévérité d'une vulnérabilité en fonction de son titre"""
    title = vuln.get('title', '').lower()
    
    if any(word in title for word in ['rce', 'remote code execution', 'sql injection', 'privilege escalation']):
        return 'high'
    elif any(word in title for word in ['xss', 'cross-site', 'csrf', 'authentication bypass']):
        return 'medium'
    elif any(word in title for word in ['information disclosure', 'path disclosure']):
        return 'low'
    else:
        return 'info'

def parse_dirb_output(output_file):
    """Analyse les résultats de Dirb"""
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        results = {'directories': []}
        
        # Extraire les répertoires trouvés
        for line in content.split('\n'):
            if line.startswith('==>') or line.startswith('++'):
                continue
            if 'CODE:' in line and 'SIZE:' in line:
                url_match = re.search(r'(https?://[^\s]+)\s+\(CODE:(\d+)', line)
                if url_match:
                    url = url_match.group(1)
                    code = url_match.group(2)
                    results['directories'].append({
                        'url': url,
                        'code': code
                    })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de Dirb: {e}")
        return None

def parse_gobuster_output(output_file):
    """Analyse les résultats de Gobuster"""
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        results = {'directories': []}
        
        # Extraire les répertoires trouvés
        for line in content.split('\n'):
            if line.strip() and not line.startswith('Gobuster'):
                parts = line.split()
                if len(parts) >= 2:
                    url = parts[0]
                    status = parts[1].strip('()')
                    results['directories'].append({
                        'url': url,
                        'status': status
                    })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de Gobuster: {e}")
        return None

def parse_nuclei_output(output_file):
    """Analyse les résultats de Nuclei"""
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        results = {'vulnerabilities': []}
        
        # Extraire les vulnérabilités trouvées
        for line in content.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    severity = 'info'
                    if '[critical]' in line.lower():
                        severity = 'high'
                    elif '[high]' in line.lower():
                        severity = 'high'
                    elif '[medium]' in line.lower():
                        severity = 'medium'
                    elif '[low]' in line.lower():
                        severity = 'low'
                    
                    # Extraire le nom de la vulnérabilité
                    vuln_name = re.search(r'\[(.*?)\]', line)
                    if vuln_name:
                        vuln_name = vuln_name.group(1)
                    else:
                        vuln_name = 'Vulnérabilité inconnue'
                    
                    results['vulnerabilities'].append({
                        'name': vuln_name,
                        'url': parts[0],
                        'severity': severity
                    })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats de Nuclei: {e}")
        return None

def parse_openvas_output(output_file):
    """Analyse les résultats d'OpenVAS"""
    try:
        import xml.etree.ElementTree as ET
        
        tree = ET.parse(output_file)
        root = tree.getroot()
        
        results = {'vulnerabilities': []}
        
        # Extraire les vulnérabilités
        for result in root.findall('.//result'):
            name_elem = result.find('.//name')
            severity_elem = result.find('.//severity')
            description_elem = result.find('.//description')
            
            if name_elem is not None and severity_elem is not None:
                severity_value = float(severity_elem.text)
                severity = 'info'
                if severity_value >= 7.0:
                    severity = 'high'
                elif severity_value >= 4.0:
                    severity = 'medium'
                elif severity_value > 0:
                    severity = 'low'
                
                results['vulnerabilities'].append({
                    'name': name_elem.text,
                    'severity': severity,
                    'severity_value': severity_value,
                    'description': description_elem.text if description_elem is not None else 'N/A'
                })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats d'OpenVAS: {e}")
        return None

def parse_zap_output(output_file):
    """Analyse les résultats d'OWASP ZAP"""
    try:
        import xml.etree.ElementTree as ET
        
        tree = ET.parse(output_file)
        root = tree.getroot()
        
        results = {'vulnerabilities': []}
        
        # Extraire les vulnérabilités
        for alert in root.findall('.//alertitem'):
            name_elem = alert.find('name')
            risk_elem = alert.find('riskcode')
            desc_elem = alert.find('desc')
            
            if name_elem is not None and risk_elem is not None:
                risk_value = int(risk_elem.text)
                severity = 'info'
                if risk_value == 3:
                    severity = 'high'
                elif risk_value == 2:
                    severity = 'medium'
                elif risk_value == 1:
                    severity = 'low'
                
                results['vulnerabilities'].append({
                    'name': name_elem.text,
                    'severity': severity,
                    'description': desc_elem.text if desc_elem is not None else 'N/A'
                })
        
        return results
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des résultats d'OWASP ZAP: {e}")
        return None



def run_all_tools(target, output_dir=None):
    """
    Exécute tous les outils de scan sur une cible
    
    Args:
        target (str): Adresse IP ou plage d'adresses IP à scanner
        output_dir (str, optional): Répertoire de sortie pour les résultats
        
    Returns:
        dict: Résultats du scan
    """
    return scan_ip(target, output_dir, tools=list(SCAN_TOOLS.keys()) + list(SPECIAL_TOOLS.keys()))

# Fonction principale pour les tests
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ip_scanner.py <target_ip_or_range>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run_all_tools(target)
    
    print(f"Scan terminé. Rapport disponible: {results['scan_info']['report_file']}")
