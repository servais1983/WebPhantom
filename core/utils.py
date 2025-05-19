#!/usr/bin/env python3
"""
Utilitaires pour WebPhantom
"""

import os
import subprocess
import logging
import time
import shutil
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_command(command, timeout=None):
    """
    Exécute une commande shell et retourne le résultat
    
    Args:
        command (str): Commande à exécuter
        timeout (int, optional): Timeout en secondes
        
    Returns:
        tuple: (success, output)
    """
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout)
        success = process.returncode == 0
        
        if not success:
            logger.warning(f"Commande échouée: {command}")
            logger.warning(f"Erreur: {stderr}")
        
        return success, stdout if success else stderr
    except subprocess.TimeoutExpired:
        process.kill()
        logger.warning(f"Timeout expiré pour la commande: {command}")
        return False, "Timeout expiré"
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution de la commande {command}: {e}")
        return False, str(e)

def ensure_tool_installed(package_name):
    """
    Vérifie si un outil est installé et l'installe si nécessaire
    
    Args:
        package_name (str): Nom du paquet à installer
        
    Returns:
        bool: True si l'installation a réussi ou si l'outil est déjà installé
    """
    logger.info(f"Vérification de l'installation de {package_name}...")
    
    # Vérifier si l'outil est déjà installé
    check_command = f"which {package_name.split()[0]}"
    success, _ = run_command(check_command)
    
    if success:
        logger.info(f"{package_name} est déjà installé.")
        return True
    
    # Installer l'outil
    logger.info(f"Installation de {package_name}...")
    install_command = f"apt-get update && apt-get install -y {package_name}"
    success, output = run_command(f"sudo {install_command}")
    
    if success:
        logger.info(f"{package_name} a été installé avec succès.")
    else:
        logger.error(f"Échec de l'installation de {package_name}: {output}")
    
    return success

def create_output_dir(prefix='output'):
    """
    Crée un répertoire de sortie avec un timestamp
    
    Args:
        prefix (str, optional): Préfixe du nom du répertoire
        
    Returns:
        str: Chemin du répertoire créé
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.join(os.getcwd(), f"{prefix}_{timestamp}")
    
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Répertoire de sortie créé: {output_dir}")
    
    return output_dir

def run_script_yaml(script_file, target_url=None):
    """
    Exécute un script YAML
    
    Args:
        script_file (str): Chemin du fichier YAML
        target_url (str, optional): URL cible à utiliser à la place de celle dans le fichier YAML
    """
    import yaml
    
    try:
        with open(script_file, 'r') as f:
            script = yaml.safe_load(f)
        
        if target_url:
            script['target'] = target_url
        
        if 'target' not in script:
            logger.error("Aucune cible spécifiée dans le script YAML ou en argument")
            return
        
        target = script['target']
        logger.info(f"Exécution du script YAML pour la cible: {target}")
        
        for step in script.get('steps', []):
            step_type = step.get('type')
            options = step.get('options', {})
            
            logger.info(f"Exécution de l'étape: {step_type}")
            
            if step_type == 'recon':
                from core import recon
                recon.run(target)
            elif step_type == 'scan':
                from core import vulns
                vulns.run(target)
            elif step_type == 'advanced-scan':
                from core import advanced_vulns
                advanced_vulns.run(target, **options)
            elif step_type == 'ai':
                from core import ai_analyzer
                ai_analyzer.run(target, **options)
            elif step_type == 'wait':
                seconds = options.get('seconds', 1)
                logger.info(f"Attente de {seconds} secondes...")
                time.sleep(seconds)
            elif step_type == 'ip-scan':
                from core import ip_scanner
                ip_scanner.scan_ip(target, tools=options.get('tools'))
            elif step_type == 'all-tools':
                from core import ip_scanner
                ip_scanner.run_all_tools(target)
            else:
                logger.warning(f"Type d'étape inconnu: {step_type}")
    
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution du script YAML: {e}")
