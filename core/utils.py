#!/usr/bin/env python3
"""
Utilitaires pour WebPhantom
"""

import os
import subprocess
import logging
import time
import shutil
import signal
import threading
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_command(command, timeout=None, silent=False, ignore_errors=False, show_output=True):
    """
    Exécute une commande shell et retourne le résultat
    
    Args:
        command (str): Commande à exécuter
        timeout (int, optional): Timeout en secondes
        silent (bool, optional): Si True, ne pas logger les erreurs non critiques
        ignore_errors (bool, optional): Si True, considérer la commande comme réussie même en cas d'erreur
        show_output (bool, optional): Si True, afficher la sortie en temps réel
        
    Returns:
        tuple: (success, output)
    """
    try:
        # Vérifier si la commande principale existe
        cmd_parts = command.split()
        main_cmd = cmd_parts[0]
        
        # Si main_cmd est sudo, prendre la commande suivante
        if main_cmd == "sudo" and len(cmd_parts) > 1:
            main_cmd = cmd_parts[1]
            
        # Vérifier si la commande existe avant de l'exécuter
        if not silent:
            logger.debug(f"Vérification de la disponibilité de la commande: {main_cmd}")
        
        cmd_exists = shutil.which(main_cmd) is not None
        if not cmd_exists:
            if not silent:
                logger.warning(f"Commande non trouvée: {main_cmd}")
            return False, f"Commande non trouvée: {main_cmd}"
        
        # Afficher la commande qui va être exécutée
        if show_output:
            print(f"\n{'='*80}\n[EXÉCUTION] {command}\n{'='*80}")
        
        # Exécuter la commande
        if show_output:
            # Mode avec affichage en temps réel
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Rediriger stderr vers stdout pour un affichage unifié
                universal_newlines=True,
                bufsize=1,  # Line buffered
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None  # Pour pouvoir terminer tout le groupe de processus
            )
            
            # Capturer la sortie complète pour le retour
            full_output = []
            
            # Timer pour le timeout
            start_time = time.time()
            
            # Fonction pour surveiller le processus et le tuer si nécessaire
            def monitor_process():
                while process.poll() is None:
                    if timeout and time.time() - start_time > timeout:
                        # Terminer le processus et tout son groupe
                        if hasattr(os, 'killpg'):
                            try:
                                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                                # Attendre un peu et forcer la fermeture si nécessaire
                                time.sleep(0.5)
                                if process.poll() is None:
                                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                            except OSError:
                                pass
                        else:
                            try:
                                process.terminate()
                                # Attendre un peu et forcer la fermeture si nécessaire
                                time.sleep(0.5)
                                if process.poll() is None:
                                    process.kill()
                            except OSError:
                                pass
                        
                        if show_output:
                            print(f"\n{'='*80}\n[TIMEOUT] La commande a dépassé le délai d'attente ({timeout}s)\n{'='*80}")
                        return
                    time.sleep(0.5)
            
            # Démarrer le thread de surveillance
            monitor_thread = threading.Thread(target=monitor_process)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Lire et afficher la sortie ligne par ligne en temps réel
            while process.poll() is None:
                try:
                    line = process.stdout.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    print(f"[SORTIE] {line.rstrip()}")
                    full_output.append(line)
                except (IOError, UnicodeDecodeError) as e:
                    # Ignorer les erreurs de lecture
                    if not silent:
                        logger.debug(f"Erreur de lecture de la sortie: {e}")
                    time.sleep(0.1)
            
            # Lire les dernières lignes
            for line in process.stdout:
                print(f"[SORTIE] {line.rstrip()}")
                full_output.append(line)
            
            process.stdout.close()
            return_code = process.wait()
            
            # Si le processus a été tué par timeout
            if return_code == -9 or return_code == -15:
                return False, "Timeout expiré"
            
            success = return_code == 0 or ignore_errors
            output = ''.join(full_output)
            
            if show_output:
                print(f"\n{'='*80}\n[TERMINÉ] Code de retour: {return_code}\n{'='*80}")
        else:
            # Mode silencieux (ancien comportement)
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                success = process.returncode == 0 or ignore_errors
                output = stdout if success else stderr
            except subprocess.TimeoutExpired:
                # Terminer le processus et tout son groupe
                if hasattr(os, 'killpg'):
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        time.sleep(0.5)
                        if process.poll() is None:
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except OSError:
                        pass
                else:
                    try:
                        process.terminate()
                        time.sleep(0.5)
                        if process.poll() is None:
                            process.kill()
                    except OSError:
                        pass
                
                process.wait()
                if not silent:
                    logger.debug(f"Timeout expiré pour la commande: {command}")
                return False, "Timeout expiré"
        
        if not success and not silent:
            logger.debug(f"Commande échouée (code {process.returncode}): {command}")
            if not show_output and stderr and stderr.strip():
                logger.debug(f"Message d'erreur: {stderr.strip()}")
        
        return success, output
    except Exception as e:
        if not silent:
            logger.debug(f"Erreur lors de l'exécution de la commande {command}: {e}")
        if show_output:
            print(f"\n{'='*80}\n[ERREUR] {str(e)}\n{'='*80}")
        return False, str(e)

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
    
    # Cas spécial pour git (utilisé pour LinPEAS)
    if tool_name == 'git':
        if shutil.which('git') is not None:
            logger.debug("git est déjà installé.")
            return True
    
    # Cas général
    if shutil.which(tool_name) is not None:
        logger.debug(f"{package_name} est déjà installé.")
        return True
    
    logger.info(f"Installation de {package_name}...")
    
    # Vérifier si nous avons les droits sudo
    has_sudo = False
    sudo_check, _ = run_command("sudo -n true", silent=True, show_output=False)
    if sudo_check:
        has_sudo = True
    
    # Installer l'outil
    if has_sudo:
        # Essayer d'abord avec apt
        install_command = f"apt-get update -qq && apt-get install -y -qq {package_name}"
        success, output = run_command(f"sudo {install_command}", silent=False, show_output=True, timeout=180)
        
        # Si apt échoue, essayer avec pip pour les outils Python
        if not success and (package_name.startswith('python') or package_name in ['sslyze', 'wpscan', 'nuclei']):
            logger.info(f"Tentative d'installation via pip pour {package_name}...")
            pip_command = f"pip install {package_name}"
            success, output = run_command(f"sudo {pip_command}", silent=False, show_output=True, timeout=120)
    else:
        # Essayer sans sudo (moins de chances de succès)
        logger.warning(f"Droits sudo non disponibles pour installer {package_name}. Tentative sans sudo...")
        install_command = f"apt-get update -qq && apt-get install -y -qq {package_name}"
        success, output = run_command(install_command, silent=False, show_output=True, timeout=180)
        
        # Essayer avec pip local si apt échoue
        if not success and (package_name.startswith('python') or package_name in ['sslyze', 'wpscan', 'nuclei']):
            logger.info(f"Tentative d'installation via pip local pour {package_name}...")
            pip_command = f"pip install --user {package_name}"
            success, output = run_command(pip_command, silent=False, show_output=True, timeout=120)
    
    # Vérifier si l'installation a réussi
    if shutil.which(tool_name) is not None:
        logger.info(f"{package_name} a été installé avec succès.")
        return True
    else:
        logger.error(f"Échec de l'installation de {package_name}: {output}")
        return False

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
                advanced_vulns.run(target, options)
            elif step_type == 'ai':
                from core import ai_analyzer
                ai_analyzer.run(target, options)
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
