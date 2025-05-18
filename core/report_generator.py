"""
Module de génération de rapports HTML/PDF pour WebPhantom.
Crée des rapports détaillés à partir des résultats de scan.
"""

import os
import json
import time
import logging
import weasyprint
from datetime import datetime
from jinja2 import Template

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Répertoire pour les templates
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
DEFAULT_TEMPLATE = os.path.join(TEMPLATE_DIR, "report_template.html")

# Créer le répertoire des templates s'il n'existe pas
os.makedirs(TEMPLATE_DIR, exist_ok=True)

# Créer un template par défaut s'il n'existe pas
if not os.path.exists(DEFAULT_TEMPLATE):
    with open(DEFAULT_TEMPLATE, "w") as f:
        f.write("""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de sécurité WebPhantom</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
            margin-top: 1.5em;
        }
        h1 {
            text-align: center;
            color: #3498db;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .summary {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 20px 0;
        }
        .vulnerability {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .critical {
            border-left: 5px solid #e74c3c;
        }
        .high {
            border-left: 5px solid #e67e22;
        }
        .medium {
            border-left: 5px solid #f1c40f;
        }
        .low {
            border-left: 5px solid #3498db;
        }
        .info {
            border-left: 5px solid #2ecc71;
        }
        .evidence {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            overflow-x: auto;
            font-size: 0.9em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            margin-top: 50px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }
        @media print {
            body {
                font-size: 12pt;
            }
            .vulnerability {
                break-inside: avoid;
            }
            a {
                text-decoration: none;
                color: #000;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport de sécurité WebPhantom</h1>
        <p>Généré le {{ timestamp }}</p>
    </div>

    <div class="summary">
        <h2>Résumé</h2>
        <p><strong>Cible :</strong> {{ target }}</p>
        <p><strong>Date du scan :</strong> {{ scan_date }}</p>
        <p><strong>Vulnérabilités détectées :</strong> {{ vulnerability_count }}</p>
        <table>
            <tr>
                <th>Sévérité</th>
                <th>Nombre</th>
            </tr>
            {% for severity, count in severity_counts.items() %}
            <tr>
                <td>{{ severity }}</td>
                <td>{{ count }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <h2>Vulnérabilités détectées</h2>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability {{ vuln.severity|lower }}">
        <h3>{{ vuln.type }}</h3>
        <p><strong>Sévérité :</strong> {{ vuln.severity }}</p>
        <p><strong>Description :</strong> {{ vuln.description }}</p>
        <p><strong>Localisation :</strong> {{ vuln.location }}</p>
        {% if vuln.evidence %}
        <div class="evidence">
            <p><strong>Preuve :</strong></p>
            <pre>{{ vuln.evidence }}</pre>
        </div>
        {% endif %}
        {% if vuln.recommendation %}
        <p><strong>Recommandation :</strong> {{ vuln.recommendation }}</p>
        {% endif %}
    </div>
    {% endfor %}

    <h2>Détails du scan</h2>
    <table>
        <tr>
            <th>Étape</th>
            <th>Statut</th>
            <th>Résultats</th>
        </tr>
        {% for step in steps %}
        <tr>
            <td>{{ step.type }}</td>
            <td>{{ step.status }}</td>
            <td>{{ step.summary }}</td>
        </tr>
        {% endfor %}
    </table>

    <div class="footer">
        <p>Rapport généré par WebPhantom - Outil de pentest web automatisé</p>
        <p>© {{ current_year }} WebPhantom</p>
    </div>
</body>
</html>""")

def generate(results, format="html", output=None, template=None):
    """
    Génère un rapport à partir des résultats de scan.
    
    Args:
        results (dict): Résultats du scan
        format (str, optional): Format du rapport (html, pdf)
        output (str, optional): Chemin du fichier de sortie
        template (str, optional): Chemin du template HTML personnalisé
        
    Returns:
        dict: Résultat de la génération
    """
    logger.info(f"Génération d'un rapport au format {format}")
    
    # Utiliser le template par défaut si aucun n'est spécifié
    template_path = template or DEFAULT_TEMPLATE
    
    # Vérifier si le template existe
    if not os.path.exists(template_path):
        logger.error(f"Template non trouvé: {template_path}")
        return {"success": False, "error": f"Template non trouvé: {template_path}"}
    
    # Préparer les données pour le template
    template_data = prepare_template_data(results)
    
    # Générer le HTML
    try:
        with open(template_path, "r") as f:
            template_content = f.read()
        
        template = Template(template_content)
        html_content = template.render(**template_data)
        
        # Déterminer le chemin de sortie si non spécifié
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = f"report_{timestamp}.{format}"
        
        # Générer le rapport au format demandé
        if format.lower() == "html":
            with open(output, "w") as f:
                f.write(html_content)
            logger.info(f"Rapport HTML généré: {output}")
            print(f"[+] Rapport HTML généré: {output}")
        elif format.lower() == "pdf":
            try:
                pdf = weasyprint.HTML(string=html_content).write_pdf()
                with open(output, "wb") as f:
                    f.write(pdf)
                logger.info(f"Rapport PDF généré: {output}")
                print(f"[+] Rapport PDF généré: {output}")
            except Exception as e:
                logger.error(f"Erreur lors de la génération du PDF: {str(e)}")
                return {"success": False, "error": f"Erreur lors de la génération du PDF: {str(e)}"}
        else:
            logger.error(f"Format non supporté: {format}")
            return {"success": False, "error": f"Format non supporté: {format}"}
        
        return {"success": True, "file": output, "format": format}
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
        return {"success": False, "error": str(e)}

def prepare_template_data(results):
    """
    Prépare les données pour le template de rapport.
    
    Args:
        results (dict): Résultats du scan
        
    Returns:
        dict: Données formatées pour le template
    """
    # Extraire les vulnérabilités de tous les résultats
    vulnerabilities = []
    for step in results.get("steps", []):
        if step.get("status") == "executed" and step.get("results") and "vulnerabilities" in step.get("results", {}):
            vulnerabilities.extend(step["results"]["vulnerabilities"])
    
    # Compter les vulnérabilités par sévérité
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Info")
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts[severity] = 1
    
    # Préparer le résumé des étapes
    steps = []
    for step in results.get("steps", []):
        step_summary = {
            "type": step.get("type", "Unknown"),
            "status": step.get("status", "Unknown"),
            "summary": ""
        }
        
        if step.get("status") == "executed" and step.get("results"):
            if "vulnerabilities" in step.get("results", {}):
                vuln_count = len(step["results"]["vulnerabilities"])
                step_summary["summary"] = f"{vuln_count} vulnérabilité(s) détectée(s)"
            elif "file" in step.get("results", {}):
                step_summary["summary"] = f"Fichier généré: {step['results']['file']}"
            else:
                step_summary["summary"] = "Exécuté avec succès"
        elif step.get("status") == "error":
            step_summary["summary"] = f"Erreur: {step.get('error', 'Inconnue')}"
        
        steps.append(step_summary)
    
    # Créer les données pour le template
    template_data = {
        "target": results.get("target", "Inconnu"),
        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "scan_date": results.get("timestamp", "Inconnu"),
        "vulnerability_count": len(vulnerabilities),
        "severity_counts": severity_counts,
        "vulnerabilities": vulnerabilities,
        "steps": steps,
        "current_year": datetime.now().year
    }
    
    return template_data

def run(url, options=None):
    """
    Fonction principale pour l'exécution du module de génération de rapports.
    
    Args:
        url (str): URL cible (non utilisée pour ce module)
        options (dict, optional): Options supplémentaires
        
    Returns:
        dict: Résultat de l'opération
    """
    if not options:
        options = {}
    
    # Créer un rapport minimal si aucun résultat n'est fourni
    if not options.get("results"):
        results = {
            "target": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "steps": [
                {
                    "type": "recon",
                    "status": "executed",
                    "results": {
                        "vulnerabilities": []
                    }
                }
            ]
        }
    else:
        results = options.get("results")
    
    format = options.get("format", "html")
    output = options.get("output", None)
    
    # Si aucun fichier de sortie n'est spécifié, en créer un dans le répertoire des résultats
    if not output and options.get("results_dir"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = os.path.join(options.get("results_dir"), f"report_{timestamp}.{format}")
    
    logger.info(f"Génération d'un rapport au format {format}")
    result = generate(results, format, output)
    
    return result
