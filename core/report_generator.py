"""
Module de génération de rapports HTML/PDF pour WebPhantom.
Ce module permet de générer des rapports détaillés et lisibles
à partir des résultats des scans de vulnérabilités et des analyses LLM.
"""

import os
import json
import logging
import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
import weasyprint

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("report_generator")

# Répertoire pour stocker les templates et les rapports
REPORTS_DIR = os.path.expanduser("~/.webphantom/reports")
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

# Créer les répertoires s'ils n'existent pas
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# Définir les templates HTML pour les rapports
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        :root {
            --primary-color: #2563eb;
            --secondary-color: #1e40af;
            --accent-color: #3b82f6;
            --background-color: #ffffff;
            --text-color: #1f2937;
            --text-secondary: #374151;
            --danger-color: #dc2626;
            --warning-color: #f59e0b;
            --info-color: #3b82f6;
            --success-color: #10b981;
            --border-color: #e5e7eb;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
            margin: 0;
            padding: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 1.5rem 2rem;
            margin-bottom: 2rem;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        h1, h2, h3, h4, h5, h6 {
            margin-top: 0;
            font-weight: 600;
            color: var(--text-color);
        }
        
        h1 {
            font-size: 2.25rem;
            margin-bottom: 1rem;
        }
        
        h2 {
            font-size: 1.75rem;
            margin-top: 2rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border-color);
        }
        
        h3 {
            font-size: 1.5rem;
            margin-top: 1.5rem;
            margin-bottom: 0.75rem;
        }
        
        p {
            margin-bottom: 1rem;
            font-size: 1rem;
            color: var(--text-color);
        }
        
        .summary {
            background-color: #f9fafb;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
            border-left: 4px solid var(--primary-color);
        }
        
        .summary h3 {
            margin-top: 0;
        }
        
        .summary-stats {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .stat-card {
            flex: 1;
            min-width: 200px;
            background-color: white;
            padding: 1rem;
            border-radius: 0.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            text-align: center;
        }
        
        .stat-card .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin: 0.5rem 0;
        }
        
        .stat-card .stat-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }
        
        .stat-critical { color: #991b1b; }
        .stat-high { color: #b91c1c; }
        .stat-medium { color: #b45309; }
        .stat-low { color: #1d4ed8; }
        .stat-info { color: #0369a1; }
        
        .vulnerability-section {
            margin-bottom: 3rem;
        }
        
        .vulnerability-card {
            background-color: white;
            border-radius: 0.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        
        .vulnerability-header {
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }
        
        .vulnerability-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
        }
        
        .vulnerability-severity {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background-color: #fee2e2;
            color: #991b1b;
        }
        
        .severity-high {
            background-color: #fee2e2;
            color: #b91c1c;
        }
        
        .severity-medium {
            background-color: #fef3c7;
            color: #b45309;
        }
        
        .severity-low {
            background-color: #dbeafe;
            color: #1d4ed8;
        }
        
        .severity-info {
            background-color: #e0f2fe;
            color: #0369a1;
        }
        
        .vulnerability-body {
            padding: 1.5rem;
        }
        
        .vulnerability-details {
            margin-bottom: 1.5rem;
        }
        
        .vulnerability-details h4 {
            font-size: 1.125rem;
            margin-top: 0;
            margin-bottom: 0.5rem;
        }
        
        .vulnerability-details p {
            margin-top: 0;
            margin-bottom: 1rem;
        }
        
        .evidence-section {
            background-color: #f9fafb;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
        }
        
        .evidence-section h4 {
            margin-top: 0;
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }
        
        .evidence-code {
            background-color: #f1f5f9;
            padding: 1rem;
            border-radius: 0.25rem;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #334155;
        }
        
        .remediation-list {
            margin-top: 0;
            padding-left: 1.5rem;
        }
        
        .remediation-list li {
            margin-bottom: 0.5rem;
            color: var(--text-color);
        }
        
        .footer {
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        
        .footer p {
            margin: 0.25rem 0;
        }
        
        @media print {
            body {
                font-size: 12pt;
            }
            
            .container {
                max-width: 100%;
                padding: 0;
            }
            
            header {
                padding: 1rem;
                margin-bottom: 1.5rem;
            }
            
            h1 {
                font-size: 24pt;
            }
            
            h2 {
                font-size: 20pt;
                margin-top: 1.5rem;
            }
            
            h3 {
                font-size: 16pt;
            }
            
            .vulnerability-card {
                page-break-inside: avoid;
                margin-bottom: 1rem;
            }
            
            .footer {
                margin-top: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{ title }}</h1>
            <p>Rapport généré le {{ generation_date }}</p>
        </header>
        
        <section class="summary">
            <h3>Résumé de l'analyse</h3>
            <p>URL analysée: <strong>{{ target_url }}</strong></p>
            <p>Durée de l'analyse: <strong>{{ scan_duration }}</strong></p>
            
            <div class="summary-stats">
                <div class="stat-card">
                    <div class="stat-value">{{ total_vulnerabilities }}</div>
                    <div class="stat-label">Vulnérabilités totales</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-critical">{{ critical_count }}</div>
                    <div class="stat-label">Critiques</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-high">{{ high_count }}</div>
                    <div class="stat-label">Élevées</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-medium">{{ medium_count }}</div>
                    <div class="stat-label">Moyennes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-low">{{ low_count }}</div>
                    <div class="stat-label">Faibles</div>
                </div>
            </div>
        </section>
        
        {% if critical_vulnerabilities %}
        <section class="vulnerability-section">
            <h2>Vulnérabilités Critiques</h2>
            {% for vuln in critical_vulnerabilities %}
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <h3 class="vulnerability-title">{{ vuln.type }}</h3>
                    <span class="vulnerability-severity severity-critical">{{ vuln.severity }}</span>
                </div>
                <div class="vulnerability-body">
                    <div class="vulnerability-details">
                        <h4>Description</h4>
                        <p>{{ vuln.details }}</p>
                        <p><strong>URL affectée:</strong> {{ vuln.url }}</p>
                    </div>
                    
                    {% if vuln.evidence %}
                    <div class="evidence-section">
                        <h4>Preuves techniques</h4>
                        <pre class="evidence-code">{{ vuln.evidence | tojson(indent=2) }}</pre>
                    </div>
                    {% endif %}
                    
                    {% if vuln.remediation %}
                    <div class="remediation-section">
                        <h4>Recommandations</h4>
                        <ul class="remediation-list">
                            {% for remedy in vuln.remediation %}
                            <li>{{ remedy }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </section>
        {% endif %}
        
        {% if high_vulnerabilities %}
        <section class="vulnerability-section">
            <h2>Vulnérabilités Élevées</h2>
            {% for vuln in high_vulnerabilities %}
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <h3 class="vulnerability-title">{{ vuln.type }}</h3>
                    <span class="vulnerability-severity severity-high">{{ vuln.severity }}</span>
                </div>
                <div class="vulnerability-body">
                    <div class="vulnerability-details">
                        <h4>Description</h4>
                        <p>{{ vuln.details }}</p>
                        <p><strong>URL affectée:</strong> {{ vuln.url }}</p>
                    </div>
                    
                    {% if vuln.evidence %}
                    <div class="evidence-section">
                        <h4>Preuves techniques</h4>
                        <pre class="evidence-code">{{ vuln.evidence | tojson(indent=2) }}</pre>
                    </div>
                    {% endif %}
                    
                    {% if vuln.remediation %}
                    <div class="remediation-section">
                        <h4>Recommandations</h4>
                        <ul class="remediation-list">
                            {% for remedy in vuln.remediation %}
                            <li>{{ remedy }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </section>
        {% endif %}
        
        {% if medium_vulnerabilities %}
        <section class="vulnerability-section">
            <h2>Vulnérabilités Moyennes</h2>
            {% for vuln in medium_vulnerabilities %}
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <h3 class="vulnerability-title">{{ vuln.type }}</h3>
                    <span class="vulnerability-severity severity-medium">{{ vuln.severity }}</span>
                </div>
                <div class="vulnerability-body">
                    <div class="vulnerability-details">
                        <h4>Description</h4>
                        <p>{{ vuln.details }}</p>
                        <p><strong>URL affectée:</strong> {{ vuln.url }}</p>
                    </div>
                    
                    {% if vuln.evidence %}
                    <div class="evidence-section">
                        <h4>Preuves techniques</h4>
                        <pre class="evidence-code">{{ vuln.evidence | tojson(indent=2) }}</pre>
                    </div>
                    {% endif %}
                    
                    {% if vuln.remediation %}
                    <div class="remediation-section">
                        <h4>Recommandations</h4>
                        <ul class="remediation-list">
                            {% for remedy in vuln.remediation %}
                            <li>{{ remedy }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </section>
        {% endif %}
        
        {% if low_vulnerabilities %}
        <section class="vulnerability-section">
            <h2>Vulnérabilités Faibles</h2>
            {% for vuln in low_vulnerabilities %}
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <h3 class="vulnerability-title">{{ vuln.type }}</h3>
                    <span class="vulnerability-severity severity-low">{{ vuln.severity }}</span>
                </div>
                <div class="vulnerability-body">
                    <div class="vulnerability-details">
                        <h4>Description</h4>
                        <p>{{ vuln.details }}</p>
                        <p><strong>URL affectée:</strong> {{ vuln.url }}</p>
                    </div>
                    
                    {% if vuln.evidence %}
                    <div class="evidence-section">
                        <h4>Preuves techniques</h4>
                        <pre class="evidence-code">{{ vuln.evidence | tojson(indent=2) }}</pre>
                    </div>
                    {% endif %}
                    
                    {% if vuln.remediation %}
                    <div class="remediation-section">
                        <h4>Recommandations</h4>
                        <ul class="remediation-list">
                            {% for remedy in vuln.remediation %}
                            <li>{{ remedy }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </section>
        {% endif %}
        
        {% if llm_analysis %}
        <section class="vulnerability-section">
            <h2>Analyse LLM</h2>
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <h3 class="vulnerability-title">Analyse par Intelligence Artificielle</h3>
                </div>
                <div class="vulnerability-body">
                    <div class="vulnerability-details">
                        <p>{{ llm_analysis.raw_analysis }}</p>
                    </div>
                    
                    {% if llm_analysis.vulnerabilities %}
                    <div class="evidence-section">
                        <h4>Vulnérabilités détectées par l'IA</h4>
                        {% for vuln in llm_analysis.vulnerabilities %}
                        <div style="margin-bottom: 1rem;">
                            <h5>{{ vuln.type }} ({{ vuln.risk_level }})</h5>
                            <p>{{ vuln.description }}</p>
                            <p><strong>Détails techniques:</strong> {{ vuln.technical_details }}</p>
                            
                            {% if vuln.recommendations %}
                            <h6>Recommandations:</h6>
                            <ul>
                                {% for rec in vuln.recommendations %}
                                <li>{{ rec }}</li>
                                {% endfor %}
                            </ul>
                            {% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    {% if llm_analysis.general_recommendations %}
                    <div class="remediation-section">
                        <h4>Recommandations générales</h4>
                        <ul class="remediation-list">
                            {% for rec in llm_analysis.general_recommendations %}
                            <li>{{ rec }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
        </section>
        {% endif %}
        
        <footer class="footer">
            <p>Rapport généré par WebPhantom - Outil de pentest web automatisé</p>
            <p>© {{ current_year }} WebPhantom</p>
        </footer>
    </div>
</body>
</html>
"""

def save_template_files():
    """
    Sauvegarde les templates HTML dans le répertoire des templates.
    """
    template_path = os.path.join(TEMPLATES_DIR, "report_template.html")
    
    # Créer le template s'il n'existe pas
    if not os.path.exists(template_path):
        with open(template_path, "w") as f:
            f.write(HTML_TEMPLATE)
        logger.info(f"Template HTML créé: {template_path}")

def generate_report(scan_results, target_url, scan_duration, llm_analysis=None, output_format="html"):
    """
    Génère un rapport à partir des résultats de scan.
    
    Args:
        scan_results: Liste des résultats de vulnérabilité
        target_url: URL cible du scan
        scan_duration: Durée du scan
        llm_analysis: Résultats de l'analyse LLM (optionnel)
        output_format: Format de sortie ("html" ou "pdf")
        
    Returns:
        str: Chemin vers le fichier de rapport généré
    """
    # S'assurer que les templates existent
    save_template_files()
    
    # Créer l'environnement Jinja2
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    # Charger le template
    template = env.get_template("report_template.html") if os.path.exists(os.path.join(TEMPLATES_DIR, "report_template.html")) else env.from_string(HTML_TEMPLATE)
    
    # Préparer les données pour le template
    now = datetime.datetime.now()
    
    # Trier les vulnérabilités par sévérité
    critical_vulns = []
    high_vulns = []
    medium_vulns = []
    low_vulns = []
    
    for result in scan_results:
        if isinstance(result, dict):
            severity = result.get("severity", "").lower()
            if severity == "critical":
                critical_vulns.append(result)
            elif severity == "high":
                high_vulns.append(result)
            elif severity == "medium":
                medium_vulns.append(result)
            else:
                low_vulns.append(result)
        else:
            # Si c'est un objet avec des attributs
            severity = getattr(result, "severity", "").lower()
            if severity == "critical":
                critical_vulns.append(result.to_dict() if hasattr(result, "to_dict") else vars(result))
            elif severity == "high":
                high_vulns.append(result.to_dict() if hasattr(result, "to_dict") else vars(result))
            elif severity == "medium":
                medium_vulns.append(result.to_dict() if hasattr(result, "to_dict") else vars(result))
            else:
                low_vulns.append(result.to_dict() if hasattr(result, "to_dict") else vars(result))
    
    # Préparer les données du contexte
    context = {
        "title": f"Rapport de sécurité pour {target_url}",
        "generation_date": now.strftime("%d/%m/%Y %H:%M:%S"),
        "target_url": target_url,
        "scan_duration": scan_duration,
        "total_vulnerabilities": len(scan_results),
        "critical_count": len(critical_vulns),
        "high_count": len(high_vulns),
        "medium_count": len(medium_vulns),
        "low_count": len(low_vulns),
        "critical_vulnerabilities": critical_vulns,
        "high_vulnerabilities": high_vulns,
        "medium_vulnerabilities": medium_vulns,
        "low_vulnerabilities": low_vulns,
        "llm_analysis": llm_analysis,
        "current_year": now.year
    }
    
    # Générer le HTML
    html_content = template.render(**context)
    
    # Créer le nom de fichier basé sur l'URL et la date
    url_part = target_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
    date_part = now.strftime("%Y%m%d_%H%M%S")
    filename_base = f"webphantom_report_{url_part}_{date_part}"
    
    # Chemin du fichier HTML
    html_path = os.path.join(REPORTS_DIR, f"{filename_base}.html")
    
    # Sauvegarder le HTML
    with open(html_path, "w") as f:
        f.write(html_content)
    
    logger.info(f"Rapport HTML généré: {html_path}")
    
    # Si le format demandé est PDF, convertir le HTML en PDF
    if output_format.lower() == "pdf":
        pdf_path = os.path.join(REPORTS_DIR, f"{filename_base}.pdf")
        try:
            # Convertir HTML en PDF avec WeasyPrint
            weasyprint.HTML(string=html_content).write_pdf(pdf_path)
            logger.info(f"Rapport PDF généré: {pdf_path}")
            return pdf_path
        except Exception as e:
            logger.error(f"Erreur lors de la génération du PDF: {e}")
            return html_path
    
    return html_path

def run(url, results, duration, llm_results=None, format="html"):
    """
    Point d'entrée principal pour la génération de rapports.
    
    Args:
        url: URL cible du scan
        results: Résultats du scan
        duration: Durée du scan
        llm_results: Résultats de l'analyse LLM (optionnel)
        format: Format de sortie ("html" ou "pdf")
        
    Returns:
        str: Chemin vers le fichier de rapport généré
    """
    print(f"[*] Génération du rapport {format.upper()} pour : {url}")
    
    try:
        report_path = generate_report(results, url, duration, llm_results, format)
        print(f"[+] Rapport généré avec succès: {report_path}")
        return report_path
    except Exception as e:
        print(f"[!] Erreur lors de la génération du rapport: {e}")
        return None

if __name__ == "__main__":
    # Exemple d'utilisation
    from advanced_vulns import VulnerabilityResult
    
    # Créer quelques résultats de test
    test_results = [
        VulnerabilityResult("XSS", "http://example.com/search?q=test", "Vulnérabilité XSS reflétée dans le paramètre q", "High"),
        VulnerabilityResult("SQLi", "http://example.com/user?id=1", "Injection SQL possible dans le paramètre id", "Critical"),
        VulnerabilityResult("CSRF", "http://example.com/profile", "Formulaire sans protection CSRF", "Medium")
    ]
    
    # Générer un rapport de test
    run("http://example.com", test_results, "00:01:23", format="html")
