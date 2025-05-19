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
            .skipped {{
                color: #6c757d;
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
                <p><strong>Scans ignorés:</strong> {results['summary'].get('skipped_scans', 0)}</p>
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
            if tool_result.get('skipped', False):
                status_class = "skipped"
                status_text = "Ignoré"
            elif tool_result.get('success', False):
                status_class = "success"
                status_text = "Réussi"
            else:
                status_class = "failure"
                status_text = "Échoué"
            
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
