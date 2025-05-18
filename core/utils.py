import yaml
from core import recon, vulns, ai_analyzer

def run_script_yaml(path, target_url=None):
    print(f"[*] Chargement du scénario : {path}")
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    # Utiliser l'URL fournie en ligne de commande si disponible, sinon celle du fichier YAML
    url = target_url if target_url else data.get("target")
    
    if url:
        print(f"[*] Cible : {url}")
    else:
        print("[!] Erreur : Aucune URL cible spécifiée (ni dans le fichier YAML, ni en ligne de commande)")
        return
    
    for step in data.get("steps", []):
        step_type = step.get("type")
        if step_type == "recon":
            recon.run(url)
        elif step_type == "scan":
            vulns.run(url)
        elif step_type == "ai_analysis":
            ai_analyzer.run(url)
        else:
            print(f"[!] Étape inconnue : {step_type}")
