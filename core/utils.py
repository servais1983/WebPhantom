import yaml
from core import recon, vulns, ai_analyzer

def run_script_yaml(path):
    print(f"[*] Chargement du scénario : {path}")
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    url = data.get("target")
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