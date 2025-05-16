import requests

def run(url):
    print(f"[*] Test de vulnérabilités sur : {url}")
    payloads = {
        "XSS": "<script>alert(1)</script>",
        "SQLi": "' OR '1'='1",
        "LFI": "../../etc/passwd"
    }

    for vuln, payload in payloads.items():
        try:
            full_url = f"{url}?q={payload}"
            r = requests.get(full_url, timeout=5)
            if payload in r.text or "root:" in r.text:
                print(f"[+] POTENTIEL {vuln} détecté sur {full_url}")
            else:
                print(f"[-] {vuln} non détecté sur {full_url}")
        except Exception as e:
            print(f"[!] Erreur pendant le test {vuln} : {e}")