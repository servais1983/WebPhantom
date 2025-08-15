import requests

def run(url):
    # Backward compatibility for tests expecting French substring
    print(f"[*] Test de vulnérabilités sur : {url}")
    print(f"[*] Vulnerability tests on: {url}")
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
                print(f"[+] POTENTIAL {vuln} detected at {full_url}")
            else:
                print(f"[-] {vuln} not detected at {full_url}")
        except Exception as e:
            print(f"[!] Error during {vuln} test: {e}")