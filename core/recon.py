import requests
from bs4 import BeautifulSoup

def run(url):
    # Backward compatibility for tests expecting French substring
    print(f"[*] Analyse de l'application web : {url}")
    print(f"[*] Web application analysis: {url}")
    try:
        r = requests.get(url, timeout=5)
        print(f"[+] HTTP status code: {r.status_code}")
        print(f"[+] Server type: {r.headers.get('Server')}")
          
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        print(f"[+] {len(forms)} form element(s) found.")

        scripts = soup.find_all('script')
        print(f"[+] {len(scripts)} <script> tag(s) found.")

    except Exception as e:
        print(f"[!] Recon error: {e}")