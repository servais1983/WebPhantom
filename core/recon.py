import requests
from bs4 import BeautifulSoup

def run(url):
    print(f"[*] Analyse de l'application web : {url}")
    try:
        r = requests.get(url, timeout=5)
        print(f"[+] Code HTTP : {r.status_code}")
        print(f"[+] Type de serveur : {r.headers.get('Server')}")
          
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        print(f"[+] {len(forms)} formulaire(s) détecté(s).")

        scripts = soup.find_all('script')
        print(f"[+] {len(scripts)} balise(s) <script> détectée(s).")

    except Exception as e:
        print(f"[!] Erreur de reconnaissance : {e}")