#!/bin/bash
echo "[*] Installation de WebPhantom sur Kali..."

sudo apt update
sudo apt install -y python3 python3-pip
pip3 install -r requirements.txt

echo "[+] Installation terminée. Utilisez : python3 webphantom.py [commande]"