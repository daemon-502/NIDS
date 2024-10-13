from scapy.all import sniff, TCP, IP, UDP, ICMP
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import time
import os

volume_trafic = Counter()
alertes = []

# Détection d'un scan SYN
def detecter_scan_syn(packet):
    if TCP in packet and packet[TCP].flags == 'S':  # SYN flag
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        print(f"Scan SYN détecté de {src_ip} vers {dst_ip}:{dst_port}")
        alertes.append(f"Scan SYN détecté de {src_ip} vers {dst_ip}:{dst_port}")

# Détection d'activité anormale par volume de trafic
def compter_paquets(packet):
    if IP in packet:
        src_ip = packet[IP].src
        volume_trafic[src_ip] += 1

def afficher_volume():
    for src_ip, count in volume_trafic.items():
        if count > 100:  # Seuil arbitraire, à ajuster en fonction du trafic
            message = f"Activité anormale détectée : {src_ip} a envoyé {count} paquets."
            print(message)
            alertes.append(message)

# Détection d'un flood UDP
def detecter_flood_udp(packet):
    if UDP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[UDP].dport
        alertes.append(f"Possible UDP flood détecté de {src_ip} vers {dst_ip}:{dst_port}")

# Détection des paquets ICMP (ex : ping flood)
def detecter_flood_icmp(packet):
    if ICMP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        alertes.append(f"Paquet ICMP détecté de {src_ip} vers {dst_ip} (possible ping flood)")

# Capture des paquets réseau
def capturer_paquets(duree_capture=60):
    print(f"Capture du trafic pendant {duree_capture} secondes...")
    # Utiliser un filtre pour ne capturer que les paquets IP
    sniff(filter="ip", prn=analyser_paquet, timeout=duree_capture)

# Analyse et détection des paquets capturés
def analyser_paquet(packet):
    detecter_scan_syn(packet)
    compter_paquets(packet)
    detecter_flood_udp(packet)
    detecter_flood_icmp(packet)

# Génération des alertes et affichage des volumes
def systeme_alerte():
    afficher_volume()
    print("Analyse complète du trafic.")

# Génération du rapport PDF avec horodatage
def generer_rapport_pdf():
    # Nom du fichier avec horodatage
    horodatage = time.strftime("%Y%m%d-%H%M%S")
    nom_fichier = f"log_nids_{horodatage}.pdf"
    
    # Création du PDF
    c = canvas.Canvas(nom_fichier, pagesize=letter)
    c.setTitle(f"Rapport NIDS - {horodatage}")
    
    # Titre et date
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Rapport NIDS - Détection d'Intrusion Réseau")
    c.setFont("Helvetica", 12)
    c.drawString(100, 730, f"Date : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Détails des alertes
    c.setFont("Helvetica", 12)
    c.drawString(100, 700, "Détails des scans SYN et des anomalies détectées :")
    
    y = 680  # Position initiale pour le texte
    for alerte in alertes:
        c.drawString(100, y, alerte)
        y -= 20
        if y < 50:  # Passer à une nouvelle page si nécessaire
            c.showPage()
            c.setFont("Helvetica", 12)
            y = 750
    
    # Résumé du volume de trafic
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y - 20, "Résumé du volume de trafic :")
    y -= 40
    for src_ip, count in volume_trafic.items():
        c.drawString(100, y, f"IP {src_ip} a envoyé {count} paquets.")
        y -= 20
        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 12)
            y = 750
    
    # Sauvegarde du fichier PDF
    c.save()
    print(f"Rapport PDF généré : {nom_fichier}")

if __name__ == "__main__":
    print("Démarrage du NIDS...")
    # Capture du trafic pour 60 secondes (peut être ajusté)
    capturer_paquets(duree_capture=60)
    systeme_alerte()
    
    # Génération du rapport PDF
    generer_rapport_pdf()
