# Projet - NIDS (Network Intrusion Detection System)

## Description
Un NIDS (Network Intrusion Detection System) est une sonde réseau permettant d'analyser le trafic en temps réel afin de détecter des activités inhabituelles ou malveillantes. Parmi ces activités, on retrouve les scans de ports, tentatives d'intrusion, mouvements latéraux, exfiltration de données, portes dérobées, etc.

Initialement, ces systèmes fonctionnaient à l'aide de signatures statiques. Aujourd'hui, des solutions comme le NTA (Network Traffic Analysis) et l'XDR (Extended Detection & Response) incluent des fonctionnalités NIDS, avec plus de 80 000 règles régulièrement mises à jour pour améliorer la détection.

## Objectif du projet
Développer un NIDS basique capable de :
- Capturer le trafic réseau en temps réel
- Analyser les paquets pour détecter des anomalies ou des signatures d'attaques spécifiques (scans de ports, attaques par déni de service, etc.)
- Alerter l'utilisateur en cas de détection

## Outils et technologies utilisés
- **Python 3.X**
- **Scapy** : Une puissante bibliothèque Python pour la manipulation et l'analyse des paquets réseau.

## Fonctionnalités prévues
- Capture du trafic réseau en temps réel
- Analyse des paquets pour détecter des comportements anormaux
- Notifications en cas de détection d'activité suspecte
