import csv
from pathlib import Path

# Chemin du fichier contenant les vulnérabilités
file_path = Path("data/samples/vulnerabilities.csv")

# Lecture du rapport CSV
with file_path.open("r", encoding="utf-8-sig", newline="") as file:
    reader = csv.DictReader(file)
    vulnerabilities = list(reader)

print("=== CyberRemediate 360 ===")
print(f"Nombre de vulnérabilités importées : {len(vulnerabilities)}")

for vulnerability in vulnerabilities:
    print(
        f"Serveur : {vulnerability['hostname']} | "
        f"CVE : {vulnerability['cve_id']} | "
        f"CVSS : {vulnerability['cvss_score']}"
    )