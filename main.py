import subprocess
import sys

print("=== Rodando Módulo 1: SQL Injection ===")
subprocess.run([sys.executable, "sqli_scanner.py"], check=True)

print("\n=== Rodando Módulo 2: XSS ===")
subprocess.run([sys.executable, "xss_scanner.py"], check=True)

print("\n=== Rodando Módulo 3: Análise Estática ===")
subprocess.run(["bandit", "-r", "exemplo_vulneravel", "-f", "json", "-o", "achados/bandit_raw.json"])
subprocess.run(["semgrep", "--config=auto", "exemplo_vulneravel", "--json", "--output", "achados/semgrep_raw.json"])
subprocess.run([sys.executable, "static_scanner.py"], check=True)

print("\n=== Gerando relatório final ===")
from report_generator import gerar_relatorio
gerar_relatorio()