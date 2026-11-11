import json
import os
from custom_rules import scan_directory

BANDIT_RAW = "achados/bandit_raw.json"
SEMGREP_RAW = "achados/semgrep_raw.json"
ALVO = "exemplo_vulneravel"


def parse_bandit(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [{
        "ferramenta": "bandit",
        "arquivo": item["filename"],
        "linha": item["line_number"],
        "regra": item["test_id"],
        "mensagem": item["issue_text"],
        "severidade": item["issue_severity"].lower(),
        "trecho": item.get("code", "").strip(),
    } for item in data.get("results", [])]


def parse_semgrep(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [{
        "ferramenta": "semgrep",
        "arquivo": item["path"],
        "linha": item["start"]["line"],
        "regra": item["check_id"],
        "mensagem": item["extra"]["message"],
        "severidade": item["extra"].get("severity", "info").lower(),
        "trecho": item["extra"].get("lines", "").strip(),
    } for item in data.get("results", [])]


SEVERIDADE_ORDEM = {"info": 0, "low": 0, "baixa": 0, "medium": 1, "warning": 1, "média": 1,
                     "high": 2, "error": 2, "alta": 2, "critica": 3}


def merge_findings(todos_achados):
    """Agrupa achados pelo mesmo arquivo+linha, juntando as ferramentas que concordaram."""
    agrupado = {}
    for f in todos_achados:
        chave = (os.path.normpath(f["arquivo"]), f["linha"])
        if chave not in agrupado:
            agrupado[chave] = {
                "arquivo": chave[0], "linha": chave[1],
                "ferramentas": [f["ferramenta"]], "regras": [f["regra"]],
                "mensagem_principal": f["mensagem"], "severidade": f["severidade"],
                "trecho": f["trecho"],
            }
        else:
            entrada = agrupado[chave]
            if f["ferramenta"] not in entrada["ferramentas"]:
                entrada["ferramentas"].append(f["ferramenta"])
            if f["regra"] not in entrada["regras"]:
                entrada["regras"].append(f["regra"])
            if SEVERIDADE_ORDEM.get(f["severidade"], 1) > SEVERIDADE_ORDEM.get(entrada["severidade"], 1):
                entrada["severidade"] = f["severidade"]
    return list(agrupado.values())


def save_findings(findings, path="achados/estatica.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)
    print(f"\n{len(findings)} achado(s) únicos (após mesclagem) salvos em {path}")


if __name__ == "__main__":
    bandit_findings = parse_bandit(BANDIT_RAW)
    semgrep_findings = parse_semgrep(SEMGREP_RAW)
    custom_findings = scan_directory(ALVO)

    print(f"Bandit: {len(bandit_findings)} | Semgrep: {len(semgrep_findings)} | Regras próprias: {len(custom_findings)}")

    todos = bandit_findings + semgrep_findings + custom_findings
    merged = merge_findings(todos)

    for m in merged:
        print(f"\n{m['arquivo']}:{m['linha']} [{m['severidade']}] — detectado por {m['ferramentas']}")
        print(f"  {m['mensagem_principal'][:90]}")

    save_findings(merged)