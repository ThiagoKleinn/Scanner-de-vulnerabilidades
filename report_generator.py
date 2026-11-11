import json
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

SEVERIDADE_MAP = {
    "low": "baixa", "info": "baixa", "baixa": "baixa",
    "medium": "media", "warning": "media", "media": "media", "média": "media",
    "high": "alta", "error": "alta", "alta": "alta",
    "critica": "critica", "crítica": "critica",
}

TIPO_LABEL = {
    "sqli_baseado_em_erro": "SQL Injection — baseado em erro/union",
    "sqli_booleano": "SQL Injection — booleano",
    "sqli_baseado_em_tempo": "SQL Injection — baseado em tempo",
    "xss_refletido": "XSS Refletido",
    "xss_armazenado": "XSS Armazenado",
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def normalizar(achados):
    for a in achados:
        a["severidade"] = SEVERIDADE_MAP.get(a["severidade"].lower(), a["severidade"].lower())
        if a.get("tipo") in TIPO_LABEL:
            a["tipo_label"] = TIPO_LABEL[a["tipo"]]
    return achados


def gerar_relatorio():
    sqli = normalizar(load_json("achados/sqli.json"))
    xss = normalizar(load_json("achados/xss.json"))
    estatica = normalizar(load_json("achados/estatica.json"))

    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("relatorio_template.html")
    html_renderizado = template.render(sqli=sqli, xss=xss, estatica=estatica)

    with open("relatorio_final.html", "w", encoding="utf-8") as f:
        f.write(html_renderizado)

    HTML(string=html_renderizado, base_url=".").write_pdf("relatorio_final.pdf")
    print("Relatório gerado: relatorio_final.html e relatorio_final.pdf")


if __name__ == "__main__":
    gerar_relatorio()