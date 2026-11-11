import re
import os

SECRET_PATTERN = re.compile(r'(API_KEY|SECRET|PASSWORD|TOKEN)\w*\s*=\s*["\']([^"\']{8,})["\']', re.IGNORECASE)
SHELL_PATTERN = re.compile(r'os\.system\(|subprocess\.(call|run|Popen)\(.*\+')
EVAL_EXEC_PATTERN = re.compile(r'\b(eval|exec)\s*\(')


def scan_file(filepath):
    findings = []
    with open(filepath, encoding="utf-8") as f:
        linhas = f.readlines()

    for i, linha in enumerate(linhas, start=1):
        if SECRET_PATTERN.search(linha):
            findings.append({
                "ferramenta": "regra_propria", "arquivo": filepath, "linha": i,
                "regra": "segredo_hardcoded",
                "mensagem": "Possível segredo (chave/senha/token) codificado diretamente no arquivo",
                "severidade": "alta", "trecho": linha.strip(),
            })
        if SHELL_PATTERN.search(linha):
            findings.append({
                "ferramenta": "regra_propria", "arquivo": filepath, "linha": i,
                "regra": "comando_shell_concatenado",
                "mensagem": "Execução de comando do SO com entrada concatenada — risco de injeção de comando",
                "severidade": "alta", "trecho": linha.strip(),
            })
        if EVAL_EXEC_PATTERN.search(linha):
            findings.append({
                "ferramenta": "regra_propria", "arquivo": filepath, "linha": i,
                "regra": "eval_exec_detectado",
                "mensagem": "Uso de eval()/exec() — pode executar código arbitrário se a entrada vier do usuário",
                "severidade": "alta", "trecho": linha.strip(),
            })
    return findings


def scan_directory(diretorio):
    findings = []
    for raiz, _, arquivos in os.walk(diretorio):
        for nome in arquivos:
            if nome.endswith(".py"):
                findings.extend(scan_file(os.path.join(raiz, nome)))
    return findings