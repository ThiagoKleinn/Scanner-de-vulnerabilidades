import os
import json
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from dvwa_session import DVWA_URL

XSS_R_URL = f"{DVWA_URL}/vulnerabilities/xss_r/"
XSS_S_URL = f"{DVWA_URL}/vulnerabilities/xss_s/"


def get_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    return webdriver.Chrome(options=options)


def login(driver):
    driver.get(f"{DVWA_URL}/login.php")
    driver.find_element(By.NAME, "username").send_keys("admin")
    driver.find_element(By.NAME, "password").send_keys("password")
    driver.find_element(By.NAME, "Login").click()
    time.sleep(1)

    if "Logout" not in driver.page_source:
        raise RuntimeError("Login via Selenium falhou.")


def test_xss_reflected(driver):
    payload = "<script>window.__xss_hit = true;</script>"
    driver.get(f"{XSS_R_URL}?name={payload}")
    executou = driver.execute_script("return window.__xss_hit === true;")
    return {"payload": payload, "executou": executou}


def test_xss_stored(driver):
    payload = "<script>window.__xss_hit_stored = true;</script>"

    driver.get(XSS_S_URL)
    driver.find_element(By.NAME, "txtName").send_keys("teste")
    driver.find_element(By.NAME, "mtxMessage").send_keys(payload)
    driver.find_element(By.NAME, "btnSign").click()
    time.sleep(1)

    driver.get(XSS_S_URL)  # recarrega do zero, sem reenviar o formulário
    executou = driver.execute_script("return window.__xss_hit_stored === true;")

    os.makedirs("evidencias", exist_ok=True)
    screenshot_path = "evidencias/xss_armazenado.png"
    driver.save_screenshot(screenshot_path)

    return {"payload": payload, "executou": executou, "screenshot": screenshot_path}


def run():
    driver = get_driver()
    login(driver)
    refletido = test_xss_reflected(driver)
    armazenado = test_xss_stored(driver)
    driver.quit()
    return refletido, armazenado


def classify(refletido, armazenado):
    findings = []

    if refletido["executou"]:
        findings.append({
            "tipo": "xss_refletido",
            "parametro": "name",
            "payload": refletido["payload"],
            "evidencia": "window.__xss_hit foi definida como true após a requisição — o script foi executado de verdade pelo navegador, não só refletido como texto",
            "severidade": "alta",
        })

    if armazenado["executou"]:
        findings.append({
            "tipo": "xss_armazenado",
            "parametro": "mtxMessage",
            "payload": armazenado["payload"],
            "evidencia": "A variável continuou true após recarregar a página do zero, sem reenviar o formulário — confirma persistência (diferencia de refletido)",
            "severidade": "critica",
            "screenshot": armazenado["screenshot"],
        })

    return findings


def save_findings(findings, path="achados/xss.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)
    print(f"\n{len(findings)} achado(s) salvo(s) em {path}")


if __name__ == "__main__":
    refletido, armazenado = run()
    print("[XSS refletido]", refletido)
    print("[XSS armazenado]", armazenado)

    findings = classify(refletido, armazenado)
    save_findings(findings)