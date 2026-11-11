import requests
from bs4 import BeautifulSoup

DVWA_URL = "http://localhost"  # troque para http://localhost:8080 se você usou essa porta

def get_logged_session():
    """Faz login no DVWA e devolve uma requests.Session autenticada."""
    session = requests.Session()

    # 1. Carrega a página de login para pegar o token CSRF atual
    login_page = session.get(f"{DVWA_URL}/login.php")
    soup = BeautifulSoup(login_page.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    csrf_token = token_input["value"] if token_input else ""

    # 2. Envia o formulário de login com o token
    resp = session.post(f"{DVWA_URL}/login.php", data={
        "username": "admin",
        "password": "password",
        "user_token": csrf_token,
        "Login": "Login",
    })

    # 3. Confere se o login funcionou (a página pós-login mostra "Logout")
    if "Logout" not in resp.text:
        raise RuntimeError("Login no DVWA falhou — confira usuário/senha ou a URL.")

    return session


if __name__ == "__main__":
    s = get_logged_session()
    print("Login no DVWA OK — sessão autenticada.")