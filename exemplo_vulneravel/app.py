import os
import pickle
import sqlite3

# Falha 1: segredo exposto no código-fonte
API_KEY = "DEMO_CHAVE_FALSA_PARA_TESTE_12345"
DB_PASSWORD = "SenhaSuperSecreta123"


def buscar_usuario(conexao, id_usuario):
    # Falha 2: SQL Injection via concatenação de string (não parametrizado)
    query = "SELECT * FROM usuarios WHERE id = '" + id_usuario + "'"
    cursor = conexao.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def calcular_expressao(expressao_usuario):
    # Falha 3: eval() em entrada vinda do usuário
    resultado = eval(expressao_usuario)
    return resultado


def carregar_preferencias(dados_serializados):
    # Falha 4: deserialização insegura de dado não confiável
    preferencias = pickle.loads(dados_serializados)
    return preferencias


def executar_comando(nome_arquivo):
    # Falha 5: injeção de comando via os.system
    os.system("cat " + nome_arquivo)