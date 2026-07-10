import os
import json
import requests
import markdown
import secrets
import sqlite3

from datetime import datetime
from collections import Counter
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, send_file, make_response
from requests.auth import HTTPBasicAuth
from openai import OpenAI


# =========================
# CONFIGURAÇÕES
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"))

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
APP_USER = os.getenv("APP_USER", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "admin")
APP_ANALYST_NAME = os.getenv("APP_ANALYST_NAME", APP_USER)

DB_PATH = os.path.join(BASE_DIR, "data", "historico_soc.db")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# =========================
# MULTI-TENANT (SIMULADO)
# =========================
# Mapeia o nome do agente Wazuh pro "cliente" que ele representa numa
# operação SOCaaS. Troque os nomes à vontade — é só rótulo de exibição,
# não muda nada na coleta real dos alertas.
CLIENTES_MAP = {
    "Windows_11": "Cliente A - TechCorp Solutions",
    "kali": "Cliente B - Comercio Silva ME",
}
CLIENTE_PADRAO = "Nao classificado"

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
#app.secret_key = os.getenv("FLASK_SECRET_KEY", "troque-essa-chave-em-producao")

# Histórico em memória para evitar problemas de session/cookie
HISTORICO = []

TOKENS_LOGIN = {}

# =========================
# FUNÇÕES AUXILIARES
# =========================

def markdown_to_html(texto):
    return markdown.markdown(
        texto or "",
        extensions=["extra", "tables", "fenced_code"]
    )


def salvar_markdown(nome_arquivo, conteudo):
    caminho = os.path.join(OUTPUT_DIR, nome_arquivo)

    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo or "")

    return caminho


# =========================
# COLETA DE ALERTAS WAZUH
# =========================

def coletar_alertas(limite=30):
    query = {
        "size": limite,
        "sort": [
            {"timestamp": {"order": "desc"}}
        ],
        "_source": [
            "timestamp",
            "agent.name",
            "agent.ip",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.groups",
            
            "data.event_type",
            "data.src_ip",
            "data.dest_ip",
            "data.srcip",
            "data.dstip",
            "data.proto",
            "data.alert.signature",
            "data.alert.category",
            "data.alert.severity",
            
            "data.win.system.eventID",
            "data.win.system.channel",
            "data.win.system.providerName",
            "data.win.system.computer",
            "data.win.eventdata.user",
            "data.win.eventdata.image",
            "data.win.eventdata.commandLine",
            "data.win.eventdata.parentImage",
            "data.win.eventdata.parentCommandLine",
            "data.win.eventdata.destinationIp",
            "data.win.eventdata.destinationPort",
            "data.win.eventdata.sourceIp",
            "data.win.eventdata.sourcePort",
            "data.win.eventdata.queryName",

            "syscheck.path",
            "syscheck.event",
            "location"
        ],

        "query": {
            "bool": {
                "should": [
                    {"match": {"rule.groups": "suricata"}},
                    {"match": {"rule.groups": "sshd"}},
                    {"match": {"rule.groups": "syscheck"}},
                    {"match": {"rule.id": "5712"}},
                    {"match": {"rule.id": "5710"}},
                    {"match": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}}
                ],
                "minimum_should_match": 1
            }
        }
    }

    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"

    response = requests.get(
        url,
        auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
        headers={"Content-Type": "application/json"},
        data=json.dumps(query),
        verify=False,
        timeout=20
    )

    if response.status_code != 200:
        raise Exception(
            f"Erro ao consultar Wazuh Indexer: {response.status_code} - {response.text}"
        )

    hits = response.json().get("hits", {}).get("hits", [])
    eventos = []

    for hit in hits:
        src = hit.get("_source", {})
        data = src.get("data", {})
        alert = data.get("alert", {})
        rule = src.get("rule", {})
        agent = src.get("agent", {})
        syscheck = src.get("syscheck", {})

        eventos.append({
            "timestamp": src.get("timestamp"),
            "agent": agent.get("name"),
            "agent_ip": agent.get("ip"),
            "cliente": CLIENTES_MAP.get(agent.get("name"), CLIENTE_PADRAO),
            "rule_id": rule.get("id"),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "groups": rule.get("groups"),
            
            # Suricata / NDR
            "src_ip": data.get("src_ip") or data.get("srcip"),
            "dest_ip": data.get("dest_ip") or data.get("dstip"),
            "proto": data.get("proto"),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "suricata_severity": alert.get("severity"),

            # FIM / Syscheck 
            "fim_path": syscheck.get("path"),
            "fim_event": syscheck.get("event"),
            "location": src.get("location"),

            # Windows / Sysmon 
            "win_event_id": data.get("win", {}).get("system", {}).get("eventID"),
            "win_channel": data.get("win", {}).get("system", {}).get("channel"),
            "win_provider": data.get("win", {}).get("system", {}).get("providerName"),
            "win_computer": data.get("win", {}).get("system", {}).get("computer"),
            "win_user": data.get("win", {}).get("eventdata", {}).get("user"),
            "process_image": data.get("win", {}).get("eventdata", {}).get("image"),
            "command_line": data.get("win", {}).get("eventdata", {}).get("commandLine"),
            "parent_image": data.get("win", {}).get("eventdata", {}).get("parentImage"),
            "parent_command_line": data.get("win", {}).get("eventdata", {}).get("parentCommandLine"),
            "destination_ip": data.get("win", {}).get("eventdata", {}).get("destinationIp"),
            "destination_port": data.get("win", {}).get("eventdata", {}).get("destinationPort"),
            "source_ip": data.get("win", {}).get("eventdata", {}).get("sourceIp"),
            "source_port": data.get("win", {}).get("eventdata", {}).get("sourcePort"),
            "dns_query": data.get("win", {}).get("eventdata", {}).get("queryName"),

            "location": src.get("location")
        })

    # Mantém uma cópia local dos alertas recentes
    caminho_alertas = os.path.join(OUTPUT_DIR, "alertas_wazuh.json")
    with open(caminho_alertas, "w", encoding="utf-8") as f:
        json.dump(eventos, f, indent=2, ensure_ascii=False)

    return eventos


# =========================
# IA - PERGUNTA LIVRE
# =========================

# =========================
# HELPER - RESUMO DE LOTE (pra SLA e multi-tenant)
# =========================

def resumo_lote(eventos):
    """Retorna (cliente_predominante, timestamp_do_alerta_mais_recente) de um lote de eventos."""
    if not eventos:
        return CLIENTE_PADRAO, None

    contagem = {}
    mais_recente = None

    for e in eventos:
        c = e.get("cliente", CLIENTE_PADRAO)
        contagem[c] = contagem.get(c, 0) + 1

        ts = e.get("timestamp")
        if ts and (mais_recente is None or ts > mais_recente):
            mais_recente = ts

    cliente_predominante = max(contagem, key=contagem.get)
    return cliente_predominante, mais_recente

# =========================
# ESTATÍSTICAS POR CLIENTE (MULTI-TENANT)
# =========================

def estatisticas_por_cliente(eventos):
    stats = {}

    for e in eventos:
        cliente = e.get("cliente", CLIENTE_PADRAO)

        if cliente not in stats:
            stats[cliente] = {
                "cliente": cliente,
                "total": 0,
                "criticos": 0,
                "altos": 0,
                "medios": 0,
                "baixos": 0,
                "ultimo_alerta": None,
            }

        registro = stats[cliente]
        registro["total"] += 1

        try:
            level = int(e.get("level") or 0)
        except (TypeError, ValueError):
            level = 0

        if level >= 11:
            registro["criticos"] += 1
        elif level >= 7:
            registro["altos"] += 1
        elif level >= 4:
            registro["medios"] += 1
        else:
            registro["baixos"] += 1

        ts = e.get("timestamp")
        if ts and (registro["ultimo_alerta"] is None or ts > registro["ultimo_alerta"]):
            registro["ultimo_alerta"] = ts

    return sorted(stats.values(), key=lambda r: r["total"], reverse=True)

def perguntar_ia(pergunta, eventos):
    prompt = f"""
Você é um assistente SOC N1/N2 integrado ao Wazuh.

Contexto:
- Quando possível, mapeie os eventos para técnicas MITRE ATT&CK.
- Não force mapeamento MITRE se não houver evidência suficiente.
- Para cada técnica MITRE, informe: ID, nome, evidência observada e nível de confiança.
- Ambiente de laboratório simulando produção.
- Wazuh centraliza logs e alertas.
- Suricata representa IDS/NDR.
- Existem eventos de SSH, Suricata/NDR, FIM e Windows/Sysmon.
- Quando houver dados Sysmon, destaque criação de processos, linha de comando, processo pai, conexões de rede e usuário.
- Responda em português brasileiro.
- Use Markdown bem organizado.
- Não invente dados que não existam nos alertas.
- Se a pergunta não puder ser respondida com os dados, diga que precisa de mais evidências.

Escala Wazuh:
- Level 0 a 3: Baixa
- Level 4 a 6: Média
- Level 7 a 10: Alta
- Level 11 ou maior: Crítica

Pergunta do analista:
{pergunta}

Quando fizer mapeamento MITRE ATT&CK, use este formato:

## MITRE ATT&CK
| Técnica | Nome | Evidência | Confiança |
|---|---|---|---|
| Txxxx | Nome da técnica | Evidência observada nos alertas | Baixa/Média/Alta |

Exemplos de referência:
- T1110 - Brute Force: tentativas repetidas de autenticação SSH.
- T1046 - Network Service Discovery: varreduras, scans ou reconhecimento de serviços.
- T1059 - Command and Scripting Interpreter: uso de PowerShell, cmd ou scripts.
- T1105 - Ingress Tool Transfer: transferência/recebimento de arquivos por HTTP, curl, wget ou servidor web simples.
- T1005 - Data from Local System: acesso ou coleta de arquivos locais.
- T1070 - Indicator Removal: exclusão/limpeza de arquivos, rastros ou logs.
- T1027 - Obfuscated Files or Information: comandos codificados ou ofuscados.
- T1562 - Impair Defenses: alteração/desativação de serviços ou controles de segurança.

Alertas recentes:
{json.dumps(eventos, indent=2, ensure_ascii=False)}
"""

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt
    )

    return response.output_text

# =========================
# IA - RELATÓRIO EXECUTIVO
# =========================

def gerar_relatorio_executivo_ia(eventos):
    prompt = f"""
Você é um analista de segurança traduzindo um relatório técnico de SOC para um relatório
executivo, destinado a um gestor ou cliente não técnico (ex: dono de empresa, diretor, CEO).

Regras obrigatórias:
- NÃO use jargão técnico (nada de "MITRE ATT&CK", "syscheck", "IOC", "rule.id", etc.).
- NÃO inclua tabelas técnicas nem IDs de técnica.
- Traduza severidade técnica em impacto de negócio (ex: "risco de indisponibilidade",
  "possível exposição de dados", "tentativa de acesso não autorizado").
- Foque em: o que aconteceu, qual o risco pro negócio, o que já foi feito, o que precisa
  de decisão/ação do gestor.
- Seja direto e objetivo. Gestores têm pouco tempo.
- Responda em português brasileiro, em Markdown simples (títulos e listas, sem tabelas).
- Não invente informação que não exista nos alertas.
- Se não houver eventos relevantes, diga isso claramente e tranquilize o leitor.

Estrutura obrigatória da resposta:

## Resumo Executivo
(2-3 frases, o essencial pra quem só vai ler isso)

## O que foi observado
(linguagem de negócio, sem termos técnicos)

## Nível de risco
(Baixo / Médio / Alto / Crítico + 1 frase explicando por quê, em termos de impacto)

## Ações recomendadas
(lista curta, priorizada, do que precisa de decisão do gestor)

Alertas recentes (uso interno, não citar termos técnicos deles na resposta):
{json.dumps(eventos, indent=2, ensure_ascii=False)}
"""

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt
    )

    return response.output_text


# =========================
# IA - PLAYBOOK
# =========================

def gerar_playbook_ia(eventos):
    prompt = f"""
Você é um analista SOC N2/N3 especialista em resposta a incidentes, Wazuh, Suricata, SSH brute force, FIM, NDR e Active Response.

Contexto:
- Ambiente de laboratório simulando produção corporativa.
- Wazuh centraliza alertas de endpoint, SSH, FIM e Suricata.
- Suricata representa IDS/NDR.
- O objetivo é gerar um playbook operacional para resposta a incidente.
- Não invente dados que não estejam nos alertas.
- Se uma informação não existir, escreva "não identificado nos alertas".
- Use linguagem profissional e objetiva.

Escala Wazuh:
- Level 0 a 3: Baixa
- Level 4 a 6: Média
- Level 7 a 10: Alta
- Level 11 ou maior: Crítica

Gere um playbook no formato abaixo:

# Playbook de Resposta a Incidente - Wazuh + Suricata

## 1. Tipo provável de incidente
Identifique se parece brute force SSH, atividade de rede suspeita, alteração de arquivos, reconhecimento, ou combinação de eventos.

## 2. Severidade estimada
Classifique como Baixa, Média, Alta ou Crítica e justifique com base nos alertas.

## 3. Evidências observadas
Liste as evidências principais:
- regras acionadas
- IPs origem/destino
- agentes envolvidos
- assinaturas Suricata
- eventos FIM
- protocolos

## 4. Mapeamento MITRE ATT&CK
Mapeie técnicas MITRE ATT&CK relacionadas ao incidente.

Use tabela:

| Técnica | Nome | Evidência | Confiança |
|---|---|---|---|
| Txxxx | Nome da técnica | Evidência observada | Baixa/Média/Alta |

Técnicas comuns neste laboratório:
- T1110 - Brute Force
- T1046 - Network Service Discovery
- T1059 - Command and Scripting Interpreter
- T1105 - Ingress Tool Transfer
- T1005 - Data from Local System
- T1070 - Indicator Removal
- T1562 - Impair Defenses

Não force mapeamento se não houver evidência suficiente.

## 5. Ações imediatas de triagem
Liste passos iniciais para o analista SOC validar o incidente.

## 6. Contenção
Liste ações para conter o incidente, como bloqueio de IP, isolamento de host, desativação de conta ou restrição de acesso.

## 7. Investigação
Liste comandos, consultas e verificações recomendadas.
Inclua exemplos úteis para Linux/Wazuh quando aplicável, como:
- verificar logs SSH
- consultar alertas no Wazuh
- revisar iptables
- validar arquivos alterados

## 8. Erradicação
Liste ações para remover causa raiz ou reduzir risco.

## 9. Recuperação
Liste ações para restaurar operação segura.

## 10. Lições aprendidas e melhorias
Liste melhorias de segurança, dashboard, regras, automação e monitoramento.

## 11. Possíveis automações futuras
Sugira automações com Wazuh Active Response, SOAR, IA ou abertura de chamado.

Alertas recentes:
{json.dumps(eventos, indent=2, ensure_ascii=False)}
"""

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt
    )

    return response.output_text


def analisar_sysmon_ia(eventos):
    prompt = f"""
Você é um analista SOC N2 especializado em Windows, Sysmon, Wazuh, detecção de endpoint e investigação de processos.

Contexto:
- Ambiente de laboratório simulando produção corporativa.
- O Wazuh coleta eventos do Windows e Sysmon.
- O Sysmon fornece telemetria de endpoint como criação de processos, conexões de rede, criação de arquivos, DNS e comandos executados.
- Analise somente com base nos alertas fornecidos.
- Não invente processos, IPs, usuários ou comandos.
- Se não houver eventos Sysmon suficientes, diga claramente.

Eventos Sysmon importantes:
- Event ID 1: Process Creation
- Event ID 3: Network Connection
- Event ID 7: Image Loaded
- Event ID 10: Process Access
- Event ID 11: File Create
- Event ID 12/13/14: Registry Events
- Event ID 22: DNS Query

Gere uma análise em Markdown com este formato:

# Análise Sysmon - Windows Endpoint

## 1. Resumo executivo
Explique rapidamente o que foi observado no endpoint Windows.

## 2. Eventos Sysmon identificados
Liste Event IDs encontrados e explique o significado de cada um.

## 3. Processos executados
Liste processos, caminhos e command lines observados.

## 4. Processo pai e relação entre processos
Analise parent process, parent command line e possíveis relações suspeitas.

## 5. Conexões de rede
Liste IPs, portas, protocolos e processos envolvidos quando disponível.

## 6. DNS e comunicação externa
Analise consultas DNS ou possíveis destinos externos quando disponível.

## 7. Atividades suspeitas
Destaque comportamentos que merecem investigação, como:
- PowerShell incomum
- execução por diretórios temporários
- comandos codificados
- conexões externas incomuns
- alterações de registro
- execução de ferramentas administrativas

## 8. Mapeamento MITRE ATT&CK
Mapeie técnicas MITRE ATT&CK relacionadas aos eventos Windows/Sysmon.

Exemplos:
- T1059.001 - PowerShell
- T1059.003 - Windows Command Shell
- T1105 - Ingress Tool Transfer
- T1049 - System Network Connections Discovery
- T1082 - System Information Discovery
- T1112 - Modify Registry
- T1070 - Indicator Removal

Use tabela:
| Técnica | Nome | Evidência | Confiança |
|---|---|---|---|

Não force mapeamento se não houver evidência suficiente.

## 9. Severidade estimada
Classifique como Baixa, Média, Alta ou Crítica e justifique.

## 10. Recomendações para o SOC
Liste ações práticas de investigação e contenção.

## 11. Próximos passos
Sugira melhorias de monitoramento, novas regras e automações.

Alertas recentes:
{json.dumps(eventos, indent=2, ensure_ascii=False)}
"""

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt
    )

    return response.output_text

# =========================
# MOTOR DE CORRELAÇÃO
# =========================

def mapear_mitre_basico(eventos):
    tecnicas = []

    tem_bruteforce = False
    tem_scan_rede = False
    tem_powershell = False
    tem_cmd = False
    tem_http_transfer = False
    tem_fim_delete = False
    tem_registry = False
    tem_network_connection = False

    for e in eventos:
        desc = (e.get("description") or "").lower()
        rule_id = str(e.get("rule_id") or "")
        groups = e.get("groups") or []

        command_line = (e.get("command_line") or "").lower()
        process_image = (e.get("process_image") or "").lower()
        parent_image = (e.get("parent_image") or "").lower()
        signature = (e.get("signature") or "").lower()
        category = (e.get("category") or "").lower()
        fim_event = (e.get("fim_event") or "").lower()
        win_event_id = str(e.get("win_event_id") or "")

        if rule_id in ["5710", "5712"] or "brute" in desc or "invalid user" in desc or "non-existent user" in desc:
            tem_bruteforce = True

        if "scan" in signature or "nmap" in signature or "network scan" in category:
            tem_scan_rede = True

        if "powershell" in command_line or "powershell" in process_image or "powershell" in parent_image:
            tem_powershell = True

        if "cmd.exe" in command_line or "cmd.exe" in process_image or "cmd.exe" in parent_image:
            tem_cmd = True

        if "curl" in command_line or "wget" in command_line or "python simplehttp" in desc or "simplehttp" in signature:
            tem_http_transfer = True

        if "delete" in fim_event or "deleted" in desc:
            tem_fim_delete = True

        if "registry" in desc or win_event_id in ["12", "13", "14"]:
            tem_registry = True

        if win_event_id == "3" or e.get("destination_ip") or e.get("destination_port"):
            tem_network_connection = True

    if tem_bruteforce:
        tecnicas.append({
            "id": "T1110",
            "nome": "Brute Force",
            "evidencia": "Tentativas de autenticação SSH inválidas ou repetidas.",
            "confianca": "Alta"
        })

    if tem_scan_rede:
        tecnicas.append({
            "id": "T1046",
            "nome": "Network Service Discovery",
            "evidencia": "Alertas de scan/reconhecimento de rede identificados pelo Suricata.",
            "confianca": "Média"
        })

    if tem_powershell:
        tecnicas.append({
            "id": "T1059.001",
            "nome": "PowerShell",
            "evidencia": "Execução de PowerShell observada em eventos Windows/Sysmon.",
            "confianca": "Média"
        })

    if tem_cmd:
        tecnicas.append({
            "id": "T1059.003",
            "nome": "Windows Command Shell",
            "evidencia": "Execução de cmd.exe observada em eventos Windows/Sysmon.",
            "confianca": "Média"
        })

    if tem_http_transfer:
        tecnicas.append({
            "id": "T1105",
            "nome": "Ingress Tool Transfer",
            "evidencia": "Uso de curl/wget/HTTP ou servidor SimpleHTTP indicando possível transferência de arquivos.",
            "confianca": "Média"
        })

    if tem_fim_delete:
        tecnicas.append({
            "id": "T1070",
            "nome": "Indicator Removal",
            "evidencia": "Eventos de exclusão/remoção de arquivos observados por FIM ou logs.",
            "confianca": "Baixa"
        })

    if tem_registry:
        tecnicas.append({
            "id": "T1112",
            "nome": "Modify Registry",
            "evidencia": "Eventos relacionados a alterações no Registro do Windows.",
            "confianca": "Média"
        })

    if tem_network_connection:
        tecnicas.append({
            "id": "T1049",
            "nome": "System Network Connections Discovery",
            "evidencia": "Eventos Sysmon de conexão de rede ou destinos de rede observados.",
            "confianca": "Baixa"
        })

    return tecnicas

def gerar_correlacao(eventos):
    total = len(eventos)
    tem_windows = False 
    tem_sysmon = False 

    por_ip_origem = Counter(e.get("src_ip") for e in eventos if e.get("src_ip"))
    por_ip_destino = Counter(e.get("dest_ip") for e in eventos if e.get("dest_ip"))
    por_regra = Counter(e.get("rule_id") for e in eventos if e.get("rule_id"))
    por_grupo = Counter()

    max_level = 0

    tem_suricata = False
    tem_ssh = False
    tem_fim = False
    tem_bruteforce = False

    evidencias = []

    for e in eventos:
        level = e.get("level")

        try:
            max_level = max(max_level, int(level))
        except Exception:
            pass

        groups = e.get("groups") or []
        win_channel = e.get("win_channel") or ""
        win_event_id = str(e.get("win_event_id") or "")

        if "windows" in groups:
            tem_windows = True

        if "sysmon" in groups or "Sysmon" in win_channel or "Microsoft-Windows-Sysmon" in win_channel:
            tem_sysmon = True        

        for g in groups:
            por_grupo[g] += 1

        desc = (e.get("description") or "").lower()
        rule_id = str(e.get("rule_id"))
    
        if "suricata" in groups:
            tem_suricata = True

        if "sshd" in groups or "ssh" in desc:
            tem_ssh = True

        if "syscheck" in groups or e.get("fim_path"):
            tem_fim = True

        if rule_id == "5712" or "brute" in desc:
            tem_bruteforce = True

        if rule_id in ["5710", "5712", "86601"]:
            evidencias.append({
                "timestamp": e.get("timestamp"),
                "agent": e.get("agent"),
                "rule_id": e.get("rule_id"),
                "level": e.get("level"),
                "description": e.get("description"),
                "src_ip": e.get("src_ip"),
                "dest_ip": e.get("dest_ip"),
                "signature": e.get("signature"),
                "fim_path": e.get("fim_path")
            })

    cadeia = []
    if tem_windows:
       cadeia.append("Eventos Windows identificados")

    if tem_sysmon:
       cadeia.append("Telemetria Sysmon identificada no endpoint Windows")  

    if tem_suricata:
        cadeia.append("Atividade de rede detectada pelo Suricata/NDR")

    if tem_ssh:
        cadeia.append("Eventos de autenticação SSH identificados")

    if tem_bruteforce:
        cadeia.append("Possível brute force SSH detectado")

    if tem_fim:
        cadeia.append("Alterações de arquivos detectadas via FIM")

    if tem_suricata and tem_ssh:
        hipotese = "Possível cadeia de reconhecimento de rede seguida de tentativa de acesso SSH."
    elif tem_ssh and tem_fim:
        hipotese = "Possível tentativa de acesso seguida de alteração em arquivos."
    elif tem_suricata and tem_fim:
        hipotese = "Atividade de rede suspeita correlacionada com alteração em arquivos."
    elif tem_suricata:
        hipotese = "Atividade suspeita de rede detectada."
    elif tem_ssh:
        hipotese = "Atividade suspeita de autenticação detectada."
    elif tem_fim:
        hipotese = "Alterações de integridade de arquivos detectadas."
    else:
        hipotese = "Não foi possível identificar uma cadeia clara de ataque com os alertas atuais."

    if max_level <= 3:
        severidade = "Baixa"
    elif max_level <= 6:
        severidade = "Média"
    elif max_level <= 10:
        severidade = "Alta"
    else:
        severidade = "Crítica"
    
    mitre = mapear_mitre_basico(eventos)  
  
    return {
        "tem_windows": tem_windows,
        "tem_sysmon": tem_sysmon,
        "total_alertas": total,
        "severidade_maxima_wazuh": max_level,
        "classificacao": severidade,
        "top_ips_origem": por_ip_origem.most_common(10),
        "top_ips_destino": por_ip_destino.most_common(10),
        "regras_mais_acionadas": por_regra.most_common(10),
        "grupos_mais_comuns": por_grupo.most_common(10),
        "tem_suricata": tem_suricata,
        "tem_ssh": tem_ssh,
        "tem_fim": tem_fim,
        "tem_bruteforce": tem_bruteforce,
        "cadeia_detectada": cadeia,
        "hipotese": hipotese,
        "mitre_attack": mitre,
        "evidencias_relevantes": evidencias[:15]
    }


def explicar_correlacao_ia(eventos, correlacao):
    prompt = f"""
Você é um analista SOC N2/N3 especializado em correlação de eventos Wazuh, Suricata, SSH, FIM e NDR.

Contexto:
- Ambiente de laboratório simulando produção corporativa.
- O Wazuh centraliza eventos de endpoint, autenticação, FIM e Suricata.
- O Suricata atua como sensor IDS/NDR.
- A análise abaixo já foi pré-processada por um motor simples de correlação em Python.
- Não invente dados fora dos eventos e da correlação.
- Se não houver evidência suficiente, informe claramente.

Gere uma análise profissional em Markdown com este formato:

# Correlação SOC - Wazuh + Suricata + IA

## 1. Resumo da correlação
Explique o que foi correlacionado.

## 2. Hipótese principal
Explique a hipótese de incidente com base nos dados.

## 3. Cadeia de ataque observada
Liste a sequência provável dos eventos.

## 4. Evidências técnicas
Liste IPs, regras, grupos, assinaturas e eventos relevantes.

## 5. Severidade
Classifique e justifique.

## 6. Risco em produção
Explique o impacto se isso ocorresse em uma rede corporativa real.

## 7. Recomendação para o SOC
Liste ações priorizadas.

## 8. Mapeamento MITRE ATT&CK
Mapeie técnicas MITRE ATT&CK relacionadas à cadeia observada.

Use o formato:

| Técnica | Nome | Evidência | Confiança |
|---|---|---|---|
| Txxxx | Nome da técnica | Evidência observada nos alertas/correlação | Baixa/Média/Alta |

Não invente técnicas sem evidência.

## 9. Próximas automações recomendadas
Sugira automações com Wazuh Active Response, SOAR ou IA.

Correlação calculada:
{json.dumps(correlacao, indent=2, ensure_ascii=False)}

Alertas recentes:
{json.dumps(eventos[:20], indent=2, ensure_ascii=False)}
"""

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt
    )

    return response.output_text

def usuario_logado():
    token = request.cookies.get("soc_auth")
    return token in TOKENS_LOGIN

def obter_analista_logado():
    token = request.cookies.get("soc_auth")
    dados = TOKENS_LOGIN.get(token, {})
    return dados.get("analista", "Analista SOC")

def proteger_rota():
    if not usuario_logado():
        return redirect(url_for("login"))
    return None


def inicializar_banco():
    conexao = sqlite3.connect(DB_PATH)
    cursor = conexao.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_hora TEXT NOT NULL,
            tipo TEXT NOT NULL,
            pergunta TEXT NOT NULL,
            resposta TEXT NOT NULL
        )
    """)

    cursor.execute("PRAGMA table_info(historico)")
    colunas = [coluna[1] for coluna in cursor.fetchall()]

    if "analista" not in colunas:
        cursor.execute("ALTER TABLE historico ADD COLUMN analista TEXT DEFAULT 'Analista SOC'")

    if "analista" not in colunas:
        cursor.execute("ALTER TABLE historico ADD COLUMN analista TEXT DEFAULT 'Analista SOC'")

    if "cliente" not in colunas:
        cursor.execute("ALTER TABLE historico ADD COLUMN cliente TEXT")

    if "alerta_recente" not in colunas:
        cursor.execute("ALTER TABLE historico ADD COLUMN alerta_recente TEXT")

    conexao.commit()
    conexao.close()

def salvar_historico_db(tipo, pergunta, resposta, analista="Analista SOC", cliente=None, alerta_recente=None):
    conexao = sqlite3.connect(DB_PATH)
    cursor = conexao.cursor()

    cursor.execute("""
        INSERT INTO historico (data_hora, tipo, pergunta, resposta, analista, cliente, alerta_recente)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        tipo,
        pergunta,
        resposta,
        analista,
        cliente,
        alerta_recente
    ))

    conexao.commit()
    conexao.close()

def carregar_historico_db(limite=8):
    conexao = sqlite3.connect(DB_PATH)
    conexao.row_factory = sqlite3.Row
    cursor = conexao.cursor()

    cursor.execute("""
        SELECT id, data_hora, tipo, pergunta, resposta, analista
        FROM historico
        ORDER BY id DESC
        LIMIT ?       
    """, (limite,))

    registros = cursor.fetchall()
    conexao.close()

    historico = []

    for item in registros:
        resposta_html = markdown_to_html(item["resposta"])

        historico.append({
            "id": item["id"],
            "data_hora": item["data_hora"],
            "tipo": item["tipo"],
            "pergunta": item["pergunta"],
            "resposta": item["resposta"],
            "resposta_html": resposta_html,
            "analista": item["analista"]
        })

    return historico


def limpar_historico_db():
    conexao = sqlite3.connect(DB_PATH)
    cursor = conexao.cursor()

    cursor.execute("DELETE FROM historico")

    conexao.commit()
    conexao.close()


# =========================
# ROTAS FLASK
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "").strip()

        if usuario == APP_USER and senha == APP_PASSWORD:
            token = secrets.token_urlsafe(32)
            TOKENS_LOGIN[token] = {
                "usuario": usuario,
                "analista": APP_ANALYST_NAME
            }

            resposta = make_response(redirect(url_for("index")))
            resposta.set_cookie(
                "soc_auth",
                token,
                httponly=True,
                samesite="Lax"
            )

            return resposta

        erro = "Usuário ou senha inválidos."

    return render_template("login.html", erro=erro)

@app.route("/", methods=["GET", "POST"])
def index():
    bloqueio = proteger_rota()
    if bloqueio:
        return bloqueio

    resposta = None
    resposta_html = None
    pergunta = ""
    historico_tela = []

    if request.method == "POST":
        pergunta = request.form.get("pergunta", "").strip()

        if pergunta:
            try:
                eventos = coletar_alertas(limite=30)
                resposta = perguntar_ia(pergunta, eventos)
                resposta_html = markdown_to_html(resposta)

                salvar_markdown("relatorio_ia_soc.md", resposta)
                cliente_lote, alerta_recente_lote = resumo_lote(eventos)
                salvar_historico_db(
                    "pergunta_livre",
                    pergunta,
                    resposta,
                    obter_analista_logado(),
                    cliente_lote,
                    alerta_recente_lote
                )

                historico_tela = [{
                    "id": None,
                    "data_hora": "",
                    "tipo": "consulta_atual",
                    "pergunta": pergunta,
                    "resposta": resposta,
                    "resposta_html": resposta_html,
                    "analista": obter_analista_logado()
                }]

            except Exception as e:
                resposta = f"Erro: {e}"
                resposta_html = f"<p><strong>Erro:</strong> {e}</p>"

                historico_tela = [{
                    "id": None,
                    "data_hora": "",
                    "tipo": "erro",
                    "pergunta": pergunta,
                    "resposta": resposta,
                    "resposta_html": resposta_html,
                    "analista": obter_analista_logado()
                }]

    return render_template(
        "index.html",
        resposta=resposta,
        resposta_html=resposta_html,
        pergunta=pergunta,
        historico=historico_tela,
        analista=obter_analista_logado()
    )


@app.route("/relatorio", methods=["GET", "POST"])
def relatorio():
    bloqueio = proteger_rota()
    if bloqueio:
        return bloqueio

    pergunta = (
        "Gere um relatório SOC completo dos alertas recentes com resumo executivo, "
        "IPs envolvidos, severidade, interpretação técnica, mapeamento MITRE ATT&CK, "
        "recomendações e próximos passos."
    )

    try:
        eventos = coletar_alertas(limite=40)
        resposta = perguntar_ia(pergunta, eventos)
        resposta_html = markdown_to_html(resposta)

        salvar_markdown("relatorio_ia_soc.md", resposta)
        cliente_lote, alerta_recente_lote = resumo_lote(eventos)
        salvar_historico_db("relatorio_soc", pergunta, resposta, obter_analista_logado(), cliente_lote, alerta_recente_lote)
       
        historico_tela = [{
            "id": None,
            "data_hora": "",
            "tipo": "relatorio_soc",
            "pergunta": pergunta,
            "resposta": resposta,
            "resposta_html": resposta_html,
            "analista": obter_analista_logado()
        }]

        return render_template(
            "index.html",
            resposta=resposta,
            resposta_html=resposta_html,
            pergunta=pergunta,
            historico=historico_tela,
            analista=obter_analista_logado()
        )

    except Exception as e:
        resposta = f"Erro: {e}"
        resposta_html = f"<p><strong>Erro:</strong> {e}</p>"

        return render_template(
            "index.html",
            resposta=resposta,
            resposta_html=resposta_html,
            pergunta="",
            historico=[],
            analista=obter_analista_logado()
        )

@app.route("/relatorio-executivo", methods=["GET"])
def relatorio_executivo():
    bloqueio = proteger_rota()
    if bloqueio:
        return bloqueio

    pergunta = "Gerar relatório executivo (linguagem de negócio) dos alertas recentes."

    try:
        eventos = coletar_alertas(limite=40)
        resposta = gerar_relatorio_executivo_ia(eventos)
        resposta_html = markdown_to_html(resposta)

        salvar_markdown("relatorio_executivo.md", resposta)
        cliente_lote, alerta_recente_lote = resumo_lote(eventos)
        salvar_historico_db("relatorio_executivo", pergunta, resposta, obter_analista_logado(), cliente_lote, alerta_recente_lote)       
 
        historico_tela = [{
            "id": None,
            "data_hora": "",
            "tipo": "relatorio_executivo",
            "pergunta": pergunta,
            "resposta": resposta,
            "resposta_html": resposta_html,
            "analista": obter_analista_logado()
        }]

        return render_template(
            "index.html",
            resposta=resposta,
            resposta_html=resposta_html,
            pergunta=pergunta,
            historico=historico_tela,
            analista=obter_analista_logado()
        )

    except Exception as e:
        resposta = f"Erro: {e}"
        resposta_html = f"<p><strong>Erro:</strong> {e}</p>"

        return render_template(
            "index.html",
            resposta=resposta,
            resposta_html=resposta_html,
            pergunta="",
            historico=[],
            analista=obter_analista_logado()
        )

@app.route("/playbook", methods=["GET"])
def playbook():
    bloqueio = proteger_rota()
    if bloqueio:
       return bloqueio

    pergunta = "Gerar playbook de resposta a incidente com base nos alertas recentes."

    try:
        eventos = coletar_alertas(limite=50)
        resposta = gerar_playbook_ia(eventos)
        resposta_html = markdown_to_html(resposta)

        salvar_markdown("playbook_incidente.md", resposta)
        cliente_lote, alerta_recente_lote = resumo_lote(eventos)
        salvar_historico_db("playbook", pergunta, resposta, obter_analista_logado(), cliente_lote, alerta_recente_lote)

        historico_tela = [{
            "id": None,
            "data_hora": "",
            "tipo": "playbook",
            "pergunta": pergunta,
            "resposta": resposta,
            "resposta_html": resposta_html,
            "analista": obter_analista_logado()
        }]


        return render_template(
            "index.html",
            resposta=resposta,
            resposta_html=resposta_html,
            pergunta=pergunta,
            historico=historico_tela,
            analista=obter_analista_logado()
        )

    except Exception as e:
        resposta = f"Erro: {e}"
        resposta_html = f"<p><strong>Erro:</strong> {e}</p>"

        return render_template(
            "index.html",
            resposta=f"Erro: {e}",
            resposta_html=f"<p><strong>Erro:</strong> {e}</p>",
            pergunta="",
            historico=[],
            analista=obter_analista_logado()
        )


@app.route("/correlacao", methods=["GET", "POST"])
def correlacao():
    bloqueio = proteger_rota()
    if bloqueio:
       return bloqueio

    pergunta = "Correlacionar incidente com base nos alertas recentes."

    try:
        eventos = coletar_alertas(limite=60)
        dados_correlacao = gerar_correlacao(eventos)
        resposta = explicar_correlacao_ia(eventos, dados_correlacao)
        resposta_html = markdown_to_html(resposta)

        salvar_markdown("correlacao_soc.md", resposta)
        cliente_lote, alerta_recente_lote = resumo_lote(eventos)
        salvar_historico_db("correlacao", pergunta, resposta, obter_analista_logado(), cliente_lote, alerta_recente_lote)

        historico_tela = [{
            "id": None,
            "data_hora": "",
            "tipo": "correlacao",
            "pergunta": pergunta,
            "resposta": resposta,
            "resposta_html": resposta_html,
            "analista": obter_analista_logado()
        }]

        return render_template(
            "index.html",
            resposta=resposta,
            resposta_html=resposta_html,
            pergunta=pergunta,
            historico=historico_tela,
            analista=obter_analista_logado()
        )

    except Exception as e:
        return render_template(
            "index.html",
            resposta=f"Erro: {e}",
            resposta_html=f"<p><strong>Erro:</strong> {e}</p>",
            pergunta="",
            historico=HISTORICO,
            analista=obter_analista_logado()
        )


@app.route("/limpar", methods=["GET"])
def limpar():
    bloqueio = proteger_rota()
    if bloqueio:
       return bloqueio
    
    limpar_historico_db()
    return redirect(url_for("index"))

@app.route("/download/<tipo>", methods=["GET"])
def download(tipo):
    bloqueio = proteger_rota()
    if bloqueio:
       return bloqueio

    arquivos = {
        "relatorio": os.path.join(OUTPUT_DIR, "relatorio_ia_soc.md"),
        "executivo": os.path.join(OUTPUT_DIR, "relatorio_executivo.md"),
        "playbook": os.path.join(OUTPUT_DIR, "playbook_incidente.md"),
        "correlacao": os.path.join(OUTPUT_DIR, "correlacao_soc.md"),
        "sysmon": os.path.join(OUTPUT_DIR, "analise_sysmon.md"),
        "alertas": os.path.join(OUTPUT_DIR, "alertas_wazuh.json"),
    }

    caminho = arquivos.get(tipo)

    if not caminho or not os.path.exists(caminho):
        return "Arquivo ainda não foi gerado.", 404

    return send_file(caminho, as_attachment=True)


@app.route("/sysmon", methods=["GET"])
def sysmon():
    bloqueio = proteger_rota()
    if bloqueio:
       return bloqueio

    pergunta = "Analisar eventos Windows/Sysmon recentes."

    try:
        eventos = coletar_alertas(limite=200)
        resposta = analisar_sysmon_ia(eventos)
        resposta_html = markdown_to_html(resposta)

        salvar_markdown("analise_sysmon.md", resposta)
        cliente_lote, alerta_recente_lote = resumo_lote(eventos)
        salvar_historico_db("sysmon", pergunta, resposta, obter_analista_logado(), cliente_lote, alerta_recente_lote)
        
        historico_tela = [{
            "id": None,
            "data_hora": "",
            "tipo": "sysmon",
            "pergunta": pergunta,
            "resposta": resposta,
            "resposta_html": resposta_html,
            "analista": obter_analista_logado()
        }]       

        return render_template(
            "index.html",
            resposta=resposta,
            resposta_html=resposta_html,
            pergunta=pergunta,
            historico=historico_tela,
            analista=obter_analista_logado()
        )

    except Exception as e:
        resposta = f"Erro: {e}"
        resposta_html = f"<p><strong>Erro:</strong> {e}</p>"

        return render_template(
            "index.html",
            resposta=f"Erro: {e}",
            resposta_html=f"<p><strong>Erro:</strong> {e}</p>",
            pergunta="",
            historico=[],
            analista=obter_analista_logado()
        )

@app.route("/logout", methods=["GET"])
def logout():
    token = request.cookies.get("soc_auth")

    if token in TOKENS_LOGIN:
         del TOKENS_LOGIN[token]    

    resposta = make_response(redirect(url_for("login")))
    resposta.delete_cookie("soc_auth")

    return resposta

@app.route("/historico", methods=["GET"])
def historico():
    bloqueio = proteger_rota()
    if bloqueio:
        return bloqueio

    registros = carregar_historico_db(limite=50)

    return render_template(
        "historico.html",
        historico=registros,
        analista=obter_analista_logado()
    )

@app.route("/clientes", methods=["GET"])
def clientes():
    bloqueio = proteger_rota()
    if bloqueio:
        return bloqueio

    try:
        eventos = coletar_alertas(limite=100)
        stats = estatisticas_por_cliente(eventos)
    except Exception as e:
        stats = []

    return render_template(
        "clientes.html",
        clientes=stats,
        analista=obter_analista_logado()
    )

def _parse_data_hora(data_hora_str):
    return datetime.strptime(data_hora_str, "%d/%m/%Y %H:%M:%S")


def _parse_alerta_ts(ts_str):
    if not ts_str:
        return None
    try:
        ts_norm = ts_str
        if len(ts_norm) >= 5 and ts_norm[-5] in "+-" and ts_norm[-3] != ":":
            ts_norm = ts_norm[:-2] + ":" + ts_norm[-2:]
        dt = datetime.fromisoformat(ts_norm)
        return dt.replace(tzinfo=None)
    except Exception:
        return None


def calcular_sla():
    """
    Calcula, por cliente:
    - TTD (tempo de deteccao): tempo entre o alerta mais recente do lote e a analise da IA
    - TTR (tempo de resposta): tempo entre a ultima analise de um cliente e o playbook seguinte
    Baseado 100% em timestamps reais gravados no historico_soc.db.
    """
    conexao = sqlite3.connect(DB_PATH)
    conexao.row_factory = sqlite3.Row
    cursor = conexao.cursor()

    cursor.execute("""
        SELECT id, data_hora, tipo, cliente, alerta_recente
        FROM historico
        WHERE tipo IN ('relatorio_soc','relatorio_executivo','correlacao','sysmon','playbook')
        ORDER BY id ASC
    """)
    registros = cursor.fetchall()
    conexao.close()

    por_cliente = {}
    ultima_analise_por_cliente = {}

    for r in registros:
        cliente = r["cliente"] or CLIENTE_PADRAO

        if cliente not in por_cliente:
            por_cliente[cliente] = {"cliente": cliente, "amostras_deteccao": [], "amostras_resposta": []}

        try:
            data_hora_dt = _parse_data_hora(r["data_hora"])
        except Exception:
            continue

        if r["tipo"] == "playbook":
            anterior = ultima_analise_por_cliente.get(cliente)
            if anterior:
                delta = (data_hora_dt - anterior).total_seconds()
                if delta >= 0:
                    por_cliente[cliente]["amostras_resposta"].append(delta)
        else:
            alerta_dt = _parse_alerta_ts(r["alerta_recente"])
            if alerta_dt:
                delta = (data_hora_dt - alerta_dt).total_seconds()
                if delta >= 0:
                    por_cliente[cliente]["amostras_deteccao"].append(delta)
            ultima_analise_por_cliente[cliente] = data_hora_dt

    resultado = []
    for cliente, dados in por_cliente.items():
        det = dados["amostras_deteccao"]
        res = dados["amostras_resposta"]

        resultado.append({
            "cliente": cliente,
            "ttd_medio_min": round(sum(det) / len(det) / 60, 1) if det else None,
            "ttd_amostras": len(det),
            "ttr_medio_min": round(sum(res) / len(res) / 60, 1) if res else None,
            "ttr_amostras": len(res),
        })

    return sorted(resultado, key=lambda r: r["cliente"])


@app.route("/sla", methods=["GET"])
def sla():
    bloqueio = proteger_rota()
    if bloqueio:
        return bloqueio

    dados = calcular_sla()

    return render_template(
        "sla.html",
        clientes=dados,
        analista=obter_analista_logado()
    )

@app.route("/sobre", methods=["GET"])
def sobre():
    bloqueio = proteger_rota()
    if bloqueio:
        return bloqueio

    return render_template(
        "sobre.html",
        analista=obter_analista_logado()
    )

# =========================
# MAIN
# =========================

if __name__ == "__main__":
    inicializar_banco()
    app.run(host="0.0.0.0", port=5000, debug=False)
