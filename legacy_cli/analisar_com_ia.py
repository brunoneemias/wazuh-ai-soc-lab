import os
import json
from dotenv import load_dotenv
from openai import OpenAI

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # sobe de legacy_cli/ pra raiz do projeto
load_dotenv(os.path.join(BASE_DIR, ".env"))

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def carregar_alertas():
    with open("alertas_wazuh.json", "r", encoding="utf-8") as f:
        return json.load(f)


def preparar_eventos(alertas, limite=25):
    eventos = []

    for a in alertas[:limite]:
        eventos.append({
            "timestamp": a.get("timestamp"),
            "agent": a.get("agent"),
            "rule_id": a.get("rule_id"),
            "level": a.get("level"),
            "description": a.get("description"),
            "groups": a.get("groups"),
            "src_ip": a.get("src_ip"),
            "dest_ip": a.get("dest_ip"),
            "proto": a.get("proto"),
            "signature": a.get("signature"),
            "category": a.get("category"),
            "suricata_severity": a.get("suricata_severity"),
            "fim_path": a.get("fim_path"),
            "fim_event": a.get("fim_event"),
            "location": a.get("location")
        })

    return eventos


def gerar_prompt(eventos):
    return f"""
Você é um analista SOC N1/N2 especializado em Wazuh, Suricata, FIM, SSH brute force, NDR e análise de logs.

Contexto:
- Este ambiente é um laboratório que simula um cenário corporativo de produção.
- O objetivo é analisar os alertas como se fossem eventos reais de um ambiente monitorado por SOC.
- O agente monitorado principal representa um endpoint corporativo.
- O Suricata representa um sensor IDS/NDR de rede.
- O Wazuh representa a plataforma SIEM/XDR centralizando e correlacionando eventos.
- Eventos como SSH brute force, alertas Suricata, alterações em arquivos e atividades de rede devem ser avaliados com postura de produção.
- Quando um evento tiver características de teste, mencione que pode ser simulação, mas mantenha a análise com foco em impacto, risco e resposta em ambiente real.
- Não invente dados que não estejam nos alertas.
- Se algo não estiver claro, diga que precisa de validação.
- Priorize eventos por severidade, frequência, impacto e possibilidade de comprometimento.

Escala de severidade baseada no Wazuh:
- Level 0 a 3: Baixa
- Level 4 a 6: Média
- Level 7 a 10: Alta
- Level 11 ou maior: Crítica

Objetivo:
Gerar uma análise com postura de SOC corporativo, ajudando na triagem, priorização, investigação e resposta a incidentes em um ambiente simulado de produção.

Formato obrigatório:

# Análise IA - Alertas Wazuh

## 1. Resumo executivo
Explique em poucas linhas o que aconteceu no ambiente, como se fosse um resumo para um coordenador ou gestor de segurança.

## 2. Classificação geral do incidente
Classifique o cenário como Baixo, Médio, Alto ou Crítico, seguindo a escala do Wazuh e considerando também frequência, origem, impacto e tipo de evento.

## 3. Alertas mais relevantes
Liste os principais eventos encontrados e explique por que são relevantes para um SOC.

## 4. IPs envolvidos
Liste os IPs de origem e destino. Explique o papel provável de cada um sem inventar informações.

## 5. Interpretação técnica
Explique os alertas encontrados, separando quando possível:
- Suricata / NDR
- SSH / autenticação
- FIM / integridade de arquivos
- Outros eventos relevantes

## 6. Possível impacto em produção
Explique qual seria o impacto caso esses eventos ocorressem em um ambiente corporativo real.

## 7. Recomendações práticas para o SOC
Liste ações práticas e priorizadas para o analista SOC executar.

## 8. Possíveis respostas automáticas
Sugira respostas automáticas possíveis, como bloqueio de IP, isolamento, notificação, abertura de chamado ou investigação adicional.

## 9. Próximos passos
Sugira melhorias de monitoramento, automação, dashboard, correlação ou resposta.

Alertas:
{json.dumps(eventos, indent=2, ensure_ascii=False)}
"""


def main():
    alertas = carregar_alertas()

    if not alertas:
        print("[ERRO] Nenhum alerta encontrado em alertas_wazuh.json")
        return

    eventos = preparar_eventos(alertas)
    prompt = gerar_prompt(eventos)

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt
    )

    analise = response.output_text

    with open("relatorio_ia_soc.md", "w", encoding="utf-8") as f:
        f.write(analise)

    print("[OK] Análise IA gerada: relatorio_ia_soc.md")
    print()
    print(analise)


if __name__ == "__main__":
    main()
