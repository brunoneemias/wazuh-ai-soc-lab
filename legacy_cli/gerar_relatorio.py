import json
from collections import Counter
from datetime import datetime


def carregar_alertas():
    with open("alertas_wazuh.json", "r", encoding="utf-8") as f:
        return json.load(f)


def classificar_level(level):
    try:
        level = int(level)
    except Exception:
        return "Indefinido"

    if level <= 3:
        return "Baixo"
    if level <= 6:
        return "Médio"
    if level <= 10:
        return "Alto"
    return "Crítico"


def main():
    alertas = carregar_alertas()

    total = len(alertas)
    por_level = Counter(str(a.get("level")) for a in alertas)
    por_regra = Counter(a.get("rule_id") for a in alertas)
    por_agente = Counter(a.get("agent") for a in alertas)
    por_origem = Counter(a.get("src_ip") for a in alertas if a.get("src_ip"))
    por_destino = Counter(a.get("dest_ip") for a in alertas if a.get("dest_ip"))
    por_assinatura = Counter(a.get("signature") for a in alertas if a.get("signature"))
    por_categoria = Counter(a.get("category") for a in alertas if a.get("category"))

    max_level = max(
        [int(a.get("level", 0)) for a in alertas if str(a.get("level", "")).isdigit()],
        default=0
    )

    linhas = []
    linhas.append("# Relatório SOC Automatizado - Wazuh + Suricata\n\n")
    linhas.append(f"**Gerado em:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n")

    linhas.append("## 1. Resumo executivo\n\n")
    linhas.append(f"Foram analisados **{total} alertas recentes** coletados do Wazuh.\n\n")
    linhas.append(f"Maior severidade encontrada: **Level {max_level} ({classificar_level(max_level)})**.\n\n")

    linhas.append("## 2. Alertas por severidade\n\n")
    for level, count in por_level.most_common():
        linhas.append(f"- Level {level} ({classificar_level(level)}): {count} eventos\n")

    linhas.append("\n## 3. Regras mais acionadas\n\n")
    for regra, count in por_regra.most_common(10):
        linhas.append(f"- Regra {regra}: {count} eventos\n")

    linhas.append("\n## 4. Agentes envolvidos\n\n")
    for agente, count in por_agente.most_common():
        linhas.append(f"- {agente}: {count} eventos\n")

    linhas.append("\n## 5. Top IPs de origem\n\n")
    if por_origem:
        for ip, count in por_origem.most_common(10):
            linhas.append(f"- {ip}: {count} eventos\n")
    else:
        linhas.append("- Nenhum IP de origem identificado nos alertas analisados.\n")

    linhas.append("\n## 6. Top IPs de destino\n\n")
    if por_destino:
        for ip, count in por_destino.most_common(10):
            linhas.append(f"- {ip}: {count} eventos\n")
    else:
        linhas.append("- Nenhum IP de destino identificado nos alertas analisados.\n")

    linhas.append("\n## 7. Assinaturas Suricata\n\n")
    if por_assinatura:
        for sig, count in por_assinatura.most_common(10):
            linhas.append(f"- {sig}: {count} eventos\n")
    else:
        linhas.append("- Nenhuma assinatura Suricata encontrada nesse conjunto.\n")

    linhas.append("\n## 8. Categorias Suricata\n\n")
    if por_categoria:
        for cat, count in por_categoria.most_common(10):
            linhas.append(f"- {cat}: {count} eventos\n")
    else:
        linhas.append("- Nenhuma categoria Suricata encontrada nesse conjunto.\n")

    linhas.append("\n## 9. Eventos relevantes\n\n")
    for a in alertas[:10]:
        linhas.append(
            f"- [{a.get('timestamp')}] Agente: {a.get('agent')} | "
            f"Regra: {a.get('rule_id')} | Level: {a.get('level')} | "
            f"{a.get('description')}\n"
        )

    linhas.append("\n## 10. Recomendação inicial\n\n")
    linhas.append(
        "Recomenda-se revisar os alertas de maior severidade, validar os IPs de origem, "
        "correlacionar eventos de rede do Suricata com eventos de autenticação SSH e verificar "
        "alterações recentes de arquivos via FIM.\n"
    )

    with open("relatorio_soc.md", "w", encoding="utf-8") as f:
        f.writelines(linhas)

    print("[OK] Relatório gerado: relatorio_soc.md")


if __name__ == "__main__":
    main()
