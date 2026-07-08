# Relatório SOC Automatizado - Wazuh + Suricata

**Gerado em:** 19/05/2026 23:30:45

## 1. Resumo executivo

Foram analisados **30 alertas recentes** coletados do Wazuh.

Maior severidade encontrada: **Level 5 (Médio)**.

## 2. Alertas por severidade

- Level 3 (Baixo): 26 eventos
- Level 5 (Médio): 4 eventos

## 3. Regras mais acionadas

- Regra 86601: 25 eventos
- Regra 5710: 4 eventos
- Regra 5715: 1 eventos

## 4. Agentes envolvidos

- kali: 29 eventos
- wazuh-server: 1 eventos

## 5. Top IPs de origem

- 192.168.56.103: 18 eventos
- fe80:0000:0000:0000:8d56:7c40:bafb:1c14: 6 eventos
- 192.168.56.1: 4 eventos
- 192.168.1.5: 1 eventos
- fe80:0000:0000:0000:95d0:121d:9802:5801: 1 eventos

## 6. Top IPs de destino

- 192.168.56.100: 18 eventos
- ff02:0000:0000:0000:0000:0000:0000:0002: 6 eventos
- fe80:0000:0000:0000:8d56:7c40:bafb:1c14: 1 eventos

## 7. Assinaturas Suricata

- ET INFO Possible Kali Linux hostname in DHCP Request Packet: 18 eventos
- ICMP Ping Detectado: 7 eventos

## 8. Categorias Suricata

- Potential Corporate Privacy Violation: 18 eventos

## 9. Eventos relevantes

- [2026-05-19T23:30:15.651+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T23:25:53.320+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ICMP Ping Detectado
- [2026-05-19T23:25:15.342+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T23:20:15.466+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T23:15:14.953+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T23:10:14.741+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T23:05:14.412+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T23:00:13.953+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T22:55:14.415+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-19T22:50:15.843+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet

## 10. Recomendação inicial

Recomenda-se revisar os alertas de maior severidade, validar os IPs de origem, correlacionar eventos de rede do Suricata com eventos de autenticação SSH e verificar alterações recentes de arquivos via FIM.
