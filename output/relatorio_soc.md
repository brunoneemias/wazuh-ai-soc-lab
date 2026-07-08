# Relatório SOC Automatizado - Wazuh + Suricata

**Gerado em:** 20/05/2026 00:51:22

## 1. Resumo executivo

Foram analisados **30 alertas recentes** coletados do Wazuh.

Maior severidade encontrada: **Level 7 (Alto)**.

## 2. Alertas por severidade

- Level 5 (Médio): 20 eventos
- Level 3 (Baixo): 7 eventos
- Level 7 (Alto): 3 eventos

## 3. Regras mais acionadas

- Regra 5710: 19 eventos
- Regra 86601: 7 eventos
- Regra 550: 2 eventos
- Regra 553: 1 eventos
- Regra 554: 1 eventos

## 4. Agentes envolvidos

- kali: 30 eventos

## 5. Top IPs de origem

- 192.168.56.1: 22 eventos
- 192.168.56.103: 4 eventos

## 6. Top IPs de destino

- 192.168.56.1: 3 eventos
- 192.168.56.103: 3 eventos
- 192.168.56.100: 1 eventos

## 7. Assinaturas Suricata

- SURICATA SSH invalid banner: 6 eventos
- ET INFO Possible Kali Linux hostname in DHCP Request Packet: 1 eventos

## 8. Categorias Suricata

- Generic Protocol Command Decode: 6 eventos
- Potential Corporate Privacy Violation: 1 eventos

## 9. Eventos relevantes

- [2026-05-20T00:50:15.834+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - ET INFO Possible Kali Linux hostname in DHCP Request Packet
- [2026-05-20T00:50:14.835+0000] Agente: kali | Regra: 553 | Level: 7 | File deleted.
- [2026-05-20T00:50:10.336+0000] Agente: kali | Regra: 550 | Level: 7 | Integrity checksum changed.
- [2026-05-20T00:50:04.341+0000] Agente: kali | Regra: 550 | Level: 7 | Integrity checksum changed.
- [2026-05-20T00:49:58.846+0000] Agente: kali | Regra: 554 | Level: 5 | File added to the system.
- [2026-05-20T00:48:56.374+0000] Agente: kali | Regra: 5710 | Level: 5 | sshd: Attempt to login using a non-existent user
- [2026-05-20T00:48:04.012+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - SURICATA SSH invalid banner
- [2026-05-20T00:48:03.512+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - SURICATA SSH invalid banner
- [2026-05-20T00:47:59.514+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - SURICATA SSH invalid banner
- [2026-05-20T00:47:59.514+0000] Agente: kali | Regra: 86601 | Level: 3 | Suricata: Alert - SURICATA SSH invalid banner

## 10. Recomendação inicial

Recomenda-se revisar os alertas de maior severidade, validar os IPs de origem, correlacionar eventos de rede do Suricata com eventos de autenticação SSH e verificar alterações recentes de arquivos via FIM.
