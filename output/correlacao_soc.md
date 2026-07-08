# Correlação SOC - Wazuh + Suricata + IA

## 1. Resumo da correlação
Foi correlacionada uma série de eventos provenientes de endpoints Windows com telemetria Sysmon, que indicam atividades locais legítimas, juntamente com logs de autenticação SSH que revelam múltiplas tentativas de login fracassadas usando usuários inexistentes, originadas do endereço IP 192.168.56.1. A análise identificou um padrão típico de ataque por força bruta (brute force) no serviço SSH, sem detecções específicas do Suricata (sensor IDS/NDR) relacionadas a esta atividade.

## 2. Hipótese principal
A hipótese do incidente é que um atacante está conduzindo um ataque de força bruta contra o servidor SSH, na tentativa de acessar o ambiente por meio da exploração de credenciais inválidas ou inexistentes. Os eventos Windows/Sysmon associados indicam atividades legítimas do endpoint, sem evidências claras de comprometimento ou execução de comandos maliciosos, apesar de indícios médios de uso de PowerShell e cmd.exe.

## 3. Cadeia de ataque observada
1. Atividade normal com eventos Windows e telemetria Sysmon no endpoint.
2. Execução de processos PowerShell e cmd.exe (detectados com confiança média).
3. Sequência contínua de tentativas falhas de login SSH via serviço sshd, todas utilizando usuários inexistentes.
4. Identificação do padrão de brute force SSH utilizando o IP 192.168.56.1 como origem das tentativas.

## 4. Evidências técnicas
- **IPs de origem:** 192.168.56.1 (mais de 40 tentativas falhas).
- **Regras mais acionadas:**
  - 5710 (sshd: tentativa de login com usuário inexistente) — 39 vezes.
  - 92205, 92032, 92004, entre outras.
- **Grupos de eventos:**
  - syslog, sshd, authentication_failed, invalid_login (com forte ocorrência).
  - sysmon (window events) com eventos 1 e 11.
- **Eventos relevantes:**
  - Logs de autenticação SSH (sshd) indicam tentativas repetidas e rápidas de login falho.
  - Execução monitorada de PowerShell e cmd.exe no Windows (confiança média de comandos suspeitos).
- **Suricata:** sem alertas relacionados ao incidente.
- **FIM (File Integrity Monitoring):** sem evidências associadas.

## 5. Severidade
**Crítica**

Justificativa: Ataque de força bruta robusto contra serviço crítico (SSH) com alto volume de tentativas rápidas, o que pode resultar em comprometimento caso credenciais fracas ou reutilizadas sejam descobertas. A ausência de bloqueio e presença contínua de tentativas tornam o cenário crítico para segurança do ambiente.

## 6. Risco em produção
Em um ambiente corporativo real, um ataque de força bruta SSH pode levar à obtenção de acesso não autorizado aos servidores, resultando em:

- Comprometimento da integridade e confidencialidade dos sistemas.
- Movimentação lateral e escalonamento de privilégios.
- Implantação de backdoors, malwares ou roubo de dados.
- Interrupção dos serviços críticos pelo atacante.
- Impacto financeiro e reputacional significativo para a organização.

## 7. Recomendação para o SOC
- Verificar e analisar os logs detalhados em tempo real para detectar padrões similares.
- Implementar bloqueios automáticos (IP ou conta) após X tentativas falhas.
- Habilitar autenticação multifator (MFA) para acessos SSH.
- Rever políticas de senha e usuários permitidos SSH.
- Monitorar eventos de execução de PowerShell e cmd.exe para atividades anômalas.
- Confirmar detecção/prevenção via Suricata ajustando regras e assinaturas.
- Executar auditoria e hardening do serviço SSH.
- Incluir o IP 192.168.56.1 na lista de monitoramento e possível bloqueio.
- Sensibilizar equipes para resposta rápida em bloqueios de credenciais.

## 8. Mapeamento MITRE ATT&CK

| Técnica | Nome                | Evidência                                            | Confiança |
|---------|---------------------|-----------------------------------------------------|-----------|
| T1110   | Brute Force         | Tentativas repetidas de autenticação SSH inválidas  | Alta      |
| T1059.001 | PowerShell          | Execução de PowerShell detectada nos eventos Windows | Média     |
| T1059.003 | Windows Command Shell | Execução de cmd.exe observada nos eventos Windows | Média     |

## 9. Próximas automações recomendadas
- Criar regra de Wazuh Active Response para bloqueio automático de IP após N tentativas falhas via SSH.
- Desenvolvimento de playbooks SOAR para análise automática e resposta a brute force SSH, incluindo alertas e bloqueios.
- Automação de coleta e análise de comandos PowerShell e cmd.exe para investigação rápida.
- Integração com firewalls para quarentena dinâmica de IPs suspeitos.
- Ajustes automáticos das regras do Suricata para incluir padrões detectados nesta análise.
- Aplicação de IA para detectar padrões anômalos em logins SSH e execução de shell em Windows em tempo real.

---

**Conclusão:** A correlação revelou um ataque de força bruta SSH severo, originado do IP 192.168.56.1, com potenciais riscos elevados para a segurança do ambiente. Recomenda-se ação rápida para mitigação e melhorias de controle para prevenção.