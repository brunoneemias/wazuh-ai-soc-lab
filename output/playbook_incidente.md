# Playbook de Resposta a Incidente - Wazuh + Suricata

## 1. Tipo provável de incidente
Atividade combinada de:
- SSH brute force (tentativas de login via SSH com usuário inexistente).
- Execução suspeita de comandos e criação de arquivos executáveis no endpoint Windows.

## 2. Severidade estimada
Crítica.  
Justificativa:  
- Presença de alerta de brute force SSH com nível 10 (alta gravidade).  
- Múltiplos alertas de tentativas de acesso inválido com nível 5 (médio).  
- Evidência de execução de shells suspeitos, criação de arquivos executáveis em pastas usadas frequentemente por malware com níveis entre 3 e 15 no agente Windows_11.

## 3. Evidências observadas
- Regras Wazuh acionadas:
  - ID 5710 (tentativa de login ssh com usuário inexistente) - nível 5.
  - ID 5712 (brute force SSH usuário inexistente) - nível 10.
  - IDs 92004, 92027, 92032, 92205, 92213 em Windows indicam spawn de shells PowerShell e cmd, criação de executáveis e execução suspeita - níveis 3 a 15.
- IP origem: 192.168.56.1 (origem das tentativas SSH).  
- Agentes envolvidos:  
  - "kali" (10.0.2.15) – sistema Linux alvo das tentativas SSH.  
  - "Windows_11" (192.168.1.8) – endpoint Windows com atividade suspeita.  
- Assinaturas Suricata: não identificado nos alertas.  
- Eventos FIM: não identificado nos alertas.  
- Protocolos: protocolo SSH (implicado pelo SSHD e logins falhos), outros protocolos não identificados.

## 4. Mapeamento MITRE ATT&CK

| Técnica | Nome                           | Evidência                                            | Confiança |
|---------|--------------------------------|-----------------------------------------------------|-----------|
| T1110   | Brute Force                   | Alertas SSHD de tentativas de login com usuários inexistentes e brute force | Alta      |
| T1059   | Command and Scripting Interpreter | Execução de PowerShell e cmd.exe em Windows com comandos suspeitos          | Alta      |
| T1105   | Ingress Tool Transfer          | Criação de arquivos executáveis em diretórios usados por malware no Windows  | Média     |

## 5. Ações imediatas de triagem
- Confirmar volumes de tentativas de login SSH ao host "kali" via logs: cat /var/log/auth.log.  
- Verificar tentativas recentes de autenticação no Windows (Sysmon logs).  
- Confirmar existência e integridade de arquivos executáveis criados no Windows root e pastas suspeitas.  
- Verificar existência de conexões ativas da origem 192.168.56.1.  
- Consultar histórico recente das contas de usuário no servidor “kali” (lista de usuários existentes versus tentativas observadas).  

## 6. Contenção
- Bloquear IP 192.168.56.1 no firewall interno e/ou iptables do host “kali”.  
- Isolar o host “Windows_11” da rede para análise forense e mitigação.  
- Desabilitar contas/usuários comprometidos ou suspeitos no Windows e Linux (se identificados).  
- Restringir acesso SSH ao servidor “kali” somente a IPs autorizados.  

## 7. Investigação
Linux - Kali (10.0.2.15):  
- Revisar logs SSH: `grep sshd /var/log/auth.log | tail -n 100`  
- Verificar tentativas de login para usuários não existentes: `grep "invalid user" /var/log/auth.log`  
- Consultar conexões TCP ativas do IP suspeito: `netstat -ntu | grep 192.168.56.1`  
- Verificar regras iptables: `iptables -L -v -n`  

Windows (192.168.1.8):  
- Analisar eventos Sysmon associados à execução de powershell e cmd (Event ID 1 e 11).  
- Verificar local das criações de arquivos executáveis listadas (eventos 92213 e 92205).  
- Listar processos ativos e comandos recentemente executados no PowerShell.  
- Corrigir/examinar scripts/task.bat citado como parent process.  

Wazuh:  
- Consultar alertas no período recente: `sudo /var/ossec/bin/manager_control -l --json | jq '.alerts'`  
- Revisar configuração FIM para detectar alterações e arquivos criados recentemente.  

## 8. Erradicação
- Remover as chaves/credenciais comprometidas e atualizar políticas SSH (ex.: desabilitar login root, usar autenticação por chave).  
- Apagar arquivos maliciosos detectados no Windows (com backup para análise forense).  
- Revisar e atualizar regras e políticas locais para prevenção de brute force SSH (fail2ban, firewall, etc).  
- Realizar análise de malware para garantir que não há persistência.  

## 9. Recuperação
- Reativar host Windows e Kali na rede somente após validação e remediation completas.  
- Aplicar patches e atualizações de segurança necessárias.  
- Restaurar contas de usuário validadas e acesso controlado.  
- Monitorar fortemente o comportamento nos próximos dias para verificar recorrências.  

## 10. Lições aprendidas e melhorias
- Implementar bloqueio automático de IPs após certo número de tentativas SSH inválidas (Fail2Ban integrado ao Wazuh Active Response).  
- Refinar regras de detecção para incluir alertas correlacionados entre SSH e atividade anômala Windows.  
- Estabelecer dashboards específicos para visualização de ataques SSH e comportamentos suspeitos em Windows.  
- Capacitar equipe SOC no reconhecimento de execuções suspeitas via PowerShell e cmd.exe.  

## 11. Possíveis automações futuras
- Automatizar bloqueio via Wazuh Active Response para IPs com múltiplas tentativas SSH inválidas.  
- Implementar playbooks automatizados em SOAR para isolamento imediato do host Windows em atividade suspeita.  
- Utilizar IA para correlação avançada entre alertas SSH brute force e eventos de execução de comandos para alertar proativamente.  
- Geração automática de tickets de incidente com resumo e evidências para times de resposta.