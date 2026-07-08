# Relatório SOC – Alertas Recentes

---

## 1. Resumo Executivo

Nos últimos alertas coletados pelo Wazuh integrando logs Sysmon, detecções FIM e eventos Windows, observamos forte atividade suspeita no host Windows_11 (IP: 192.168.1.12), especificamente envolvendo execução e criação de arquivos executáveis em diretórios comumente usados por malware, múltiplos processos PowerShell e CMD com padrões anômalos, além da presença de processos suspeitos identificados como *backgroundTaskHost.exe* (taskhost.exe). 

Os níveis de severidade variaram de 3 (baixa) até 15 (crítica), indicando eventos que configuram possível comprometimento por ações de execução remota, criação de arquivos maliciosos, possível persistência e técnicas de reconhecimento interno da rede local. O uso de ferramentas legítimas do sistema (PowerShell, cmd.exe, SecEdit.exe) de forma anormal sugere movimentação e ações típicas de invasores para escalonamento de privilégios e manipulação local do sistema.

Não houve registros de eventos Suricata/NDR com severidade relevante nesta janela, nem evidências claras de movimentação lateral via rede ou transferências externas.

---

## 2. IPs Envolvidos

| IP | Descrição |
|---|---|
| 192.168.1.12 | Host Windows_11 onde ocorreram as atividades suspeitas. |
| N/D | Outros IPs não evidenciados nos alertas para conexões externas. |

---

## 3. Severidade e Eventos

| Nível | Quantidade | Exemplos de eventos |
|---|---|---|
| 15 (Crítico) | 8 | Executáveis dropped em pastas comumente usadas por malware (regra 92213, Sysmon EID11) |
| 12 (Alta) | 6 | Processos suspeitos taskhost.exe (backgroundTaskHost.exe) detectados (regra 61634) |
| 9 (Alta) | 15 | PowerShell criando executáveis na raiz Windows (regra 92205) |
| 6 (Média) | 1 | Criação de arquivos de script em pasta temporária (regra 92200) |
| 4 (Média) | 6 | Cmd shell iniciado por processos anormais, uso do SecEdit.exe em local suspeito |
| 3 (Baixa) | 6 | Execuções suspeitas de cmd e atividades de descoberta (net user) |

---

## 4. Interpretação Técnica e Análise

- Múltiplos eventos indicam a criação de executáveis em pastas usadas por malware pelo PowerShell (regra 92213, nível crítico 15), evidenciando possível atividade maliciosa após execução inicial.
- Processos *backgroundTaskHost.exe* (taskhost.exe) com linha de comando anômala e alto nível de severidade (12), possivelmente processos disfarçados para persistência.
- Uso intenso do PowerShell para spawnar cmd.exe e executar scripts inconclusos, alguns lançando arquivos batch (*task.bat*), com tentativas de esconder janelas (WindowStyle Hidden).
- Execução do SecEdit.exe pela PowerShell em local suspeito para exportar configurações de políticas de segurança (LockoutDuration, MaximumPasswordAge, etc) pode indicar coleta de informações de segurança para planejar futuras ações.
- Atividades de descoberta interna, como a execução do comando *net user*, para lista de contas locais.
- Execuções do *wsl.exe* via cmd.exe iniciadas a partir de VSCode, indicam uso de ambiente Linux subsistema Windows possivelmente para tarefas ocultas.
- Sessão SSH autenticada proveniente do host Windows_11 no servidor Wazuh, sem alertas de brute force.
- Ausência de conexões de rede em alertas windows; foco é maiormente em ações locais no host comprometido.

---

## 5. Mapeamento MITRE ATT&CK

| Técnica | Nome | Evidência | Confiança |
|---------|------|-----------|-----------|
| T1059 | Command and Scripting Interpreter | Execução frequente de PowerShell e cmd.exe, spawn de shells por PowerShell, scripts ocultos (WindowsPowerShell.exe, cmd.exe) | Alta |
| T1105 | Ingress Tool Transfer | Criacão de executáveis em pastas suspeitas após processos PowerShell; possível transferência implícita (sem evidência direta de rede) | Média |
| T1543 | Create or Modify System Process | Processos taskhost.exe (backgroundTaskHost.exe) anômalos detectados, possível persistência por serviço disfarçado | Alta |
| T1083 | File and Directory Discovery | Execução de comandos de descoberta via net user para listar usuários locais | Média |
| T1036 | Masquerading | Uso de processos Windows legítimos em locais suspeitos (SecEdit.exe no SysWOW64) e taskhost.exe para mascarar atividade | Alta |
| T1562 | Impair Defenses | Exportação das políticas de segurança por SecEdit.exe para obtenção de dados de Lockout e Password Policy | Média |
| T1070 | Indicator Removal | Uso do PowerShell para remover arquivos temporários após leitura (Remove-Item $env:TEMP) | Média |

---

## 6. Recomendações

1. **Isolamento do host 192.168.1.12 (Windows_11) para análise detalhada e investigação forense.**
2. Revisar processos em execução e autorizações para *backgroundTaskHost.exe* e *powershell.exe*, validar a linha de comando completa.
3. Analisar conteúdo e origem dos executáveis e scripts criados em pastas suspeitas.
4. Auditar logs de acesso para identificar origem da iniciação do PowerShell e execução de arquivos batch *task.bat*.
5. Revisar políticas de segurança local e atualizar senhas administrativas e bloqueio de contas se considerado necessário.
6. Monitorar e restringir execução do WSL e PowerShell via políticas de grupo (GPO).
7. Aplicar limpeza e reforçar mecanismo de detecção para evitar persistência por processos mascarados.
8. Caso possível, conduzir análise de rede e endpoint para captura de artefatos residuais de transferência ou comunicação externa.
9. Validar regras de IDS/NDR para alertar sobre comportamento suspeito similar.
10. Executar varredura antivírus/antimalware e análise de integridade dos arquivos executáveis.
11. Atualizar assinaturas e ferramentas de proteção endpoint com detections fortalecidas para essas técnicas.

---

## 7. Próximos Passos

- **Resposta Imediata:** Isolar host Windows_11 e iniciar coleta de memória, disco e logs complementares.
- **Investigação:** Análise detalhada dos arquivos criados, scripts e processos em execução suspeitos, linhas de comando completas e eventuais conexões de rede ocultas.
- **Remediação:** Remover artefatos maliciosos, restringir contas comprometidas e atualizar políticas de controle.
- **Prevenção:** Reforçar regras de monitoramento para execução de PowerShell e cmd via executáveis não padrão, limitar privilégios de scripts.
- **Reportar Evento:** Escalar para time de resposta a incidentes para avaliação de impacto e comunicação interna.

---

# Fim do relatório.  
Estou à disposição para auxiliar em análise detalhada dos hosts ou elaboração de playbooks para resposta.