# Análise Sysmon - Windows Endpoint

## 1. Resumo executivo
O ambiente Windows 11 (máquina "Fsociety") apresentou múltiplos eventos registrados pelo Sysmon indicando execuções frequentes de shell CMD e PowerShell, com processos como `powershell.exe`, `cmd.exe`, e ferramentas administrativas (ex: sdbinst.exe). Há várias ocorrências de arquivos executáveis sendo criados em pastas normalmente usadas por malware, e registros de exclusão em massa de entradas de registro relacionadas a serviços do sistema. No host Kali, foram detectados múltiplos acessos SSH falhos usando usuários inexistentes, caracterizando um ataque de força bruta externo.

## 2. Eventos Sysmon identificados
- **Event ID 1 (Process Creation):** Registra criação de processos, seus argumentos e relação de processo pai. Útil para detectar execuções suspeitas.
- **Event ID 11 (File Create):** Registro de criação de arquivos, sinalizando potencial instalação de malware ou artefatos maliciosos.
- Não há eventos de rede nem DNS destacados nos alertas recebidos.
- Eventos FWIM e syscheck indicam alterações e deleções em arquivos/registro.

## 3. Processos executados
Principais processos observados no Windows:
- `powershell.exe` — executando comandos para criar arquivos executáveis e spawn de outras instâncias.
- `cmd.exe` — iniciado principalmente por `powershell.exe` e processos relacionados ao PyCharm.
- `whoami.exe`, `hostname.exe` — comandos administrativos básicos executados pelo CMD.
- `sdbinst.exe` — ferramenta legítima para gerenciar SDB da aplicação.
- `task.exe` localizado na pasta `Intel\SUR\QUEENCREEK\x64\` — executado via cmd, originado por PowerShell.
- `java.exe` do PyCharm — executando classes Java via CMD (ligado a IDE JetBrains PyCharm).
- `conda.exe` e `doskey.exe` — utilizados para manipulação do ambiente Python/miniconda.

## 4. Processo pai e relação entre processos
- `powershell.exe` frequentemente é responsável por spawn de `cmd.exe`, demonstrando cadeia PowerShell -> CMD -> comandos.
- `cmd.exe` frequentemente é iniciado por processos ligados ao PyCharm (`pycharm64.exe`), indicando atividade de desenvolvimento/testes.
- `conda.exe` executa comandos via CMD, e `doskey.exe` adiciona alias para conda como parte do ambiente.
- `task.exe` é iniciado por `cmd.exe` que também tenta executar script batch `task.bat` em pasta Intel, via PowerShell com janela oculta.
- A cadeia de execução revela processos legítimos (IDE, Python, PowerShell) mas com ações sensíveis como criação de arquivos executáveis e manipulação de scripts ocultos.

## 5. Conexões de rede
- Não foram relatados eventos Sysmon ID 3 ou similares com conexão de rede para o Windows.
- No host Kali várias tentativas de login SSH falhadas vindas do IP 192.168.56.1 indicam atividade de força bruta via SSH.

## 6. DNS e comunicação externa
- Nenhum evento de DNS Query (Sysmon ID 22) foi informado.

## 7. Atividades suspeitas
- Alta frequência de criação de arquivos executáveis dentro do Windows, especialmente controlados por `powershell.exe`, em diretórios sensíveis.
- Exclusões massivas e coordenadas de várias chaves de registro de serviços do sistema, sugestivas de tentativa de remoção ou manipulação de configuração crítica do sistema.
- Execução de `cmd.exe` e `powershell.exe` com possíveis scripts ocultos (`task.bat` iniciado via PowerShell com janela oculta).
- Tentativas de força bruta SSH vindas do IP 192.168.56.1 no ambiente Kali, com múltiplos logins com usuário inexistente.
- Uso de ferramentas administrativas (`sdbinst.exe`) e spawn frequente de instâncias PowerShell em cadeia.
- Execução de processos via PyCharm executando scripts Python relacionados a "ssh_bruteforce_lab.py", indicando atividade de testes ou simulação.

## 8. Mapeamento MITRE ATT&CK

| Técnica     | Nome                               | Evidência                                                                               | Confiança  |
|-------------|-----------------------------------|----------------------------------------------------------------------------------------|------------|
| T1059.001   | PowerShell                        | Múltiplas execuções de `powershell.exe` com comandos, spawn de outros processos        | Alta       |
| T1059.003   | Windows Command Shell             | Execuções repetidas de `cmd.exe` com comandos /c, spawn por PowerShell e outros        | Alta       |
| T1112       | Modify Registry                  | Exclusão em massa de chaves no registro `CurrentControlSet\Services`                   | Alta       |
| T1070       | Indicator Removal                 | Exclusão de múltiplas entradas de serviço de registro pode indicar tentativa de limpeza| Alta       |
| T1036       | Masquerading                     | Execução de `task.exe` em pasta suspeita, possivelmente malware                         | Média      |
| T1113       | Screen Capture (indireto - possível) | `task.bat` executado com janela oculta pode ocultar ações maliciosas                  | Baixa      |

Não há evidências claras de rede (exfiltração, comando e controle) nem DNS suspeito.

## 9. Severidade estimada
**Alta.** Há forte evidência de atividade potencialmente maliciosa, incluindo criação de executáveis em locais suspeitos, manipulação de registro de serviços, ações via PowerShell com spawn de shells CMD, e tentativa de ataque bruto no lado Kali (exterior). A alteração em registro pode causar instabilidade ou ocultação de persistência. A atividade de desenvolvimento pode ser legítima, porém os padrões são típicos de investigação para possível comprometimento.

## 10. Recomendações para o SOC
- Isolar e investigar o host Windows ("Fsociety"), revisando os arquivos executáveis criados e scripts relacionados.
- Analisar conteúdo e origens do `task.bat` e `task.exe` em Intel\SUR\QUEENCREEK para detectar malwares.
- Revisar alterações de registro específicas para entender se removem proteções ou modificam serviços críticos.
- Revisar logs e histórico de execução do PowerShell e CMD para identificar comandos maliciosos.
- Monitorar e bloquear IP 192.168.56.1 por tentativas repetidas de SSH no Kali.
- Executar varredura antivírus/antimalware no Windows e Kali.
- Verificar se códigos Python em PyCharm são legítimos do usuário ou scripts maliciosos camuflados.
- Incrementar regras de detecção para execuções suspeitas de PowerShell, criação/exclusão de arquivos executáveis e alteração de registro.

## 11. Próximos passos
- Criar alertas reforçados para múltiplas exclusões sequenciais de registro associadas a serviços sistema no Windows.
- Configurar detecção de spawn PowerShell -> CMD especialmente executando scripts ocultos.
- Implantar monitoramento de integridade em diretórios de sistema e pasta Intel onde executáveis suspeitos foram criados.
- Automatizar bloqueio e alerta para força bruta SSH baseados em tentativas falhas por usuário inexistente.
- Investigar a possível conexão entre atividades do PyCharm e ações do PowerShell/CMD para diferenciar atividade legítima vs maliciosa.
- Melhorar visibilidade de rede para detectar conexões suspeitas do host comprometido.
- Avaliar e reforçar políticas de execução restrita do PowerShell no endpoint.

---

**Observação:** A análise foi realizada exclusivamente com os alertas e eventos fornecidos, sem acesso adicional a dados de rede, DNS ou logs complementares.