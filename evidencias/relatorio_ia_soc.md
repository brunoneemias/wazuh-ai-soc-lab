# Análise IA - Alertas Wazuh

## 1. Resumo executivo
No ambiente monitorado, foram detectados diversos alertas de origem do host "kali" com sinais de atividades típicas de um ambiente de testes ou pentest, como requisições DHCP com hostname Kali Linux, múltiplos pings ICMP IPv6 e várias tentativas de login SSH fracassadas usando usuários inexistentes vindas de IPs internos. Houve também uma autenticação SSH bem-sucedida a partir de um IP interno diferente. Embora haja indícios de simulação (uso explícito de Kali Linux), o padrão de tentativas de acesso SSH inválidas apresenta risco real em ambiente corporativo e exige análise e mitigação.

## 2. Classificação geral do incidente
Médio (Level 5).  
A presença de múltiplas tentativas falhas de login SSH com usuários inexistentes indica tentativa de brute force/credential stuffing, o que eleva o risco. Os alertas Suricata, apesar de serem de severidade baixa a média (level 3), indicam potencial reconhecimento de rede. Não há evidências de comprometimento confirmadas, mas o padrão de atividade sugere esforço inicial para exploração.

## 3. Alertas mais relevantes
- **sshd: Attempt to login using a non-existent user** (Level 5): Falhas de autenticação repetidas indicam brute force ou exploração de contas inexistentes, foco primário para escalonamento de ameaça.  
- **sshd: authentication success** (Level 3): Login bem-sucedido registrado, requer validação para garantir usuário legítimo e monitorar possíveis ações anormais.  
- **Suricata ET INFO Possible Kali Linux hostname in DHCP Request Packet** (Level 3): Indica a presença de agente Kali Linux, típico de laboratórios ou testes, mas pode revelar tentativa de reconhecimento.  
- **Suricata ICMP Ping Detectado** (Level 3): Atividades de varredura ou mapeamento de rede, comum em fases iniciais de ataque.

## 4. IPs envolvidos
- **192.168.56.103**: Host identificado com Kali Linux via DHCP, origem da maioria dos alertas Suricata e, presumivelmente, origem das tentativas de login. Provável host testador ou invasor simulado.  
- **192.168.56.1**: IP de onde partem as tentativas SSH com usuários inexistentes. Pode ser gateway, host legível ou parte do laboratório, origem ativa de brute force.  
- **192.168.56.100**: Destino dos pacotes DHCP detectados. Pode ser o servidor DHCP ou gateway da rede.  
- **192.168.1.5**: IP que teve autenticação SSH bem sucedida, possivelmente cliente legítimo – porém deve ser analisado para comportamento pós-login.  
- **IPv6 fe80::8d56:7c40:bafb:1c14 e ff02::2**: Origem e destino dos pings ICMP v6, possivelmente tráfego local para reconhecimento.

## 5. Interpretação técnica

### Suricata / NDR
- Diversos alertas de DHCP com hostname "Kali Linux" indicam um agente ativo se identificando explicitamente, típico em laboratório/teste.  
- ICMP Ping IPv6 repetido sugere varredura de rede ou descoberta de hosts/vizinhos.

### SSH / autenticação
- Quatro registros de tentativas de login SSH com usuários inexistentes, nível 5, sugerindo possível ataque de brute force ou reconhecimento por força bruta.  
- Registro de autenticação SSH bem sucedida em IP diferente pode representar acesso legítimo ou lateralidade interna, requerendo confirmação e monitoramento.

### FIM / integridade de arquivos
- Nenhuma alteração detectada em arquivos ou eventos FIM associados.

### Outros eventos
- Não há outras categorias relevantes evidenciadas além do monitoramento padrão.

## 6. Possível impacto em produção
- As tentativas de login SSH falhas constantes indicam risco de comprometimento por força bruta, podendo levar à exploração de contas e acesso não autorizado se combinadas com credenciais válidas.  
- Atividades de reconhecimento via DHCP e ICMP podem ser preliminares a ataques mais graves.  
- A autenticação bem-sucedida pode representar risco se for comprometida ou incógnita, possibilitando acesso lateral, instalação de backdoors ou exfiltração.  
- Em ambiente real, ignorar esse padrão pode levar a invasões e vazamentos de dados.

## 7. Recomendações práticas para o SOC
1. Confirmar a legitimidade do host 192.168.56.103 (Kali Linux) e sua função no ambiente (teste autorizado ou possível invasor).  
2. Analisar o usuário e atividade ligada ao login SSH bem-sucedido no IP 192.168.1.5. Validar se é esperado.  
3. Investigar tentativas de login SSH falhas do IP 192.168.56.1, entendendo se é fonte autorizada ou host malicioso.  
4. Monitorar padrões adicionais de brute force, aumentar bloqueio ou aplicar regras para limitar tentativas SSH.  
5. Revisar política de acesso SSH, incluindo uso de autenticação multifator e restrição por IP.  
6. Documentar e correlacionar atividades de rede associadas a agentes Kali Linux para garantir que são testes autorizados.  
7. Continuar monitoramento das atividades de rede para mapeamento ou reconhecimento não autorizados.

## 8. Possíveis respostas automáticas
- Bloquear automaticamente o IP 192.168.56.1 temporariamente após múltiplas tentativas falhas de login SSH.  
- Notificação imediata para equipe SOC ao detectar autenticação SSH fora do padrão (novo usuário, horário anômalo).  
- Quarentena ou isolamento do host 192.168.56.103 se não for ambiente autorizado.  
- Abertura automática de chamado para investigação sobre atividade suspeita de brute force.  
- Reforçar alertas no painel para eventos de autenticação SSH (tanto falhas quanto sucesso).

## 9. Próximos passos
- Implementar dashboards específicos para tentativas SSH de brute force e autenticações suspeitas.  
- Criar regras de correlação no Wazuh para vincular atividades de reconhecimento (DHCP, ICMP) com tentativas iniciais de intrusão.  
- Automatizar bloqueios temporários baseados em limiares de falha de login com alertas para analistas.  
- Revisar e fortalecer controles de acesso via SSH, incluindo whitelist de IP e MFA.  
- Validar se agentes de teste Kali e IPs relacionados foram previamente registrados como autorizados.  
- Introduzir monitoramento complementar para comportamentos pós-login, visando detectar atividade lateral ou comandos maliciosos.  

---

**Resumo:** Trata-se de um cenário de atividade padrão de laboratório/pentest demonstrado pelos alertas Suricata referente a Kali Linux, mas com eventos de autenticação SSH que representam ameaça real de brute force. Recomenda-se foco rápido na análise de autenticações SSH, reforço de controles e monitoramento contínuo para prevenir comprometimentos em produção.