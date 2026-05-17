# Splunk SIEM Lab — Detecção de Ameaças com Windows Event Logs

## Objetivo

Configurar o Splunk Enterprise como SIEM local, ingerir logs reais do Windows e simular dois cenários de ataque para praticar detecção, investigação e criação de alertas automáticos — replicando o fluxo de trabalho de um analista SOC.

---

## Ambiente

| Componente | Detalhe |
|---|---|
| SIEM | Splunk Enterprise (licença Free — 500 MB/dia) |
| Host | Windows 10/11 local (sem VM) |
| Logs ingeridos | Security, System, Application (WinEventLog) |
| Index | `main` |
| Sourcetype | `wineventlog:security` |

---

## Configuração Inicial

### 1. Ingestão de Logs
Logs configurados via **Settings → Add Data → Monitor → Local Event Logs**, selecionando os canais Security, System e Application.

### 2. Auditoria de Process Creation
Habilitada via PowerShell (necessária para capturar command line no Event ID 4688):

```powershell
auditpol /set /subcategory:"Criação de Processo" /success:enable /failure:enable

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## Cenário 1 — Detecção de Brute Force (Event ID 4625)

### Descrição
Simulação de múltiplas tentativas de logon com senha incorreta para gerar eventos 4625 e investigar via SPL.

### Simulação
Erros intencionais de senha na tela de login do Windows geraram 4 eventos 4625 no canal Security.

### Investigação SPL

**Listar falhas de logon com contexto:**
```spl
index=main sourcetype="wineventlog:security" EventCode=4625
| table _time, Nome_da_Conta, Tipo_de_logon, Message, ComputerName
| sort -_time
```

**Contar falhas por máquina (base para detecção de brute force):**
```spl
index=main sourcetype="wineventlog:security" EventCode=4625
| stats count by ComputerName
| where count > 3
```

### Análise do Incidente

| Campo | Valor | Interpretação |
|---|---|---|
| EventCode | 4625 | Falha de autenticação |
| Logon Type | 2 | Acesso físico/interativo |
| Quantidade | 4 eventos | Baixo volume |
| Origem | WORKGROUP (local) | Sem acesso remoto |
| Veredicto | Benigno | Usuário legítimo errou a senha |

### Alerta Configurado
- **Nome:** `Brute Force - Multiplas Falhas de Logon`
- **Tipo:** Scheduled — a cada hora
- **Trigger:** Number of Results > 0
- **Ação:** Add to Triggered Alerts

---

## Cenário 2 — Detecção de Reconhecimento Pós-Comprometimento (Event ID 4688)

### Descrição
Simulação do comportamento de um atacante após comprometer uma máquina: execução sequencial de comandos nativos de reconhecimento do ambiente. Detecção via SPL com mapeamento para MITRE ATT&CK.

### Simulação — Comandos Executados
```cmd
whoami
net user
ipconfig /all
tasklist
systeminfo
```

### Detecção SPL

**Identificar processos suspeitos:**
```spl
index=main sourcetype="wineventlog:security" EventCode=4688
| search Nome_do_Novo_Processo="*whoami*" OR Nome_do_Novo_Processo="*net.exe*" OR Nome_do_Novo_Processo="*ipconfig*" OR Nome_do_Novo_Processo="*tasklist*" OR Nome_do_Novo_Processo="*systeminfo*"
| table _time, Nome_do_Novo_Processo, Linha_de_Comando_do_Processo, Nome_da_Conta
| sort -_time
```

### Resultado
Todos os 5 comandos detectados em sequência, executados pelo usuário Ruan em menos de 1 minuto — padrão clássico de reconhecimento pós-comprometimento.

### Mapeamento MITRE ATT&CK

| Comando | Técnica | ID |
|---|---|---|
| `whoami` | System Owner/User Discovery | T1033 |
| `net user` | Account Discovery: Local Account | T1087.001 |
| `net localgroup administrators` | Permission Groups Discovery | T1069.001 |
| `ipconfig /all` | System Network Configuration Discovery | T1016 |
| `tasklist` | Process Discovery | T1057 |
| `systeminfo` | System Information Discovery | T1082 |

### Alerta Configurado
- **Nome:** `Reconhecimento - Comandos Suspeitos Detectados`
- **Tipo:** Scheduled — a cada hora
- **Trigger:** Number of Results > 0
- **Ação:** Add to Triggered Alerts

---

## Dashboard — Visão Geral dos Event IDs

Query utilizada para construir o painel de monitoramento:

```spl
index=main sourcetype="wineventlog:security"
| stats count by EventCode
| eval Descricao=case(
    EventCode=4624, "Logon bem-sucedido",
    EventCode=4625, "Falha de logon",
    EventCode=4634, "Logoff",
    EventCode=4648, "Logon com credenciais explícitas",
    EventCode=4672, "Privilégios de admin atribuídos",
    EventCode=4688, "Processo criado",
    EventCode=4798, "Enumeração de grupos do usuário",
    EventCode=4799, "Enumeração de grupo local",
    EventCode=5058, "Operação com chave criptográfica",
    EventCode=5061, "Operação criptográfica KSP",
    EventCode=5379, "Leitura do Credential Manager",
    true(), "Outro"
  )
| sort -count
```

---

## SPL — Comandos Utilizados

| Comando | Função |
|---|---|
| `index=` / `sourcetype=` | Filtragem da fonte de dados |
| `stats count by` | Agregação e contagem por campo |
| `eval` + `case()` | Enriquecimento condicional de campos |
| `table` | Formatação de saída em colunas |
| `sort` | Ordenação de resultados |
| `where` | Filtragem pós-agregação |
| `search` | Filtragem por valor de campo |
| `head` | Retorna os N primeiros eventos |

---

## Evidências

As evidências do lab (screenshots) estão na pasta `EVIDENCIAS-LAB-SIEM-SPLUNK/`.

---

## Lições Aprendidas

- O Splunk em Windows PT-BR usa nomes de campos em português (ex: `Nome_do_Novo_Processo`, `Linha_de_Comando_do_Processo`) — diferente da documentação oficial em inglês. É necessário inspecionar o evento bruto para identificar os field names corretos.
- O Event ID 4688 só registra o command line se a auditoria de Process Creation for habilitada explicitamente via `auditpol` e registro.
- A correlação entre timestamp e sequência de comandos é suficiente para identificar padrão de reconhecimento mesmo em ambiente local sem AD.

---

## Referências

- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows Security Event IDs — ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
