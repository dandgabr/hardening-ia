# 📖 Guia Completo de Comandos, Parâmetros e Argumentos (CLI & TUI Reference)

Este documento fornece a especificação técnica e o manual de referência completo para todos os comandos, scripts de inicialização, flags, parâmetros, modos de execução e comportamentos do **Hardening IA Framework**.

---

## 📑 Tabela de Conteúdos

1. [Scripts de Inicialização (Launchers)](#1-scripts-de-inicialização-launchers)
2. [Sintaxe Geral da CLI](#2-sintaxe-geral-da-cli)
3. [Tabela Resumo de Parâmetros e Flags](#3-tabela-resumo-de-parâmetros-e-flags)
4. [Detalhamento de Comandos e Parâmetros](#4-detalhamento-de-comandos-e-parâmetros)
   - [4.1 Modos de Interface](#41-modos-de-interface)
   - [4.2 Descoberta e Listagem de Ferramentas](#42-descoberta-e-listagem-de-ferramentas)
   - [4.3 Aplicação e Reversão de Hardening](#43-aplicação-e-reversão-de-hardening)
   - [4.4 Modo Restritivo (Strict Mode)](#44-modo-restritivo-strict-mode)
   - [4.5 Auditoria de Compliance e Auto-Remediação](#45-auditoria-de-compliance-e-auto-remediação)
   - [4.6 Modo Administrador Corporativo (System-Wide & Read-Only Locking)](#46-modo-administrador-corporativo-system-wide--read-only-locking)
   - [4.7 Avaliação de Risco de Comandos (Command Risk Matrix)](#47-avaliação-de-risco-de-comandos-command-risk-matrix)
   - [4.8 Análise de Vulnerabilidades em Código (SAST & SCA Scanner)](#48-análise-de-vulnerabilidades-em-código-sast--sca-scanner)
   - [4.9 Instalação de Componentes Extras](#49-instalação-de-componentes-extras)
   - [4.10 Execução de Testes Automatizados e Diagnóstico](#410-execução-de-testes-automatizados-e-diagnóstico)
5. [Atalhos da Interface Gráfica Terminal (TUI)](#5-atalhos-da-interface-gráfica-terminal-tui)
6. [Variáveis de Ambiente e Logs](#6-variáveis-de-ambiente-e-logs)
7. [Códigos de Saída (Exit Codes)](#7-códigos-de-saída-exit-codes)

---

## 1. Scripts de Inicialização (Launchers)

O framework disponibiliza scripts idempotentes para inicialização rápida e gestão automática de ambiente virtual (`.venv`):

| Script | Sistema Operacional | Descrição | Exemplo de Execução |
| :--- | :--- | :--- | :--- |
| `main.sh` | Linux / macOS | Script Bash com verificação e ativação automática do `.venv` | `./main.sh [argumentos]` |
| `main.ps1` | Windows | Script PowerShell 5.1+ / Core com elevação e gestão de `.venv` | `.\main.ps1 [argumentos]` |
| `main.cmd` | Windows | Script Batch para Command Prompt tradicional | `main.cmd [argumentos]` |
| `main.py` | Multiplataforma | Ponto de entrada direto via interpretador Python | `python main.py [argumentos]` |

> [!NOTE]
> Todos os scripts de inicialização são idempotentes: caso o ambiente virtual `.venv` já exista no diretório, ele não será recriado, preservando as dependências instaladas.

---

## 2. Sintaxe Geral da CLI

```bash
python main.py [MODO] [AÇÃO] [FILTROS] [MODIFICADORES] [OPÇÕES]
```

### Exemplos Básicos:
```bash
# Executar a interface gráfica no terminal:
python main.py

# Aplicar hardening estrito em ferramentas instaladas:
python main.py --apply --installed-only --strict

# Auditar e corrigir compliance de 100%:
python main.py --verify --fix

# Enforçar políticas de administrador com bloqueio somente leitura:
sudo python main.py --apply --admin --strict
```

---

## 3. Tabela Resumo de Parâmetros e Flags

| Parâmetro / Flag | Alias | Tipo de Dado | Descrição |
| :--- | :--- | :--- | :--- |
| `-gui`, `--gui` | — | Flag | Inicia a interface visual interativa no terminal (Textual TUI). |
| `--cli` | — | Flag | Força explicitamente a execução em modo texto / headless. |
| `--list` | — | Flag | Lista as 14 ferramentas suportadas e seus status de detecção. |
| `--installed-only` | — | Flag | Restringe a execução apenas às ferramentas detectadas no host. |
| `--tool <NAME>` | — | String | Filtra a ação para uma ferramenta específica (ex: `cursor`, `google/antigravity`). |
| `--apply` | — | Flag | Aplica as políticas declarativas de segurança nos arquivos de configuração. |
| `--strict` | `--restrictive` | Flag | Ativa o modo restritivo (bloqueio explícito de caminhos perigosos e escrita). |
| `--remove` | `--revert` | Flag | Reverte cirurgicamente as modificações e restaura backups. |
| `--verify` | — | Flag | Realiza a auditoria de compliance e validação dos arquivos locais. |
| `--fix` | `--remediate` | Flag | Corrige automaticamente todas as divergências elevando o score para 100%. |
| `--admin` | `--system-wide` | Flag | **[Apenas CLI]** Verifica privilégios de Admin/Root e bloqueia arquivos como Read-Only para todos os usuários. |
| `--check-command <CMD>`| — | String | Avalia o nível de risco de uma instrução shell na Risk Matrix. |
| `--scan-code [PATH]` | — | Path (Opcional)| Executa análise estática de vulnerabilidades e segredos (SAST/SCA). Default: `.`. |
| `--install-extra <T>` | — | String | Instala ferramentas adicionais de isolamento (`ai-jail`, `opengrep`, `all`). |
| `--dry-run` | — | Flag | Simula as operações em memória sem escrever alterações em disco. |
| `--test` | — | Flag | Executa a suíte completa de 31 testes unitários e de integração. |
| `--verbose`, `-v` | — | Flag | Ativa logs detalhados de depuração (DEBUG level). |
| `-h`, `--help` | — | Flag | Exibe a mensagem de ajuda formatada com exemplos práticos. |

---

## 4. Detalhamento de Comandos e Parâmetros

### 4.1 Modos de Interface

#### `--gui` / `-gui`
- **Descrição:** Inicia a interface gráfica baseada em terminal (Textual TUI) em tela cheia com navegação por mouse e teclado, logs em tempo real e guias temáticas.
- **Uso:**
  ```bash
  python main.py
  python main.py --gui
  ```

#### `--cli`
- **Descrição:** Força a execução puramente por linha de comando, ideal para scripts CI/CD, automações em batch ou execuções não-interativas.
- **Uso:**
  ```bash
  python main.py --cli --list
  ```

---

### 4.2 Descoberta e Listagem de Ferramentas

#### `--list`
- **Descrição:** Exibe uma tabela Rich contendo o catálogo completo das 14 ferramentas suportadas, categoria (`ide`, `cli`, `agentic`), fornecedor e status de presença no host.
- **Uso:**
  ```bash
  python main.py --list
  ```

#### `--installed-only`
- **Descrição:** Modificador de filtro que restringe qualquer operação subsequente (`--list`, `--apply`, `--remove`, `--verify`) apenas às ferramentas detectadas ativas na máquina.
- **Uso:**
  ```bash
  python main.py --list --installed-only
  python main.py --apply --installed-only
  python main.py --verify --installed-only
  ```

#### `--tool <NAME>`
- **Argumento esperado:** Nome da ferramenta (`cursor`, `copilot`, `antigravity`, `claude-code`, etc.) ou formato `vendor/name` (`anysphere/cursor`, `anthropic/claude-code`).
- **Descrição:** Filtra a execução para atingir exclusivamente a ferramenta especificada.
- **Uso:**
  ```bash
  python main.py --tool cursor --apply
  python main.py --tool google/antigravity --verify
  python main.py --tool claude-code --remove
  ```

---

### 4.3 Aplicação e Reversão de Hardening

#### `--apply`
- **Descrição:** Aplica as políticas declarativas de hardening definidas em `configs/tools/`. Cria backups automáticos antes de modificar qualquer arquivo, preserva configurações customizadas de usuários e injeta regras de segurança específicas do sistema operacional.
- **Uso:**
  ```bash
  # Aplicar em todas as ferramentas instaladas:
  python main.py --apply --installed-only

  # Provisionar configurações para todas as 14 ferramentas suportadas:
  python main.py --apply
  ```

#### `--remove` / `--revert`
- **Descrição:** Reverte cirurgicamente todas as modificações aplicadas pelo framework, removendo overrides de segurança e restaurando os valores anteriores sem afetar extensões ou provedores personalizados.
- **Uso:**
  ```bash
  python main.py --remove --installed-only
  python main.py --tool cursor --remove
  ```

#### `--dry-run`
- **Descrição:** Executa todo o pipeline de resolução de políticas, cálculo de diffs e checagem de permissões **sem gravar nenhuma alteração em disco**.
- **Uso:**
  ```bash
  python main.py --apply --dry-run
  python main.py --remove --dry-run
  ```

---

### 4.4 Modo Restritivo (Strict Mode)

#### `--strict` / `--restrictive`
- **Descrição:** Eleva o nível de proteção para o patamar máximo de isolamento:
  1. **Bloqueio Explícito de Comandos Críticos:** Bloqueia comandos destrutivos (`rm -rf /`, `mkfs`, `format`, `dd if=/dev/zero`, `diskpart`, etc.) sem questionar.
  2. **Bloqueio de Caminhos Perigosos do SO:** Acesso a diretórios sensíveis (`/etc`, `/boot`, `~/.ssh`, `~/.aws`, `C:\Windows`, `/System`, etc.) é barrado sumariamente.
  3. **Desativação de Auto-Aprovação em Edições de Arquivos:** Desativa aceitação automática de diffs e edições autônomas (`acceptEdits: False`, `autoApply: False`, `auto_write_files: False`).
  4. **Rate Limits & Timeouts Ativos:** Limite estrito de 30 req/min e timeouts de 30s para comandos.
- **Uso:**
  ```bash
  python main.py --apply --strict
  python main.py --apply --installed-only --strict
  python main.py --verify --strict
  ```

---

### 4.5 Auditoria de Compliance e Auto-Remediação

#### `--verify`
- **Descrição:** Realiza a auditoria estática dos arquivos de configuração locais e regras implantadas, calculando um índice percentual de conformidade de 0% a 100% por ferramenta.
- **Uso:**
  ```bash
  python main.py --verify
  python main.py --verify --installed-only
  python main.py --verify --strict
  ```

#### `--fix` / `--remediate`
- **Descrição:** Quando combinado com `--verify`, identifica qualquer configuração ausente ou divergente, repara os parâmetros faltantes e atualiza o relatório de auditoria para **100% de compliance**.
- **Uso:**
  ```bash
  # Auditar e corrigir divergências em modo padrão:
  python main.py --verify --fix

  # Auditar e corrigir divergências em modo restritivo:
  python main.py --verify --installed-only --strict --fix
  ```

---

### 4.6 Modo Administrador Corporativo (System-Wide & Read-Only Locking)

#### `--admin` / `--system-wide` *(Exclusivo via CLI)*
- **Descrição:** Funcionalidade corporativa para administradores de sistemas e equipes de segurança:
  1. **Validação de Elevação:** Exige e verifica privilégios de Administrador/Root (`sudo` em Linux/macOS ou `Run as Administrator` no Windows).
  2. **Varredura Multi-Usuário:** Mapeia todos os perfis de usuários locais da máquina (`/home/*`, `/root`, `/etc/skel`, `/Users/*`, `C:\Users\*`).
  3. **Bloqueio Somente Leitura (Read-Only Locking):**
     - **Linux / macOS:** Aplica `chown root:root` (ou `root:wheel`) e `chmod 644` nos arquivos e `chmod 755` nos diretórios.
     - **Windows:** Aplica ACLs NTFS restritivas via `icacls` concedendo `BUILTIN\Administrators:F` e `BUILTIN\Users:R` (removendo permissão de escrita de usuários comuns).
     - **Efeito:** Os usuários conseguem usar seus assistentes de IA, mas **não conseguem editar, sobrescrever ou desativar as políticas de segurança**.
  4. **Desativação Global de Telemetria:** Implanta script em `/etc/profile.d/hardening-ia-telemetry.sh` (Linux/macOS) ou variáveis de ambiente de máquina (Windows).
- **Uso:**
  ```bash
  # Linux & macOS (com sudo):
  sudo python main.py --apply --admin --installed-only
  sudo python main.py --apply --admin --strict
  sudo python main.py --verify --admin

  # Windows (PowerShell ou Prompt de Comando como Administrador):
  python main.py --apply --admin --installed-only
  python main.py --apply --admin --strict
  python main.py --verify --admin
  ```

> [!IMPORTANT]
> A flag `--admin` é intencionalmente omitida da interface gráfica interativa (TUI) e deve ser executada exclusivamente via terminal com elevação de privilégios.

---

### 4.7 Avaliação de Risco de Comandos (Command Risk Matrix)

#### `--check-command <CMD>`
- **Argumento esperado:** Linha de comando a ser avaliada entre aspas (ex: `"rm -rf /"`, `"git status"`, `"sudo apt-get update"`).
- **Descrição:** Avalia a instrução na matriz de risco e políticas de segurança do sistema operacional ativo, classificando-a em:
  - `LOW`: Comandos de leitura e diagnóstico (execução segura automática).
  - `MEDIUM`: Comandos de desenvolvimento e escrita local (exige confirmação do operador).
  - `HIGH`: Comandos administrativos e modificação de rede/serviços (exige confirmação explícita).
  - `CRITICAL`: Comandos destrutivos ou violações de caminhos perigosos (bloqueio em modo estrito).
- **Uso:**
  ```bash
  python main.py --check-command "ls -la"
  python main.py --check-command "cat /etc/shadow"
  python main.py --check-command "rm -rf /"
  python main.py --check-command "rm -rf /" --strict
  ```

---

### 4.8 Análise de Vulnerabilidades em Código (SAST & SCA Scanner)

#### `--scan-code [PATH]`
- **Argumento esperado:** (Opcional) Caminho relativo ou absoluto do diretório/arquivo a ser auditado. Default: diretório atual (`.`).
- **Descrição:** Executa o mecanismo de análise estática de código (SAST) e análise de composição de software (SCA) baseado no OpenGrep com regras especializadas em vulnerabilidades comuns em código gerado por IA (Command Injection, SQL Injection, Path Traversal, Credenciais Hardcoded, Uso inseguro de Deserialização).
- **Uso:**
  ```bash
  # Escanear o diretório corrente do projeto:
  python main.py --scan-code

  # Escanear pasta específica:
  python main.py --scan-code ./src
  python main.py --scan-code /caminho/do/projeto
  ```

---

### 4.9 Instalação de Componentes Extras

#### `--install-extra <TOOL>`
- **Argumentos suportados:** `ai-jail`, `opengrep` ou `all`.
- **Descrição:** Executa os instaladores de segurança isolados para o sistema operacional em uso:
  - `ai-jail`: Sandboxing em nível de processo baseado em namespaces/containers.
  - `opengrep`: Motor de análise estática de código rápido e local.
  - `all`: Instala ambos os componentes.
- **Uso:**
  ```bash
  python main.py --install-extra opengrep
  python main.py --install-extra ai-jail
  python main.py --install-extra all
  ```

---

### 4.10 Execução de Testes Automatizados e Diagnóstico

#### `--test`
- **Descrição:** Descobre e executa toda a suíte de testes unitários e de integração (`unittest`) cobrindo classificadores de risco, analisador SAST, engine de hardening, verificador de compliance, detector de SO e gerenciador administrativo.
- **Uso:**
  ```bash
  python main.py --test
  ./main.sh --test
  ```

#### `--verbose` / `-v`
- **Descrição:** Habilita nível de log `DEBUG`, detalhando cada arquivo lido, chaves JSON inspecionadas e chamadas de subprocesso.
- **Uso:**
  ```bash
  python main.py --apply --verbose
  ```

---

## 5. Atalhos da Interface Gráfica Terminal (TUI)

Ao executar `python main.py` (ou `main.sh` / `main.ps1` sem argumentos), a TUI disponibiliza os seguintes atalhos de teclado:

| Tecla | Ação Executada |
| :---: | :--- |
| `q` | **Sair:** Fecha a aplicação com segurança. |
| `a` | **Aplicar Hardening:** Aplica a política na ferramenta atualmente selecionada. |
| `s` | **Alternar Modo Restritivo:** Ativa ou desativa a checkbox de *Regras Restritivas*. |
| `r` | **Reverter Política:** Remove o hardening e restaura configurações da ferramenta selecionada. |
| `v` | **Verificar Compliance:** Audita a ferramenta selecionada e exibe o relatório de conformidade. |
| `f` | **Corrigir Compliance:** Auto-remedia as divergências elevando o score para 100%. |
| `t` | **Executar Testes:** Roda a suíte completa de testes automatizados. |
| `d` | **Modo Dry-Run:** Alterna a checkbox de simulação (sem escrita em disco). |
| `c` | **Limpar Logs:** Limpa a janela inferior de logs em tempo real. |
| `1` - `4` | **Navegar Guias:** Alterna entre *Ferramentas*, *Auditoria*, *Risco de Comandos* e *Scanner SAST*. |

---

## 6. Variáveis de Ambiente e Logs

### Variáveis de Ambiente Enforçadas pelo Framework:
- `DO_NOT_TRACK=1`: Padrão internacional de bloqueio de telemetria e rastreamento.
- `CLAUDE_TELEMETRY_DISABLED=1`: Desativa coleta de analytics em ferramentas Anthropic.
- `CLAUDE_CODE_ENABLE_TELEMETRY=0`: Desativa telemetria no Claude Code CLI.
- `ANTHROPIC_TELEMETRY_DISABLED=1`: Bloqueio global de telemetria de agentes.

### Arquivos de Log e Auditoria:
- `logs/hardening.log`: Log rotativo de execução técnica (máximo 10MB por arquivo, até 5 rotações).
- `logs/audit.jsonl`: Registro imutável de auditoria em formato JSON Lines contendo timestamps, eventos (`POLICY_APPLIED`, `POLICY_REVERTED`, `ADMIN_SYSTEM_WIDE_ENFORCEMENT`, `VERIFICATION_AUDIT`), ferramentas e status.

---

## 7. Códigos de Saída (Exit Codes)

O utilitário CLI retorna códigos de saída padrão para integração em pipelines de automação e scripts de CI/CD:

| Código | Significado | Descrição |
| :---: | :--- | :--- |
| `0` | **Success** | A operação foi concluída com sucesso e sem violações. |
| `1` | **Error / Elevation Failure** | Erro de execução, privilégios insuficientes para `--admin` ou falha nos testes unitários. |
| `2` | **Invalid Argument** | Parâmetro inválido ou sintaxe incorreta fornecida ao `argparse`. |
