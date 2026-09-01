# Linux Log Analyzer

Ferramenta desenvolvida em Python para análise de logs Linux,
com foco em identificação de eventos relacionados a autenticação
e possíveis tentativas de brute force.

## Objetivo

O projeto lê arquivos de log, identifica eventos relevantes,
contabiliza tentativas de login e destaca comportamentos
potencialmente suspeitos.

## Funcionalidades

- Análise de logs SSH/Linux
- Identificação de logins bem-sucedidos
- Identificação de tentativas de login falhas
- Identificação de usuários inválidos
- Contagem de falhas por endereço IP
- Detecção de possíveis ataques de brute force
- Janela de tempo configurável
- Threshold configurável
- Classificação de severidade
- Relatório no terminal
- Exportação do relatório para arquivo
- Tratamento de erros
- Interface de linha de comando com argparse
- Expressões regulares para identificação dos eventos

## Tecnologias

- Python 3
- Linux
- Regex
- argparse
- pathlib
- datetime
- collections.Counter

## Estrutura

```text
linux-log-analyzer/
├── log_analyzer.py
├── README.md
├── sample_auth.log
└── reports/
    └── report.txt
