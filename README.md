# MedSync API — Agendamento Seguro de Consultas Médicas

API RESTful modularizada desenvolvida com **FastAPI**, **Pydantic** e **SQLModel** para gerenciamento de agendamentos em redes de clínicas médicas, em estrita conformidade com a **LGPD** e as melhores práticas da **OWASP Top 10**.

**Estudante:** Marcos Ryan

---

## Vídeo de Apresentação Técnica (YouTube)

- **Link do Vídeo (Não Listado):** [youtube-link](https://youtu.be/0cyzDBWq-KE)
- **Duração:** Até 5 minutos
- **Conteúdo Apresentado:** Apresentação da arquitetura modular, mitigações OWASP (BOLA, XSS, Mass Assignment), autenticação RBAC com ownership, demonstração ao vivo com 31 testes pytest aprovados, Security Gate no GitHub Actions e parecer de risco residual.
- **Link de vídeo Drive (Backup):** [link](https://drive.google.com/file/d/1NbZpZJL85cR2zsuIglHnQMpHzZoefh7W/view?usp=drive_link)

---

## Como Executar o Projeto Localmente

### 1. Criar e Ativar o Ambiente Virtual Python

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Instalar as Dependências

```bash
pip install -r requirements.txt
```

### 3. Configurar Variáveis de Ambiente

```bash
cp .env.example .env
```

### 4. Executar o Servidor FastAPI

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

* **Swagger UI (Documentação Interativa):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **OpenAPI Schema (JSON):** [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)
* **Portal Web da Recepção (Jinja2):** [http://127.0.0.1:8000/recepcao/agenda](http://127.0.0.1:8000/recepcao/agenda)

---

## Como Executar a Suíte de Testes Automatizados

```bash
pytest -v
```

Todos os **31 testes automatizados** cobrem:

- Rotas RESTful de consultas
- Não-vazamento de dados internos de auditoria (Pydantic Response Models)
- Prevenção contra Stored XSS com autoescape do Jinja2
- Hashing de senhas com bcrypt
- RBAC e restrição de acesso administrativo
- MFA simulado para contas de administradores
- Verificação de ownership de consultas (prevenção de BOLA/IDOR)
- Fluxo OAuth 2.0 Client Credentials e escopos do laboratório (M2M)
- Rejeição de propriedades não declaradas (`extra="forbid"`)
- Validações de regex e whitelist para CPF, CRM e nomes
- Cabeçalhos de segurança HTTP (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Allowlist explícita de CORS
- Rate Limiting diferenciado na rota de login
- Persistência segura e queries parametrizadas com SQLModel
- Testes unitários com Mocks e auditoria da especificação OpenAPI

---

## Auditorias de Segurança Automatizadas

### Scan SAST com Bandit (Security Gate: Médio/Alto)

```bash
bandit -r app/ -ll
```

### Análise de Dependências (SCA) com Pip-Audit

```bash
pip-audit -r requirements.txt
```

### Auditoria e Scan Passivo OWASP ZAP

```bash
python scripts/run_zap_passive_audit.py
```

O relatório consolidado de 30 verificações aprovadas é salvo em `docs/owasp_zap_scan_report.json`.

---

## Documentação Técnica Completa (Relatórios de Avaliação)

- **Exercícios 3, 4 e 5:** [`docs/modelagem_seguranca_ex3_ex4_ex5.md`](docs/modelagem_seguranca_ex3_ex4_ex5.md) (Tríade CIA, DFD com Trust Boundaries, STRIDE e Arquitetura nos 3 Eixos)
- **Exercícios 8, 9, 10 e 11:** [`docs/vulnerabilidades_owasp_e_correcoes_ex8_ex9.md`](docs/vulnerabilidades_owasp_e_correcoes_ex8_ex9.md) (Identificação de Falhas OWASP, Evidências Antes/Depois, Hardening e SQLModel)
- **Exercícios 12 e 13:** [`docs/relatorio_final_capstone_ex12_ex13.md`](docs/relatorio_final_capstone_ex12_ex13.md) (Pipeline DevSecOps, CVSS, Auditoria ZAP, Avaliação de Risco Residual e Roteiro do Vídeo)
