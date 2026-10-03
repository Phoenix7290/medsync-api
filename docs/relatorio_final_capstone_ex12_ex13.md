# MedSync API — Relatório Final de DevSecOps, Auditoria Capstone e Rastreabilidade
**Assessment de Desenvolvimento Seguro (Exercícios 12 e 13)**  
**Autor:** Marcos Ryan (`marcos.ryanss@proton.me`)  
**Repositório Oficial:** [https://github.com/Phoenix7290/medsync-api](https://github.com/Phoenix7290/medsync-api)

---

## 1. Exercício 12: Pipeline DevSecOps e Justificativa no SDLC

### 1.1 Posicionamento Estratégico de Ferramentas no Ciclo de Vida (SDLC)

Para viabilizar a abordagem *Shift Left* sem degradar a velocidade de entrega contínua (*Continuous Delivery*), distribuímos as análises de segurança nas seguintes fases:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             CICLO DE VIDA DEVSECOPS                              │
│                                                                                  │
│   1. CODE / PR            2. BUILD / CI            3. TEST / QA       4. DEPLOY  │
│  ┌──────────────┐       ┌─────────────────┐      ┌──────────────┐   ┌───────────┐│
│  │     SAST     │  ──>  │       SCA       │ ──>  │     DAST     │──>│ MONITORING││
│  │ (Bandit/Linter│      │   (pip-audit)   │      │  (OWASP ZAP) │   │  & IAST   ││
│  └──────────────┘       └─────────────────┘      └──────────────┘   └───────────┘│
└──────────────────────────────────────────────────────────────────────────────────┘
```

| Tipo de Análise | Ferramenta Adotada | Fase do SDLC / Trigger | Justificativa Técnica e Operacional |
| :--- | :--- | :--- | :--- |
| **SAST (Static Application Security Testing)** | `Bandit` | **Commit / Pull Request (Pré-Merge)** | Analisa o código-fonte em repouso sem necessidade de execução. Identifica precocemente antipatterns criptográficos, injeção de comandos, binds inseguros e brechas na sintaxe antes que o código chegue à branch principal. |
| **SCA (Software Composition Analysis)** | `pip-audit` | **Build / CI (Dependências)** | Valida o `requirements.txt` consultando bases públicas de vulnerabilidades conhecidas (CVE/NVD/PyPA). Impede a introdução de dependências de terceiros com exploits conhecidos na cadeia de suprimentos (*supply chain*). |
| **DAST (Dynamic Application Security Testing)** | `OWASP ZAP` | **Test / Staging (Pós-Deploy Efêmero)** | Avalia a aplicação em tempo de execução como uma "caixa-preta", testando headers reais, comportamento de endpoints HTTP, proteção contra Clickjacking e vazamento de informações contextuais. |
| **IAST (Interactive Application Security Testing)** | Agente de instrumentação / Telemetria ASGI | **QA / Testes Automatizados E2E** | Instrumenta o bytecode e runtime durante a execução dos testes automatizados de integração, correlacionando requisições com chamadas SQL no banco de dados para detectar falhas em tempo real com baixa taxa de falso-positivo. |

---

### 1.2 Matriz de Priorização de Vulnerabilidades (CVSS v3.1 e Impacto de Negócio)

| ID | Vulnerabilidade Identificada | Categoria OWASP | Vetor CVSS v3.1 | CVSS Score | Severidade | Impacto de Negócio no Domínio de Saúde |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | BOLA / IDOR no Acesso a Consultas (`/appointments/{id}`) | API1:2023 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5 (Medium/High)** | **High** | Violação direta da LGPD (Art. 5º, II - dados sensíveis de saúde). Risco de multas de até 2% do faturamento da rede de clínicas e perda de reputação. |
| **VULN-02** | BOLA na Exclusão Arbitrária de Consultas (`DELETE`) | API1:2023 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | **8.1 (High)** | **High** | Cancelamento indevido de consultas agendadas, gerando caos operacional nas clínicas e impedindo atendimento de pacientes graves. |
| **VULN-03** | Stored XSS via Cadastro de Paciente na Agenda | A03:2021 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` | **9.6 (Critical)** | **Critical** | Sequestro de sessão e roubo de credenciais de recepcionistas e médicos com execução de ações no contexto privilegiado do navegador. |
| **VULN-04** | Mass Assignment / Poluição de Parâmetros (`extra_forbid`) | API3:2023 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` | **5.3 (Medium)** | **Medium** | Corrupção de campos de controle ou adulteração prematura de status de agendamentos. |
| **VULN-05** | Força Bruta no Endpoint de Login (`/auth/token`) | A07:2021 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5 (High)** | **High** | Comprometimento de credenciais médicas por tentativas automatizadas de adivinhação de senhas fracas. |
| **VULN-06** | Ausência de Cabeçalhos de Segurança HTTP (Clickjacking) | A05:2021 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` | **4.2 (Medium)** | **Medium** | Indução do operador a clicar em frames sobrepostos invisíveis para confirmar cancelamentos involuntários. |

---

### 1.3 Critério de Severidade do Security Gate no GitHub Actions

O Security Gate implementado em `.github/workflows/security-pipeline.yml` adota o seguinte critério de bloqueio:
* **Critério de Bloqueio (*Break the Build*):**
  - Qualquer vulnerabilidade identificada pelo `Bandit` com severidade **High** (`-ll` / `-lll`) ou falha em dependências de severidade **High/Critical** no `pip-audit`.
  - Qualquer falha na suíte de testes de segurança do `pytest`.
* **Justificativa do Critério:**
  Em sistemas que processam dados médicos e prontuários regulados pela LGPD, vulnerabilidades com score CVSS $\ge 7.0$ (High/Critical) representam risco imediato de vazamento e sanção jurídica, sendo inaceitável permitir que avancem para o ambiente de produção. Achados classificados como *Low* ou *Informational* (como ausência de headers opcionais de cache) geram avisos (*warnings*) registrados para resolução em sprints de melhoria, sem interromper deploys emergenciais de correção.

---

## 2. Exercício 13: Capstone, Auditoria ZAP e Rastreabilidade Completa

### 2.1 Matriz de Rastreabilidade Ponta a Ponta

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐       ┌─────────────────┐
│  THREAT MODEL   │  ──>  │ VULNERABILIDADE │  ──>  │ CORREÇÃO CÓDIGO  │  ──>  │   EVIDÊNCIA &   │
│  (STRIDE Ex 4)  │       │  (OWASP Ex 8)   │       │  (Ex 9, 10, 11)  │       │  TESTES / ZAP   │
└─────────────────┘       └─────────────────┘       └──────────────────┘       └─────────────────┘
```

| Ameaça STRIDE (Ex. 4) | Categoria OWASP (Ex. 8) | Componente Afetado | Correção Aplicada (Ex. 9, 10, 11) | Evidência de Verificação (Testes / ZAP) |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing (S):** Falsificação de token ou CRM de outro médico | API1:2023 (BOLA) | `routes/appointments.py` | Checagem obrigatória de ownership: CRM do token JWT comparado com o CRM da consulta. | `test_doctor_ownership_enforcement` (403 Forbidden). |
| **Tampering (T):** Injeção de scripts (XSS Stored) na agenda | A03:2021 (Injection) | `models/appointment.py` & `templates/` | 1. Whitelist regex no Pydantic (`validate_patient_name_whitelist`).<br>2. Auto-escape nativo Jinja2 sem filtro `\| safe`. | `test_whitelist_and_regex_validation` (422) e `test_jinja2_template_autoescape_prevents_stored_xss`. |
| **Tampering (T):** Injeção de propriedades não autorizadas | API3:2023 (Mass Assignment) | `models/appointment.py` | Diretiva `extra='forbid'` configurada no `AppointmentCreate`. | `test_extra_forbid_blocks_parameter_pollution` (422 extra_forbidden). |
| **Information Disclosure (I):** Vazamento de metadados internos | API3:2023 (Excessive Data Exposure) | `models/appointment.py` | `response_model=AppointmentResponse` suprimindo campos `internal_audit_id`, `created_by_ip`, etc. | `test_response_model_blocks_internal_audit_fields` e ZAP Regra 10062 (PASS). |
| **Denial of Service (D):** Ataque de força bruta no login | A07:2021 (Identification Failures) | `routes/auth.py` | Middleware de Rate Limiting (5 requisições/minuto por IP). | `test_login_rate_limiting` (HTTP 429). |
| **Tampering / Information Disclosure:** Injeção SQL na camada de dados | A03:2021 (SQLi) | `database/session.py` | Migração completa para SQLModel com queries 100% parametrizadas (`select().where()`). | `test_sqlmodel_persistence_and_parameterized_query`. |
| **Elevation of Privilege (E):** Laboratório acessando rotas de pacientes | API5:2023 (Broken Function Level Auth) | `routes/lab.py` | Escopos OAuth 2.0 refinados (`appointments:read_slots`) via Client Credentials. | `test_partner_lab_forbidden_on_unauthorized_scope` (403 insufficient_scope). |

---

### 2.2 Auditoria da Especificação OpenAPI (`/openapi.json`)
* Todos os endpoints protegidos declaram explicitamente esquemas de segurança OAuth2 (`OAuth2PasswordBearer`).
* O esquema público do `AppointmentResponse` no OpenAPI não lista nem expõe propriedades confidenciais de auditoria interna.
* **Comprovado pelo teste automatizado:** `test_openapi_specification_audit`.

---

### 2.3 Resultado do Scan Passivo OWASP ZAP
A execução da auditoria passiva cobriu os 6 endpoints principais da aplicação frente às regras oficiais da OWASP:
* **Total de Verificações:** 30 verificações.
* **Aprovações:** 30 (100%).
* **Falhas:** 0.
* **Relatório JSON consolidado em:** `docs/owasp_zap_scan_report.json`.

---

### 2.4 Avaliação de Risco Residual e Parecer Técnico de Deploy

Embora todos os controles e testes exigidos tenham sido implementados com sucesso, a análise de segurança identificou **dois riscos residuais conhecidos**:

1. **Risco Residual 1: Rate Limiter Centralizado em Memória Local**
   * *Descrição:* O controle de taxa de requisições de login (`LoginRateLimiter`) reside na memória da instância atual da aplicação FastAPI.
   * *Cenário:* Se a aplicação for escalada horizontalmente em um cluster Kubernetes com múltiplos pods/réplicas sem afinidade de sessão (*session affinity*), um atacante distribuído poderia contornar o limite alternando requisições entre instâncias.
   * *Mitigação Futura Recomendada:* Conectar o middleware de rate limiting a um cluster centralizado Redis/KeyDB com token bucket compartilhado.
2. **Risco Residual 2: Armazenamento da Chave Mestra de Assinatura JWT via Arquivo `.env`**
   * *Descrição:* A chave `SECRET_KEY` é injetada por variável de ambiente lida pelo `BaseSettings`.
   * *Cenário:* Em caso de comprometimento do servidor host, a variável de ambiente pode ser inspecionada no processo.
   * *Mitigação Futura Recomendada:* Integração com um cofre de segredos com rotação automática de chaves (como AWS Secrets Manager ou HashiCorp Vault).

#### Parecer Técnico de Liberação (*Deploy Sign-off*)
> **PARECER:** **AUTORIZADO PARA DEPLOY COM RESSALVA TÉCNICA CONTROLADA.**  
> O risco residual identificado é de nível **BAIXO** para a fase inicial de entrada em operação da rede de clínicas, pois:
> 1. O volume de requisições inicial será atendido por instância única segura com monitoramento ativo;
> 2. O segredo JWT possui entropia criptográfica de 256 bits, impedindo quebra matemática;
> 3. Todas as vulnerabilidades de alto impacto (BOLA, XSS Stored, Mass Assignment, SQL Injection e vazamento de dados sensíveis de pacientes sob a LGPD) foram matematicamente eliminadas do código e validadas por testes automatizados contínuos e pelo scan passivo ZAP.  
> As mitigações adicionais (Redis e cofre de segredos) ficam registradas no backlog técnico para o próximo ciclo de infraestrutura.

---

## 3. Roteiro Sugerido para Gravação do Vídeo de 5 Minutos (YouTube)

O edital exige um vídeo de até 5 minutos no YouTube (não listado), demonstrando o código e explicando as decisões tomadas. Sugestão de roteiro estruturado minuto a minuto:

* **Minuto 0:00 - 0:45 | Introdução e Contextualização do Projeto:**
  - Apresente-se ("Olá, meu nome é Marcos Ryan...").
  - Explique o objetivo: construção da API MedSync para agendamento seguro em clínicas médicas sob a ótica da LGPD (dados de saúde protegidos).
  - Mostre a estrutura de pastas modular (`routes`, `models`, `database`, `templates`, `tests`).
* **Minuto 0:45 - 2:00 | Decisões Centrais de Arquitetura e Mitigações OWASP:**
  - Abra o arquivo `app/models/appointment.py` e mostre o `AppointmentCreate` com `extra="forbid"` e validações regex (CPF e CRM), explicando como isso elimina Mass Assignment e injeções.
  - Mostre o `AppointmentResponse` e explique como ele impede o vazamento de dados de auditoria interna (resolvendo a OWASP API3).
  - Mostre o Jinja2 com auto-escaping nativo em `app/templates/agenda.html` prevenindo Stored XSS na tela da recepção.
* **Minuto 2:00 - 3:15 | Autenticação, RBAC, Ownership e Integração M2M:**
  - Explique o modelo de autorização híbrido: RBAC para papéis (`receptionist`, `doctor`, `admin`) + verificação estrita de ownership de consultas por CRM para neutralizar BOLA (OWASP API1).
  - Explique o MFA simulado obrigatório para administradores.
  - Explique o fluxo OAuth 2.0 Client Credentials garantindo que o laboratório parceiro só tenha acesso ao escopo `appointments:read_slots`.
* **Minuto 3:15 - 4:15 | Demonstração Prática da Aplicação e Testes:**
  - Mostre o terminal executando `pytest -v` com todos os **31 testes passando** (mostre na tela o 100% de aprovação).
  - Mostre o Swagger UI rodando em `http://127.0.0.1:8000/docs` e a tela web da recepção em `http://127.0.0.1:8000/recepcao/agenda`.
* **Minuto 4:15 - 5:00 | Security Gate no GitHub Actions e Risco Residual (Capstone):**
  - Mostre o arquivo `.github/workflows/security-pipeline.yml` e explique com suas palavras a regra do Security Gate: **bloqueio imediato no CI para achados de severidade High e Critical no Bandit e pip-audit**.
  - Conclua justificando o parecer de deploy: o risco residual (rate limiting em memória local) é aceitável para o início da operação e tem evolução planejada com Redis no backlog de infraestrutura.
