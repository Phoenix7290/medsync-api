# MedSync API — Relatório Final de DevSecOps, Auditoria Capstone e Rastreabilidade (Ex. 12 e 13)

> Convenção: **Implementado** = existe no código/pipeline e é verificável; **Recomendado** = decisão justificada, mas não implementada neste Assessment.

---

## 1. Exercício 12 — Pipeline DevSecOps

### 1.1 Em que fase do SDLC cada tipo de análise atua (decisão e justificativa)

```
 CODE / PR            BUILD / CI              TEST / PRÉ-RELEASE           QA / STAGING        OPERAÇÃO
┌────────────┐     ┌──────────────┐        ┌──────────────────┐        ┌────────────┐     ┌──────────────┐
│ SAST       │ ──> │ SCA          │ ──> ── │ pytest segurança │ ──> ── │ DAST (ZAP) │ ──> │ re-SCA semanal│
│ Bandit     │     │ pip-audit    │        │ (regressão authz)│        │ autenticado│     │ (cron)        │
└────────────┘     └──────────────┘        └──────────────────┘        └────────────┘     └──────────────┘
 GitHub Actions     GitHub Actions           GitHub Actions             scripts/run_zap_scan.sh   GitHub Actions
                                                                        + scripts/zap_gate.py
                                  IAST: Recomendado (QA, durante os testes E2E) — não implementado
```

| Tipo                           | Ferramenta                                              | Fase                                                                       | Status                                                                                          | Por que nesta fase (amarrado ao pipeline construído)                                                                                                                                                                                                                                                                                                         |
| :----------------------------- | :------------------------------------------------------ | :------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **SAST**                 | Bandit (`bandit -r app/ -ll`)                         | **Pull Request / push em `main`** (job `security-gate`, Stage 2) | **Implementado**                                                                          | Não precisa executar a aplicação e roda em segundos; barrar aqui é o ponto mais barato de correção. Detecta o que é padrão sintático (ex.:`shell=True`, `eval`, hash fraco, bind em `0.0.0.0`, segredos literais). **Limite conhecido:** não enxerga falhas de lógica de autorização — por isso o pytest (abaixo) é parte do gate. |
| **SCA**                  | pip-audit (`--strict`)                                | **Build/CI** (Stage 1) **+ cron semanal**                      | **Implementado**                                                                          | Dependência vulnerável não depende do nosso commit: uma CVE pode surgir depois do merge. Por isso roda a cada PR**e** semanalmente (`schedule` no workflow).                                                                                                                                                                                       |
| **Testes de segurança** | pytest (63 testes)                                      | **CI** (Stage 3)                                                     | **Implementado**                                                                          | Todas as vulnerabilidades críticas/altas do histórico foram falhas de**autorização/autenticação** (V02, V07–V11, V13). Nenhum scanner as acha; só testes derivados do threat model.                                                                                                                                                             |
| **DAST**                 | OWASP ZAP (`zap-api-scan -S`, passivo) autenticado    | **Pré-release / staging**, sobre o *release candidate*            | **Implementado como gate manual** (`scripts/run_zap_scan.sh` + `scripts/zap_gate.py`) | Precisa da aplicação rodando + imagem Docker + minutos de execução; não compensa por PR. Valida o que só aparece em runtime (headers reais, cache, CORS, respostas de erro). Não foi colocado no workflow porque o runner não tem o app seedado/autenticado de forma reprodutível sem expor credenciais de demo.                                     |
| **IAST**                 | Agente de instrumentação (ex.: Contrast, Datadog ASM) | **QA/staging, enquanto os testes automatizados/E2E rodam**           | **Recomendado — não implementado**                                                      | Só entrega valor correlacionando tráfego real a chamadas SQL/sinks dentro do runtime; com uma única API pequena, as queries já são 100% parametrizadas (SQLModel) e o pytest cobre a autorização, então o custo/ganho não se justifica agora. Entra se o número de endpoints crescer.                                                               |

### 1.2 Priorização das vulnerabilidades do Assessment (CVSS v3.1 + impacto de negócio)

Os scores abaixo foram **recalculados a partir de cada vetor** com a fórmula oficial do CVSS v3.1 (conferidos programaticamente). V01–V06 já constavam no relatório anterior (com scores corrigidos); V07–V13 são falhas que existiam na versão inicial e foram corrigidas nos Ex. 6–9, mas só estavam registradas nos testes de regressão.

| ID  | Vulnerabilidade (estado inicial)                                        | OWASP                | Vetor CVSS v3.1                         |     Score     |   Sev.   | Impacto de negócio (saúde / LGPD)                                                                           | Correção                                                                               | Teste de regressão                                                                                           |
| :-- | :---------------------------------------------------------------------- | :------------------- | :-------------------------------------- | :-----------: | :------: | :------------------------------------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------ |
| V07 | Auto-cadastro sem autenticação com`role=admin` (`/auth/register`) | API5:2023 / A01:2021 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical | Qualquer pessoa vira administrador e lê/apaga toda a agenda: sigilo médico comprometido e sanção da ANPD. | Rota só para admin**com MFA**; `partner` proibido; `extra='forbid'`           | `test_register_*`                                                                                           |
| V08 | MFA com código fixo no código-fonte e sem exigir 1º fator            | API2:2023 / A07:2021 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical | Bypass total do segundo fator das contas administrativas.                                                     | TOTP (RFC 6238) por usuário + exige token do 1º fator                                  | `test_mfa_requires_first_factor_token`, `test_mfa_old_static_code_rejected`                               |
| V12 | Segredos hardcoded (senhas de demo, chave do JWT com valor padrão)     | API8:2023 / A02:2021 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical | Quem acessa o repositório forja tokens de qualquer papel.                                                    | `BaseSettings` sem default, `SECRET_KEY` ≥ 32 chars, `.env.example` sem segredos  | `test_no_hardcoded_secret_defaults_in_source`                                                               |
| V03 | Stored XSS via nome do paciente na agenda                               | A03:2021             | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` | **9.3** | Critical | Sequestro da sessão de recepcionistas/médicos que abrem a agenda.                                           | Whitelist no Pydantic + auto-escape Jinja2 + CSP sem`script-src`                       | `test_jinja2_template_autoescape_prevents_stored_xss`, `test_whitelist_and_regex_validation`              |
| V09 | Token M2M do laboratório aceito em rotas de pacientes                  | API5:2023            | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8** |   High   | Violaria o contrato com o laboratório: acesso a dados que o parceiro nunca poderia ver.                      | `require_roles` exige papel humano; escopo `appointments:read_slots` só no `/lab` | `test_partner_token_cannot_touch_appointments`, `test_human_token_cannot_use_lab_slots_scope`             |
| V02 | BOLA na exclusão (`DELETE /appointments/{id}`)                       | API1:2023            | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | **8.1** |   High   | Cancelamento indevido de consultas e caos operacional.                                                        | Ownership centralizado (`enforce_appointment_ownership`)                               | `test_doctor_ownership_enforcement`                                                                         |
| V11 | Recepcionista podia criar/apagar consultas (BFLA)                       | API5:2023            | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | **8.1** |   High   | Adulteração da agenda por papel sem competência clínica.                                                  | `require_roles([DOCTOR], ["appointments:write"])`                                      | `test_receptionist_cannot_create_or_delete_but_can_read`                                                    |
| V13 | Força bruta no código MFA de 6 dígitos                               | API4:2023 / A07:2021 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **8.1** |   High   | 10⁶ combinações seriam esgotadas com a senha de um admin já vazada.                                       | Rate limit dedicado ao MFA (IP+usuário)                                                 | `test_mfa_brute_force_is_rate_limited`                                                                      |
| V05 | Força bruta no login                                                   | A07:2021 / API2:2023 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** |   High   | Comprometimento de credenciais médicas.                                                                      | Rate limit 5/min por IP + bcrypt + tempo constante p/ usuário inexistente               | `test_login_rate_limiting`                                                                                  |
| V10 | Agenda HTML (`/recepcao/agenda`) sem autenticação                   | API2:2023 / A01:2021 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** |   High   | Qualquer pessoa na internet lê nomes e especialidades dos pacientes.                                         | `require_roles([RECEPTIONIST, ADMIN], ["appointments:read"])`                          | `test_agenda_requires_authentication`, `test_agenda_forbidden_for_doctor_allowed_for_reception_and_admin` |
| V01 | BOLA na leitura (`GET /appointments/{id}`)                            | API1:2023            | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** |  Medium  | Exposição de dados de saúde de terceiros (mas exige token válido).                                        | Ownership centralizado                                                                   | `test_doctor_ownership_enforcement`, `test_doctor_list_is_filtered_to_own_crm`                            |
| V04 | Mass assignment (campos não declarados)                                | API3:2023            | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` | **4.3** |  Medium  | Forjar`status`/campos de auditoria.                                                                         | `extra='forbid'`                                                                       | `test_extra_forbid_blocks_parameter_pollution`                                                              |
| V06 | Sem cabeçalhos de segurança (clickjacking, sniffing, downgrade)       | API8:2023 / A05:2021 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` | **4.2** |  Medium  | Operador induzido a cliques ocultos.                                                                          | `SecurityHeadersMiddleware`                                                            | `test_security_headers_present`                                                                             |

**Riscos residuais (existem hoje, não foram eliminados):**

| ID | Risco residual                                                                                           | Vetor CVSS v3.1                         | Score |  Sev.  | Impacto de negócio                                                               | Mitigação recomendada                                           |
| :- | :------------------------------------------------------------------------------------------------------- | :-------------------------------------- | :---: | :----: | :-------------------------------------------------------------------------------- | :---------------------------------------------------------------- |
| R5 | `SECRET_KEY` fica em variável de ambiente/`.env`; leitura do host permite forjar tokens             | `AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N` |  5.7  | Medium | Comprometimento de todas as contas, porém exige acesso privilegiado ao servidor. | Cofre de segredos com rotação (Vault / Secrets Manager)         |
| R1 | CPF e`mfa_secret` armazenados em texto no banco                                                        | `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N` |  4.4  | Medium | Dump do banco expõe CPF e permite regenerar TOTP de admins.                      | Criptografia de campo/coluna e do volume                          |
| R4 | IDs sequenciais + 404 (não existe) vs 403 (existe, não é seu) permitem enumerar IDs                   | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |  4.3  | Medium | Revela volume/existência de consultas (sem revelar conteúdo).                   | UUIDs e 404 uniforme para "não existe" e "não é seu"           |
| R2 | JWT stateless sem revogação: token roubado vale até expirar (60 min)                                  | `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` |  4.2  | Medium | Janela de uso após logout/demissão.                                             | Expiração menor + refresh tokens + denylist (`jti`)           |
| R3 | Rate limiter em memória e por IP: não escala horizontalmente; atrás de proxy todos parecem o mesmo IP | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L` |  3.7  |  Low  | Bypass parcial do limite em cluster.                                              | Redis compartilhado + tratamento de`X-Forwarded-For` no gateway |

### 1.3 Security gate: critério definido e justificado

**O pipeline BLOQUEIA se qualquer condição ocorrer:**

| # | Gate   | Condição de bloqueio                                                                                   | Onde roda                            |
| :-: | :----- | :------------------------------------------------------------------------------------------------------- | :----------------------------------- |
| 1 | SCA    | `pip-audit --strict` encontra **qualquer** vulnerabilidade conhecida (ou não consegue auditar)  | GitHub Actions, Stage 1              |
| 2 | SAST   | `bandit -ll` encontra achado de severidade **Medium ou High** (Low é registrado, não bloqueia) | GitHub Actions, Stage 2              |
| 3 | Testes | **Qualquer** falha no `pytest` (inclui toda a suíte de regressão de autorização)             | GitHub Actions, Stage 3              |
| 4 | DAST   | Qualquer alerta ZAP com risco**≥ Medium** (`riskcode ≥ 2`)                                     | Pré-release:`scripts/zap_gate.py` |

**Justificativa (decorrente do histórico acima):**

1. **O limiar equivale a CVSS ≥ 4.0 (Medium)**, não 7.0. O motivo: Bandit e pip-audit não emitem CVSS, então não dá para filtrar por 7.0 sem inventar uma conversão; adotamos o mapeamento conservador "Medium e High bloqueiam". Com dados de saúde sob a LGPD, o custo de um falso positivo (um PR atrasado) é muito menor que o de um vazamento.
2. **O gate mais valioso é o nº 3.** Das 13 vulnerabilidades levantadas, 8 têm CVSS ≥ 7.0 e **todas** são de autenticação/autorização, que scanners não detectam; cada uma tem teste de regressão nomeado na tabela 1.2. Se alguém reintroduzir `/auth/register` aberto, o pytest falha e o merge é barrado.
3. **Low/Informational não bloqueiam** (ex.: alertas informativos do ZAP), para não criar fadiga de alerta; ficam registrados e triados na tabela 2.2.
4. **Exceção auditável:** um CVE sem correção disponível pode ser aceito apenas com `--ignore-vuln <ID>` no workflow, com justificativa no PR.

**Como o bloqueio de merge é efetivado:** o workflow só *reprova o check* `Security Gate`; quem impede o merge é a **branch protection** da `main` exigindo esse check (comando `gh api` no README, seção “CI”). Sem essa configuração o gate é apenas informativo.

### 1.4 Estratégia de testes de segurança derivada do threat model (Ex. 4)

Cada ameaça do Ex. 4 tem pelo menos um teste. O teste inicial do Ex. 6 (`test_non_admin_forbidden_on_admin_endpoint`) foi expandido para os vetores abaixo.

| Ameaça (Ex. 4)               | Vetor                                                       | Testes pytest                                                                                                                                                                                                                             |
| :---------------------------- | :---------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MC-03 / STRIDE-E (BOLA)       | Trocar o ID na URL                                          | `test_doctor_ownership_enforcement`, `test_doctor_token_without_crm_claim_sees_nothing`, `test_doctor_list_is_filtered_to_own_crm`                                                                                                  |
| STRIDE-S (spoofing de CRM)    | Criar consulta no CRM de outro médico                      | `test_cross_doctor_appointment_creation_spoofing`                                                                                                                                                                                       |
| STRIDE-S (token forjado)      | Assinatura inválida /`alg=none` / sem `exp` / expirado | `test_invalid_signature_token_rejected_with_401`, `test_alg_none_token_is_rejected`, `test_token_without_exp_is_rejected`, `test_expired_token_rejected_with_401`                                                                 |
| MC-05 / STRIDE-E              | Escalada via`/auth/register`                              | `test_register_requires_authentication`, `test_register_self_service_admin_escalation_blocked`, `test_register_forbidden_for_non_admin_and_admin_without_mfa`, `test_register_rejects_partner_role_unknown_fields_and_weak_input` |
| MC-06 / STRIDE-S              | Bypass/brute force de MFA                                   | `test_mfa_requires_first_factor_token`, `test_mfa_old_static_code_rejected`, `test_mfa_rejected_for_account_without_mfa`, `test_mfa_brute_force_is_rate_limited`, `test_admin_without_mfa_forbidden`                            |
| MC-07 / STRIDE-E (M2M)        | Token do laboratório em rotas de pacientes/admin/agenda    | `test_partner_token_cannot_touch_appointments`, `test_partner_token_cannot_open_agenda_or_admin`, `test_partner_lab_forbidden_on_unauthorized_scope`, `test_human_token_cannot_use_lab_slots_scope`                               |
| STRIDE-E (BFLA)               | Recepção cria/apaga; médico abre agenda                  | `test_receptionist_cannot_create_or_delete_but_can_read`, `test_agenda_forbidden_for_doctor_allowed_for_reception_and_admin`                                                                                                          |
| MC-01 / STRIDE-T (XSS)        | Script no nome do paciente                                  | `test_whitelist_and_regex_validation`, `test_status_and_text_fields_use_whitelist`, `test_jinja2_template_autoescape_prevents_stored_xss`                                                                                           |
| MC-04 / STRIDE-T              | Campos extras                                               | `test_extra_forbid_blocks_parameter_pollution`                                                                                                                                                                                          |
| MC-02 / STRIDE-I              | Vazamento de campos internos                                | `test_response_model_blocks_internal_audit_fields`, `test_openapi_specification_audit`                                                                                                                                                |
| MC-08 / STRIDE-D              | Força bruta no login                                       | `test_login_rate_limiting`, `test_login_unknown_user_same_error_as_wrong_password`                                                                                                                                                    |
| STRIDE-D (página HTML)       | Página gigante/parâmetros inválidos                      | `test_agenda_filters_by_day_and_paginates`, `test_agenda_rejects_invalid_query`                                                                                                                                                       |
| STRIDE-T (SQLi)               | Payload SQL em campo                                        | `test_status_and_text_fields_use_whitelist` (`DROP TABLE`), `test_sqlmodel_persistence_and_parameterized_query`                                                                                                                     |
| STRIDE-I (segredos)           | Segredo no código                                          | `test_no_hardcoded_secret_defaults_in_source`                                                                                                                                                                                           |
| ZAP 90004 / 10049             | Headers CORP e cache                                        | `test_zap_corp_header_present`, `test_no_store_cache_control_on_all_responses`                                                                                                                                                        |
| Superfície de reconhecimento | `/docs` e OpenAPI em produção                           | `test_docs_disabled_in_production`                                                                                                                                                                                                      |

Testes unitários **com mocking** (rubrica 4.6): `test_unit_with_mocked_database_session` substitui `get_session` por `MagicMock` via `app.dependency_overrides` e verifica que a rota de listagem usa a sessão sem tocar no banco.

---

## 2. Exercício 13 — Capstone: auditoria final e rastreabilidade

### 2.1 Matriz de rastreabilidade (Threat model → OWASP → correção → evidência)

| Ameaça STRIDE (Ex. 4)                              | OWASP                | Componente                                     | Correção                                                                                   | Evidência                                                                                                |
| :-------------------------------------------------- | :------------------- | :--------------------------------------------- | :------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- |
| **S** — token forjado / CRM de outro médico | API2:2023, API1:2023 | `core/security.py`, `core/dependencies.py` | JWT com`exp`/`sub` obrigatórios e algoritmo fixo; CRM do token comparado ao da consulta | testes de §1.4 (S)                                                                                       |
| **T** — XSS stored na agenda                 | A03:2021             | `models/appointment.py`, `templates/`      | Whitelist + auto-escape Jinja2 + CSP                                                         | `test_jinja2_template_autoescape_prevents_stored_xss`, `docs/evidencias/test-xss.png`                 |
| **T** — campos não declarados               | API3:2023            | `models/*.py`                                | `extra='forbid'`                                                                           | `test_extra_forbid_blocks_parameter_pollution`                                                          |
| **T** — SQL injection                        | A03:2021             | `database/*.py`, `routes/*.py`             | SQLModel`select().where()` parametrizado                                                   | `test_sqlmodel_persistence_and_parameterized_query`                                                     |
| **I** — vazamento de metadados               | API3:2023            | `models/appointment.py`                      | `response_model=AppointmentResponse` (sem `patient_cpf`, `internal_*`, `created_*`)  | `test_response_model_blocks_internal_audit_fields`                                                      |
| **I** — dados em cache                       | API8:2023            | `core/middleware.py`                         | `Cache-Control: no-store`                                                                  | `test_no_store_cache_control_on_all_responses`, ZAP 10049                                               |
| **D** — força bruta login/MFA               | API2:2023, API4:2023 | `core/middleware.py`, `routes/auth.py`     | Rate limit login e MFA                                                                       | `test_login_rate_limiting`, `test_mfa_brute_force_is_rate_limited`                                    |
| **D** — página HTML ilimitada               | API4:2023            | `routes/web.py`                              | Filtro por dia +`limit ≤ 200`                                                             | `test_agenda_filters_by_day_and_paginates`                                                              |
| **E** — escalada de papel                    | API5:2023            | `core/dependencies.py`, `routes/auth.py`   | `require_roles`, `require_admin_with_mfa`                                                | testes de §1.4 (E)                                                                                       |
| **E** — laboratório fora do escopo          | API5:2023            | `routes/lab.py`, `core/dependencies.py`    | Client Credentials + escopo`appointments:read_slots`                                       | `test_partner_*`                                                                                        |
| **Misconfig** — headers/CORS/docs            | API8:2023            | `main.py`, `core/middleware.py`            | HSTS, XFO, nosniff, CSP, CORP, CORS allowlist, docs off em prod                              | `test_security_headers_present`, `test_cors_explicit_allowlist`, `test_docs_disabled_in_production` |

### 2.2 Scan passivo OWASP ZAP — resultados reais

Ferramenta: **OWASP ZAP 2.17.0**, `zap-api-scan.py -f openapi -S` (modo seguro/passivo), alvo `/openapi.json`. Os relatórios são os gerados pelo próprio ZAP.
O script de verificações caseiras (`run_zap_passive_audit.py`) usado antes **foi removido**: não era o ZAP e seu “30/30 aprovadas” não deve ser citado.

**Scan 1 — baseline, sem autenticação** (`docs/owasp_zap_baseline.json` / `.html`): 14 endpoints importados.

| Plugin ZAP | Risco | Achado                                      |         Instâncias         | Categoria OWASP      | Ação / correção                                                                                         | Verificação                                                                          |
| :--------: | :---: | :------------------------------------------ | :--------------------------: | :------------------- | :---------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------- |
|   90004   |  Low  | Cross-Origin-Resource-Policy ausente        | 2 (`/`, `/openapi.json`) | API8:2023 / A05:2021 | Header`Cross-Origin-Resource-Policy: same-origin` no middleware                                           | `test_zap_corp_header_present` + rescan (§2.3)                                      |
|   10049   | Info | Conteúdo armazenável em cache             | 2 (`/`, `/openapi.json`) | API8:2023 / A05:2021 | `Cache-Control: no-store` em todas as respostas (a API trafega dados de saúde)                           | `test_no_store_cache_control_on_all_responses` + rescan                              |
|   10049   | Info | Conteúdo não armazenável                 |      5 (respostas 401)      | —                   | Nenhuma: comportamento desejado                                                                             | —                                                                                     |
|   100000   | Info | Resposta 4xx                                |    12 (11× 401, 1× 422)    | API2:2023 / A01:2021 | Nenhuma: prova que as rotas protegidas**negam acesso sem token**; também revela a limitação abaixo | scan 2                                                                                 |
|   10111   | Info | Requisição de autenticação identificada |     1 (`/auth/token`)     | API2:2023 / A07:2021 | Já mitigado: bcrypt, rate limit, resposta idêntica para usuário/senha inválidos                         | `test_login_rate_limiting`, `test_login_unknown_user_same_error_as_wrong_password` |

**Resultado do gate DAST no scan 1:** nenhum alerta ≥ Medium (`python scripts/zap_gate.py docs/owasp_zap_baseline.json`).

**Limitação do scan 1 (importante):** apenas `/` e `/openapi.json` retornaram 2xx; todas as rotas protegidas responderam 401. Ou seja, o ZAP **não analisou as respostas autenticadas** (agenda HTML, listagem, `/lab`, `/admin`), e o “zero Medium” cobre só a superfície pública. Por isso foi criado o **scan 2 autenticado** (`scripts/run_zap_scan.sh after`), que injeta um token admin+MFA.

### 2.3 Scan 2 — autenticado, pós-correção

> `bash scripts/run_zap_scan.sh after` (arquivos `docs/owasp_zap_after.json` / `.html`):
>
> ```text
> Number of Imported URLs: 2
> Total of 2 URLs
> [... 118 regras validadas com PASS (omitidas para brevidade) ...]
> FAIL-NEW: 0     FAIL-INPROG: 0  WARN-NEW: 0     WARN-INPROG: 0  INFO: 0 IGNORE: 0  PASS: 118
> 
> ZAP 2.17.0 | owasp_zap_after.json | 2 alertas
>   High          0
>   Medium        0
>   Low           0
>   Informational 2
> 
> GATE DAST: APROVADO (nenhum alerta com risco >= Medium)
> ```

### 2.4 Auditoria da especificação OpenAPI (`/openapi.json`)

Auditoria feita sobre o schema gerado pela própria aplicação (13 operações, 1 esquema de segurança `OAuth2PasswordBearer`).

| # | Verificação                                                                                                                   | Resultado                                                                                                                                     | Ação                                                                                                    |
| :-: | :------------------------------------------------------------------------------------------------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- |
| 1 | Operações sem`security`                                                                                                     | Só`POST /auth/token`, `POST /auth/m2m/token` e `GET /` — públicas por desenho (emissão de token e healthcheck)                      | Nenhuma                                                                                                   |
| 2 | Modelos de entrada com`additionalProperties: false`                                                                           | `AppointmentCreate`, `UserCreate`, `MFAVerifyRequest`, `M2MTokenRequest` ✔                                                           | Nenhuma                                                                                                   |
| 3 | Schema de saída sem campos sensíveis                                                                                          | `AppointmentResponse` expõe 7 campos; sem `patient_cpf`, `internal_audit_id`, `created_by_ip`, `internal_notes`, `created_at` ✔ | Teste`test_openapi_specification_audit`                                                                 |
| 4 | **Falha de design:** `/docs`, `/redoc` e `/openapi.json` públicos facilitam reconhecimento                         | Confirmado em desenvolvimento                                                                                                                 | **Corrigido:** desativados quando `ENVIRONMENT=production` (`test_docs_disabled_in_production`) |
| 5 | **Falha de design:** mensagem 403 listava os papéis aceitos (`['doctor', ...]`)                                        | Confirmado                                                                                                                                    | **Corrigido:** mensagem genérica (`test_forbidden_message_does_not_list_allowed_roles`)          |
| 6 | **Falha de design:** respostas 401/403/404/429 não documentadas no schema (só 2xx e 422)                                | Confirmado                                                                                                                                    | Residual de baixo risco: documentar com`responses={...}`                                                |
| 7 | **Falha de design:** `POST /lab/manage-patients` é rota-isca para demonstrar negação de escopo e aparece no contrato | Confirmado                                                                                                                                    | Residual: remover antes de produção                                                                     |
| 8 | **Falha de design:** IDs inteiros sequenciais + 404/403 distintos                                                         | Confirmado                                                                                                                                    | Residual**R4**                                                                                      |
| 9 | `UserCreatedResponse` retorna `mfa_provisioning_secret`                                                                     | Por desenho (entrega única do segredo TOTP ao criar admin)                                                                                   | Aceito; exige TLS                                                                                         |

### 2.5 Riscos residuais e parecer de deploy

Riscos residuais: **R1–R5** (tabela do §1.2) e a **limitação de cobertura do ZAP** (§2.2).

| Risco                                   | Score | Abaixo do limiar de bloqueio? |
| :-------------------------------------- | :---: | :---------------------------: |
| R5 chave JWT no ambiente                |  5.7  |          Sim (< 7.0)          |
| R1 CPF/`mfa_secret` em texto no banco |  4.4  |              Sim              |
| R4 enumeração de IDs                  |  4.3  |              Sim              |
| R2 sem revogação de token             |  4.2  |              Sim              |
| R3 rate limit em memória               |  3.7  |              Sim              |

> **PARECER: LIBERAÇÃO CONDICIONADA.** Nenhuma vulnerabilidade residual atinge CVSS ≥ 7.0 e todas as vulnerabilidades altas/críticas do histórico (V02, V03, V05, V07–V13) têm correção e teste de regressão. Porém, **o deploy fica bloqueado até que as condições abaixo sejam cumpridas**:
>
> 1. **(Bloqueante)** Executar o scan ZAP **autenticado** (§2.3) sem nenhum alerta ≥ Medium. Sem isso, a cobertura do DAST se limita à superfície pública.
> 2. **(Bloqueante)** `ENVIRONMENT=production`, `SECRET_KEY` gerada por `openssl rand -hex 32` e entregue por cofre de segredos/variável do orquestrador, **nunca** por `.env` versionado; `SEED_DEMO_DATA=false`.
> 3. **(Bloqueante)** TLS terminado em proxy/gateway (HSTS só tem efeito sob HTTPS) e **instância única** da API, pois o rate limiter é em memória (R3).
> 4. **(Prazo curto, até a 1ª sprint pós-deploy)** Criptografar CPF e `mfa_secret` (R1) e adotar UUID + 404 uniforme (R4).
>
> **Por que não bloquear por R1–R5:** para explorar R5 e R1 o atacante já precisa de acesso privilegiado ao host/banco (`PR:H`, `AC:H`), e R2–R4 expõem informação limitada sem acesso ao conteúdo clínico. Bloquear por eles atrasaria o início da operação sem reduzir o risco imediato.
>
> **Alcance da afirmação:** o que se demonstra é que **os ataques conhecidos são barrados por testes automatizados e revisados pelo gate**; isso não equivale a afirmar que não existam vulnerabilidades desconhecidas, e por isso a liberação é condicionada, não automática.
