# MedSync API — Vulnerabilidades OWASP, Correções, Hardening e Persistência (Ex. 8, 9, 10 e 11)

## 1. Exercício 8: Identificação de Vulnerabilidades no Código (OWASP Top 10)

A análise manual do código-fonte identificou três vulnerabilidades graves de categorias distintas do OWASP Top 10:

### 1.1 Vulnerabilidade 1: Broken Object Level Authorization (BOLA / IDOR)
* **Categoria OWASP:** **API1:2023 - Broken Object Level Authorization** (e A01:2021 - Broken Access Control).
* **Localização no Código Original:** Rota `GET /appointments/{appointment_id}` em `app/routes/appointments.py`.
* **Padrão de Código Vulnerável:**
  ```python
  @router.get("/{appointment_id}")
  async def get_appointment(appointment_id: int, repo = Depends(get_db_repository)):
      appointment = repo.get_by_id(appointment_id)
      if not appointment:
          raise HTTPException(status_code=404, detail="Não encontrado")
      return appointment
  ```
* **Mecanismo de Exploração:** A aplicação confiava cegamente no identificador numérico enviado na URL. Qualquer usuário autenticado (ou até não autenticado na versão preliminar) podia simplesmente incrementar ou iterar sobre os IDs (`/appointments/1`, `/appointments/2`, `/appointments/3`) para ler o nome do paciente, histórico de consultas, médico assistente e especialidade clínica.
* **Impacto no Domínio de Saúde (LGPD):** Exposição massiva de dados pessoais sensíveis (Art. 5º, II da LGPD), viabilizando engenharia social e quebra do sigilo médico-paciente.

---

### 1.2 Vulnerabilidade 2: Mass Assignment e Poluição de Parâmetros
* **Categoria OWASP:** **API3:2023 - Broken Object Property Level Authorization**.
* **Localização no Código Original:** Modelo de entrada `AppointmentCreate` em `app/models/appointment.py`.
* **Padrão de Código Vulnerável:**
  ```python
  class AppointmentCreate(AppointmentBase):
      pass  # Aceitava campos extras por padrão ou herdava sem restrição de dicionário
  ```
* **Mecanismo de Exploração:** O modelo de entrada não possuía a diretiva de proibição de propriedades adicionais. Um atacante podia enviar campos internos como `internal_audit_id`, `created_by_ip` ou até forjar o atributo `status="confirmada"` no payload de agendamento:
  ```json
  {
    "patient_name": "Carlos",
    "patient_cpf": "123.456.789-01",
    "doctor_name": "Dr. Silva",
    "doctor_crm": "CRM/SP 123456",
    "appointment_datetime": "2026-10-15T10:00:00Z",
    "specialty": "Cardiologia",
    "internal_audit_id": "FORGED-AUDIT-BYPASS",
    "status": "realizada"
  }
  ```
* **Impacto:** Adulteração de metadados de auditoria e quebra de regras de faturamento e fluxo clínico da clínica.

---

### 1.3 Vulnerabilidade 3: Falha de Validação de Entrada e Risco de Injeção
* **Categoria OWASP:** **A03:2021 - Injection / API8:2023 - Security Misconfiguration**.
* **Localização no Código Original:** Atributos `patient_cpf`, `doctor_crm` e `patient_name` em `AppointmentBase`.
* **Padrão de Código Vulnerável:**
  ```python
  patient_cpf: str = Field(...)
  doctor_crm: str = Field(...)
  patient_name: str = Field(...)
  ```
* **Mecanismo de Exploração:** Apenas o tipo genérico `str` era exigido. Não havia máscara de CPF, validação do formato de CRM médico nem *whitelist* de caracteres no nome do paciente. Isso permitia o envio de caracteres especiais, payloads de script ou sequências de controle que poderiam desestabilizar integrações ou viabilizar ataques no banco de dados.
* **Impacto:** Corrupção de dados cadastrais clínicos, impossibilidade de emissão de prontuários válidos e vetores de injeção em camadas posteriores.

---

## 2. Exercício 9: Correções Defensivas e Evidência Antes vs Depois

### 2.1 Implementação das Correções Técnicas

1. **Validação Rigorosa de Entrada (Whitelist e Regex):**
   * **CPF:** Validação estrita por expressão regular `r"^\d{3}\.\d{3}\.\d{3}-\d{2}$"`.
   * **CRM:** Validação estrita por expressão regular `r"^CRM/[A-Z]{2}\s\d{4,6}$"`.
   * **Nome do Paciente:** Validação por whitelist `r"^[A-Za-zÀ-ÖØ-öø-ÿ\s\.\'-]{2,100}$"`, rejeitando tags HTML, colchetes, parênteses e caracteres de script.
2. **Rejeição Estrita de Campos Extras no Pydantic:**
   * Inclusão de `model_config = ConfigDict(extra="forbid")` na classe `AppointmentCreate`. O envio de qualquer campo não mapeado resulta imediatamente em **HTTP 422 Unprocessable Entity**.
3. **Middleware / Dependência JWT Centralizada com Verificação de Ownership:**
   * Extração de claims seguras (`sub`, `role`, `doctor_crm`) e validação de vínculo: médicos com papel `doctor` só podem visualizar ou manipular consultas onde o CRM coincide exatamente com seu registro.
4. **Output Encoding no Jinja2:**
   * Auto-escaping ativo no Jinja2 e ausência deliberada de filtros perigosos como `| safe`.
5. **Endpoint Extra Identificado e Corrigido:**
   * **Endpoint:** `DELETE /appointments/{appointment_id}` (Cancelamento de Consulta).
   * **Justificativa:** O endpoint `DELETE` não foi citado no Exercício 8, mas compartilhava exatamente o mesmo padrão de vulnerabilidade BOLA. Se um médico de outra clínica ou concorrente autenticado soubesse o ID da consulta, poderia deletá-la arbitrariamente.
   * **Correção Aplicada:** Implementada verificação de ownership idêntica, na mesma dependência centralizada do `GET`: apenas o papel `doctor` com o escopo `appointments:write` pode cancelar, e somente consultas do seu próprio CRM. Administradores e recepcionistas **não** têm permissão de exclusão (recebem 403).

### 2.2 Tabela de Evidência Antes vs Depois

Resultados **medidos** executando os mesmos ataques contra as versões reais do repositório (`scripts/antes_depois.py`): `1d6d142` (versão inicial, Ex. 1 e 2, sem autenticação), `ab4db0d` (autenticação dos Ex. 6 e 7, antes das correções dos Ex. 8 e 9) e a versão atual. Saída completa em `docs/evidencias/antes_ataques.txt`, `depois_ataques.txt` e `comparativo_antes_depois.txt`.

| Cenário de ataque | Versão testada (ANTES) | ANTES | DEPOIS | Teste automatizado |
| :--- | :-- | :-: | :-: | :-- |
| Campo não declarado (`is_admin`) em `POST /appointments/` | `ab4db0d` | **201** (aceito sem erro) | **422** (`extra_forbidden`) | `test_extra_forbid_blocks_parameter_pollution` |
| CPF fora do padrão (`invalid-cpf-1`) | `ab4db0d` | **201** (aceito) | **422** | `test_whitelist_and_regex_validation` |
| `patient_name` = `<script>alert(1)</script>` | `ab4db0d` | **201** (gravado; só o Jinja2 protegia a saída) | **422** (whitelist) | `test_whitelist_and_regex_validation` |
| SQL injection em `doctor_name` (`x'); DROP TABLE users;--`) | `ab4db0d` | **201** (aceito) | **422** (whitelist) | `test_status_and_text_fields_use_whitelist` |
| BOLA: `GET /appointments/2` sem identidade | `1d6d142` | **200** com dados de outro paciente | **401** | `test_appointments_require_authentication` |
| BOLA: listar todas as consultas sem token | `1d6d142` | **200** | **401** | `test_appointments_require_authentication` |
| BOLA: médico lê consulta de outro médico (`id 2`) | `ab4db0d` | **403** (controle por CRM já existia) | **403** | `test_doctor_ownership_enforcement` |
| Recepcionista apaga consulta (`DELETE /appointments/2`) | `ab4db0d` | **204** | **403** | `test_receptionist_cannot_create_or_delete_but_can_read` |
| Recepcionista cria consulta | `ab4db0d` | **201** | **403** | `test_receptionist_cannot_create_or_delete_but_can_read` |
| Token M2M do laboratório em `GET /appointments/` e `/appointments/1` | `ab4db0d` | **200** | **403** | `test_partner_token_cannot_touch_appointments` |
| Agenda HTML sem token | `1d6d142` e `ab4db0d` | **200** | **401** | `test_agenda_requires_authentication` |
| MFA com código fixo `849201` sem 1º fator, seguido de `/admin/audit-logs` | `ab4db0d` | **200** | **401** | `test_mfa_requires_first_factor_token`, `test_mfa_old_static_code_rejected` |
| JWT de admin forjado com a chave padrão do código antigo | `ab4db0d` | **200** | **401** | `test_token_signed_with_previous_hardcoded_key_is_rejected` |
| Controle: payload legítimo do médico | ambas | **201** | **201** | `test_create_appointment_success` |

Observações para leitura correta:
- No Ex. 6 o controle de CRM do `GET` e do `DELETE` já estava no código, mas continha uma falha lógica (`if payload.doctor_crm and ...`): um token de médico **sem** a claim de CRM pulava a verificação. A correção do Ex. 9 nega esse caso (`test_doctor_token_without_crm_claim_sees_nothing`).
- “Aceito (201)” para XSS e SQLi significa que a entrada maliciosa chegou à camada de persistência. Em `ab4db0d` os dados ficavam em memória, portanto não houve execução de SQL; o ganho da correção é impedir o dado hostil na entrada, independentemente da camada abaixo.

---

## 3. Exercício 10: Hardening de Rede e Proteção contra Abuso

### 3.1 CORS com Allowlist Explícita
Configurado no `app/main.py` via `CORSMiddleware`:
* **Origens permitidas:** `http://localhost:3000` (desenvolvimento local) e `https://clinica.medsync.com.br` (domínio oficial de produção).
* **Wildcard (`*`) estritamente proibido:** Impede que sites maliciosos de terceiros explorem sessões e credenciais de usuários da clínica via navegador.
* **Comprovado pelo teste:** `test_cors_explicit_allowlist`.

### 3.2 Cabeçalhos de Segurança HTTP (Security Headers)
Implementados via `SecurityHeadersMiddleware` em `app/core/middleware.py`:
1. `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (obriga o navegador a comunicar-se exclusivamente via HTTPS).
2. `X-Frame-Options: DENY` (protege contra ataques de Clickjacking).
3. `X-Content-Type-Options: nosniff` (impede ataques de MIME-type sniffing).
4. `Content-Security-Policy: default-src 'self'; frame-ancestors 'none';` (restringe a execução de scripts e origens de carregamento ao próprio domínio).
5. `Referrer-Policy: strict-origin-when-cross-origin` (previne vazamento de URLs internas em cabeçalhos Referer).
6. `Cross-Origin-Resource-Policy: same-origin` (achado 90004 do ZAP).
7. `Cache-Control: no-store` em todas as respostas (achado 10049 do ZAP; respostas trafegam dados de saúde).
* **Comprovado pelos testes:** `test_security_headers_present`, `test_zap_corp_header_present`, `test_no_store_cache_control_on_all_responses`.

### 3.3 Rate Limiting Diferenciado para Login (`/auth/token`)
* Implementado em `app/core/middleware.py` com limite de **5 tentativas de login por minuto por endereço IP** (configurável por `LOGIN_RATE_LIMIT_PER_MINUTE`), com limiter **separado** para o código MFA (IP+usuário) e para a emissão M2M. **Limitação:** o contador fica em memória (residual R3).
* Em caso de excesso de requisições, a aplicação responde imediatamente com **HTTP 429 Too Many Requests** e o cabeçalho `Retry-After: 60`, mitigando ataques automatizados de força bruta e esgotamento de CPU por hashing bcrypt.
* **Comprovado pelo teste:** `test_login_rate_limiting`.

---

## 4. Exercício 11: Persistência Segura com SQLModel e Variáveis de Ambiente

### 4.1 Migração para SQLModel e Queries Parametrizadas
* A camada de persistência foi integralmente migrada de estruturas voláteis em memória para o **SQLModel** (ORM construído sobre SQLAlchemy 2.0, com sessões síncronas por requisição).
* Todas as consultas e operações de manipulação utilizam comandos estruturados baseados na API de `select()` do SQLModel:
  ```python
  statement = select(Appointment).where(Appointment.id == appointment_id)
  appointment = session.exec(statement).first()
  ```
* **Zero concatenação de strings:** nenhuma consulta usa interpolação manual (`f"SELECT... {id}"`); os valores sempre chegam como parâmetros vinculados, o que remove o vetor clássico de SQL Injection nessas consultas.
* As sessões de banco de dados são injetadas de forma desacoplada via `Depends(get_session)`.

### 4.2 Gerenciamento de Credenciais via BaseSettings e `.env`
* As credenciais e a URL de conexão do banco de dados são geridas de forma tipada e segura pelo `BaseSettings` (`pydantic-settings`) no módulo `app/core/config.py`.
* O arquivo `.env` está devidamente listado no `.gitignore` para garantir que segredos nunca sejam versionados no repositório Git.
* Um modelo estruturado sem segredos reais foi disponibilizado no arquivo `.env.example`, atendendo plenamente às exigências do edital.
* **Comprovado pelo teste:** `test_sqlmodel_persistence_and_parameterized_query`.


---

## 5. Vulnerabilidades adicionais encontradas e corrigidas (além das três do Ex. 8)

A revisão manual do código inicial encontrou outras falhas, todas corrigidas e cobertas por testes de regressão (`tests/test_regressao_falhas_corrigidas.py`). A priorização com CVSS está em `docs/relatorio_final_capstone_ex12_ex13.md` §1.2.

| ID | Falha no código inicial | Categoria OWASP | Correção |
| :-: | :-- | :-- | :-- |
| V07 | `/auth/register` aceitava auto-cadastro com `role=admin` | API5:2023 / A01:2021 | Só admin com MFA; papel `partner` vetado; `extra='forbid'` |
| V08 | MFA com código fixo no código-fonte, sem exigir o 1º fator | API2:2023 / A07:2021 | TOTP por usuário; exige token do 1º fator |
| V09 | Token M2M do laboratório aceito em rotas de pacientes | API5:2023 | `require_roles` exige papel humano |
| V10 | `/recepcao/agenda` pública | API2:2023 | Autenticação, papel e escopo |
| V11 | Recepcionista podia criar/apagar consultas | API5:2023 | `require_roles([DOCTOR])` |
| V12 | Senhas e chave JWT com valor padrão no código | API8:2023 / A02:2021 | `BaseSettings` sem default; `.env.example` sem segredos |
| V13 | Código MFA de 6 dígitos sem limite de tentativas | API4:2023 | Rate limit dedicado |

### 5.1 Endpoint não citado no Ex. 8 com o mesmo padrão (exigência do Ex. 9)
- **`DELETE /appointments/{id}`** compartilhava o padrão BOLA do `GET` (ver §2.1, item 5) e foi corrigido com a **mesma** dependência centralizada (`get_manageable_appointment`).
- **`POST /appointments/`** também: sem a checagem, um médico podia criar consulta no CRM de outro (spoofing). `enforce_appointment_ownership(payload, data.doctor_crm)` aplica a mesma regra. Teste: `test_cross_doctor_appointment_creation_spoofing`.
- **`GET /appointments/` (listagem)** devolveria consultas de todos; agora o filtro por CRM é aplicado na query. Teste: `test_doctor_list_is_filtered_to_own_crm`.

---

## 6. Como reproduzir a evidência “antes e depois” (Ex. 9)

O script `scripts/antes_depois.py` extrai do git as versões `1d6d142` e `ab4db0d`, sobe cada uma em uma porta própria junto com a versão atual e dispara **os mesmos ataques** contra as três, registrando o código HTTP e o veredito (`EXPLORADO` ou `BLOQUEADO`).

```bash
python scripts/antes_depois.py
```

Saídas gravadas em `docs/evidencias/`: `antes_ataques.txt`, `depois_ataques.txt` e `comparativo_antes_depois.txt`. O script termina com código de saída diferente de zero se qualquer ataque ainda for explorado na versão atual, e inclui um controle (payload legítimo, 201 nas duas versões) para provar que os bloqueios vêm da validação e não de uma falha genérica.

**Limite honesto da evidência:** as versões “antes” são as que existem no histórico do repositório. As falhas V07 (`/auth/register` aberto) e V10/V11 em sua forma original foram corrigidas antes de serem commitadas e por isso não aparecem na execução; elas estão cobertas apenas pelos testes de regressão (`tests/test_regressao_falhas_corrigidas.py`).

