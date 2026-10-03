# MedSync API — Identificação de Vulnerabilidades OWASP, Correções 

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
   * **Correção Aplicada:** Implementada verificação de ownership idêntica: médicos só podem cancelar consultas vinculadas ao seu próprio CRM; administradores mantêm a prerrogativa de gerenciamento geral.

### 2.2 Tabela de Evidência Antes vs Depois

| Cenário de Ataque / Payload | Comportamento ANTES da Correção | Comportamento DEPOIS da Correção | Teste Automatizado de Comprovação |
| :--- | :--- | :--- | :--- |
| **Injeção de Campo Não Autorizado**<br>`POST /appointments/` com `"extra_admin_field": "hacked"` | O campo era aceito e processado silenciosamente pelo backend. | **Bloqueado com HTTP 422 (extra_forbidden).** | `test_extra_forbid_blocks_parameter_pollution` |
| **Envio de CPF Inválido**<br>`POST /appointments/` com `"patient_cpf": "123-invalid-cpf"` | Aceito sem validação de máscara legal. | **Bloqueado com HTTP 422 (validação de formato de CPF).** | `test_whitelist_and_regex_validation` |
| **Tentativa de Injeção de Script**<br>`POST /appointments/` com `"patient_name": "<script>alert(1)</script>"` | Gravado no banco; dependia exclusivamente do Jinja2 na saída. | **Bloqueado na entrada com HTTP 422 (whitelist de caracteres).** | `test_whitelist_and_regex_validation` |
| **BOLA no Acesso a Consultas**<br>Dr. Roberto acessando consulta da Dra. Beatriz (`GET /appointments/2`) | Acesso concedido com HTTP 200 exibindo dados confidenciais do paciente alheio. | **Bloqueado com HTTP 403 Forbidden (ownership violado).** | `test_doctor_ownership_enforcement` |
| **BOLA na Exclusão (Endpoint Extra)**<br>Dr. Roberto deletando consulta da Dra. Beatriz (`DELETE /appointments/2`) | Consulta excluída com sucesso sem checagem de autorização. | **Bloqueado com HTTP 403 Forbidden (ownership violado).** | `test_doctor_ownership_enforcement` |

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
* **Comprovado pelo teste:** `test_security_headers_present`.

### 3.3 Rate Limiting Diferenciado para Login (`/auth/token`)
* Implementado em `app/core/middleware.py` com limite de **5 tentativas de login por minuto por endereço IP**.
* Em caso de excesso de requisições, a aplicação responde imediatamente com **HTTP 429 Too Many Requests** e o cabeçalho `Retry-After: 60`, mitigando ataques automatizados de força bruta e esgotamento de CPU por hashing bcrypt.
* **Comprovado pelo teste:** `test_login_rate_limiting`.

---

## 4. Exercício 11: Persistência Segura com SQLModel e Variáveis de Ambiente

### 4.1 Migração para SQLModel e Queries Parametrizadas
* A camada de persistência foi integralmente migrada de estruturas voláteis em memória para o **SQLModel** (ORM assíncrono construído sobre SQLAlchemy 2.0).
* Todas as consultas e operações de manipulação utilizam comandos estruturados baseados na API de `select()` do SQLModel:
  ```python
  statement = select(Appointment).where(Appointment.id == appointment_id)
  appointment = session.exec(statement).first()
  ```
* **Zero Concatenação de Strings:** Nenhuma consulta utiliza interpolação manual (`f"SELECT... {id}"`), eliminando matematicamente o risco de **SQL Injection (SQLi)**.
* As sessões de banco de dados são injetadas de forma desacoplada via `Depends(get_session)`.

### 4.2 Gerenciamento de Credenciais via BaseSettings e `.env`
* As credenciais e a URL de conexão do banco de dados são geridas de forma tipada e segura pelo `BaseSettings` (`pydantic-settings`) no módulo `app/core/config.py`.
* O arquivo `.env` está devidamente listado no `.gitignore` para garantir que segredos nunca sejam versionados no repositório Git.
* Um modelo estruturado sem segredos reais foi disponibilizado no arquivo `.env.example`, atendendo plenamente às exigências do edital.
* **Comprovado pelo teste:** `test_sqlmodel_persistence_and_parameterized_query`.
