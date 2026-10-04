# MedSync API — Decisões de Segurança dos Exercícios 1, 2, 6 e 7

## Exercício 1 — Fundação da API

**Decisões**
- **Ambiente isolado:** `python3 -m venv .venv` + `pip install -r requirements.txt` (passo a passo no README). Evita dependências do sistema operacional e torna o `pip-audit` do pipeline reprodutível.
- **Modularização desde o início**, para que o serviço não vire “dezenas de rotas em um arquivo”:

  | Módulo | Responsabilidade |
  | :-- | :-- |
  | `app/routes/` | Um `APIRouter` por recurso: `appointments`, `auth`, `admin`, `lab`, `web` |
  | `app/models/` | Tabelas SQLModel e schemas Pydantic (entrada/saída separados) |
  | `app/database/` | Engine, sessão (`get_session`) e repositório de usuários |
  | `app/core/` | Camada de autenticação/autorização separada (`security.py`, `dependencies.py`), `config.py`, `middleware.py` |

- **Recurso RESTful completo (consultas):** `POST /appointments/`, `GET /appointments/`, `GET /appointments/{id}`, `DELETE /appointments/{id}` via `APIRouter`.
- **Falha-rápida de configuração:** `SECRET_KEY` não tem valor padrão; sem `.env` a aplicação nem inicia (decisão de segurança que o Ex. 11 formaliza).
- **Primeiro teste:** `tests/test_appointments.py::test_create_appointment_success` (caminho de sucesso do endpoint de consultas) e `test_root_healthcheck`. É o arquivo que cresceu ao longo do Assessment (hoje são 63 testes em 7 arquivos).

**Evidências:** `docs/evidencias/medsync-api_docs.png` (uvicorn + Swagger com as rotas), `docs/evidencias/pytest.png`.

---

## Exercício 2 — Exposição de dados e templates seguros

### 2.1 Por que `response_model` é obrigatório (risco quando não é definido)

Sem `response_model`, o FastAPI serializa **tudo** que a função retorna. Nesta aplicação a função retorna o objeto de tabela `Appointment`, que contém:

| Campo interno | Se vazasse |
| :-- | :-- |
| `patient_cpf` | Dado pessoal identificador (LGPD): permite cruzar a pessoa com a especialidade (dado de saúde sensível). |
| `created_by_ip` | Revela a topologia de rede interna e identifica de onde o profissional operou. |
| `internal_audit_id` | Identificador de trilha de auditoria: ajuda a correlacionar/forjar referências e a mapear o sistema. |
| `internal_notes` | Texto livre que pode conter informação clínica (“paciente com retorno prioritário”). |
| `created_at` | Metadado de infraestrutura. |

Há ainda um risco **estrutural**: sem `response_model`, qualquer coluna adicionada amanhã à tabela vaza automaticamente (inseguro por padrão). Com `response_model=AppointmentResponse` a regra se inverte: só o que está declarado sai (**seguro por padrão**). Isso corresponde a **API3:2023 (Broken Object Property Level Authorization)**.

**Implementação:** `AppointmentResponse` expõe apenas `id, patient_name, doctor_name, doctor_crm, appointment_datetime, specialty, status` e é usado em todas as rotas de consulta. O CPF é gravado, mas nunca devolvido nem exibido na agenda.
**Prova:** `test_response_model_blocks_internal_audit_fields` e `test_openapi_specification_audit` (o próprio schema OpenAPI não lista os campos); resposta real em `docs/evidencias/evidencias_*.txt` (seção “Ex.2”).

### 2.2 Página HTML da recepção com Jinja2 seguro

- **Herança de templates:** `base.html` (layout, estilos, rodapé LGPD) → `agenda.html` (`{% extends "base.html" %}`, blocos `title`, `extra_head`, `content`).
- **Auto-escape ativo:** `Jinja2Templates` do Starlette habilita auto-escape; **nenhum** `| safe` foi usado. `<script>` vira `&lt;script&gt;`.
- **Defesa em profundidade contra XSS stored (três camadas):**
  1. *Entrada:* whitelist por regex em `patient_name`, `doctor_name`, `specialty` e `status` (Pydantic).
  2. *Saída:* auto-escape do Jinja2.
  3. *Navegador:* CSP `default-src 'self'` na rota `/recepcao` (**sem `script-src`**: scripts inline não executam).
- **Menor exposição:** o template só recebe horário, paciente, profissional, especialidade e status. **Nenhum** campo de auditoria e **nenhum** CPF.
- **Controle de acesso:** a página exige token com papel `receptionist` ou `admin` e escopo `appointments:read` (no estado inicial era pública, V10).
- **Filtro e paginação:** `?data=AAAA-MM-DD&limit=&offset=` (`limit ≤ 200`) evita página gigante (STRIDE D).

**Prova:** `test_jinja2_template_autoescape_prevents_stored_xss` (grava `<script>` direto no banco, **contornando** a validação, e confirma que a página o escapa), `test_template_inheritance_renders_base_layout`; `docs/evidencias/test-xss.png`.

**Limitação conhecida:** a página exige o header `Authorization: Bearer ...`, que um navegador não envia sozinho. Em produção ela deve ser servida atrás de um proxy/SSO que injete o token, ou ganhar login por cookie `HttpOnly`+`SameSite=Strict` com proteção CSRF (não implementado).

---

## Exercício 6 — Autenticação e autorização

### 6.1 Autenticação
| Requisito | Implementação |
| :-- | :-- |
| OAuth2PasswordBearer | `oauth2_scheme` em `core/dependencies.py`, `tokenUrl=/auth/token` |
| Hash bcrypt | `hash_password`/`verify_password` (`core/security.py`), sal automático por senha; senhas nunca em texto; teste `test_password_hashing_bcrypt` |
| Enumeração de usuários | Mesma resposta/mesmo custo de tempo para usuário inexistente e senha errada (`DUMMY_PASSWORD_HASH`) |
| JWT com expiração | Claim `exp` **obrigatória** na decodificação (`options={"require": ["exp","sub"]}`), algoritmo fixado (rejeita `alg=none`), `ACCESS_TOKEN_EXPIRE_MINUTES=60` |
| MFA | O enunciado pede “simulado”; foi implementado **TOTP real (RFC 6238)** com a biblioteca padrão, para contas `admin`. O token do 1º fator vem com `mfa_verified=false`; só `/auth/mfa/verify` emite `mfa_verified=true`. Rotas administrativas exigem `require_admin_with_mfa`. Rate limit próprio para o código de 6 dígitos |

### 6.2 Modelo de autorização escolhido: **RBAC + autorização por recurso (ownership)**

| Opção | Decisão | Motivo |
| :-- | :-- | :-- |
| **RBAC** | ✔ Usado para **função** (o que cada papel pode fazer) | O sistema tem só 3 papéis estáveis (recepcionista, profissional, admin) e o enunciado os define; a regra é simples de auditar e testar. Matriz em `core/security.py::ROLE_SCOPES`. |
| **Autorização por recurso (ownership)** | ✔ Usado para **objeto** | O produto exige que o profissional gerencie “as consultas dos próprios pacientes”. Isso **não** é expressável por papel: dois médicos têm o mesmo papel e dados distintos. Sem isso, nasce BOLA (V01/V02). Regra: `doctor_crm` do token == `doctor_crm` da consulta. |
| **ABAC** | ✘ Não adotado | Exigiria motor de políticas (atributos de contexto: horário, unidade, consentimento). As regras atuais são só *papel + escopo + igualdade de CRM*; ABAC acrescentaria complexidade e superfície de erro sem ganho. **Quando migrar:** se surgirem regras como “só durante o plantão” ou “só com consentimento do paciente”. |

| Papel | Escopos no token | Pode |
| :-- | :-- | :-- |
| `doctor` | `appointments:read`, `appointments:write` | Criar/ler/apagar consultas **do próprio CRM** |
| `receptionist` | `appointments:read` | Ler consultas e abrir a agenda; **não** criar/apagar |
| `admin` | `admin:manage`, `appointments:read`, `appointments:write` | Rotas administrativas (**com MFA**); ler todas as consultas; cadastrar usuários |

**Sem duplicação de lógica de segurança (exigência do enunciado):** a verificação de papel/escopo está em `require_roles`; a de ownership **somente** em `enforce_appointment_ownership`, usada tanto por `appointment_access` (GET/DELETE por ID) quanto pelo `POST`. Para listagem, o filtro por CRM é aplicado na própria query.

**Teste do exercício:** `test_non_admin_forbidden_on_admin_endpoint` (recepcionista e médico recebem 403 em `/admin/audit-logs`), expandido no Ex. 12 (ver §1.4 do relatório final).

**Limitação conhecida:** o ownership é por CRM do profissional; não existe “paciente” como usuário autenticado (os três papéis do enunciado são internos).

---

## Exercício 7 — Escopos e integração externa (M2M)

### 7.1 Fluxo escolhido: **OAuth 2.0 Client Credentials**
| Fluxo | Adequado? | Motivo |
| :-- | :-: | :-- |
| **Client Credentials** | ✔ | Máquina-a-máquina, **sem usuário humano**: o laboratório é o próprio cliente e o token representa o sistema, não uma pessoa. |
| Password | ✘ | Pressupõe um usuário humano e entrega a senha ao cliente. |
| Authorization Code (+PKCE) | ✘ | Exige navegador e consentimento de um usuário. |
| Implicit | ✘ | Obsoleto (RFC 9700). |

**Implementação:** `POST /auth/m2m/token` com `client_id`, `client_secret` e `grant_type=client_credentials`. O segredo é guardado **com hash bcrypt** (`partner_clients.client_secret_hash`), há rate limit e a mensagem de erro não distingue cliente inexistente de segredo errado.

### 7.2 Claims e escopos: laboratório × profissional de saúde
| Claim | Profissional (humano) | Laboratório (M2M) |
| :-- | :-- | :-- |
| `sub` | username | `client_id` (`partner-lab-01`) |
| `role` | `doctor` / `receptionist` / `admin` | `partner` |
| `scopes` | `appointments:read`, `appointments:write` (e `admin:manage`) | **somente** `appointments:read_slots` (vem do banco, por cliente) |
| `doctor_crm` | presente (médicos) | ausente |
| `mfa_verified` | conforme o fluxo | sempre `false` |

### 7.3 Por que a limitação é técnica, não só contratual (mesmo com token vazado)
1. As rotas de pacientes exigem **papel humano** (`require_roles`) **e** escopo `appointments:read/write`. O token do laboratório tem papel `partner` e não tem esses escopos: **403** em `/appointments/*`, `/recepcao/agenda` e `/admin/*`.
2. A única rota do laboratório (`/lab/available-slots`) devolve somente data, horário, especialidade e profissional — **nenhum dado de paciente**.
3. O escopo vem **do banco** (`allowed_scopes` do cliente), não do pedido: o laboratório não consegue pedir escopo maior.
4. O caminho inverso também é barrado: token humano em `/lab/available-slots` → 403.

**Prova:** `test_partner_token_cannot_touch_appointments`, `test_partner_token_cannot_open_agenda_or_admin`, `test_human_token_cannot_use_lab_slots_scope`, `test_partner_lab_forbidden_on_unauthorized_scope`, `test_m2m_token_exchange_*`.

**Limitações conhecidas:** os horários de `/lab/available-slots` são dados estáticos de demonstração; o token M2M usa a mesma validade de 60 min dos humanos (em produção convém validade mais curta); a rota `/lab/manage-patients` existe só para demonstrar a negação de escopo e deve ser removida antes da produção.
