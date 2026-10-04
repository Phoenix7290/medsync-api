set -u
BASE="${BASE:-http://127.0.0.1:8000}"
set -a; source .env; set +a
OUT="docs/evidencias/evidencias_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p docs/evidencias
G=$'\e[32m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'
PASS=0; FAIL=0
J='Content-Type: application/json'

check() { # descricao esperado obtido
  if [ "$2" = "$3" ]; then echo "  ${G}[OK]${N} $1  -> HTTP $3 (esperado $2)"; PASS=$((PASS+1))
  else echo "  ${R}[FALHOU]${N} $1  -> HTTP $3 (esperado $2)"; FAIL=$((FAIL+1)); fi
}
code() { curl -s -o /tmp/ev_body -w '%{http_code}' "$@"; }
tok() { python -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))'; }
login() { curl -s -X POST "$BASE/auth/token" -d "username=$1" --data-urlencode "password=$DEMO_USERS_PASSWORD" | tok; }
sec() { echo; echo "${B}== $1 ==${N}"; }

{
echo "${B}EVIDENCIAS MedSync API - $(date -Is)${N}  alvo: $BASE"

TREC=$(login recepcao); TDOC=$(login dr_roberto); TADM=$(login admin)
TLAB=$(curl -s -X POST "$BASE/auth/m2m/token" -H "$J" -d "{\"client_id\":\"partner-lab-01\",\"client_secret\":\"$DEMO_LAB_CLIENT_SECRET\"}" | tok)
AR="Authorization: Bearer $TREC"; AD="Authorization: Bearer $TDOC"; AA="Authorization: Bearer $TADM"; AL="Authorization: Bearer $TLAB"

sec "Ex.6 - Autenticacao (bcrypt + JWT) e RBAC"
check "login com senha errada" 401 "$(code -X POST $BASE/auth/token -d 'username=recepcao&password=errada')"
check "rota protegida sem token" 401 "$(code $BASE/appointments/)"
check "recepcao nao acessa rota admin" 403 "$(code $BASE/admin/audit-logs -H "$AR")"
check "medico nao acessa rota admin" 403 "$(code $BASE/admin/audit-logs -H "$AD")"
check "admin SEM MFA bloqueado na rota admin" 403 "$(code $BASE/admin/audit-logs -H "$AA")"
CODE=$(python scripts/gen_totp.py)
TADM2=$(curl -s -X POST "$BASE/auth/mfa/verify" -H "$J" -H "$AA" -d "{\"mfa_code\":\"$CODE\"}" | tok)
check "admin COM MFA (TOTP) acessa rota admin" 200 "$(code $BASE/admin/audit-logs -H "Authorization: Bearer $TADM2")"

sec "Falha 1 - Escalada de privilegio via /auth/register"
check "ATAQUE: auto-cadastro como admin sem autenticacao" 401 "$(code -X POST $BASE/auth/register -H "$J" -d '{"username":"hacker","email":"h@x.com","role":"admin","full_name":"Hacker","password":"abcdefgh"}')"
check "medico tentando cadastrar usuario" 403 "$(code -X POST $BASE/auth/register -H "$J" -H "$AD" -d '{"username":"hacker","email":"h@x.com","role":"admin","full_name":"Hacker","password":"abcdefgh"}')"
SUF=$RANDOM
check "admin+MFA cadastra recepcionista" 201 "$(code -X POST $BASE/auth/register -H "$J" -H "Authorization: Bearer $TADM2" -d "{\"username\":\"rec_$SUF\",\"email\":\"r$SUF@medsync.com\",\"role\":\"receptionist\",\"full_name\":\"Recepcionista Teste\",\"password\":\"SenhaForte-123\"}")"
check "admin+MFA tentando criar papel 'partner'" 422 "$(code -X POST $BASE/auth/register -H "$J" -H "Authorization: Bearer $TADM2" -d '{"username":"p1","email":"p@x.com","role":"partner","full_name":"Parceiro","password":"SenhaForte-123"}')"

sec "Falha 2 - MFA fixo / sem primeiro fator"
check "ATAQUE: codigo fixo 849201 sem token" 401 "$(code -X POST $BASE/auth/mfa/verify -H "$J" -d '{"username":"admin","mfa_code":"849201"}')"
check "ATAQUE: codigo fixo 849201 COM token do 1o fator" 401 "$(code -X POST $BASE/auth/mfa/verify -H "$J" -H "$AA" -d '{"mfa_code":"849201"}')"
echo "  brute-force de MFA (8 tentativas seguidas):"
for i in 1 2 3 4 5 6 7 8; do printf "    tentativa %s -> HTTP %s\n" $i "$(code -X POST $BASE/auth/mfa/verify -H "$J" -H "$AA" -d "{\"mfa_code\":\"00000$i\"}")"; done

sec "Ex.7 / Falha 3 - Token M2M do laboratorio (escopo so read_slots)"
check "lab le horarios disponiveis (permitido)" 200 "$(code $BASE/lab/available-slots -H "$AL")"
check "ATAQUE: lab lista consultas" 403 "$(code $BASE/appointments/ -H "$AL")"
check "ATAQUE: lab le consulta por ID" 403 "$(code $BASE/appointments/1 -H "$AL")"
check "ATAQUE: lab apaga consulta" 403 "$(code -X DELETE $BASE/appointments/1 -H "$AL")"
check "lab fora do escopo (/lab/manage-patients)" 403 "$(code -X POST $BASE/lab/manage-patients -H "$AL")"
check "medico nao usa escopo do lab" 403 "$(code $BASE/lab/available-slots -H "$AD")"

sec "Ex.8/9 - BOLA / ownership centralizado (Dr. Roberto = CRM/SP 123456)"
check "medico le a PROPRIA consulta (id 1)" 200 "$(code $BASE/appointments/1 -H "$AD")"
check "ATAQUE BOLA: medico le consulta de OUTRO (id 2)" 403 "$(code $BASE/appointments/2 -H "$AD")"
check "ATAQUE BOLA: medico APAGA consulta de outro (id 2)" 403 "$(code -X DELETE $BASE/appointments/2 -H "$AD")"
P='"patient_name":"Paciente Teste","patient_cpf":"111.222.333-44","appointment_datetime":"2026-10-20T10:00:00Z","specialty":"Cardiologia","status":"agendada"'
check "ATAQUE spoofing: criar consulta no CRM de outro medico" 403 "$(code -X POST $BASE/appointments/ -H "$J" -H "$AD" -d "{$P,\"doctor_name\":\"Dra. Beatriz Santos\",\"doctor_crm\":\"CRM/SP 654321\"}")"
check "recepcao NAO cria consulta" 403 "$(code -X POST $BASE/appointments/ -H "$J" -H "$AR" -d "{$P,\"doctor_name\":\"Dr. Roberto Silva\",\"doctor_crm\":\"CRM/SP 123456\"}")"
check "recepcao NAO apaga consulta" 403 "$(code -X DELETE $BASE/appointments/1 -H "$AR")"

sec "Ex.9 - Validacao de entrada (whitelist/regex/extra=forbid)"
D='"doctor_name":"Dr. Roberto Silva","doctor_crm":"CRM/SP 123456"'
check "campo nao declarado (mass assignment)" 422 "$(code -X POST $BASE/appointments/ -H "$J" -H "$AD" -d "{$P,$D,\"is_admin\":true}")"
check "XSS no nome do paciente" 422 "$(code -X POST $BASE/appointments/ -H "$J" -H "$AD" -d "{\"patient_name\":\"<script>alert(1)</script>\",\"patient_cpf\":\"111.222.333-44\",\"appointment_datetime\":\"2026-10-20T10:00:00Z\",\"specialty\":\"Cardiologia\",\"status\":\"agendada\",$D}")"
check "CPF fora do padrao" 422 "$(code -X POST $BASE/appointments/ -H "$J" -H "$AD" -d "{\"patient_name\":\"Paciente Teste\",\"patient_cpf\":\"123\",\"appointment_datetime\":\"2026-10-20T10:00:00Z\",\"specialty\":\"Cardiologia\",\"status\":\"agendada\",$D}")"
check "SQL injection em doctor_name" 422 "$(code -X POST $BASE/appointments/ -H "$J" -H "$AD" -d "{$P,\"doctor_name\":\"x'); DROP TABLE users;--\",\"doctor_crm\":\"CRM/SP 123456\"}")"

sec "Ex.2 - response_model (sem campos internos de auditoria)"
code $BASE/appointments/1 -H "$AD" >/dev/null; cat /tmp/ev_body; echo
if grep -qE 'internal_audit_id|created_by_ip|internal_notes|created_at|patient_cpf' /tmp/ev_body; then echo "  ${R}[FALHOU]${N} vazou campo interno"; FAIL=$((FAIL+1)); else echo "  ${G}[OK]${N} resposta sem internal_audit_id / created_by_ip / internal_notes / CPF"; PASS=$((PASS+1)); fi
sec "Ex.2/Falha 4 - Pagina da recepcao (Jinja2) exige autenticacao"
check "ATAQUE: agenda sem token" 401 "$(code $BASE/recepcao/agenda)"
check "agenda com token da recepcao" 200 "$(code $BASE/recepcao/agenda -H "$AR")"
check "agenda com token de medico" 403 "$(code $BASE/recepcao/agenda -H "$AD")"

sec "Ex.10 - Headers de seguranca e CORS"
curl -sI $BASE/ | grep -iE 'strict-transport|x-frame|x-content-type|content-security|referrer-policy'
echo "  CORS origem permitida (http://localhost:3000):"
curl -s -D - -o /dev/null -X OPTIONS $BASE/appointments/ -H 'Origin: http://localhost:3000' -H 'Access-Control-Request-Method: GET' | grep -i 'access-control-allow-origin' || echo "    (sem header)"
echo "  CORS origem do atacante (https://attacker.com) -> nao deve haver allow-origin:"
curl -s -D - -o /dev/null -X OPTIONS $BASE/appointments/ -H 'Origin: https://attacker.com' -H 'Access-Control-Request-Method: GET' | grep -i 'access-control-allow-origin' || echo "    (sem header allow-origin = bloqueado)"

sec "Ex.10 - Rate limiting no login (por ultimo)"
for i in 1 2 3 4 5 6 7 8; do printf "    tentativa %s -> HTTP %s\n" $i "$(code -X POST $BASE/auth/token -d 'username=recepcao&password=errada')"; done

echo; echo "${B}RESUMO: ${G}$PASS OK${N} / ${R}$FAIL falhas${N}"
} 2>&1 | tee "$OUT"
echo; echo "Evidencia salva em: $OUT"
