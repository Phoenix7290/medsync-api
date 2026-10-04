"""Imprime o código TOTP atual a partir de um segredo base32 (útil para demo/vídeo em desenvolvimento).

Uso:  python scripts/gen_totp.py            # lê DEMO_ADMIN_MFA_SECRET do .env/ambiente
      python scripts/gen_totp.py <SEGREDO>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings  # noqa: E402
from app.core.security import totp_code  # noqa: E402

secret = sys.argv[1] if len(sys.argv) > 1 else settings.DEMO_ADMIN_MFA_SECRET
if not secret:
    sys.exit("Informe o segredo como argumento ou defina DEMO_ADMIN_MFA_SECRET.")
print(totp_code(secret))
