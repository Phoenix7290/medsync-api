import json
import sys
from collections import Counter
from pathlib import Path

BLOCKING_RISKCODE = 2
RISK_NAMES = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
MIN_AUTHENTICATED_2XX_PERCENT = 20.0


def load_report(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"relatorio ZAP ilegivel ({path}): {exc}")


def collect_alerts(report: dict) -> list[dict]:
    return [alert for site in report.get("site", []) for alert in site.get("alerts", [])]


def percent_2xx(report: dict) -> float | None:
    for insight in report.get("insights", []):
        if insight.get("key") == "insight.code.2xx":
            return float(insight.get("statistic", 0))
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("uso: python scripts/zap_gate.py <relatorio_zap.json>", file=sys.stderr)
        return 2

    path = Path(argv[1])
    report = load_report(path)
    alerts = collect_alerts(report)
    if not report.get("site"):
        print(f"{path}: relatorio sem sites analisados", file=sys.stderr)
        return 2

    by_risk = Counter(RISK_NAMES.get(str(a.get("riskcode")), "?") for a in alerts)
    print(f"ZAP {report.get('@version', '?')} | {path.name} | {len(alerts)} alertas")
    for name in ("High", "Medium", "Low", "Informational"):
        print(f"  {name:<14}{by_risk.get(name, 0)}")

    coverage = percent_2xx(report)
    if coverage is not None:
        print(f"  respostas 2xx: {coverage:.0f}%")
        if coverage < MIN_AUTHENTICATED_2XX_PERCENT:
            print("  AVISO: baixa cobertura de respostas 2xx; as rotas protegidas podem nao ter sido analisadas")

    blocking = [a for a in alerts if int(a.get("riskcode", 0)) >= BLOCKING_RISKCODE]
    if blocking:
        print("\nGATE DAST: BLOQUEADO (alerta com risco >= Medium)")
        for alert in blocking:
            risk = RISK_NAMES.get(str(alert.get("riskcode")), "?")
            print(f"  [{risk}] {alert.get('pluginid')} {alert.get('name')} ({alert.get('count', '?')} instancias)")
        return 1

    print("\nGATE DAST: APROVADO (nenhum alerta com risco >= Medium)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
