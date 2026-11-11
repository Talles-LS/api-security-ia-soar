"""
run_pipeline.py
===============
Executa a pipeline completa de ponta a ponta (etapas 1 a 4):

    1. Geração de logs sintéticos (API Gateway / WAF)
    2. Detecção de anomalias com Isolation Forest
    3. Playbook SOAR (resposta automatizada)
    4. Dashboard de segurança (dark theme)

Uso:
    python run_pipeline.py
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
STEPS = [
    "src/1_generate_logs.py",
    "src/2_anomaly_detection.py",
    "src/3_soar_playbook.py",
    "src/4_generate_dashboard.py",
]
ARTIFACTS = [
    "data/api_logs.csv",
    "data/analyzed_logs.csv",
    "output/model_metrics.json",
    "output/soar_actions_payload.json",
    "output/soar_execution.log",
    "output/security_dashboard.png",
]


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    t0 = time.perf_counter()
    for step in STEPS:
        print(f"\n>>> Executando {step}\n", flush=True)
        result = subprocess.run([sys.executable, str(ROOT_DIR / step)], cwd=ROOT_DIR)
        if result.returncode != 0:
            print(f"\n[FALHA] {step} terminou com código {result.returncode}")
            return result.returncode

    print("\n" + "=" * 72)
    print(" PIPELINE CONCLUÍDA - artefatos gerados:")
    print("=" * 72)
    ok = True
    for art in ARTIFACTS:
        path = ROOT_DIR / art
        exists = path.exists() and path.stat().st_size > 0
        ok &= exists
        size = f"{path.stat().st_size / 1024:>10,.1f} KB" if path.exists() else "-"
        print(f" [{'OK' if exists else 'XX'}] {art:<36} {size}")
    print(f"\n Tempo total: {time.perf_counter() - t0:.1f}s")
    print("=" * 72)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

