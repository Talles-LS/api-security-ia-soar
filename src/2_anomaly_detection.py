"""
2_anomaly_detection.py
======================
Detecção comportamental de anomalias em APIs financeiras com Isolation Forest
(aprendizado NÃO supervisionado).

O modelo é treinado sem qualquer rótulo: ele aprende o "perfil normal" do
tráfego e isola pontos que precisam de poucas partições aleatórias para serem
separados do restante (anomalias). A coluna `is_attack_ground_truth` é usada
APENAS após a inferência, para medir a qualidade da detecção.

Entrada : data/api_logs.csv
Saídas  : data/analyzed_logs.csv
          output/model_metrics.json

Uso:
    python src/2_anomaly_detection.py [--contamination 0.07] [--seed 42]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT_DIR / "data" / "api_logs.csv"
OUTPUT_FILE = ROOT_DIR / "data" / "analyzed_logs.csv"
METRICS_FILE = ROOT_DIR / "output" / "model_metrics.json"

FEATURES = [
    "hour_of_day",
    "requests_per_min",
    "bytes_transferred",
    "error_rate_4xx_5xx",
    "latency_ms",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Isolation Forest para logs de API.")
    parser.add_argument("--contamination", type=float, default=0.07,
                        help="Proporção esperada de anomalias (baseline do SOC).")
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not INPUT_FILE.exists():
        sys.exit(f"[ERRO] {INPUT_FILE} não encontrado. Execute src/1_generate_logs.py primeiro.")

    df = pd.read_csv(INPUT_FILE)
    X = df[FEATURES].astype(float).values

    # ------------------------------------------------------------------ #
    # Treinamento não supervisionado
    # ------------------------------------------------------------------ #
    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples="auto",          # min(256, n) amostras por árvore (paper original)
        contamination=args.contamination,
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=args.seed,
    )
    model.fit(X)

    df["anomaly_pred"] = model.predict(X)  # -1 = anomalia | 1 = normal
    # score_samples() retorna o NEGATIVO do score do paper (Liu et al., 2008).
    # Invertendo o sinal obtemos s(x, n) em (0, 1]: quanto MAIOR, mais anômalo.
    df["anomaly_score"] = (-model.score_samples(X)).round(6)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    # ------------------------------------------------------------------ #
    # Avaliação contra o ground truth (somente validação)
    # ------------------------------------------------------------------ #
    y_true = df["is_attack_ground_truth"].values
    y_pred = (df["anomaly_pred"] == -1).astype(int).values

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    roc_auc = roc_auc_score(y_true, df["anomaly_score"].values)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    threshold = float(-model.offset_)  # limiar de decisão na escala de anomaly_score

    anomalies = df[df["anomaly_pred"] == -1]

    print("=" * 72)
    print(" [2/4] DETECÇÃO DE ANOMALIAS - ISOLATION FOREST (NÃO SUPERVISIONADO)")
    print("=" * 72)
    print(f" Registros analisados : {len(df):,}")
    print(f" Features             : {', '.join(FEATURES)}")
    print(f" Hiperparâmetros      : n_estimators={args.n_estimators}, "
          f"contamination={args.contamination}, random_state={args.seed}")
    print(f" Limiar de decisão    : anomaly_score >= {threshold:.4f}")
    print("-" * 72)
    print(f" >>> TOTAL DE ANOMALIAS DETECTADAS: {len(anomalies):,} "
          f"({len(anomalies) / len(df):.2%} do tráfego)")
    print(f" >>> IPs únicos suspeitos         : {anomalies['source_ip'].nunique()}")
    print("-" * 72)
    print(" MATRIZ DE CONFUSÃO (linhas = real | colunas = predito)\n")
    print(f" {'':>18} | {'Pred. Normal':>13} | {'Pred. Anomalia':>14}")
    print(f" {'-' * 18}-+-{'-' * 13}-+-{'-' * 14}")
    print(f" {'Real Normal':>18} | {tn:>13,} | {fp:>14,}   (FP)")
    print(f" {'Real Ataque':>18} | {fn:>13,} | {tp:>14,}   (TP)")
    print("-" * 72)
    print(f" Precisão (Precision) : {precision:.4f}  -> dos alertas, quantos eram ataques reais")
    print(f" Revocação (Recall)   : {recall:.4f}  -> dos ataques reais, quantos foram detectados")
    print(f" F1-Score             : {f1:.4f}")
    print(f" Acurácia             : {accuracy:.4f}")
    print(f" Taxa de Falso Positivo: {fpr:.4f}")
    print(f" ROC-AUC (anomaly_score): {roc_auc:.4f}")
    print("-" * 72)
    print(" Classification report:\n")
    print(classification_report(y_true, y_pred, target_names=["Normal", "Ataque"], digits=4))
    print("-" * 72)
    print(" Anomalias por endpoint:")
    print(anomalies["endpoint"].value_counts().to_string())
    print("-" * 72)
    print(" Top 5 eventos mais anômalos:")
    cols = ["timestamp", "source_ip", "endpoint", "hour_of_day", "requests_per_min",
            "error_rate_4xx_5xx", "bytes_transferred", "anomaly_score"]
    print(df.nlargest(5, "anomaly_score")[cols].to_string(index=False))
    print("-" * 72)
    print(f" Arquivo gerado: {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print("=" * 72)

    # Métricas persistidas para o dashboard e para o README
    METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    METRICS_FILE.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": "IsolationForest",
        "features": FEATURES,
        "hyperparameters": {
            "n_estimators": args.n_estimators,
            "contamination": args.contamination,
            "max_samples": "auto",
            "random_state": args.seed,
        },
        "decision_threshold_anomaly_score": round(threshold, 6),
        "total_records": int(len(df)),
        "anomalies_detected": int(len(anomalies)),
        "suspicious_unique_ips": int(anomalies["source_ip"].nunique()),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "accuracy": round(float(accuracy), 4),
        "false_positive_rate": round(float(fpr), 4),
        "roc_auc": round(float(roc_auc), 4),
    }, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    np.set_printoptions(suppress=True)
    main()

