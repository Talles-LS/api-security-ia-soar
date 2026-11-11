"""
1_generate_logs.py
==================
Gerador de dataset sintético de logs de API Gateway / WAF para uma instituição
financeira em migração para nuvem.

Cenário simulado
----------------
* APIs críticas: /api/v1/login, /api/v1/pix, /api/v1/saldo
* Tráfego legítimo (93%): concentrado em horário comercial (08h-20h), baixa
  taxa de requisições por minuto, baixa taxa de erro e payloads moderados.
* Tráfego malicioso (7%): concentrado na madrugada (01h-05h), dividido em:
    - Credential Stuffing / Brute Force   -> /api/v1/login
      (150-500 req/min, taxa de erro HTTP 4xx/5xx > 0.70)
    - Exfiltração de Dados / Scraping     -> /api/v1/saldo e /api/v1/pix
      (alto volume de bytes transferidos e alta frequência de chamadas)

Saída: data/api_logs.csv

Uso:
    python src/1_generate_logs.py [--rows 5000] [--attack-ratio 0.07] [--seed 42]
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

# Garante saída UTF-8 no terminal do Windows (acentos e caracteres de caixa)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
OUTPUT_FILE = DATA_DIR / "api_logs.csv"

ENDPOINTS = ["/api/v1/login", "/api/v1/pix", "/api/v1/saldo"]

# Janela de observação dos logs (7 dias corridos)
WINDOW_START = datetime(2026, 11, 2, 0, 0, 0)
WINDOW_DAYS = 7

# Distribuição horária do tráfego legítimo: pico comercial 08h-20h, com uma
# cauda residual noturna (usuários reais também acessam de madrugada, o que
# torna o problema de detecção mais realista e gera falsos positivos plausíveis).
NORMAL_HOUR_WEIGHTS = np.array([
    0.4, 0.2, 0.15, 0.1, 0.1, 0.2,   # 00h-05h  (madrugada: quase nenhum uso)
    0.8, 2.5,                        # 06h-07h  (início do dia)
    6.5, 8.0, 8.5, 8.5, 9.0, 8.5,    # 08h-13h  (horário comercial)
    8.5, 8.5, 8.0, 7.5, 7.5, 7.0,    # 14h-19h  (horário comercial)
    6.0,                             # 20h
    3.0, 1.8, 0.9,                   # 21h-23h  (fim do dia)
])
NORMAL_HOUR_WEIGHTS = NORMAL_HOUR_WEIGHTS / NORMAL_HOUR_WEIGHTS.sum()

ATTACK_NIGHT_HOURS = np.array([1, 2, 3, 4, 5])


# --------------------------------------------------------------------------- #
# Geração de endereços IP
# --------------------------------------------------------------------------- #
def build_legit_ip_pool(rng: np.random.Generator, size: int = 900) -> np.ndarray:
    """IPs de clientes legítimos em faixas típicas de ISPs brasileiros."""
    isp_prefixes = ["177", "179", "186", "187", "189", "191", "200", "201"]
    ips = set()
    while len(ips) < size:
        p = rng.choice(isp_prefixes)
        ips.add(f"{p}.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}")
    return np.array(sorted(ips))


def build_attacker_ip_pool() -> dict[str, np.ndarray]:
    """IPs de atacantes: VPS/bulletproof hosting, nós de saída Tor e botnets.

    Faixas inspiradas em ASNs frequentemente vistos em feeds de Threat Intel
    (endereços fictícios para fins acadêmicos).
    """
    credential_stuffing = np.array([
        "185.220.101.34", "185.220.101.57", "45.155.205.233", "45.155.205.119",
        "91.240.118.172", "193.142.146.35", "141.98.11.62", "141.98.10.121",
        "89.248.165.74", "80.94.95.115", "103.145.13.209", "194.26.29.102",
        "5.188.206.18", "212.70.149.54",
    ])
    exfiltration = np.array([
        "23.129.64.210", "198.98.51.189", "104.244.76.13", "171.25.193.78",
        "62.102.148.69", "37.120.247.88", "146.70.124.33", "179.43.187.19",
        "195.206.105.217", "209.141.58.146",
    ])
    return {"credential_stuffing": credential_stuffing, "exfiltration": exfiltration}


def zipf_weights(n: int, a: float = 1.15) -> np.ndarray:
    """Pesos de Zipf: poucos IPs concentram a maior parte das requisições."""
    w = 1.0 / np.arange(1, n + 1) ** a
    return w / w.sum()


# --------------------------------------------------------------------------- #
# Geração de tráfego
# --------------------------------------------------------------------------- #
def random_timestamps(rng: np.random.Generator, hours: np.ndarray) -> list[datetime]:
    days = rng.integers(0, WINDOW_DAYS, size=len(hours))
    minutes = rng.integers(0, 60, size=len(hours))
    seconds = rng.integers(0, 60, size=len(hours))
    millis = rng.integers(0, 1000, size=len(hours))
    return [
        WINDOW_START + timedelta(days=int(d), hours=int(h), minutes=int(m),
                                 seconds=int(s), milliseconds=int(ms))
        for d, h, m, s, ms in zip(days, hours, minutes, seconds, millis)
    ]


def generate_normal_traffic(rng: np.random.Generator, n: int, ip_pool: np.ndarray) -> pd.DataFrame:
    hours = rng.choice(np.arange(24), size=n, p=NORMAL_HOUR_WEIGHTS)
    endpoints = rng.choice(ENDPOINTS, size=n, p=[0.30, 0.25, 0.45])

    # Requisições por minuto: 5 a 40, assimétrica (maioria dos clientes faz poucas chamadas)
    rpm = np.clip(np.round(5 + rng.gamma(shape=2.2, scale=6.0, size=n)), 5, 40).astype(int)

    # Bytes transferidos moderados, dependentes do endpoint
    base_bytes = {"/api/v1/login": 1_400, "/api/v1/pix": 3_200, "/api/v1/saldo": 2_400}
    bytes_tx = np.array([
        int(rng.lognormal(mean=np.log(base_bytes[e]), sigma=0.35)) for e in endpoints
    ])

    # Taxa de erro baixa (< 0.05): senhas digitadas errado, timeouts esporádicos
    error_rate = np.clip(rng.beta(a=1.2, b=60, size=n), 0.0, 0.049).round(4)

    # Outliers LEGÍTIMOS (tornam o problema realista e geram falsos positivos):
    #  - exportação de extratos/comprovantes em lote (payloads maiores, 15-120 KB)
    export = (rng.random(n) < 0.03) & (endpoints != "/api/v1/login")
    bytes_tx = np.where(export, rng.integers(15_000, 120_000, size=n), bytes_tx)

    # Latência: leve aumento em horário de pico
    peak = ((hours >= 10) & (hours <= 17)).astype(float)
    latency = np.clip(rng.normal(loc=110 + 35 * peak, scale=30, size=n), 25, 450)
    #  - degradação pontual de backend (cold start de Lambda, lock no core banking)
    degraded = rng.random(n) < 0.02
    latency = np.where(degraded, rng.uniform(600, 2_500, size=n), latency).round(1)

    return pd.DataFrame({
        "timestamp": random_timestamps(rng, hours),
        "source_ip": rng.choice(ip_pool, size=n),
        "endpoint": endpoints,
        "hour_of_day": hours,
        "requests_per_min": rpm,
        "bytes_transferred": bytes_tx,
        "error_rate_4xx_5xx": error_rate,
        "latency_ms": latency,
        "is_attack_ground_truth": 0,
    })


def attack_hours(rng: np.random.Generator, n: int, night_ratio: float = 0.88) -> np.ndarray:
    """Ataques concentrados na madrugada (01h-05h), com parte residual diurna
    (atacantes 'low and slow' tentando se misturar ao tráfego comercial)."""
    is_night = rng.random(n) < night_ratio
    night = rng.choice(ATTACK_NIGHT_HOURS, size=n, p=[0.16, 0.24, 0.26, 0.21, 0.13])
    other = rng.choice(np.setdiff1d(np.arange(24), ATTACK_NIGHT_HOURS), size=n)
    return np.where(is_night, night, other)


def generate_credential_stuffing(rng: np.random.Generator, n: int, ips: np.ndarray) -> pd.DataFrame:
    hours = attack_hours(rng, n)
    return pd.DataFrame({
        "timestamp": random_timestamps(rng, hours),
        "source_ip": rng.choice(ips, size=n, p=zipf_weights(len(ips))),
        "endpoint": "/api/v1/login",
        "hour_of_day": hours,
        "requests_per_min": rng.integers(150, 501, size=n),
        # Respostas de login são pequenas (401 Unauthorized / 429 / 403)
        "bytes_transferred": rng.integers(380, 1_600, size=n),
        "error_rate_4xx_5xx": rng.uniform(0.71, 0.99, size=n).round(4),
        # Backend de autenticação sob estresse (hash de senha / IdP)
        "latency_ms": rng.normal(loc=520, scale=140, size=n).clip(180, 1_400).round(1),
        "is_attack_ground_truth": 1,
    })


def generate_exfiltration(rng: np.random.Generator, n: int, ips: np.ndarray) -> pd.DataFrame:
    hours = attack_hours(rng, n)
    endpoints = rng.choice(["/api/v1/saldo", "/api/v1/pix"], size=n, p=[0.6, 0.4])
    return pd.DataFrame({
        "timestamp": random_timestamps(rng, hours),
        "source_ip": rng.choice(ips, size=n, p=zipf_weights(len(ips))),
        "endpoint": endpoints,
        "hour_of_day": hours,
        # Alta frequência de chamadas (scraping automatizado / BOLA enumeration)
        "requests_per_min": rng.integers(70, 320, size=n),
        # Alto volume de dados extraídos (dezenas de KB a alguns MB por janela)
        "bytes_transferred": rng.lognormal(mean=np.log(350_000), sigma=0.9, size=n).astype(int),
        # Token válido (roubado) -> erros moderados (403 em IDs de terceiros, 429)
        "error_rate_4xx_5xx": rng.uniform(0.08, 0.40, size=n).round(4),
        "latency_ms": rng.normal(loc=780, scale=220, size=n).clip(250, 2_200).round(1),
        "is_attack_ground_truth": 1,
    })


# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description="Gera logs sintéticos de API Gateway/WAF.")
    parser.add_argument("--rows", type=int, default=5_000)
    parser.add_argument("--attack-ratio", type=float, default=0.07)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)

    n_attack = int(round(args.rows * args.attack_ratio))
    n_normal = args.rows - n_attack
    n_cred = int(round(n_attack * 0.55))
    n_exfil = n_attack - n_cred

    legit_ips = build_legit_ip_pool(rng)
    attacker_ips = build_attacker_ip_pool()

    df = pd.concat([
        generate_normal_traffic(rng, n_normal, legit_ips),
        generate_credential_stuffing(rng, n_cred, attacker_ips["credential_stuffing"]),
        generate_exfiltration(rng, n_exfil, attacker_ips["exfiltration"]),
    ], ignore_index=True)

    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3] + "Z"
    df["bytes_transferred"] = df["bytes_transferred"].astype(int)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    # ---------------------------- Resumo -------------------------------- #
    print("=" * 72)
    print(" [1/4] GERAÇÃO DE LOGS SINTÉTICOS - API GATEWAY / WAF")
    print("=" * 72)
    print(f" Arquivo gerado      : {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print(f" Total de requisições: {len(df):,}")
    print(f" Tráfego legítimo    : {n_normal:,} ({n_normal / len(df):.1%})")
    print(f" Tráfego malicioso   : {n_attack:,} ({n_attack / len(df):.1%})")
    print(f"   - Credential Stuffing/Brute Force (/login)  : {n_cred}")
    print(f"   - Exfiltração/Scraping (/saldo, /pix)        : {n_exfil}")
    night = df[df["hour_of_day"].between(1, 5)]
    print(f" Ataques na madrugada (01h-05h): "
          f"{night['is_attack_ground_truth'].sum()} de {n_attack} "
          f"({night['is_attack_ground_truth'].sum() / n_attack:.1%})")
    print(f" IPs únicos          : {df['source_ip'].nunique():,}")
    print("-" * 72)
    print(" Estatísticas por classe (média):")
    stats = df.groupby("is_attack_ground_truth")[[
        "requests_per_min", "bytes_transferred", "error_rate_4xx_5xx", "latency_ms"
    ]].mean().round(2)
    stats.index = ["Normal", "Ataque"]
    print(stats.to_string())
    print("-" * 72)
    print(" Amostra:")
    print(df.head(5).to_string(index=False))
    print("=" * 72)


if __name__ == "__main__":
    main()
