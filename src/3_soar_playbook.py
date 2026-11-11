"""
3_soar_playbook.py
==================
Simulação de um motor de orquestração SOAR para resposta automatizada a
incidentes em APIs financeiras.

Fluxo simulado:
    AWS API Gateway / WAF logs
        -> SIEM (Wazuh / ELK)  : ingestão + regra de correlação com score de IA
        -> Shuffle SOAR        : webhook dispara o playbook
        -> Ações de resposta   : AWS WAF (block / rate limit), IdP (Step-Up MFA),
                                 TheHive (case), Slack/SOC (alerta)

Regras do playbook (por IP agregado):
    * MODERADO -> Rate Limiting no AWS WAF + Step-Up MFA obrigatório no IdP
    * CRÍTICO  -> (atividade na madrugada com alta taxa de erro OU alto volume,
                  ou anomaly_score muito alto)
                  Bloqueio imediato no AWS WAF + Case crítico no TheHive +
                  Alerta para o SOC

Nenhuma chamada de rede é feita: os payloads gerados seguem o formato real das
APIs (Wazuh alert JSON, Shuffle webhook, AWS WAFv2 UpdateIPSet, TheHive 5,
Slack Incoming Webhook) e as respostas são simuladas.

Entrada : data/analyzed_logs.csv
Saídas  : output/soar_actions_payload.json
          output/soar_execution.log

Uso:
    python src/3_soar_playbook.py
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if os.name == "nt":
    os.system("")  # habilita sequências ANSI (cores) no console do Windows

ROOT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT_DIR / "data" / "analyzed_logs.csv"
OUTPUT_DIR = ROOT_DIR / "output"
PAYLOAD_FILE = OUTPUT_DIR / "soar_actions_payload.json"
LOG_FILE = OUTPUT_DIR / "soar_execution.log"

# --------------------------------------------------------------------------- #
# Configuração do playbook
# --------------------------------------------------------------------------- #
PLAYBOOK = {
    "id": "PB-API-ABUSE-001",
    "name": "API Abuse - Credential Stuffing & Data Exfiltration Response",
    "version": "1.3.0",
    "engine": "Shuffle SOAR (simulado)",
}

NIGHT_HOURS = range(0, 6)              # 00h-05h -> janela de madrugada
CRITICAL_ERROR_RATE = 0.70             # alta taxa de erro (brute force)
CRITICAL_RPM = 150                     # alto volume de requisições
CRITICAL_BYTES = 100_000               # alto volume de dados (exfiltração)
CRITICAL_SCORE = 0.68                  # anomaly_score muito alto -> crítico em qualquer horário

ALLOWLIST = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8",       # VPC interna / health checks do ALB
    "172.16.0.0/12",    # rede corporativa
    "192.168.0.0/16",   # scanners de vulnerabilidade autorizados
)]

AWS_REGION = "sa-east-1"
WAF_BLOCK_IPSET = {"Name": "soar-blocklist-critical",
                   "Id": "a1b2c3d4-5678-90ab-cdef-111122223333"}
WAF_RATELIMIT_IPSET = {"Name": "soar-ratelimit-watchlist",
                       "Id": "e5f6a7b8-9012-34cd-ef56-444455556666"}
SHUFFLE_WEBHOOK = "https://shuffle.soc.bank.local/api/v1/hooks/webhook_7f3c2a9e-1d4b-4e8a-9c61-2b5f0e8d7a14"
THEHIVE_URL = "https://thehive.soc.bank.local"
IDP_URL = "https://idp.bank.local"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T0SOC0001/B0SOAR001/XXXXXXXXXXXXXXXXXXXXXXXX"

MITRE = {
    "credential_stuffing": {
        "label": "Credential Stuffing / Brute Force",
        "tactic": ["Credential Access"],
        "technique": ["Brute Force: Credential Stuffing", "Brute Force: Password Guessing"],
        "id": ["T1110.004", "T1110.001"],
        "wazuh_rule_id": "100210",
    },
    "exfiltration": {
        "label": "Data Exfiltration / API Scraping",
        "tactic": ["Collection", "Exfiltration"],
        "technique": ["Automated Collection", "Automated Exfiltration"],
        "id": ["T1119", "T1020"],
        "wazuh_rule_id": "100220",
    },
    "behavioral": {
        "label": "Desvio comportamental (baseline de API)",
        "tactic": ["Discovery"],
        "technique": ["Anomalous API usage"],
        "id": ["N/A"],
        "wazuh_rule_id": "100200",
    },
}


# --------------------------------------------------------------------------- #
# Logging (console colorido + arquivo texto)
# --------------------------------------------------------------------------- #
class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[90m", "INFO": "\033[36m", "WARNING": "\033[33m",
        "ERROR": "\033[31m", "CRITICAL": "\033[1;41;97m",
    }
    COMPONENT_COLORS = {
        "SIEM": "\033[94m", "SHUFFLE": "\033[95m", "AWS-WAF": "\033[91m",
        "IDP-MFA": "\033[93m", "THEHIVE": "\033[33m", "SOC-ALERT": "\033[31m",
        "PLAYBOOK": "\033[92m", "TRIAGE": "\033[96m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        lvl = record.levelname
        comp = getattr(record, "component", "PLAYBOOK")
        msg = msg.replace(f"| {lvl:<8} |", f"| {self.COLORS.get(lvl, '')}{lvl:<8}{self.RESET} |", 1)
        msg = msg.replace(f"[{comp:<9}]", f"[{self.COMPONENT_COLORS.get(comp, '')}{comp:<9}{self.RESET}]", 1)
        return msg


class ComponentFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "component"):
            record.component = "PLAYBOOK"
        return True


def build_logger() -> logging.Logger:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("soar")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fmt = "%(asctime)s.%(msecs)03d | %(levelname)-8s | [%(component)-9s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    # utf-8-sig (BOM) -> acentos corretos também no `Get-Content`/`type` do Windows PowerShell 5
    fh = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8-sig")
    fh.setFormatter(logging.Formatter(fmt, datefmt))
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(ColorFormatter(fmt, datefmt))
    for h in (fh, ch):
        h.addFilter(ComponentFilter())
        logger.addHandler(h)
    return logger


LOG = build_logger()


def log(level: int, component: str, msg: str) -> None:
    LOG.log(level, msg, extra={"component": component})


def banner(text: str) -> None:
    line = "=" * 96
    for t in (line, f" {text}", line):
        log(logging.INFO, "PLAYBOOK", t)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def det_uuid(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(parts)))


def lock_token(seed: str) -> str:
    return str(uuid.UUID(hashlib.md5(seed.encode()).hexdigest()))


def is_allowlisted(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in ALLOWLIST)


# --------------------------------------------------------------------------- #
# Triagem: agregação por IP e classificação
# --------------------------------------------------------------------------- #
def aggregate_by_ip(anomalies: pd.DataFrame) -> pd.DataFrame:
    anomalies = anomalies.assign(
        is_night=anomalies["hour_of_day"].isin(NIGHT_HOURS),
        is_login=anomalies["endpoint"].eq("/api/v1/login"),
    )
    agg = anomalies.groupby("source_ip").agg(
        events=("timestamp", "count"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        night_events=("is_night", "sum"),
        login_events=("is_login", "sum"),
        max_score=("anomaly_score", "max"),
        mean_score=("anomaly_score", "mean"),
        max_rpm=("requests_per_min", "max"),
        mean_rpm=("requests_per_min", "mean"),
        max_error=("error_rate_4xx_5xx", "max"),
        mean_error=("error_rate_4xx_5xx", "mean"),
        total_bytes=("bytes_transferred", "sum"),
        max_bytes=("bytes_transferred", "max"),
        mean_latency=("latency_ms", "mean"),
        endpoints=("endpoint", lambda s: sorted(set(s))),
        hours=("hour_of_day", lambda s: sorted(set(int(h) for h in s))),
    ).reset_index()
    return agg


def classify_attack(row: pd.Series) -> str:
    login_share = row["login_events"] / row["events"]
    if login_share >= 0.5 and row["mean_error"] >= 0.5:
        return "credential_stuffing"
    if row["max_bytes"] >= CRITICAL_BYTES:
        return "exfiltration"
    return "behavioral"


def classify_severity(row: pd.Series) -> tuple[str, list[str]]:
    reasons = []
    night = row["night_events"] > 0
    if night and row["max_error"] >= CRITICAL_ERROR_RATE:
        reasons.append(f"madrugada + taxa de erro {row['max_error']:.0%} >= {CRITICAL_ERROR_RATE:.0%}")
    if night and row["max_rpm"] >= CRITICAL_RPM:
        reasons.append(f"madrugada + {int(row['max_rpm'])} req/min >= {CRITICAL_RPM}")
    if night and row["max_bytes"] >= CRITICAL_BYTES:
        reasons.append(f"madrugada + {row['max_bytes'] / 1000:.0f} kB/req >= {CRITICAL_BYTES / 1000:.0f} kB")
    if row["max_score"] >= CRITICAL_SCORE:
        reasons.append(f"anomaly_score {row['max_score']:.3f} >= {CRITICAL_SCORE}")
    if reasons:
        return "CRITICAL", reasons
    return "MODERATE", [f"anomaly_score {row['max_score']:.3f} acima do limiar do modelo, "
                        f"sem indicadores críticos"]


# --------------------------------------------------------------------------- #
# Construtores de payloads (formatos reais de integração)
# --------------------------------------------------------------------------- #
def wazuh_alert(row: pd.Series, attack: str, severity: str) -> dict:
    m = MITRE[attack]
    return {
        "timestamp": now_iso(),
        "id": f"{int(time.time())}.{int(hashlib.sha1(row['source_ip'].encode()).hexdigest(), 16) % 10_000_000}",
        "rule": {
            "id": m["wazuh_rule_id"],
            "level": 14 if severity == "CRITICAL" else 10,
            "description": f"ML Isolation Forest: {m['label']} detectado em API crítica",
            "firedtimes": int(row["events"]),
            "groups": ["aws_waf", "api_gateway", "ml_anomaly", attack],
            "mitre": {"id": m["id"], "tactic": m["tactic"], "technique": m["technique"]},
            "pci_dss": ["10.6.1", "11.4"],
            "gdpr": ["IV_35.7.d"],
        },
        "agent": {"id": "000", "name": "wazuh-manager-aws"},
        "manager": {"name": "wazuh-manager-aws"},
        "decoder": {"name": "aws-waf"},
        "location": f"aws-s3:waf-logs-{AWS_REGION}",
        "data": {
            "srcip": row["source_ip"],
            "url": row["endpoints"],
            "aws": {"source": "waf", "region": AWS_REGION},
            "ml": {
                "model": "IsolationForest",
                "anomaly_score_max": round(float(row["max_score"]), 4),
                "anomaly_score_mean": round(float(row["mean_score"]), 4),
                "anomalous_events": int(row["events"]),
                "night_events": int(row["night_events"]),
                "max_requests_per_min": int(row["max_rpm"]),
                "max_error_rate_4xx_5xx": round(float(row["max_error"]), 4),
                "total_bytes_transferred": int(row["total_bytes"]),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            },
        },
    }


def shuffle_trigger(alert: dict, incident_id: str) -> dict:
    return {
        "method": "POST",
        "url": SHUFFLE_WEBHOOK,
        "headers": {"Content-Type": "application/json"},
        "body": {"execution_argument": alert, "start": PLAYBOOK["id"], "incident_id": incident_id},
        "simulated_response": {
            "success": True,
            "execution_id": det_uuid("shuffle", incident_id),
            "authorization": det_uuid("auth", incident_id),
        },
    }


def waf_ipset_add(ip: str, ipset: dict, incident_id: str) -> dict:
    return {
        "action": "aws_waf.ip_set.add_address",
        "service": "AWS WAFv2",
        "region": AWS_REGION,
        "ip_set": ipset["Name"],
        "address": f"{ip}/32",
        "status": "SUCCESS",
        "executed_at": now_iso(),
        "simulated_response": {"NextLockToken": lock_token(ip + ipset["Id"] + incident_id)},
    }


def waf_update_ipset_request(ipset: dict, addresses: list[str]) -> dict:
    """Requisição real (consolidada) da API AWS WAFv2 UpdateIPSet.

    UpdateIPSet substitui a lista inteira de endereços, por isso o SOAR envia
    o conjunto completo de IPs a cada execução.
    """
    return {
        "method": "POST",
        "url": f"https://wafv2.{AWS_REGION}.amazonaws.com/",
        "headers": {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSWAF_20190729.UpdateIPSet",
            "Authorization": "AWS4-HMAC-SHA256 Credential=<ASSUMED-ROLE soar-responder>/...",
        },
        "body": {
            "Name": ipset["Name"],
            "Scope": "REGIONAL",
            "Id": ipset["Id"],
            "Description": f"Gerenciado automaticamente por {PLAYBOOK['id']}",
            "Addresses": sorted(addresses),
            "LockToken": lock_token(ipset["Id"]),
        },
        "simulated_response": {"NextLockToken": lock_token(ipset["Id"] + str(len(addresses)))},
    }


def waf_rate_based_rule() -> dict:
    """Regra rate-based do WebACL que referencia a watchlist (aplicada 1x)."""
    return {
        "Name": "soar-rate-limit-suspicious",
        "Priority": 5,
        "Action": {"Block": {"CustomResponse": {"ResponseCode": 429}}},
        "Statement": {
            "RateBasedStatement": {
                "Limit": 100,
                "EvaluationWindowSec": 300,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": {
                    "IPSetReferenceStatement": {
                        "ARN": f"arn:aws:wafv2:{AWS_REGION}:123456789012:regional/ipset/"
                               f"{WAF_RATELIMIT_IPSET['Name']}/{WAF_RATELIMIT_IPSET['Id']}"
                    }
                },
            }
        },
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                             "MetricName": "soar-rate-limit-suspicious"},
    }


def stepup_mfa(ip: str, incident_id: str, score: float) -> dict:
    return {
        "action": "idp.adaptive_auth.require_step_up_mfa",
        "service": "IdP / Adaptive Authentication",
        "status": "SUCCESS",
        "executed_at": now_iso(),
        "request": {
            "method": "POST",
            "url": f"{IDP_URL}/admin/realms/internet-banking/risk-policies/step-up",
            "headers": {"Content-Type": "application/json", "Authorization": "Bearer <SOAR_SERVICE_TOKEN>"},
            "body": {
                "subject": {"type": "source_ip", "value": ip},
                "policy": "REQUIRE_STEP_UP_MFA",
                "allowed_factors": ["FIDO2_WEBAUTHN", "PUSH_APP", "TOTP"],
                "applies_to": ["/api/v1/login", "/api/v1/pix", "/api/v1/saldo"],
                "ttl_seconds": 3600,
                "risk_score": round(score * 100, 1),
                "reason": f"Anomalia comportamental (Isolation Forest) - {incident_id}",
            },
        },
        "simulated_response": {"status": 201, "policy_id": det_uuid("mfa", ip)},
    }


def thehive_case(row: pd.Series, attack: str, incident_id: str, reasons: list[str]) -> dict:
    m = MITRE[attack]
    ip = row["source_ip"]
    description = (
        f"### Incidente {incident_id}\n"
        f"**Origem:** `{ip}`  \n**Classificação:** {m['label']}  \n"
        f"**MITRE ATT&CK:** {', '.join(m['id'])}  \n"
        f"**Endpoints afetados:** {', '.join(row['endpoints'])}  \n"
        f"**Janela:** {row['first_seen']} -> {row['last_seen']}  \n"
        f"**Eventos anômalos:** {int(row['events'])} ({int(row['night_events'])} na madrugada)  \n"
        f"**Pico:** {int(row['max_rpm'])} req/min | erro máx. {row['max_error']:.0%} | "
        f"{row['total_bytes'] / 1_048_576:.2f} MB transferidos  \n"
        f"**Critérios de criticidade:** {'; '.join(reasons)}  \n\n"
        f"Contenção automática executada: IP bloqueado no AWS WAF ({WAF_BLOCK_IPSET['Name']})."
    )
    case_number = int(hashlib.sha1(ip.encode()).hexdigest(), 16) % 9000 + 1000
    return {
        "action": "thehive.case.create",
        "service": "TheHive 5",
        "status": "SUCCESS",
        "executed_at": now_iso(),
        "request": {
            "method": "POST",
            "url": f"{THEHIVE_URL}/api/v1/case",
            "headers": {"Content-Type": "application/json", "Authorization": "Bearer <THEHIVE_API_KEY>"},
            "body": {
                "title": f"[CRÍTICO][{incident_id}] {m['label']} - {ip}",
                "description": description,
                "severity": 4,          # 1=Low 2=Medium 3=High 4=Critical
                "tlp": 2,               # AMBER
                "pap": 2,               # AMBER
                "flag": True,
                "tags": ["soar:auto", "source:wazuh", "ml:isolation-forest", f"attack:{attack}",
                         *[f"mitre:{t}" for t in m["id"]], "asset:api-gateway", "bacen:4893"],
                "tasks": [
                    {"title": "Validar bloqueio no AWS WAF e monitorar evasão (rotação de IP)", "group": "Contenção"},
                    {"title": "Identificar contas-alvo e forçar reset de credenciais", "group": "Erradicação"},
                    {"title": "Avaliar exposição de dados (LGPD art. 48) e acionar DPO se necessário", "group": "Compliance"},
                    {"title": "Enriquecer IOC (AbuseIPDB, VirusTotal, MISP)", "group": "Investigação"},
                ],
                "customFields": {"anomaly-score": {"float": round(float(row["max_score"]), 4)},
                                 "playbook": {"string": PLAYBOOK["id"]}},
            },
        },
        "follow_up_request": {
            "method": "POST",
            "url": f"{THEHIVE_URL}/api/v1/case/~{case_number}/observable",
            "body": {"dataType": "ip", "data": ip, "ioc": True, "sighted": True, "tlp": 2,
                     "tags": ["blocked:aws-waf"], "message": "IP de origem do ataque"},
        },
        "simulated_response": {"status": 201, "_id": f"~{case_number}", "number": case_number,
                               "status_case": "New", "stage": "New"},
    }


def soc_alert(row: pd.Series, attack: str, incident_id: str, case_ref: str) -> dict:
    m = MITRE[attack]
    ip = row["source_ip"]
    return {
        "action": "soc.notify.slack",
        "service": "Slack Incoming Webhook (#soc-critical)",
        "status": "SUCCESS",
        "executed_at": now_iso(),
        "request": {
            "method": "POST",
            "url": SLACK_WEBHOOK,
            "headers": {"Content-Type": "application/json"},
            "body": {
                "text": f":rotating_light: CRÍTICO {incident_id}: {m['label']} de {ip} - IP bloqueado no WAF",
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text",
                                                "text": f"Incidente Crítico {incident_id}"}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*IP:*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Ataque:*\n{m['label']}"},
                        {"type": "mrkdwn", "text": f"*Anomaly score:*\n{row['max_score']:.3f}"},
                        {"type": "mrkdwn", "text": f"*Eventos:*\n{int(row['events'])}"},
                        {"type": "mrkdwn", "text": f"*Endpoints:*\n{', '.join(row['endpoints'])}"},
                        {"type": "mrkdwn", "text": f"*TheHive:*\n{case_ref}"},
                    ]},
                    {"type": "context", "elements": [{"type": "mrkdwn",
                        "text": f"Ação automática: AWS WAF BLOCK | Playbook {PLAYBOOK['id']}"}]},
                ],
            },
        },
        "simulated_response": {"status": 200, "body": "ok"},
    }


# --------------------------------------------------------------------------- #
# Motor do playbook
# --------------------------------------------------------------------------- #
def main() -> None:
    t0 = time.perf_counter()
    if not INPUT_FILE.exists():
        sys.exit(f"[ERRO] {INPUT_FILE} não encontrado. Execute src/2_anomaly_detection.py primeiro.")

    df = pd.read_csv(INPUT_FILE)
    anomalies = df[df["anomaly_pred"] == -1].copy()
    run_id = det_uuid("run", now_iso())
    execution_date = datetime.now().strftime("%Y%m%d")

    banner(f"SOAR ENGINE | {PLAYBOOK['name']} | {PLAYBOOK['id']} v{PLAYBOOK['version']}")
    log(logging.INFO, "PLAYBOOK", f"Execução {run_id} iniciada | engine: {PLAYBOOK['engine']}")
    log(logging.INFO, "SIEM", f"Wazuh/ELK: {len(df):,} eventos de API Gateway/WAF indexados "
                              f"(index: aws-waf-logs-*)")
    log(logging.INFO, "SIEM", f"Regra de correlação ML (Isolation Forest): {len(anomalies):,} eventos "
                              f"com anomaly_pred = -1")

    agg = aggregate_by_ip(anomalies)
    log(logging.INFO, "TRIAGE", f"Agrupamento por source_ip: {len(agg)} IPs suspeitos únicos")

    allow_mask = agg["source_ip"].apply(is_allowlisted)
    for ip in agg.loc[allow_mask, "source_ip"]:
        log(logging.WARNING, "TRIAGE", f"{ip} está na allowlist corporativa -> ignorado (supressão de FP)")
    agg = agg[~allow_mask].copy()

    agg["attack_type"] = agg.apply(classify_attack, axis=1)
    sev = agg.apply(classify_severity, axis=1)
    agg["severity"] = [s for s, _ in sev]
    agg["reasons"] = [r for _, r in sev]
    agg["sev_rank"] = agg["severity"].map({"CRITICAL": 0, "MODERATE": 1})
    agg = agg.sort_values(["sev_rank", "max_score"], ascending=[True, False]).reset_index(drop=True)

    n_crit = int((agg["severity"] == "CRITICAL").sum())
    n_mod = int((agg["severity"] == "MODERATE").sum())
    log(logging.INFO, "TRIAGE", f"Classificação: {n_crit} CRÍTICOS | {n_mod} MODERADOS")
    log(logging.INFO, "PLAYBOOK", "-" * 84)

    incidents, blocked, watchlist = [], [], []
    counters = {"waf_block": 0, "waf_rate_limit": 0, "step_up_mfa": 0,
                "thehive_cases": 0, "soc_alerts": 0}

    for i, row in agg.iterrows():
        ip, attack, severity = row["source_ip"], row["attack_type"], row["severity"]
        incident_id = f"INC-{execution_date}-{i + 1:04d}"
        label = MITRE[attack]["label"]

        alert = wazuh_alert(row, attack, severity)
        trigger = shuffle_trigger(alert, incident_id)
        log(logging.INFO, "SIEM", f"{incident_id} | Wazuh rule {alert['rule']['id']} "
                                  f"(level {alert['rule']['level']}) | srcip={ip} | {label}")
        log(logging.INFO, "SHUFFLE", f"{incident_id} | Webhook recebido -> execução "
                                     f"{trigger['simulated_response']['execution_id'][:8]} | "
                                     f"score={row['max_score']:.3f} eventos={int(row['events'])}")

        actions = []
        if severity == "CRITICAL":
            log(logging.CRITICAL, "PLAYBOOK", f"{incident_id} | SEVERIDADE CRÍTICA | "
                                              f"{'; '.join(row['reasons'])}")
            actions.append(waf_ipset_add(ip, WAF_BLOCK_IPSET, incident_id))
            blocked.append(f"{ip}/32")
            counters["waf_block"] += 1
            log(logging.ERROR, "AWS-WAF", f"{incident_id} | BLOCK {ip}/32 -> IPSet "
                                          f"'{WAF_BLOCK_IPSET['Name']}' ({AWS_REGION}) | HTTP 200")

            case = thehive_case(row, attack, incident_id, row["reasons"])
            actions.append(case)
            counters["thehive_cases"] += 1
            case_ref = f"Case #{case['simulated_response']['number']}"
            log(logging.WARNING, "THEHIVE", f"{incident_id} | {case_ref} criado | severity=CRITICAL(4) "
                                            f"TLP:AMBER | MITRE {', '.join(MITRE[attack]['id'])}")

            actions.append(soc_alert(row, attack, incident_id, case_ref))
            counters["soc_alerts"] += 1
            log(logging.WARNING, "SOC-ALERT", f"{incident_id} | Alerta enviado ao #soc-critical "
                                              f"(Slack) | plantonista acionado")
        else:
            log(logging.WARNING, "PLAYBOOK", f"{incident_id} | SEVERIDADE MODERADA | "
                                             f"{'; '.join(row['reasons'])}")
            actions.append(waf_ipset_add(ip, WAF_RATELIMIT_IPSET, incident_id))
            watchlist.append(f"{ip}/32")
            counters["waf_rate_limit"] += 1
            log(logging.INFO, "AWS-WAF", f"{incident_id} | RATE LIMIT {ip}/32 -> 100 req/5min "
                                         f"(IPSet '{WAF_RATELIMIT_IPSET['Name']}')")
            actions.append(stepup_mfa(ip, incident_id, float(row["max_score"])))
            counters["step_up_mfa"] += 1
            log(logging.INFO, "IDP-MFA", f"{incident_id} | Step-Up MFA obrigatório para {ip} "
                                         f"(FIDO2/Push/TOTP, TTL 1h)")

        incidents.append({
            "incident_id": incident_id,
            "source_ip": ip,
            "severity": severity,
            "attack_type": attack,
            "attack_label": label,
            "mitre_attack": MITRE[attack]["id"],
            "severity_reasons": row["reasons"],
            "metrics": {
                "anomalous_events": int(row["events"]),
                "night_events": int(row["night_events"]),
                "max_anomaly_score": round(float(row["max_score"]), 4),
                "mean_anomaly_score": round(float(row["mean_score"]), 4),
                "max_requests_per_min": int(row["max_rpm"]),
                "max_error_rate_4xx_5xx": round(float(row["max_error"]), 4),
                "total_bytes_transferred": int(row["total_bytes"]),
                "endpoints": row["endpoints"],
                "hours_of_day": row["hours"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            },
            "siem_alert": alert,
            "soar_trigger": trigger,
            "actions": actions,
        })

    # Requisições consolidadas para o AWS WAF (UpdateIPSet substitui a lista inteira)
    log(logging.INFO, "PLAYBOOK", "-" * 84)
    waf_requests = []
    if blocked:
        waf_requests.append(waf_update_ipset_request(WAF_BLOCK_IPSET, blocked))
        log(logging.ERROR, "AWS-WAF", f"UpdateIPSet '{WAF_BLOCK_IPSET['Name']}' -> "
                                      f"{len(blocked)} endereços bloqueados | HTTP 200")
    if watchlist:
        waf_requests.append(waf_update_ipset_request(WAF_RATELIMIT_IPSET, watchlist))
        log(logging.INFO, "AWS-WAF", f"UpdateIPSet '{WAF_RATELIMIT_IPSET['Name']}' -> "
                                     f"{len(watchlist)} endereços sob rate limiting | HTTP 200")

    elapsed = time.perf_counter() - t0
    total_actions = sum(counters.values())

    # Validação contra ground truth (apenas para fins acadêmicos)
    truth = df.groupby("source_ip")["is_attack_ground_truth"].max()
    blocked_ips = [b.split("/")[0] for b in blocked]
    blocked_true = int(truth.reindex(blocked_ips).fillna(0).sum())
    attacker_ips = int(truth.sum())

    summary = {
        "events_analyzed": int(len(df)),
        "anomalous_events": int(len(anomalies)),
        "suspicious_ips": int(len(agg)),
        "critical_incidents": n_crit,
        "moderate_incidents": n_mod,
        "actions": counters,
        "total_actions": total_actions,
        "playbook_execution_seconds": round(elapsed, 3),
        "validation_ground_truth": {
            "real_attacker_ips": attacker_ips,
            "blocked_ips_that_are_real_attackers": blocked_true,
            "blocked_ips_false_positives": len(blocked_ips) - blocked_true,
            "attacker_ip_coverage_by_block": round(blocked_true / attacker_ips, 4) if attacker_ips else 0.0,
        },
    }

    payload = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "run_id": run_id,
        "playbook": PLAYBOOK,
        "pipeline": ["AWS API Gateway/WAF logs", "SIEM Wazuh/ELK", "ML Isolation Forest",
                     "Shuffle SOAR", "AWS WAF / IdP / TheHive / Slack"],
        "rules": {
            "critical": {
                "condition": "(night_events > 0 AND (max_error_rate >= 0.70 OR max_rpm >= 150 "
                             "OR max_bytes >= 100000)) OR max_anomaly_score >= %.2f" % CRITICAL_SCORE,
                "actions": ["aws_waf.block_ip", "thehive.case.create(severity=4)", "soc.notify.slack"],
            },
            "moderate": {
                "condition": "anomaly_pred == -1 AND NOT critical",
                "actions": ["aws_waf.rate_limit(100 req/5min)", "idp.require_step_up_mfa"],
            },
            "allowlist": [str(n) for n in ALLOWLIST],
        },
        "summary": summary,
        "aws_waf": {
            "web_acl_rate_based_rule": waf_rate_based_rule(),
            "update_ip_set_requests": waf_requests,
        },
        "incidents": incidents,
    }
    PAYLOAD_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                            encoding="utf-8")

    banner("RESUMO DA EXECUÇÃO DO PLAYBOOK SOAR")
    log(logging.INFO, "PLAYBOOK", f"Eventos analisados ............: {len(df):,}")
    log(logging.INFO, "PLAYBOOK", f"Eventos anômalos (IA) ..........: {len(anomalies):,}")
    log(logging.INFO, "PLAYBOOK", f"IPs suspeitos ..................: {len(agg)}")
    log(logging.INFO, "PLAYBOOK", f"Incidentes CRÍTICOS ............: {n_crit}")
    log(logging.INFO, "PLAYBOOK", f"Incidentes MODERADOS ...........: {n_mod}")
    log(logging.INFO, "PLAYBOOK", f"IPs bloqueados no AWS WAF ......: {counters['waf_block']}")
    log(logging.INFO, "PLAYBOOK", f"IPs sob Rate Limiting ..........: {counters['waf_rate_limit']}")
    log(logging.INFO, "PLAYBOOK", f"Step-Up MFA acionado ...........: {counters['step_up_mfa']}")
    log(logging.INFO, "PLAYBOOK", f"Cases críticos no TheHive ......: {counters['thehive_cases']}")
    log(logging.INFO, "PLAYBOOK", f"Alertas enviados ao SOC ........: {counters['soc_alerts']}")
    log(logging.INFO, "PLAYBOOK", f"Total de ações automatizadas ...: {total_actions}")
    log(logging.INFO, "PLAYBOOK", f"Validação: {blocked_true}/{len(blocked_ips)} IPs bloqueados são "
                                  f"atacantes reais | cobertura {summary['validation_ground_truth']['attacker_ip_coverage_by_block']:.0%} "
                                  f"dos {attacker_ips} IPs atacantes")
    log(logging.INFO, "PLAYBOOK", f"Tempo de resposta do playbook ..: {elapsed:.2f}s "
                                  f"(vs. horas em triagem manual)")
    log(logging.INFO, "PLAYBOOK", f"Payloads: {PAYLOAD_FILE.relative_to(ROOT_DIR)} | "
                                  f"Log: {LOG_FILE.relative_to(ROOT_DIR)}")
    log(logging.INFO, "PLAYBOOK", "=" * 96)


if __name__ == "__main__":
    main()
