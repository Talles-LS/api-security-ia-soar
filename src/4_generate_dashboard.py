"""
4_generate_dashboard.py
=======================
Painel visual unificado (dark theme estilo Grafana/Kibana) consolidando a
detecção por IA e a resposta automatizada do SOAR.

Entradas: data/analyzed_logs.csv
          output/soar_actions_payload.json
          output/model_metrics.json (opcional, KPIs do modelo)
Saída   : output/security_dashboard.png (300 DPI)

Uso:
    python src/4_generate_dashboard.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # backend sem interface gráfica (servidores / CI)

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.gridspec import GridSpec
from matplotlib.patches import FancyBboxPatch

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parent.parent
LOGS_FILE = ROOT_DIR / "data" / "analyzed_logs.csv"
PAYLOAD_FILE = ROOT_DIR / "output" / "soar_actions_payload.json"
METRICS_FILE = ROOT_DIR / "output" / "model_metrics.json"
OUTPUT_FILE = ROOT_DIR / "output" / "security_dashboard.png"

# Paleta Grafana
BG = "#111217"
PANEL = "#181b1f"
BORDER = "#2c3235"
GRID = "#2a2e33"
TEXT = "#d8d9da"
MUTED = "#8e8e8e"
GREEN = "#73bf69"
RED = "#f2495c"
ORANGE = "#ff9830"
YELLOW = "#fade2a"
BLUE = "#5794f2"
PURPLE = "#b877d9"
CYAN = "#8ab8ff"


def setup_theme() -> None:
    sns.set_theme(style="darkgrid", rc={
        "figure.facecolor": BG,
        "axes.facecolor": PANEL,
        "axes.edgecolor": BORDER,
        "axes.labelcolor": TEXT,
        "axes.titlecolor": TEXT,
        "axes.titleweight": "bold",
        "axes.titlesize": 13,
        "axes.labelsize": 10.5,
        "grid.color": GRID,
        "grid.linewidth": 0.7,
        "text.color": TEXT,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "legend.facecolor": PANEL,
        "legend.edgecolor": BORDER,
        "legend.labelcolor": TEXT,
        "font.family": "DejaVu Sans",
        "savefig.facecolor": BG,
    })


def panel_title(ax, title: str, subtitle: str) -> None:
    ax.set_title(title, loc="left", pad=26, fontsize=13, fontweight="bold", color=TEXT)
    ax.text(0, 1.025, subtitle, transform=ax.transAxes, fontsize=9.5, color=MUTED, va="bottom")
    for spine in ax.spines.values():
        spine.set_color(BORDER)


def kpi_card(fig, rect, label: str, value: str, color: str, sub: str = "") -> None:
    ax = fig.add_axes(rect)
    ax.set_axis_off()
    ax.add_patch(FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0,rounding_size=0.06",
                                transform=ax.transAxes, facecolor=PANEL, edgecolor=BORDER, lw=1.2))
    ax.add_patch(FancyBboxPatch((0, 0), 0.018, 1, boxstyle="square,pad=0",
                                transform=ax.transAxes, facecolor=color, edgecolor="none"))
    ax.text(0.08, 0.72, label.upper(), fontsize=9, color=MUTED, fontweight="bold", va="center")
    ax.text(0.08, 0.34, value, fontsize=21, color=color, fontweight="bold", va="center")
    if sub:
        ax.text(0.94, 0.72, sub, fontsize=9, color=MUTED, va="center", ha="right")


# --------------------------------------------------------------------------- #
# Painéis
# --------------------------------------------------------------------------- #
def plot_hourly(ax, df: pd.DataFrame) -> None:
    hourly = (df.assign(status=np.where(df["anomaly_pred"] == -1, "Anomalia", "Normal"))
                .groupby(["hour_of_day", "status"]).size().unstack(fill_value=0)
                .reindex(range(24), fill_value=0))
    hours = np.arange(24)

    ax.axvspan(0.5, 5.5, color=RED, alpha=0.08, zorder=0)
    ax.text(3, 215, "JANELA CRÍTICA\n01h - 05h", ha="center",
            va="center", fontsize=9, color=RED, fontweight="bold", alpha=0.95, zorder=5)

    ax.bar(hours - 0.2, hourly["Normal"], width=0.4, color=GREEN, alpha=0.85,
           label="Tráfego normal", zorder=3)
    ax.bar(hours + 0.2, hourly["Anomalia"], width=0.4, color=RED, alpha=0.95,
           label="Anomalias (Isolation Forest)", zorder=3)

    # Linha de taxa de anomalia (eixo secundário)
    rate = hourly["Anomalia"] / hourly.sum(axis=1).replace(0, np.nan) * 100
    ax2 = ax.twinx()
    ax2.plot(hours, rate.fillna(0), color=YELLOW, lw=2, marker="o", ms=4,
             label="% anômalo na hora", zorder=4)
    ax2.set_ylabel("% de requisições anômalas", color=YELLOW)
    ax2.tick_params(axis="y", colors=YELLOW)
    ax2.set_ylim(0, 105)
    ax2.grid(False)
    for s in ax2.spines.values():
        s.set_color(BORDER)

    ax.set_xticks(hours)
    ax.set_xticklabels([f"{h:02d}h" for h in hours], fontsize=8)
    ax.set_xlim(-0.7, 23.7)
    ax.set_xlabel("Hora do dia")
    ax.set_ylabel("Requisições")
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper right", fontsize=8.5, framealpha=0.9)
    panel_title(ax, "1. Distribuição de Tráfego por Hora do Dia",
                "Normal vs. Anomalias detectadas — pico de ataques na madrugada")


def plot_scatter(ax, df: pd.DataFrame) -> None:
    data = df.assign(Classe=np.where(df["anomaly_pred"] == -1, "Anomalia", "Normal"))
    data = data.sort_values("Classe", ascending=False)  # anomalias por cima
    ax.axhspan(0.70, 1.02, xmin=0, xmax=1, color=RED, alpha=0.06, zorder=0)
    ax.axvline(150, color=ORANGE, ls="--", lw=1.1, alpha=0.8, zorder=1)
    ax.axhline(0.70, color=ORANGE, ls="--", lw=1.1, alpha=0.8, zorder=1)
    ax.text(505, 0.665, "Credential Stuffing / Brute Force (/login)  \u2191", ha="right", va="top",
            fontsize=8.5, color=RED, fontweight="bold")
    ax.text(335, 0.30, "\u2190 Exfiltração / Scraping\n    (/saldo, /pix)", ha="left", va="top",
            fontsize=8.5, color=ORANGE, fontweight="bold")
    ax.text(146, 0.55, "150 req/min", fontsize=8, color=ORANGE, rotation=90, va="center", ha="right")
    ax.text(8, 0.715, "erro 70%", fontsize=8, color=ORANGE, va="bottom")

    sns.scatterplot(
        data=data, x="requests_per_min", y="error_rate_4xx_5xx", hue="Classe",
        palette={"Normal": GREEN, "Anomalia": RED}, size="Classe",
        sizes={"Normal": 14, "Anomalia": 34}, alpha=0.7, edgecolor="none", ax=ax, zorder=3,
    )
    ax.set_xlim(0, 520)
    ax.set_ylim(-0.02, 1.02)
    ax.set_xlabel("Requisições por minuto")
    ax.set_ylabel("Taxa de erro HTTP 4xx/5xx")
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
    handles, labels = ax.get_legend_handles_labels()
    keep = [(h, l) for h, l in zip(handles, labels) if l in ("Normal", "Anomalia")]
    ax.legend([h for h, _ in keep], ["Normal (predito)", "Anomalia (Isolation Forest)"],
              loc="lower right", fontsize=8.5, markerscale=1.4, framealpha=0.9)
    panel_title(ax, "2. Requests/min vs. Taxa de Erro 4xx/5xx",
                "Separação comportamental aprendida sem rótulos (não supervisionado)")


def plot_top_ips(ax, payload: dict) -> None:
    blocked = [i for i in payload["incidents"] if i["severity"] == "CRITICAL"]
    top = sorted(blocked, key=lambda i: i["metrics"]["anomalous_events"], reverse=True)[:10]
    if not top:
        ax.text(0.5, 0.5, "Nenhum IP bloqueado", ha="center", va="center", color=MUTED)
        return
    data = pd.DataFrame({
        "ip": [i["source_ip"] for i in top],
        "events": [i["metrics"]["anomalous_events"] for i in top],
        "score": [i["metrics"]["max_anomaly_score"] for i in top],
        "type": ["Brute Force" if i["attack_type"] == "credential_stuffing" else "Exfiltração"
                 for i in top],
    })
    palette = {"Brute Force": RED, "Exfiltração": ORANGE}
    sns.barplot(data=data, y="ip", x="events", hue="type", palette=palette, dodge=False,
                ax=ax, zorder=3, edgecolor="none", saturation=1)
    xmax = data["events"].max()
    for y, (ev, sc) in enumerate(zip(data["events"], data["score"])):
        ax.text(ev + xmax * 0.015, y, f"{ev} eventos  |  score {sc:.3f}", va="center",
                fontsize=8.5, color=TEXT)
    ax.set_xlim(0, xmax * 1.45)
    ax.set_xlabel("Eventos anômalos detectados")
    ax.set_ylabel("")
    ax.tick_params(axis="y", labelsize=9.5, colors=TEXT)
    for lbl in ax.get_yticklabels():
        lbl.set_fontfamily("DejaVu Sans Mono")
    ax.legend(title="Tipo de ataque", loc="lower right", fontsize=8.5, title_fontsize=8.5,
              framealpha=0.9)
    panel_title(ax, "3. Top 10 IPs Atacantes Bloqueados no AWS WAF",
                "Bloqueio automático pelo playbook SOAR (severidade crítica)")


def plot_actions(ax, payload: dict) -> None:
    a = payload["summary"]["actions"]
    labels = ["IPs bloqueados\nno AWS WAF", "Cases críticos\nno TheHive", "Alertas ao SOC\n(Slack)",
              "Rate Limiting\nno AWS WAF", "Step-Up MFA\nacionado"]
    values = [a["waf_block"], a["thehive_cases"], a["soc_alerts"], a["waf_rate_limit"], a["step_up_mfa"]]
    colors = [RED, ORANGE, YELLOW, BLUE, PURPLE]
    total = sum(values)

    wedges, _ = ax.pie(values, colors=colors, startangle=90, counterclock=False,
                       wedgeprops=dict(width=0.36, edgecolor=PANEL, linewidth=3))
    ax.text(0, 0.1, f"{total}", ha="center", va="center", fontsize=30, fontweight="bold", color=TEXT)
    ax.text(0, -0.17, "ações\nautomatizadas", ha="center", va="center", fontsize=9.5, color=MUTED)
    ax.legend(wedges, [f"{l.replace(chr(10), ' ')}: {v} ({v / total:.0%})"
                       for l, v in zip(labels, values)],
              loc="center left", bbox_to_anchor=(0.98, 0.5), fontsize=9.5, frameon=False,
              labelcolor=TEXT, handlelength=1.2, handleheight=1.2)
    s = payload["summary"]
    ax.text(1.02, 0.08,
            f"Críticos: {s['critical_incidents']}  ->  WAF Block + TheHive + SOC\n"
            f"Moderados: {s['moderate_incidents']}  ->  Rate Limit + Step-Up MFA\n"
            f"Tempo de execução do playbook: {s['playbook_execution_seconds']:.2f}s",
            transform=ax.transAxes, fontsize=8.8, color=MUTED, va="bottom", linespacing=1.6)
    ax.set_aspect("equal")
    panel_title(ax, "4. Ações Automatizadas do Playbook SOAR",
                f"{payload['playbook']['id']} — Wazuh/ELK -> Shuffle -> AWS WAF / IdP / TheHive")


# --------------------------------------------------------------------------- #
def main() -> None:
    for f in (LOGS_FILE, PAYLOAD_FILE):
        if not f.exists():
            sys.exit(f"[ERRO] {f} não encontrado. Execute as etapas 1 a 3 primeiro.")

    df = pd.read_csv(LOGS_FILE)
    payload = json.loads(PAYLOAD_FILE.read_text(encoding="utf-8"))
    metrics = json.loads(METRICS_FILE.read_text(encoding="utf-8")) if METRICS_FILE.exists() else {}

    setup_theme()
    fig = plt.figure(figsize=(20, 12.5))

    # Cabeçalho
    fig.text(0.03, 0.965, "SOC  |  Defesa Proativa de APIs Financeiras", fontsize=21,
             fontweight="bold", color=TEXT)
    fig.text(0.03, 0.94, "IA (Isolation Forest)  +  Big Data (SIEM Wazuh/ELK)  +  Automação SOAR "
                         "(Shuffle -> AWS WAF)   •   /api/v1/login  /api/v1/pix  /api/v1/saldo",
             fontsize=11, color=MUTED)
    fig.text(0.97, 0.965, "LIVE", fontsize=11, color=GREEN, fontweight="bold", ha="right")
    fig.text(0.97, 0.94, f"run {payload['run_id'][:8]}  •  {payload['generated_at'][:19]}Z",
             fontsize=9.5, color=MUTED, ha="right")

    # KPIs
    s = payload["summary"]
    kpis = [
        ("Requisições analisadas", f"{s['events_analyzed']:,}".replace(",", "."), BLUE, "7 dias"),
        ("Anomalias detectadas", f"{s['anomalous_events']}", RED,
         f"{s['anomalous_events'] / s['events_analyzed']:.1%}"),
        ("Precisão / Recall", f"{metrics.get('precision', 0):.1%} / {metrics.get('recall', 0):.1%}"
         if metrics else "-", GREEN, f"AUC {metrics.get('roc_auc', 0):.3f}" if metrics else ""),
        ("IPs bloqueados (WAF)", f"{s['actions']['waf_block']}", ORANGE,
         f"{s['validation_ground_truth']['blocked_ips_that_are_real_attackers']} confirmados"),
        ("Step-Up MFA", f"{s['actions']['step_up_mfa']}", PURPLE, "resposta gradual"),
    ]
    w, gap, x0 = 0.178, 0.0125, 0.03
    for k, (label, value, color, sub) in enumerate(kpis):
        kpi_card(fig, [x0 + k * (w + gap), 0.835, w, 0.075], label, value, color, sub)

    gs = GridSpec(2, 2, figure=fig, left=0.075, right=0.965, top=0.765, bottom=0.075,
                  hspace=0.42, wspace=0.22)
    plot_hourly(fig.add_subplot(gs[0, 0]), df)
    plot_scatter(fig.add_subplot(gs[0, 1]), df)
    plot_top_ips(fig.add_subplot(gs[1, 0]), payload)
    ax4 = fig.add_subplot(gs[1, 1])
    plot_actions(ax4, payload)
    ax4.set_position([ax4.get_position().x0 - 0.04, ax4.get_position().y0,
                      ax4.get_position().width, ax4.get_position().height])

    fig.text(0.5, 0.01, "Dados sintéticos para fins acadêmicos  •  Detecção não supervisionada "
                         "(scikit-learn IsolationForest)  •  Payloads SOAR simulados",
             ha="center", fontsize=8.5, color=MUTED)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT_FILE, dpi=300, facecolor=BG)
    plt.close(fig)

    print("=" * 72)
    print(" [4/4] DASHBOARD DE SEGURANÇA")
    print("=" * 72)
    print(f" Arquivo gerado : {OUTPUT_FILE.relative_to(ROOT_DIR)}")
    print(f" Resolução      : 300 DPI ({int(20 * 300)} x {int(12.5 * 300)} px)")
    print(f" Tamanho        : {OUTPUT_FILE.stat().st_size / 1_048_576:.2f} MB")
    print(" Painéis        : distribuição horária | scatter rpm x erro | "
          "top 10 IPs bloqueados | ações SOAR")
    print("=" * 72)


if __name__ == "__main__":
    main()
