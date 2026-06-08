"""
PR Review Automático — VulnScanner v8
Comenta automaticamente em Pull Requests do GitHub e GitLab
com o resultado do scan de segurança e diff em relação ao branch base.

Uso no CI:
    from cicd.pr_review import post_github_pr_comment, post_gitlab_mr_comment
"""

import os
import json
import requests
from typing import Dict, Optional


# ── GitHub ────────────────────────────────────────────────────────────────────

def post_github_pr_comment(
    report: Dict,
    repo: str,           # "owner/repo"
    pr_number: int,
    token: str,
    base_report: Optional[Dict] = None,
) -> bool:
    """
    Posta comentário de revisão de segurança num PR do GitHub.

    Args:
        report: Relatório do scan do branch atual
        repo: "owner/repo" (ex: "marioti/meusite")
        pr_number: Número do PR
        token: GitHub token com permissão write:pull_requests
        base_report: Relatório do branch base para diff (opcional)

    Returns:
        True se postado com sucesso
    """
    body = _build_github_comment(report, base_report)

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Deleta comentário anterior do VulnScanner se existir
    _delete_old_github_comment(repo, pr_number, token)

    resp = requests.post(url, json={"body": body}, headers=headers, timeout=15)
    return resp.status_code == 201


def _delete_old_github_comment(repo: str, pr_number: int, token: str):
    """Remove comentário anterior do VulnScanner no PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return
        for comment in resp.json():
            if "VulnScanner" in comment.get("body", "")[:50]:
                del_url = f"https://api.github.com/repos/{repo}/issues/comments/{comment['id']}"
                requests.delete(del_url, headers=headers, timeout=10)
                break
    except Exception:
        pass


def _build_github_comment(report: Dict, base_report: Optional[Dict] = None) -> str:
    """Constrói o corpo do comentário Markdown para GitHub."""
    score   = report.get("score", 0)
    counts  = report.get("counts", {})
    url     = report.get("url", "")
    scan_id = report.get("scan_id", "")
    ex      = report.get("executive", {}).get("executive", {})

    # Score emoji e status
    if score >= 70:
        score_emoji = "🟢"
        status      = "APROVADO"
    elif score >= 40:
        score_emoji = "🟡"
        status      = "ATENÇÃO"
    else:
        score_emoji = "🔴"
        status      = "REPROVADO"

    critical = counts.get("critical", 0)
    high     = counts.get("high", 0)
    medium   = counts.get("medium", 0)

    lines = [
        f"## {score_emoji} VulnScanner — Security Review",
        f"",
        f"> **Status:** `{status}` &nbsp;|&nbsp; **Score:** `{score}/100` &nbsp;|&nbsp; **Scan ID:** `{scan_id}`",
        f"",
        f"| Severidade | Encontrados |",
        f"|:---|:---:|",
        f"| 🔴 Critical | **{critical}** |",
        f"| 🟠 High     | **{high}** |",
        f"| 🔵 Medium   | **{medium}** |",
        f"| 🟢 Low      | **{counts.get('low', 0)}** |",
        f"",
    ]

    # Diff com base se disponível
    if base_report:
        from modules.scan_diff import compare_scans
        diff = compare_scans(base_report, report)
        new_count   = diff["summary"]["new_count"]
        fixed_count = diff["summary"]["fixed_count"]
        delta       = diff["score_delta"]

        lines += [
            f"### 📊 Comparação com base",
            f"",
            f"| | Base | PR | Δ |",
            f"|:---|:---:|:---:|:---:|",
            f"| Score | {base_report.get('score',0)} | {score} | {'+' if delta>=0 else ''}{delta} |",
            f"| Critical | {diff['severity_delta']['critical']['old']} | {diff['severity_delta']['critical']['new']} | {'+' if diff['severity_delta']['critical']['diff']>=0 else ''}{diff['severity_delta']['critical']['diff']} |",
            f"| High | {diff['severity_delta']['high']['old']} | {diff['severity_delta']['high']['new']} | {'+' if diff['severity_delta']['high']['diff']>=0 else ''}{diff['severity_delta']['high']['diff']} |",
            f"",
        ]

        if new_count > 0:
            lines.append(f"⚠️ **{new_count} nova(s) vulnerabilidade(s) introduzida(s) neste PR:**")
            lines.append("")
            for v in diff["new_vulnerabilities"][:5]:
                sev_emoji = {"critical":"🔴","high":"🟠","medium":"🔵","low":"🟢"}.get(v["severity"],"⚪")
                lines.append(f"- {sev_emoji} `{v['severity'].upper()}` **{v['title']}** _{v['module']}_")
            lines.append("")

        if fixed_count > 0:
            lines.append(f"✅ **{fixed_count} vulnerabilidade(s) corrigida(s) neste PR.**")
            lines.append("")

    # Top findings críticos/altos
    top = []
    for mod in report.get("modules", []):
        for f in mod.get("findings", []):
            if f.get("severity") in ("critical", "high"):
                top.append((f["severity"], f["title"], mod.get("module",""), f.get("fix","")))
    top.sort(key=lambda x: 0 if x[0]=="critical" else 1)

    if top:
        lines += [
            f"### ⚠️ Vulnerabilidades que bloqueiam o merge",
            f"",
        ]
        for sev, title, module, fix in top[:8]:
            emoji = "🔴" if sev == "critical" else "🟠"
            lines.append(f"<details>")
            lines.append(f"<summary>{emoji} <strong>[{module}]</strong> {title}</summary>")
            lines.append(f"")
            if fix:
                lines.append(f"**Como corrigir:** {fix}")
            lines.append(f"</details>")
        lines.append("")

    # Attack chains
    for mod in report.get("modules", []):
        if mod.get("module") == "Attack Chain Engine":
            chains = mod.get("chains", [])
            crit_chains = [c for c in chains if c.get("severity") == "critical"]
            if crit_chains:
                lines += [
                    f"### ⛓ Attack Chains Detectadas",
                    f"",
                ]
                for chain in crit_chains[:3]:
                    lines.append(f"<details>")
                    lines.append(f"<summary>🔴 <strong>{chain['title']}</strong> (CVSS {chain.get('cvss_estimate','?')})</summary>")
                    lines.append(f"")
                    lines.append(f"{chain.get('attack_narrative','')}")
                    lines.append(f"")
                    lines.append(f"**Remediação:** {chain.get('unified_fix','')}")
                    lines.append(f"</details>")
                lines.append("")
            break

    # Sumário executivo
    summary = ex.get("summary", "")
    if summary:
        lines += [
            f"### 📋 Avaliação",
            f"",
            f"> {summary}",
            f"",
        ]

    # Gate de qualidade
    if critical > 0 or high > 0:
        lines += [
            f"---",
            f"",
            f"⛔ **Merge bloqueado** — {critical} crítico(s) e {high} alto(s) devem ser corrigidos.",
            f"",
            f"[Ver relatório completo →](https://vulnscanner.local/report/{scan_id})",
            f"",
            f"<sub>🔍 VulnScanner v8 — Use apenas em sistemas autorizados</sub>",
        ]
    else:
        lines += [
            f"---",
            f"",
            f"✅ **Sem bloqueadores críticos.** Revisão de segurança aprovada.",
            f"",
            f"[Ver relatório completo →](https://vulnscanner.local/report/{scan_id})",
            f"",
            f"<sub>🔍 VulnScanner v8 — Use apenas em sistemas autorizados</sub>",
        ]

    return "\n".join(lines)


# ── GitLab ────────────────────────────────────────────────────────────────────

def post_gitlab_mr_comment(
    report: Dict,
    project_id: str,      # ID numérico ou "namespace/project"
    mr_iid: int,          # Internal ID do MR
    token: str,
    gitlab_url: str = "https://gitlab.com",
    base_report: Optional[Dict] = None,
) -> bool:
    """
    Posta nota em Merge Request do GitLab.
    """
    body = _build_github_comment(report, base_report)  # Markdown compatível

    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    headers = {
        "PRIVATE-TOKEN": token,
        "Content-Type": "application/json",
    }

    # Deleta nota anterior
    try:
        list_resp = requests.get(url, headers=headers, timeout=10)
        if list_resp.status_code == 200:
            for note in list_resp.json():
                if "VulnScanner" in note.get("body", "")[:50]:
                    del_url = f"{url}/{note['id']}"
                    requests.delete(del_url, headers=headers, timeout=10)
                    break
    except Exception:
        pass

    resp = requests.post(url, json={"body": body}, headers=headers, timeout=15)
    return resp.status_code == 201


# ── Webhook handler (recebe eventos de CI) ───────────────────────────────────

def handle_github_webhook(payload: Dict, secret: str, report: Dict,
                          token: str) -> bool:
    """
    Processa webhook do GitHub e posta comentário automaticamente.
    Configure o webhook em: Settings → Webhooks → Pull requests.
    """
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return False

    pr      = payload.get("pull_request", {})
    pr_num  = pr.get("number")
    repo    = payload.get("repository", {}).get("full_name", "")

    if not pr_num or not repo:
        return False

    return post_github_pr_comment(report, repo, pr_num, token)


def handle_gitlab_webhook(payload: Dict, report: Dict, token: str,
                          gitlab_url: str = "https://gitlab.com") -> bool:
    """
    Processa webhook do GitLab e posta comentário automaticamente.
    Configure em: Settings → Webhooks → Merge request events.
    """
    object_kind = payload.get("object_kind")
    if object_kind != "merge_request":
        return False

    attrs      = payload.get("object_attributes", {})
    state      = attrs.get("state")
    if state not in ("opened", "updated"):
        return False

    mr_iid     = attrs.get("iid")
    project_id = payload.get("project", {}).get("id")

    if not mr_iid or not project_id:
        return False

    return post_gitlab_mr_comment(report, str(project_id), mr_iid, token, gitlab_url)
