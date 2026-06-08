"""
CI/CD Integration — VulnScanner v6
Gera outputs compatíveis com pipelines de CI/CD:
- JUnit XML (GitHub Actions, Jenkins, GitLab CI)
- Exit codes baseados em severidade
- Summaries para GitHub Actions step summary
- Badge SVG de score
"""

import xml.etree.ElementTree as ET
import json
import datetime
from typing import Dict, List


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_junit_xml(report: Dict, fail_on: str = "high") -> str:
    """
    Gera XML no formato JUnit compatível com GitHub Actions,
    GitLab CI, Jenkins e qualquer CI que aceite test reports.

    Args:
        report: Relatório completo do scan
        fail_on: Severidade mínima para marcar como falha
                 ('critical', 'high', 'medium', 'low')
    """
    fail_severities = set()
    sev_levels = ["critical", "high", "medium", "low"]
    fail_idx = sev_levels.index(fail_on) if fail_on in sev_levels else 1
    for i in range(fail_idx + 1):
        fail_severities.add(sev_levels[i])

    url = report.get("url", "unknown")
    scan_id = report.get("scan_id", "unknown")
    score = report.get("score", 0)
    elapsed = report.get("elapsed", 0)
    timestamp = report.get("timestamp", datetime.datetime.utcnow().isoformat())

    # Root element
    testsuites = ET.Element("testsuites")
    testsuites.set("name", "VulnScanner Security Report")
    testsuites.set("time", str(elapsed))

    total_tests = 0
    total_failures = 0
    total_errors = 0

    for mod in report.get("modules", []):
        module_name = mod.get("module", "Unknown")
        findings = [f for f in mod.get("findings", []) if f.get("severity") != "info"]

        if not findings:
            continue

        testsuite = ET.SubElement(testsuites, "testsuite")
        testsuite.set("name", module_name)
        testsuite.set("timestamp", timestamp)
        testsuite.set("time", "0")

        suite_failures = 0
        suite_tests = 0

        for finding in findings:
            sev = finding.get("severity", "info")
            title = finding.get("title", "Unknown finding")
            detail = finding.get("detail", "")
            fix = finding.get("fix", "")
            cvss = finding.get("cvss", "")

            testcase = ET.SubElement(testsuite, "testcase")
            testcase.set("name", title)
            testcase.set("classname", f"vulnscanner.{module_name.lower().replace(' ', '_')}")
            testcase.set("time", "0")

            suite_tests += 1
            total_tests += 1

            is_failure = sev in fail_severities
            if is_failure:
                suite_failures += 1
                total_failures += 1

                failure = ET.SubElement(testcase, "failure")
                failure.set("type", f"SecurityVulnerability.{sev.upper()}")
                failure.set("message", title)

                cvss_str = f"CVSS: {cvss} | " if cvss else ""
                failure.text = (
                    f"Severity: {sev.upper()}\n"
                    f"{cvss_str}"
                    f"Module: {module_name}\n"
                    f"Target: {url}\n"
                    f"Scan ID: {scan_id}\n\n"
                    f"Detail:\n{detail}\n\n"
                    f"Remediation:\n{fix}"
                )

        testsuite.set("tests", str(suite_tests))
        testsuite.set("failures", str(suite_failures))
        testsuite.set("errors", "0")

    testsuites.set("tests", str(total_tests))
    testsuites.set("failures", str(total_failures))
    testsuites.set("errors", str(total_errors))

    # Score como testsuite adicional
    score_suite = ET.SubElement(testsuites, "testsuite")
    score_suite.set("name", "Security Score")
    score_suite.set("tests", "1")
    score_suite.set("failures", "0" if score >= 70 else "1")
    score_suite.set("errors", "0")
    score_tc = ET.SubElement(score_suite, "testcase")
    score_tc.set("name", f"Security Score >= 70 (atual: {score}/100)")
    score_tc.set("classname", "vulnscanner.score")
    if score < 70:
        sf = ET.SubElement(score_tc, "failure")
        sf.set("type", "SecurityScore")
        sf.set("message", f"Score de segurança abaixo do mínimo: {score}/100 (mínimo: 70)")
        sf.text = f"Score atual: {score}/100\nTarget: {url}\nMelhore a postura de segurança para score >= 70."

    return ET.tostring(testsuites, encoding="unicode", xml_declaration=True)


def get_exit_code(report: Dict, fail_on: str = "high") -> int:
    """
    Retorna exit code para uso em CI/CD:
    0 = sem falhas na severidade configurada
    1 = vulnerabilidades encontradas na severidade configurada
    2 = erro no scan
    """
    sev_levels = ["critical", "high", "medium", "low"]
    fail_idx = sev_levels.index(fail_on) if fail_on in sev_levels else 1
    fail_severities = set(sev_levels[:fail_idx + 1])

    counts = report.get("counts", {})
    for sev in fail_severities:
        if counts.get(sev, 0) > 0:
            return 1
    return 0


def generate_github_summary(report: Dict) -> str:
    """
    Gera markdown para GitHub Actions Step Summary.
    Cole em $GITHUB_STEP_SUMMARY para aparecer na aba Summary do workflow.
    """
    url = report.get("url", "")
    score = report.get("score", 0)
    counts = report.get("counts", {})
    scan_id = report.get("scan_id", "")
    elapsed = report.get("elapsed", 0)

    score_emoji = "🟢" if score >= 70 else "🟡" if score >= 40 else "🔴"
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)

    chains = []
    for mod in report.get("modules", []):
        if mod.get("module") == "Attack Chain Engine":
            chains = mod.get("chains", [])
            break

    lines = [
        f"## {score_emoji} VulnScanner — Security Report",
        f"",
        f"| Campo | Valor |",
        f"|---|---|",
        f"| **Target** | `{url}` |",
        f"| **Score** | {score}/100 |",
        f"| **Scan ID** | `{scan_id}` |",
        f"| **Duração** | {elapsed}s |",
        f"",
        f"### Findings por Severidade",
        f"",
        f"| Severidade | Count |",
        f"|---|---|",
        f"| 🔴 Critical | {counts.get('critical', 0)} |",
        f"| 🟠 High | {counts.get('high', 0)} |",
        f"| 🔵 Medium | {counts.get('medium', 0)} |",
        f"| 🟢 Low | {counts.get('low', 0)} |",
        f"",
    ]

    # Top findings
    top = []
    for mod in report.get("modules", []):
        for f in mod.get("findings", []):
            if f.get("severity") in ("critical", "high"):
                top.append((f["severity"], f["title"], mod["module"]))

    top.sort(key=lambda x: 0 if x[0] == "critical" else 1)

    if top:
        lines += [
            f"### ⚠️ Vulnerabilidades Críticas/Altas",
            f"",
        ]
        for sev, title, module in top[:10]:
            emoji = "🔴" if sev == "critical" else "🟠"
            lines.append(f"- {emoji} **[{module}]** {title}")
        lines.append("")

    # Attack chains
    if chains:
        crit_chains = [c for c in chains if c.get("severity") == "critical"]
        if crit_chains:
            lines += [
                f"### ⛓ Attack Chains Detectadas",
                f"",
            ]
            for chain in crit_chains[:3]:
                lines.append(f"- 🔴 **{chain['title']}** (CVSS {chain.get('cvss_estimate', 'N/A')})")
            lines.append("")

    if critical > 0 or high > 0:
        lines += [
            f"> ⛔ **Pipeline falhou** — {critical} crítico(s) e {high} alto(s) encontrado(s).",
            f"> Corrija antes de fazer deploy em produção.",
        ]
    else:
        lines += [
            f"> ✅ **Nenhuma vulnerabilidade crítica ou alta detectada.**",
        ]

    return "\n".join(lines)


def generate_score_badge(score: int) -> str:
    """Gera SVG de badge de score (estilo shields.io) para README."""
    if score >= 70:
        color = "#2ED573"
        label_color = "#1a5c38"
    elif score >= 40:
        color = "#FFA502"
        label_color = "#7a4a00"
    else:
        color = "#FF4757"
        label_color = "#7a1a1a"

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="140" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="140" height="20" fill="#555"/>
  <rect rx="3" x="80" width="60" height="20" fill="{color}"/>
  <rect x="80" width="4" height="20" fill="{color}"/>
  <rect rx="3" width="140" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="40" y="15" fill="#010101" fill-opacity=".3">security score</text>
    <text x="40" y="14">security score</text>
    <text x="110" y="15" fill="#010101" fill-opacity=".3">{score}/100</text>
    <text x="110" y="14">{score}/100</text>
  </g>
</svg>"""


def generate_gitlab_ci_yaml() -> str:
    """Gera snippet de .gitlab-ci.yml para integração."""
    return """# VulnScanner — GitLab CI Integration
# Adicione este job ao seu .gitlab-ci.yml

vulnscan:
  stage: test
  image: python:3.12-slim
  variables:
    TARGET_URL: "https://staging.seusite.com"
    VULNSCAN_API_KEY: $VULNSCAN_API_KEY   # Configure como CI/CD Variable
    VULNSCAN_URL: "http://seu-vulnscanner:5000"
    FAIL_ON: "high"                        # critical | high | medium
  script:
    - |
      pip install requests -q
      python3 - << 'EOF'
      import requests, sys, json

      resp = requests.post(
          f"{os.environ['VULNSCAN_URL']}/api/scan",
          json={"url": os.environ['TARGET_URL'], "rate_profile": "normal"},
          headers={"X-API-Key": os.environ['VULNSCAN_API_KEY']},
          timeout=300
      )
      report = resp.json()
      score = report.get('score', 0)
      counts = report.get('counts', {})

      print(f"Score: {score}/100")
      print(f"Critical: {counts.get('critical', 0)}, High: {counts.get('high', 0)}")

      fail_on = os.environ.get('FAIL_ON', 'high')
      fail_map = {'critical': ['critical'], 'high': ['critical','high'],
                  'medium': ['critical','high','medium']}
      for sev in fail_map.get(fail_on, ['critical','high']):
          if counts.get(sev, 0) > 0:
              print(f"FAILED: {counts[sev]} {sev} vulnerability(ies) found")
              sys.exit(1)

      print("PASSED: No blocking vulnerabilities found")
      EOF
  artifacts:
    reports:
      junit: vulnscan-report.xml
    paths:
      - vulnscan-report.xml
    when: always
  allow_failure: false
  only:
    - main
    - staging
"""


def generate_github_actions_yaml() -> str:
    """Gera snippet de GitHub Actions workflow."""
    return """# VulnScanner — GitHub Actions Integration
# Salve em .github/workflows/security-scan.yml

name: Security Scan

on:
  push:
    branches: [main, staging]
  schedule:
    - cron: '0 3 * * 1'  # Toda segunda às 03:00 UTC

jobs:
  vulnscan:
    runs-on: ubuntu-latest
    steps:
      - name: Run VulnScanner
        id: scan
        run: |
          RESPONSE=$(curl -s -X POST "${{ secrets.VULNSCAN_URL }}/api/scan" \\
            -H "X-API-Key: ${{ secrets.VULNSCAN_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{"url": "${{ secrets.TARGET_URL }}", "rate_profile": "normal"}')

          echo "$RESPONSE" > scan_result.json
          SCAN_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

      - name: Download JUnit Report
        run: |
          curl -s "${{ secrets.VULNSCAN_URL }}/api/report/${{ steps.scan.outputs.scan_id }}/junit" \\
            -H "X-API-Key: ${{ secrets.VULNSCAN_API_KEY }}" \\
            -o vulnscan-junit.xml

      - name: Publish Test Results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: vulnscan-junit.xml

      - name: Write Step Summary
        run: |
          curl -s "${{ secrets.VULNSCAN_URL }}/api/report/${{ steps.scan.outputs.scan_id }}/github-summary" \\
            -H "X-API-Key: ${{ secrets.VULNSCAN_API_KEY }}" >> $GITHUB_STEP_SUMMARY

      - name: Check Security Gate
        run: |
          python3 - << 'EOF'
          import json, sys
          with open('scan_result.json') as f:
              report = json.load(f)
          counts = report.get('counts', {})
          if counts.get('critical', 0) > 0 or counts.get('high', 0) > 0:
              print(f"Security gate FAILED")
              sys.exit(1)
          print("Security gate PASSED")
          EOF
"""
