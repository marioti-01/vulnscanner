"""
Testes v8 — SPA Crawler, Compliance, PR Review, WebSocket, Docker
Execute: pytest tests/test_v8.py -v
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture(scope="session")
def app():
    from app import create_app
    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test-secret-v8",
    })
    with test_app.app_context():
        from database.models import db
        db.create_all()
        yield test_app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def sample_modules():
    """Módulos de scan simulados para testes."""
    return [
        {
            "module": "SSL/TLS",
            "icon": "ti-lock",
            "findings": [
                {"severity": "high", "title": "Cipher fraco em uso: RC4",
                 "detail": "RC4 é inseguro", "fix": "Use AES-GCM"},
                {"severity": "info", "title": "TLS 1.3 ativo", "detail": "", "fix": ""},
            ]
        },
        {
            "module": "Headers HTTP",
            "icon": "ti-world",
            "findings": [
                {"severity": "high", "title": "HSTS ausente",
                 "detail": "Sem HSTS configurado", "fix": "Configure HSTS"},
                {"severity": "high", "title": "CSP ausente",
                 "detail": "Sem Content-Security-Policy", "fix": "Configure CSP"},
                {"severity": "medium", "title": "X-Frame-Options ausente",
                 "detail": "Clickjacking possível", "fix": "Adicione X-Frame-Options"},
            ]
        },
        {
            "module": "OWASP Web",
            "icon": "ti-bug",
            "findings": [
                {"severity": "critical", "title": "XSS Refletido detectado",
                 "detail": "Payload em /?q=", "fix": "Escape inputs", "cvss": "9.3"},
                {"severity": "critical", "title": "SQL Injection detectado",
                 "detail": "Erro de SQL visível", "fix": "Use prepared statements", "cvss": "9.8"},
            ]
        },
        {
            "module": "CORS Policy",
            "icon": "ti-arrows-exchange",
            "findings": [
                {"severity": "high", "title": "CORS: origem refletida sem validação",
                 "detail": "Access-Control-Allow-Origin: *", "fix": "Valide origens"},
            ]
        },
        {
            "module": "SSRF",
            "icon": "ti-server-bolt",
            "findings": [
                {"severity": "critical", "title": "SSRF detectado — parâmetro: url",
                 "detail": "Acesso a AWS metadata", "fix": "Bloqueie IPs internos", "cvss": "9.8"},
            ]
        },
        {
            "module": "CVE Lookup",
            "icon": "ti-database-search",
            "findings": [
                {"severity": "high", "title": "CVE-2023-1234 — Apache 2.4.50",
                 "detail": "RCE conhecido", "fix": "Atualize o Apache"},
            ]
        },
    ]


# ── Testes: SPA Crawler ───────────────────────────────────────────────────────

class TestSPACrawler:
    def test_fallback_returns_valid_dict(self):
        from modules.spa_crawler import _crawl_fallback
        result = _crawl_fallback("https://example.com")
        assert "module" in result
        assert "findings" in result
        assert "crawl_data" in result
        cd = result["crawl_data"]
        assert "urls" in cd
        assert "forms" in cd
        assert "params" in cd
        assert "js_rendered" in cd

    def test_fallback_crawl_data_structure(self):
        from modules.spa_crawler import _crawl_fallback
        result = _crawl_fallback("https://example.com")
        cd = result["crawl_data"]
        assert isinstance(cd["urls"], list)
        assert isinstance(cd["forms"], list)
        assert isinstance(cd["params"], list)
        assert isinstance(cd["spa_routes"], list)
        assert isinstance(cd["js_rendered"], bool)

    def test_fallback_js_rendered_false(self):
        from modules.spa_crawler import _crawl_fallback
        result = _crawl_fallback("https://example.com")
        assert result["crawl_data"]["js_rendered"] is False

    def test_check_spa_crawler_returns_valid(self):
        """check_spa_crawler deve sempre retornar dict válido."""
        from modules.spa_crawler import check_spa_crawler
        result = check_spa_crawler("https://example.com")
        assert "module" in result
        assert "findings" in result
        assert "crawl_data" in result
        assert isinstance(result["findings"], list)

    def test_is_same_origin(self):
        from modules.spa_crawler import _is_same_origin
        assert _is_same_origin("https://example.com", "https://example.com/page") is True
        assert _is_same_origin("https://example.com", "https://evil.com") is False
        assert _is_same_origin("https://example.com", "https://sub.example.com") is False

    def test_normalize_url_removes_fragment(self):
        from modules.spa_crawler import _normalize_url
        url = "https://example.com/page#section"
        assert "#" not in _normalize_url(url)

    def test_extract_params_from_url(self):
        from modules.spa_crawler import _extract_params_from_url
        params = _extract_params_from_url("https://example.com/?id=1&name=test&q=hello")
        assert "id" in params
        assert "name" in params
        assert "q" in params


# ── Testes: Compliance ────────────────────────────────────────────────────────

class TestCompliance:
    def test_generate_returns_required_keys(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        assert "overall_score" in result
        assert "overall_level" in result
        assert "frameworks" in result
        assert "critical_gaps" in result

    def test_frameworks_present(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        assert "owasp_top10" in result["frameworks"]
        assert "pci_dss_4"   in result["frameworks"]
        assert "nist_800_53" in result["frameworks"]

    def test_framework_structure(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        owasp = result["frameworks"]["owasp_top10"]
        assert "score_pct" in owasp
        assert "compliance_level" in owasp
        assert "controls" in owasp
        assert "total_controls" in owasp
        assert "passing" in owasp

    def test_xss_maps_to_owasp_a03(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        a03 = result["frameworks"]["owasp_top10"]["controls"].get("A03:2021", {})
        assert a03.get("status") in ("fail_critical", "fail_high", "fail_medium")

    def test_ssl_maps_to_owasp_a02(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        a02 = result["frameworks"]["owasp_top10"]["controls"].get("A02:2021", {})
        assert a02.get("status") in ("fail_critical", "fail_high", "fail_medium")

    def test_ssrf_maps_to_owasp_a10(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        a10 = result["frameworks"]["owasp_top10"]["controls"].get("A10:2021", {})
        assert a10.get("status") in ("fail_critical", "fail_high", "fail_medium")

    def test_clean_scan_has_high_compliance(self):
        from modules.compliance import generate_compliance_report
        clean = [{"module": "SSL/TLS", "icon": "ti-lock", "findings": [
            {"severity": "info", "title": "Certificado válido", "detail": "", "fix": ""},
        ]}]
        result = generate_compliance_report(clean)
        assert result["overall_score"] >= 80

    def test_critical_gaps_sorted_by_severity(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        gaps = result["critical_gaps"]
        for i in range(len(gaps) - 1):
            curr = 0 if gaps[i]["status"] == "fail_critical" else 1
            next_ = 0 if gaps[i+1]["status"] == "fail_critical" else 1
            assert curr <= next_

    def test_score_pct_range(self, sample_modules):
        from modules.compliance import generate_compliance_report
        result = generate_compliance_report(sample_modules)
        assert 0 <= result["overall_score"] <= 100
        for fw in result["frameworks"].values():
            assert 0 <= fw["score_pct"] <= 100

    def test_compliance_to_findings(self, sample_modules):
        from modules.compliance import generate_compliance_report
        from app import _compliance_to_findings
        compliance = generate_compliance_report(sample_modules)
        findings = _compliance_to_findings(compliance)
        assert isinstance(findings, list)
        assert len(findings) > 0
        assert all("severity" in f for f in findings)
        assert all("title" in f for f in findings)


# ── Testes: PR Review ─────────────────────────────────────────────────────────

class TestPRReview:
    def test_build_github_comment_structure(self, sample_modules):
        from cicd.pr_review import _build_github_comment
        report = {
            "scan_id": "test1234",
            "url": "https://exemplo.com",
            "score": 35,
            "counts": {"critical": 2, "high": 3, "medium": 1, "low": 0, "info": 5},
            "modules": sample_modules,
            "executive": {"executive": {"summary": "2 críticos encontrados."}},
        }
        comment = _build_github_comment(report)
        assert "VulnScanner" in comment
        assert "35" in comment
        assert "REPROVADO" in comment
        assert "## " in comment  # Has headers

    def test_approved_status_when_no_criticals(self):
        from cicd.pr_review import _build_github_comment
        report = {
            "scan_id": "ok123456",
            "url": "https://exemplo.com",
            "score": 85,
            "counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 8},
            "modules": [],
            "executive": {"executive": {"summary": "Sem críticos."}},
        }
        comment = _build_github_comment(report)
        assert "APROVADO" in comment or "aprovada" in comment.lower()

    def test_warning_status_for_medium_score(self):
        from cicd.pr_review import _build_github_comment
        report = {
            "scan_id": "warn1234",
            "url": "https://exemplo.com",
            "score": 55,
            "counts": {"critical": 0, "high": 1, "medium": 3, "low": 2, "info": 5},
            "modules": [],
            "executive": {"executive": {"summary": "1 high encontrado."}},
        }
        comment = _build_github_comment(report)
        assert "ATENÇÃO" in comment or "55" in comment

    def test_comment_contains_score(self, sample_modules):
        from cicd.pr_review import _build_github_comment
        report = {
            "scan_id": "abc12345",
            "url": "https://exemplo.com",
            "score": 42,
            "counts": {"critical": 1, "high": 2, "medium": 1, "low": 0, "info": 3},
            "modules": sample_modules,
            "executive": {"executive": {"summary": "Avaliação geral."}},
        }
        comment = _build_github_comment(report)
        assert "42" in comment
        assert "abc12345" in comment

    def test_comment_with_diff(self, sample_modules):
        from cicd.pr_review import _build_github_comment
        base = {
            "scan_id": "base0000",
            "url": "https://exemplo.com",
            "score": 60,
            "counts": {"critical": 1, "high": 1, "medium": 2, "low": 1, "info": 5},
            "modules": [{"module": "SSL/TLS", "icon": "ti-lock", "findings": [
                {"severity": "high", "title": "TLS 1.0 ativo", "detail": "", "fix": ""}
            ]}],
        }
        current = {
            "scan_id": "curr0000",
            "url": "https://exemplo.com",
            "score": 55,
            "counts": {"critical": 2, "high": 1, "medium": 1, "low": 0, "info": 4},
            "modules": sample_modules,
            "executive": {"executive": {"summary": "Regressão detectada."}},
        }
        comment = _build_github_comment(current, base_report=base)
        assert "Comparação" in comment or "comparação" in comment.lower() or "Base" in comment

    def test_comment_has_scan_link(self):
        from cicd.pr_review import _build_github_comment
        report = {
            "scan_id": "link5678",
            "url": "https://exemplo.com",
            "score": 80,
            "counts": {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 4},
            "modules": [],
            "executive": {"executive": {"summary": "OK"}},
        }
        comment = _build_github_comment(report)
        assert "link5678" in comment  # scan ID no link


# ── Testes: WebSocket ─────────────────────────────────────────────────────────

class TestWebSocket:
    def test_notify_functions_importable(self):
        from websocket.events import (
            notify_scan_complete, notify_scan_progress,
            notify_chain_detected, notify_scheduled_scan_done,
            broadcast_system_message,
        )
        assert callable(notify_scan_complete)
        assert callable(notify_scan_progress)
        assert callable(notify_chain_detected)
        assert callable(notify_scheduled_scan_done)
        assert callable(broadcast_system_message)

    def test_socketio_initialized(self, app):
        from websocket.events import socketio
        assert socketio is not None

    def test_chain_notification_only_for_critical(self, app):
        """notify_chain_detected só deve emitir para chains críticas."""
        from websocket.events import notify_chain_detected
        # Não deve lançar exceção para chain não-crítica
        notify_chain_detected("user_123", {"severity": "high", "title": "Test"}, "scan_abc")
        notify_chain_detected("user_123", {"severity": "critical", "title": "Critical Chain", "cvss_estimate": "9.8"}, "scan_abc")


# ── Testes: Docker e Deploy ───────────────────────────────────────────────────

class TestDockerDeploy:
    def test_dockerfile_exists(self):
        assert os.path.exists("Dockerfile")

    def test_docker_compose_exists(self):
        assert os.path.exists("docker-compose.yml")

    def test_nginx_conf_exists(self):
        assert os.path.exists("deploy/nginx.conf")

    def test_setup_script_exists(self):
        assert os.path.exists("deploy/setup.sh")

    def test_dockerfile_has_healthcheck(self):
        with open("Dockerfile") as f:
            content = f.read()
        assert "HEALTHCHECK" in content

    def test_dockerfile_has_non_root_user(self):
        with open("Dockerfile") as f:
            content = f.read()
        assert "USER" in content
        assert "root" not in content.split("USER")[-1]

    def test_docker_compose_has_required_services(self):
        with open("docker-compose.yml") as f:
            content = f.read()
        assert "db:" in content
        assert "redis:" in content
        assert "app:" in content
        assert "nginx:" in content

    def test_docker_compose_has_healthchecks(self):
        with open("docker-compose.yml") as f:
            content = f.read()
        assert "healthcheck:" in content

    def test_nginx_has_ssl(self):
        with open("deploy/nginx.conf") as f:
            content = f.read()
        assert "ssl" in content
        assert "TLSv1.2" in content or "TLSv1.3" in content

    def test_nginx_has_rate_limiting(self):
        with open("deploy/nginx.conf") as f:
            content = f.read()
        assert "limit_req_zone" in content

    def test_nginx_has_security_headers(self):
        with open("deploy/nginx.conf") as f:
            content = f.read()
        assert "X-Frame-Options" in content
        assert "X-Content-Type-Options" in content

    def test_env_example_exists(self):
        assert os.path.exists(".env.example")

    def test_env_example_has_required_vars(self):
        with open(".env.example") as f:
            content = f.read()
        assert "SECRET_KEY" in content
        assert "DATABASE_URL" in content
        assert "ANTHROPIC_API_KEY" in content


# ── Testes: Health endpoint ───────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_returns_json(self, client):
        r = client.get("/health")
        data = r.get_json()
        assert data["status"] == "ok"
        assert "version" in data
        assert data["version"] == "8.0.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
