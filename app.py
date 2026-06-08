"""
VulnScanner v8 — App principal
Integra auth, dashboard, multi-tenancy, rate limiting, scheduler,
WebSocket, SPA crawler, PR Review, Compliance e todos os módulos de scan.
"""

import os, json, time, uuid, datetime, queue, threading, concurrent.futures
from flask import Flask, render_template, request, jsonify, Response, stream_with_context, g
from flask_login import current_user

# ── DB e Auth ────────────────────────────────────────────────────────────────
from database.models import db, bcrypt, User, Scan, Project
from auth.middleware import init_auth, require_auth, get_current_user
from auth.routes import auth_bp
from auth.rate_limit import scan_quota_required, register_scan_start, register_scan_end, rate_limited
from auth.tenancy import get_user_scan
from dashboard.routes import dashboard_bp

# ── WebSocket ─────────────────────────────────────────────────────────────────
from websocket.events import init_socketio, notify_scan_complete, notify_chain_detected

# ── Módulos de scan ──────────────────────────────────────────────────────────
from modules.ssl_checker        import check_ssl
from modules.header_checker     import check_headers
from modules.port_scanner       import check_ports
from modules.owasp_checker      import check_owasp
from modules.dns_checker        import check_dns
from modules.cors_checker       import check_cors
from modules.tech_detector      import check_tech
from modules.redirect_checker   import check_redirects
from modules.cve_lookup         import check_cves
from modules.spa_crawler        import check_spa_crawler   # v8: SPA support
from modules.blind_sqli         import check_blind_sqli
from modules.idor_checker       import check_idor
from modules.ssrf_checker       import check_ssrf
from modules.xxe_checker        import check_xxe
from modules.auth_flow          import check_auth_flow
from modules.false_positive_filter import filter_false_positives
from modules.executive_report   import generate_executive_report
from modules.attack_chain_engine import analyze_attack_chains
from modules.circuit_breaker    import safe_run_module
from modules.scan_diff          import compare_scans
from modules.compliance         import generate_compliance_report   # v8: compliance
from plugins.engine             import run_all_plugins
from cicd.integration           import generate_junit_xml, get_exit_code, generate_github_summary

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def create_app():
    app = Flask(__name__)

    # ── Config ───────────────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///vulnscanner.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    # ── Extensões ────────────────────────────────────────────────────────────
    db.init_app(app)
    bcrypt.init_app(app)
    init_auth(app)

    # ── WebSocket ─────────────────────────────────────────────────────────────
    init_socketio(app)

    # ── Blueprints ───────────────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    # ── DB init ──────────────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    # ── Scheduler ────────────────────────────────────────────────────────────
    try:
        from scheduler.manager import init_scheduler
        init_scheduler(app)
    except Exception as e:
        print(f"⚠ Scheduler não iniciado: {e}")

    # ── Health check (dentro do app factory) ─────────────────────────────────
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "version": "8.0.0"}), 200

    return app


# ── Constantes (definidas antes do create_app para uso nos testes) ────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#FF4757", "high": "#FFA502",
    "medium": "#3742FA",   "low": "#2ED573", "info": "#747D8C",
}

BASE_MODULES = [
    {"fn": check_ssl,       "name": "SSL/TLS",           "icon": "ti-lock",            "key": "ssl"},
    {"fn": check_headers,   "name": "Headers HTTP",      "icon": "ti-world",           "key": "headers"},
    {"fn": check_ports,     "name": "Port Scanner",      "icon": "ti-radar",           "key": "ports"},
    {"fn": check_dns,       "name": "DNS / Subdomains",  "icon": "ti-network",         "key": "dns"},
    {"fn": check_cors,      "name": "CORS Policy",       "icon": "ti-arrows-exchange", "key": "cors"},
    {"fn": check_tech,      "name": "Tecnologias / WAF", "icon": "ti-cpu",             "key": "tech"},
    {"fn": check_redirects, "name": "Redirects",         "icon": "ti-arrow-right",     "key": "redirects"},
    {"fn": check_auth_flow, "name": "Auth Flow",         "icon": "ti-login",           "key": "auth_flow"},
]

CRAWLER_MODULES = [
    {"fn": check_owasp,      "name": "OWASP Web",          "icon": "ti-bug",          "key": "owasp"},
    {"fn": check_blind_sqli, "name": "Blind SQL Injection", "icon": "ti-database-x",  "key": "blind_sqli"},
    {"fn": check_idor,       "name": "IDOR",                "icon": "ti-lock-open",   "key": "idor"},
    {"fn": check_ssrf,       "name": "SSRF",                "icon": "ti-server-bolt", "key": "ssrf"},
    {"fn": check_xxe,        "name": "XXE",                 "icon": "ti-file-code",   "key": "xxe"},
]

ALL_MODULE_NAMES = (
    ["SPA Crawler"] +
    [m["name"] for m in BASE_MODULES] +
    [m["name"] for m in CRAWLER_MODULES] +
    ["CVE Lookup", "Attack Chain Engine", "Compliance"]
)


# ── Helpers ───────────────────────────────────────────────────────────────────
def score_findings(results):
    w = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
    return max(0, 100 - sum(w.get(f["severity"], 0) for m in results for f in m.get("findings", [])))


def count_by_severity(results):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for m in results:
        for f in m.get("findings", []):
            c[f.get("severity", "info")] = c.get(f.get("severity", "info"), 0) + 1
    return c


def sort_mod(result):
    result["findings"].sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return result


def _parse_auth(data):
    return {"cookies": data.get("cookies", ""), "auth_headers": data.get("auth_headers", {})}


def _compliance_to_findings(compliance: dict) -> list:
    findings = []
    overall = compliance.get("overall_level", "")
    score   = compliance.get("overall_score", 0)
    color_map = {"Conforme": "low", "Parcialmente Conforme": "medium", "Não Conforme": "high"}
    sev = color_map.get(overall, "medium")
    findings.append({
        "severity": sev,
        "title": f"Compliance geral: {overall} ({score}%)",
        "detail": (
            f"OWASP Top 10 2021: {compliance['frameworks']['owasp_top10']['score_pct']}% | "
            f"PCI DSS 4.0: {compliance['frameworks']['pci_dss_4']['score_pct']}% | "
            f"NIST SP 800-53: {compliance['frameworks']['nist_800_53']['score_pct']}%"
        ),
        "fix": "Corrija as vulnerabilidades listadas para melhorar a conformidade.",
    })
    for gap in compliance.get("critical_gaps", [])[:8]:
        findings.append({
            "severity": "high" if gap["status"] == "fail_critical" else "medium",
            "title": f"[{gap['framework']}] {gap['control']} — {gap['name']}",
            "detail": f"Controle falhando com {len(gap['findings'])} finding(s) relacionado(s).",
            "fix": f"Corrija as vulnerabilidades associadas ao controle {gap['control']}.",
        })
    return findings


def _run_scan(url, auth, rate_profile="normal"):
    """Executa scan completo e retorna lista de resultados de módulos."""
    results = []
    tech_result = None

    cr = safe_run_module(check_spa_crawler, "SPA Crawler", "ti-spider", url, auth=auth)
    results.append(sort_mod(cr))
    crawl_data = cr.get("crawl_data")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(safe_run_module, m["fn"], m["name"], m["icon"], url, auth=auth): m
                   for m in BASE_MODULES}
        for f in concurrent.futures.as_completed(futures):
            m = futures[f]
            try:
                r = sort_mod(f.result())
                results.append(r)
                if m["key"] == "tech":
                    tech_result = r
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {
            ex.submit(safe_run_module, m["fn"], m["name"], m["icon"], url,
                      crawl_data=crawl_data, auth=auth, rate_profile=rate_profile): m
            for m in CRAWLER_MODULES
        }
        for f in concurrent.futures.as_completed(futures):
            try:
                results.append(sort_mod(f.result()))
            except Exception:
                pass

    tech_inner = tech_result.get("tech_data") if tech_result else None
    cve = safe_run_module(check_cves, "CVE Lookup", "ti-database-search", url,
                          tech_data=tech_inner, auth=auth)
    results.append(sort_mod(cve))

    try:
        from auth.middleware import get_current_user as gcu
        user = gcu()
        if user:
            from database.models import Plugin
            plugins = Plugin.query.filter_by(user_id=user.id, is_active=True).all()
            if plugins:
                results.extend(run_all_plugins(plugins, url, auth))
    except Exception:
        pass

    chain = analyze_attack_chains(url, results, use_ai=(rate_profile != "stealth"))
    results.append(chain)

    try:
        compliance = generate_compliance_report(results)
        results.append({
            "module": "Compliance", "icon": "ti-certificate",
            "findings": _compliance_to_findings(compliance),
            "compliance_data": compliance,
        })
    except Exception:
        pass

    return results


def _save_scan(scan_id, url, user, project_id, results, elapsed, rate_profile):
    score  = score_findings(results)
    counts = count_by_severity(results)
    executive = generate_executive_report(
        url=url, scan_id=scan_id, elapsed=elapsed,
        score=score, counts=counts, modules_results=results,
    )
    report = {
        "scan_id": scan_id, "url": url, "elapsed": round(elapsed, 1),
        "score": score, "counts": counts, "modules": results,
        "severity_colors": SEVERITY_COLORS,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "executive": executive,
    }
    scan = Scan(
        scan_id=scan_id, user_id=user.id, project_id=project_id or None,
        url=url, status="done", score=score, elapsed=round(elapsed, 1),
        rate_profile=rate_profile,
        completed_at=datetime.datetime.utcnow(),
        count_critical=counts.get("critical", 0), count_high=counts.get("high", 0),
        count_medium=counts.get("medium", 0),     count_low=counts.get("low", 0),
        count_info=counts.get("info", 0),
    )
    scan.set_report(report)
    db.session.add(scan)
    if project_id:
        proj = Project.query.get(project_id)
        if proj and str(proj.user_id) == str(user.id):
            proj.updated_at = datetime.datetime.utcnow()
    db.session.commit()
    return report, scan


# ── App factory call ──────────────────────────────────────────────────────────
app = create_app()


# ── Admin API ─────────────────────────────────────────────────────────────────
@app.route("/api/admin/users/<user_id>", methods=["PUT"])
@require_auth
def admin_update_user(user_id):
    from auth.middleware import get_current_user as gcu
    current = gcu()
    if current.role != "admin":
        return jsonify({"error": "Acesso negado"}), 403
    from database.models import User
    u = User.query.get_or_404(user_id)
    data = request.get_json()
    if "is_active" in data:
        u.is_active = bool(data["is_active"])
    db.session.commit()
    return jsonify({"success": True})


# ── Scan page ─────────────────────────────────────────────────────────────────
@app.route("/scan-page")
@require_auth
def scan_page():
    user = get_current_user()
    from auth.tenancy import get_user_projects
    projects = get_user_projects()
    return render_template("index.html", user=user, projects=projects,
                           module_names=ALL_MODULE_NAMES)


# ── API: Scan síncrono ───────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@require_auth
@rate_limited
@scan_quota_required
def api_scan():
    data     = request.get_json()
    url      = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL obrigatória"}), 400

    user         = get_current_user()
    auth         = _parse_auth(data)
    rate_profile = data.get("rate_profile", "normal")
    project_id   = data.get("project_id")
    verify_fps   = data.get("verify_false_positives", True)
    scan_id      = str(uuid.uuid4())[:8]
    start        = time.time()

    register_scan_start(user)
    try:
        results = _run_scan(url, auth, rate_profile)
        if verify_fps:
            results, *_ = filter_false_positives(results, auth=auth, rate_profile=rate_profile)
        elapsed = time.time() - start
        report, _ = _save_scan(scan_id, url, user, project_id, results, elapsed, rate_profile)
        return jsonify(report)
    finally:
        register_scan_end(user)


# ── API: Scan SSE (streaming) ─────────────────────────────────────────────────
@app.route("/scan-stream")
@require_auth
def scan_stream():
    url          = request.args.get("url", "").strip()
    rate_profile = request.args.get("rate_profile", "normal")
    verify_fps   = request.args.get("verify_false_positives", "true").lower() == "true"
    project_id   = request.args.get("project_id", "")
    cookies      = request.args.get("cookies", "")
    try:
        auth_headers = json.loads(request.args.get("auth_headers", "{}"))
    except Exception:
        auth_headers = {}

    auth    = {"cookies": cookies, "auth_headers": auth_headers}
    user    = get_current_user()
    scan_id = str(uuid.uuid4())[:8]

    if not url:
        return jsonify({"error": "URL obrigatória"}), 400

    allowed_quota = True
    from auth.rate_limit import check_scan_quota
    ok, reason = check_scan_quota(user)
    if not ok:
        return jsonify({"error": reason}), 429

    def generate():
        results      = []
        tech_result  = None
        eq           = queue.Queue()
        start        = time.time()

        yield f"data: {json.dumps({'event':'scan_start','scan_id':scan_id,'module_names':ALL_MODULE_NAMES})}\n\n"

        def emit(evt): eq.put(evt)

        def drain():
            out = []
            try:
                while True: out.append(eq.get_nowait())
            except queue.Empty: pass
            return out

        def run_mod(fn, name, icon, *a, **kw):
            emit({"event":"module_start","module":name})
            r = safe_run_module(fn, name, icon, *a, **kw)
            r = sort_mod(r)
            crits = sum(1 for f in r["findings"] if f["severity"]=="critical")
            highs = sum(1 for f in r["findings"] if f["severity"]=="high")
            emit({"event":"module_done","module":name,
                  "findings_count":len(r["findings"]),"critical":crits,"high":highs,"medium":0})
            return r

        # Crawler
        cr = run_mod(check_spa_crawler, "SPA Crawler", "ti-spider", url, auth=auth)
        results.append(cr)
        crawl_data = cr.get("crawl_data")
        for e in drain(): yield f"data: {json.dumps(e)}\n\n"

        # Base
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(run_mod, m["fn"], m["name"], m["icon"], url, auth=auth): m
                    for m in BASE_MODULES}
            while futs:
                done, _ = concurrent.futures.wait(futs, timeout=0.3,
                                                   return_when=concurrent.futures.FIRST_COMPLETED)
                for f in done:
                    m = futs.pop(f)
                    try:
                        r = f.result()
                        results.append(r)
                        if m["key"] == "tech": tech_result = r
                    except Exception: pass
                for e in drain(): yield f"data: {json.dumps(e)}\n\n"

        # Crawler-dependent
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(run_mod, m["fn"], m["name"], m["icon"], url,
                              crawl_data=crawl_data, auth=auth, rate_profile=rate_profile): m
                    for m in CRAWLER_MODULES}
            while futs:
                done, _ = concurrent.futures.wait(futs, timeout=0.3,
                                                   return_when=concurrent.futures.FIRST_COMPLETED)
                for f in done:
                    futs.pop(f)
                    try: results.append(f.result())
                    except Exception: pass
                for e in drain(): yield f"data: {json.dumps(e)}\n\n"

        # CVE
        tech_inner = tech_result.get("tech_data") if tech_result else None
        cve = run_mod(check_cves, "CVE Lookup", "ti-database-search", url,
                      tech_data=tech_inner, auth=auth)
        results.append(cve)
        for e in drain(): yield f"data: {json.dumps(e)}\n\n"

        # FP filter
        recheck_log, fp_count, confirmed_count = [], 0, 0
        if verify_fps:
            yield f"data: {json.dumps({'event':'module_start','module':'Verificação de Falsos Positivos'})}\n\n"
            results, recheck_log, confirmed_count, fp_count = filter_false_positives(
                results, auth=auth, rate_profile=rate_profile)
            yield f"data: {json.dumps({'event':'module_done','module':'Verificação de Falsos Positivos','findings_count':confirmed_count+fp_count,'critical':0,'high':0,'medium':0})}\n\n"

        # Attack Chains
        yield f"data: {json.dumps({'event':'module_start','module':'Attack Chain Engine'})}\n\n"
        chain = analyze_attack_chains(url, results, use_ai=(rate_profile != "stealth"))
        results.append(chain)
        crits = sum(1 for c in chain.get("chains",[]) if c.get("severity")=="critical")
        yield f"data: {json.dumps({'event':'module_done','module':'Attack Chain Engine','findings_count':chain.get('chains_count',0),'critical':crits,'high':0,'medium':0,'ai_analysis':chain.get('ai_analysis',False)})}\n\n"

        # Salva no DB
        elapsed = time.time() - start
        with app.app_context():
            report, _ = _save_scan(scan_id, url, user, project_id or None,
                                   results, elapsed, rate_profile)

        yield f"data: {json.dumps({'event':'scan_complete','scan_id':scan_id,'score':report['score'],'elapsed':round(elapsed,1),'counts':report['counts'],'url':url,'timestamp':report['timestamp']})}\n\n"
        register_scan_end(user)

    register_scan_start(user)
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"},
    )


# ── Redirect raiz ────────────────────────────────────────────────────────────
@app.route("/index")
def root_index():
    from flask_login import current_user
    if current_user.is_authenticated:
        return app.redirect("/")
    return app.redirect("/auth/login")


# ── API: histórico global ─────────────────────────────────────────────────────
@app.route("/api/history")
@require_auth
def api_history():
    from auth.tenancy import get_user_scans
    scans = get_user_scans(limit=50)
    return jsonify([s.to_dict() for s in scans])


# ── Swagger / OpenAPI ─────────────────────────────────────────────────────────
try:
    from flasgger import Swagger
    swagger_config = {
        "headers": [],
        "specs": [{"endpoint": "apispec", "route": "/api/spec.json"}],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs",
    }
    swagger_template = {
        "info": {
            "title": "VulnScanner API",
            "description": "API de segurança web com Attack Chain Engine",
            "version": "7.0.0",
        },
        "securityDefinitions": {
            "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
        },
    }
    Swagger(app, config=swagger_config, template=swagger_template)
except ImportError:
    pass

# ── PR Review webhooks ────────────────────────────────────────────────────────
@app.route("/api/webhooks/github", methods=["POST"])
def webhook_github():
    """Recebe webhook do GitHub e posta comentário no PR."""
    import hmac, hashlib
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if secret:
        sig = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            secret.encode(), request.data, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return jsonify({"error": "Assinatura inválida"}), 401

    payload   = request.get_json()
    token     = request.headers.get("X-GitHub-Token", os.getenv("GITHUB_TOKEN", ""))
    scan_url  = request.args.get("url", "")

    if not scan_url or not token:
        return jsonify({"error": "url e X-GitHub-Token são obrigatórios"}), 400

    # Roda scan em background
    def run_and_comment():
        with app.app_context():
            results = _run_scan(scan_url, {})
            score   = score_findings(results)
            counts  = count_by_severity(results)
            scan_id = str(uuid.uuid4())[:8]
            report  = {
                "scan_id": scan_id, "url": scan_url,
                "score": score, "counts": counts,
                "modules": results,
                "executive": generate_executive_report(
                    scan_url, scan_id, 0, score, counts, results
                ),
            }
            from cicd.pr_review import handle_github_webhook
            handle_github_webhook(payload, secret, report, token)

    threading.Thread(target=run_and_comment, daemon=True).start()
    return jsonify({"status": "scan iniciado"}), 202


@app.route("/api/webhooks/gitlab", methods=["POST"])
def webhook_gitlab():
    """Recebe webhook do GitLab e posta comentário no MR."""
    token     = request.headers.get("X-GitLab-Token", os.getenv("GITLAB_TOKEN", ""))
    scan_url  = request.args.get("url", "")
    gitlab_url = request.args.get("gitlab_url", "https://gitlab.com")

    if not scan_url or not token:
        return jsonify({"error": "url e X-GitLab-Token são obrigatórios"}), 400

    payload = request.get_json()

    def run_and_comment():
        with app.app_context():
            results = _run_scan(scan_url, {})
            score   = score_findings(results)
            counts  = count_by_severity(results)
            scan_id = str(uuid.uuid4())[:8]
            report  = {
                "scan_id": scan_id, "url": scan_url,
                "score": score, "counts": counts,
                "modules": results,
                "executive": generate_executive_report(
                    scan_url, scan_id, 0, score, counts, results
                ),
            }
            from cicd.pr_review import handle_gitlab_webhook
            handle_gitlab_webhook(payload, report, token, gitlab_url)

    threading.Thread(target=run_and_comment, daemon=True).start()
    return jsonify({"status": "scan iniciado"}), 202


# ── API: Compliance ───────────────────────────────────────────────────────────
@app.route("/api/report/<scan_id>/compliance")
@require_auth
def api_compliance(scan_id):
    """Retorna dados de compliance de um scan."""
    scan   = get_user_scan(scan_id)
    report = scan.get_report()
    for mod in report.get("modules", []):
        if mod.get("module") == "Compliance":
            return jsonify(mod.get("compliance_data", {}))
    # Gera on-demand se não tiver
    compliance = generate_compliance_report(report.get("modules", []))
    return jsonify(compliance)


if __name__ == "__main__":
    from websocket.events import socketio
    print("\n🔍 VulnScanner v8.0 iniciado!")
    print(f"   {len(ALL_MODULE_NAMES)} módulos | SPA Crawler | Compliance | WebSocket | PR Review")
    print("   Dashboard: http://localhost:5000")
    print("   API Docs:  http://localhost:5000/api/docs\n")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
