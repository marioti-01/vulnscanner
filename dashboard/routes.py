"""
Dashboard Blueprint — VulnScanner v7
Rotas para dashboard principal, projetos, histórico e trending.
"""

import json
import datetime
from flask import Blueprint, render_template, request, jsonify, abort, send_file
from auth.middleware import require_auth, get_current_user
from auth.tenancy import (
    get_user_projects, get_user_project, get_user_scans,
    get_user_scan, user_stats, get_user_scheduled_scans,
    get_user_plugins, get_user_plugin
)
from auth.rate_limit import rate_limited, get_quota_status
from database.models import db, Project, Scan, ScheduledScan, Plugin
from modules.scan_diff import compare_scans
from cicd.integration import (
    generate_junit_xml, get_exit_code,
    generate_github_summary, generate_score_badge,
    generate_github_actions_yaml, generate_gitlab_ci_yaml,
)
from export.pdf_generator import export_pdf, export_html
import io

dashboard_bp = Blueprint("dashboard_bp", __name__)


# ── Dashboard principal ───────────────────────────────────────────────────────

@dashboard_bp.route("/")
@require_auth
def index():
    user = get_current_user()
    projects = get_user_projects()
    stats = user_stats()
    recent_scans = get_user_scans(limit=5)
    return render_template(
        "dashboard/index.html",
        user=user,
        projects=projects,
        stats=stats,
        recent_scans=recent_scans,
    )


# ── Projetos ──────────────────────────────────────────────────────────────────

@dashboard_bp.route("/projects")
@require_auth
def projects():
    user = get_current_user()
    projects = get_user_projects()
    return render_template("dashboard/projects.html", user=user, projects=projects)


@dashboard_bp.route("/api/projects", methods=["GET"])
@require_auth
@rate_limited
def api_list_projects():
    projects = get_user_projects()
    return jsonify([p.to_dict() for p in projects])


@dashboard_bp.route("/api/projects", methods=["POST"])
@require_auth
@rate_limited
def api_create_project():
    user = get_current_user()
    data = request.get_json()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Nome obrigatório"}), 400

    project = Project(
        user_id=user.id,
        name=name,
        description=data.get("description", ""),
        color=data.get("color", "#FF4757"),
    )
    db.session.add(project)
    db.session.commit()
    return jsonify(project.to_dict()), 201


@dashboard_bp.route("/api/projects/<project_id>", methods=["GET"])
@require_auth
def api_get_project(project_id):
    project = get_user_project(project_id)
    scans = get_user_scans(project_id=project_id, limit=50)
    return jsonify({
        **project.to_dict(),
        "scans": [s.to_dict() for s in scans],
    })


@dashboard_bp.route("/api/projects/<project_id>", methods=["PUT"])
@require_auth
def api_update_project(project_id):
    project = get_user_project(project_id)
    data = request.get_json()
    if "name" in data:
        project.name = data["name"].strip()
    if "description" in data:
        project.description = data["description"]
    if "color" in data:
        project.color = data["color"]
    project.updated_at = datetime.datetime.utcnow()
    db.session.commit()
    return jsonify(project.to_dict())


@dashboard_bp.route("/api/projects/<project_id>", methods=["DELETE"])
@require_auth
def api_delete_project(project_id):
    project = get_user_project(project_id)
    db.session.delete(project)
    db.session.commit()
    return jsonify({"success": True})


# ── Projeto individual ────────────────────────────────────────────────────────

@dashboard_bp.route("/projects/<project_id>")
@require_auth
def project_detail(project_id):
    user = get_current_user()
    project = get_user_project(project_id)
    scans = get_user_scans(project_id=project_id, limit=50)

    # Score trending data para gráfico
    trending = [
        {
            "date": s.created_at.strftime("%d/%m"),
            "score": s.score,
            "scan_id": s.scan_id,
            "critical": s.count_critical,
            "high": s.count_high,
        }
        for s in reversed(scans[:30])
    ]

    return render_template(
        "dashboard/project.html",
        user=user,
        project=project,
        scans=scans,
        trending=json.dumps(trending),
    )


# ── Histórico e trending ──────────────────────────────────────────────────────

@dashboard_bp.route("/api/projects/<project_id>/trending")
@require_auth
def api_project_trending(project_id):
    project = get_user_project(project_id)
    scans = get_user_scans(project_id=project_id, limit=90)
    data = [
        {
            "date": s.created_at.isoformat(),
            "score": s.score,
            "scan_id": s.scan_id,
            "critical": s.count_critical,
            "high": s.count_high,
            "medium": s.count_medium,
        }
        for s in reversed(scans)
    ]
    return jsonify(data)


# ── Diff entre scans ─────────────────────────────────────────────────────────

@dashboard_bp.route("/api/diff")
@require_auth
def api_diff():
    scan_id_a = request.args.get("a", "")
    scan_id_b = request.args.get("b", "")
    if not scan_id_a or not scan_id_b:
        return jsonify({"error": "Parâmetros 'a' e 'b' obrigatórios"}), 400

    scan_a = get_user_scan(scan_id_a)
    scan_b = get_user_scan(scan_id_b)

    report_a = scan_a.get_report()
    report_b = scan_b.get_report()

    if not report_a or not report_b:
        return jsonify({"error": "Relatório não disponível para um dos scans"}), 404

    diff = compare_scans(report_a, report_b)
    return jsonify(diff)


@dashboard_bp.route("/diff")
@require_auth
def diff_page():
    user = get_current_user()
    scan_id_a = request.args.get("a", "")
    scan_id_b = request.args.get("b", "")
    scans = get_user_scans(limit=100)
    return render_template(
        "dashboard/diff.html",
        user=user,
        scans=scans,
        scan_id_a=scan_id_a,
        scan_id_b=scan_id_b,
    )


# ── Scan individual ───────────────────────────────────────────────────────────

@dashboard_bp.route("/report/<scan_id>")
@require_auth
def view_report(scan_id):
    user = get_current_user()
    scan = get_user_scan(scan_id)
    report = scan.get_report()
    if not report:
        abort(404)
    return render_template("report.html", report=report, user=user)


@dashboard_bp.route("/api/report/<scan_id>")
@require_auth
@rate_limited
def api_report(scan_id):
    scan = get_user_scan(scan_id)
    return jsonify(scan.to_dict(include_report=True))


@dashboard_bp.route("/api/report/<scan_id>/junit")
@require_auth
def api_report_junit(scan_id):
    scan = get_user_scan(scan_id)
    report = scan.get_report()
    fail_on = request.args.get("fail_on", "high")
    xml = generate_junit_xml(report, fail_on=fail_on)
    return xml, 200, {
        "Content-Type": "application/xml",
        "Content-Disposition": f"attachment; filename=vulnscan-{scan_id}.xml"
    }


@dashboard_bp.route("/api/report/<scan_id>/github-summary")
@require_auth
def api_report_github_summary(scan_id):
    scan = get_user_scan(scan_id)
    report = scan.get_report()
    summary = generate_github_summary(report)
    return summary, 200, {"Content-Type": "text/markdown"}


@dashboard_bp.route("/api/report/<scan_id>/pdf")
@require_auth
def api_report_pdf(scan_id):
    scan = get_user_scan(scan_id)
    report = scan.get_report()
    content, mime, ext = export_pdf(report)
    return send_file(
        io.BytesIO(content),
        mimetype=mime,
        as_attachment=True,
        download_name=f"vulnscan-{scan_id}{ext}",
    )


@dashboard_bp.route("/api/report/<scan_id>/badge.svg")
def api_report_badge(scan_id):
    """Badge SVG público (sem auth) para usar em README."""
    from database.models import Scan
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    svg = generate_score_badge(scan.score or 0)
    return svg, 200, {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "max-age=3600",
    }


@dashboard_bp.route("/api/report/<scan_id>/exit-code")
@require_auth
def api_report_exit_code(scan_id):
    scan = get_user_scan(scan_id)
    report = scan.get_report()
    fail_on = request.args.get("fail_on", "high")
    code = get_exit_code(report, fail_on)
    return jsonify({"exit_code": code, "fail_on": fail_on, "scan_id": scan_id})


# ── Scans agendados ───────────────────────────────────────────────────────────

@dashboard_bp.route("/scheduled")
@require_auth
def scheduled_page():
    user = get_current_user()
    scheduled = get_user_scheduled_scans()
    projects = get_user_projects()
    return render_template(
        "dashboard/scheduled.html",
        user=user,
        scheduled=scheduled,
        projects=projects,
    )


@dashboard_bp.route("/api/scheduled", methods=["GET"])
@require_auth
def api_list_scheduled():
    return jsonify([s.to_dict() for s in get_user_scheduled_scans()])


@dashboard_bp.route("/api/scheduled", methods=["POST"])
@require_auth
def api_create_scheduled():
    from scheduler.manager import add_scheduled_scan
    user = get_current_user()
    data = request.get_json()

    required = ["url", "frequency", "project_id"]
    if not all(data.get(k) for k in required):
        return jsonify({"error": "url, frequency e project_id são obrigatórios"}), 400

    project = get_user_project(data["project_id"])
    next_run = _calc_next_run(data["frequency"])

    sched = ScheduledScan(
        project_id=project.id,
        user_id=user.id,
        url=data["url"],
        frequency=data["frequency"],
        rate_profile=data.get("rate_profile", "normal"),
        notify_email=data.get("notify_email", ""),
        notify_on=data.get("notify_on", "always"),
        next_run=next_run,
    )
    db.session.add(sched)
    db.session.commit()
    add_scheduled_scan(sched)
    return jsonify(sched.to_dict()), 201


@dashboard_bp.route("/api/scheduled/<sched_id>", methods=["DELETE"])
@require_auth
def api_delete_scheduled(sched_id):
    from scheduler.manager import remove_scheduled_scan
    sched = ScheduledScan.query.get_or_404(sched_id)
    if str(sched.user_id) != str(get_current_user().id):
        abort(404)
    remove_scheduled_scan(sched_id)
    db.session.delete(sched)
    db.session.commit()
    return jsonify({"success": True})


# ── Plugins ───────────────────────────────────────────────────────────────────

@dashboard_bp.route("/plugins")
@require_auth
def plugins_page():
    user = get_current_user()
    plugins = get_user_plugins()
    from plugins.engine import get_plugin_template, BUILTIN_PLUGINS
    return render_template(
        "dashboard/plugins.html",
        user=user,
        plugins=plugins,
        builtin_plugins=BUILTIN_PLUGINS,
        template=get_plugin_template(),
    )


@dashboard_bp.route("/api/plugins", methods=["GET"])
@require_auth
def api_list_plugins():
    return jsonify([p.to_dict() for p in get_user_plugins()])


@dashboard_bp.route("/api/plugins", methods=["POST"])
@require_auth
def api_create_plugin():
    user = get_current_user()
    data = request.get_json()
    if not data.get("name") or not data.get("code"):
        return jsonify({"error": "name e code são obrigatórios"}), 400

    plugin = Plugin(
        user_id=user.id,
        name=data["name"],
        description=data.get("description", ""),
        version=data.get("version", "1.0.0"),
        code=data["code"],
    )
    db.session.add(plugin)
    db.session.commit()
    return jsonify(plugin.to_dict()), 201


@dashboard_bp.route("/api/plugins/<plugin_id>", methods=["PUT"])
@require_auth
def api_update_plugin(plugin_id):
    plugin = get_user_plugin(plugin_id)
    data = request.get_json()
    for field in ("name", "description", "version", "code", "is_active"):
        if field in data:
            setattr(plugin, field, data[field])
    db.session.commit()
    return jsonify(plugin.to_dict())


@dashboard_bp.route("/api/plugins/<plugin_id>", methods=["DELETE"])
@require_auth
def api_delete_plugin(plugin_id):
    plugin = get_user_plugin(plugin_id)
    db.session.delete(plugin)
    db.session.commit()
    return jsonify({"success": True})


@dashboard_bp.route("/api/plugins/<plugin_id>/test", methods=["POST"])
@require_auth
def api_test_plugin(plugin_id):
    from plugins.engine import run_plugin
    plugin = get_user_plugin(plugin_id)
    data = request.get_json()
    url = data.get("url", "https://example.com")
    result = run_plugin(plugin.code, plugin.name, url)
    return jsonify(result)


# ── Configurações ─────────────────────────────────────────────────────────────

@dashboard_bp.route("/settings")
@require_auth
def settings():
    user = get_current_user()
    quota = get_quota_status(user)
    return render_template("dashboard/settings.html", user=user, quota=quota)


@dashboard_bp.route("/api/quota")
@require_auth
def api_quota():
    user = get_current_user()
    return jsonify(get_quota_status(user))


# ── CI/CD Templates ───────────────────────────────────────────────────────────

@dashboard_bp.route("/api/cicd/github-actions")
@require_auth
def api_github_actions_yaml():
    return generate_github_actions_yaml(), 200, {
        "Content-Type": "text/yaml",
        "Content-Disposition": "attachment; filename=vulnscan.yml"
    }


@dashboard_bp.route("/api/cicd/gitlab-ci")
@require_auth
def api_gitlab_ci_yaml():
    return generate_gitlab_ci_yaml(), 200, {
        "Content-Type": "text/yaml",
        "Content-Disposition": "attachment; filename=vulnscan-gitlab.yml"
    }


# ── Admin ─────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/admin")
@require_auth
def admin_panel():
    from auth.middleware import require_admin
    user = get_current_user()
    if user.role != "admin":
        abort(403)
    from database.models import User
    from modules.circuit_breaker import get_breakers_status
    from scheduler.manager import get_scheduler_status
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template(
        "dashboard/admin.html",
        user=user,
        users=users,
        breakers=get_breakers_status(),
        scheduler=get_scheduler_status(),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _calc_next_run(frequency: str) -> datetime.datetime:
    now = datetime.datetime.utcnow()
    if frequency == "daily":
        return (now + datetime.timedelta(days=1)).replace(hour=3, minute=0, second=0)
    elif frequency == "weekly":
        days_ahead = 7 - now.weekday()
        return (now + datetime.timedelta(days=days_ahead)).replace(hour=3, minute=0, second=0)
    elif frequency == "monthly":
        if now.month == 12:
            return now.replace(year=now.year+1, month=1, day=1, hour=3, minute=0, second=0)
        return now.replace(month=now.month+1, day=1, hour=3, minute=0, second=0)
    return now + datetime.timedelta(days=1)
