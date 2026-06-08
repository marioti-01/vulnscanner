"""
Multi-tenancy — VulnScanner v7
Garante isolamento total de dados entre usuários.
Nenhum usuário acessa dados de outro, mesmo com IDs diretos.
"""

import functools
from flask import g, jsonify, abort
from auth.middleware import get_current_user


def owned_by_current_user(model_instance) -> bool:
    """Verifica se um objeto pertence ao usuário atual."""
    user = get_current_user()
    if not user:
        return False
    if user.role == "admin":
        return True  # Admin vê tudo
    owner_id = getattr(model_instance, "user_id", None)
    return str(owner_id) == str(user.id)


def get_user_project(project_id: str):
    """Retorna projeto se pertencer ao usuário atual, 404 caso contrário."""
    from database.models import Project
    project = Project.query.get_or_404(project_id)
    if not owned_by_current_user(project):
        abort(404)  # 404 em vez de 403 para não revelar existência
    return project


def get_user_scan(scan_id: str):
    """Retorna scan se pertencer ao usuário atual."""
    from database.models import Scan
    # Aceita tanto UUID completo quanto scan_id curto
    scan = (
        Scan.query.filter_by(scan_id=scan_id).first() or
        Scan.query.get(scan_id)
    )
    if not scan:
        abort(404)
    if not owned_by_current_user(scan):
        abort(404)
    return scan


def get_user_plugin(plugin_id: str):
    """Retorna plugin se pertencer ao usuário atual."""
    from database.models import Plugin
    plugin = Plugin.query.get_or_404(plugin_id)
    if not owned_by_current_user(plugin):
        abort(404)
    return plugin


def get_user_projects():
    """Retorna todos os projetos do usuário atual."""
    from database.models import Project
    user = get_current_user()
    if not user:
        return []
    if user.role == "admin":
        return Project.query.order_by(Project.updated_at.desc()).all()
    return Project.query.filter_by(user_id=user.id).order_by(Project.updated_at.desc()).all()


def get_user_scans(project_id: str = None, limit: int = 50):
    """Retorna scans do usuário atual, opcionalmente filtrados por projeto."""
    from database.models import Scan
    user = get_current_user()
    if not user:
        return []

    query = Scan.query
    if user.role != "admin":
        query = query.filter_by(user_id=user.id)
    if project_id:
        query = query.filter_by(project_id=project_id)

    return query.order_by(Scan.created_at.desc()).limit(limit).all()


def get_user_scheduled_scans():
    """Retorna scans agendados do usuário atual."""
    from database.models import ScheduledScan
    user = get_current_user()
    if not user:
        return []
    if user.role == "admin":
        return ScheduledScan.query.order_by(ScheduledScan.created_at.desc()).all()
    return ScheduledScan.query.filter_by(user_id=user.id).order_by(ScheduledScan.created_at.desc()).all()


def get_user_plugins():
    """Retorna plugins do usuário atual."""
    from database.models import Plugin
    user = get_current_user()
    if not user:
        return []
    return Plugin.query.filter_by(user_id=user.id).order_by(Plugin.created_at.desc()).all()


def user_stats() -> dict:
    """Estatísticas do usuário atual para o dashboard."""
    from database.models import Scan, Project, ScheduledScan
    user = get_current_user()
    if not user:
        return {}

    base_scan = Scan.query if user.role == "admin" else Scan.query.filter_by(user_id=user.id)
    base_proj = Project.query if user.role == "admin" else Project.query.filter_by(user_id=user.id)
    base_sched = ScheduledScan.query if user.role == "admin" else ScheduledScan.query.filter_by(user_id=user.id)

    scans = base_scan.all()
    total_criticals = sum(s.count_critical for s in scans)
    total_highs = sum(s.count_high for s in scans)
    scores = [s.score for s in scans if s.score is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0

    return {
        "projects": base_proj.count(),
        "scans": len(scans),
        "scheduled": base_sched.filter_by(is_active=True).count(),
        "total_criticals": total_criticals,
        "total_highs": total_highs,
        "avg_score": avg_score,
        "last_scan": scans[0].created_at.isoformat() if scans else None,
    }
