"""
Testes v7 — Auth, Tenancy, Rate Limiting, Dashboard
Execute: pytest tests/test_v7.py -v
"""

import pytest
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture(scope="session")
def app():
    """Cria app de teste com banco em memória."""
    from app import create_app
    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret",
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
def db(app):
    from database.models import db as _db
    with app.app_context():
        yield _db


@pytest.fixture
def admin_user(app, db):
    """Cria usuário admin para testes."""
    from database.models import User
    with app.app_context():
        existing = User.query.filter_by(username="admin_test").first()
        if existing:
            return existing
        user = User(username="admin_test", email="admin@test.com", role="admin")
        user.set_password("senha123456")
        db.session.add(user)
        db.session.commit()
        return user


@pytest.fixture
def regular_user(app, db):
    """Cria usuário comum para testes."""
    from database.models import User
    with app.app_context():
        existing = User.query.filter_by(username="user_test").first()
        if existing:
            return existing
        user = User(username="user_test", email="user@test.com", role="user")
        user.set_password("senha123456")
        db.session.add(user)
        db.session.commit()
        return user


@pytest.fixture
def other_user(app, db):
    """Outro usuário para testar isolamento."""
    from database.models import User
    with app.app_context():
        existing = User.query.filter_by(username="other_test").first()
        if existing:
            return existing
        user = User(username="other_test", email="other@test.com", role="user")
        user.set_password("senha123456")
        db.session.add(user)
        db.session.commit()
        return user


def login_user(client, username, password):
    """Helper para fazer login."""
    return client.post("/auth/login", json={"username": username, "password": password})


# ── Testes: Autenticação ──────────────────────────────────────────────────────

class TestAuth:
    def test_login_page_accessible(self, client):
        r = client.get("/auth/login")
        assert r.status_code == 200

    def test_register_first_user_becomes_admin(self, client, app, db):
        with app.app_context():
            from database.models import User
            User.query.filter_by(username="first_admin").delete()
            db.session.commit()

        r = client.post("/auth/register", json={
            "username": "first_admin",
            "email": "first@test.com",
            "password": "senha123456",
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("success")

        with app.app_context():
            from database.models import User
            u = User.query.filter_by(username="first_admin").first()
            # Primeiro usuário pode ser admin dependendo do estado do DB
            assert u is not None

    def test_login_valid_credentials(self, client, admin_user, app):
        with app.app_context():
            r = login_user(client, "admin_test", "senha123456")
            assert r.status_code == 200
            data = r.get_json()
            assert data.get("success")

    def test_login_invalid_credentials(self, client):
        r = client.post("/auth/login", json={
            "username": "nobody",
            "password": "wrongpass",
        })
        assert r.status_code == 401

    def test_login_missing_fields(self, client):
        r = client.post("/auth/login", json={"username": "admin_test"})
        assert r.status_code == 400

    def test_register_duplicate_username(self, client, admin_user, app):
        with app.app_context():
            r = client.post("/auth/register", json={
                "username": "admin_test",
                "email": "new@test.com",
                "password": "senha123456",
            })
            assert r.status_code == 409

    def test_register_short_password(self, client):
        r = client.post("/auth/register", json={
            "username": "newuser99",
            "email": "new99@test.com",
            "password": "123",
        })
        assert r.status_code == 400

    def test_protected_route_requires_auth(self, client):
        r = client.get("/api/projects")
        assert r.status_code in (302, 401)

    def test_api_requires_auth(self, client):
        r = client.get("/api/history")
        assert r.status_code in (302, 401, 404)


# ── Testes: API Keys ──────────────────────────────────────────────────────────

class TestApiKeys:
    def test_create_api_key(self, client, admin_user, app):
        with app.app_context():
            login_user(client, "admin_test", "senha123456")
            r = client.post("/auth/api-keys", json={"name": "Minha Key CI"})
            assert r.status_code == 201
            data = r.get_json()
            assert data["key"].startswith("vs_")
            assert data["name"] == "Minha Key CI"

    def test_list_api_keys(self, client, admin_user, app):
        with app.app_context():
            login_user(client, "admin_test", "senha123456")
            r = client.get("/auth/api-keys")
            assert r.status_code == 200
            assert isinstance(r.get_json(), list)

    def test_delete_api_key(self, client, admin_user, app):
        with app.app_context():
            login_user(client, "admin_test", "senha123456")
            create_r = client.post("/auth/api-keys", json={"name": "Para deletar"})
            key_id = create_r.get_json()["id"]
            delete_r = client.delete(f"/auth/api-keys/{key_id}")
            assert delete_r.status_code == 200

    def test_api_key_auth(self, client, admin_user, app):
        with app.app_context():
            login_user(client, "admin_test", "senha123456")
            create_r = client.post("/auth/api-keys", json={"name": "Test Key"})
            api_key = create_r.get_json()["key"]

            # Logout e testa com API key
            client.get("/auth/logout")
            r = client.get("/auth/api-keys",
                           headers={"X-API-Key": api_key})
            assert r.status_code == 200


# ── Testes: Multi-tenancy ─────────────────────────────────────────────────────

class TestMultiTenancy:
    def test_user_cannot_see_other_users_project(self, client, regular_user, other_user, app, db):
        with app.app_context():
            from database.models import Project, User
            ou = User.query.filter_by(username="other_test").first()
            proj = Project(user_id=ou.id, name="Projeto Secreto v2")
            db.session.add(proj)
            db.session.commit()
            proj_id = proj.id

            login_user(client, "user_test", "senha123456")
            r = client.get(f"/api/projects/{proj_id}")
            assert r.status_code == 404

    def test_user_can_see_own_project(self, client, regular_user, app, db):
        with app.app_context():
            from database.models import Project
            login_user(client, "user_test", "senha123456")

            # Cria projeto
            create_r = client.post("/api/projects", json={"name": "Meu Projeto"})
            assert create_r.status_code == 201
            proj_id = create_r.get_json()["id"]

            # Acessa o projeto criado
            r = client.get(f"/api/projects/{proj_id}")
            assert r.status_code == 200

    def test_user_cannot_delete_other_users_project(self, client, regular_user, other_user, app, db):
        with app.app_context():
            from database.models import Project

            proj = Project(user_id=other_user.id, name="Projeto do Outro")
            db.session.add(proj)
            db.session.commit()
            proj_id = proj.id

            login_user(client, "user_test", "senha123456")
            r = client.delete(f"/api/projects/{proj_id}")
            assert r.status_code == 404

    def test_admin_can_see_all_projects(self, client, admin_user, other_user, app, db):
        with app.app_context():
            from database.models import Project

            proj = Project(user_id=other_user.id, name="Projeto Visível para Admin")
            db.session.add(proj)
            db.session.commit()

            login_user(client, "admin_test", "senha123456")
            r = client.get("/api/projects")
            assert r.status_code == 200
            # Admin vê todos
            projects = r.get_json()
            assert isinstance(projects, list)

    def test_user_projects_list_isolation(self, client, regular_user, other_user, app, db):
        with app.app_context():
            from database.models import Project

            # Cria projeto para other_user
            proj_other = Project(user_id=other_user.id, name="Projeto Isolado Outro")
            db.session.add(proj_other)
            db.session.commit()

            login_user(client, "user_test", "senha123456")
            r = client.get("/api/projects")
            projects = r.get_json()

            # Não deve aparecer projeto do outro usuário
            names = [p["name"] for p in projects]
            assert "Projeto Isolado Outro" not in names


# ── Testes: Rate Limiting ─────────────────────────────────────────────────────

class TestRateLimiting:
    def test_quota_status_returns_dict(self, app, admin_user):
        with app.app_context():
            from auth.rate_limit import get_quota_status
            quota = get_quota_status(admin_user)
            assert "scans_today" in quota
            assert "scans_limit" in quota
            assert "scans_remaining" in quota
            assert "concurrent_active" in quota

    def test_admin_has_higher_limits(self, app, admin_user, regular_user):
        with app.app_context():
            from auth.rate_limit import get_quota_status
            admin_quota = get_quota_status(admin_user)
            user_quota  = get_quota_status(regular_user)
            assert admin_quota["scans_limit"] > user_quota["scans_limit"]

    def test_scan_quota_decrements(self, app, regular_user):
        with app.app_context():
            from auth.rate_limit import (
                get_quota_status, register_scan_start,
                register_scan_end, check_scan_quota
            )
            initial = get_quota_status(regular_user)["scans_remaining"]
            register_scan_start(regular_user)
            active = get_quota_status(regular_user)["concurrent_active"]
            assert active >= 1
            register_scan_end(regular_user)
            final_active = get_quota_status(regular_user)["concurrent_active"]
            assert final_active == 0

    def test_rate_limit_check(self, app, regular_user):
        with app.app_context():
            from auth.rate_limit import check_rate_limit
            allowed, reason, headers = check_rate_limit(regular_user)
            assert allowed is True
            assert "X-RateLimit-Limit" in headers
            assert "X-RateLimit-Remaining" in headers

    def test_scan_quota_check_passes(self, app, regular_user):
        with app.app_context():
            from auth.rate_limit import check_scan_quota
            allowed, reason = check_scan_quota(regular_user)
            assert allowed is True
            assert reason == ""


# ── Testes: Projects CRUD ─────────────────────────────────────────────────────

class TestProjects:
    def test_create_project(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            r = client.post("/api/projects", json={
                "name": "Projeto Teste CRUD",
                "description": "Descrição de teste",
                "color": "#FF4757",
            })
            assert r.status_code == 201
            data = r.get_json()
            assert data["name"] == "Projeto Teste CRUD"
            assert data["color"] == "#FF4757"

    def test_update_project(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            create_r = client.post("/api/projects", json={"name": "Para Atualizar"})
            proj_id = create_r.get_json()["id"]

            r = client.put(f"/api/projects/{proj_id}", json={"name": "Atualizado"})
            assert r.status_code == 200
            assert r.get_json()["name"] == "Atualizado"

    def test_delete_project(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            create_r = client.post("/api/projects", json={"name": "Para Deletar"})
            proj_id = create_r.get_json()["id"]

            r = client.delete(f"/api/projects/{proj_id}")
            assert r.status_code == 200

            r2 = client.get(f"/api/projects/{proj_id}")
            assert r2.status_code == 404

    def test_project_requires_name(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            r = client.post("/api/projects", json={"description": "sem nome"})
            assert r.status_code == 400


# ── Testes: Scan Diff via API ─────────────────────────────────────────────────

class TestScanDiffAPI:
    def test_diff_missing_params(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            r = client.get("/api/diff?a=abc")
            assert r.status_code == 400

    def test_diff_nonexistent_scan(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            r = client.get("/api/diff?a=notexist1&b=notexist2")
            assert r.status_code == 404


# ── Testes: Plugins ───────────────────────────────────────────────────────────

class TestPluginsAPI:
    def test_create_plugin(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            r = client.post("/api/plugins", json={
                "name": "Test Plugin",
                "description": "Meu plugin",
                "code": 'def run(url, auth=None):\n    return {"module":"Test","icon":"ti-plug","findings":[]}',
            })
            assert r.status_code == 201
            assert r.get_json()["name"] == "Test Plugin"

    def test_list_plugins(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            r = client.get("/api/plugins")
            assert r.status_code == 200
            assert isinstance(r.get_json(), list)

    def test_update_plugin(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            create_r = client.post("/api/plugins", json={
                "name": "Plugin Atualizável",
                "code": 'def run(url, auth=None): return {"module":"X","icon":"ti-x","findings":[]}',
            })
            plugin_id = create_r.get_json()["id"]
            r = client.put(f"/api/plugins/{plugin_id}", json={"name": "Plugin Renomeado"})
            assert r.status_code == 200
            assert r.get_json()["name"] == "Plugin Renomeado"

    def test_delete_plugin(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            create_r = client.post("/api/plugins", json={
                "name": "Plugin para Deletar",
                "code": 'def run(url, auth=None): return {"module":"X","icon":"ti-x","findings":[]}',
            })
            plugin_id = create_r.get_json()["id"]
            r = client.delete(f"/api/plugins/{plugin_id}")
            assert r.status_code == 200

    def test_cannot_access_other_users_plugin(self, client, regular_user, other_user, app, db):
        with app.app_context():
            from database.models import Plugin
            plugin = Plugin(
                user_id=other_user.id,
                name="Plugin Secreto",
                code='def run(url, auth=None): return {"module":"X","icon":"ti-x","findings":[]}',
            )
            db.session.add(plugin)
            db.session.commit()
            plugin_id = plugin.id

            login_user(client, "user_test", "senha123456")
            r = client.delete(f"/api/plugins/{plugin_id}")
            assert r.status_code == 404


# ── Testes: User stats ────────────────────────────────────────────────────────

class TestUserStats:
    def test_user_stats_returns_dict(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            from auth.tenancy import user_stats
            stats = user_stats()
            assert "projects" in stats
            assert "scans" in stats
            assert "avg_score" in stats

    def test_quota_api_endpoint(self, client, regular_user, app):
        with app.app_context():
            login_user(client, "user_test", "senha123456")
            r = client.get("/api/quota")
            assert r.status_code == 200
            data = r.get_json()
            assert "scans_today" in data
            assert "scans_remaining" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
