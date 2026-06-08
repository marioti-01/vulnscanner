"""
SPA Crawler — VulnScanner v8
Usa Playwright (Chromium headless) para renderizar JavaScript
e descobrir rotas, forms e parâmetros em SPAs (React, Vue, Angular).

Fallback automático para BeautifulSoup se Playwright não estiver disponível.
"""

import os
import re
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set


MAX_PAGES = int(os.getenv("SPA_MAX_PAGES", "25"))
MAX_DEPTH = int(os.getenv("SPA_MAX_DEPTH", "3"))
PLAYWRIGHT_ENABLED = os.getenv("PLAYWRIGHT_ENABLED", "true").lower() == "true"
NAV_TIMEOUT = 15000  # ms


def _is_same_origin(base_url: str, url: str) -> bool:
    base = urlparse(base_url)
    target = urlparse(url)
    return base.netloc == target.netloc


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


def _extract_forms_from_html(html: str, page_url: str) -> List[Dict]:
    """Extrai formulários do HTML renderizado."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        full_action = urljoin(page_url, action) if action else page_url
        method = form.get("method", "GET").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            if name:
                inputs.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
        forms.append({"action": full_action, "method": method, "inputs": inputs})
    return forms


def _extract_links_from_html(html: str, base_url: str) -> Set[str]:
    """Extrai links do HTML renderizado."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "lxml")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        full = urljoin(base_url, href)
        if _is_same_origin(base_url, full):
            links.add(_normalize_url(full))
    return links


def _extract_params_from_url(url: str) -> List[str]:
    from urllib.parse import parse_qs
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    return params


async def _crawl_with_playwright(url: str, auth: dict = None) -> Dict:
    """Crawl assíncrono com Playwright."""
    from playwright.async_api import async_playwright

    visited: Set[str] = set()
    to_visit = [(url, 0)]
    all_urls: List[str] = []
    all_forms: List[Dict] = []
    all_params: Set[str] = set()
    spa_routes: List[str] = []
    findings = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",  # Para CORS nos testes
            ]
        )

        context = await browser.new_context(
            user_agent="Mozilla/5.0 VulnScanner/8.0",
            ignore_https_errors=True,
            java_script_enabled=True,
        )

        # Injeta cookies de auth se disponíveis
        if auth and auth.get("cookies"):
            parsed = urlparse(url)
            for cookie_str in auth["cookies"].split(";"):
                cookie_str = cookie_str.strip()
                if "=" in cookie_str:
                    name, value = cookie_str.split("=", 1)
                    try:
                        await context.add_cookies([{
                            "name": name.strip(),
                            "value": value.strip(),
                            "domain": parsed.netloc,
                            "path": "/",
                        }])
                    except Exception:
                        pass

        page = await context.new_page()

        # Intercepta navegação para capturar rotas SPA
        intercepted_routes: Set[str] = set()

        async def on_request(request):
            req_url = request.url
            if _is_same_origin(url, req_url):
                parsed = urlparse(req_url)
                if parsed.path and parsed.path not in intercepted_routes:
                    intercepted_routes.add(parsed.path)

        page.on("request", on_request)

        while to_visit and len(visited) < MAX_PAGES:
            current_url, depth = to_visit.pop(0)
            current_url = _normalize_url(current_url)

            if current_url in visited or depth > MAX_DEPTH:
                continue
            visited.add(current_url)

            try:
                # Navega com timeout
                await page.goto(current_url, timeout=NAV_TIMEOUT,
                                wait_until="networkidle")

                # Aguarda conteúdo dinâmico
                await page.wait_for_timeout(1000)

                # Scroll para ativar lazy-loading
                await page.evaluate("""
                    window.scrollTo(0, document.body.scrollHeight / 2);
                """)
                await page.wait_for_timeout(500)

                html = await page.content()
                all_urls.append(current_url)
                all_params.update(_extract_params_from_url(current_url))

                # Extrai forms do HTML renderizado
                forms = _extract_forms_from_html(html, current_url)
                all_forms.extend(forms)

                # Extrai links
                links = _extract_links_from_html(html, current_url)
                for link in links:
                    if link not in visited:
                        to_visit.append((link, depth + 1))

                # Captura rotas SPA via hash e pushState
                spa_found = await page.evaluate("""
                    () => {
                        const routes = new Set();
                        // React Router / Vue Router links
                        document.querySelectorAll('a[href]').forEach(a => {
                            const h = a.getAttribute('href');
                            if (h && (h.startsWith('/') || h.startsWith('#'))) {
                                routes.add(h);
                            }
                        });
                        // data-route attributes
                        document.querySelectorAll('[data-route],[data-path],[to]').forEach(el => {
                            const r = el.getAttribute('data-route') ||
                                      el.getAttribute('data-path') ||
                                      el.getAttribute('to');
                            if (r) routes.add(r);
                        });
                        return Array.from(routes);
                    }
                """)

                base_parsed = urlparse(url)
                for route in spa_found:
                    if route.startswith("/"):
                        full = f"{base_parsed.scheme}://{base_parsed.netloc}{route}"
                        spa_routes.append(full)
                        if full not in visited:
                            to_visit.append((full, depth + 1))

            except Exception as e:
                findings.append({
                    "severity": "info",
                    "title": f"Página ignorada pelo crawler SPA: {current_url[:80]}",
                    "detail": str(e)[:100],
                    "fix": "",
                })
                continue

        await browser.close()

    # Detecta framework JS
    framework = "Desconhecido"
    all_intercepted = " ".join(intercepted_routes)
    if "__next" in all_intercepted or "_next" in all_intercepted:
        framework = "Next.js"
    elif "/_nuxt/" in all_intercepted:
        framework = "Nuxt.js"
    elif "/static/js/main." in all_intercepted:
        framework = "Create React App"
    elif "/assets/index." in all_intercepted:
        framework = "Vite (React/Vue)"
    elif "angular" in all_intercepted.lower():
        framework = "Angular"

    findings.insert(0, {
        "severity": "info",
        "title": f"SPA Crawler: {len(visited)} página(s) renderizadas — Framework: {framework}",
        "detail": (
            f"Páginas visitadas: {len(visited)} | "
            f"Forms: {len(all_forms)} | "
            f"Rotas SPA: {len(set(spa_routes))} | "
            f"Parâmetros: {len(all_params)} | "
            f"Requests interceptados: {len(intercepted_routes)}"
        ),
        "fix": "",
    })

    return {
        "module": "SPA Crawler",
        "icon": "ti-spider",
        "findings": findings,
        "crawl_data": {
            "urls": list(set(all_urls + list(set(spa_routes)))),
            "forms": all_forms,
            "params": list(all_params),
            "spa_routes": list(set(spa_routes)),
            "framework": framework,
            "js_rendered": True,
        }
    }


def _crawl_fallback(url: str, auth: dict = None) -> Dict:
    """Fallback para BeautifulSoup quando Playwright não está disponível."""
    import requests
    from bs4 import BeautifulSoup
    urllib3_available = True
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        urllib3_available = False

    headers = {"User-Agent": "Mozilla/5.0 VulnScanner/8.0"}
    if auth:
        if auth.get("cookies"):
            headers["Cookie"] = auth["cookies"]
        if auth.get("auth_headers"):
            headers.update(auth["auth_headers"])

    visited: Set[str] = set()
    to_visit = [(url, 0)]
    all_urls: List[str] = []
    all_forms: List[Dict] = []
    all_params: Set[str] = set()

    while to_visit and len(visited) < MAX_PAGES:
        current_url, depth = to_visit.pop(0)
        current_url = _normalize_url(current_url)
        if current_url in visited or depth > MAX_DEPTH:
            continue
        visited.add(current_url)

        try:
            resp = requests.get(current_url, timeout=10, verify=False,
                                headers=headers, allow_redirects=True)
            if "text/html" not in resp.headers.get("content-type", ""):
                continue

            html = resp.text
            all_urls.append(current_url)
            all_params.update(_extract_params_from_url(current_url))
            all_forms.extend(_extract_forms_from_html(html, current_url))

            for link in _extract_links_from_html(html, current_url):
                if link not in visited:
                    to_visit.append((link, depth + 1))
        except Exception:
            continue

    return {
        "module": "Crawler / Spider",
        "icon": "ti-spider",
        "findings": [{
            "severity": "info",
            "title": f"Crawler estático: {len(visited)} página(s) — JavaScript NÃO renderizado",
            "detail": "Playwright não disponível. SPAs podem ter cobertura reduzida.",
            "fix": "Instale Playwright para cobertura completa de SPAs.",
        }],
        "crawl_data": {
            "urls": all_urls,
            "forms": all_forms,
            "params": list(all_params),
            "spa_routes": [],
            "framework": "Desconhecido (sem renderização JS)",
            "js_rendered": False,
        }
    }


def check_spa_crawler(url: str, auth: dict = None) -> Dict:
    """
    Ponto de entrada do SPA Crawler.
    Usa Playwright se disponível, fallback para requests/BS4.
    """
    if not url.startswith("http"):
        url = "https://" + url

    if not PLAYWRIGHT_ENABLED:
        return _crawl_fallback(url, auth)

    try:
        import asyncio
        from playwright.async_api import async_playwright

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Em contexto assíncrono (ex: eventlet)
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, _crawl_with_playwright(url, auth))
                    return future.result(timeout=120)
            else:
                return loop.run_until_complete(_crawl_with_playwright(url, auth))
        except RuntimeError:
            return asyncio.run(_crawl_with_playwright(url, auth))

    except ImportError:
        return _crawl_fallback(url, auth)
    except Exception as e:
        result = _crawl_fallback(url, auth)
        result["findings"].insert(0, {
            "severity": "info",
            "title": f"SPA Crawler com erro, usando fallback: {str(e)[:80]}",
            "detail": str(e),
            "fix": "",
        })
        return result
