import socket
import dns.resolver
import dns.zone
import dns.query
import concurrent.futures
from typing import List

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "store", "portal", "app", "dashboard", "cdn",
    "static", "assets", "img", "images", "media", "upload", "uploads",
    "secure", "vpn", "remote", "intranet", "internal", "beta", "old",
    "backup", "db", "database", "mysql", "phpmyadmin", "jenkins",
    "gitlab", "git", "jira", "confluence", "kibana", "grafana",
    "monitor", "status", "smtp", "pop", "imap", "ns1", "ns2",
    "mx", "webmail", "cpanel", "whm", "support", "help",
    # DevOps, CI/CD, containers, orchestration
    "ci", "cd", "docker", "k8s", "kubernetes", "registry", "vault",
    "sentry", "minio", "traefik", "prometheus", "alertmanager",
    "elasticsearch", "logstash", "rabbitmq", "redis", "memcached",
    "cassandra", "kafka", "zookeeper", "consul", "nomad",
    "terraform", "ansible", "puppet", "chef",
    # Monitoring & management
    "nagios", "zabbix", "cacti", "netdata", "cockpit", "webmin",
    "plesk", "directadmin", "ispconfig",
    # Communication & collaboration
    "roundcube", "sogo", "nextcloud", "owncloud", "mattermost",
    "rocket", "slack", "teams", "meet", "zoom", "jitsi",
    "wiki", "docs", "documentation", "helpdesk", "ticketing",
    # Business applications
    "erp", "crm", "hr", "finance", "accounting", "billing",
    "invoice", "payment", "checkout", "cart", "orders",
    "inventory", "shipping", "tracking",
    # Analytics & observability
    "analytics", "metrics", "logs", "audit", "compliance",
    # Backup & disaster recovery
    "backup2", "restore", "disaster", "failover", "mirror",
    # Infrastructure
    "proxy", "gateway", "loadbalancer", "lb", "cache",
    "queue", "worker", "scheduler", "cron", "batch",
    "task", "job", "pipeline", "build", "deploy", "release",
    # Environments & stages
    "canary", "preview", "demo", "sandbox", "lab", "poc",
    "prototype", "mvp", "alpha", "gamma", "rc", "nightly",
    "edge", "latest", "stable", "production", "prod",
    "pre", "preprod", "hotfix", "patch", "fix",
    # Debug & testing
    "debug", "trace", "profile", "benchmark", "perf",
    "stress", "load", "smoke", "e2e", "integration",
    "acceptance", "uat", "qa", "quality", "review",
    # Source control & artifacts
    "code", "repo", "svn", "hg", "mercurial", "bitbucket",
    "github", "source", "artifact", "nexus", "sonatype",
    "harbor", "quay", "ecr", "gcr", "acr",
    # Container & cluster infrastructure
    "container", "pod", "node", "cluster", "master", "slave",
    "replica", "shard", "primary", "secondary", "standby",
    "passive", "active", "main", "core", "central",
    # Scope & access
    "global", "local", "private", "public", "external",
    "mgmt", "management", "ops", "devops", "sre",
    "platform", "infra", "infrastructure",
    # Security
    "network", "firewall", "ids", "ips", "siem", "waf",
    "antivirus", "scan", "scanner", "pentest", "exploit",
    "vuln", "vulnerability", "patch2", "update", "upgrade",
    # Cloud services
    "aws", "azure", "gcp", "cloud", "s3", "cdn1", "cdn2",
    "assets1", "assets2", "static1", "static2",
    # API patterns
    "api-v1", "api-v2", "api-staging", "api-dev", "api-prod",
    "graphql-api", "graphql", "rest", "ws", "websocket", "grpc",
    # Email
    "mx1", "mx2", "mx3", "mail2", "mail3", "smtp2",
    "pop3", "imap2", "exchange", "owa", "autodiscover", "autoconfig",
    # Auth & identity
    "sso", "oauth", "cas", "ldap", "saml", "identity",
    "login", "auth", "auth0", "keycloak",
    # Storage
    "storage", "nas", "nfs", "ftp2", "sftp",
    "files", "share", "backup3",
    # Database
    "mariadb", "postgres", "couchdb", "neo4j", "clickhouse",
    "influxdb", "timescaledb", "cockroachdb", "dgraph", "arangodb",
    "mongodb", "couchbase",
    # Monitoring (expanded)
    "datadog", "newrelic", "splunk", "graylog", "loki",
    "tempo", "mimir", "thanos", "cortex", "jaeger", "zipkin",
    # CI/CD (expanded)
    "drone", "circleci", "teamcity", "bamboo", "buildbot",
    "argo", "argocd", "flux", "spinnaker", "concourse",
    "gocd", "woodpecker",
    # CMS & community
    "blog2", "cms", "forum", "community", "portal2",
    "intranet2", "kb", "knowledge", "faq",
    # Dev tools
    "sonar", "sonarqube", "artifactory", "jfrog", "verdaccio",
    "codecov", "coveralls", "renovate", "dependabot",
    # Security (expanded)
    "waf2", "ids2", "ips2", "soc", "csirt", "cert",
    "abuse", "security", "bugbounty", "hackerone",
    # Gaming, streaming & media
    "stream", "live", "video", "audio", "podcast",
    "radio", "tv", "broadcast", "rtmp", "hls",
    # Mobile
    "mobile", "m", "ios", "android", "app2", "pwa", "hybrid",
    # Networking
    "ns3", "ns4", "dns1", "dns2", "vpn2",
    "openvpn", "wireguard", "ipsec", "radius", "tacacs",
    # Regions
    "us", "eu", "ap", "sa", "af",
    "us-east", "us-west", "eu-west", "eu-central", "ap-south",
    # Misc common
    "web", "web2", "www2", "www3", "new", "old2",
    "legacy", "archive", "temp", "tmp", "scratch", "playground",
    # Ticketing
    "servicenow", "zendesk", "freshdesk", "osticket",
    "otrs", "rt", "redmine", "mantis",
    # Collaboration
    "sharepoint", "onedrive", "dropbox", "box",
    "drive", "calendar", "contacts",
    # E-commerce
    "shop2", "marketplace", "catalog", "products",
    "orders2", "shipping2", "returns", "refund",
    # Analytics (expanded)
    "matomo", "piwik", "plausible", "umami", "fathom",
    "segment", "mixpanel", "amplitude", "heap",
    # Virtualization
    "proxmox", "vmware", "esxi", "vcenter",
    "hyperv", "xen", "kvm", "ovirt", "openstack",
    # Container orchestration (expanded)
    "rancher", "portainer", "swarm", "mesos", "marathon",
    "istio", "linkerd", "envoy", "kong", "traefik2",
    # Backup (expanded)
    "veeam", "commvault", "bacula", "restic",
    "borg", "duplicati", "rclone",
]

def resolve_subdomain(subdomain: str, domain: str):
    hostname = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(hostname)
        return hostname, ip
    except:
        return None

def check_dns(url: str, auth=None) -> dict:
    findings = []
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    # Remove subdomínio se já tiver (pegar domínio raiz)
    parts = domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    # ── 1. Registros DNS básicos ─────────────────────────────────────────────
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    dns_records = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            dns_records[rtype] = [str(r) for r in answers]
        except:
            dns_records[rtype] = []

    a_records = dns_records.get("A", [])
    if a_records:
        findings.append({"severity": "info", "title": f"Registros A: {', '.join(a_records)}", "detail": "IPs do domínio.", "fix": ""})

    # ── 2. Zone Transfer (AXFR) ──────────────────────────────────────────────
    ns_records = dns_records.get("NS", [])
    zone_transfer_vuln = False
    for ns in ns_records:
        ns = ns.rstrip(".")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            names = [str(n) for n in zone.nodes.keys()]
            findings.append({
                "severity": "critical",
                "title": f"Zone Transfer (AXFR) permitido no NS: {ns}",
                "detail": f"O servidor DNS permite transferência de zona, expondo TODOS os registros DNS. Subdomínios encontrados: {', '.join(names[:20])}",
                "fix": "Restrinja transferências de zona apenas para servidores NS secundários autorizados.",
            })
            zone_transfer_vuln = True
        except:
            pass

    if not zone_transfer_vuln and ns_records:
        findings.append({"severity": "info", "title": "Zone Transfer bloqueado", "detail": "Servidores NS não permitem AXFR. Boa configuração.", "fix": ""})

    # ── 3. SPF / DMARC / DKIM (proteção contra email spoofing) ──────────────
    spf_found = False
    for txt in dns_records.get("TXT", []):
        if "v=spf1" in txt.lower():
            spf_found = True
            if "~all" in txt:
                findings.append({
                    "severity": "medium",
                    "title": "SPF configurado com ~all (softfail)",
                    "detail": f"SPF com ~all não bloqueia emails falsos, apenas os marca. Registro: {txt[:100]}",
                    "fix": "Mude ~all para -all para rejeitar emails não autorizados.",
                })
            elif "-all" in txt:
                findings.append({"severity": "info", "title": "SPF configurado corretamente (-all)", "detail": txt[:100], "fix": ""})

    if not spf_found:
        findings.append({
            "severity": "high",
            "title": "SPF ausente — domínio vulnerável a email spoofing",
            "detail": "Sem registro SPF, qualquer pessoa pode enviar emails fingindo ser do seu domínio.",
            "fix": "Adicione registro TXT: v=spf1 include:_spf.google.com -all (adapte ao seu provedor)",
        })

    dmarc_found = False
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for r in answers:
            txt = str(r)
            if "v=dmarc1" in txt.lower():
                dmarc_found = True
                if "p=none" in txt.lower():
                    findings.append({
                        "severity": "medium",
                        "title": "DMARC em modo monitoramento (p=none)",
                        "detail": "DMARC com p=none não protege contra spoofing, apenas monitora.",
                        "fix": "Mude para p=quarantine ou p=reject após analisar os relatórios.",
                    })
                else:
                    findings.append({"severity": "info", "title": "DMARC configurado", "detail": txt[:100], "fix": ""})
    except:
        pass

    if not dmarc_found:
        findings.append({
            "severity": "high",
            "title": "DMARC ausente",
            "detail": "Sem DMARC, emails falsificados do seu domínio não serão rejeitados pelos destinatários.",
            "fix": "Adicione: _dmarc.seudominio.com TXT 'v=DMARC1; p=reject; rua=mailto:dmarc@seudominio.com'",
        })

    # ── 4. Enumeração de subdomínios ─────────────────────────────────────────
    found_subs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(resolve_subdomain, sub, root_domain): sub for sub in COMMON_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                hostname, ip = result
                found_subs.append((hostname, ip))

    sensitive_subs = ["admin", "dev", "staging", "test", "beta", "old", "backup",
                      "db", "database", "jenkins", "gitlab", "git", "phpmyadmin",
                      "kibana", "grafana", "internal", "intranet",
                      "vault", "sentry", "prometheus", "elasticsearch", "redis",
                      "memcached", "rabbitmq", "kafka", "zookeeper", "consul",
                      "docker", "k8s", "kubernetes", "registry", "debug",
                      "sandbox", "lab", "poc", "pentest", "exploit", "vuln",
                      "sso", "oauth", "ldap", "keycloak", "sonarqube",
                      "argocd", "portainer", "proxmox", "vcenter", "splunk",
                      "rancher", "artifactory"]

    for hostname, ip in sorted(found_subs):
        sub = hostname.split(".")[0]
        if any(s in sub for s in sensitive_subs):
            findings.append({
                "severity": "medium",
                "title": f"Subdomínio sensível encontrado: {hostname}",
                "detail": f"IP: {ip}. Subdomínios de desenvolvimento/admin expostos podem ter menos proteção.",
                "fix": f"Verifique se {hostname} precisa estar acessível publicamente. Considere restringir por IP ou VPN.",
            })
        else:
            findings.append({"severity": "info", "title": f"Subdomínio: {hostname}", "detail": f"IP: {ip}", "fix": ""})

    if not found_subs:
        findings.append({"severity": "info", "title": "Nenhum subdomínio comum encontrado", "detail": "Wordlist básica não encontrou subdomínios ativos.", "fix": ""})

    # ── 5. DNSSEC verification ───────────────────────────────────────────────
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=5)
        findings.append({
            "severity": "info",
            "title": "DNSSEC configurado",
            "detail": "Registro DNSKEY encontrado. O domínio utiliza DNSSEC para proteger contra spoofing DNS.",
            "fix": "",
        })
    except dns.resolver.NoAnswer:
        findings.append({
            "severity": "medium",
            "title": "DNSSEC não configurado",
            "detail": "Nenhum registro DNSKEY encontrado. Sem DNSSEC, respostas DNS podem ser falsificadas.",
            "fix": "Configure DNSSEC no seu registrador de domínio e servidor DNS para proteger contra DNS spoofing.",
        })
    except dns.resolver.NXDOMAIN:
        findings.append({
            "severity": "medium",
            "title": "DNSSEC não configurado",
            "detail": "Consulta DNSKEY retornou NXDOMAIN. DNSSEC não está habilitado.",
            "fix": "Configure DNSSEC no seu registrador de domínio e servidor DNS para proteger contra DNS spoofing.",
        })
    except Exception:
        pass

    # ── 6. CAA record check ──────────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=5)
        caa_records = [str(r) for r in answers]
        if caa_records:
            cas = ", ".join(caa_records)
            findings.append({
                "severity": "info",
                "title": "Registro CAA configurado",
                "detail": f"CAs autorizadas a emitir certificados: {cas}",
                "fix": "",
            })
    except dns.resolver.NoAnswer:
        findings.append({
            "severity": "medium",
            "title": "Registro CAA ausente",
            "detail": "Sem registro CAA, qualquer Autoridade Certificadora pode emitir certificados para o domínio.",
            "fix": "Adicione registros CAA para restringir quais CAs podem emitir certificados. Ex: 0 issue \"letsencrypt.org\"",
        })
    except dns.resolver.NXDOMAIN:
        findings.append({
            "severity": "medium",
            "title": "Registro CAA ausente",
            "detail": "Sem registro CAA, qualquer Autoridade Certificadora pode emitir certificados para o domínio.",
            "fix": "Adicione registros CAA para restringir quais CAs podem emitir certificados. Ex: 0 issue \"letsencrypt.org\"",
        })
    except Exception:
        pass

    return {"module": "DNS / Subdomains", "icon": "ti-network", "findings": findings}
