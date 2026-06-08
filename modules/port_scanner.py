import socket
import concurrent.futures
from typing import List, Tuple

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle DB", 2375: "Docker API (sem TLS!)",
    2379: "etcd", 2181: "ZooKeeper",
    3000: "Grafana/Node.js", 3306: "MySQL", 3389: "RDP",
    4243: "Docker API Alt", 4444: "Metasploit default",
    5000: "Flask/Dev Server", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 6379: "Redis", 6443: "Kubernetes API",
    8000: "Django/Dev Server", 8080: "HTTP Alt", 8081: "HTTP Proxy Alt",
    8161: "ActiveMQ", 8443: "HTTPS Alt", 8888: "Jupyter Notebook",
    9090: "Prometheus", 9100: "Node Exporter", 9200: "Elasticsearch",
    10250: "Kubelet", 11211: "Memcached", 15672: "RabbitMQ Management",
    27017: "MongoDB", 27018: "MongoDB", 50000: "Jenkins Agent",
}

DANGEROUS_PORTS = {
    21: ("high", "FTP aberto", "FTP transmite credenciais em texto plano.", "Desabilite FTP. Use SFTP ou SCP."),
    23: ("critical", "Telnet aberto", "Telnet transmite tudo sem criptografia, incluindo senhas.", "Desabilite Telnet imediatamente. Use SSH."),
    2375: ("critical", "Docker API sem TLS exposta", "API do Docker sem autenticação permite controle total do host.", "Nunca exponha a API Docker sem TLS e autenticação."),
    2379: ("critical", "etcd exposto", "etcd sem autenticação expõe todos os secrets do Kubernetes.", "Habilite autenticação e TLS no etcd. Nunca exponha à internet."),
    4243: ("critical", "Docker API Alt exposta", "API alternativa do Docker sem TLS permite controle total do host.", "Desabilite esta porta. Use apenas a API com TLS na 2376."),
    4444: ("critical", "Porta padrão do Metasploit aberta", "Possível backdoor ou sessão Meterpreter ativa.", "Investigue imediatamente. Feche a porta."),
    10250: ("critical", "Kubelet API exposto", "API do Kubelet sem autenticação permite execução de comandos em pods.", "Habilite autenticação no Kubelet. Restrinja acesso."),
    5601: ("high", "Kibana exposto", "Kibana sem autenticação expõe dados de logs e índices Elasticsearch.", "Habilite segurança no Kibana. Restrinja acesso por IP."),
    5900: ("high", "VNC exposto", "VNC pode ter autenticação fraca ou nenhuma.", "Restrinja VNC ao localhost. Use túnel SSH se necessário."),
    6379: ("high", "Redis exposto sem autenticação", "Redis sem autenticação permite leitura/escrita total dos dados.", "Adicione autenticação ao Redis. Restrinja ao localhost."),
    6443: ("high", "Kubernetes API exposto", "API do Kubernetes pode permitir acesso não autorizado ao cluster.", "Configure RBAC. Use autenticação forte. Nunca exponha sem VPN."),
    9200: ("high", "Elasticsearch exposto", "Elasticsearch sem autenticação expõe todos os dados.", "Habilite X-Pack Security. Restrinja acesso por IP."),
    11211: ("high", "Memcached exposto", "Memcached sem autenticação permite leitura/escrita de cache e pode ser usado em DDoS amplification.", "Restrinja Memcached ao localhost. Use SASL para autenticação."),
    2181: ("high", "ZooKeeper exposto", "ZooKeeper exposto pode permitir manipulação de configuração de cluster.", "Restrinja acesso ao ZooKeeper por firewall. Use autenticação SASL."),
    27017: ("high", "MongoDB exposto", "MongoDB sem autenticação expõe todos os dados.", "Habilite autenticação no MongoDB. Restrinja o bind address."),
    50000: ("high", "Jenkins Agent exposto", "Porta do agente Jenkins pode permitir execução remota de código.", "Restrinja acesso à porta do agente. Use autenticação."),
    1433: ("medium", "SQL Server exposto", "Banco de dados exposto à internet é um risco alto.", "Restrinja acesso ao SQL Server por firewall."),
    3306: ("medium", "MySQL exposto", "Banco de dados exposto à internet é um risco alto.", "Configure bind-address=127.0.0.1 e restrinja por firewall."),
    3389: ("medium", "RDP exposto", "RDP é alvo frequente de brute force e exploits (BlueKeep).", "Restrinja RDP por VPN. Habilite NLA."),
    5432: ("medium", "PostgreSQL exposto", "Banco de dados exposto à internet é um risco alto.", "Configure pg_hba.conf para restringir acesso."),
    9090: ("medium", "Prometheus exposto", "Prometheus exposto pode revelar métricas internas e dados sensíveis.", "Restrinja acesso ao Prometheus. Use autenticação reversa proxy."),
    15672: ("medium", "RabbitMQ Management exposto", "Painel administrativo do RabbitMQ pode ter credenciais padrão (guest/guest).", "Mude credenciais padrão. Restrinja acesso à interface de gerenciamento."),
}

def scan_port(host: str, port: int, timeout: float = 1.5) -> Tuple[int, bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        banner = ""
        if result == 0:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(256).decode(errors="ignore").split("\n")[0][:80]
            except:
                pass
        sock.close()
        return port, result == 0, banner
    except:
        return port, False, ""

def check_ports(url: str, auth=None) -> dict:
    findings = []
    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        ip = socket.gethostbyname(hostname)
        findings.append({"severity": "info", "title": f"IP resolvido: {ip}", "detail": f"Hostname: {hostname}", "fix": ""})
    except:
        findings.append({"severity": "info", "title": "Não foi possível resolver o hostname", "detail": hostname, "fix": ""})
        return {"module": "Port Scanner", "icon": "ti-radar", "findings": findings}

    open_ports = []

    # ── Adaptive timeout: começa com 1.0s, aumenta para 3.0s se primeiras 5 portas falharem
    initial_timeout = 1.0
    probe_ports = list(COMMON_PORTS.keys())[:5]
    probe_all_timeout = True

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        probe_futures = {ex.submit(scan_port, hostname, port, initial_timeout): port for port in probe_ports}
        for future in concurrent.futures.as_completed(probe_futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))
                probe_all_timeout = False

    adaptive_timeout = 3.0 if probe_all_timeout else initial_timeout

    # Se houve timeout em todas as 5 primeiras, re-escanear essas 5 com timeout maior
    remaining_ports = [p for p in COMMON_PORTS if p not in probe_ports]
    if probe_all_timeout:
        rescan_ports = probe_ports + remaining_ports
    else:
        rescan_ports = remaining_ports

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, hostname, port, adaptive_timeout): port for port in rescan_ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                # Evitar duplicatas das probe ports que já abriram
                if not any(p == port for p, _ in open_ports):
                    open_ports.append((port, banner))

    open_ports.sort()

    if not open_ports:
        findings.append({"severity": "info", "title": "Nenhuma porta comum aberta encontrada", "detail": "Apenas portas comuns foram verificadas.", "fix": ""})
    else:
        for port, banner in open_ports:
            service = COMMON_PORTS.get(port, "Desconhecido")
            if port in DANGEROUS_PORTS:
                sev, title, detail, fix = DANGEROUS_PORTS[port]
                detail_full = detail
                if banner:
                    detail_full += f" Banner: {banner}"
                findings.append({"severity": sev, "title": f"{title} (:{port})", "detail": detail_full, "fix": fix})
            else:
                findings.append({
                    "severity": "info",
                    "title": f"Porta {port} ({service}) aberta",
                    "detail": f"Banner: {banner}" if banner else "Sem banner.",
                    "fix": "Verifique se esta porta precisa estar exposta à internet.",
                })

    return {"module": "Port Scanner", "icon": "ti-radar", "findings": findings}
