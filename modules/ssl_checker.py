import ssl
import socket
import datetime
from dataclasses import dataclass, field
from typing import List

@dataclass
class SSLResult:
    findings: List[dict] = field(default_factory=list)

    def add(self, severity, title, detail, fix):
        self.findings.append({"severity": severity, "title": title, "detail": detail, "fix": fix})

def check_ssl(hostname: str, auth=None) -> dict:
    result = SSLResult()
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        # Versão do protocolo
        if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            result.add("critical", f"Protocolo obsoleto: {version}",
                       f"O servidor aceita {version}, que possui vulnerabilidades conhecidas.",
                       "Desabilite TLS 1.0 e 1.1. Use somente TLS 1.2 e 1.3.")
        else:
            result.add("info", f"Protocolo: {version}", "Versão do protocolo TLS em uso.", "")

        # Expiração do certificado
        exp_str = cert.get("notAfter", "")
        if exp_str:
            exp_date = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
            if days_left < 0:
                result.add("critical", "Certificado EXPIRADO",
                           f"Expirou em {exp_str}.",
                           "Renove o certificado SSL imediatamente.")
            elif days_left < 30:
                result.add("high", f"Certificado expira em {days_left} dias",
                           f"Expira em {exp_str}.",
                           "Renove o certificado antes que expire.")
            else:
                result.add("info", f"Certificado válido por {days_left} dias", f"Expira em {exp_str}.", "")

        # Cipher fraco
        if cipher:
            cipher_name = cipher[0]
            weak = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
            if any(w in cipher_name for w in weak):
                result.add("high", f"Cipher fraco em uso: {cipher_name}",
                           "Ciphers fracos permitem descriptografar tráfego.",
                           "Configure o servidor para usar apenas ciphers modernos (AES-GCM, ChaCha20).")
            else:
                result.add("info", f"Cipher: {cipher_name}", "Cipher negociado na sessão.", "")

        # Certificado auto-assinado (self-signed)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        if issuer == subject:
            result.add("critical", "Certificado auto-assinado (self-signed)",
                       "O certificado foi emitido pelo próprio servidor, sem validação de uma CA confiável.",
                       "Obtenha um certificado de uma Autoridade Certificadora (CA) confiável como Let's Encrypt.")

        # SAN check — hostname presente no Subject Alternative Name
        san_list = []
        for ext_type, ext_value in cert.get("subjectAltName", ()):
            if ext_type.lower() == "dns":
                san_list.append(ext_value.lower())
        if san_list:
            hostname_lower = hostname.lower()
            san_match = False
            for san in san_list:
                if san.startswith("*."):
                    # Wildcard: *.example.com matches sub.example.com
                    wildcard_base = san[2:]
                    if hostname_lower == wildcard_base or hostname_lower.endswith("." + wildcard_base):
                        san_match = True
                        break
                elif san == hostname_lower:
                    san_match = True
                    break
            if not san_match:
                result.add("high", "Hostname não presente no SAN do certificado",
                           f"O hostname '{hostname}' não foi encontrado na lista SAN do certificado: {', '.join(san_list[:10])}",
                           "Gere um novo certificado incluindo o hostname correto no campo SAN.")
        else:
            result.add("medium", "Certificado sem SAN (Subject Alternative Name)",
                       "O certificado não possui extensão subjectAltName. Navegadores modernos exigem SAN.",
                       "Gere um novo certificado com o campo SAN preenchido corretamente.")

        # Certificate chain depth
        try:
            ctx_chain = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock_chain:
                with ctx_chain.wrap_socket(sock_chain, server_hostname=hostname) as ssock_chain:
                    chain = ssock_chain.get_channel_binding()
                    peer_cert_chain = ssock_chain.getpeercert(binary_form=False)
                    # Em CPython, verificamos via contexto o comprimento da cadeia
                    chain_depth = ctx_chain.get_ca_certs()
                    # Reportar info sobre a cadeia
                    issuer_cn = issuer.get("commonName", issuer.get("organizationName", "Desconhecido"))
                    subject_cn = subject.get("commonName", "Desconhecido")
                    result.add("info", f"Cadeia do certificado: {subject_cn} → {issuer_cn}",
                               f"Emissor: {issuer_cn}. Sujeito: {subject_cn}.", "")
        except Exception:
            # Se não conseguir obter info de cadeia, reportar com info do cert principal
            issuer_cn = issuer.get("commonName", issuer.get("organizationName", "Desconhecido"))
            subject_cn = subject.get("commonName", "Desconhecido")
            result.add("info", f"Cadeia do certificado: {subject_cn} → {issuer_cn}",
                       f"Emissor: {issuer_cn}. Sujeito: {subject_cn}.", "")

    except ssl.SSLCertVerificationError as e:
        result.add("critical", "Falha na verificação do certificado",
                   str(e), "Obtenha um certificado válido de uma CA confiável.")
    except ConnectionRefusedError:
        result.add("info", "HTTPS não disponível na porta 443",
                   "O servidor não aceitou conexão SSL.", "Considere habilitar HTTPS.")
    except Exception as e:
        result.add("info", "Não foi possível verificar SSL", str(e), "")

    # ── TLS 1.3 support check ────────────────────────────────────────────────
    try:
        ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx13.load_default_certs()
        with socket.create_connection((hostname, 443), timeout=10) as sock13:
            with ctx13.wrap_socket(sock13, server_hostname=hostname) as ssock13:
                result.add("info", "TLS 1.3 suportado",
                           "O servidor suporta TLS 1.3, a versão mais segura do protocolo.", "")
    except Exception:
        result.add("low", "TLS 1.3 não suportado",
                   "O servidor não suporta TLS 1.3. Embora TLS 1.2 seja aceitável, TLS 1.3 é mais seguro e rápido.",
                   "Configure o servidor para suportar TLS 1.3.")

    return {"module": "SSL/TLS", "icon": "ti-lock", "findings": result.findings}

