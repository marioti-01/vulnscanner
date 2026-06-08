"""
Circuit Breaker — VulnScanner v6
Evita que módulos travados bloqueiem o scan inteiro.
Implementa padrão: CLOSED → OPEN → HALF-OPEN.
"""

import time
import threading
import concurrent.futures
from enum import Enum
from typing import Callable, Any


class State(Enum):
    CLOSED    = "closed"     # Normal — chamadas passam
    OPEN      = "open"       # Falhou — bloqueia chamadas
    HALF_OPEN = "half_open"  # Testando recuperação


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        timeout: float = 90.0,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.timeout = timeout

        self._state = State.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._lock = threading.Lock()

    @property
    def state(self):
        with self._lock:
            if self._state == State.OPEN:
                if time.monotonic() - self._last_failure_time > self.recovery_timeout:
                    self._state = State.HALF_OPEN
            return self._state

    def _on_success(self):
        with self._lock:
            self._failure_count = 0
            self._state = State.CLOSED

    def _on_failure(self):
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.failure_threshold:
                self._state = State.OPEN

    def call(self, fn: Callable, *args, **kwargs) -> Any:
        """
        Executa fn com timeout e circuit breaker.
        Lança CircuitOpenError se o circuito estiver aberto.
        """
        if self.state == State.OPEN:
            raise CircuitOpenError(f"Módulo '{self.name}' desabilitado temporariamente após falhas repetidas.")

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(fn, *args, **kwargs)
            try:
                result = future.result(timeout=self.timeout)
                self._on_success()
                return result
            except concurrent.futures.TimeoutError:
                self._on_failure()
                raise ModuleTimeoutError(
                    f"Módulo '{self.name}' excedeu timeout de {self.timeout}s."
                )
            except CircuitOpenError:
                raise
            except Exception as e:
                self._on_failure()
                raise ModuleExecutionError(f"Módulo '{self.name}' falhou: {e}") from e

    def reset(self):
        with self._lock:
            self._state = State.CLOSED
            self._failure_count = 0


class CircuitOpenError(Exception):
    pass

class ModuleTimeoutError(Exception):
    pass

class ModuleExecutionError(Exception):
    pass


# ── Registry de breakers por módulo ──────────────────────────────────────────
_breakers: dict[str, CircuitBreaker] = {}
_breakers_lock = threading.Lock()

MODULE_TIMEOUTS = {
    "Crawler / Spider":      60,
    "SSL/TLS":               20,
    "Headers HTTP":          20,
    "Port Scanner":          90,
    "DNS / Subdomains":      60,
    "CORS Policy":           20,
    "Tecnologias / WAF":     30,
    "Redirects":             20,
    "Auth Flow":             30,
    "CVE Lookup":            60,
    "OWASP Web":             120,
    "Blind SQL Injection":   180,
    "IDOR":                  120,
    "SSRF":                  90,
    "XXE":                   60,
    "Attack Chain Engine":   90,
}


def get_breaker(module_name: str) -> CircuitBreaker:
    with _breakers_lock:
        if module_name not in _breakers:
            timeout = MODULE_TIMEOUTS.get(module_name, 60)
            _breakers[module_name] = CircuitBreaker(
                name=module_name,
                failure_threshold=2,
                recovery_timeout=60.0,
                timeout=float(timeout),
            )
        return _breakers[module_name]


def safe_run_module(fn: Callable, module_name: str, icon: str, *args, **kwargs) -> dict:
    """
    Executa um módulo de scan com circuit breaker.
    Sempre retorna um dict válido, mesmo em caso de falha.
    """
    breaker = get_breaker(module_name)
    try:
        return breaker.call(fn, *args, **kwargs)
    except ModuleTimeoutError as e:
        return {
            "module": module_name,
            "icon": icon,
            "findings": [{
                "severity": "info",
                "title": f"⏱ Timeout: {module_name}",
                "detail": str(e),
                "fix": "O módulo excedeu o tempo limite. Tente com perfil 'stealth' (mais lento e cuidadoso).",
            }],
        }
    except CircuitOpenError as e:
        return {
            "module": module_name,
            "icon": icon,
            "findings": [{
                "severity": "info",
                "title": f"⚡ Módulo desabilitado temporariamente: {module_name}",
                "detail": str(e),
                "fix": "O módulo falhou repetidamente. Será reativado automaticamente em 60s.",
            }],
        }
    except Exception as e:
        return {
            "module": module_name,
            "icon": icon,
            "findings": [{
                "severity": "info",
                "title": f"Erro no módulo: {module_name}",
                "detail": str(e),
                "fix": "",
            }],
        }


def get_breakers_status() -> list:
    """Retorna status de todos os circuit breakers."""
    with _breakers_lock:
        return [
            {
                "module": name,
                "state": b.state.value,
                "failures": b._failure_count,
                "timeout": b.timeout,
            }
            for name, b in _breakers.items()
        ]
