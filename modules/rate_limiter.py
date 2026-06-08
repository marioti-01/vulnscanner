"""
Rate Limiter — controla o ritmo de requisições para não derrubar o alvo
e evitar acionamento de alertas de segurança.
"""

import time
import threading
from collections import deque


class RateLimiter:
    """
    Token bucket + sliding window rate limiter.
    Garante no máximo `max_per_second` requisições por segundo
    e `max_per_minute` por minuto.
    """

    def __init__(self, max_per_second: float = 5.0, max_per_minute: int = 120):
        self.max_per_second = max_per_second
        self.max_per_minute = max_per_minute
        self._lock = threading.Lock()
        self._minute_window: deque = deque()  # timestamps das últimas reqs
        self._last_request: float = 0.0

    def wait(self):
        """Bloqueia até que seja seguro fazer a próxima requisição."""
        with self._lock:
            now = time.monotonic()

            # ── Sliding window: máx por minuto ──────────────────────────
            cutoff = now - 60.0
            while self._minute_window and self._minute_window[0] < cutoff:
                self._minute_window.popleft()

            if len(self._minute_window) >= self.max_per_minute:
                sleep_time = 60.0 - (now - self._minute_window[0]) + 0.05
                if sleep_time > 0:
                    time.sleep(sleep_time)
                now = time.monotonic()

            # ── Token bucket: máx por segundo ───────────────────────────
            min_interval = 1.0 / self.max_per_second
            elapsed = now - self._last_request
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
                now = time.monotonic()

            self._last_request = now
            self._minute_window.append(now)

    def reset(self):
        with self._lock:
            self._minute_window.clear()
            self._last_request = 0.0


# Perfis prontos
PROFILES = {
    "stealth":     RateLimiter(max_per_second=0.5, max_per_minute=20),   # Furtivo
    "normal":      RateLimiter(max_per_second=3.0, max_per_minute=100),  # Padrão
    "aggressive":  RateLimiter(max_per_second=10.0, max_per_minute=300), # Rápido
}

# Limiter global padrão (pode ser substituído pelo app)
_default = PROFILES["normal"]


def get_limiter(profile: str = "normal") -> RateLimiter:
    return PROFILES.get(profile, _default)
