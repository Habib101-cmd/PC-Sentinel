import time
from collections import defaultdict, deque
from threading import Lock


class SlidingWindowLimiter:
    """Compte des événements dans une fenêtre glissante (en mémoire, un seul processus)."""

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def _purge(self, key: str, now: float) -> deque | None:
        events = self._events.get(key)
        if events is None:
            return None
        while events and now - events[0] > self.window:
            events.popleft()
        if not events:
            del self._events[key]
            return None
        return events

    def retry_after(self, key: str) -> int:
        """Secondes à attendre avant de pouvoir réessayer (0 si autorisé)."""
        now = time.monotonic()
        with self._lock:
            events = self._purge(key, now)
            if events is None or len(events) < self.limit:
                return 0
            return int(self.window - (now - events[0])) + 1

    def add(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._events) > 10_000:  # évite une croissance sans fin
                for old_key in list(self._events):
                    self._purge(old_key, now)
            self._events[key].append(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


# 5 échecs par couple (adresse, nom d'utilisateur) : un attaquant ne peut pas
# verrouiller le compte d'un autre depuis une autre adresse.
login_user_limiter = SlidingWindowLimiter(limit=5, window_seconds=15 * 60)
# 20 échecs par adresse, tous noms confondus : bloque le « password spraying ».
login_ip_limiter = SlidingWindowLimiter(limit=20, window_seconds=15 * 60)
# 10 créations de compte par heure et par adresse.
register_ip_limiter = SlidingWindowLimiter(limit=10, window_seconds=60 * 60)


def reset_all() -> None:
    for limiter in (login_user_limiter, login_ip_limiter, register_ip_limiter):
        limiter.reset()
