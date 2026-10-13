import logging
import sys

logger = logging.getLogger("pcsentinel")

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def log_event(event: str, *, level: int = logging.INFO, **fields) -> None:
    """Journalise un événement. Ne jamais passer de mot de passe, de jeton ou de nom saisi."""
    details = " ".join(f"{key}={str(value).replace(chr(10), ' ')[:100]}" for key, value in fields.items())
    logger.log(level, "%s %s", event, details)
