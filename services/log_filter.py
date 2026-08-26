import logging
import re

# Module-level logger — logging configuration is initialized in app.py lifespan
logger = logging.getLogger("apix.fetcher")


class SensitiveDataFilter(logging.Filter):
    """
    Custom logging filter that automatically redacts sensitive query parameters,
    proxy basic auth credentials, authorization tokens, and secrets from all log messages.
    """

    SENSITIVE_PARAM_REGEX = re.compile(
        r"(?i)([\?&](?:api[_-]?key|token|access[_-]?token|auth|secret|password|passwd|pwd|key|session[_-]?id|jwt|bearer|signature|sig|credential)=)([^&\s#]+)"
    )
    PROXY_CREDS_REGEX = re.compile(r"(?i)(https?://[^:\s/@]+):([^@\s/]+)@")
    AUTH_HEADER_REGEX = re.compile(
        r"(?i)(bearer\s+|token\s+|x-api-key:\s*)[a-zA-Z0-9_\-\.]{6,}"
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            msg = self.SENSITIVE_PARAM_REGEX.sub(r"\1***REDACTED***", msg)
            msg = self.PROXY_CREDS_REGEX.sub(r"\1:***REDACTED***@", msg)
            msg = self.AUTH_HEADER_REGEX.sub(r"\1***REDACTED***", msg)
            record.msg = msg
        if record.args:
            new_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    arg = self.SENSITIVE_PARAM_REGEX.sub(r"\1***REDACTED***", arg)
                    arg = self.PROXY_CREDS_REGEX.sub(r"\1:***REDACTED***@", arg)
                    arg = self.AUTH_HEADER_REGEX.sub(r"\1***REDACTED***", arg)
                new_args.append(arg)
            record.args = tuple(new_args)
        return True


def sanitize_url(url: str) -> str:
    """Masks sensitive query parameters from URLs."""
    if not url:
        return ""
    return SensitiveDataFilter.SENSITIVE_PARAM_REGEX.sub(r"\1***REDACTED***", str(url))


def sanitize_proxy_url(proxy_url: str | None) -> str | None:
    """Masks username/password credentials in proxy URLs."""
    if not proxy_url:
        return None
    return SensitiveDataFilter.PROXY_CREDS_REGEX.sub(
        r"\1:***REDACTED***@", str(proxy_url)
    )
