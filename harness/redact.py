"""Secret redaction shared by the worker (results to the planner) and the report generator."""
import re

# Secrets are kept in evidence files but redacted from what goes back to the planner (and OpenRouter).
REDACT = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED AWS KEY ID]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}\b"), "[REDACTED API KEY]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED JWT]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\s*[:=]\s*)(['\"]?)(?!\[REDACTED)[^\s'\",;]{4,}\3"),
     r"\1\2[REDACTED]"),
]


def redact(x):
    if isinstance(x, str):
        for pat, rep in REDACT:
            x = pat.sub(rep, x)
        return x
    if isinstance(x, list):
        return [redact(i) for i in x]
    if isinstance(x, dict):
        return {k: redact(v) for k, v in x.items()}
    return x
