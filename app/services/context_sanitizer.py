import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Redaction:
    secret_type: str
    placeholder: str
    line: int


@dataclass(frozen=True, slots=True)
class SanitizedContext:
    text: str
    redactions: tuple[Redaction, ...]

    @property
    def summary(self) -> dict:
        counts = Counter(item.secret_type for item in self.redactions)
        return {
            "count": len(self.redactions),
            "types": dict(sorted(counts.items())),
            "lines": sorted({item.line for item in self.redactions}),
        }


@dataclass(frozen=True, slots=True)
class SecretRule:
    secret_type: str
    pattern: re.Pattern[str]


RULES = (
    SecretRule(
        "private_key",
        re.compile(
            r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----.*?"
            r"-----END (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    SecretRule(
        "credential_assignment",
        re.compile(
            r"(?im)(?:^|[,{\s])(?:[\"']?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|private[_-]?key|openai_api_key|github_token|"
            r"aws_secret_access_key)[\"']?\s*[:=]\s*[\"'])(?P<secret>[^\"'\n]{6,})(?=[\"'])"
        ),
    ),
    SecretRule(
        "environment_credential",
        re.compile(
            r"(?im)^\s*(?:OPENAI_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|DATABASE_PASSWORD|"
            r"CLIENT_SECRET|AUTH_TOKEN|ACCESS_TOKEN)\s*=\s*[\"']?(?P<secret>(?!<REDACTED_SECRET_)[^\"'\s#]{8,})[\"']?"
        ),
    ),
    SecretRule(
        "connection_password",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/@]+:"
            r"(?P<secret>[^@\s/]+)(?=@)"
        ),
    ),
    SecretRule("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b")),
    SecretRule("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    SecretRule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    SecretRule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    SecretRule("bearer_token", re.compile(r"(?i)(?<=Bearer )[A-Za-z0-9._~+/=-]{16,}")),
)


def _replace_secret(match: re.Match[str], placeholder: str) -> str:
    if "secret" not in match.re.groupindex:
        return placeholder
    secret = match.group("secret")
    start = match.start("secret") - match.start()
    end = start + len(secret)
    value = match.group(0)
    return f"{value[:start]}{placeholder}{value[end:]}"


def sanitize_context(context: str) -> SanitizedContext:
    text = context
    redactions: list[Redaction] = []

    for rule in RULES:
        current_text = text

        def replace(
            match: re.Match[str],
            *,
            current_rule: SecretRule = rule,
            source_text: str = current_text,
        ) -> str:
            index = len(redactions) + 1
            placeholder = f"<REDACTED_SECRET_{index}:{current_rule.secret_type.upper()}>"
            secret_start = match.start("secret") if "secret" in match.re.groupindex else match.start()
            line = source_text.count("\n", 0, secret_start) + 1
            redactions.append(
                Redaction(
                    secret_type=current_rule.secret_type,
                    placeholder=placeholder,
                    line=line,
                )
            )
            return _replace_secret(match, placeholder)

        text = rule.pattern.sub(replace, text)

    return SanitizedContext(text=text, redactions=tuple(redactions))
