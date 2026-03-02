from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .models import RecommendedAction, Signal

DECEPTIVE_KEYWORDS = {
    "login",
    "verify",
    "update",
    "secure",
    "password",
    "account",
    "invoice",
    "bank",
    "confirm",
    "suspended",
}

ALLOWLIST = {
    "google.com",
    "apple.com",
    "microsoft.com",
    "paypal.com",
}

CONFUSABLE_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})


@dataclass
class AnalysisResult:
    original_url: str
    normalized_url: str
    risk_score: int
    risk_label: str
    signals: list[Signal]
    recommended_actions: list[RecommendedAction]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        curr = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = curr[j - 1] + 1
            delete_cost = prev[j] + 1
            replace_cost = prev[j - 1] + (char_a != char_b)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev = curr
    return prev[-1]


def _registrable_domain(hostname: str) -> str:
    parts = [part for part in hostname.split(".") if part]
    if len(parts) < 2:
        return hostname
    return ".".join(parts[-2:])


def normalize_url(raw_url: str) -> tuple[str, object]:
    parsed = urlsplit(raw_url.strip())

    if not parsed.scheme:
        raise ValueError("URL must include scheme (http:// or https://).")

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https.")

    if not parsed.hostname:
        raise ValueError("URL must include a valid hostname.")

    host = parsed.hostname.lower()

    default_port = 80 if scheme == "http" else 443
    port = parsed.port
    include_port = bool(port and port != default_port)

    if parsed.username or parsed.password:
        auth = parsed.username or ""
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        netloc = f"{auth}@{host}"
    else:
        netloc = host

    if include_port:
        netloc = f"{netloc}:{port}"

    encoded_path = quote(unquote(parsed.path or ""), safe="/%:@").rstrip("/")
    normalized = urlunsplit((scheme, netloc, encoded_path, parsed.query, ""))

    return normalized, parsed


def _score_to_label(score: int) -> str:
    if score >= 67:
        return "high"
    if score >= 34:
        return "medium"
    return "low"


def _build_actions(score: int, has_brand_signal: bool) -> list[RecommendedAction]:
    actions = [
        RecommendedAction(
            id="verify_sender",
            label="Verify the sender before sharing sensitive info.",
        ),
        RecommendedAction(
            id="check_domain",
            label="Double-check the domain spelling and URL path.",
        ),
    ]

    if score >= 67:
        actions.append(
            RecommendedAction(
                id="do_not_open",
                label="Do not sign in or submit personal data on this link.",
            )
        )
    if has_brand_signal:
        actions.append(
            RecommendedAction(
                id="visit_directly",
                label="Open the known official website directly instead of this link.",
            )
        )
    return actions


def analyze_url(raw_url: str, suspicious_tlds: set[str]) -> AnalysisResult:
    normalized_url, parsed = normalize_url(raw_url)
    hostname = (parsed.hostname or "").lower()

    score = 10
    signals: list[Signal] = []

    if parsed.scheme.lower() == "https":
        score -= 8
        signals.append(
            Signal(id="https_present", severity="info", message="Uses HTTPS.")
        )
    else:
        score += 12
        signals.append(
            Signal(
                id="http_scheme",
                severity="medium",
                message="Uses HTTP instead of HTTPS.",
            )
        )

    try:
        ipaddress.ip_address(hostname)
        score += 25
        signals.append(
            Signal(
                id="ip_hostname",
                severity="high",
                message="Hostname is an IP address.",
            )
        )
    except ValueError:
        pass

    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld and tld in suspicious_tlds:
        score += 18
        signals.append(
            Signal(
                id="suspicious_tld",
                severity="high",
                message=f"Top-level domain .{tld} is commonly abused.",
            )
        )

    subdomain_count = max(0, len([p for p in hostname.split(".") if p]) - 2)
    if subdomain_count >= 3:
        score += 12
        signals.append(
            Signal(
                id="many_subdomains",
                severity="medium",
                message="URL has many subdomains, which can hide the real destination.",
            )
        )

    if len(normalized_url) >= 120:
        score += 10
        signals.append(
            Signal(
                id="long_url",
                severity="medium",
                message="URL is unusually long.",
            )
        )

    lower_url = normalized_url.lower()
    keyword_hits = [word for word in DECEPTIVE_KEYWORDS if word in lower_url]
    if keyword_hits:
        score += min(20, 4 * len(keyword_hits))
        signals.append(
            Signal(
                id="deceptive_keywords",
                severity="high" if len(keyword_hits) >= 3 else "medium",
                message="Contains common phishing lure keywords.",
            )
        )

    if "@" in normalized_url:
        score += 20
        signals.append(
            Signal(
                id="at_symbol",
                severity="high",
                message="Contains '@' which can obscure the real destination.",
            )
        )

    if "xn--" in hostname:
        score += 18
        signals.append(
            Signal(
                id="punycode",
                severity="high",
                message="Hostname includes punycode (xn--) and may be a lookalike.",
            )
        )

    if parsed.port and parsed.port not in {80, 443}:
        score += 14
        signals.append(
            Signal(
                id="unusual_port",
                severity="medium",
                message=f"Uses unusual port {parsed.port}.",
            )
        )

    if "%25" in lower_url or re.search(r"(?:%2f){2,}", lower_url):
        score += 15
        signals.append(
            Signal(
                id="double_encoding",
                severity="high",
                message="Contains signs of double or repeated URL encoding.",
            )
        )

    brand_signal = False
    reg_domain = _registrable_domain(hostname)
    root = reg_domain.split(".")[0]
    root_mapped = root.translate(CONFUSABLE_MAP)
    for trusted in ALLOWLIST:
        trusted_root = trusted.split(".")[0]
        if reg_domain == trusted:
            score -= 12
            signals.append(
                Signal(
                    id="trusted_allowlist",
                    severity="info",
                    message=f"Domain matches trusted site {trusted}.",
                )
            )
            break
        if root_mapped == trusted_root and reg_domain != trusted:
            score += 22
            brand_signal = True
            signals.append(
                Signal(
                    id="lookalike_domain",
                    severity="high",
                    message=f"Domain resembles trusted brand {trusted}.",
                )
            )
            break
        if _levenshtein(root, trusted_root) == 1:
            score += 22
            brand_signal = True
            signals.append(
                Signal(
                    id="lookalike_domain",
                    severity="high",
                    message=f"Domain spelling is close to trusted brand {trusted}.",
                )
            )
            break

    score = max(0, min(100, score))

    if not signals:
        signals.append(
            Signal(
                id="no_major_flags",
                severity="info",
                message="No major phishing signals were detected in this URL string.",
            )
        )

    return AnalysisResult(
        original_url=raw_url,
        normalized_url=normalized_url,
        risk_score=score,
        risk_label=_score_to_label(score),
        signals=signals,
        recommended_actions=_build_actions(score, brand_signal),
    )
