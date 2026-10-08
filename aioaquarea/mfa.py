"""Helpers for inspecting and completing Panasonic's MFA challenge page.

Everything here is experimental. The functions that produce text for logs
(``describe_response``) are pure and never include cookies, tokens, state
values, e-mail addresses, query string values or input values.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

MAX_REDIRECTS = 5

# Input names that look like a one-time code field (compared in lower case).
CODE_INPUT_NAMES = frozenset({"code", "otp", "otpcode", "verificationcode"})

KEYWORDS = ("guardian", "otp", "email", "sms", "totp", "recovery")


def _path(url: str) -> str:
    """Return only the path of a URL (no scheme query, fragment)."""
    parsed = urllib.parse.urlparse(url or "")
    return parsed.path or "/"


def _query_names(url: str) -> list[str]:
    return sorted(urllib.parse.parse_qs(urllib.parse.urlparse(url or "").query))


def describe_response(
    status: int,
    location: str | None = None,
    content_type: str | None = None,
    body: str | None = None,
) -> str:
    """Describe one HTTP hop without leaking sensitive data.

    Logs the status, the path only, and for HTML the title, h1/h2 texts, forms
    (method, action path, input names and types), script source paths and
    keyword flags.
    """
    lines = [f"status={status}"]
    if location:
        names = _query_names(location)
        suffix = f" (query params: {', '.join(names)})" if names else ""
        lines.append(f"redirect to path={_path(location)}{suffix}")
    is_html = bool(body) and (
        "html" in (content_type or "").lower() or "<" in (body or "")[:200]
    )
    if not is_html:
        return "\n".join(lines)

    soup = BeautifulSoup(body, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else ""
    lines.append(f"title={title!r}")
    headings = [h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"])]
    lines.append(f"headings={headings}")
    forms = soup.find_all("form")
    lines.append(f"forms={len(forms)}")
    for form in forms:
        method = (form.get("method") or "get").lower()
        inputs = [
            f"{i.get('name') or '(unnamed)'}:{(i.get('type') or 'text').lower()}"
            for i in form.find_all(["input", "button", "select", "textarea"])
        ]
        lines.append(
            f"  form method={method} action={_path(form.get('action') or '')} "
            f"inputs={inputs}"
        )
    scripts = [_path(s["src"]) for s in soup.find_all("script", src=True)]
    lines.append(f"scripts={scripts}")
    lowered = body.lower()
    flags = {k: (k in lowered) for k in KEYWORDS}
    lines.append("mentions=" + ",".join(f"{k}={'yes' if v else 'no'}" for k, v in flags.items()))
    return "\n".join(lines)


@dataclass
class MfaForm:
    """A plain HTML form with a code input, ready to be posted."""

    action: str
    fields: dict[str, str] = field(default_factory=dict)
    code_field: str = ""


def find_code_form(body: str, page_url: str) -> MfaForm | None:
    """Find a POST form containing a code-like input, or None."""
    soup = BeautifulSoup(body or "", "html.parser")
    for form in soup.find_all("form"):
        if (form.get("method") or "get").lower() != "post":
            continue
        code_input = None
        for i in form.find_all("input"):
            name = i.get("name") or ""
            if name.lower() in CODE_INPUT_NAMES and (i.get("type") or "text").lower() not in (
                "hidden",
                "submit",
            ):
                code_input = i
                break
        if code_input is None:
            continue
        fields: dict[str, str] = {}
        submit_taken = False
        for i in form.find_all("input"):
            name = i.get("name")
            if not name:
                continue
            itype = (i.get("type") or "text").lower()
            if itype == "hidden":
                fields[name] = i.get("value") or ""
            elif itype == "submit" and not submit_taken:
                fields[name] = i.get("value") or ""
                submit_taken = True
        action = urllib.parse.urljoin(page_url, form.get("action") or page_url)
        return MfaForm(action=action, fields=fields, code_field=code_input["name"])
    return None


def unsupported_reason(body: str | None) -> str:
    """Short sanitized reason why a page cannot be completed automatically."""
    lowered = (body or "").lower()
    if "guardian" in lowered:
        return "unsupported MFA page: guardian widget"
    if "<form" in lowered:
        return "unsupported MFA page: no POST form with a code input"
    return "unsupported MFA page: no form"
