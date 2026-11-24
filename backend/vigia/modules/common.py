"""Shared helpers for native modules: HTML parsing, response store, canaries, differential comparison."""
from __future__ import annotations

import difflib
import re
import secrets
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urldefrag, urlencode, urljoin, urlsplit, urlunsplit

from vigia.security.http import HttpResponse

MAX_STORED_BODY = 150_000
MAX_STORE_TOTAL = 60_000_000


@dataclass
class StoredResponse:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    content_type: str
    method: str = "GET"
    identity: str = "default"

    def header(self, name: str, default: str = "") -> str:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default

    def header_list(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class ResponseStore:
    def __init__(self) -> None:
        self.items: dict[str, StoredResponse] = {}
        self.total = 0

    def add(self, r: HttpResponse, identity: str = "default") -> StoredResponse:
        ctype = r.content_type
        keep = ctype.startswith(("text/", "application/json", "application/javascript", "application/xml",
                                 "application/x-javascript", "image/svg")) or ctype == ""
        body = r.content[:MAX_STORED_BODY] if keep and self.total < MAX_STORE_TOTAL else b""
        self.total += len(body)
        sr = StoredResponse(r.url, r.status, list(r.headers.multi_items()), body, ctype, r.method, identity)
        self.items[r.url] = sr
        return sr

    def html_pages(self) -> list[StoredResponse]:
        return [s for s in self.items.values() if "html" in s.content_type and s.body]


def canary() -> str:
    """Unique, inert marker: letters+digits only, so it survives most filters and is easy to find."""
    return "vg" + secrets.token_hex(5)


def same_doc(url: str) -> str:
    return urldefrag(url)[0]


def with_param(url: str, name: str, value: str) -> str:
    p = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != name]
    q.append((name, value))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q, doseq=True), ""))


def query_params(url: str) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def similarity(a: str, b: str) -> float:
    """Ratio in [0,1]; quick path for big bodies (compare length + sampled lines)."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    if len(a) > 60_000 or len(b) > 60_000:
        la, lb = len(a), len(b)
        return min(la, lb) / max(la, lb) * 0.9
    return difflib.SequenceMatcher(None, a, b, autojunk=False).quick_ratio()


def strip_reflections(body: str, *values: str) -> str:
    for v in values:
        if v:
            body = body.replace(v, "")
    return re.sub(r"\b\d{10,13}\b", "", body)  # timestamps / cache busters


@dataclass
class ParsedForm:
    action: str
    method: str
    inputs: dict[str, str] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    enctype: str = "application/x-www-form-urlencoded"


class _Parser(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[ParsedForm] = []
        self.meta: dict[str, str] = {}
        self.title = ""
        self.comments: list[str] = []
        self.iframes: list[str] = []
        self.http_resources: list[str] = []
        self._in_script = False
        self._in_title = False
        self._form: ParsedForm | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = urljoin(self.base, a["href"])
        for attr in ("href", "src", "action", "data-url", "formaction"):
            if a.get(attr) and not a[attr].startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                url = urljoin(self.base, a[attr].strip())
                if tag in ("a", "link", "area", "iframe", "frame", "form") or attr in ("action", "formaction", "data-url"):
                    self.links.append(url)
                if a[attr].startswith("http://") and tag in ("script", "link", "iframe", "img", "embed", "object"):
                    self.http_resources.append(a[attr])
        if tag == "script":
            if a.get("src"):
                self.scripts.append(urljoin(self.base, a["src"]))
            else:
                self._in_script = True
                self._buf = []
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")
        elif tag in ("iframe", "frame") and a.get("src"):
            self.iframes.append(urljoin(self.base, a["src"]))
        elif tag == "form":
            self._form = ParsedForm(action=urljoin(self.base, a.get("action") or self.base),
                                    method=(a.get("method") or "GET").upper(),
                                    enctype=a.get("enctype") or "application/x-www-form-urlencoded")
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            name = a.get("name")
            if name:
                typ = (a.get("type") or tag).lower()
                if typ in ("submit", "button", "image", "reset") and tag != "select":
                    if typ == "submit" and a.get("value"):
                        self._form.inputs.setdefault(name, a.get("value", ""))
                    return
                self._form.inputs[name] = a.get("value", "")
                self._form.types[name] = typ

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self._in_script = False
            self.inline_scripts.append("".join(self._buf))
        elif tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buf.append(data)
        elif self._in_title:
            self.title += data

    def handle_comment(self, data: str) -> None:
        if len(self.comments) < 50:
            self.comments.append(data.strip()[:500])


def parse_html(body: str, base: str) -> _Parser:
    p = _Parser(base)
    try:
        p.feed(body[:MAX_STORED_BODY])
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML must not stop the module
        pass
    return p


ERROR_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Django DEBUG", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>|DEBUG = True")),
    ("Flask/Werkzeug debugger", re.compile(r"Werkzeug Debugger|werkzeug\.exceptions|The debugger caught an exception")),
    ("Java stack trace", re.compile(r"(?:Exception|Error)(?: in thread \"[^\"]+\")?[:\s][^\n]{0,200}\n\s+at [\w$.]+\([\w$]+\.java:\d+\)")),
    ("Spring Whitelabel", re.compile(r"Whitelabel Error Page")),
    ("ASP.NET error", re.compile(r"Server Error in '/[^']*' Application|System\.[\w.]+Exception|ASP\.NET is configured to show verbose")),
    ("PHP error", re.compile(r"<b>(?:Warning|Fatal error|Parse error|Notice)</b>:\s.*? on line <b>\d+</b>|PHP (?:Warning|Fatal error|Parse error)")),
    ("Laravel/Whoops", re.compile(r"Whoops, looks like something went wrong|Illuminate\\[A-Za-z\\]+Exception")),
    ("Node.js stack", re.compile(r"at (?:Layer|Module|Object|process)\.[\w<>.]+ \((?:/|[A-Z]:\\)[^)]+\.js:\d+:\d+\)")),
    ("Ruby on Rails", re.compile(r"ActionController::RoutingError|ActiveRecord::\w+Error|<h1>Routing Error</h1>")),
    ("Go panic", re.compile(r"goroutine \d+ \[running\]:")),
]

SQL_ERRORS: list[tuple[str, re.Pattern[str]]] = [
    ("MySQL", re.compile(r"You have an error in your SQL syntax|mysql_fetch|mysqli?_|MySqlException|SQLSTATE\[\d+\]", re.I)),
    ("PostgreSQL", re.compile(r"PG::SyntaxError|psycopg2\.\w+Error|unterminated quoted string at or near|syntax error at or near \"", re.I)),
    ("SQL Server", re.compile(r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|SqlException", re.I)),
    ("Oracle", re.compile(r"ORA-\d{5}|quoted string not properly terminated", re.I)),
    ("SQLite", re.compile(r"sqlite3\.OperationalError|SQLITE_ERROR|unrecognized token: \"|near \"[^\"]*\": syntax error", re.I)),
    ("Generic SQL", re.compile(r"SQL syntax.*?error|Syntax error in string in query expression|JDBC|ODBC SQL", re.I)),
]


def find_signature(text: str, sigs: list[tuple[str, re.Pattern[str]]]) -> tuple[str, str] | None:
    for name, rx in sigs:
        m = rx.search(text)
        if m:
            start = max(0, m.start() - 80)
            return name, text[start:m.end() + 120]
    return None


def evidence_from(r: HttpResponse | StoredResponse, excerpt_around: str | None = None, limit: int = 1500) -> dict[str, Any]:
    body = r.text if isinstance(r, (HttpResponse, StoredResponse)) else ""
    if excerpt_around and excerpt_around in body:
        i = body.index(excerpt_around)
        excerpt = body[max(0, i - 300): i + len(excerpt_around) + 300]
    else:
        excerpt = body[:limit]
    method = getattr(r, "method", "GET")
    status = getattr(r, "status", None)
    headers = dict(r.headers) if isinstance(r, HttpResponse) else dict(r.headers)
    keep = {k: v for k, v in headers.items() if k.lower() in ("server", "content-type", "location", "x-powered-by",
                                                             "access-control-allow-origin",
                                                             "access-control-allow-credentials", "set-cookie",
                                                             "content-security-policy", "strict-transport-security",
                                                             "www-authenticate")}
    return {"request": f"{method} {r.url}", "status": status, "response_headers": keep,
            "response_excerpt": excerpt[:limit]}
