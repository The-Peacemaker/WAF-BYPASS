import base64
import html
from urllib.parse import quote


def identity(value: str) -> str:
    return value


def url_encode(value: str) -> str:
    return quote(value, safe="")


def double_url_encode(value: str) -> str:
    return quote(url_encode(value), safe="")


def html_encode(value: str) -> str:
    return html.escape(value, quote=True)


def unicode_escape(value: str) -> str:
    return "".join(f"\\u{ord(ch):04x}" for ch in value)


def b64_text(value: str) -> str:
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"BASE64[{encoded}]"


ENCODERS = {
    "identity": identity,
    "url": url_encode,
    "double_url": double_url_encode,
    "html": html_encode,
    "unicode": unicode_escape,
    "base64": b64_text,
}
