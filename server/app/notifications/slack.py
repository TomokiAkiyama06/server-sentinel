"""Optional Slack incoming webhooks with a local, value-free failure surface."""

from dataclasses import dataclass, field
from enum import StrEnum
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
import json
import re
import ssl


class DeliveryResult(StrEnum):
    DISABLED = "disabled"
    SENT = "sent"
    FAILED = "failed"
    SUPPRESSED = "suppressed"
    PENDING = "pending"


@dataclass(frozen=True)
class SlackEndpoint:
    url: str = field(repr=False)

    def __post_init__(self):
        try:
            if not isinstance(self.url, str) or any(ord(char) <= 32 for char in self.url):
                raise ValueError()
            parsed = urlsplit(self.url)
            valid = (parsed.scheme == "https" and parsed.hostname == "hooks.slack.com"
                     and parsed.port in (None, 443) and not parsed.username and not parsed.password
                     and not parsed.query and not parsed.fragment
                     and bool(re.fullmatch(r"/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+",
                                           parsed.path))
                     and len(self.url) <= 2048)
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("invalid Slack endpoint") from None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SlackDelivery:
    """One bounded HTTPS attempt, with no environment proxy or URL redirect.

    The credential is a deployment secret; it is never part of result/repr/logs.
    The optional opener is a test transport boundary, not an application setting.
    """

    def __init__(self, endpoint: SlackEndpoint | None = None, *, opener=None,
                 timeout_seconds: float = 10):
        if type(timeout_seconds) not in (float, int) or not 0 < timeout_seconds <= 30:
            raise ValueError("invalid Slack timeout")
        self._endpoint = endpoint
        self._opener = opener
        self._timeout = timeout_seconds

    def __repr__(self):
        return f"SlackDelivery(configured={self._endpoint is not None})"

    @property
    def configured(self) -> bool:
        return self._endpoint is not None

    def send(self, text: str) -> DeliveryResult:
        if self._endpoint is None:
            return DeliveryResult.DISABLED
        if not isinstance(text, str) or not text or len(text.encode("utf-8")) > 4096:
            return DeliveryResult.FAILED
        try:
            opener = self._opener or build_opener(
                ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context()),
            )
            request = Request(self._endpoint.url,
                              data=json.dumps({"text": text}, ensure_ascii=True).encode("ascii"),
                              headers={"Content-Type": "application/json"}, method="POST")
            with opener.open(request, timeout=self._timeout) as response:
                body = response.read(33)
                if response.status == 200 and len(body) <= 32 and body.strip() == b"ok":
                    return DeliveryResult.SENT
        except HTTPError as error:
            # HTTPError owns a response stream; close it so cleanup warnings
            # cannot later expose its secret-bearing URL outside this boundary.
            try:
                error.close()
            except Exception:
                pass
        except Exception:
            # No response body, URL, exception/cause or credentials leave here.
            pass
        return DeliveryResult.FAILED
