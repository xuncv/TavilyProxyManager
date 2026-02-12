"""
GPTMail API client (standalone).

Based on: https://www.chatgpt.org.uk/2025/11/gptmailapiapi.html

Supports:
  - Generate a temp email:        GET/POST /api/generate-email
  - List mailbox emails:          GET /api/emails?email=...
  - Fetch an email by id:         GET /api/email/{id}
  - Delete an email by id:        DELETE /api/email/{id}
  - Clear mailbox:               DELETE /api/emails/clear?email=...
"""

from __future__ import annotations

import io
import re
import sys
import time
from dataclasses import dataclass
from typing import Any

import requests


# Windows console output can be GBK; keep logs readable.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True, write_through=True)
    except Exception:
        try:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer,
                encoding="utf-8",
                errors="replace",
                line_buffering=True,
                write_through=True,
            )
        except Exception:
            pass

    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True, write_through=True)
    except Exception:
        try:
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer,
                encoding="utf-8",
                errors="replace",
                line_buffering=True,
                write_through=True,
            )
        except Exception:
            pass


@dataclass(frozen=True)
class GPTMailAPIError(RuntimeError):
    status_code: int | None
    message: str
    response: Any | None = None
    url: str | None = None

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        parts = [self.message]
        if self.status_code is not None:
            parts.append(f"(status={self.status_code})")
        if self.url:
            parts.append(f"url={self.url}")
        return " ".join(parts)


class GPTMailClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        if not api_key:
            raise ValueError("api_key is required")

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "X-API-Key": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "tavily-register/gptmail-client",
            }
        )

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self) -> "GPTMailClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        if not path.startswith("/"):
            path = "/" + path

        url = f"{self.base_url}{path}"
        try:
            resp = self._session.request(method, url, params=params, json=json_body, timeout=self.timeout)
        except requests.RequestException as e:
            raise GPTMailAPIError(None, f"Request failed: {e}", url=url) from e

        try:
            payload = resp.json()
        except ValueError:
            raise GPTMailAPIError(resp.status_code, "Non-JSON response", response=resp.text, url=url)

        if isinstance(payload, dict) and payload.get("success") is True:
            return payload.get("data")

        message = "API request failed"
        if isinstance(payload, dict) and payload.get("error"):
            message = str(payload.get("error"))
        raise GPTMailAPIError(resp.status_code, message, response=payload, url=url)

    def generate_email(self, *, prefix: str | None = None, domain: str | None = None) -> str:
        """
        Generate a new temp email address.

        Docs:
          - GET  /api/generate-email (random)
          - POST /api/generate-email {prefix?, domain?}
        """
        if prefix or domain:
            data = self._request("POST", "/api/generate-email", json_body={"prefix": prefix, "domain": domain})
        else:
            data = self._request("GET", "/api/generate-email")

        if not isinstance(data, dict) or not data.get("email"):
            raise GPTMailAPIError(None, "Malformed generate-email response", response=data)

        return str(data["email"])

    def list_emails(self, email: str) -> list[dict[str, Any]]:
        """List latest emails for the given address (GET /api/emails?email=...)."""
        data = self._request("GET", "/api/emails", params={"email": email})
        if not isinstance(data, dict):
            raise GPTMailAPIError(None, "Malformed emails response", response=data)
        emails = data.get("emails", [])
        if not isinstance(emails, list):
            raise GPTMailAPIError(None, "Malformed emails list", response=data)
        return [e for e in emails if isinstance(e, dict)]

    def get_email(self, email_id: str) -> dict[str, Any]:
        """Fetch one email detail by id (GET /api/email/{id})."""
        data = self._request("GET", f"/api/email/{email_id}")
        if not isinstance(data, dict):
            raise GPTMailAPIError(None, "Malformed email detail response", response=data)
        return data

    def delete_email(self, email_id: str) -> dict[str, Any]:
        """Delete one email by id (DELETE /api/email/{id})."""
        data = self._request("DELETE", f"/api/email/{email_id}")
        return data if isinstance(data, dict) else {"data": data}

    def clear_mailbox(self, email: str) -> dict[str, Any]:
        """Delete all emails for an address (DELETE /api/emails/clear?email=...)."""
        data = self._request("DELETE", "/api/emails/clear", params={"email": email})
        return data if isinstance(data, dict) else {"data": data}

    def wait_for_verification_link(
        self,
        email: str,
        *,
        timeout: int = 180,
        poll_interval: float = 5.0,
    ) -> str | None:
        """
        Poll the mailbox until a Tavily/Auth0 verification link is found.

        Returns:
            Verification link URL, or None on timeout.
        """
        patterns = [
            r'https://auth\.tavily\.com/u/email-verification\?ticket=[A-Za-z0-9_\-]+',
            r'https://auth\.tavily\.com/u/email-verification\?ticket=[^\s\"\'\<\>]+',
            r'https://auth\.tavily\.com[^\s\"\'\<\>]+ticket=[^\s\"\'\<\>]+',
            r'href=["\']?(https://auth\.tavily\.com[^"\'\s\<\>]+)',
        ]

        seen_ids: set[str] = set()
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            try:
                summaries = self.list_emails(email)
            except GPTMailAPIError:
                summaries = []

            for summary in summaries:
                email_id = _extract_email_id(summary)
                if not email_id or email_id in seen_ids:
                    continue
                seen_ids.add(email_id)

                try:
                    detail = self.get_email(email_id)
                except GPTMailAPIError:
                    continue

                blob = "\n".join(_iter_strings(summary)) + "\n" + "\n".join(_iter_strings(detail))
                for pattern in patterns:
                    matches = re.findall(pattern, blob, flags=re.IGNORECASE)
                    if matches:
                        link = matches[0]
                        link = link.replace("&amp;", "&")
                        link = re.sub(r'["\'\<\>#]+$', "", link)
                        return link

            time.sleep(poll_interval)

        return None


def _iter_strings(obj: Any) -> list[str]:
    out: list[str] = []

    def _walk(v: Any) -> None:
        if v is None:
            return
        if isinstance(v, str):
            if v:
                out.append(v)
            return
        if isinstance(v, bytes):
            try:
                s = v.decode("utf-8", errors="replace")
            except Exception:
                return
            if s:
                out.append(s)
            return
        if isinstance(v, dict):
            for vv in v.values():
                _walk(vv)
            return
        if isinstance(v, (list, tuple)):
            for vv in v:
                _walk(vv)
            return

    _walk(obj)
    return out


def _extract_email_id(summary: dict[str, Any]) -> str | None:
    for key in ("id", "_id", "email_id", "emailId", "message_id", "messageId", "mail_id", "mailId"):
        v = summary.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return None
