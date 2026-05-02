from __future__ import annotations

import json
from typing import Any, Iterable, List, Mapping, Optional
from urllib.parse import quote

import requests

from .crypto import decrypt, encrypt, generate_key
from .errors import ValidPayError
from .types import CreateIntentResult, VerifyIntentResult

DEFAULT_BASE_URL = "https://api.validpay.io"
DEFAULT_TIMEOUT = 30.0


class ValidPayClient:
    """Client for the ValidPay API.

    The client encrypts payloads on your machine before they leave the
    process — only the encrypted blob is sent to the ValidPay API. The
    decryption key is returned to you in :attr:`CreateIntentResult.key`
    and must be delivered out-of-band to whoever will verify the intent.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not api_key:
            raise ValidPayError("invalid_config", "api_key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = session if session is not None else requests.Session()

    def create_intent(
        self,
        document_type: str,
        payload: Any,
    ) -> CreateIntentResult:
        """Encrypt ``payload`` locally and register it with the ValidPay API.

        Args:
            document_type: A short string identifying the document kind
                (``"check"``, ``"money_order"``, ``"ssn_card"``, etc.).
            payload: Any JSON-serializable object. Will be ``json.dumps``ed
                and AES-256-GCM encrypted before transmission.

        Returns:
            A :class:`CreateIntentResult` containing the retrieval id and
            the freshly-generated AES key (base64).
        """
        if not document_type:
            raise ValidPayError("invalid_argument", "document_type is required")

        key = generate_key()
        encrypted_payload = encrypt(json.dumps(payload), key)

        data = self._request(
            "POST",
            "/v1/intent",
            body={"document_type": document_type, "encrypted_payload": encrypted_payload},
            auth=True,
        )

        retrieval_id = data.get("retrieval_id") if isinstance(data, dict) else None
        if not retrieval_id:
            raise ValidPayError(
                "invalid_response",
                "API response missing retrieval_id",
                details=data,
            )

        return CreateIntentResult(retrieval_id=retrieval_id, key=key)

    def create_intent_batch(
        self,
        intents: Iterable[Mapping[str, Any]],
    ) -> List[CreateIntentResult]:
        """Encrypt and register up to 100 intents in a single API call.

        Each item must be a mapping with ``document_type`` (str) and
        ``payload`` (any JSON-serializable). A unique AES key is generated
        for every intent — the result list preserves the input order so
        ``results[i].key`` corresponds to ``intents[i]``.

        Returns:
            A list of :class:`CreateIntentResult`, one per input intent.
        """
        items = list(intents)
        if not items:
            raise ValidPayError("invalid_argument", "intents must contain at least 1 item")
        if len(items) > 100:
            raise ValidPayError(
                "invalid_argument",
                f"intents must contain at most 100 items (got {len(items)})",
            )

        keys: List[str] = []
        request_items: List[dict] = []
        for idx, item in enumerate(items):
            doc_type = item.get("document_type")
            if not doc_type:
                raise ValidPayError(
                    "invalid_argument",
                    f"intents[{idx}].document_type is required",
                )
            if "payload" not in item:
                raise ValidPayError(
                    "invalid_argument",
                    f"intents[{idx}].payload is required",
                )
            key = generate_key()
            keys.append(key)
            request_items.append({
                "document_type": doc_type,
                "encrypted_payload": encrypt(json.dumps(item["payload"]), key),
            })

        data = self._request(
            "POST",
            "/v1/intent/batch",
            body={"intents": request_items},
            auth=True,
        )

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != len(keys):
            raise ValidPayError(
                "invalid_response",
                "API response missing results array of expected length",
                details=data,
            )

        out: List[CreateIntentResult] = []
        for i, row in enumerate(results):
            retrieval_id = row.get("retrieval_id") if isinstance(row, dict) else None
            if not retrieval_id:
                raise ValidPayError(
                    "invalid_response",
                    f"results[{i}] missing retrieval_id",
                    details=data,
                )
            out.append(CreateIntentResult(retrieval_id=retrieval_id, key=keys[i]))
        return out

    def verify_intent(
        self,
        retrieval_id: str,
        key: str,
    ) -> VerifyIntentResult:
        """Fetch an intent by id and decrypt its payload with ``key``.

        This endpoint is public (no API key required), so a verifier never
        needs to be a ValidPay customer to confirm an intent's contents.
        """
        if not retrieval_id:
            raise ValidPayError("invalid_argument", "retrieval_id is required")
        if not key:
            raise ValidPayError("invalid_argument", "key is required")

        data = self._request(
            "GET",
            f"/v1/intent/{quote(retrieval_id, safe='')}",
            auth=False,
        )

        if not isinstance(data, dict) or "encrypted_payload" not in data:
            raise ValidPayError(
                "invalid_response",
                "API response missing encrypted_payload",
                details=data,
            )

        decrypted = decrypt(data["encrypted_payload"], key)
        try:
            payload = json.loads(decrypted)
        except json.JSONDecodeError as exc:
            raise ValidPayError(
                "invalid_payload",
                "Decrypted payload is not valid JSON",
            ) from exc

        return VerifyIntentResult(
            intent_id=data.get("intent_id", ""),
            payload=payload,
            issuer=data.get("issuer", ""),
            issuer_verified=bool(data.get("issuer_verified", False)),
            registered_at=data.get("registered_at", ""),
            status=data.get("status", ""),
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Any] = None,
        auth: bool,
    ) -> Any:
        url = f"{self._base_url}{path}"
        headers = {"Accept": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if body is not None:
            headers["Content-Type"] = "application/json"

        try:
            response = self._session.request(
                method,
                url,
                headers=headers,
                data=json.dumps(body) if body is not None else None,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise ValidPayError("network_error", f"Request to {url} failed") from exc

        text = response.text
        parsed: Any = None
        if text:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None

        if not response.ok:
            err_body = parsed if parsed is not None else text
            code = "http_error"
            if isinstance(err_body, dict):
                err_code = err_body.get("error")
                if isinstance(err_code, str):
                    code = err_code
            raise ValidPayError(
                code,
                f"ValidPay API {method} {path} failed: {response.status_code}",
                status=response.status_code,
                details=err_body,
            )

        return parsed
