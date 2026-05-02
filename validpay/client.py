from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import quote

import requests

from .crypto import compute_commitment_hash, decrypt, encrypt, generate_key
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
        plaintext = json.dumps(payload)
        commitment_hash = compute_commitment_hash(plaintext)
        encrypted_payload = encrypt(plaintext, key)

        data = self._request(
            "POST",
            "/v1/intent",
            body={
                "document_type": document_type,
                "encrypted_payload": encrypted_payload,
                "commitment_hash": commitment_hash,
            },
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
            plaintext = json.dumps(item["payload"])
            request_items.append({
                "document_type": doc_type,
                "encrypted_payload": encrypt(plaintext, key),
                "commitment_hash": compute_commitment_hash(plaintext),
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

        if not isinstance(data, dict):
            raise ValidPayError(
                "invalid_response",
                "API response missing intent body",
                details=data,
            )

        # Blind Revocation (Patent H). Revoked intents return status="revoked"
        # with encrypted_payload=null — refuse to decrypt anything and surface
        # the revocation context to the caller.
        if data.get("status") == "revoked" or not data.get("encrypted_payload"):
            if data.get("status") == "revoked":
                msg = f"Intent {retrieval_id} has been revoked"
                if data.get("revocation_reason"):
                    msg = f"{msg}: {data['revocation_reason']}"
            else:
                msg = f"Intent {retrieval_id} has been revoked — no payload available"
            raise ValidPayError(
                "intent_revoked",
                msg,
                details={
                    "intent_id": data.get("intent_id"),
                    "status": data.get("status"),
                    "revoked_at": data.get("revoked_at"),
                    "revocation_reason": data.get("revocation_reason"),
                },
            )

        decrypted = decrypt(data["encrypted_payload"], key)

        # Hybrid Commitment Scheme — proves the server hasn't swapped the
        # ciphertext. Server is blind so it can't forge a matching hash.
        # Legacy intents (no hash stored) still verify, just without this check.
        commitment_hash = data.get("commitment_hash")
        integrity_verified = False
        if commitment_hash:
            actual_hash = compute_commitment_hash(decrypted)
            if actual_hash != commitment_hash:
                raise ValidPayError(
                    "integrity_failure",
                    "INTEGRITY VERIFICATION FAILED — the decrypted payload does not match "
                    "the commitment hash stored at issuance. This may indicate server-side "
                    "tampering or payload corruption.",
                )
            integrity_verified = True

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
            integrity_verified=integrity_verified,
        )

    def revoke_intent(
        self,
        retrieval_id: str,
        *,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Revoke a previously issued intent (e.g., stop-payment).

        Only the issuer who created the intent can revoke it. Once revoked,
        verifiers will see ``status='revoked'`` and the encrypted payload
        will no longer be returned by the API.

        Args:
            retrieval_id: The ``vp_*`` identifier of the intent to revoke.
            reason: Optional human-readable reason (max 500 chars).

        Returns:
            A dict with ``intent_id``, ``status``, and ``revoked_at``.
        """
        if not retrieval_id:
            raise ValidPayError("invalid_argument", "retrieval_id is required")

        data = self._request(
            "PATCH",
            f"/v1/intent/{quote(retrieval_id, safe='')}/revoke",
            body={"reason": reason} if reason else {},
            auth=True,
        )
        return data if isinstance(data, dict) else {}

    def reinstate_intent(
        self,
        retrieval_id: str,
        *,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Reinstate a previously revoked intent.

        Only the issuer who created the intent can reinstate it.

        Args:
            retrieval_id: The ``vp_*`` identifier of the intent to reinstate.
            reason: Optional human-readable reason (max 500 chars).

        Returns:
            A dict with ``intent_id`` and ``status``.
        """
        if not retrieval_id:
            raise ValidPayError("invalid_argument", "retrieval_id is required")

        data = self._request(
            "PATCH",
            f"/v1/intent/{quote(retrieval_id, safe='')}/reinstate",
            body={"reason": reason} if reason else {},
            auth=True,
        )
        return data if isinstance(data, dict) else {}

    def get_revocation_history(self, retrieval_id: str) -> List[Dict[str, Any]]:
        """Fetch the revocation audit trail for an intent.

        Only the issuer who created the intent can view this. Each event has
        ``id``, ``action`` (``"revoked"`` or ``"reinstated"``), ``reason``,
        and ``performed_at``. Newest first.
        """
        if not retrieval_id:
            raise ValidPayError("invalid_argument", "retrieval_id is required")

        data = self._request(
            "GET",
            f"/v1/intent/{quote(retrieval_id, safe='')}/revocations",
            auth=True,
        )
        if isinstance(data, dict):
            events = data.get("events")
            if isinstance(events, list):
                return events
        return []

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
