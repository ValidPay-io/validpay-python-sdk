from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import quote

import requests

from .crypto import (
    build_key_map,
    combine_key_shares,
    compute_commitment_hash,
    decrypt,
    decrypt_fields,
    encrypt,
    encrypt_fields,
    generate_key,
    split_key as split_key_fn,
)
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

        # Selective Field Disclosure (Patent E). Per-field encryption uses a
        # different envelope shape; verify_intent can't decrypt it.
        if data.get("selective_disclosure"):
            raise ValidPayError(
                "selective_disclosure_required",
                "This intent uses selective field disclosure. "
                "Use verify_selective_intent(retrieval_id, key, role) instead of verify_intent().",
            )

        # Split-Key Verification (Patent C). The caller passed a single key,
        # but this intent was issued with a key split into two shares —
        # verify_intent doesn't have enough information to reconstruct.
        if data.get("split_key"):
            raise ValidPayError(
                "split_key_required",
                f"Intent {retrieval_id} uses split-key protection. "
                "Use verify_split_key_intent(retrieval_id, share_a) instead of verify_intent().",
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

    def create_split_key_intent(
        self,
        document_type: str,
        payload: Any,
    ) -> CreateIntentResult:
        """Create an intent with split-key protection (Patent C).

        The AES-256 key is split into two XOR shares. Share A is returned
        to the caller (for embedding in the QR code). Share B is stored on
        the ValidPay server. Neither share alone can decrypt the payload —
        both are required at verification time.

        The full key exists only transiently in this process; it is never
        persisted, never sent over the wire, and never logged.

        Args:
            document_type: A short string identifying the document kind.
            payload: Any JSON-serializable object.

        Returns:
            A :class:`CreateIntentResult` whose ``key`` is **Share A**, not
            the full key. Embed it in the QR code as you would the regular key.
        """
        if not document_type:
            raise ValidPayError("invalid_argument", "document_type is required")

        full_key = generate_key()
        share_a, share_b = split_key_fn(full_key)

        plaintext = json.dumps(payload)
        commitment_hash = compute_commitment_hash(plaintext)
        encrypted_payload = encrypt(plaintext, full_key)

        data = self._request(
            "POST",
            "/v1/intent",
            body={
                "document_type": document_type,
                "encrypted_payload": encrypted_payload,
                "commitment_hash": commitment_hash,
                "split_key": True,
                "key_fragment_b": share_b,
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

        return CreateIntentResult(retrieval_id=retrieval_id, key=share_a)

    def verify_split_key_intent(
        self,
        retrieval_id: str,
        share_a: str,
    ) -> VerifyIntentResult:
        """Verify a split-key intent by combining Share A with the API's Share B.

        Steps: fetch the intent → reject if revoked → fetch Share B from the
        fragment endpoint → XOR-combine to reconstruct the full key → decrypt
        → run the commitment-hash integrity check → return the parsed payload.
        The reconstructed key exists only inside this method's local scope.

        Args:
            retrieval_id: The ``vp_*`` identifier.
            share_a: Base64-encoded Share A (the share embedded in the QR code).
        """
        if not retrieval_id:
            raise ValidPayError("invalid_argument", "retrieval_id is required")
        if not share_a:
            raise ValidPayError("invalid_argument", "share_a is required")

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

        if data.get("status") == "revoked" or not data.get("encrypted_payload"):
            msg = f"Intent {retrieval_id} has been revoked"
            if data.get("revocation_reason"):
                msg = f"{msg}: {data['revocation_reason']}"
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

        fragment_data = self._request(
            "GET",
            f"/v1/intent/{quote(retrieval_id, safe='')}/fragment",
            auth=False,
        )
        if isinstance(fragment_data, dict) and fragment_data.get("error"):
            raise ValidPayError(
                str(fragment_data.get("error")),
                f"Fragment retrieval failed: {fragment_data.get('error')}",
                details=fragment_data,
            )
        share_b = (
            fragment_data.get("fragment_b")
            if isinstance(fragment_data, dict)
            else None
        )
        if not share_b:
            raise ValidPayError(
                "missing_fragment",
                "Server did not return key fragment",
                details=fragment_data,
            )

        full_key = combine_key_shares(share_a, share_b)
        decrypted = decrypt(data["encrypted_payload"], full_key)

        commitment_hash = data.get("commitment_hash")
        integrity_verified = False
        if commitment_hash:
            actual_hash = compute_commitment_hash(decrypted)
            if actual_hash != commitment_hash:
                raise ValidPayError(
                    "integrity_failure",
                    "INTEGRITY VERIFICATION FAILED — the decrypted payload does not match "
                    "the commitment hash stored at issuance.",
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

    def create_selective_intent(
        self,
        document_type: str,
        payload: dict,
        disclosure_policy: dict,
        *,
        split_key: bool = False,
    ) -> CreateIntentResult:
        """Create an intent with per-field encryption and a disclosure policy (Patent E).

        Each field is encrypted with its own AES-256 key. The disclosure_policy
        maps role names to lists of field names that role can access. A "full"
        role is automatically added with access to all fields.

        The field key map is encrypted with the master key (or Share A for
        split-key intents) and stored on the server. The server cannot decrypt
        it — only the QR holder can.

        Args:
            document_type: Short string identifying the document kind.
            payload: Dict of field_name → value.
            disclosure_policy: { role_name: [field_name, ...] }.
            split_key: If True, use split-key verification (Patent C).

        Returns:
            CreateIntentResult with retrieval_id and key (or Share A if split_key).
        """
        if not document_type:
            raise ValidPayError("invalid_argument", "document_type is required")
        if not payload or not isinstance(payload, dict):
            raise ValidPayError("invalid_argument", "payload must be a non-empty dict")
        if not disclosure_policy or not isinstance(disclosure_policy, dict):
            raise ValidPayError("invalid_argument", "disclosure_policy must be a non-empty dict")

        for role, fields in disclosure_policy.items():
            if not isinstance(fields, list):
                raise ValidPayError(
                    "invalid_argument",
                    f"disclosure_policy['{role}'] must be a list",
                )
            for f in fields:
                if f not in payload:
                    raise ValidPayError(
                        "invalid_argument",
                        f"Field '{f}' in role '{role}' not found in payload",
                    )

        master_key = generate_key()
        encrypted_fields, field_keys = encrypt_fields(payload)
        key_map = build_key_map(field_keys, disclosure_policy)
        encrypted_key_map = encrypt(json.dumps(key_map), master_key)

        full_plaintext = json.dumps(payload)
        commitment_hash = compute_commitment_hash(full_plaintext)
        envelope = json.dumps(encrypted_fields)

        qr_key = master_key
        key_fragment_b: Optional[str] = None
        if split_key:
            share_a, share_b = split_key_fn(master_key)
            qr_key = share_a
            key_fragment_b = share_b

        body: Dict[str, Any] = {
            "document_type": document_type,
            "encrypted_payload": envelope,
            "commitment_hash": commitment_hash,
            "selective_disclosure": True,
            "disclosure_policy": json.dumps(disclosure_policy),
            "encrypted_key_map": encrypted_key_map,
            "split_key": split_key,
        }
        if key_fragment_b is not None:
            body["key_fragment_b"] = key_fragment_b

        data = self._request("POST", "/v1/intent", body=body, auth=True)

        retrieval_id = data.get("retrieval_id") if isinstance(data, dict) else None
        if not retrieval_id:
            raise ValidPayError(
                "invalid_response",
                "API response missing retrieval_id",
                details=data,
            )

        return CreateIntentResult(retrieval_id=retrieval_id, key=qr_key)

    def verify_selective_intent(
        self,
        retrieval_id: str,
        key: str,
        role: str = "full",
    ) -> VerifyIntentResult:
        """Verify a selective-disclosure intent, decrypting only fields for the given role.

        Args:
            retrieval_id: The vp_* identifier.
            key: The master key (or Share A for split-key intents) from the QR code.
            role: The verifier's role. "full" decrypts everything. Other roles see
                only their authorized fields; unauthorized fields are "[REDACTED]".

        Returns:
            VerifyIntentResult with the (possibly partial) payload.
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

        if data.get("status") == "revoked" or not data.get("encrypted_payload"):
            msg = f"Intent {retrieval_id} has been revoked"
            if data.get("revocation_reason"):
                msg = f"{msg}: {data['revocation_reason']}"
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

        master_key = key
        if data.get("split_key"):
            fragment_data = self._request(
                "GET",
                f"/v1/intent/{quote(retrieval_id, safe='')}/fragment",
                auth=False,
            )
            if isinstance(fragment_data, dict) and fragment_data.get("error"):
                raise ValidPayError(
                    str(fragment_data["error"]),
                    f"Fragment retrieval failed: {fragment_data['error']}",
                    details=fragment_data,
                )
            share_b = (
                fragment_data.get("fragment_b")
                if isinstance(fragment_data, dict)
                else None
            )
            if not share_b:
                raise ValidPayError(
                    "missing_fragment",
                    "Server did not return key fragment",
                    details=fragment_data,
                )
            master_key = combine_key_shares(key, share_b)

        encrypted_key_map = data.get("encrypted_key_map")
        if not encrypted_key_map:
            raise ValidPayError(
                "invalid_response",
                "Selective disclosure intent missing encrypted_key_map",
            )

        key_map_json = decrypt(encrypted_key_map, master_key)
        try:
            key_map = json.loads(key_map_json)
        except json.JSONDecodeError as exc:
            raise ValidPayError(
                "invalid_payload",
                "Decrypted key map is not valid JSON",
            ) from exc

        if role not in key_map:
            available = ", ".join(sorted(key_map.keys()))
            raise ValidPayError(
                "invalid_role",
                f"Role '{role}' is not defined in this document's disclosure policy. "
                f"Available roles: {available}",
            )
        field_keys = key_map[role]

        try:
            encrypted_fields = json.loads(data["encrypted_payload"])
        except json.JSONDecodeError as exc:
            raise ValidPayError(
                "invalid_payload",
                "Encrypted payload is not a valid JSON envelope",
            ) from exc

        payload = decrypt_fields(encrypted_fields, field_keys)

        integrity_verified = False
        commitment_hash = data.get("commitment_hash")
        if commitment_hash and role == "full":
            all_keys = key_map.get("full", {})
            full_payload = decrypt_fields(encrypted_fields, all_keys)
            full_plaintext = json.dumps(full_payload)
            actual_hash = compute_commitment_hash(full_plaintext)
            if actual_hash != commitment_hash:
                raise ValidPayError(
                    "integrity_failure",
                    "INTEGRITY VERIFICATION FAILED — the decrypted payload does not match "
                    "the commitment hash stored at issuance.",
                )
            integrity_verified = True

        return VerifyIntentResult(
            intent_id=data.get("intent_id", ""),
            payload=payload,
            issuer=data.get("issuer", ""),
            issuer_verified=bool(data.get("issuer_verified", False)),
            registered_at=data.get("registered_at", ""),
            status=data.get("status", ""),
            integrity_verified=integrity_verified,
        )

    def create_bound_intent(
        self,
        document_type: str,
        payload: dict,
        binding_zone_image: bytes,
        *,
        binding_threshold: int = 10,
        split_key: bool = False,
        selective_disclosure: bool = False,
        disclosure_policy: Optional[dict] = None,
    ) -> CreateIntentResult:
        """Create an intent with physical medium binding (Patent G).

        Computes a perceptual hash of the binding zone image and includes
        it as an encrypted field ``_binding_hash`` in the payload. The
        ``_binding_threshold`` is also stored so the verifier knows the
        issuer's tolerance setting.

        This method supports combining with split-key and selective
        disclosure features.

        Args:
            document_type: Short string identifying the document kind.
            payload: Dict of field_name → value.
            binding_zone_image: Raw bytes of the binding zone image (JPEG/PNG).
            binding_threshold: Hamming distance threshold (default 10).
            split_key: If True, use split-key verification (Patent C).
            selective_disclosure: If True, use per-field encryption (Patent E).
            disclosure_policy: Required if selective_disclosure is True.

        Returns:
            CreateIntentResult with retrieval_id and key.
        """
        from .binding import compute_binding_hash

        if not document_type:
            raise ValidPayError("invalid_argument", "document_type is required")
        if not payload or not isinstance(payload, dict):
            raise ValidPayError("invalid_argument", "payload must be a non-empty dict")
        if not binding_zone_image:
            raise ValidPayError("invalid_argument", "binding_zone_image is required")

        binding_hash = compute_binding_hash(binding_zone_image)

        bound_payload = dict(payload)
        bound_payload["_binding_hash"] = binding_hash
        bound_payload["_binding_threshold"] = binding_threshold

        if selective_disclosure:
            if not disclosure_policy:
                raise ValidPayError(
                    "invalid_argument",
                    "disclosure_policy is required when selective_disclosure is True",
                )
            return self.create_selective_intent(
                document_type=document_type,
                payload=bound_payload,
                disclosure_policy=disclosure_policy,
                split_key=split_key,
            )
        elif split_key:
            return self.create_split_key_intent(
                document_type=document_type,
                payload=bound_payload,
            )
        else:
            return self.create_intent(
                document_type=document_type,
                payload=bound_payload,
            )

    @staticmethod
    def verify_binding(
        payload: dict,
        binding_zone_image: bytes,
    ) -> "BindingComparisonResult":
        """Compare a freshly captured binding zone image against the stored hash.

        Call this AFTER ``verify_intent`` / ``verify_split_key_intent`` /
        ``verify_selective_intent`` has returned the decrypted payload.

        Args:
            payload: The decrypted payload dict (must contain ``_binding_hash``).
            binding_zone_image: Raw bytes of the freshly captured binding zone.

        Returns:
            BindingComparisonResult with match status and Hamming distance.

        Raises:
            ValidPayError: If the payload doesn't contain binding metadata.
        """
        from .binding import compute_binding_hash, compare_binding_hashes

        stored_hash = payload.get("_binding_hash")
        if not stored_hash:
            raise ValidPayError(
                "no_binding",
                "This intent does not contain physical medium binding data. "
                "The _binding_hash field is missing from the payload.",
            )

        threshold = payload.get("_binding_threshold", 10)
        if not isinstance(threshold, int):
            threshold = int(threshold)

        current_hash = compute_binding_hash(binding_zone_image)

        return compare_binding_hashes(
            stored_hash,
            current_hash,
            threshold=threshold,
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
