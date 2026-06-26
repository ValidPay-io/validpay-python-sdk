from __future__ import annotations

import json
import warnings
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import quote

import requests

from ._timelock import compute_time_lock_status as _compute_time_lock_status
from ._timelock import validate_time_lock as _validate_time_lock
from .crypto import (
    build_aad,
    build_key_map,
    combine_key_shares,
    compute_commitment_hash,
    decrypt,
    decrypt_fields,
    encrypt,
    encrypt_bytes,
    encrypt_fields,
    generate_key,
    split_key as split_key_fn,
    split_key_pieces,
    combine_key_pieces,
)
from .errors import ValidPayError
from .rail import (
    fetch_rail_piece,
    KEYHALVE_RAIL_BASE_URL,
    KEYHALVE_RAIL_PUBLIC_KEY_SPKI_B64,
)
from .types import CreateIntentResult, VerifyIntentResult

_HOLDER_KEYHALVE = "keyhalve"

DEFAULT_BASE_URL = "https://api.validpay.com"
DEFAULT_TIMEOUT = 30.0


def _verify_commitment(data: Mapping[str, Any]) -> bool:
    """Version-aware commitment check (Prompt 097 C-1).

    v2 commitments are SHA-256(ciphertext): recompute over the received
    ``encrypted_payload`` and compare. v1 (legacy SHA-256(plaintext)) is a
    confirmation-oracle risk and is intentionally skipped — those documents
    expire naturally. Returns whether integrity was confirmed; raises on a
    v2 mismatch (the ciphertext was swapped after issuance).
    """
    commitment_hash = data.get("commitment_hash")
    version = data.get("commitment_version", 1)
    if not commitment_hash or not isinstance(version, int) or version < 2:
        return False
    if compute_commitment_hash(data["encrypted_payload"]) != commitment_hash:
        raise ValidPayError(
            "integrity_failure",
            "INTEGRITY VERIFICATION FAILED — the ciphertext does not match the "
            "commitment hash recorded at issuance. This document may have been "
            "tampered with.",
        )
    return True


def _aad_for(data: Mapping[str, Any]) -> Optional[str]:
    """AAD to pass to decrypt (Prompt 097 M-5). For v2 intents, reconstruct it
    from the server-returned metadata so a server that altered document_type
    or the validity window fails the GCM tag check. None for legacy v1."""
    if not isinstance(data.get("encryption_version"), int) or data["encryption_version"] < 2:
        return None
    return build_aad(
        data.get("document_type", ""),
        data.get("valid_from"),
        data.get("valid_until"),
    )


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
        rail_base_url: str = KEYHALVE_RAIL_BASE_URL,
        rail_public_key_spki: str = KEYHALVE_RAIL_PUBLIC_KEY_SPKI_B64,
    ) -> None:
        if not api_key:
            raise ValidPayError("invalid_config", "api_key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = session if session is not None else requests.Session()
        self._rail_base_url = rail_base_url
        self._rail_public_key_spki = rail_public_key_spki

    def create_intent(
        self,
        document_type: str,
        payload: Any,
        *,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        split_key: bool = True,
        on_behalf_of: Optional[Dict[str, str]] = None,
    ) -> CreateIntentResult:
        """Encrypt ``payload`` locally and register it with the ValidPay API.

        As of SDK 1.1.0 this uses **split-key protection (Patent C) by
        default**: the AES-256 key is split into two XOR shares — Share A
        is returned to you (embed it in the QR code exactly as you would
        the key before), Share B is stored on the ValidPay server. The
        full decryption key never exists on any single system after this
        call returns.

        Args:
            document_type: A short string identifying the document kind
                (``"check"``, ``"money_order"``, ``"ssn_card"``, etc.).
            payload: Any JSON-serializable object. Will be ``json.dumps``ed
                and AES-256-GCM encrypted before transmission.
            valid_from: Optional ISO-8601 timestamp. The verifier surfaces
                "not yet valid" status before this time. Server stores the
                value but does NOT enforce it (Patent D — Time-Locked
                Verification, blind intermediary preserved).
            valid_until: Optional ISO-8601 timestamp. The verifier surfaces
                "expired" status after this time.
            split_key: Default ``True``. Set ``False`` for the legacy
                single-key flow, where ``key`` in the result is the full
                AES key. Verification of legacy intents is unchanged.

        Returns:
            A :class:`CreateIntentResult` containing the retrieval id and
            the key material (base64): **Share A** when ``split_key=True``
            (the default), the full AES key when ``split_key=False``.
        """
        if not document_type:
            raise ValidPayError("invalid_argument", "document_type is required")
        _validate_time_lock(valid_from, valid_until)

        full_key = generate_key()
        share_b: Optional[str] = None
        result_key = full_key
        if split_key:
            result_key, share_b = split_key_fn(full_key)

        plaintext = json.dumps(payload)
        # M-5: bind document_type + validity window as AAD.
        aad = build_aad(document_type, valid_from, valid_until)
        encrypted_payload = encrypt(plaintext, full_key, aad)
        # Commitment v2: hash the ciphertext, not the plaintext (C-1).
        commitment_hash = compute_commitment_hash(encrypted_payload)

        body: Dict[str, Any] = {
            "document_type": document_type,
            "encrypted_payload": encrypted_payload,
            "commitment_hash": commitment_hash,
            "encryption_version": 2,
        }
        if split_key:
            body["split_key"] = True
            body["key_fragment_b"] = share_b
        if valid_from is not None:
            body["valid_from"] = valid_from
        if valid_until is not None:
            body["valid_until"] = valid_until
        if on_behalf_of is not None:
            body["on_behalf_of"] = on_behalf_of

        data = self._request(
            "POST",
            "/v1/intent",
            body=body,
            auth=True,
        )

        retrieval_id = data.get("retrieval_id") if isinstance(data, dict) else None
        if not retrieval_id:
            raise ValidPayError(
                "invalid_response",
                "API response missing retrieval_id",
                details=data,
            )

        return CreateIntentResult(retrieval_id=retrieval_id, key=result_key)

    def create_end_cell_intent(
        self,
        document_type: str,
        payload: Any,
        *,
        holders: Optional[List[str]] = None,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        on_behalf_of: Optional[Dict[str, str]] = None,
    ) -> CreateIntentResult:
        """Seal a document with End-Cell (CVCP Layer 6B): an n-of-n XOR split across
        ShareA (returned as ``key``, embed in the QR) + one mandatory piece per holder
        (default: the KeyHalve rail + the platform). No single party can read or
        assemble the key. Requires API End-Cell issuance to be enabled.
        """
        if not document_type:
            raise ValidPayError("invalid_argument", "document_type is required")
        _validate_time_lock(valid_from, valid_until)

        holders = holders or ["keyhalve", "platform"]
        if len(set(holders)) != len(holders):
            raise ValidPayError("invalid_argument", "holders must be unique")
        if holders.count(_HOLDER_KEYHALVE) != 1 or not any(h != _HOLDER_KEYHALVE for h in holders):
            raise ValidPayError(
                "invalid_argument",
                'end_cell requires exactly one "keyhalve" rail share and >= 1 platform share',
            )

        full_key = generate_key()
        parts = split_key_pieces(full_key, len(holders))  # [share_a, piece_1, ...]
        share_a = parts[0]
        pieces = [{"holder": h, "piece": parts[i + 1]} for i, h in enumerate(holders)]

        aad = build_aad(document_type, valid_from, valid_until)
        encrypted_payload = encrypt(json.dumps(payload), full_key, aad)
        body: Dict[str, Any] = {
            "document_type": document_type,
            "encrypted_payload": encrypted_payload,
            "commitment_hash": compute_commitment_hash(encrypted_payload),
            "encryption_version": 2,
            "end_cell": True,
            "pieces": pieces,
        }
        if valid_from is not None:
            body["valid_from"] = valid_from
        if valid_until is not None:
            body["valid_until"] = valid_until
        if on_behalf_of is not None:
            body["on_behalf_of"] = on_behalf_of

        data = self._request("POST", "/v1/intent", body=body, auth=True)
        retrieval_id = data.get("retrieval_id") if isinstance(data, dict) else None
        if not retrieval_id:
            raise ValidPayError("invalid_response", "API response missing retrieval_id", details=data)
        return CreateIntentResult(retrieval_id=retrieval_id, key=share_a)

    def create_file_intent(
        self,
        document_type: str,
        file: bytes,
        *,
        file_name: Optional[str] = None,
        file_content_type: Optional[str] = None,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        split_key: bool = True,
        on_behalf_of: Optional[Dict[str, str]] = None,
    ) -> CreateIntentResult:
        """Seal a full document file (PDF, image, DOCX, …) end-to-end.

        Unlike :meth:`create_intent`, which JSON-encodes a structured payload,
        this encrypts the raw ``file`` bytes directly with AES-256-GCM and
        registers them — so a verifier decrypts back the exact original bytes
        and can confirm a byte-for-byte match. Split-key protection (Patent C)
        is on by default, identical to :meth:`create_intent`.

        Args:
            document_type: Short document-kind string (``"contract"``,
                ``"wire_instructions"``, ``"title"``, …).
            file: Raw file bytes to seal. Encrypted locally; never sent in the
                clear.
            file_name: Original filename, stored for the issuer's records. It
                is treated as potentially sensitive and is NOT echoed on the
                public verify endpoint.
            file_content_type: MIME type (``"application/pdf"``,
                ``"image/png"``, …). Returned on verify so downloads get the
                right type/extension instead of a generic ``.bin``.
            valid_from: Optional ISO-8601 start of the validity window.
            valid_until: Optional ISO-8601 end of the validity window.
            split_key: Default ``True`` (Patent C). ``False`` returns the full
                AES key in the result instead of Share A.

        Returns:
            A :class:`CreateIntentResult` with the retrieval id and the key
            material (Share A by default).
        """
        if not document_type:
            raise ValidPayError("invalid_argument", "document_type is required")
        if not isinstance(file, (bytes, bytearray)):
            raise ValidPayError("invalid_argument", "file must be bytes")
        if len(file) == 0:
            raise ValidPayError("invalid_argument", "file is empty")
        _validate_time_lock(valid_from, valid_until)

        full_key = generate_key()
        share_b: Optional[str] = None
        result_key = full_key
        if split_key:
            result_key, share_b = split_key_fn(full_key)

        # M-5: bind document_type + validity window as AAD, same as create_intent.
        aad = build_aad(document_type, valid_from, valid_until)
        encrypted_payload = encrypt_bytes(bytes(file), full_key, aad)
        # Commitment v2: hash the ciphertext, not the plaintext (C-1).
        commitment_hash = compute_commitment_hash(encrypted_payload)

        body: Dict[str, Any] = {
            "document_type": document_type,
            "encrypted_payload": encrypted_payload,
            "commitment_hash": commitment_hash,
            "encryption_version": 2,
            "file_size_bytes": len(file),
        }
        if split_key:
            body["split_key"] = True
            body["key_fragment_b"] = share_b
        if file_name is not None:
            body["file_name"] = file_name
        if file_content_type is not None:
            body["file_content_type"] = file_content_type
        if valid_from is not None:
            body["valid_from"] = valid_from
        if valid_until is not None:
            body["valid_until"] = valid_until
        if on_behalf_of is not None:
            body["on_behalf_of"] = on_behalf_of

        data = self._request("POST", "/v1/intent", body=body, auth=True)

        retrieval_id = data.get("retrieval_id") if isinstance(data, dict) else None
        if not retrieval_id:
            raise ValidPayError(
                "invalid_response",
                "API response missing retrieval_id",
                details=data,
            )

        return CreateIntentResult(retrieval_id=retrieval_id, key=result_key)

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
            valid_from = item.get("valid_from")
            valid_until = item.get("valid_until")
            try:
                _validate_time_lock(valid_from, valid_until)
            except ValidPayError as exc:
                raise ValidPayError(
                    "invalid_argument",
                    f"intents[{idx}]: {exc.message}",
                ) from exc

            key = generate_key()
            keys.append(key)
            plaintext = json.dumps(item["payload"])
            # M-5: bind document_type + validity window as AAD per item.
            aad = build_aad(doc_type, valid_from, valid_until)
            encrypted_payload = encrypt(plaintext, key, aad)
            req_item: Dict[str, Any] = {
                "document_type": doc_type,
                "encrypted_payload": encrypted_payload,
                # Commitment v2: hash the ciphertext, not the plaintext (C-1).
                "commitment_hash": compute_commitment_hash(encrypted_payload),
                "encryption_version": 2,
            }
            if valid_from is not None:
                req_item["valid_from"] = valid_from
            if valid_until is not None:
                req_item["valid_until"] = valid_until
            on_behalf_of = item.get("on_behalf_of")
            if on_behalf_of is not None:
                req_item["on_behalf_of"] = on_behalf_of
            request_items.append(req_item)

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

    def _fetch_fragment_b(self, retrieval_id: str) -> str:
        """Fetch Share B from the public fragment endpoint (Patent C)."""
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
        return share_b

    def _fetch_pieces(self, retrieval_id: str) -> List[str]:
        """Fetch the End-Cell PLATFORM share(s) from the API /fragment endpoint.

        The rail share is NOT here — it is fetched separately from the KeyHalve rail.
        """
        data = self._request(
            "GET",
            f"/v1/intent/{quote(retrieval_id, safe='')}/fragment",
            auth=False,
        )
        if isinstance(data, dict) and data.get("error"):
            raise ValidPayError(
                str(data.get("error")),
                f"Fragment retrieval failed: {data.get('error')}",
                details=data,
            )
        pieces = data.get("pieces") if isinstance(data, dict) else None
        if not isinstance(pieces, dict) or not pieces:
            raise ValidPayError("missing_fragment", "Server did not return End-Cell pieces", details=data)
        order = data.get("holders") or list(pieces.keys())
        result = [pieces[h] for h in order if pieces.get(h)]
        if len(result) != len(order):
            raise ValidPayError("missing_fragment", "An End-Cell piece was missing", details=data)
        return result

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

        # Split-Key Verification (Patent C). Since 1.1.0 split-key is the
        # default issue path, so the key the caller holds is Share A —
        # fetch Share B from the fragment endpoint and XOR-combine, so
        # create_intent -> verify_intent round-trips keep working.
        if data.get("end_cell"):
            # Custody separation: platform share(s) from the API + the rail share from
            # the independent KeyHalve rail (signature-verified vs the pinned key),
            # XOR-combined with ShareA. Fails closed if either is missing.
            platform_pieces = self._fetch_pieces(retrieval_id)
            rail_piece = fetch_rail_piece(
                self._session,
                self._rail_base_url,
                self._rail_public_key_spki,
                retrieval_id,
                self._timeout,
            )
            key = combine_key_pieces(key, [*platform_pieces, rail_piece])
        elif data.get("split_key"):
            key = combine_key_shares(key, self._fetch_fragment_b(retrieval_id))

        # Commitment check over the ciphertext (C-1) — proves the server
        # hasn't swapped the blob. Done before decryption since it no longer
        # needs the plaintext. Legacy v1 intents skip this check.
        integrity_verified = _verify_commitment(data)

        # M-5: pass the reconstructed AAD for v2 intents so altered metadata
        # fails the GCM tag check.
        decrypted = decrypt(data["encrypted_payload"], key, _aad_for(data))

        try:
            payload = json.loads(decrypted)
        except json.JSONDecodeError as exc:
            raise ValidPayError(
                "invalid_payload",
                "Decrypted payload is not valid JSON",
            ) from exc

        valid_from_str = data.get("valid_from")
        valid_until_str = data.get("valid_until")
        time_lock_status = _compute_time_lock_status(valid_from_str, valid_until_str)

        return VerifyIntentResult(
            intent_id=data.get("intent_id", ""),
            payload=payload,
            issuer=data.get("issuer", ""),
            issuer_verified=bool(data.get("issuer_verified", False)),
            registered_at=data.get("registered_at", ""),
            status=data.get("status", ""),
            integrity_verified=integrity_verified,
            verification_level=data.get("verification_level"),
            delegated_by=data.get("delegated_by"),
            valid_from=valid_from_str,
            valid_until=valid_until_str,
            time_lock_status=time_lock_status,
        )

    def create_split_key_intent(
        self,
        document_type: str,
        payload: Any,
        *,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
    ) -> CreateIntentResult:
        """Deprecated alias for :meth:`create_intent` (since SDK 1.1.0).

        Split-key protection (Patent C) is the default for
        ``create_intent`` now, so this method adds nothing. It is kept so
        1.0.x code keeps working; new code should call ``create_intent``.
        """
        warnings.warn(
            "create_split_key_intent() is deprecated since validpay 1.1.0: "
            "create_intent() uses split-key protection by default. Call "
            "create_intent() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.create_intent(
            document_type,
            payload,
            valid_from=valid_from,
            valid_until=valid_until,
            split_key=True,
        )

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

        share_b = self._fetch_fragment_b(retrieval_id)

        # Commitment check over the ciphertext (C-1); legacy v1 skips.
        integrity_verified = _verify_commitment(data)

        full_key = combine_key_shares(share_a, share_b)
        # M-5: AAD bound for v2 intents.
        decrypted = decrypt(data["encrypted_payload"], full_key, _aad_for(data))

        try:
            payload = json.loads(decrypted)
        except json.JSONDecodeError as exc:
            raise ValidPayError(
                "invalid_payload",
                "Decrypted payload is not valid JSON",
            ) from exc

        valid_from_str = data.get("valid_from")
        valid_until_str = data.get("valid_until")
        time_lock_status = _compute_time_lock_status(valid_from_str, valid_until_str)

        return VerifyIntentResult(
            intent_id=data.get("intent_id", ""),
            payload=payload,
            issuer=data.get("issuer", ""),
            issuer_verified=bool(data.get("issuer_verified", False)),
            registered_at=data.get("registered_at", ""),
            status=data.get("status", ""),
            integrity_verified=integrity_verified,
            verification_level=data.get("verification_level"),
            delegated_by=data.get("delegated_by"),
            valid_from=valid_from_str,
            valid_until=valid_until_str,
            time_lock_status=time_lock_status,
        )

    def create_selective_intent(
        self,
        document_type: str,
        payload: dict,
        disclosure_policy: dict,
        *,
        split_key: bool = False,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        on_behalf_of: Optional[Dict[str, str]] = None,
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
        _validate_time_lock(valid_from, valid_until)

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

        envelope = json.dumps(encrypted_fields)
        # Commitment v2: hash the transported ciphertext envelope, not the
        # plaintext (C-1). Role-independent — the server hashes this exact
        # string and the verifier recomputes it.
        commitment_hash = compute_commitment_hash(envelope)

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
        if valid_from is not None:
            body["valid_from"] = valid_from
        if valid_until is not None:
            body["valid_until"] = valid_until
        if on_behalf_of is not None:
            body["on_behalf_of"] = on_behalf_of

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

        # Commitment over the ciphertext envelope (C-1) — role-independent
        # now, since it no longer requires decrypting the full payload.
        # Legacy v1 intents skip this check.
        integrity_verified = _verify_commitment(data)

        valid_from_str = data.get("valid_from")
        valid_until_str = data.get("valid_until")
        time_lock_status = _compute_time_lock_status(valid_from_str, valid_until_str)

        return VerifyIntentResult(
            intent_id=data.get("intent_id", ""),
            payload=payload,
            issuer=data.get("issuer", ""),
            issuer_verified=bool(data.get("issuer_verified", False)),
            registered_at=data.get("registered_at", ""),
            status=data.get("status", ""),
            integrity_verified=integrity_verified,
            verification_level=data.get("verification_level"),
            delegated_by=data.get("delegated_by"),
            valid_from=valid_from_str,
            valid_until=valid_until_str,
            time_lock_status=time_lock_status,
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
