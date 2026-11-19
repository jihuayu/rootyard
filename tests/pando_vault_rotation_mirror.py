#!/usr/bin/env python3
"""Complete typed mirror validation for the issue #21 negative oracle.

This does not re-implement encryption or MAC verification.  It validates the
full authenticated ``KmsEnvelopeRecord`` shape and bindings that the product
requires, compares the DB-visible and manifest-visible fields, and optionally
requires equality with a previously validated healthy record.
"""
from __future__ import annotations

import json
import re
import stat

from pando_vault_rotation_support import (
    QualificationError,
    mirror_path,
    require,
    valid_uuid,
)

MIRROR_SCHEMA = "rootyard.pando.kms-envelope.v1"
MIRROR_MODE = "authenticated-envelope-v1"
MIRROR_FIELDS = frozenset({
    "schema", "repo", "pack_id", "key_id", "key_version", "cipher_suite",
    "pack_sha256", "idx_sha256", "plaintext_sha256", "envelope_mac",
    "storage_tier", "encryption_mode", "envelope_id", "nonce_prefix",
    "wrapped_key_json", "ciphertext_sha256", "ciphertext_bytes",
    "provider_kind",
})
WRAPPED_FIELDS = frozenset({"pando_wrapped_dek"})
WRAPPED_BODY_FIELDS = frozenset({
    "version", "provider_kind", "key_id", "key_version", "payload_hex",
})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
CIPHER_SUITES = frozenset({"AES-256-GCM-HMAC-SHA256",
                           "CHACHA20-POLY1305-SHA256"})
STORAGE_TIERS = frozenset({"hot", "cold_archive"})


def _valid_sha256(value):
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _valid_wrapped(record, stage):
    wrapped = record.get("wrapped_key_json")
    require(isinstance(wrapped, str) and bool(wrapped)
            and len(wrapped) <= 16 * 1024,
            "mirror_wrapped_key_missing", stage)
    try:
        wrapper = json.loads(wrapped)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise QualificationError("mirror_wrapped_key_invalid", stage) from None
    require(isinstance(wrapper, dict) and set(wrapper) == WRAPPED_FIELDS,
            "mirror_wrapped_key_shape", stage)
    body = wrapper.get("pando_wrapped_dek")
    require(isinstance(body, dict) and set(body) == WRAPPED_BODY_FIELDS,
            "mirror_wrapped_key_shape", stage)
    require(type(body.get("version")) is int and body["version"] == 1,
            "mirror_wrapped_key_version", stage)
    require(body.get("provider_kind") == record.get("provider_kind"),
            "mirror_wrapped_key_provider", stage)
    require(body.get("key_id") == record.get("key_id"),
            "mirror_wrapped_key_identity", stage)
    require(body.get("key_version") == record.get("key_version"),
            "mirror_wrapped_key_identity", stage)
    payload_hex = body.get("payload_hex")
    require(isinstance(payload_hex, str) and bool(payload_hex)
            and len(payload_hex) <= 8192 and HEX_RE.fullmatch(payload_hex),
            "mirror_wrapped_payload_invalid", stage)
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        raise QualificationError("mirror_wrapped_payload_invalid", stage) from None
    prefix = ("vault:v%d:" % record["key_version"]).encode()
    require(payload.startswith(prefix) and len(payload) > len(prefix)
            and all(32 <= byte < 127 for byte in payload[len(prefix):]),
            "mirror_wrapped_key_binding", stage)
    return True


def read_complete_mirror(ctx, pack, canonical=None, db=None,
                         stage="mirror_validation"):
    """Require a regular, complete, typed and identity-bound mirror record.

    ``db`` may be the healthy pre-tamper DB snapshot when the live row is
    intentionally mutated; otherwise it is read from the context.
    """
    path = mirror_path(ctx.root.path, ctx.repo, pack)
    try:
        info = path.lstat()
    except OSError:
        raise QualificationError("mirror_missing", stage) from None
    require(stat.S_ISREG(info.st_mode), "mirror_not_regular", stage)
    try:
        raw = path.read_bytes()
    except OSError:
        raise QualificationError("mirror_unreadable", stage) from None
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise QualificationError("mirror_invalid_json", stage) from None
    require(isinstance(record, dict), "mirror_invalid_shape", stage)
    require(set(record) == MIRROR_FIELDS, "mirror_fields_incomplete", stage)
    require(record.get("schema") == MIRROR_SCHEMA, "mirror_schema_invalid", stage)
    require(valid_uuid(record.get("repo")) and record["repo"] == ctx.repo,
            "mirror_repo_invalid", stage)
    require(valid_uuid(record.get("pack_id")) and record["pack_id"] == pack,
            "mirror_pack_invalid", stage)
    require(isinstance(record.get("key_id"), str)
            and KEY_ID_RE.fullmatch(record["key_id"]) is not None,
            "mirror_key_id_invalid", stage)
    require(type(record.get("key_version")) is int
            and record["key_version"] >= 1, "mirror_key_version_invalid", stage)
    require(record.get("cipher_suite") in CIPHER_SUITES,
            "mirror_cipher_suite_invalid", stage)
    for name in ("pack_sha256", "idx_sha256", "plaintext_sha256",
                 "envelope_mac", "ciphertext_sha256"):
        require(_valid_sha256(record.get(name)), "mirror_" + name + "_invalid",
                stage)
    require(record.get("storage_tier") in STORAGE_TIERS,
            "mirror_storage_tier_invalid", stage)
    require(record.get("encryption_mode") == MIRROR_MODE,
            "mirror_mode_invalid", stage)
    require(valid_uuid(record.get("envelope_id")), "mirror_envelope_id_invalid",
            stage)
    nonce = record.get("nonce_prefix")
    require(isinstance(nonce, str) and bool(nonce)
            and HEX_RE.fullmatch(nonce) is not None,
            "mirror_nonce_prefix_invalid", stage)
    require(type(record.get("ciphertext_bytes")) is int
            and record["ciphertext_bytes"] >= 0,
            "mirror_ciphertext_bytes_invalid", stage)
    require(record.get("provider_kind") == "vault-transit",
            "mirror_provider_kind_invalid", stage)
    _valid_wrapped(record, stage)
    if db is None:
        db = ctx.envelope(pack)
    manifest = ctx.manifest(pack)
    for name in ("key_id", "key_version", "cipher_suite", "plaintext_sha256",
                 "envelope_mac", "encryption_mode", "ciphertext_sha256",
                 "ciphertext_bytes", "provider_kind"):
        require(record[name] == db.get(name), "mirror_db_" + name + "_mismatch",
                stage)
    for name in ("pack_sha256", "idx_sha256"):
        require(record[name] == manifest.get(name),
                "mirror_manifest_" + name + "_mismatch", stage)
    require(record["plaintext_sha256"] == manifest.get("pack_sha256"),
            "mirror_manifest_plaintext_mismatch", stage)
    require(record["ciphertext_sha256"] == manifest.get("ciphertext_sha256"),
            "mirror_manifest_ciphertext_mismatch", stage)
    require(record["ciphertext_bytes"] == manifest.get("ciphertext_bytes"),
            "mirror_manifest_ciphertext_bytes_mismatch", stage)
    require(record["encryption_mode"] == manifest.get("encryption_mode"),
            "mirror_manifest_mode_mismatch", stage)
    if canonical is not None:
        require(record == canonical, "mirror_not_full_canonical", stage)
    return path, raw, record
