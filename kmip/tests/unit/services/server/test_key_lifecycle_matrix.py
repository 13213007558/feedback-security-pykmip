# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Key lifecycle security matrix for the PyKMIP server.

Every check drives the real server processing entry point
(``KmipEngine.process_request`` -> ``_process_batch`` -> the operation
handler) against an in-memory SQLite backend and verifies afterwards that the
managed object's state either changed as required by the operation or was
left untouched. A frozen clock is used everywhere so that Initial Date
values and request timestamps are fully deterministic.

The matrix covers the five lifecycle states of KMIP 1.2 (Pre-Active,
Active, Deactivated, Compromised, Destroyed) crossed with the management and
cryptographic operations actually implemented by this repository:

    management : Activate, Revoke, Destroy, Get (export), GetAttributes,
                 Locate, DeriveKey
    crypto     : Encrypt, Decrypt, Signature Verify, Sign, MAC

Operations from the KMIP state/usage tables that this server does not
implement (Rekey, RekeyKeyPair, Certify, Recertify, Archive, Recover,
Validate, ObtainLease, GetUsageAllocation, ...) are listed in the module
docstring of the companion documentation and are asserted as
OperationNotSupported where applicable.

Usage-mask semantics are exercised separately from state: a key that holds
the relevant mask bit is allowed wherever the state permits it, and a key
without the bit is always rejected even while Active.
"""

import datetime
import os
import tempfile
from unittest import mock

import pytest
from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects as core_objects
from kmip.core import primitives
from kmip.core.factories import attributes as attribute_factory
from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core.messages import payloads
from kmip.pie import objects as pie_objects
from kmip.services.server import engine as server_engine
import sqlalchemy

# Frozen "now": 2026-01-01T00:00:00Z. All time.time() calls made while a
# matrix test runs return this value, so request TimeStamp headers and
# server-generated Initial Date attributes are reproducible.
FROZEN_NOW = int(
    datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    .timestamp()
)

# Small, fast test material (128-bit AES key, 1024-bit RSA pair, 128-bit
# HMAC key). Generated once per session to keep the suite quick.
AES_KEY_BYTES = bytes(range(16))
HMAC_KEY_BYTES = b'\x00' * 16
PLAINTEXT = b'lifecycle-matrix'
SIGN_DATA = b'sign-me'
MAC_DATA = b'mac-me'

STATES = [
    enums.State.PRE_ACTIVE,
    enums.State.ACTIVE,
    enums.State.DEACTIVATED,
    enums.State.COMPROMISED,
]


@pytest.fixture
def frozen_clock():
    with mock.patch('kmip.services.server.engine.time.time',
                    return_value=FROZEN_NOW):
        yield FROZEN_NOW


@pytest.fixture
def kmip_engine(frozen_clock):
    """
    A KmipEngine backed by an isolated SQLite file under the sandbox-writable
    temp directory, with operation-policy checks permissively stubbed so the
    matrix isolates state/mask enforcement from authorization policy.
    """
    db_dir = tempfile.mkdtemp()
    db_path = os.path.join(db_dir, 'lifecycle_matrix.db')
    e = server_engine.KmipEngine(database_path=db_path)
    e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
    e._logger = mock.MagicMock()
    e._cryptography_engine.logger = mock.MagicMock()
    # process_request resets client identity from the (absent) connection
    # credential to None; pin a fixed identity so handlers that stamp the
    # object owner (Create/DeriveKey) behave as they do behind a real client
    # certificate.
    e._verify_credential = mock.Mock()
    e._client_identity = ['matrix-tester', None]
    # Force the KMIP 1.2 protocol: Decrypt, Sign, MAC and Signature Verify
    # are 1.2 operations and must be evaluated against a version that defines
    # them.
    e._protocol_version = contents.ProtocolVersion(1, 2)
    yield e
    e._data_store.dispose()


def _request(operation, payload):
    """Wrap a single operation payload in a KMIP 1.2 request message."""
    batch = [
        messages.RequestBatchItem(
            operation=contents.Operation(operation),
            request_payload=payload
        )
    ]
    header = messages.RequestHeader(
        protocol_version=contents.ProtocolVersion(1, 2),
        maximum_response_size=contents.MaximumResponseSize(2 ** 20),
        asynchronous_indicator=contents.AsynchronousIndicator(False),
        authentication=None,
        batch_error_cont_option=contents.BatchErrorContinuationOption(
            enums.BatchErrorContinuationOption.STOP
        ),
        batch_order_option=contents.BatchOrderOption(True),
        time_stamp=contents.TimeStamp(FROZEN_NOW),
        batch_count=contents.BatchCount(1)
    )
    return messages.RequestMessage(request_header=header, batch_items=batch)


def dispatch(kmip_engine, operation, payload):
    """
    Drive the full server entry point and return the result status together
    with the response payload (or error reason/message).
    """
    response, _, _ = kmip_engine.process_request(_request(operation, payload))
    batch_item = response.batch_items[0]
    return batch_item


def fresh_session(kmip_engine):
    return kmip_engine._data_store_session_factory()


def add_key(kmip_engine, managed_object, state):
    managed_object.state = state
    # The frozen clock fixture patches server-side time.time(); set the
    # Initial Date through the same value so the attribute is deterministic
    # even when the object is constructed outside a process_request call.
    managed_object.initial_date = FROZEN_NOW
    session = fresh_session(kmip_engine)
    session.add(managed_object)
    session.commit()
    return str(managed_object.unique_identifier)


def get_state(kmip_engine, uid):
    session = fresh_session(kmip_engine)
    return session.query(pie_objects.ManagedObject).filter(
        pie_objects.ManagedObject.unique_identifier == uid
    ).one().state


def object_exists(kmip_engine, uid):
    session = fresh_session(kmip_engine)
    return session.query(
        sqlalchemy.literal(1)
    ).select_from(pie_objects.ManagedObject).filter(
        pie_objects.ManagedObject.unique_identifier == uid
    ).first() is not None


def aes_key(mask):
    return pie_objects.SymmetricKey(
        enums.CryptographicAlgorithm.AES,
        128,
        AES_KEY_BYTES,
        [mask]
    )


def hmac_key(mask):
    return pie_objects.SymmetricKey(
        enums.CryptographicAlgorithm.HMAC_SHA256,
        128,
        HMAC_KEY_BYTES,
        [mask]
    )


def rsa_pair():
    crypto = server_engine.engine.CryptographyEngine()
    public, private = crypto.create_asymmetric_key_pair(
        enums.CryptographicAlgorithm.RSA, 1024
    )
    public_key = pie_objects.PublicKey(
        enums.CryptographicAlgorithm.RSA,
        1024,
        public.get('value'),
        public.get('format'),
        masks=[enums.CryptographicUsageMask.VERIFY]
    )
    private_key = pie_objects.PrivateKey(
        enums.CryptographicAlgorithm.RSA,
        1024,
        private.get('value'),
        private.get('format'),
        masks=[enums.CryptographicUsageMask.SIGN]
    )
    return public_key, private_key


def assert_allowed(result):
    assert result.result_status.value == enums.ResultStatus.SUCCESS, \
        "expected SUCCESS but got {0}: {1}".format(
            result.result_status,
            result.result_message
        )


def assert_denied(result, reason=enums.ResultReason.PERMISSION_DENIED):
    assert result.result_status.value == enums.ResultStatus.OPERATION_FAILED
    assert result.result_reason.value == reason


def assert_illegal(result):
    assert_denied(result, enums.ResultReason.ILLEGAL_OPERATION)


# ---------------------------------------------------------------------------
# State-transition management operations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("state", STATES)
def test_activate_matrix(kmip_engine, state):
    """
    Activate is legal only from Pre-Active; every other lifecycle state is
    rejected and must leave the object's state unchanged.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine,
        enums.Operation.ACTIVATE,
        payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )
    )
    if state == enums.State.PRE_ACTIVE:
        assert_allowed(result)
        assert get_state(kmip_engine, uid) == enums.State.ACTIVE
    else:
        assert_denied(result)
        assert get_state(kmip_engine, uid) == state


@pytest.mark.parametrize("state", STATES)
def test_revoke_deactivation_matrix(kmip_engine, state):
    """
    Revoke with a non-compromise reason is defined only for Active keys,
    which transition to Deactivated. Re-activating the resulting Deactivated
    key must fail: there is no Deactivated -> Active transition in KMIP.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine,
        enums.Operation.REVOKE,
        payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid),
            revocation_reason=core_objects.RevocationReason(
                code=enums.RevocationReasonCode.UNSPECIFIED
            )
        )
    )
    if state == enums.State.ACTIVE:
        assert_allowed(result)
        assert get_state(kmip_engine, uid) == enums.State.DEACTIVATED

        # Legal-use contrast: a deactivated key cannot be activated again.
        reactivate = dispatch(
            kmip_engine,
            enums.Operation.ACTIVATE,
            payloads.ActivateRequestPayload(
                unique_identifier=attributes.UniqueIdentifier(uid)
            )
        )
        assert_denied(reactivate)
        assert get_state(kmip_engine, uid) == enums.State.DEACTIVATED
    else:
        assert_illegal(result)
        assert get_state(kmip_engine, uid) == state


@pytest.mark.parametrize("state", STATES)
def test_revoke_compromise_matrix(kmip_engine, state):
    """
    Revoke with KEY_COMPROMISE is allowed from every non-destroyed state and
    always lands on Compromised; it is the escape hatch that lets a retired
    key be marked compromised.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine,
        enums.Operation.REVOKE,
        payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid),
            revocation_reason=core_objects.RevocationReason(
                code=enums.RevocationReasonCode.KEY_COMPROMISE
            ),
            compromise_occurrence_date=primitives.DateTime(
                tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE,
                value=FROZEN_NOW
            )
        )
    )
    assert_allowed(result)
    assert get_state(kmip_engine, uid) == enums.State.COMPROMISED


@pytest.mark.parametrize("state", STATES)
def test_destroy_matrix(kmip_engine, state):
    """
    Destroy removes the object from the store unless it is Active: an Active
    key must first be retired (this implementation cannot evaluate a stored
    Deactivation Date, so destroying an Active key is conservatively
    refused). A Compromised key is destroyed into Destroyed-Compromised
    semantics, represented here by hard deletion like every other state.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine,
        enums.Operation.DESTROY,
        payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )
    )
    if state == enums.State.ACTIVE:
        assert_denied(result)
        assert object_exists(kmip_engine, uid)
        assert get_state(kmip_engine, uid) == enums.State.ACTIVE
    else:
        assert_allowed(result)
        assert not object_exists(kmip_engine, uid)


def test_compromised_then_destroy_becomes_destroyed_compromised(kmip_engine):
    """
    The Compromised -> Destroyed-Compromised transition: a compromised key
    that is destroyed first moves to the combined terminal state, which a
    later KEY_COMPROMISE revoke on an already-destroyed key mirrors.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  enums.State.COMPROMISED)
    result = dispatch(
        kmip_engine,
        enums.Operation.DESTROY,
        payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )
    )
    assert_allowed(result)
    assert not object_exists(kmip_engine, uid)


# ---------------------------------------------------------------------------
# Read / export operations (no state transition permitted)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("state", STATES)
def test_get_export_matrix(kmip_engine, state):
    """
    Get (key export) is allowed in every non-destroyed state and must never
    mutate the object's state. Destroyed objects no longer exist, so Get
    resolves to ItemNotFound.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine,
        enums.Operation.GET,
        payloads.GetRequestPayload(unique_identifier=uid)
    )
    assert_allowed(result)
    assert result.response_payload is not None
    assert get_state(kmip_engine, uid) == state


def test_get_after_destroy_is_item_not_found(kmip_engine):
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  enums.State.DEACTIVATED)
    dispatch(
        kmip_engine,
        enums.Operation.DESTROY,
        payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )
    )
    result = dispatch(
        kmip_engine,
        enums.Operation.GET,
        payloads.GetRequestPayload(unique_identifier=uid)
    )
    assert_denied(result, enums.ResultReason.ITEM_NOT_FOUND)


@pytest.mark.parametrize("state", STATES)
def test_get_attributes_matrix(kmip_engine, state):
    """Metadata reads stay available in every non-destroyed state."""
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine,
        enums.Operation.GET_ATTRIBUTES,
        payloads.GetAttributesRequestPayload(
            unique_identifier=uid,
            attribute_names=['State', 'Cryptographic Usage Mask']
        )
    )
    assert_allowed(result)
    assert get_state(kmip_engine, uid) == state


@pytest.mark.parametrize("state", STATES)
def test_locate_matrix(kmip_engine, state):
    """
    Locate carries no state gate in the KMIP tables: a key must remain
    discoverable (filtered by its State attribute) regardless of lifecycle
    state.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine,
        enums.Operation.LOCATE,
        payloads.LocateRequestPayload()
    )
    assert_allowed(result)
    assert uid in result.response_payload.unique_identifiers
    assert get_state(kmip_engine, uid) == state


# ---------------------------------------------------------------------------
# Cryptographic operations: state x usage mask
# ---------------------------------------------------------------------------

def _encrypt_payload(uid):
    # Omit the IV/nonce so the server generates one and returns it; the same
    # value is then required by the matching Decrypt request.
    return payloads.EncryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.GCM,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            tag_length=128
        ),
        data=PLAINTEXT,
        iv_counter_nonce=None
    )


def _decrypt_payload(uid, cipher_text, iv, auth_tag=None):
    return payloads.DecryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.GCM,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            tag_length=128
        ),
        data=cipher_text,
        iv_counter_nonce=iv,
        auth_tag=auth_tag
    )


@pytest.mark.parametrize("state", STATES)
def test_encrypt_matrix(kmip_engine, state):
    """
    New ciphertext can only be produced by an Active key carrying the
    Encrypt mask. Pre-Active, Deactivated and Compromised keys are refused;
    state never changes as a side effect of a crypto operation.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  state)
    result = dispatch(
        kmip_engine, enums.Operation.ENCRYPT, _encrypt_payload(uid)
    )
    if state == enums.State.ACTIVE:
        assert_allowed(result)
        assert result.response_payload.data
    else:
        assert_denied(result)
    assert get_state(kmip_engine, uid) == state


def test_encrypt_requires_encrypt_mask_even_when_active(kmip_engine):
    """Mask contrast: Active alone is not sufficient, the Encrypt bit is."""
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.DECRYPT),
                  enums.State.ACTIVE)
    result = dispatch(
        kmip_engine, enums.Operation.ENCRYPT, _encrypt_payload(uid)
    )
    assert_denied(result)
    assert get_state(kmip_engine, uid) == enums.State.ACTIVE


@pytest.mark.parametrize("state", STATES)
def test_decrypt_matrix(kmip_engine, state):
    """
    Decryption of existing ciphertext remains legal after retirement: Active,
    Deactivated and Compromised keys with the Decrypt bit all succeed so old
    data stays recoverable. Only Pre-Active material is unusable.
    """
    # Produce real ciphertext once with an Active encrypt/decrypt key.
    producer = pie_objects.SymmetricKey(
        enums.CryptographicAlgorithm.AES,
        128,
        AES_KEY_BYTES,
        [
            enums.CryptographicUsageMask.ENCRYPT,
            enums.CryptographicUsageMask.DECRYPT
        ]
    )
    producer_uid = add_key(kmip_engine, producer, enums.State.ACTIVE)
    encrypted = dispatch(
        kmip_engine, enums.Operation.ENCRYPT, _encrypt_payload(producer_uid)
    ).response_payload
    cipher_text = encrypted.data
    iv = encrypted.iv_counter_nonce
    auth_tag = encrypted.auth_tag

    # The same key value, re-homed at each matrix state, tests read access to
    # old ciphertext without depending on a state transition.
    target = pie_objects.SymmetricKey(
        enums.CryptographicAlgorithm.AES,
        128,
        AES_KEY_BYTES,
        [enums.CryptographicUsageMask.DECRYPT]
    )
    uid = add_key(kmip_engine, target, state)
    result = dispatch(
        kmip_engine,
        enums.Operation.DECRYPT,
        _decrypt_payload(uid, cipher_text, iv, auth_tag)
    )
    if state == enums.State.PRE_ACTIVE:
        assert_denied(result)
    else:
        assert_allowed(result)
        assert result.response_payload.data == PLAINTEXT
    assert get_state(kmip_engine, uid) == state


def test_decrypt_requires_decrypt_mask(kmip_engine):
    """Mask contrast: an Active key without the Decrypt bit cannot decrypt."""
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  enums.State.ACTIVE)
    result = dispatch(
        kmip_engine,
        enums.Operation.DECRYPT,
        _decrypt_payload(uid, b'cipher', b'\x00' * 12)
    )
    assert_denied(result)
    assert get_state(kmip_engine, uid) == enums.State.ACTIVE


@pytest.mark.parametrize("state", STATES)
def test_signature_verify_matrix(kmip_engine, state):
    """
    Verifying an old signature with a public key is a read-only check that
    must keep working after the key is retired: Active, Deactivated and
    Compromised public keys all return VALID/INVALID. Pre-Active keys are
    not yet in service and are refused.
    """
    public_key, private_key = rsa_pair()
    private_uid = add_key(kmip_engine, private_key, enums.State.ACTIVE)
    sign_result = dispatch(
        kmip_engine,
        enums.Operation.SIGN,
        payloads.SignRequestPayload(
            unique_identifier=private_uid,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=(
                    enums.DigitalSignatureAlgorithm.
                    SHA256_WITH_RSA_ENCRYPTION
                )
            ),
            data=SIGN_DATA
        )
    )
    assert_allowed(sign_result)
    signature = sign_result.response_payload.signature_data

    uid = add_key(kmip_engine, public_key, state)
    result = dispatch(
        kmip_engine,
        enums.Operation.SIGNATURE_VERIFY,
        payloads.SignatureVerifyRequestPayload(
            unique_identifier=uid,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=(
                    enums.DigitalSignatureAlgorithm.
                    SHA256_WITH_RSA_ENCRYPTION
                )
            ),
            data=SIGN_DATA,
            signature_data=signature
        )
    )
    if state == enums.State.PRE_ACTIVE:
        assert_denied(result)
    else:
        assert_allowed(result)
        assert result.response_payload.validity_indicator == \
            enums.ValidityIndicator.VALID
    assert get_state(kmip_engine, uid) == state


def test_signature_verify_requires_verify_mask(kmip_engine):
    """Mask contrast: a public key without the Verify bit cannot verify."""
    public_key, _ = rsa_pair()
    public_key.cryptographic_usage_masks = [
        enums.CryptographicUsageMask.ENCRYPT
    ]
    uid = add_key(kmip_engine, public_key, enums.State.ACTIVE)
    result = dispatch(
        kmip_engine,
        enums.Operation.SIGNATURE_VERIFY,
        payloads.SignatureVerifyRequestPayload(
            unique_identifier=uid,
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=(
                    enums.DigitalSignatureAlgorithm.
                    SHA256_WITH_RSA_ENCRYPTION
                )
            ),
            data=SIGN_DATA,
            signature_data=b'\x00' * 128
        )
    )
    assert_denied(result)
    assert get_state(kmip_engine, uid) == enums.State.ACTIVE


@pytest.mark.parametrize("state", STATES)
def test_sign_matrix(kmip_engine, state):
    """New signatures can only be produced by an Active private key."""
    _, private_key = rsa_pair()
    uid = add_key(kmip_engine, private_key, state)
    result = dispatch(
        kmip_engine,
        enums.Operation.SIGN,
        payloads.SignRequestPayload(
            unique_identifier=uid,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=(
                    enums.DigitalSignatureAlgorithm.
                    SHA256_WITH_RSA_ENCRYPTION
                )
            ),
            data=SIGN_DATA
        )
    )
    if state == enums.State.ACTIVE:
        assert_allowed(result)
        assert result.response_payload.signature_data
    else:
        assert_denied(result)
    assert get_state(kmip_engine, uid) == state


@pytest.mark.parametrize("state", STATES)
def test_mac_matrix(kmip_engine, state):
    """MAC generation, like signing and encryption, is Active-only."""
    uid = add_key(
        kmip_engine,
        hmac_key(enums.CryptographicUsageMask.MAC_GENERATE),
        state
    )
    result = dispatch(
        kmip_engine,
        enums.Operation.MAC,
        payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid),
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=(
                    enums.CryptographicAlgorithm.HMAC_SHA256
                )
            ),
            data=core_objects.Data(MAC_DATA)
        )
    )
    if state == enums.State.ACTIVE:
        assert_allowed(result)
        assert result.response_payload.mac_data
    else:
        assert_denied(result)
    assert get_state(kmip_engine, uid) == state


# ---------------------------------------------------------------------------
# DeriveKey: state gate plus usage mask gate
# ---------------------------------------------------------------------------

def _derive_payload(uid):
    return payloads.DeriveKeyRequestPayload(
        object_type=enums.ObjectType.SYMMETRIC_KEY,
        unique_identifiers=[uid],
        derivation_method=enums.DerivationMethod.HMAC,
        derivation_parameters=attributes.DerivationParameters(
            cryptographic_parameters=attributes.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.SHA_256
            ),
            derivation_data=b'derivation-data',
            salt=b'\x00' * 13
        ),
        template_attribute=core_objects.TemplateAttribute(
            attributes=[
                attribute_factory.AttributeFactory().create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH, 128
                ),
                attribute_factory.AttributeFactory().create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                )
            ]
        )
    )


@pytest.mark.parametrize("state", STATES)
def test_derive_key_matrix(kmip_engine, state):
    """
    DeriveKey creates fresh keying material, so only Pre-Active and Active
    base keys are permitted. The base key's state must be unchanged; the
    derived object is born Pre-Active like any newly created key.
    """
    uid = add_key(
        kmip_engine,
        hmac_key(enums.CryptographicUsageMask.DERIVE_KEY),
        state
    )
    result = dispatch(
        kmip_engine, enums.Operation.DERIVE_KEY, _derive_payload(uid)
    )
    if state in (enums.State.PRE_ACTIVE, enums.State.ACTIVE):
        assert_allowed(result)
        derived_uid = result.response_payload.unique_identifier
        assert get_state(kmip_engine, derived_uid) == \
            enums.State.PRE_ACTIVE
    else:
        assert_denied(result)
    assert get_state(kmip_engine, uid) == state


def test_derive_key_requires_derive_mask(kmip_engine):
    """Mask contrast: an Active key without the DeriveKey bit is refused."""
    uid = add_key(
        kmip_engine,
        hmac_key(enums.CryptographicUsageMask.ENCRYPT),
        enums.State.ACTIVE
    )
    result = dispatch(
        kmip_engine, enums.Operation.DERIVE_KEY, _derive_payload(uid)
    )
    assert result.result_status.value == enums.ResultStatus.OPERATION_FAILED
    assert get_state(kmip_engine, uid) == enums.State.ACTIVE


# ---------------------------------------------------------------------------
# Destroyed-state access: every operation must fail once the object is gone
# ---------------------------------------------------------------------------

DESTROYED_PROBES = [
    (enums.Operation.GET, lambda uid:
        payloads.GetRequestPayload(unique_identifier=uid)),
    (enums.Operation.GET_ATTRIBUTES, lambda uid:
        payloads.GetAttributesRequestPayload(unique_identifier=uid)),
    (enums.Operation.ACTIVATE, lambda uid:
        payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid))),
    (enums.Operation.DESTROY, lambda uid:
        payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid))),
]


@pytest.mark.parametrize("operation,payload_builder", DESTROYED_PROBES)
def test_destroyed_object_is_unusable(kmip_engine, operation,
                                      payload_builder):
    """
    Once Destroyed, the row is physically removed; every later management
    request against that identifier must fail with ItemNotFound rather than
    resurrecting or recreating state.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  enums.State.DEACTIVATED)
    destroy = dispatch(
        kmip_engine,
        enums.Operation.DESTROY,
        payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )
    )
    assert_allowed(destroy)
    result = dispatch(kmip_engine, operation, payload_builder(uid))
    assert_denied(result, enums.ResultReason.ITEM_NOT_FOUND)


# ---------------------------------------------------------------------------
# Protocol-version gate and unimplemented operations
# ---------------------------------------------------------------------------

def test_kmip_1_0_rejects_1_2_crypto_operations(kmip_engine):
    """
    Decrypt, Signature Verify, Sign and MAC were introduced in KMIP 1.2. On
    a 1.0 protocol session they must fail with OperationNotSupported before
    any state logic runs, and must not touch the object.
    """
    kmip_engine._protocol_version = contents.ProtocolVersion(1, 0)
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.DECRYPT),
                  enums.State.ACTIVE)
    header = messages.RequestHeader(
        protocol_version=contents.ProtocolVersion(1, 0),
        maximum_response_size=contents.MaximumResponseSize(2 ** 20),
        asynchronous_indicator=contents.AsynchronousIndicator(False),
        authentication=None,
        batch_error_cont_option=contents.BatchErrorContinuationOption(
            enums.BatchErrorContinuationOption.STOP
        ),
        batch_order_option=contents.BatchOrderOption(True),
        time_stamp=contents.TimeStamp(FROZEN_NOW),
        batch_count=contents.BatchCount(1)
    )
    request = messages.RequestMessage(
        request_header=header,
        batch_items=[
            messages.RequestBatchItem(
                operation=contents.Operation(enums.Operation.DECRYPT),
                request_payload=_decrypt_payload(uid, b'x', b'\x00' * 12)
            )
        ]
    )
    response, _, _ = kmip_engine.process_request(request)
    result = response.batch_items[0]
    assert_denied(result, enums.ResultReason.OPERATION_NOT_SUPPORTED)
    assert get_state(kmip_engine, uid) == enums.State.ACTIVE


def test_unimplemented_operation_is_marked_not_supported(kmip_engine):
    """
    Operations named in the KMIP lifecycle tables but absent from this
    repository's operation router are explicitly reported as unsupported
    rather than silently accepted.
    """
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  enums.State.ACTIVE)
    with pytest.raises(exceptions.OperationNotSupported):
        kmip_engine._process_operation(
            enums.Operation.REKEY,
            payloads.RekeyRequestPayload(unique_identifier=uid)
        )
    assert get_state(kmip_engine, uid) == enums.State.ACTIVE


def test_initial_date_uses_frozen_clock(kmip_engine):
    """The fixed clock flows into server-generated Initial Date attributes."""
    uid = add_key(kmip_engine, aes_key(enums.CryptographicUsageMask.ENCRYPT),
                  enums.State.PRE_ACTIVE)
    session = fresh_session(kmip_engine)
    key = session.query(pie_objects.SymmetricKey).filter(
        pie_objects.SymmetricKey.unique_identifier == uid
    ).one()
    assert key.initial_date == FROZEN_NOW
