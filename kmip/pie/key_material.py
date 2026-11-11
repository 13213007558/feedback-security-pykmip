# Copyright (c) 2024 The Johns Hopkins University/Applied Physics Laboratory
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
Material consistency checks for keys entering the server through Register.

The checks in this module only inspect data that is available without
unwrapping the key material. They verify that the declared algorithm,
cryptographic length, and key format type are consistent with the inspectable
key bytes. When a key value is wrapped, the plaintext key bytes are not
available, so the material-level checks are skipped by design; only the
metadata that can still be checked (the declared key format type) is
validated. Nothing in this module claims to have verified the contents of a
wrapped key.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key

from kmip.core import enums
from kmip.pie import exceptions


# The key sizes accepted by the symmetric ciphers the server supports.
# The values mirror the key_sizes constraints exposed by the corresponding
# pyca/cryptography algorithm classes used by the server crypto engine.
_SYMMETRIC_KEY_SIZES = {
    enums.CryptographicAlgorithm.AES:        frozenset([128, 192, 256]),
    enums.CryptographicAlgorithm.TRIPLE_DES: frozenset([64, 128, 192]),
    enums.CryptographicAlgorithm.BLOWFISH:   frozenset(range(32, 449, 8)),
    enums.CryptographicAlgorithm.CAMELLIA:   frozenset([128, 192, 256]),
    enums.CryptographicAlgorithm.CAST5:      frozenset(range(40, 129, 8)),
    enums.CryptographicAlgorithm.IDEA:       frozenset([128]),
    enums.CryptographicAlgorithm.RC4:        frozenset(
        [40, 56, 64, 80, 128, 160, 192, 256]
    )
}

# Key format types the repository can parse and therefore verify, grouped by
# the key classes and algorithms that support them.
_SUPPORTED_PUBLIC_KEY_FORMATS = {
    enums.CryptographicAlgorithm.RSA: frozenset([
        enums.KeyFormatType.RAW,
        enums.KeyFormatType.PKCS_1,
        enums.KeyFormatType.X_509
    ])
}
_SUPPORTED_PRIVATE_KEY_FORMATS = {
    enums.CryptographicAlgorithm.RSA: frozenset([
        enums.KeyFormatType.RAW,
        enums.KeyFormatType.PKCS_1,
        enums.KeyFormatType.PKCS_8
    ])
}

# DER universal tags used to discriminate between the supported RSA key
# container formats.
_DER_TAG_INTEGER = 0x02
_DER_TAG_BIT_STRING = 0x03
_DER_TAG_SEQUENCE = 0x30


def is_wrapped(managed_object):
    """
    Determine whether the key's value is wrapped.

    A key is considered wrapped when its key wrapping data contains a
    wrapping method. In that case the stored value is ciphertext, not the
    plaintext key material, and material-level byte checks must not be
    applied to it.

    Args:
        managed_object (Key): A pie Key object to inspect.

    Returns:
        bool: True if the key carries key wrapping data with a wrapping
            method, False otherwise.
    """
    wrapping_data = getattr(managed_object, 'key_wrapping_data', None)
    if not wrapping_data:
        return False
    return wrapping_data.get('wrapping_method') is not None


def validate_key_material(managed_object):
    """
    Validate that the declared key metadata matches the inspectable material.

    This is the entry point used by the Register operation before the key is
    made visible to other operations or persisted. It dispatches on the key
    class and applies only checks that can be proven without unwrapping the
    value.

    Args:
        managed_object (Key): A pie SymmetricKey, PublicKey, or PrivateKey
            object built from the Register request.

    Raises:
        kmip.pie.exceptions.KeyMaterialConsistencyError: If the declared
            algorithm, length, or format is inconsistent with the inspectable
            key material, or if the material cannot be parsed in the declared
            format.
    """
    # Imported lazily to avoid a circular import between kmip.pie.objects and
    # this module.
    from kmip.pie import objects

    if isinstance(managed_object, objects.SymmetricKey):
        _validate_symmetric_key(managed_object)
    elif isinstance(managed_object, objects.PublicKey):
        _validate_asymmetric_key(managed_object, private=False)
    elif isinstance(managed_object, objects.PrivateKey):
        _validate_asymmetric_key(managed_object, private=True)
    else:
        # Other managed object types (certificates, secret data, opaque
        # objects, split keys) have no algorithm/length/format material
        # contract to check at this layer.
        return


def _validate_symmetric_key(key):
    if is_wrapped(key):
        # The value is ciphertext. Its byte length reflects the wrapping
        # transformation, not the plaintext key, so neither the value length
        # nor the raw material can be checked without unwrapping. The
        # declared algorithm and length remain trusted metadata.
        return

    algorithm = key.cryptographic_algorithm
    length = key.cryptographic_length
    value = key.value

    if key.key_format_type != enums.KeyFormatType.RAW:
        raise exceptions.KeyMaterialConsistencyError(
            "Symmetric keys must use the RAW key format type; observed "
            "{0}.".format(key.key_format_type)
        )

    allowed_lengths = _SYMMETRIC_KEY_SIZES.get(algorithm)
    if allowed_lengths is None:
        raise exceptions.KeyMaterialConsistencyError(
            "The cryptographic algorithm {0} is not supported for "
            "symmetric key material validation.".format(algorithm)
        )

    if length not in allowed_lengths:
        raise exceptions.KeyMaterialConsistencyError(
            "The declared cryptographic length ({0} bits) is not valid for "
            "the cryptographic algorithm ({1}).".format(length, algorithm)
        )

    observed_length = len(value) * 8
    if observed_length != length:
        raise exceptions.KeyMaterialConsistencyError(
            "The declared cryptographic length ({0} bits) does not match "
            "the length of the key material ({1} bits).".format(
                length, observed_length
            )
        )


def _validate_asymmetric_key(key, private):
    algorithm = key.cryptographic_algorithm
    format_type = key.key_format_type

    _validate_supported_format(key, private)

    if is_wrapped(key):
        # The value is wrapped ciphertext and cannot be parsed in the
        # declared format without the wrapping key. Only the declared format
        # type (checked above) can still be verified.
        return

    length = key.cryptographic_length
    value = key.value

    if algorithm != enums.CryptographicAlgorithm.RSA:
        # The repository only supports RSA key material parsing. For any
        # other algorithm the bytes cannot be verified here; do not pretend
        # the material has been checked.
        return

    if format_type == enums.KeyFormatType.RAW:
        # RAW RSA key bytes have no self-describing structure, so the
        # relationship between the bytes and the declared length cannot be
        # proven without an external specification. Nothing material-level
        # is verifiable beyond the format support check above.
        return

    _validate_der_structure(value, format_type, private)

    try:
        if private:
            parsed = load_der_private_key(value, password=None)
        else:
            parsed = load_der_public_key(value)
    except Exception as e:
        raise exceptions.KeyMaterialConsistencyError(
            "The key material could not be parsed as {0} key material in "
            "the {1} format: {2}".format(algorithm, format_type, e)
        )

    if not isinstance(
        parsed,
        rsa.RSAPrivateKey if private else rsa.RSAPublicKey
    ):
        raise exceptions.KeyMaterialConsistencyError(
            "The parsed key material is not an {0} {1} key, even though "
            "that algorithm was declared.".format(
                algorithm, 'private' if private else 'public'
            )
        )

    observed_length = parsed.key_size
    if observed_length != length:
        raise exceptions.KeyMaterialConsistencyError(
            "The declared cryptographic length ({0} bits) does not match "
            "the length of the parsed {1} key material ({2} bits).".format(
                length, algorithm, observed_length
            )
        )


def _validate_supported_format(key, private):
    algorithm = key.cryptographic_algorithm
    format_type = key.key_format_type

    if private:
        supported_algorithms = _SUPPORTED_PRIVATE_KEY_FORMATS
    else:
        supported_algorithms = _SUPPORTED_PUBLIC_KEY_FORMATS

    supported_formats = supported_algorithms.get(algorithm)
    if supported_formats is None:
        raise exceptions.KeyMaterialConsistencyError(
            "The cryptographic algorithm {0} is not supported for {1} key "
            "material validation.".format(
                algorithm, 'private' if private else 'public'
            )
        )

    if format_type not in supported_formats:
        raise exceptions.KeyMaterialConsistencyError(
            "The key format type {0} is not supported for {1} {2} keys. "
            "Supported formats are: {3}.".format(
                format_type,
                algorithm,
                'private' if private else 'public',
                sorted(f.name for f in supported_formats)
            )
        )


def _validate_der_structure(value, format_type, private):
    """
    Verify that the DER container structure matches the declared format.

    The pyca/cryptography key loaders accept several RSA container formats
    interchangeably, so parsing alone cannot prove that the bytes are in the
    declared format. The top-level structure of each supported format is
    distinct and cheap to check:

    * X.509 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE, BIT STRING }
    * PKCS#1 RSAPublicKey:        SEQUENCE { INTEGER, INTEGER }
    * PKCS#8 PrivateKeyInfo:      SEQUENCE { INTEGER, SEQUENCE, OCTET STRING }
    * PKCS#1 RSAPrivateKey:       SEQUENCE { INTEGER, INTEGER, ... }
    """
    child_tags = _der_child_tags(value, 2)
    if child_tags is None:
        raise exceptions.KeyMaterialConsistencyError(
            "The key material is not well-formed DER and cannot be matched "
            "against the declared {0} format.".format(format_type)
        )

    if private:
        if format_type == enums.KeyFormatType.PKCS_8:
            expected = (_DER_TAG_INTEGER, _DER_TAG_SEQUENCE)
        else:
            expected = (_DER_TAG_INTEGER, _DER_TAG_INTEGER)
    else:
        if format_type == enums.KeyFormatType.X_509:
            expected = (_DER_TAG_SEQUENCE, _DER_TAG_BIT_STRING)
        else:
            expected = (_DER_TAG_INTEGER, _DER_TAG_INTEGER)

    if tuple(child_tags) != expected:
        raise exceptions.KeyMaterialConsistencyError(
            "The key material structure does not match the declared {0} "
            "format.".format(format_type)
        )


def _der_child_tags(data, count):
    """
    Read the tags of the first children of a DER SEQUENCE.

    Args:
        data (bytes): The DER-encoded structure.
        count (int): The number of child tags to read.

    Returns:
        list: The child tags, or None if the data is not a SEQUENCE or is
            truncated.
    """
    try:
        tag, content_start, _ = _read_der_tlv(data, 0)
        if tag != _DER_TAG_SEQUENCE:
            return None
        tags = []
        offset = content_start
        for _ in range(count):
            tag, content_start, content_end = _read_der_tlv(data, offset)
            tags.append(tag)
            offset = content_end
        return tags
    except (IndexError, ValueError):
        return None


def _read_der_tlv(data, offset):
    """
    Read a single DER TLV header.

    Returns:
        tuple: (tag, content start offset, content end offset)
    """
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte & 0x80:
        length_size = length_byte & 0x7F
        if length_size == 0 or length_size > 4:
            raise ValueError("Unsupported DER length encoding.")
        length = int.from_bytes(
            data[offset + 2:offset + 2 + length_size], 'big'
        )
        header_size = 2 + length_size
    else:
        length = length_byte
        header_size = 2
    content_start = offset + header_size
    content_end = content_start + length
    if content_end > len(data):
        raise ValueError("Truncated DER structure.")
    return tag, content_start, content_end
