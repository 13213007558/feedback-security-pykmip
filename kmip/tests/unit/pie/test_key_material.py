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

import testtools

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key

from kmip.core import enums
from kmip.pie import exceptions
from kmip.pie import key_material
from kmip.pie import objects


class TestKeyMaterialValidation(testtools.TestCase):
    """
    Test suite for the key material consistency checks applied to keys
    entering the server through Register.
    """

    def setUp(self):
        super(TestKeyMaterialValidation, self).setUp()

        self.bytes_128 = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
            b'\x0F')
        self.bytes_192 = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
            b'\x0F\x10\x11\x12\x13\x14\x15\x16\x17')
        self.bytes_256 = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
            b'\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D'
            b'\x1E\x1F')

        # Key values taken from Sections 8.2 and 13.4 of the KMIP 1.1
        # testing documentation.
        self.rsa_public_1024_x509 = (
            b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01'
            b'\x01\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81\x81\x00\x93'
            b'\x04\x51\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17\xDD\x09\x38\x1B\xD2'
            b'\x3B\xE4\x3E\xCA\x8C\x75\x39\xF3\x01\xFC\x8A\x8C\xD5\xD5\x27'
            b'\x4C\x3E\x76\x99\xDB\xDC\x71\x1C\x97\xA7\xAA\x91\xE2\xC5\x0A'
            b'\x82\xBD\x0B\x10\x34\xF0\xDF\x49\x3D\xEC\x16\x36\x24\x27\xE5'
            b'\x8A\xCC\xE7\xF6\xCE\x0F\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0\x09'
            b'\x4A\x27\x03\xBA\x0D\x09\xEB\x19\xD1\x00\x5F\x2F\xB2\x65\x52'
            b'\x6A\xAC\x75\xAF\x32\xF8\xBC\x78\x2C\xDE\xD2\xA5\x7F\x81\x1E'
            b'\x03\xEA\xF6\x7A\x94\x4D\xE5\xE7\x84\x13\xDC\xA8\xF2\x32\xD0'
            b'\x74\xE6\xDC\xEA\x4C\xEC\x9F\x02\x03\x01\x00\x01')
        self.rsa_public_2048_pkcs1 = (
            b'\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76'
            b'\x00\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55'
            b'\xF8\x00\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46'
            b'\x48\x34\x6D\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83'
            b'\xBC\x4D\x7D\xC7\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7'
            b'\xD0\x3F\xC6\x26\x7F\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7'
            b'\xC2\xD8\x33\xE5\xA5\xF4\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11'
            b'\x00\xF8\xAA\x21\x49\x00\xDF\x8B\x65\x08\x9F\x98\x13\x5B\x1C'
            b'\x67\xB7\x01\x67\x5A\xBD\xBC\x7D\x57\x21\xAA\xC9\xD1\x4A\x7F'
            b'\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC\xC8\x29\x53\x53\xC7\x95'
            b'\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7\xF4\xE8\xAC\x8C\x81'
            b'\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D\x0C\xA3\x41\x42'
            b'\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE\x64\xC5\x41'
            b'\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC\xE8\x94'
            b'\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73\xA1'
            b'\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01')
        self.rsa_private_1024_pkcs8 = (
            b'\x30\x82\x02\x76\x02\x01\x00\x30\x0D\x06\x09\x2A\x86\x48\x86'
            b'\xF7\x0D\x01\x01\x01\x05\x00\x04\x82\x02\x60\x30\x82\x02\x5C'
            b'\x02\x01\x00\x02\x81\x81\x00\x93\x04\x51\xC9\xEC\xD9\x4F\x5B'
            b'\xB9\xDA\x17\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E\xCA\x8C\x75\x39'
            b'\xF3\x01\xFC\x8A\x8C\xD5\xD5\x27\x4C\x3E\x76\x99\xDB\xDC\x71'
            b'\x1C\x97\xA7\xAA\x91\xE2\xC5\x0A\x82\xBD\x0B\x10\x34\xF0\xDF'
            b'\x49\x3D\xEC\x16\x36\x24\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F\x9B'
            b'\xCC\x61\x7B\xBD\x8C\x90\xD0\x09\x4A\x27\x03\xBA\x0D\x09\xEB'
            b'\x19\xD1\x00\x5F\x2F\xB2\x65\x52\x6A\xAC\x75\xAF\x32\xF8\xBC'
            b'\x78\x2C\xDE\xD2\xA5\x7F\x81\x1E\x03\xEA\xF6\x7A\x94\x4D\xE5'
            b'\xE7\x84\x13\xDC\xA8\xF2\x32\xD0\x74\xE6\xDC\xEA\x4C\xEC\x9F'
            b'\x02\x03\x01\x00\x01\x02\x81\x80\x0B\x6A\x7D\x73\x61\x99\xEA'
            b'\x48\xA4\x20\xE4\x53\x7C\xA0\xC7\xC0\x46\x78\x4D\xCB\xEA\xA6'
            b'\x3B\xAE\xBC\x0B\xC1\x32\x78\x74\x49\xCD\xE8\xD7\xCA\xD0\xC0'
            b'\xC8\x63\xC0\xFE\xFB\x06\xC3\x06\x2B\xEF\xC5\x00\x33\xEC\xF8'
            b'\x7B\x4E\x33\xA9\xBE\x7B\xCB\xC8\xF1\x51\x1A\xE2\x15\xE8\x0D'
            b'\xEB\x5D\x8A\xF2\xBD\x31\x31\x9D\x78\x21\x19\x66\x40\x93\x5A'
            b'\x0C\xD6\x7C\x94\x59\x95\x79\xF2\x10\x0D\x65\xE0\x38\x83\x1F'
            b'\xDA\xFB\x0D\xBE\x2B\xBD\xAC\x00\xA6\x96\xE6\x7E\x75\x63\x50'
            b'\xE1\xC9\x9A\xCE\x11\xA3\x6D\xAB\xAC\x3E\xD3\xE7\x30\x96\x00'
            b'\x59\x02\x41\x00\xDD\xF6\x72\xFB\xCC\x5B\xDA\x3D\x73\xAF\xFC'
            b'\x4E\x79\x1E\x0C\x03\x39\x02\x24\x40\x5D\x69\xCC\xAA\xBC\x74'
            b'\x9F\xAA\x0D\xCD\x4C\x25\x83\xC7\x1D\xDE\x89\x41\xA7\xB9\xAA'
            b'\x03\x0F\x52\xEF\x14\x51\x46\x6C\x07\x4D\x4D\x33\x8F\xE6\x77'
            b'\x89\x2A\xCD\x9E\x10\xFD\x35\xBD\x02\x41\x00\xA9\x8F\xBC\x3E'
            b'\xD6\xB4\xC6\xF8\x60\xF9\x71\x65\xAC\x2F\x7B\xB6\xF2\xE2\xCB'
            b'\x19\x2A\x9A\xBD\x49\x79\x5B\xE5\xBC\xF3\x7D\x8E\xE6\x9A\x6E'
            b'\x16\x9C\x24\xE5\xC3\x2E\x4E\x7F\xA3\x32\x65\x46\x14\x07\xF9'
            b'\x52\xBA\x49\xE2\x04\x81\x8A\x2F\x78\x5F\x11\x3F\x92\x2B\x8B'
            b'\x02\x40\x25\x3F\x94\x70\x39\x0D\x39\x04\x93\x03\x77\x7D\xDB'
            b'\xC9\x75\x0E\x9D\x64\x84\x9C\xE0\x90\x3E\xAE\x70\x4D\xC9\xF5'
            b'\x89\xB7\x68\x0D\xEB\x9D\x60\x9F\xD5\xBC\xD4\xDE\xCD\x6F\x12'
            b'\x05\x42\xE5\xCF\xF5\xD7\x6F\x2A\x43\xC8\x61\x5F\xB5\xB3\xA9'
            b'\x21\x34\x63\x79\x7A\xA9\x02\x41\x00\xA1\xDD\xF0\x23\xC0\xCD'
            b'\x94\xC0\x19\xBB\x26\xD0\x9B\x9E\x3C\xA8\xFA\x97\x1C\xB1\x6A'
            b'\xA5\x8B\x9B\xAF\x79\xD6\x08\x1A\x1D\xBB\xA4\x52\xBA\x53\x65'
            b'\x3E\x28\x04\xBA\x98\xFF\x69\xE8\xBB\x1B\x3A\x16\x1E\xA2\x25'
            b'\xEA\x50\x14\x63\x21\x6A\x8D\xAB\x9B\x88\xA7\x5E\x5F\x02\x40'
            b'\x61\x78\x64\x6E\x11\x2C\xF7\x9D\x92\x1A\x8A\x84\x3F\x17\xF6'
            b'\xE7\xFF\x97\x4F\x68\x81\x22\x36\x5B\xF6\x69\x0C\xDF\xC9\x96'
            b'\xE1\x89\x09\x52\xEB\x38\x20\xDD\x18\x90\xEC\x1C\x86\x19\xE8'
            b'\x7A\x2B\xD3\x8F\x9D\x03\xB3\x7F\xAC\x74\x2E\xFB\x74\x8C\x78'
            b'\x85\x94\x2C\x39')

        # Derive the matching PKCS#1 private key bytes from the PKCS#8 test
        # vector so both containers describe the same 1024-bit RSA key.
        private_key = load_der_private_key(
            self.rsa_private_1024_pkcs8, password=None)
        self.rsa_private_1024_pkcs1 = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )

    def _build_wrapping_data(self):
        return {
            'wrapping_method': enums.WrappingMethod.ENCRYPT,
            'encryption_key_information': {
                'unique_identifier': '1',
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP
                }
            }
        }

    # Symmetric key tests

    def test_symmetric_key_valid_aes_128(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128)
        key_material.validate_key_material(key)

    def test_symmetric_key_valid_aes_192(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 192, self.bytes_192)
        key_material.validate_key_material(key)

    def test_symmetric_key_valid_aes_256(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 256, self.bytes_256)
        key_material.validate_key_material(key)

    def test_symmetric_key_valid_3des(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES, 192, self.bytes_192)
        key_material.validate_key_material(key)

    def test_symmetric_key_declared_length_too_large(self):
        """
        Test that a key claiming to be AES-256 while carrying only 16 bytes
        of material is rejected.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128)
        # The pie object itself rejects unwrapped length mismatches at
        # construction time; mutate afterwards to exercise the material
        # validator directly.
        key.cryptographic_length = 256

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_symmetric_key_declared_length_too_small(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 256, self.bytes_256)
        key.cryptographic_length = 128

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_symmetric_key_invalid_length_for_algorithm(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128)
        key.cryptographic_length = 64
        key.value = self.bytes_128[:8]

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_symmetric_key_unsupported_algorithm(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128)
        key.cryptographic_algorithm = enums.CryptographicAlgorithm.DES

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_symmetric_key_non_raw_format(self):
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128)
        key.key_format_type = enums.KeyFormatType.OPAQUE

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_symmetric_key_wrapped_skips_material_checks(self):
        """
        Test that a wrapped symmetric key is not checked against its
        ciphertext byte count. The wrapped value may be any length because
        it is ciphertext, not the plaintext key.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            256,
            self.bytes_128,
            key_wrapping_data=self._build_wrapping_data()
        )
        key_material.validate_key_material(key)

        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            256,
            self.bytes_256 + self.bytes_128,
            key_wrapping_data=self._build_wrapping_data()
        )
        key_material.validate_key_material(key)

    def test_symmetric_key_wrapping_data_without_method(self):
        """
        Test that key wrapping data without a wrapping method does not mark
        the key as wrapped, so material checks still apply.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128,
            key_wrapping_data={'iv_counter_nonce': b'\x00' * 16}
        )
        self.assertFalse(key_material.is_wrapped(key))
        key_material.validate_key_material(key)

    # Public key tests

    def test_public_key_valid_rsa_x509(self):
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_public_1024_x509,
            enums.KeyFormatType.X_509
        )
        key_material.validate_key_material(key)

    def test_public_key_valid_rsa_pkcs1(self):
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            self.rsa_public_2048_pkcs1,
            enums.KeyFormatType.PKCS_1
        )
        key_material.validate_key_material(key)

    def test_public_key_valid_rsa_raw(self):
        """
        Test that RAW RSA public key material is accepted without parsing;
        raw bytes carry no self-describing structure to verify.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_public_1024_x509,
            enums.KeyFormatType.RAW
        )
        key_material.validate_key_material(key)

    def test_public_key_length_mismatch(self):
        """
        Test that a public key declaring 1024 bits while carrying 2048-bit
        material is rejected.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_public_2048_pkcs1,
            enums.KeyFormatType.PKCS_1
        )
        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_public_key_unparseable_material(self):
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_128,
            enums.KeyFormatType.X_509
        )
        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_public_key_wrong_format_material(self):
        """
        Test that PKCS#1 material declared as X.509 is rejected because its
        structure does not match the declared format.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            self.rsa_public_2048_pkcs1,
            enums.KeyFormatType.X_509
        )
        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_public_key_unsupported_format(self):
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_public_1024_x509,
            enums.KeyFormatType.X_509
        )
        key.key_format_type = enums.KeyFormatType.PKCS_8

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_public_key_unsupported_algorithm(self):
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_public_1024_x509,
            enums.KeyFormatType.X_509
        )
        key.cryptographic_algorithm = enums.CryptographicAlgorithm.DSA

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_public_key_wrapped_skips_material_checks(self):
        """
        Test that a wrapped public key is not parsed; only its declared
        format support is checked.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            self.bytes_256,
            enums.KeyFormatType.PKCS_1,
            key_wrapping_data=self._build_wrapping_data()
        )
        key_material.validate_key_material(key)

    def test_public_key_wrapped_unsupported_format(self):
        """
        Test that a wrapped public key with an unsupported declared format
        is still rejected; format support is checkable without unwrapping.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            self.bytes_256,
            enums.KeyFormatType.PKCS_1,
            key_wrapping_data=self._build_wrapping_data()
        )
        key.key_format_type = enums.KeyFormatType.PKCS_8

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    # Private key tests

    def test_private_key_valid_rsa_pkcs8(self):
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_private_1024_pkcs8,
            enums.KeyFormatType.PKCS_8
        )
        key_material.validate_key_material(key)

    def test_private_key_valid_rsa_pkcs1(self):
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_private_1024_pkcs1,
            enums.KeyFormatType.PKCS_1
        )
        key_material.validate_key_material(key)

    def test_private_key_length_mismatch(self):
        """
        Test that a private key declaring 2048 bits while carrying 1024-bit
        material is rejected.
        """
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            self.rsa_private_1024_pkcs8,
            enums.KeyFormatType.PKCS_8
        )
        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_private_key_unparseable_material(self):
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_128,
            enums.KeyFormatType.PKCS_8
        )
        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_private_key_wrong_format_material(self):
        """
        Test that PKCS#8 material declared as PKCS#1 is rejected because its
        structure does not match the declared format.
        """
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_private_1024_pkcs8,
            enums.KeyFormatType.PKCS_1
        )
        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_private_key_unsupported_format(self):
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.rsa_private_1024_pkcs8,
            enums.KeyFormatType.PKCS_8
        )
        key.key_format_type = enums.KeyFormatType.X_509

        self.assertRaises(
            exceptions.KeyMaterialConsistencyError,
            key_material.validate_key_material,
            key
        )

    def test_private_key_wrapped_skips_material_checks(self):
        """
        Test that a wrapped private key is not parsed; only its declared
        format support is checked.
        """
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            self.bytes_256,
            enums.KeyFormatType.PKCS_8,
            key_wrapping_data=self._build_wrapping_data()
        )
        key_material.validate_key_material(key)

    # Non-key managed objects

    def test_non_key_objects_pass_through(self):
        """
        Test that managed objects without key material contracts are not
        subject to material validation.
        """
        secret_data = objects.SecretData(
            self.bytes_128, enums.SecretDataType.PASSWORD)
        key_material.validate_key_material(secret_data)

        opaque = objects.OpaqueObject(
            self.bytes_128, enums.OpaqueDataType.NONE)
        key_material.validate_key_material(opaque)

        certificate = objects.X509Certificate(self.bytes_128)
        key_material.validate_key_material(certificate)
