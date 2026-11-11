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

import testtools

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import utils

from kmip.core.messages import contents


class TestMessageExtension(testtools.TestCase):

    def setUp(self):
        super(TestMessageExtension, self).setUp()

        # This encoding matches the following set of values:
        # MessageExtension
        #     VendorIdentification - "Acme"
        #     CriticalityIndicator - True
        #     VendorExtension - 0x0102030405060708 (raw bytes)
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x51\x01\x00\x00\x00\x28'
            b'\x42\x00\x9D\x07\x00\x00\x00\x04'
            b'\x41\x63\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x26\x06\x00\x00\x00\x08'
            b'\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x01\x02\x03\x04\x05\x06\x07\x08'
        )

        # This encoding is missing the criticality indicator.
        self.encoding_no_criticality_indicator = utils.BytearrayStream(
            b'\x42\x00\x51\x01\x00\x00\x00\x10'
            b'\x42\x00\x9D\x07\x00\x00\x00\x04'
            b'\x41\x63\x6D\x65\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestMessageExtension, self).tearDown()

    def test_init(self):
        """
        Test that a MessageExtension struct can be constructed with no
        arguments.
        """
        struct = contents.MessageExtension()

        self.assertIsNone(struct.vendor_identification)
        self.assertIsNone(struct.criticality_indicator)
        self.assertIsNone(struct.vendor_extension)

    def test_invalid_vendor_identification(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        set the vendor identification of a MessageExtension.
        """
        self.assertRaisesRegex(
            TypeError,
            "The vendor identification must be a string.",
            contents.MessageExtension,
            vendor_identification=0
        )

    def test_invalid_criticality_indicator(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        set the criticality indicator of a MessageExtension.
        """
        self.assertRaisesRegex(
            TypeError,
            "The criticality indicator must be a boolean.",
            contents.MessageExtension,
            criticality_indicator="invalid"
        )

    def test_invalid_vendor_extension(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        set the vendor extension of a MessageExtension.
        """
        self.assertRaisesRegex(
            TypeError,
            "The vendor extension must be a binary string.",
            contents.MessageExtension,
            vendor_extension="invalid"
        )

    def test_read(self):
        """
        Test that a MessageExtension struct can be correctly read in from
        a data stream.
        """
        struct = contents.MessageExtension()
        struct.read(self.full_encoding)

        self.assertEqual("Acme", struct.vendor_identification)
        self.assertTrue(struct.criticality_indicator)
        self.assertEqual(
            b'\x01\x02\x03\x04\x05\x06\x07\x08',
            struct.vendor_extension
        )

    def test_read_missing_criticality_indicator(self):
        """
        Test that an InvalidMessage error is raised when reading a
        malformed MessageExtension encoding that is missing its
        criticality indicator.
        """
        struct = contents.MessageExtension()

        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "The message extension is missing its criticality indicator.",
            struct.read,
            self.encoding_no_criticality_indicator
        )

    def test_write(self):
        """
        Test that a MessageExtension struct can be written to a data
        stream.
        """
        struct = contents.MessageExtension(
            vendor_identification="Acme",
            criticality_indicator=True,
            vendor_extension=b'\x01\x02\x03\x04\x05\x06\x07\x08'
        )

        buffer = utils.BytearrayStream()
        struct.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_missing_vendor_identification(self):
        """
        Test that an InvalidMessage error is raised when writing a
        MessageExtension that is missing its vendor identification.
        """
        struct = contents.MessageExtension(
            criticality_indicator=True,
            vendor_extension=b'\x01'
        )

        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "The message extension is missing its vendor identification.",
            struct.write,
            utils.BytearrayStream()
        )

    def test_write_missing_criticality_indicator(self):
        """
        Test that an InvalidMessage error is raised when writing a
        MessageExtension that is missing its criticality indicator.
        """
        struct = contents.MessageExtension(
            vendor_identification="Acme",
            vendor_extension=b'\x01'
        )

        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "The message extension is missing its criticality indicator.",
            struct.write,
            utils.BytearrayStream()
        )
