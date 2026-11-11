Key Lifecycle Security Matrix
=============================

This document records which management and cryptographic operations the
PyKMIP server actually permits for a managed cryptographic object in each
KMIP lifecycle state. Every cell is enforced by an executable, state-asserting
test in
``kmip/tests/unit/services/server/test_key_lifecycle_matrix.py`` that drives
the full server entry point (``KmipEngine.process_request``) against an
in-memory database using a frozen clock and small test keys.

The matrix reflects KMIP 1.2, the highest protocol version this server
implements. Operations named in the KMIP state/usage tables but not
implemented by PyKMIP are listed separately below rather than guessed at.

How to read the matrix
----------------------

* **Allowed** — the server returns ``Success`` and performs the operation.
* **Denied** — the server returns ``PermissionDenied`` / ``IllegalOperation``
  and the object's state is provably left unchanged.
* **Transition** — a management operation that is allowed *because* it moves
  the object to another state.
* **Gone** — the object has been physically destroyed; later requests resolve
  to ``ItemNotFound``.
* State never changes as a side effect of a cryptographic or read operation.

Management operations
---------------------

+----------------------+-------------+-------------+--------------+-------------+-------------+
| Operation            | Pre-Active  | Active      | Deactivated  | Compromised | Destroyed   |
+======================+=============+=============+==============+=============+=============+
| Activate             | Transition  | Denied      | Denied       | Denied      | Gone        |
|                      | -> Active   |             |              |             |             |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Revoke (other reason)| Denied      | Transition  | Denied       | Denied      | Gone        |
|                      |             | -> Deact.   |              |             |             |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Revoke KEY_COMPROMISE| Transition  | Transition  | Transition   | Transition  | Gone        |
|                      | -> Compr.   | -> Compr.   | -> Compr.    | -> Compr.   |             |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Destroy              | Allowed     | Denied [#f1]| Allowed      | Allowed     | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Get (export key)     | Allowed     | Allowed     | Allowed      | Allowed     | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| GetAttributes        | Allowed     | Allowed     | Allowed      | Allowed     | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Locate               | Allowed     | Allowed     | Allowed      | Allowed     | Gone [#f2]  |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| DeriveKey            | Allowed [#f3]| Allowed    | Denied       | Denied      | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+

Cryptographic operations
------------------------

Cryptographic operations additionally require the matching bit in the
object's Cryptographic Usage Mask, independent of state. An Active key
without the required mask bit is always denied; the test suite contains a
mask-contrast case for every operation below.

+----------------------+-------------+-------------+--------------+-------------+-------------+
| Operation (mask bit) | Pre-Active  | Active      | Deactivated  | Compromised | Destroyed   |
+======================+=============+=============+==============+=============+=============+
| Encrypt (Encrypt)    | Denied      | Allowed     | Denied       | Denied      | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Decrypt (Decrypt)    | Denied      | Allowed     | Allowed      | Allowed     | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Sign (Sign)          | Denied      | Allowed     | Denied       | Denied      | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| Signature Verify     | Denied      | Allowed     | Allowed      | Allowed     | Gone        |
| (Verify)             |             |             |              |             |             |
+----------------------+-------------+-------------+--------------+-------------+-------------+
| MAC (MAC Generate)   | Denied      | Allowed     | Denied       | Denied      | Gone        |
+----------------------+-------------+-------------+--------------+-------------+-------------+

The distinction is deliberate: operations that produce **new** protected
material (Encrypt, Sign, MAC) are Active-only, while operations that consume
**existing** material to preserve access to old data (Decrypt of old
ciphertext, Signature Verify of old signatures) remain available on
Deactivated and Compromised keys. New keying material (DeriveKey) cannot be
produced from retired or compromised keys.

Re-activation
-------------

There is no Deactivated -> Active transition in KMIP. Once a key is revoked
to Deactivated, a subsequent Activate request is denied and the state remains
Deactivated. Only a Pre-Active object can be activated. The
``test_revoke_deactivation_matrix`` case asserts both the Active ->
Deactivated transition and the failed re-activation.

Activation and deactivation dates
---------------------------------

This implementation stores ``Activation Date`` and ``Deactivation Date`` only
as in-memory placeholders; they are not persisted and the server performs no
time-driven state transitions. Object state changes exclusively through the
Activate, Revoke and Destroy operations. The test suite therefore pins a
single frozen clock (``FROZEN_NOW``) and drives state explicitly instead of
relying on wall-clock expiry. The conservative consequence is that an Active
key cannot be Destroyed until it is first revoked, because the server cannot
evaluate a stored Deactivation Date to confirm the key's lifetime has ended.

Protocol-version gate
---------------------

Decrypt, Sign, MAC and Signature Verify were introduced in KMIP 1.2. On a
1.0 protocol session the server raises ``OperationNotSupported`` before any
state logic runs and does not touch the object, as asserted by
``test_kmip_1_0_rejects_1_2_crypto_operations``.

Operations not implemented by this server
-----------------------------------------

The following KMIP lifecycle operations have no handler in
``KmipEngine._process_operation`` and return ``OperationNotSupported``; they
are intentionally excluded from the executable matrix:

* Rekey, RekeyKeyPair
* Certify, Recertify
* Archive, Recover
* Validate
* ObtainLease, GetUsageAllocation
* Check, Cancel, Poll

The unsupported-operation contract itself is covered by
``test_unimplemented_operation_is_marked_not_supported``.

Footnotes
---------

.. [#f1] Destroy of an Active key is conservatively refused because the
         server cannot evaluate a persisted Deactivation Date (see above).
.. [#f2] Locate itself has no state gate and keeps returning surviving
         objects; a destroyed row simply no longer matches any identifier.
.. [#f3] DeriveKey from a Pre-Active base key is permitted by the KMIP
         usage/state tables; the derived object is always born Pre-Active.
