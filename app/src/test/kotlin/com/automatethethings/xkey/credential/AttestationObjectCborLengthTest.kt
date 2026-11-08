/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.credential

import com.automatethethings.xkey.credential.handler.CreateCredentialHandler
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The CBOR length prefix of the attestation object [CreateCredentialHandler]
 * builds.
 *
 * The attestation object is parsed by the relying party, not by this app, so a
 * wrong byte-string header is invisible here and fatal there. A registration's
 * authenticator data always lands in the 24..255 range, which is the only
 * branch a ceremony can reach — the other two are covered directly.
 */
class AttestationObjectCborLengthTest {

    /**
     * CBOR encodes a byte string's length in one of three ways depending on
     * size, and the relying party's parser follows the header it is given. A
     * registration only ever produces authenticator data in the middle range,
     * so the short and long forms are checked directly.
     *
     * The encoder is private and has no other caller a test can steer; it is
     * pure byte assembly, so it is reached reflectively rather than left
     * unverified. It reads no field of the handler, so the handler is
     * allocated without running its constructor, which opens the Keystore and
     * the database.
     */
    @Test
    fun theAttestationObjectUsesTheRightCborLengthPrefixForEverySize() {
        val encode = CreateCredentialHandler::class.java.getDeclaredMethod(
            "buildAttestationObject", ByteArray::class.java
        )
        encode.isAccessible = true
        val handler = allocateWithoutConstructor(CreateCredentialHandler::class.java)

        // Every attestation object starts with the same 3-entry map header,
        // "fmt": "none", "attStmt": {} and the "authData" key.
        val prefixLength = 1 + 1 + 3 + 1 + 4 + 1 + 7 + 1 + 1 + 8

        // <= 23 bytes: the length rides in the major-type byte.
        val tiny = ByteArray(20) { 1 }
        val tinyEncoded = encode.invoke(handler, tiny) as ByteArray
        assertEquals(0x54.toByte(), tinyEncoded[prefixLength])
        assertEquals(prefixLength + 1 + tiny.size, tinyEncoded.size)

        // 24..255 bytes: one length byte after 0x58. This is what a real
        // registration produces.
        val medium = ByteArray(164) { 2 }
        val mediumEncoded = encode.invoke(handler, medium) as ByteArray
        assertEquals(0x58.toByte(), mediumEncoded[prefixLength])
        assertEquals(164.toByte(), mediumEncoded[prefixLength + 1])
        assertEquals(prefixLength + 2 + medium.size, mediumEncoded.size)

        // > 255 bytes: two big-endian length bytes after 0x59.
        val large = ByteArray(300) { 3 }
        val largeEncoded = encode.invoke(handler, large) as ByteArray
        assertEquals(0x59.toByte(), largeEncoded[prefixLength])
        assertEquals(0x01.toByte(), largeEncoded[prefixLength + 1])
        assertEquals(0x2C.toByte(), largeEncoded[prefixLength + 2])
        assertEquals(prefixLength + 3 + large.size, largeEncoded.size)

        // The fixed header really is the "none" attestation shape.
        assertEquals(0xA3.toByte(), mediumEncoded[0])
        assertEquals(
            "fmt",
            String(mediumEncoded.copyOfRange(2, 5))
        )
    }

    private fun <T> allocateWithoutConstructor(type: Class<T>): T {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val theUnsafe = unsafeClass.getDeclaredField("theUnsafe")
        theUnsafe.isAccessible = true
        val allocate = unsafeClass.getMethod("allocateInstance", Class::class.java)
        return type.cast(allocate.invoke(theUnsafe.get(null), type))
    }
}
