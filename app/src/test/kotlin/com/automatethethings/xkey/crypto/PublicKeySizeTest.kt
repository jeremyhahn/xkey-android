/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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

package com.automatethethings.xkey.crypto

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** [publicKeySizeBits] reads the size of the key that was made off its SPKI. */
class PublicKeySizeTest {

    private fun rsa(bits: Int): ByteArray =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair().public.encoded

    private fun ec(curve: String): ByteArray =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair().public.encoded

    @Test
    fun `an RSA key reports its modulus bit length`() {
        for (bits in listOf(2048, 3072, 4096)) {
            assertEquals(bits, publicKeySizeBits(rsa(bits)))
        }
    }

    @Test
    fun `an EC key reports its curve field size`() {
        assertEquals(256, publicKeySizeBits(ec("secp256r1")))
        assertEquals(384, publicKeySizeBits(ec("secp384r1")))
        assertEquals(521, publicKeySizeBits(ec("secp521r1")))
    }

    @Test
    fun `no key or an undecodable one has no size`() {
        assertNull(publicKeySizeBits(null))
        assertNull(publicKeySizeBits(ByteArray(0)))
        assertNull(publicKeySizeBits(ByteArray(91) { 1 }))
        assertNull(publicKeySizeBits("not a key".toByteArray()))
    }
}
