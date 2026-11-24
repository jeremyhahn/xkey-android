/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ble

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.junit.Test

/**
 * [X25519] against the RFC 7748 test vectors, on the platform provider and on
 * the Bouncy Castle fallback that devices without a platform X25519 use.
 */
@RunWith(Parameterized::class)
class X25519Test(private val fallback: Boolean) {

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "fallback={0}")
        fun paths(): List<Array<Any>> = listOf(arrayOf<Any>(false), arrayOf<Any>(true))

        fun hex(s: String): ByteArray =
            ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

        val BASE_POINT = ByteArray(32).also { it[0] = 9 }
    }

    @org.junit.Before
    fun setUp() {
        X25519.forceFallbackForTest = fallback
    }

    @After
    fun tearDown() {
        X25519.forceFallbackForTest = false
    }

    /** RFC 7748 §5.2, first single vector. */
    @Test
    fun rfc7748FirstVector() {
        val k = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        assertArrayEquals(
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            X25519.dh(k, u)
        )
    }

    /** RFC 7748 §5.2, second single vector (u has its top bit set). */
    @Test
    fun rfc7748SecondVector() {
        val k = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        val u = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        assertArrayEquals(
            hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
            X25519.dh(k, u)
        )
    }

    /** RFC 7748 §5.2 iterated: k = u = 9, then k, u = X25519(k, u), k. */
    @Test
    fun rfc7748IteratedOnceAndAThousandTimes() {
        var k = BASE_POINT.copyOf()
        var u = BASE_POINT.copyOf()
        for (i in 1..1000) {
            val r = X25519.dh(k, u)
            u = k
            k = r
            if (i == 1) {
                assertArrayEquals(
                    hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
                    k
                )
            }
        }
        assertArrayEquals(
            hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
            k
        )
    }

    /** RFC 7748 §6.1: both public keys and the shared secret. */
    @Test
    fun rfc7748DiffieHellman() {
        val alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bobPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val alicePub = X25519.scalarMultBase(alicePriv)
        val bobPub = X25519.scalarMultBase(bobPriv)
        assertArrayEquals(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), alicePub)
        assertArrayEquals(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), bobPub)
        val shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        assertArrayEquals(shared, X25519.dh(alicePriv, bobPub))
        assertArrayEquals(shared, X25519.dh(bobPriv, alicePub))
    }

    /** u = 0 and u = 1 are small-order points: the all-zero result is refused. */
    @Test
    fun smallOrderPointsAreRefused() {
        val k = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        assertThrows(NoiseException::class.java) { X25519.dh(k, ByteArray(32)) }
        assertThrows(NoiseException::class.java) { X25519.dh(k, ByteArray(32).also { it[0] = 1 }) }
    }

    /** The output is always 32 bytes and the inputs are left as they were. */
    @Test
    fun inputsAreNotModified() {
        val k = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val kCopy = k.copyOf()
        val out = X25519.scalarMultBase(k)
        assertEquals(32, out.size)
        assertArrayEquals(kCopy, k)
    }
}
