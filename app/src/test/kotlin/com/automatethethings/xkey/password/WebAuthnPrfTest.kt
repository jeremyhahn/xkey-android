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
package com.automatethethings.xkey.password

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [WebAuthnPrf.hmacSecretSalt].
 *
 * The vectors were computed by hand, outside this code, as
 * SHA-256(context || 0x00 || salt) where context is the ASCII bytes of
 * "WebAuthn PRF":
 *
 * ```
 * "WebAuthn PRF"           = 57 65 62 41 75 74 68 6e 20 50 52 46
 * separator                = 00
 *
 * salt = (empty)
 *   input  = 576562417574686e2050524600
 *   SHA-256 = 6a7e64b2aa34c92736143a062fa149aff1bd8bb3f7ee6f346885481f9414a3d3
 *
 * salt = 32 zero bytes
 *   input  = 576562417574686e2050524600 || 00 * 32
 *   SHA-256 = 4f24c9221e0ed3b764b4558a0d880ecea08117d62f2bdc13ae2c6c3ea662e3a1
 *
 * salt = "xkey-vault-salt"     = 78 6b 65 79 2d 76 61 75 6c 74 2d 73 61 6c 74
 *   input  = 576562417574686e2050524600786b65792d7661756c742d73616c74
 *   SHA-256 = 643a5e3f39cf78a9ebd830cf167fbd14e69d59a7a89faa328b4653f1b1907616
 * ```
 *
 * (python3: `hashlib.sha256(b"WebAuthn PRF" + b"\x00" + salt).hexdigest()`.)
 */
class WebAuthnPrfTest {

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun `the transform of an empty salt is the hash of the context and separator`() {
        assertEquals(
            "6a7e64b2aa34c92736143a062fa149aff1bd8bb3f7ee6f346885481f9414a3d3",
            WebAuthnPrf.hmacSecretSalt(ByteArray(0)).hex()
        )
    }

    @Test
    fun `the transform of a 32-byte zero salt matches the hand-computed vector`() {
        assertEquals(
            "4f24c9221e0ed3b764b4558a0d880ecea08117d62f2bdc13ae2c6c3ea662e3a1",
            WebAuthnPrf.hmacSecretSalt(ByteArray(32)).hex()
        )
    }

    @Test
    fun `the transform of an ASCII salt matches the hand-computed vector`() {
        assertEquals(
            "643a5e3f39cf78a9ebd830cf167fbd14e69d59a7a89faa328b4653f1b1907616",
            WebAuthnPrf.hmacSecretSalt("xkey-vault-salt".toByteArray(Charsets.US_ASCII)).hex()
        )
    }

    @Test
    fun `the transformed salt is the 32-byte hmac-secret salt size`() {
        assertEquals(32, WebAuthnPrf.hmacSecretSalt(ByteArray(7)).size)
    }
}
