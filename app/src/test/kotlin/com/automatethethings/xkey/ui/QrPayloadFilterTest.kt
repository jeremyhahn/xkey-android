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
package com.automatethethings.xkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [QrPayloadFilter]: the scanner accepts the payload kind the
 * intent asks for, otpauth by default, and never both kinds at once.
 */
class QrPayloadFilterTest {

    private val otpauth = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    private val cosignRequest =
        """{"v":1,"hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","alg":"SHA-256","from":"a1b2"}"""
    private val cosignResponse = """{"v":1,"sig":"QUJD","fp":"f5e6","name":"Bob","alg":"ES256"}"""

    @Test
    fun `kind defaults to otpauth for a missing or unknown extra`() {
        assertEquals(QrPayloadKind.OTPAUTH, QrPayloadKind.fromExtra(null))
        assertEquals(QrPayloadKind.OTPAUTH, QrPayloadKind.fromExtra(""))
        assertEquals(QrPayloadKind.OTPAUTH, QrPayloadKind.fromExtra("bogus"))
        assertEquals(QrPayloadKind.COSIGN, QrPayloadKind.fromExtra(QrPayloadKind.COSIGN.name))
    }

    @Test
    fun `otpauth is accepted by default`() {
        assertTrue(QrPayloadFilter.accepts(otpauth, QrPayloadKind.fromExtra(null)))
        assertTrue(QrPayloadFilter.accepts(otpauth, QrPayloadKind.OTPAUTH))
    }

    @Test
    fun `co-sign payloads are refused by default`() {
        assertFalse(QrPayloadFilter.accepts(cosignRequest, QrPayloadKind.OTPAUTH))
        assertFalse(QrPayloadFilter.accepts(cosignResponse, QrPayloadKind.OTPAUTH))
    }

    @Test
    fun `co-sign payloads are accepted when the intent asks for them`() {
        assertTrue(QrPayloadFilter.accepts(cosignRequest, QrPayloadKind.COSIGN))
        assertTrue(QrPayloadFilter.accepts(cosignResponse, QrPayloadKind.COSIGN))
        assertTrue(QrPayloadFilter.accepts("  $cosignResponse\n", QrPayloadKind.COSIGN))
    }

    @Test
    fun `otpauth is refused when the intent asks for co-sign`() {
        assertFalse(QrPayloadFilter.accepts(otpauth, QrPayloadKind.COSIGN))
    }

    @Test
    fun `no kind accepts both otpauth and co-sign`() {
        QrPayloadKind.entries.forEach { kind ->
            val both = QrPayloadFilter.accepts(otpauth, kind) && QrPayloadFilter.accepts(cosignRequest, kind)
            assertFalse(kind.name, both)
        }
    }

    @Test
    fun `other payloads are refused for every kind`() {
        val others = listOf("https://example.com", "hello", "{not json", "[1,2]", """{"hash":"ab"}""", "")
        QrPayloadKind.entries.forEach { kind ->
            others.forEach { value -> assertFalse("$kind $value", QrPayloadFilter.accepts(value, kind)) }
        }
    }
}
