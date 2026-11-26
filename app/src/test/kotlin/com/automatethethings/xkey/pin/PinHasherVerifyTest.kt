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

package com.automatethethings.xkey.pin

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [PinHasher.verifyPin] accepts exactly the stored hash. Argon2 is native
 * and does not run on the JVM, so the hash step is stubbed; the comparison
 * under test is the real one.
 */
class PinHasherVerifyTest {

    private val salt = ByteArray(16) { 1 }
    private val stored = ByteArray(32) { it.toByte() }

    @Before
    fun setUp() {
        mockkObject(PinHasher)
        every { PinHasher.hashPin("123456", salt) } returns stored.copyOf()
        every { PinHasher.hashPin("654321", salt) } returns stored.copyOf().also { it[31] = 0 }
        every { PinHasher.hashPin("111111", salt) } returns stored.copyOf(16)
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `the right PIN verifies`() {
        assertTrue(PinHasher.verifyPin("123456", salt, stored))
    }

    @Test
    fun `a PIN whose hash differs in one byte does not verify`() {
        assertFalse(PinHasher.verifyPin("654321", salt, stored))
    }

    @Test
    fun `a hash of another length does not verify`() {
        assertFalse(PinHasher.verifyPin("111111", salt, stored))
    }
}
