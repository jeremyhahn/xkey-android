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

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.piv.FakePivKeystore
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivTestCertificates
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A PIV slot key (`xkey_piv_*`) is reached only through
 * [com.automatethethings.xkey.piv.PivKeyManager], which keeps its `piv_slots`
 * row in step. The general key operations of a real [KeystoreManager] must not
 * resolve or delete it by its raw alias, while a general key whose logical id
 * merely starts with `xkey_piv_` (stored at `xkey_key_xkey_piv_*`) must still
 * work (#173).
 */
class KeystoreManagerPivAliasTest {

    private val pivAlias = PivSlot.AUTHENTICATION.keystoreAlias
    private val generalId = "xkey_piv_example"
    private val generalAlias = "xkey_key_$generalId"

    private lateinit var fake: FakePivKeystore
    private lateinit var keystoreManager: KeystoreManager
    private var generalPresent = true

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit

        fake = FakePivKeystore(PivTestCertificates.ecKeyPair())
        generalPresent = true
        every { fake.keyStore.containsAlias(generalAlias) } answers { generalPresent }
        every { fake.keyStore.deleteEntry(generalAlias) } answers { generalPresent = false }
        fake.install()
        keystoreManager = KeystoreManager(mockk<Context>(relaxed = true))
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a raw PIV slot alias does not resolve as a general key`() {
        assertNull(keystoreManager.resolveKeystoreAlias(pivAlias))
        assertFalse(keystoreManager.keyExists(pivAlias))
    }

    @Test
    fun `deleteKey of a raw PIV slot alias leaves the slot key`() {
        assertFalse(keystoreManager.deleteKey(pivAlias))
        assertNotNull(fake.live)
        verify(exactly = 0) { fake.keyStore.deleteEntry(pivAlias) }
    }

    @Test
    fun `deleteByAlias of a PIV slot alias leaves the slot key`() {
        assertFalse(keystoreManager.deleteByAlias(pivAlias))
        assertNotNull(fake.live)
        verify(exactly = 0) { fake.keyStore.deleteEntry(pivAlias) }
    }

    @Test
    fun `a general key whose id starts with the PIV prefix resolves and deletes`() {
        assertEquals(generalAlias, keystoreManager.resolveKeystoreAlias(generalId))
        assertTrue(keystoreManager.deleteKey(generalId))
        verify { fake.keyStore.deleteEntry(generalAlias) }
        assertNull(keystoreManager.resolveKeystoreAlias(generalId))
    }

    @Test
    fun `deleteByAlias removes a general key whose id starts with the PIV prefix`() {
        val alias = keystoreManager.resolveKeystoreAlias(generalId)
        assertEquals(generalAlias, alias)
        assertTrue(keystoreManager.deleteByAlias(alias!!))
        verify { fake.keyStore.deleteEntry(generalAlias) }
    }
}
