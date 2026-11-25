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
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [KeystoreManager.deleteCredentialKey] removes exactly a credential's
 * `xkey_credential_<id>` entry, never the general key of the same ID, and
 * writes the audit record of every deletion it makes.
 */
class KeystoreManagerCredentialDeleteTest {

    private val entries = mutableSetOf("xkey_credential_c", "xkey_key_c")
    private lateinit var keystoreManager: KeystoreManager

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
        val keyStore = mockk<KeyStore>(relaxed = true)
        every { keyStore.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { keyStore.deleteEntry(any()) } answers { entries.remove(firstArg<String>()) }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
        keystoreManager = KeystoreManager(mockk<Context>(relaxed = true))
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    @Test
    fun `a credential delete removes only its entry and is audited`() {
        assertTrue(keystoreManager.deleteCredentialKey("c"))

        assertEquals(setOf("xkey_key_c"), entries)
        verify(exactly = 1) { AuditLogger.logKeyDeleted("c", "c", "fido2") }
    }

    @Test
    fun `a missing credential is not deleted and not audited`() {
        assertFalse(keystoreManager.deleteCredentialKey("missing"))

        assertEquals(2, entries.size)
        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }
}
