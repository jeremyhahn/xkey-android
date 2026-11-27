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
import android.content.SharedPreferences
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A key deletion that fails is a failure, never "no key": a software Ed25519
 * key whose removal does not commit, and a software key store that cannot be
 * opened while the key may be in it, make the delete throw. The phone's
 * delete path then keeps the key's metadata row, so the key still lists and
 * the delete can be retried.
 */
class KeystoreManagerDeleteFailureTest {

    private lateinit var keyStore: KeyStore
    private lateinit var keystoreManager: KeystoreManager

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
        keyStore = mockk(relaxed = true)
        every { keyStore.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
        keystoreManager = KeystoreManager(mockk<Context>(relaxed = true), pqcStore = noPqcKeys())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a software Ed25519 removal that does not commit throws and is not audited`() {
        val manager = softwareEd25519Manager { failingCommitPrefs() }

        assertThrows(KeyDeletionException::class.java) { manager.deleteGeneralKey("ed") }

        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    @Test
    fun `deleteByAlias of a software Ed25519 key that does not commit throws`() {
        val manager = softwareEd25519Manager { failingCommitPrefs() }

        assertThrows(KeyDeletionException::class.java) { manager.deleteByAlias("xkey_key_ed") }
    }

    @Test
    fun `an unreadable software key store is a failure, not an absent key`() {
        val manager = softwareEd25519Manager { throw IllegalStateException("master key unreadable") }

        assertThrows(KeyDeletionException::class.java) { manager.deleteGeneralKey("ed") }

        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    @Test
    fun `a Keystore entry that cannot be deleted is a deletion failure`() {
        every { keyStore.containsAlias("xkey_key_hw") } returns true
        every { keyStore.deleteEntry("xkey_key_hw") } throws java.security.KeyStoreException("busy")

        assertThrows(KeyDeletionException::class.java) { keystoreManager.deleteGeneralKey("hw") }
        assertThrows(KeyDeletionException::class.java) { keystoreManager.deleteByAlias("xkey_key_hw") }

        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    @Test
    fun `a key stored nowhere in a readable store is still absent`() {
        val manager = softwareEd25519Manager { failingCommitPrefs() }

        assertFalse(manager.deleteGeneralKey("none"))
        assertFalse(manager.deleteByAlias("xkey_key_none"))
    }

    /** Software Ed25519 key `xkey_key_ed` is stored, and removing it does not commit. */
    private fun failingCommitPrefs(): SharedPreferences {
        val editor = mockk<SharedPreferences.Editor>()
        every { editor.remove(any()) } returns editor
        every { editor.commit() } returns false
        val prefs = mockk<SharedPreferences>()
        every { prefs.contains(any()) } answers { firstArg<String>() == "xkey_key_ed" }
        every { prefs.edit() } returns editor
        return prefs
    }

    /** A manager on an API 33+ device whose software Ed25519 store is [prefs]. */
    private fun softwareEd25519Manager(prefs: () -> SharedPreferences): KeystoreManager {
        val manager = spyk(keystoreManager)
        every { manager.softwareEd25519Supported() } returns true
        every { manager.ed25519Prefs() } answers { prefs() }
        return manager
    }
}
