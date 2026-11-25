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
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.KeyStore
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The audited key deletes of [KeystoreManager]: [KeystoreManager.deleteKey],
 * [KeystoreManager.deleteGeneralKey] and [KeystoreManager.deleteCredentialKey].
 * [KeystoreManager.deleteCredentialKey] removes exactly a credential's
 * `xkey_credential_<id>` entry, never the general key of the same ID.
 *
 * Each delete writes its audit record only for an entry it removed: a
 * missing alias writes none, and of two deletes of one key racing on two
 * threads exactly one succeeds and is audited. A software Ed25519 key, kept
 * outside the Keystore, is removed by the delete too, so it no longer
 * resolves.
 */
class KeystoreManagerCredentialDeleteTest {

    private val entries: MutableSet<String> = ConcurrentHashMap.newKeySet<String>().apply {
        addAll(listOf("xkey_credential_c", "xkey_key_c", "xkey_key_g"))
    }
    private lateinit var keyStore: KeyStore
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
        keyStore = mockk(relaxed = true)
        every { keyStore.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { keyStore.deleteEntry(any()) } answers { entries.remove(firstArg<String>()) }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
        keystoreManager = KeystoreManager(mockk<Context>(relaxed = true), pqcStore = noPqcKeys())
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    @Test
    fun `a credential delete removes only its entry and is audited`() {
        assertTrue(keystoreManager.deleteCredentialKey("c"))

        assertEquals(setOf("xkey_key_c", "xkey_key_g"), entries.toSet())
        verify(exactly = 1) { AuditLogger.logKeyDeleted("c", "c", "fido2") }
    }

    @Test
    fun `a missing credential is not deleted and not audited`() {
        assertFalse(keystoreManager.deleteCredentialKey("missing"))

        assertEquals(3, entries.size)
        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    @Test
    fun `deleteGeneralKey of a missing alias is not audited`() {
        assertFalse(keystoreManager.deleteGeneralKey("missing"))

        assertEquals(3, entries.size)
        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    @Test
    fun `two racing deleteGeneralKey calls audit one deletion`() {
        val results = racingDeletes("xkey_key_g") { keystoreManager.deleteGeneralKey("g") }

        assertEquals(listOf(false, true), results.sorted())
        assertFalse("xkey_key_g" in entries)
        verify(exactly = 1) { AuditLogger.logKeyDeleted("g", "g", "general") }
    }

    @Test
    fun `two racing deleteCredentialKey calls audit one deletion`() {
        val results = racingDeletes("xkey_credential_c") { keystoreManager.deleteCredentialKey("c") }

        assertEquals(listOf(false, true), results.sorted())
        assertFalse("xkey_credential_c" in entries)
        verify(exactly = 1) { AuditLogger.logKeyDeleted("c", "c", "fido2") }
    }

    @Test
    fun `deleteGeneralKey removes a software Ed25519 key and audits it once`() {
        val prefs = InMemorySharedPreferences()
        val manager = softwareEd25519Manager(prefs)
        prefs.edit().putString("xkey_key_ed", "encoded-private-key").commit()
        assertEquals("xkey_key_ed", manager.resolveKeystoreAlias("ed", UserKeyKind.GENERAL))

        assertTrue(manager.deleteGeneralKey("ed"))

        assertFalse(prefs.contains("xkey_key_ed"))
        assertNull(manager.resolveKeystoreAlias("ed", UserKeyKind.GENERAL))
        assertFalse(manager.deleteGeneralKey("ed"))
        verify(exactly = 1) { AuditLogger.logKeyDeleted("ed", "ed", "general") }
    }

    @Test
    fun `a software Ed25519 removal that does not commit is not audited`() {
        val editor = mockk<SharedPreferences.Editor>()
        every { editor.remove(any()) } returns editor
        every { editor.commit() } returns false
        val prefs = mockk<SharedPreferences>()
        every { prefs.contains("xkey_key_ed") } returns true
        every { prefs.edit() } returns editor
        val manager = softwareEd25519Manager(prefs)

        assertThrows(KeyDeletionException::class.java) { manager.deleteGeneralKey("ed") }

        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    /** A manager on an API 33+ device whose software Ed25519 store is [prefs]. */
    private fun softwareEd25519Manager(prefs: SharedPreferences): KeystoreManager {
        val manager = spyk(keystoreManager)
        every { manager.softwareEd25519Supported() } returns true
        every { manager.ed25519Prefs() } returns prefs
        return manager
    }

    /**
     * Runs [delete] twice at once on one key. The first existence check of
     * [alias] records its answer, then starts the second delete on another
     * thread and gives it a moment to run (it blocks if the first holds the
     * alias gate; the gate is reentrant, so a same-thread call would not
     * race) before answering. Returns both results.
     */
    private fun racingDeletes(alias: String, delete: () -> Boolean): List<Boolean> {
        val results = Collections.synchronizedList(mutableListOf<Boolean>())
        val raced = AtomicBoolean(false)
        var second: Thread? = null
        every { keyStore.containsAlias(alias) } answers {
            val present = alias in entries
            if (raced.compareAndSet(false, true)) {
                second = Thread { results.add(delete()) }.also {
                    it.start()
                    it.join(200)
                }
            }
            present
        }

        results.add(delete())
        val other = checkNotNull(second) { "the delete never checked $alias" }
        other.join(5_000)
        assertFalse("the second delete did not finish", other.isAlive)
        return results.toList()
    }
}
