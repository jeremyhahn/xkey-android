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
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * SharedPreferences drops a removed key from its in-memory map before it
 * writes to disk, and keeps it dropped when the write fails. A software
 * Ed25519 key whose removal did not commit is still on disk, so every later
 * presence read (a delete retry, keyMaterialAbsent, a lookup) must count it
 * present until a retry of the removal reaches disk.
 */
class KeystoreManagerUncommittedRemovalTest {

    private lateinit var keyStore: KeyStore
    private lateinit var keystoreManager: KeystoreManager

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
        keyStore = mockk(relaxed = true)
        every { keyStore.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
        keystoreManager = KeystoreManager(mockk<Context>(relaxed = true))
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a delete retry while the disk still fails throws again`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_ua" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        prefs.diskFails = true

        assertThrows(KeyDeletionException::class.java) { manager.deleteKey("ua") }
        assertFalse("the cache already dropped the key", prefs.contains("xkey_key_ua"))
        assertThrows(KeyDeletionException::class.java) { manager.deleteKey("ua") }
        assertThrows(KeyDeletionException::class.java) { manager.deleteByAlias("xkey_key_ua") }
        assertTrue("the key is still on disk", "xkey_key_ua" in prefs.disk)
    }

    @Test
    fun `deleteByAlias retried while the disk still fails throws again`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_ub" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        prefs.diskFails = true

        assertThrows(KeyDeletionException::class.java) { manager.deleteByAlias("xkey_key_ub") }
        assertThrows(KeyDeletionException::class.java) { manager.deleteByAlias("xkey_key_ub") }
    }

    @Test
    fun `keyMaterialAbsent never reports a key whose removal did not commit absent`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_uc" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        prefs.diskFails = true

        assertThrows(KeyDeletionException::class.java) { manager.deleteByAlias("xkey_key_uc") }

        val absent = runCatching { manager.keyMaterialAbsent("uc") }
        assertTrue(
            "a key still on disk must not read as absent, got $absent",
            absent.isFailure || absent.getOrNull() == false
        )
    }

    @Test
    fun `a healed disk lets the delete retry commit the removal`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_ud" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        prefs.diskFails = true
        assertThrows(KeyDeletionException::class.java) { manager.deleteKey("ud") }

        prefs.diskFails = false
        val writesBefore = prefs.diskWrites

        assertTrue("the retried removal reports the key removed", manager.deleteKey("ud"))
        assertTrue("the retry wrote to disk", prefs.diskWrites > writesBefore)
        assertFalse("the key is gone from disk", "xkey_key_ud" in prefs.disk)
        assertTrue(manager.keyMaterialAbsent("ud"))
        assertFalse(manager.deleteKey("ud"))
    }

    @Test
    fun `every presence path counts a removal that did not commit as present`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_ue" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        prefs.diskFails = true
        assertThrows(KeyDeletionException::class.java) { manager.deleteByAlias("xkey_key_ue") }
        assertFalse("the cache already dropped the key", prefs.contains("xkey_key_ue"))

        assertEquals("xkey_key_ue", manager.resolveKeystoreAlias("ue"))
        val absent = runCatching { manager.keyMaterialAbsent("ue") }
        assertTrue("keyMaterialAbsent, got $absent", absent.isFailure || absent.getOrNull() == false)
        assertEquals(KeySecurityLevel.SOFTWARE, manager.generalKeySecurityLevel("ue"))
        assertThrows(KeyDeletionException::class.java) { manager.deleteKey("ue") }
        assertTrue("the key is still on disk", "xkey_key_ue" in prefs.disk)
    }

    /** A manager on an API 33+ device whose software Ed25519 store is [prefs]. */
    private fun softwareEd25519Manager(prefs: SharedPreferences): KeystoreManager {
        val manager = spyk(keystoreManager)
        every { manager.softwareEd25519Supported() } returns true
        every { manager.ed25519Prefs() } returns prefs
        return manager
    }
}

/**
 * An in-memory [SharedPreferences] that behaves like Android's on a failed
 * write: [SharedPreferences.Editor.commit] applies the edit to the in-memory
 * map first, then returns false while [diskFails], leaving [disk] as it was.
 * A later commit with the disk healthy writes the whole in-memory map.
 */
internal class FakeSharedPreferences(initial: Map<String, Any?> = emptyMap()) : SharedPreferences {

    private val memory = HashMap<String, Any?>(initial)

    /** What a restart would read back. */
    val disk = HashMap<String, Any?>(initial)

    /** True while every commit fails to reach disk. */
    @Volatile var diskFails = false

    /** Commits that reached disk. */
    @Volatile var diskWrites = 0

    @Synchronized private fun commitEdit(removes: Set<String>, clear: Boolean, puts: Map<String, Any?>): Boolean {
        if (clear) memory.clear()
        removes.forEach { memory.remove(it) }
        memory.putAll(puts)
        if (diskFails) return false
        disk.clear()
        disk.putAll(memory)
        diskWrites++
        return true
    }

    @Synchronized override fun getAll(): MutableMap<String, *> = HashMap(memory)
    @Synchronized override fun getString(key: String, defValue: String?): String? =
        memory[key] as String? ?: defValue
    @Suppress("UNCHECKED_CAST")
    @Synchronized override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
        memory[key] as MutableSet<String>? ?: defValues
    @Synchronized override fun getInt(key: String, defValue: Int): Int = memory[key] as Int? ?: defValue
    @Synchronized override fun getLong(key: String, defValue: Long): Long = memory[key] as Long? ?: defValue
    @Synchronized override fun getFloat(key: String, defValue: Float): Float = memory[key] as Float? ?: defValue
    @Synchronized override fun getBoolean(key: String, defValue: Boolean): Boolean =
        memory[key] as Boolean? ?: defValue
    @Synchronized override fun contains(key: String): Boolean = memory.containsKey(key)

    override fun edit(): SharedPreferences.Editor = Editor()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    private inner class Editor : SharedPreferences.Editor {
        private val puts = HashMap<String, Any?>()
        private val removes = HashSet<String>()
        private var clear = false

        private fun put(key: String, value: Any?): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun putString(key: String, value: String?) = put(key, value)
        override fun putStringSet(key: String, values: MutableSet<String>?) = put(key, values)
        override fun putInt(key: String, value: Int) = put(key, value)
        override fun putLong(key: String, value: Long) = put(key, value)
        override fun putFloat(key: String, value: Float) = put(key, value)
        override fun putBoolean(key: String, value: Boolean) = put(key, value)
        override fun remove(key: String): SharedPreferences.Editor {
            removes += key
            return this
        }
        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }
        override fun commit(): Boolean = commitEdit(removes, clear, puts)
        override fun apply() {
            commitEdit(removes, clear, puts)
        }
    }
}
