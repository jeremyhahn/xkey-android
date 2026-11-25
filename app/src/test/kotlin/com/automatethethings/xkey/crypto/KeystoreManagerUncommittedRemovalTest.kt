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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
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
        keystoreManager = KeystoreManager(mockk<Context>(relaxed = true), pqcStore = noPqcKeys())
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

        assertThrows(KeyDeletionException::class.java) { manager.deleteGeneralKey("ua") }
        assertFalse("the cache already dropped the key", prefs.contains("xkey_key_ua"))
        assertThrows(KeyDeletionException::class.java) { manager.deleteGeneralKey("ua") }
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
        assertThrows(KeyDeletionException::class.java) { manager.deleteGeneralKey("ud") }

        prefs.diskFails = false
        val writesBefore = prefs.diskWrites

        assertTrue("the retried removal reports the key removed", manager.deleteGeneralKey("ud"))
        assertTrue("the retry wrote to disk", prefs.diskWrites > writesBefore)
        assertFalse("the key is gone from disk", "xkey_key_ud" in prefs.disk)
        assertTrue(manager.keyMaterialAbsent("ud"))
        assertFalse(manager.deleteGeneralKey("ud"))
    }

    @Test
    fun `every presence path counts a removal that did not commit as present`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_ue" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        prefs.diskFails = true
        assertThrows(KeyDeletionException::class.java) { manager.deleteByAlias("xkey_key_ue") }
        assertFalse("the cache already dropped the key", prefs.contains("xkey_key_ue"))

        assertEquals("xkey_key_ue", manager.resolveKeystoreAlias("ue", UserKeyKind.GENERAL))
        val absent = runCatching { manager.keyMaterialAbsent("ue") }
        assertTrue("keyMaterialAbsent, got $absent", absent.isFailure || absent.getOrNull() == false)
        assertEquals(KeySecurityLevel.SOFTWARE, manager.generalKeySecurityLevel("ue"))
        assertThrows(KeyDeletionException::class.java) { manager.deleteGeneralKey("ue") }
        assertTrue("the key is still on disk", "xkey_key_ue" in prefs.disk)
    }

    @Test
    fun `keyMaterialAbsent during an in-flight removal that then fails reports the key present`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_uf" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        val removal = PausedRemoval.start(prefs) { manager.deleteByAlias("xkey_key_uf") }

        val absent = AtomicReference<Result<Boolean>>()
        val probe = thread { absent.set(runCatching { manager.keyMaterialAbsent("uf") }) }
        awaitParkedOrDone(probe)
        removal.failCommit()
        probe.join(10_000)

        assertTrue("the removal did not commit", removal.result.isFailure)
        val read = absent.get()
        assertTrue("a key still on disk must not read as absent, got $read", read.isFailure || read.getOrNull() == false)
        assertTrue("the key is still on disk", "xkey_key_uf" in prefs.disk)
    }

    @Test
    fun `no presence path reads a key absent while its removal is in flight`() {
        val prefs = FakeSharedPreferences(mapOf("xkey_key_ug" to "secret"))
        val manager = softwareEd25519Manager(prefs)
        val removal = PausedRemoval.start(prefs) { manager.deleteByAlias("xkey_key_ug") }

        val resolved = AtomicReference<Result<String?>>()
        val stored = AtomicReference<Result<Boolean>>()
        val absent = AtomicReference<Result<Boolean>>()
        val deleted = AtomicReference<Result<Boolean>>()
        val deletedByAlias = AtomicReference<Result<Boolean>>()
        val probe = thread {
            resolved.set(runCatching { manager.resolveKeystoreAlias("ug", UserKeyKind.GENERAL) })
            stored.set(runCatching { manager.hasSoftwareEd25519Key("xkey_key_ug") })
            absent.set(runCatching { manager.keyMaterialAbsent("ug") })
            deleted.set(runCatching { manager.deleteGeneralKey("ug") })
            deletedByAlias.set(runCatching { manager.deleteByAlias("xkey_key_ug") })
        }
        awaitParkedOrDone(probe)
        removal.failCommit()
        probe.join(10_000)

        assertTrue("the removal did not commit", removal.result.isFailure)
        assertEquals("resolveKeystoreAlias", "xkey_key_ug", resolved.get().getOrNull())
        assertEquals("hasSoftwareEd25519Key", true, stored.get().getOrNull())
        val read = absent.get()
        assertTrue("keyMaterialAbsent, got $read", read.isFailure || read.getOrNull() == false)
        assertTrue("deleteKey must throw, got ${deleted.get()}", deleted.get().exceptionOrNull() is KeyDeletionException)
        assertTrue(
            "deleteByAlias must throw, got ${deletedByAlias.get()}",
            deletedByAlias.get().exceptionOrNull() is KeyDeletionException
        )
        assertTrue("the key is still on disk", "xkey_key_ug" in prefs.disk)
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
 * A key removal run on its own thread whose commit is held after the
 * in-memory edit, before the disk write, until [failCommit].
 */
internal class PausedRemoval private constructor(
    private val prefs: FakeSharedPreferences,
    private val pause: FakeSharedPreferences.CommitPause,
    private val worker: Thread,
    private val outcome: AtomicReference<Result<Boolean>>
) {
    /** The removal's outcome; valid after [failCommit]. */
    val result: Result<Boolean> get() = outcome.get()

    /** Lets the held commit fail to reach disk and waits for the removal to end. */
    fun failCommit() {
        prefs.diskFails = true
        pause.release.countDown()
        worker.join(10_000)
        check(!worker.isAlive) { "the removal did not end" }
    }

    companion object {
        /** Starts [remove] and returns once its commit is held. */
        fun start(prefs: FakeSharedPreferences, remove: () -> Boolean): PausedRemoval {
            val pause = FakeSharedPreferences.CommitPause()
            prefs.pauseNextCommit = pause
            val outcome = AtomicReference<Result<Boolean>>()
            val worker = thread { outcome.set(runCatching(remove)) }
            check(pause.reached.await(10, TimeUnit.SECONDS)) { "the removal never reached its commit" }
            return PausedRemoval(prefs, pause, worker, outcome)
        }
    }
}

/**
 * Waits until [probe] has ended or is parked (on a lock such as an alias
 * gate), so a probe that does not wait has already read the store.
 */
internal fun awaitParkedOrDone(probe: Thread) {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while (System.nanoTime() < deadline) {
        when (probe.state) {
            Thread.State.TERMINATED, Thread.State.WAITING, Thread.State.TIMED_WAITING, Thread.State.BLOCKED -> return
            else -> Thread.sleep(5)
        }
    }
    error("probe neither ended nor waited")
}

/**
 * A software ML-DSA store holding no key, for a [KeystoreManager] built on a
 * mocked context, whose files directory the real store cannot use.
 */
internal fun noPqcKeys(): PqcSoftwareKeyStore = mockk(relaxed = true)

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

    /**
     * Holds the next commit between its in-memory edit and its disk write,
     * with the store unlocked, as Android's disk writer does.
     */
    class CommitPause {
        /** Counted down once the edit is in memory and the commit waits. */
        val reached = java.util.concurrent.CountDownLatch(1)

        /** Counted down by the test to let the commit write (or fail). */
        val release = java.util.concurrent.CountDownLatch(1)
    }

    /** Pauses the next commit only; set [diskFails] before release to fail it. */
    @Volatile var pauseNextCommit: CommitPause? = null

    private fun commitEdit(removes: Set<String>, clear: Boolean, puts: Map<String, Any?>): Boolean {
        val pause = synchronized(this) {
            if (clear) memory.clear()
            removes.forEach { memory.remove(it) }
            memory.putAll(puts)
            pauseNextCommit.also { pauseNextCommit = null }
        }
        if (pause != null) {
            pause.reached.countDown()
            check(pause.release.await(10, java.util.concurrent.TimeUnit.SECONDS)) { "commit pause never released" }
        }
        synchronized(this) {
            if (diskFails) return false
            disk.clear()
            disk.putAll(memory)
            diskWrites++
            return true
        }
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
