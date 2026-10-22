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

import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.VaultUnlockAttempts
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * Unit tests for [PasswordVault].
 *
 * Argon2 is native (JNI) and unavailable on the JVM, so the vault is built with
 * a SHA-256 stand-in hasher; what is under test is the gate, not the KDF.
 */
class PasswordVaultTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val sha256Hasher = PassphraseHasher { passphrase, salt ->
        MessageDigest.getInstance("SHA-256").run {
            update(salt)
            digest(passphrase.toByteArray(Charsets.UTF_8))
        }
    }

    private class InMemoryFactorStore : PasswordVaultFactorStore {
        val records = mutableListOf<PasswordVaultFactorRecord>()
        override suspend fun list(): List<PasswordVaultFactorRecord> = records.toList()
        override suspend fun add(record: PasswordVaultFactorRecord) {
            records += record
        }
    }

    /** Stands in for the PIN settings DataStore; it outlives any one vault. */
    private class InMemoryAttemptStore(
        var thresholds: VaultUnlockLimits = PinSettingsData().let {
            VaultUnlockLimits(it.maxPinAttempts, it.lockoutDurationSeconds)
        }
    ) : VaultUnlockAttemptStore {
        var counter = VaultUnlockAttempts()
        override suspend fun limits(): VaultUnlockLimits = thresholds
        override suspend fun read(): VaultUnlockAttempts = counter
        override suspend fun write(attempts: VaultUnlockAttempts) {
            counter = attempts
        }
    }

    /** The fake clock, in epoch milliseconds. */
    private var now = 1_700_000_000_000L

    private var hashes = 0

    private val countingHasher = PassphraseHasher { passphrase, salt ->
        hashes++
        sha256Hasher.hash(passphrase, salt)
    }

    private fun vault(
        store: PasswordVaultFactorStore = InMemoryFactorStore(),
        attempts: VaultUnlockAttemptStore = InMemoryAttemptStore()
    ) = PasswordVault(store, attempts, countingHasher, clock = { now })

    private val wrong = PasswordVaultCredential.Passphrase("tr0ub4dor")
    private val right = PasswordVaultCredential.Passphrase("correct horse battery staple")

    private suspend fun failTimes(vault: PasswordVault, times: Int) = repeat(times) {
        assertTrue(rejection(vault, wrong) is VaultCredentialRejectedException)
    }

    private suspend fun rejection(vault: PasswordVault, credential: PasswordVaultCredential): Exception =
        try {
            vault.unlock(credential)
            throw AssertionError("expected the unlock to fail")
        } catch (e: PasswordVaultException) {
            e
        }

    @Test
    fun `the enrolled passphrase unlocks the vault`() = runTest {
        val vault = vault()
        vault.enrollPassphrase("correct horse battery staple")
        assertTrue(vault.isLocked())

        vault.unlock(PasswordVaultCredential.Passphrase("correct horse battery staple"))

        assertTrue(vault.isUnlocked())
        assertFalse(vault.isLocked())
    }

    @Test
    fun `a wrong passphrase is rejected without detail and leaves the vault locked`() = runTest {
        val vault = vault()
        vault.enrollPassphrase("correct horse battery staple")

        val e = rejection(vault, PasswordVaultCredential.Passphrase("tr0ub4dor"))

        assertTrue(e is VaultCredentialRejectedException)
        assertEquals("password vault credential rejected", e.message)
        assertTrue(vault.isLocked())
    }

    @Test
    fun `an unlock before any enrollment is not initialized`() = runTest {
        val vault = vault()

        val e = rejection(vault, PasswordVaultCredential.Passphrase("anything"))

        assertTrue(e is VaultNotInitializedException)
        assertFalse("an uninitialized vault does not gate the store", vault.isLocked())
    }

    @Test
    fun `a passkey credential is rejected because no passkey factor can be enrolled`() = runTest {
        val vault = vault()
        vault.enrollPassphrase("correct horse battery staple")

        val e = rejection(vault, PasswordVaultCredential.Passkey(byteArrayOf(1), ByteArray(32), null))

        assertTrue(e is VaultCredentialRejectedException)
    }

    @Test
    fun `a key credential is rejected because no key factor can be enrolled`() = runTest {
        val vault = vault()
        vault.enrollPassphrase("correct horse battery staple")

        val e = rejection(vault, PasswordVaultCredential.Key("tpm", "fp", byteArrayOf(1)))

        assertTrue(e is VaultCredentialRejectedException)
    }

    @Test
    fun `lock relocks an unlocked vault`() = runTest {
        val vault = vault()
        vault.enrollPassphrase("pass")
        vault.unlock(PasswordVaultCredential.Passphrase("pass"))

        vault.lock()

        assertTrue(vault.isLocked())
    }

    @Test(expected = VaultNotInitializedException::class)
    fun `lock before any enrollment is not initialized`() = runTest {
        vault().lock()
    }

    @Test
    fun `the verifier is not the passphrase`() = runTest {
        val record = vault().enrollPassphrase("pass")

        assertFalse(record.verifier.contentEquals("pass".toByteArray()))
        assertEquals(16, record.salt.size)
    }

    @Test
    fun `the file store round-trips enrolled factors`() = runTest {
        val dir = tmp.newFolder("vault")
        val written = vault(FilePasswordVaultFactorStore(dir)).enrollPassphrase("pass", label = "laptop")

        val reloaded = FilePasswordVaultFactorStore(dir).list().single()

        assertEquals(written.id, reloaded.id)
        assertEquals("passphrase", reloaded.factor)
        assertEquals("laptop", reloaded.label)
        assertArrayEquals(written.salt, reloaded.salt)
        assertArrayEquals(written.verifier, reloaded.verifier)
    }

    @Test
    fun `a fresh vault over a persisted factor starts locked and unlocks`() = runTest {
        val dir = tmp.newFolder("vault")
        vault(FilePasswordVaultFactorStore(dir)).enrollPassphrase("pass")

        val session = vault(FilePasswordVaultFactorStore(dir))
        assertTrue(session.isLocked())
        session.unlock(PasswordVaultCredential.Passphrase("pass"))

        assertFalse(session.isLocked())
    }

    private suspend fun thrown(block: suspend () -> Unit): Throwable =
        try {
            block()
            throw AssertionError("expected a failure")
        } catch (e: PasswordVaultFactorsUnreadableException) {
            e
        }

    @Test
    fun `a factor file that cannot be read fails closed, never as uninitialized`() = runTest {
        val dir = tmp.newFolder("vault")
        // A directory where factors.json belongs: the read fails with an I/O
        // error even for root, which ignores permission bits.
        val factors = File(dir, "factors.json").apply { assertTrue(mkdir()) }
        val store = FilePasswordVaultFactorStore(dir)
        val vault = vault(store)

        thrown { store.list() }
        thrown { vault.isInitialized() }
        thrown { vault.isLocked() }
        thrown { requirePasswordStoreUnlocked(store) }
        thrown { vault.lock() }
        thrown { vault.unlock(right) }
        assertFalse(vault.isUnlocked())

        // An enrollment must not replace factors it could not read.
        thrown { vault.enrollPassphrase("pass") }
        assertTrue(factors.isDirectory)
    }

    @Test
    fun `a lock that cannot read the factors still locks an unlocked vault`() = runTest {
        val dir = tmp.newFolder("vault")
        val store = FilePasswordVaultFactorStore(dir)
        val vault = vault(store)
        vault.enrollPassphrase("pass")
        vault.unlock(PasswordVaultCredential.Passphrase("pass"))
        // A directory where factors.json was: the read fails even for root.
        val factors = File(dir, "factors.json")
        assertTrue(factors.delete())
        assertTrue(factors.mkdir())

        thrown { vault.lock() }

        assertFalse("a failed lock must not leave the vault unlocked", vault.isUnlocked())
        thrown { vault.isLocked() }
        withContext(SessionPasswordVault(vault)) {
            thrown { requirePasswordStoreUnlocked(store) }
        }
    }

    @Test
    fun `a factor file the process may not read fails closed`() = runTest {
        val dir = tmp.newFolder("vault")
        vault(FilePasswordVaultFactorStore(dir)).enrollPassphrase("pass")
        val factors = File(dir, "factors.json")
        assertTrue(factors.setReadable(false, false))
        try {
            // Root reads it regardless; the directory case above covers root.
            assumeFalse("running as root: permission bits are not enforced", factors.canRead())
            val store = FilePasswordVaultFactorStore(dir)

            thrown { store.list() }
            thrown { vault(store).isLocked() }
            thrown { requirePasswordStoreUnlocked(store) }
        } finally {
            factors.setReadable(true, false)
        }
    }

    // -------------------------------------------------------------------------
    // Attempt limit: the PIN lockout rule, with the PIN's thresholds
    // -------------------------------------------------------------------------

    @Test
    fun `the PIN attempt limit is the threshold, the failure that reaches it locks`() = runTest {
        val attempts = InMemoryAttemptStore()
        val vault = vault(attempts = attempts)
        vault.enrollPassphrase(right.passphrase)
        val max = PinSettingsData().maxPinAttempts

        failTimes(vault, max - 1)
        assertEquals(VaultUnlockAttempts(max - 1, 0), attempts.counter)

        failTimes(vault, 1)
        assertTrue(rejection(vault, wrong) is VaultUnlockLockedOutException)
        assertEquals(max, attempts.counter.failedAttempts)
    }

    @Test
    fun `a locked-out unlock refuses even the right passphrase without hashing or detail`() = runTest {
        val attempts = InMemoryAttemptStore()
        val vault = vault(attempts = attempts)
        vault.enrollPassphrase(right.passphrase)
        failTimes(vault, attempts.thresholds.maxAttempts)
        val hashesBefore = hashes
        val counterBefore = attempts.counter

        val e = rejection(vault, right)

        assertTrue(e is VaultUnlockLockedOutException)
        assertEquals("password vault unlock is locked out", e.message)
        assertEquals("no Argon2id while locked out", hashesBefore, hashes)
        assertEquals("a refusal is not counted", counterBefore, attempts.counter)
        assertTrue(vault.isLocked())
    }

    @Test
    fun `the lockout lasts the PIN lockout duration and each later failure relocks for it again`() = runTest {
        val attempts = InMemoryAttemptStore(VaultUnlockLimits(maxAttempts = 3, lockoutDurationSeconds = 60))
        val vault = vault(attempts = attempts)
        vault.enrollPassphrase(right.passphrase)
        failTimes(vault, 3)
        assertEquals(now + 60_000L, attempts.counter.lockedUntil)

        now += 59_999L
        assertTrue(rejection(vault, wrong) is VaultUnlockLockedOutException)

        // The PIN rule is a fixed duration: no doubling, so no cap to reach.
        now += 1L
        failTimes(vault, 1)
        assertEquals(VaultUnlockAttempts(4, now + 60_000L), attempts.counter)
        assertTrue(rejection(vault, right) is VaultUnlockLockedOutException)
    }

    @Test
    fun `a successful unlock resets the counter`() = runTest {
        val attempts = InMemoryAttemptStore()
        val vault = vault(attempts = attempts)
        vault.enrollPassphrase(right.passphrase)
        val max = attempts.thresholds.maxAttempts
        failTimes(vault, max - 1)

        vault.unlock(right)

        assertEquals(VaultUnlockAttempts(), attempts.counter)
        vault.lock()
        failTimes(vault, max - 1)
        vault.unlock(right)
        assertTrue(vault.isUnlocked())
    }

    @Test
    fun `a successful unlock after a lockout ends resets the counter`() = runTest {
        val attempts = InMemoryAttemptStore()
        val vault = vault(attempts = attempts)
        vault.enrollPassphrase(right.passphrase)
        failTimes(vault, attempts.thresholds.maxAttempts)

        now += attempts.thresholds.lockoutDurationSeconds * 1000L
        vault.unlock(right)

        assertEquals(VaultUnlockAttempts(), attempts.counter)
    }

    /**
     * The counter lives in the attempt store, not the vault: a new vault over
     * the same store keeps counting. The store here is in memory, so this
     * proves nothing about persistence; `PinSettingsVaultUnlockAttemptStoreTest`
     * reopens the real DataStore adapter from disk.
     */
    @Test
    fun `the counter outlives a vault instance in its attempt store`() = runTest {
        val dir = tmp.newFolder("vault")
        val attempts = InMemoryAttemptStore()
        val first = vault(FilePasswordVaultFactorStore(dir), attempts)
        first.enrollPassphrase(right.passphrase)
        failTimes(first, attempts.thresholds.maxAttempts - 1)

        val second = vault(FilePasswordVaultFactorStore(dir), attempts)
        failTimes(second, 1)

        val third = vault(FilePasswordVaultFactorStore(dir), attempts)
        assertTrue(rejection(third, right) is VaultUnlockLockedOutException)
    }
}
