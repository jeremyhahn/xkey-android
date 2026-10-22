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

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.settings.VaultUnlockAttempts
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/**
 * Instrumented regression for Codex review 6650 P1 (PasswordVaultTest.kt:364):
 * the vault lockout through [PinSettingsVaultUnlockAttemptStore] on the app's
 * real `Context` PIN settings DataStore.
 *
 * **CI does not run this test**: the runners have no device. The proof is the
 * JVM unit test `PinSettingsVaultUnlockAttemptStoreTest`, which closes and
 * reopens a file-backed DataStore between vaults. Here the `Context`
 * DataStore is a process-wide singleton that cannot be reopened within one
 * process, so each step opens a fresh [PinSettingsRepository], adapter and
 * vault on it, as a USB reconnect does.
 *
 * Red on an adapter that does not persist either counter field.
 *
 * The store belongs to the app, so the suite snapshots the device's real PIN
 * settings and vault counter and puts them back in teardown.
 */
@RunWith(AndroidJUnit4::class)
class PasswordVaultLockoutPersistenceTest {

    private lateinit var context: Context
    private lateinit var factorDir: File
    private lateinit var snapshot: PinSettingsData
    private lateinit var snapshotAttempts: VaultUnlockAttempts

    /** The fake clock, in epoch milliseconds. */
    private var now = 1_700_000_000_000L

    private var hashes = 0

    /** A counting SHA-256 stand-in for Argon2id: shows whether a credential was checked. */
    private val countingHasher = PassphraseHasher { passphrase, salt ->
        hashes++
        MessageDigest.getInstance("SHA-256").run {
            update(salt)
            digest(passphrase.toByteArray(Charsets.UTF_8))
        }
    }

    private val wrong = PasswordVaultCredential.Passphrase("tr0ub4dor")
    private val right = PasswordVaultCredential.Passphrase("correct horse battery staple")

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        factorDir = File(context.cacheDir, "vault-lockout-persistence-test").apply {
            deleteRecursively()
            mkdirs()
        }
        val repository = PinSettingsRepository(context)
        runBlocking {
            snapshot = repository.getSettings()
            snapshotAttempts = repository.getVaultUnlockAttempts()
            repository.clearSettings()
        }
    }

    @After
    fun tearDown() {
        val repository = PinSettingsRepository(context)
        runBlocking {
            repository.clearSettings()
            repository.updateSettings(snapshot)
            repository.updateVaultUnlockAttempts(snapshotAttempts)
        }
        factorDir.deleteRecursively()
    }

    private fun vault(attempts: VaultUnlockAttemptStore) =
        PasswordVault(FilePasswordVaultFactorStore(factorDir), attempts, countingHasher, clock = { now })

    private suspend fun rejection(vault: PasswordVault, credential: PasswordVaultCredential): Exception =
        try {
            vault.unlock(credential)
            throw AssertionError("expected the unlock to fail")
        } catch (e: PasswordVaultException) {
            e
        }

    @Test
    fun lockout_survivesFreshRepositoryAndVault_refusesRightPassphraseBeforeHashing() = runBlocking {
        val limits = PinSettingsData().let { VaultUnlockLimits(it.maxPinAttempts, it.lockoutDurationSeconds) }

        val first = vault(PinSettingsVaultUnlockAttemptStore(PinSettingsRepository(context)))
        first.enrollPassphrase(right.passphrase)
        repeat(limits.maxAttempts - 1) {
            assertTrue(rejection(first, wrong) is VaultCredentialRejectedException)
        }

        val secondRepository = PinSettingsRepository(context)
        assertEquals(
            "the failures are persisted",
            VaultUnlockAttempts(failedAttempts = limits.maxAttempts - 1, lockedUntil = 0),
            secondRepository.getVaultUnlockAttempts()
        )
        val second = vault(PinSettingsVaultUnlockAttemptStore(secondRepository))
        assertTrue(rejection(second, wrong) is VaultCredentialRejectedException)

        val lockedOut = VaultUnlockAttempts(
            failedAttempts = limits.maxAttempts,
            lockedUntil = now + limits.lockoutDurationSeconds * 1000L
        )
        val thirdRepository = PinSettingsRepository(context)
        assertEquals("both counter fields are persisted", lockedOut, thirdRepository.getVaultUnlockAttempts())
        val third = vault(PinSettingsVaultUnlockAttemptStore(thirdRepository))
        val hashesBefore = hashes

        val e = rejection(third, right)

        assertTrue("the refusal is the lockout, not a rejection", e is VaultUnlockLockedOutException)
        assertEquals("no Argon2id while locked out", hashesBefore, hashes)
        assertTrue(third.isLocked())
        assertEquals("a refusal is not counted", lockedOut, PinSettingsRepository(context).getVaultUnlockAttempts())
    }
}
