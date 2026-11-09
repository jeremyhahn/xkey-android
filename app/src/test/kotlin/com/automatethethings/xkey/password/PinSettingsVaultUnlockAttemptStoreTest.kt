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

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.settings.VaultUnlockAttempts
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * The vault's failed-unlock counter through the production adapter,
 * [PinSettingsVaultUnlockAttemptStore], on a real file-backed Preferences
 * DataStore: what a USB reconnect or an app restart reads back.
 *
 * DataStore Preferences core is plain JVM, so this runs in CI's unit tests.
 * Between vaults the DataStore and its scope are closed and a fresh
 * DataStore, [PinSettingsRepository], adapter and vault are opened on the
 * same file: the counter can only come back from disk.
 *
 * This is the one test that the unlock attempt counter survives a restart.
 */
class PinSettingsVaultUnlockAttemptStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** The fake clock, in epoch milliseconds. */
    private var now = 1_700_000_000_000L

    private var hashes = 0

    /** Argon2 is JNI-only; a counting SHA-256 stand-in shows whether a credential was checked. */
    private val countingHasher = PassphraseHasher { passphrase, salt ->
        hashes++
        MessageDigest.getInstance("SHA-256").run {
            update(salt)
            digest(passphrase.toByteArray(Charsets.UTF_8))
        }
    }

    private val wrong = PasswordVaultCredential.Passphrase("tr0ub4dor")
    private val right = PasswordVaultCredential.Passphrase("correct horse battery staple")

    /** One process's view of the PIN settings file: its own DataStore, scope, repository and adapter. */
    private class Opened(file: File) {
        private val job = Job()
        val repository = PinSettingsRepository(
            PreferenceDataStoreFactory.create(scope = CoroutineScope(Dispatchers.IO + job)) { file }
        )
        val attempts = PinSettingsVaultUnlockAttemptStore(repository)

        /** Closes the DataStore: its scope ends and the file is released. */
        suspend fun close() = job.cancelAndJoin()
    }

    private suspend fun <T> opened(file: File, block: suspend (Opened) -> T): T {
        val opened = Opened(file)
        try {
            return block(opened)
        } finally {
            opened.close()
        }
    }

    private fun vault(factorDir: File, attempts: VaultUnlockAttemptStore) =
        PasswordVault(FilePasswordVaultFactorStore(factorDir), attempts, countingHasher, clock = { now })

    private suspend fun rejection(vault: PasswordVault, credential: PasswordVaultCredential): Exception =
        try {
            vault.unlock(credential)
            throw AssertionError("expected the unlock to fail")
        } catch (e: PasswordVaultException) {
            e
        }

    /**
     * Regression (PasswordVaultTest.kt:364): the
     * lockout must survive a reopened PIN settings DataStore, so neither a
     * reconnect nor a restart resets the guessing limit.
     *
     * Red on an adapter that does not persist either counter field. Without
     * `failedAttempts` the failure after the first reopen counts as the first,
     * nothing locks, and the last vault hashes and accepts the right
     * passphrase; without `lockedUntil` the last vault does the same; either
     * way the read-back assertions also fail.
     */
    @Test
    fun `a lockout read back from a reopened DataStore refuses the right passphrase before hashing`() = runTest {
        val settings = File(tmp.newFolder("settings"), "pin_settings.preferences_pb")
        val factorDir = tmp.newFolder("vault")
        val limits = PinSettingsData().let { VaultUnlockLimits(it.maxPinAttempts, it.lockoutDurationSeconds) }

        opened(settings) { first ->
            val vault = vault(factorDir, first.attempts)
            vault.enrollPassphrase(right.passphrase)
            repeat(limits.maxAttempts - 1) {
                assertTrue(rejection(vault, wrong) is VaultCredentialRejectedException)
            }
        }

        opened(settings) { second ->
            assertEquals(
                "the failures come back from disk",
                VaultUnlockAttempts(failedAttempts = limits.maxAttempts - 1, lockedUntil = 0),
                second.repository.getVaultUnlockAttempts()
            )
            val vault = vault(factorDir, second.attempts)
            assertTrue(rejection(vault, wrong) is VaultCredentialRejectedException)
        }

        val lockedOut = VaultUnlockAttempts(
            failedAttempts = limits.maxAttempts,
            lockedUntil = now + limits.lockoutDurationSeconds * 1000L
        )
        opened(settings) { third ->
            assertEquals("both counter fields come back from disk", lockedOut, third.repository.getVaultUnlockAttempts())
            assertEquals(lockedOut, third.attempts.read())
            val vault = vault(factorDir, third.attempts)
            val hashesBefore = hashes

            val e = rejection(vault, right)

            assertTrue("the refusal is the lockout, not a rejection", e is VaultUnlockLockedOutException)
            assertEquals("no Argon2id while locked out", hashesBefore, hashes)
            assertTrue(vault.isLocked())
        }

        opened(settings) { fourth ->
            assertEquals("a refusal is not counted", lockedOut, fourth.repository.getVaultUnlockAttempts())
        }
    }
}
