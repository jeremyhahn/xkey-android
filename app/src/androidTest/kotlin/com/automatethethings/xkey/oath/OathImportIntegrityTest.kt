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
package com.automatethethings.xkey.oath

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for the two ways [OathRepository.importFromUri] used to
 * hand back a credential that looked fine and was not.
 *
 * **The secret was repaired rather than rejected.** The Base32 decoder folded
 * `0`, `1`, and `8` onto `O`, `L`, and `B` before decoding. Those digits are
 * not in the RFC 4648 alphabet, so the only thing the fold could do was turn a
 * corrupt secret into a different, silently wrong one: the import succeeded, the
 * credential rendered six plausible digits, and the mismatch surfaced at the
 * verifier — possibly weeks later, with no way for the user to tell a typo from
 * a broken app.
 *
 * **The HOTP counter arrived in a second write.** The credential was inserted at
 * counter 0 and only then advanced by an `UPDATE`. Anything failing between the
 * two left the credential permanently behind the server, which for HOTP means it
 * never authenticates again. The decisive check here uses a DAO that refuses
 * `updateCounter` outright, so the counter can only be correct if it was part of
 * the insert.
 *
 * The database is in-memory, so nothing touches the on-device credential table.
 * The real [OathSecretManager] is used because its Keystore key is an app-level
 * singleton rather than per-test state.
 */
@RunWith(AndroidJUnit4::class)
class OathImportIntegrityTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: OathCredentialDao
    private lateinit var secretManager: OathSecretManager
    private lateinit var repository: OathRepository

    /** RFC 4226 test seed "12345678901234567890" in Base32. */
    private val rfcSeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        dao = database.oathCredentialDao()
        secretManager = OathSecretManager()
        repository = OathRepository(dao, secretManager)
    }

    @After
    fun tearDown() {
        database.close()
    }

    /** The failure from importing [uri], or null when the import succeeded. */
    private fun importFailure(uri: String): Throwable? =
        runCatching { runBlocking { repository.importFromUri(uri) } }.exceptionOrNull()

    private fun storedSecret(oathId: String): ByteArray = runBlocking {
        secretManager.decryptSecret(dao.getByOathId(oathId)!!.secretEncrypted)
    }

    // -------------------------------------------------------------------------
    // A secret is never repaired
    // -------------------------------------------------------------------------

    @Test
    fun importFromUri_rejectsTheDigitsThatAreNotInTheBase32Alphabet() {
        val error = importFailure("otpauth://totp/user?secret=01813333")

        assertTrue("a digit outside the alphabet must fail the import", error is IllegalArgumentException)
        assertEquals("nothing may be stored from a rejected secret", 0, runBlocking { dao.count() })
    }

    @Test
    fun importFromUri_namesEveryCharacterItRejected() {
        val message = importFailure("otpauth://totp/user?secret=A0B1C8D!")!!.message!!

        for (offender in listOf("'0'", "'1'", "'8'", "'!'")) {
            assertTrue("the rejection must name $offender: $message", message.contains(offender))
        }
    }

    @Test
    fun importFromUri_namesEachOffendingCharacterOnce() {
        // Repeating a bad character is one mistake, not four.
        val message = importFailure("otpauth://totp/user?secret=A!!!AAAA")!!.message!!

        assertEquals("'!' should be named once: $message", 1, message.split("'!'").size - 1)
    }

    @Test
    fun importFromUri_saysWhichLetterAMistypedDigitProbablyMeant() {
        val message = importFailure("otpauth://totp/user?secret=0AAAAAAA")!!.message!!

        assertTrue(
            "a confusable digit should be explained, not silently substituted: $message",
            message.contains("'O' for '0'")
        )
    }

    @Test
    fun importFromUri_doesNotTurnAMistypedSecretIntoTheLetterSpelling() {
        // Under the old fold these two produced byte-identical credentials, so a
        // typo was indistinguishable from the secret the service issued.
        val spelled = runBlocking { repository.importFromUri("otpauth://totp/spelled?secret=OLBL3333") }

        assertTrue(importFailure("otpauth://totp/typo?secret=01813333") is IllegalArgumentException)
        assertEquals("only the valid spelling may be stored", 1, runBlocking { dao.count() })
        assertEquals("eight Base32 characters carry five whole bytes", 5, storedSecret(spelled).size)
    }

    @Test
    fun importFromUri_stillAcceptsTheFormattingThatIsNotKeyMaterial() {
        // Padding, spaces, hyphens, and case are presentation, not content:
        // rejecting a secret must not mean rejecting a readable one.
        val plain = runBlocking { repository.importFromUri("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP") }
        val decorated = runBlocking {
            repository.importFromUri("otpauth://totp/b?secret=jbsw-y3dp%20ehpk3pxp======")
        }

        assertTrue(storedSecret(plain).contentEquals(storedSecret(decorated)))
    }

    // -------------------------------------------------------------------------
    // The HOTP counter is part of the credential
    // -------------------------------------------------------------------------

    @Test
    fun importFromUri_storesTheHotpCounterInTheSameWriteAsTheCredential() = runBlocking {
        val strict = OathRepository(CounterUpdateForbiddenDao(dao), secretManager)

        val oathId = strict.importFromUri("otpauth://hotp/user?secret=$rfcSeedBase32&counter=42")

        assertEquals(
            "the counter must be persisted by the insert, not by a follow-up update",
            42L,
            dao.getByOathId(oathId)!!.counter
        )
    }

    @Test
    fun importFromUri_importsACounterlessHotpCredentialWithoutASecondWrite() = runBlocking {
        val strict = OathRepository(CounterUpdateForbiddenDao(dao), secretManager)

        val oathId = strict.importFromUri("otpauth://hotp/user?secret=$rfcSeedBase32")

        assertEquals(0L, dao.getByOathId(oathId)!!.counter)
    }

    @Test
    fun importFromUri_ignoresANegativeCounter() = runBlocking {
        val oathId = repository.importFromUri(
            "otpauth://hotp/user?secret=$rfcSeedBase32&counter=-5"
        )

        assertEquals(0L, dao.getByOathId(oathId)!!.counter)
    }

    @Test
    fun addCredential_persistsAnInitialCounter() = runBlocking {
        val strict = OathRepository(CounterUpdateForbiddenDao(dao), secretManager)

        val oathId = strict.addCredential(
            issuer = "Example",
            accountName = "counter@example.com",
            secret = "12345678901234567890".toByteArray(Charsets.US_ASCII),
            type = "HOTP",
            counter = 7L
        )

        assertEquals(7L, dao.getByOathId(oathId)!!.counter)
    }

    /**
     * A DAO that fails any attempt to advance a counter with a separate write.
     *
     * Everything else is delegated to the real DAO, so a test using it is
     * exercising the production persistence path minus the one call whose
     * absence is being proved.
     */
    private class CounterUpdateForbiddenDao(
        private val delegate: OathCredentialDao
    ) : OathCredentialDao by delegate {

        override suspend fun updateCounter(oathId: String, counter: Long) {
            throw AssertionError(
                "importFromUri must not need a second write to set the counter " +
                    "(oathId=$oathId, counter=$counter)"
            )
        }
    }
}
