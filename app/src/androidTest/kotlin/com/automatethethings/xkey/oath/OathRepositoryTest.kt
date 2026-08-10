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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [OathRepository].
 *
 * The repository's `otpauth://` importer is the entry point for every QR code a
 * user scans, and it is built on `android.net.Uri`, so it can only be proved on
 * a device — a JVM test would be testing a mock of the parser rather than the
 * parser. The Base32 decoder behind it is likewise reachable only through an
 * imported URI, and it is the piece most likely to silently produce a credential
 * that generates wrong codes forever: a mis-decoded secret still yields six
 * plausible digits.
 *
 * The database is always **in-memory**, so nothing touches the shared on-device
 * `oath_credentials` table. The real [OathSecretManager] is used, since its
 * Keystore key is an app-level singleton that is created on first use and
 * shared with the running app rather than being per-test state.
 */
@RunWith(AndroidJUnit4::class)
class OathRepositoryTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: OathCredentialDao
    private lateinit var secretManager: OathSecretManager
    private lateinit var repository: OathRepository

    /** RFC 4226 test seed "12345678901234567890" in Base32. */
    private val rfcSeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    private val rfcSeed = "12345678901234567890".toByteArray(Charsets.US_ASCII)

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

    /** The plaintext secret behind a stored credential. */
    private fun storedSecret(oathId: String): ByteArray = runBlocking {
        secretManager.decryptSecret(dao.getByOathId(oathId)!!.secretEncrypted)
    }

    // -------------------------------------------------------------------------
    // addCredential
    // -------------------------------------------------------------------------

    @Test
    fun addCredential_persistsTheCredentialUnderAFreshId() = runBlocking {
        val id = repository.addCredential("GitHub", "user@example.com", rfcSeed)

        val stored = dao.getByOathId(id)!!
        assertEquals("GitHub", stored.issuer)
        assertEquals("user@example.com", stored.accountName)
        assertEquals("TOTP", stored.oathType)
        assertEquals("SHA1", stored.algorithm)
        assertEquals(6, stored.digits)
        assertEquals(30, stored.periodSeconds)
        assertEquals(0L, stored.counter)
        assertEquals("local", stored.source)
    }

    @Test
    fun addCredential_generatesADistinctIdEachTime() = runBlocking {
        val first = repository.addCredential("GitHub", "a@example.com", rfcSeed)
        val second = repository.addCredential("GitHub", "b@example.com", rfcSeed)

        assertNotEquals(first, second)
        assertEquals(2, dao.count())
    }

    @Test
    fun addCredential_normalisesTypeAndAlgorithmToUpperCase() = runBlocking {
        val id = repository.addCredential(
            issuer = "Example",
            accountName = "user",
            secret = rfcSeed,
            type = "hotp",
            algorithm = "sha256"
        )

        val stored = dao.getByOathId(id)!!
        assertEquals("HOTP", stored.oathType)
        assertEquals("SHA256", stored.algorithm)
    }

    @Test
    fun addCredential_encryptsTheSecretBeforeStoringIt() = runBlocking {
        val id = repository.addCredential(null, "user", rfcSeed)

        val persisted = dao.getByOathId(id)!!.secretEncrypted
        assertFalse(
            "the raw OATH secret must never reach the database",
            persisted.contentEquals(rfcSeed)
        )
        assertTrue(storedSecret(id).contentEquals(rfcSeed))
    }

    @Test
    fun addCredential_acceptsANullIssuer() = runBlocking {
        val id = repository.addCredential(null, "user@example.com", rfcSeed)

        assertNull(dao.getByOathId(id)!!.issuer)
    }

    @Test
    fun addCredential_stampsACreationTime() = runBlocking {
        val before = System.currentTimeMillis()
        val id = repository.addCredential("Example", "user", rfcSeed)
        val after = System.currentTimeMillis()

        assertTrue(dao.getByOathId(id)!!.createdAt in before..after)
    }

    // -------------------------------------------------------------------------
    // importFromUri: happy paths
    // -------------------------------------------------------------------------

    @Test
    fun importFromUri_readsEveryParameterOfAFullTotpUri() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://totp/GitHub:user@example.com" +
                "?secret=$rfcSeedBase32&issuer=GitHub&algorithm=SHA256&digits=8&period=60"
        )

        val stored = dao.getByOathId(id)!!
        assertEquals("TOTP", stored.oathType)
        assertEquals("GitHub", stored.issuer)
        assertEquals("user@example.com", stored.accountName)
        assertEquals("SHA256", stored.algorithm)
        assertEquals(8, stored.digits)
        assertEquals(60, stored.periodSeconds)
        assertTrue(storedSecret(id).contentEquals(rfcSeed))
    }

    @Test
    fun importFromUri_appliesTheRfcDefaultsWhenOptionalParametersAreAbsent() = runBlocking {
        val id = repository.importFromUri("otpauth://totp/user@example.com?secret=$rfcSeedBase32")

        val stored = dao.getByOathId(id)!!
        assertEquals("SHA1", stored.algorithm)
        assertEquals(6, stored.digits)
        assertEquals(30, stored.periodSeconds)
        assertNull(stored.issuer)
        assertEquals("user@example.com", stored.accountName)
    }

    @Test
    fun importFromUri_prefersTheIssuerParameterOverTheLabelPrefix() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://totp/LabelIssuer:user@example.com?secret=$rfcSeedBase32&issuer=QueryIssuer"
        )

        assertEquals("QueryIssuer", dao.getByOathId(id)!!.issuer)
    }

    @Test
    fun importFromUri_fallsBackToTheLabelPrefixForTheIssuer() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://totp/LabelIssuer:user@example.com?secret=$rfcSeedBase32"
        )

        assertEquals("LabelIssuer", dao.getByOathId(id)!!.issuer)
    }

    @Test
    fun importFromUri_trimsWhitespaceAroundTheLabelParts() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://totp/%20Spaced%20:%20user@example.com%20?secret=$rfcSeedBase32"
        )

        val stored = dao.getByOathId(id)!!
        assertEquals("Spaced", stored.issuer)
        assertEquals("user@example.com", stored.accountName)
    }

    @Test
    fun importFromUri_treatsAnEmptyLabelIssuerAsAbsent() = runBlocking {
        val id = repository.importFromUri("otpauth://totp/:user@example.com?secret=$rfcSeedBase32")

        assertNull(dao.getByOathId(id)!!.issuer)
        assertEquals("user@example.com", dao.getByOathId(id)!!.accountName)
    }

    @Test
    fun importFromUri_decodesAPercentEncodedLabel() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://totp/Big%20Corp:first.last%40example.com?secret=$rfcSeedBase32"
        )

        val stored = dao.getByOathId(id)!!
        assertEquals("Big Corp", stored.issuer)
        assertEquals("first.last@example.com", stored.accountName)
    }

    @Test
    fun importFromUri_acceptsAnUpperCaseSchemeHost() = runBlocking {
        val id = repository.importFromUri("otpauth://TOTP/user?secret=$rfcSeedBase32")

        assertEquals("TOTP", dao.getByOathId(id)!!.oathType)
    }

    @Test
    fun importFromUri_ignoresUnparseableDigitsAndPeriodRatherThanFailing() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://totp/user?secret=$rfcSeedBase32&digits=six&period=half-a-minute"
        )

        val stored = dao.getByOathId(id)!!
        assertEquals(6, stored.digits)
        assertEquals(30, stored.periodSeconds)
    }

    // -------------------------------------------------------------------------
    // importFromUri: HOTP counter
    // -------------------------------------------------------------------------

    @Test
    fun importFromUri_seedsTheHotpCounterFromTheUri() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://hotp/user?secret=$rfcSeedBase32&counter=42"
        )

        val stored = dao.getByOathId(id)!!
        assertEquals("HOTP", stored.oathType)
        assertEquals(42L, stored.counter)
    }

    @Test
    fun importFromUri_leavesTheHotpCounterAtZeroWhenTheUriOmitsIt() = runBlocking {
        val id = repository.importFromUri("otpauth://hotp/user?secret=$rfcSeedBase32")

        assertEquals(0L, dao.getByOathId(id)!!.counter)
    }

    @Test
    fun importFromUri_ignoresAnUnparseableCounter() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://hotp/user?secret=$rfcSeedBase32&counter=lots"
        )

        assertEquals(0L, dao.getByOathId(id)!!.counter)
    }

    @Test
    fun importFromUri_doesNotApplyACounterToATotpCredential() = runBlocking {
        val id = repository.importFromUri(
            "otpauth://totp/user?secret=$rfcSeedBase32&counter=99"
        )

        assertEquals(0L, dao.getByOathId(id)!!.counter)
    }

    // -------------------------------------------------------------------------
    // importFromUri: Base32 handling
    // -------------------------------------------------------------------------

    @Test
    fun importFromUri_decodesTheBase32SecretExactly() = runBlocking {
        // "JBSWY3DPEHPK3PXP" is the canonical Google Authenticator sample secret.
        val id = repository.importFromUri("otpauth://totp/user?secret=JBSWY3DPEHPK3PXP")

        assertTrue(
            storedSecret(id).contentEquals(
                byteArrayOf(
                    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde.toByte(),
                    0xad.toByte(), 0xbe.toByte(), 0xef.toByte()
                )
            )
        )
    }

    @Test
    fun importFromUri_acceptsALowerCaseSecret() = runBlocking {
        val upper = repository.importFromUri("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP")
        val lower = repository.importFromUri("otpauth://totp/b?secret=jbswy3dpehpk3pxp")

        assertTrue(storedSecret(upper).contentEquals(storedSecret(lower)))
    }

    @Test
    fun importFromUri_stripsPaddingSpacesAndHyphensFromTheSecret() = runBlocking {
        val plain = repository.importFromUri("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP")
        val decorated = repository.importFromUri(
            "otpauth://totp/b?secret=JBSW-Y3DP%20EHPK3PXP======"
        )

        assertTrue(storedSecret(plain).contentEquals(storedSecret(decorated)))
    }

    /**
     * 0/1/8 used to be folded onto O/L/B so a hand-typed secret "still worked".
     * They are not in the RFC 4648 alphabet, so that silently turned a corrupt
     * secret into a valid-looking credential that generates wrong codes forever,
     * with nothing on the phone to diagnose. It is refused now, and the message
     * names the offending characters.
     */
    @Test
    fun importFromUri_refusesTheDigitsThatLookLikeLetters() {
        val error = runCatching {
            runBlocking { repository.importFromUri("otpauth://totp/a?secret=01813333") }
        }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        val message = error!!.message!!
        assertTrue("should name the offenders, was: $message", message.contains("'0'"))
        assertTrue("should name the offenders, was: $message", message.contains("'1'"))
        assertTrue("should name the offenders, was: $message", message.contains("'8'"))
    }

    @Test
    fun importFromUri_rejectsASecretOutsideTheBase32Alphabet() {
        val error = runCatching {
            runBlocking { repository.importFromUri("otpauth://totp/user?secret=NOT!VALID") }
        }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        assertTrue(error!!.message!!.contains("Invalid Base32 character"))
    }

    @Test
    fun importFromUri_decodesASecretWhoseLengthIsNotAWholeNumberOfBytes() = runBlocking {
        // 4 Base32 characters carry 20 bits, which yields 2 whole bytes; the
        // trailing 4 bits are discarded rather than emitted as a partial byte.
        val id = repository.importFromUri("otpauth://totp/user?secret=MZXW")

        assertEquals(2, storedSecret(id).size)
    }

    // -------------------------------------------------------------------------
    // importFromUri: rejections
    // -------------------------------------------------------------------------

    private fun importFailure(uri: String): IllegalArgumentException {
        val error = runCatching { runBlocking { repository.importFromUri(uri) } }.exceptionOrNull()
        assertTrue("expected a rejection for $uri, got $error", error is IllegalArgumentException)
        return error as IllegalArgumentException
    }

    @Test
    fun importFromUri_rejectsAForeignScheme() {
        val error = importFailure("https://example.com/totp/user?secret=$rfcSeedBase32")

        assertTrue(error.message!!.contains("Invalid URI scheme"))
    }

    @Test
    fun importFromUri_rejectsAnUnknownOtpType() {
        val error = importFailure("otpauth://ocra/user?secret=$rfcSeedBase32")

        assertTrue(error.message!!.contains("Invalid OTP type"))
    }

    @Test
    fun importFromUri_rejectsAMissingSecret() {
        val error = importFailure("otpauth://totp/user?issuer=GitHub")

        assertTrue(error.message!!.contains("Missing required 'secret'"))
    }

    @Test
    fun importFromUri_rejectsABlankSecret() {
        importFailure("otpauth://totp/user?secret=")
    }

    @Test
    fun importFromUri_storesNothingWhenItRejectsAUri() = runBlocking {
        runCatching { repository.importFromUri("otpauth://ocra/user?secret=$rfcSeedBase32") }

        assertEquals(0, dao.count())
    }

    // -------------------------------------------------------------------------
    // generateCode
    // -------------------------------------------------------------------------

    @Test
    fun generateCode_producesTheRfcTotpValueForTheStoredCredential() = runBlocking {
        val id = repository.addCredential("Example", "user", rfcSeed)

        val now = System.currentTimeMillis()
        val code = repository.generateCode(id)

        assertEquals(6, code.length)
        assertTrue(code.all { it.isDigit() })
        // The call reads the clock itself, so accept this window or the next in
        // case a period boundary fell between the two reads.
        assertTrue(
            code == OathEngine.generateTotpCode(rfcSeed, "SHA1", 6, 30, now) ||
                code == OathEngine.generateTotpCode(rfcSeed, "SHA1", 6, 30, now + 30_000L)
        )
    }

    @Test
    fun generateCode_producesTheRfcHotpValueAtTheStoredCounter() = runBlocking {
        val id = repository.addCredential("Example", "user", rfcSeed, type = "HOTP")

        assertEquals("755224", repository.generateCode(id))
    }

    @Test
    fun generateCode_advancesTheHotpCounterSoTheNextCodeDiffers() = runBlocking {
        val id = repository.addCredential("Example", "user", rfcSeed, type = "HOTP")

        assertEquals("755224", repository.generateCode(id))
        assertEquals(1L, dao.getByOathId(id)!!.counter)
        assertEquals("287082", repository.generateCode(id))
        assertEquals(2L, dao.getByOathId(id)!!.counter)
    }

    @Test
    fun generateCode_leavesATotpCounterAlone() = runBlocking {
        val id = repository.addCredential("Example", "user", rfcSeed)

        repository.generateCode(id)

        assertEquals(0L, dao.getByOathId(id)!!.counter)
    }

    @Test
    fun generateCode_recordsTheUsage() = runBlocking {
        val id = repository.addCredential("Example", "user", rfcSeed)

        val before = System.currentTimeMillis()
        repository.generateCode(id)
        repository.generateCode(id)
        val after = System.currentTimeMillis()

        val stored = dao.getByOathId(id)!!
        assertEquals(2, stored.useCount)
        assertTrue(stored.lastUsedAt!! in before..after)
    }

    @Test
    fun generateCode_honoursTheStoredDigitsAndAlgorithm() = runBlocking {
        val id = repository.addCredential(
            issuer = "Example",
            accountName = "user",
            secret = rfcSeed,
            type = "HOTP",
            algorithm = "SHA256",
            digits = 8
        )

        val code = repository.generateCode(id)

        assertEquals(8, code.length)
        assertEquals(OathEngine.generateHotpCode(rfcSeed, 0L, "SHA256", 8), code)
    }

    @Test
    fun generateCode_failsForAnUnknownCredential() {
        val error = runCatching {
            runBlocking { repository.generateCode("not-a-real-id") }
        }.exceptionOrNull()

        assertTrue(error is NoSuchElementException)
    }

    @Test
    fun generateCode_failsForACredentialWithAnUnrecognisedType() = runBlocking {
        dao.insert(
            OathCredentialEntity(
                oathId = "weird",
                oathType = "OCRA",
                algorithm = "SHA1",
                issuer = null,
                accountName = "user",
                secretEncrypted = secretManager.encryptSecret(rfcSeed),
                createdAt = System.currentTimeMillis()
            )
        )

        val error = runCatching { runBlocking { repository.generateCode("weird") } }
            .exceptionOrNull()

        assertTrue(error is IllegalStateException)
    }

    // -------------------------------------------------------------------------
    // observeAll
    // -------------------------------------------------------------------------

    @Test
    fun observeAll_pairsEachCredentialWithItsCurrentCode() = runBlocking {
        repository.addCredential("GitHub", "user", rfcSeed)

        val observed = repository.observeAll().first().single()

        assertEquals("GitHub", observed.credential.issuer)
        assertEquals(6, observed.code.length)
        assertTrue(observed.secondsRemaining in 1..30)
    }

    @Test
    fun observeAll_reportsNoExpiryForHotp() = runBlocking {
        repository.addCredential("Example", "user", rfcSeed, type = "HOTP")

        val observed = repository.observeAll().first().single()

        assertEquals(0, observed.secondsRemaining)
        assertEquals("755224", observed.code)
    }

    @Test
    fun observeAll_doesNotAdvanceTheHotpCounter() = runBlocking {
        val id = repository.addCredential("Example", "user", rfcSeed, type = "HOTP")

        repository.observeAll().first()

        assertEquals(0L, dao.getByOathId(id)!!.counter)
    }

    @Test
    fun observeAll_rendersPlaceholderDigitsForAnUnrecognisedType() = runBlocking {
        dao.insert(
            OathCredentialEntity(
                oathId = "weird",
                oathType = "OCRA",
                algorithm = "SHA1",
                issuer = null,
                accountName = "user",
                secretEncrypted = secretManager.encryptSecret(rfcSeed),
                createdAt = System.currentTimeMillis()
            )
        )

        assertEquals("------", repository.observeAll().first().single().code)
    }

    @Test
    fun observeAll_isEmptyForAnEmptyStore() = runBlocking {
        assertTrue(repository.observeAll().first().isEmpty())
    }

    @Test
    fun observeAll_ordersByIssuerThenAccount() = runBlocking {
        repository.addCredential("Zulu", "user", rfcSeed)
        repository.addCredential("Alpha", "b@example.com", rfcSeed)
        repository.addCredential("Alpha", "a@example.com", rfcSeed)

        val issuersAndAccounts = repository.observeAll().first()
            .map { it.credential.issuer to it.credential.accountName }

        assertEquals(
            listOf(
                "Alpha" to "a@example.com",
                "Alpha" to "b@example.com",
                "Zulu" to "user"
            ),
            issuersAndAccounts
        )
    }

    // -------------------------------------------------------------------------
    // delete and sync export
    // -------------------------------------------------------------------------

    @Test
    fun deleteCredential_removesOnlyTheNamedCredential() = runBlocking {
        val kept = repository.addCredential("Keep", "user", rfcSeed)
        val removed = repository.addCredential("Remove", "user", rfcSeed)

        repository.deleteCredential(removed)

        assertNull(dao.getByOathId(removed))
        assertEquals(kept, dao.getByOathId(kept)!!.oathId)
        assertEquals(1, dao.count())
    }

    @Test
    fun deleteCredential_isSilentForAnUnknownId() = runBlocking {
        repository.addCredential("Keep", "user", rfcSeed)

        repository.deleteCredential("not-a-real-id")

        assertEquals(1, dao.count())
    }

    @Test
    fun getCredentialsForSync_returnsOnlyLocallyCreatedCredentials() = runBlocking {
        val local = repository.addCredential("Local", "user", rfcSeed)
        dao.insert(
            OathCredentialEntity(
                oathId = "from-desktop",
                oathType = "TOTP",
                algorithm = "SHA1",
                issuer = "Remote",
                accountName = "user",
                secretEncrypted = secretManager.encryptSecret(rfcSeed),
                source = "remote",
                remoteDeviceId = "desktop-1",
                createdAt = System.currentTimeMillis()
            )
        )

        val forSync = repository.getCredentialsForSync()

        assertEquals(listOf(local), forSync.map { it.oathId })
    }

    @Test
    fun getCredentialsForSync_isEmptyWhenEverythingCameFromElsewhere() = runBlocking {
        dao.insert(
            OathCredentialEntity(
                oathId = "from-desktop",
                oathType = "TOTP",
                algorithm = "SHA1",
                issuer = "Remote",
                accountName = "user",
                secretEncrypted = secretManager.encryptSecret(rfcSeed),
                source = "remote",
                createdAt = System.currentTimeMillis()
            )
        )

        assertTrue(repository.getCredentialsForSync().isEmpty())
    }
}
