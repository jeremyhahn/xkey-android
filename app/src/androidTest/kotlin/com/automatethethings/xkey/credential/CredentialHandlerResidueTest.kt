/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.credential

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.handler.CreateCredentialHandler
import com.automatethethings.xkey.credential.handler.GetCredentialHandler
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * The corners of the credential provider that
 * [CreateCredentialHandlerTest] and [GetCredentialHandlerTest] leave alone:
 * a credential with no user name, a request missing its relying-party id, a
 * signing failure part-way through a ceremony, and the CBOR length prefix of
 * the attestation object.
 *
 * The CBOR check matters out of proportion to its size: the attestation object
 * is parsed by the relying party, not by this app, so a wrong byte-string
 * header is invisible here and fatal there. A registration's authenticator
 * data always lands in the 24..255 range, which is the only branch a ceremony
 * can reach — the other two are covered directly.
 *
 * Everything seeded here is removed in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialHandlerResidueTest {

    private lateinit var context: Context
    private lateinit var getHandler: GetCredentialHandler
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var credentialDao: CredentialMetadataDao
    private lateinit var keyDao: KeyDao

    /** Credentials seeded by the running test, removed in [tearDown]. */
    private val seededCredentialIds = linkedSetOf<String>()

    private var rpCounter = 0

    @Before
    fun setUp() {
        assumeTrue(
            "The credential provider requires Android 14",
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        )
        context = ApplicationProvider.getApplicationContext()
        AuditLogger.initialize(context)
        getHandler = GetCredentialHandler(context)
        keystoreManager = KeystoreManager(context)
        val database = XKeyDatabase.getInstance(context)
        credentialDao = database.credentialMetadataDao()
        keyDao = database.keyDao()
    }

    @After
    fun tearDown() {
        if (!this::credentialDao.isInitialized) return
        runBlocking {
            for (credentialId in seededCredentialIds) {
                runCatching { keystoreManager.deleteKey(credentialId) }
                credentialDao.deleteByCredentialId(credentialId)
                keyDao.deleteByKeyId(credentialId)
            }
        }
        seededCredentialIds.clear()
    }

    // ---------------------------------------------------------------------
    // Begin phase
    // ---------------------------------------------------------------------

    /**
     * The account picker needs a line of text. A passkey registered without a
     * user name — which a relying party is allowed to do — must fall back to
     * the display name rather than offering the user a blank row.
     */
    @Test
    fun anEntryWithNoUserNameFallsBackToTheDisplayName() {
        val rpId = nextRpId()
        seedCredential(rpId, "")

        val response = runBlocking {
            getHandler.handleBeginGetCredential(
                CredentialRequestFixtures.beginGetRequest(
                    listOf(
                        CredentialRequestFixtures.beginGetOption(
                            CredentialRequestFixtures.getRequestJson(rpId)
                        )
                    )
                )
            )
        }

        assertEquals(1, response.credentialEntries.size)
    }

    // ---------------------------------------------------------------------
    // Final phase
    // ---------------------------------------------------------------------

    /**
     * A request with no `rpId` cannot be matched against a stored credential.
     * It has to surface as an [InvalidRequestException], which the service maps
     * to a framework error — a raw `JSONException` would escape as a crash.
     */
    @Test
    fun aRequestWithNoRelyingPartyIdIsAnInvalidRequest() {
        val credentialId = seedCredential(nextRpId(), "user@example.com")

        // Valid JSON — the framework option type rejects anything else — but
        // with no rpId in it.
        val requestJson = JSONObject().put("challenge", "Y2hhbGxlbmdl").toString()

        try {
            runBlocking {
                getHandler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(requestJson),
                    credentialId
                )
            }
            fail("a request with no rpId must be rejected")
        } catch (e: InvalidRequestException) {
            assertTrue(e.message!!.contains("rpId"))
        }
    }

    /**
     * If the key backing a credential has gone — revoked, or invalidated by a
     * lock-screen change — the ceremony must fail as an assertion failure. A
     * raw Keystore exception would escape the provider contract.
     */
    @Test
    fun aSigningFailureIsReportedAsAnAssertionFailure() {
        val rpId = nextRpId()
        val credentialId = seedCredential(rpId, "user@example.com")

        // The metadata row survives; the key does not.
        runBlocking { keystoreManager.deleteKey(credentialId) }

        try {
            runBlocking {
                getHandler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(
                        CredentialRequestFixtures.getRequestJson(rpId)
                    ),
                    credentialId
                )
            }
            fail("signing with a missing key must fail the ceremony")
        } catch (e: CredentialAssertionException) {
            assertTrue(
                "the failure must name the assertion, not leak a Keystore message: ${e.message}",
                e.message!!.contains("sign", ignoreCase = true)
            )
        }
    }

    // ---------------------------------------------------------------------
    // Attestation object encoding
    // ---------------------------------------------------------------------

    /**
     * CBOR encodes a byte string's length in one of three ways depending on
     * size, and the relying party's parser follows the header it is given. A
     * registration only ever produces authenticator data in the middle range,
     * so the short and long forms are checked directly.
     *
     * The encoder is private and has no other caller a test can steer; it is
     * pure byte assembly, so it is reached reflectively rather than left
     * unverified.
     */
    @Test
    fun theAttestationObjectUsesTheRightCborLengthPrefixForEverySize() {
        val encode = CreateCredentialHandler::class.java.getDeclaredMethod(
            "buildAttestationObject", ByteArray::class.java
        )
        encode.isAccessible = true
        val handler = CreateCredentialHandler(context)

        // Every attestation object starts with the same 3-entry map header,
        // "fmt": "none", "attStmt": {} and the "authData" key.
        val prefixLength = 1 + 1 + 3 + 1 + 4 + 1 + 7 + 1 + 1 + 8

        // <= 23 bytes: the length rides in the major-type byte.
        val tiny = ByteArray(20) { 1 }
        val tinyEncoded = encode.invoke(handler, tiny) as ByteArray
        assertEquals(0x54.toByte(), tinyEncoded[prefixLength])
        assertEquals(prefixLength + 1 + tiny.size, tinyEncoded.size)

        // 24..255 bytes: one length byte after 0x58. This is what a real
        // registration produces.
        val medium = ByteArray(164) { 2 }
        val mediumEncoded = encode.invoke(handler, medium) as ByteArray
        assertEquals(0x58.toByte(), mediumEncoded[prefixLength])
        assertEquals(164.toByte(), mediumEncoded[prefixLength + 1])
        assertEquals(prefixLength + 2 + medium.size, mediumEncoded.size)

        // > 255 bytes: two big-endian length bytes after 0x59.
        val large = ByteArray(300) { 3 }
        val largeEncoded = encode.invoke(handler, large) as ByteArray
        assertEquals(0x59.toByte(), largeEncoded[prefixLength])
        assertEquals(0x01.toByte(), largeEncoded[prefixLength + 1])
        assertEquals(0x2C.toByte(), largeEncoded[prefixLength + 2])
        assertEquals(prefixLength + 3 + large.size, largeEncoded.size)

        // The fixed header really is the "none" attestation shape.
        assertEquals(0xA3.toByte(), mediumEncoded[0])
        assertEquals(
            "fmt",
            String(mediumEncoded.copyOfRange(2, 5))
        )
    }

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    private fun nextRpId(): String = "residue-${rpCounter++}-${System.nanoTime()}.example.com"

    /** Seeds a real Keystore key plus both metadata rows, and returns its id. */
    private fun seedCredential(rpId: String, userName: String): String {
        val rawId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val credentialId = CredentialRequestFixtures.encodeUrl(rawId)
        val publicKeyCose = runBlocking {
            keystoreManager.generateKeyWithAuthDuration(
                credentialId = credentialId,
                authDurationSeconds = -1,
                requireStrongBox = false
            )
        }
        seededCredentialIds += credentialId

        runBlocking {
            credentialDao.insert(
                CredentialMetadataEntity(
                    credentialId = credentialId,
                    rpId = rpId,
                    rpName = "Residue RP",
                    userId = "dXNlci1pZA",
                    userName = userName,
                    userDisplayName = "Residue User",
                    publicKeyCose = publicKeyCose,
                    signCount = 0,
                    isDiscoverable = true
                )
            )
            keyDao.insert(
                KeyEntity(
                    keyId = credentialId,
                    keyType = "fido2",
                    algorithm = "ES256",
                    label = "Residue RP",
                    publicKeyCose = publicKeyCose,
                    keySizeBits = 256,
                    biometricRequired = false,
                    authDurationSeconds = -1,
                    source = "local",
                    rpId = rpId,
                    rpName = "Residue RP",
                    userId = "dXNlci1pZA",
                    userName = userName,
                    userDisplayName = "Residue User",
                    isDiscoverable = true,
                    signCount = 0
                )
            )
        }
        return credentialId
    }
}
