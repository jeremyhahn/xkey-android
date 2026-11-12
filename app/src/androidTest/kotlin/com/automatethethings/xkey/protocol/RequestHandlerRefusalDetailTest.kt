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

package com.automatethethings.xkey.protocol

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicLong

/**
 * Refusals that only differ from an already-covered refusal in *which* branch
 * produced them.
 *
 * Each case here is a request the desktop can genuinely send and that the
 * handler has a dedicated arm for, but where an existing suite only ever
 * reaches the first arm of the same construct: the DER export failure is
 * covered while the PEM, OpenSSH and COSE ones are not; the odd-length hash is
 * covered while the even-length non-hex one is not. The arms are worth pinning
 * separately because they are the ones that decide the error *code*, and the
 * desktop branches on that code.
 *
 * Nothing here needs a prompt, a paired peer or a live transport.
 *
 * Every key is per-run and removed in [tearDown]. The PIV slot used is only
 * ever probed with input that fails before the slot is touched, so no slot
 * state is created.
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerRefusalDetailTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        /**
         * A PIV slot this suite only ever probes with input that is rejected
         * before the slot is read or written. Deliberately not 9a, which other
         * suites assert on.
         */
        private const val PROBE_SLOT = "9c"

        private val nextRequestId = AtomicLong(1)

        /** Every key id this suite persists, torn down in [tearDown]. */
        private val createdKeyIds = mutableSetOf<String>()

        @JvmStatic
        @BeforeClass
        fun setUp() {
            context = ApplicationProvider.getApplicationContext()
            handler = RequestHandler(
                context = context,
                keystoreManager = KeystoreManager(context),
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager(),
                pivKeyManager = PivKeyManager(XKeyDatabase.getInstance(context).pivSlotDao())
            )
        }

        @JvmStatic
        @AfterClass
        fun tearDown() {
            runBlocking {
                val db = XKeyDatabase.getInstance(context)
                val keystoreManager = KeystoreManager(context)

                val ids = createdKeyIds.toMutableSet()
                for (entity in db.keyDao().getAll()) {
                    if (entity.keyId.contains(runId)) ids.add(entity.keyId)
                }
                for (keyId in ids) {
                    runCatching { keystoreManager.deleteGeneralKey(keyId) }
                    runCatching { db.keyDao().deleteByKeyId(keyId) }
                    runCatching { db.auditLogDao().deleteByKeyId(keyId) }
                }
            }
        }
    }

    @Before
    fun resetHandlerState() {
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    // ------------------------------------------------------------------
    // Public-key export: every format has its own failure arm
    // ------------------------------------------------------------------

    /**
     * A symmetric key is a legitimate entry in the key store with no public
     * half at all. Each export format asks the key store a different question
     * and has its own "nothing to export" arm, so each must report
     * EXPORT_FAILED rather than fall through to a generic internal error or,
     * worse, return an empty string the desktop would treat as a key.
     */
    @Test
    fun everyExportFormatRefusesAKeyWithNoPublicHalf() {
        val keyId = generateSymmetricKey("no-public-half-$runId")

        for (format in listOf("der", "pem", "ssh", "cose")) {
            val response = call(
                "local.getPublicKey",
                JSONObject().put("keyId", keyId).put("format", format)
            )
            assertEquals(
                "format $format must report an export failure",
                ErrorCodes.EXPORT_FAILED,
                response.errorCode()
            )
        }
    }

    /**
     * The COSE arm reports a different reason from the other three, because a
     * COSE_Key is a different structure rather than a different encoding of
     * the same DER.
     */
    @Test
    fun theCoseExportFailureNamesTheCoseStructure() {
        val keyId = generateSymmetricKey("cose-reason-$runId")

        val response = call(
            "local.getPublicKey",
            JSONObject().put("keyId", keyId).put("format", "cose")
        )

        assertTrue(
            "expected the COSE-specific reason, got: ${response.errorMessage()}",
            response.errorMessage().contains("COSE")
        )
    }

    // ------------------------------------------------------------------
    // Payloads that are not the encoding they claim to be
    // ------------------------------------------------------------------

    /**
     * The phone never inspects a backup blob, but it does have to decode the
     * transport encoding. A truncated payload -- one whose final base64 group
     * carries a single character, and so encodes no whole byte -- must come
     * back as an error frame rather than propagate a decoder exception.
     */
    @Test
    fun createBackupRejectsAPayloadThatIsNotBase64() {
        val response = call(
            "local.createBackup",
            JSONObject().put("backup_data", "AAAAA")
        )

        assertTrue("a bad payload must produce an error frame", response.isError())
        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
    }

    /**
     * Same shape on the PIV side: the slot and the certificate are validated
     * separately, and a certificate that is not base64 must be refused after
     * the slot has been accepted, as a bad parameter rather than a crash (#173).
     */
    @Test
    fun importingAPivCertificateThatIsNotBase64IsRejected() {
        val response = call(
            "local.pivImportCert",
            JSONObject()
                .put("slot", PROBE_SLOT)
                .put("certificate_der", "!!! not base64 !!!")
        )

        assertTrue(response.isError())
        assertEquals(ErrorCodes.INVALID_PARAMS, response.errorCode())
    }

    /**
     * A co-signing request carries its digest as hex. An odd-length string is
     * already refused on length alone; an even-length string of non-hex
     * characters is the dangerous one, because `Character.digit` returns -1
     * rather than failing and the digest would otherwise be signed as garbage.
     * The key has to exist, or the request is refused before the digest is
     * ever decoded.
     */
    @Test
    fun cosignRejectsAnEvenLengthHashThatIsNotHexadecimal() {
        val keyId = generateSigningKey("cosign-hex-$runId")

        val response = call(
            "cosign.request",
            JSONObject()
                .put("hash", "zzzzzzzzzzzzzzzz")
                .put("keyId", keyId)
        )

        assertTrue("a non-hex digest must never be signed", response.isError())
        assertTrue(
            "the refusal must point at the offending character, got: ${response.errorMessage()}",
            response.errorMessage().contains("non-hex")
        )
    }

    /**
     * The same request with a well-formed digest of the same length succeeds,
     * which is what makes the refusal above attributable to the characters
     * rather than to the length or the key.
     */
    @Test
    fun cosignAcceptsTheSameLengthDigestWhenItIsActuallyHexadecimal() {
        val keyId = generateSigningKey("cosign-ok-$runId")

        val response = call(
            "cosign.request",
            JSONObject()
                .put("hash", "0123456789abcdef")
                .put("keyId", keyId)
        )

        assertTrue(
            "a well-formed digest must be co-signed: " + response.toJsonString(),
            response.isSuccess()
        )
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** An EC signing key, so a co-sign request has something to sign with. */
    private fun generateSigningKey(keyId: String): String {
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertTrue(
            "key generation must succeed: " + response.toJsonString(),
            response.isSuccess()
        )
        return keyId
    }

    /** An AES key: a real key-store row with no public half to export. */
    private fun generateSymmetricKey(keyId: String): String {
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "secret")
                .put("algorithm", "AES-256-GCM")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertTrue(
            "key generation must succeed: " + response.toJsonString(),
            response.isSuccess()
        )
        return keyId
    }

    private fun call(method: String, params: JSONObject): Response =
        dispatch(method, params)

    /**
     * Written without default arguments on purpose: a function that carries a
     * default argument and also builds a coroutine lambda has repeatedly
     * crashed the Kotlin JVM backend in these suites.
     */
    private fun dispatch(method: String, params: JSONObject?): Response {
        val request = Request(nextRequestId.getAndIncrement(), method, params)
        return runBlocking { handler.handleRequest(request) }
    }

    private fun Response.errorCode(): Int =
        error?.code ?: throw AssertionError("expected an error response, got: " + toJsonString())

    private fun Response.errorMessage(): String =
        error?.message ?: throw AssertionError("expected an error response, got: " + toJsonString())
}
