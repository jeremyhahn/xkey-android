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
package com.automatethethings.xkey.protocol

import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Pins the wire shape of the `remote.*` enrollment payloads, the direction in
 * which this phone is the Certificate Authority and the desktop is the enrollee.
 *
 * Counterparts are `RemoteGetTCGCSRIDevIDResult`, `RemoteActivateCredential*`,
 * `RemoteGetAttestationQuote*` and `RemoteStoreEnrollmentCerts*` in
 * `go-xkms/xkey/pkg/pairing/protocol_remote.go` and `protocol_attestation.go`.
 * No code is shared across the two languages, so a key renamed on either side
 * does not fail — it deserializes to a zero value and the ceremony silently
 * verifies nothing. These tests assert the exact key names for that reason.
 *
 * `android.util.Base64` throws on the JVM, so it is mocked onto `java.util.Base64`.
 */
class RemoteEnrollmentMessagesTest {

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    private fun b64(text: String): String =
        java.util.Base64.getEncoder().encodeToString(text.toByteArray())

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg())
        }
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // Method names
    // -------------------------------------------------------------------------

    @Test
    fun `the ceremony uses the remote namespace the desktop bridge routes`() {
        assertEquals("remote.getTCGCSRIDevID", MethodNames.REMOTE_GET_TCG_CSR_IDEVID)
        assertEquals("remote.activateCredential", MethodNames.REMOTE_ACTIVATE_CREDENTIAL)
        assertEquals("remote.getAttestationQuote", MethodNames.REMOTE_GET_ATTESTATION_QUOTE)
        assertEquals("remote.storeEnrollmentCerts", MethodNames.REMOTE_STORE_ENROLLMENT_CERTS)
    }

    // -------------------------------------------------------------------------
    // remote.getTCGCSRIDevID
    // -------------------------------------------------------------------------

    @Test
    fun `getTCGCSRIDevID params omit the backend so the desktop applies its default`() {
        assertEquals(emptySet<String>(), RemoteGetTCGCSRIDevIDParams().toJson().keySet())
        assertEquals(setOf("backend"), RemoteGetTCGCSRIDevIDParams("tpm2").toJson().keySet())
    }

    @Test
    fun `getTCGCSRIDevID result parses every field the bridge sends`() {
        val json = JSONObject()
            .put("csr", b64("packed-csr"))
            .put("ekCert", b64("ek-der"))
            .put("iakPublicKey", b64("iak-public-area"))
            .put("idevidPublicKey", b64("idevid-public-area"))
            .put("platformManufacturer", "IFX")
            .put("platformModel", "XPS 15 9520")
            .put("platformSerial", "SN-1")

        val result = RemoteGetTCGCSRIDevIDResult.fromJson(json)

        assertArrayEquals("packed-csr".toByteArray(), result.csr)
        assertArrayEquals("ek-der".toByteArray(), result.ekCert)
        assertArrayEquals("iak-public-area".toByteArray(), result.iakPublicKey)
        assertArrayEquals("idevid-public-area".toByteArray(), result.idevidPublicKey)
        assertEquals("IFX", result.platformManufacturer)
        assertEquals("XPS 15 9520", result.platformModel)
        assertEquals("SN-1", result.platformSerial)
    }

    @Test
    fun `getTCGCSRIDevID result tolerates a TPM with no EK certificate`() {
        val result = RemoteGetTCGCSRIDevIDResult.fromJson(
            JSONObject()
                .put("csr", b64("packed-csr"))
                .put("iakPublicKey", b64("iak"))
                .put("idevidPublicKey", b64("idevid"))
        )
        assertNull(result.ekCert)
        assertEquals("", result.platformModel)
    }

    @Test
    fun `getTCGCSRIDevID result refuses a package with no CSR`() {
        try {
            RemoteGetTCGCSRIDevIDResult.fromJson(
                JSONObject()
                    .put("iakPublicKey", b64("iak"))
                    .put("idevidPublicKey", b64("idevid"))
            )
            fail("a result with no CSR must not parse")
        } catch (e: ProtocolException) {
            assertTrue(e.message!!.contains("csr"))
        }
    }

    @Test
    fun `getTCGCSRIDevID result round trips`() {
        val original = RemoteGetTCGCSRIDevIDResult(
            csr = "csr".toByteArray(),
            ekCert = "ek".toByteArray(),
            iakPublicKey = "iak".toByteArray(),
            idevidPublicKey = "idevid".toByteArray(),
            platformManufacturer = "IFX",
            platformModel = "model",
            platformSerial = "serial"
        )
        assertEquals(original, RemoteGetTCGCSRIDevIDResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // remote.activateCredential
    // -------------------------------------------------------------------------

    @Test
    fun `activateCredential params carry the challenge under the bridge's key names`() {
        val json = RemoteActivateCredentialParams(
            credentialBlob = "blob".toByteArray(),
            encryptedSecret = "secret".toByteArray()
        ).toJson()

        assertEquals(setOf("credentialBlob", "encryptedSecret"), json.keySet())
        assertEquals(b64("blob"), json.getString("credentialBlob"))
        assertEquals(b64("secret"), json.getString("encryptedSecret"))
    }

    @Test
    fun `activateCredential params round trip with an explicit backend`() {
        val original = RemoteActivateCredentialParams(
            credentialBlob = "blob".toByteArray(),
            encryptedSecret = "secret".toByteArray(),
            backend = "tpm2"
        )
        assertEquals(original, RemoteActivateCredentialParams.fromJson(original.toJson()))
    }

    @Test
    fun `activateCredential params refuse a challenge missing a half`() {
        try {
            RemoteActivateCredentialParams.fromJson(
                JSONObject().put("credentialBlob", b64("blob"))
            )
            fail("a challenge with no encrypted secret must not parse")
        } catch (e: ProtocolException) {
            assertTrue(e.message!!.contains("encryptedSecret"))
        }
    }

    @Test
    fun `activateCredential result reads the decrypted secret`() {
        val result = RemoteActivateCredentialResult.fromJson(
            JSONObject().put("decryptedSecret", b64("recovered"))
        )
        assertArrayEquals("recovered".toByteArray(), result.decryptedSecret)
    }

    @Test
    fun `activateCredential result refuses a reply with no secret`() {
        try {
            RemoteActivateCredentialResult.fromJson(JSONObject().put("stored", true))
            fail("a reply with no secret must not parse as an activation")
        } catch (e: ProtocolException) {
            assertTrue(e.message!!.contains("decryptedSecret"))
        }
    }

    // -------------------------------------------------------------------------
    // remote.getAttestationQuote
    // -------------------------------------------------------------------------

    @Test
    fun `getAttestationQuote params emit the nonce, indices and bank`() {
        val json = RemoteGetAttestationQuoteParams(
            nonce = "nonce".toByteArray(),
            pcrIndices = listOf(0, 1, 2, 3, 4, 5, 6, 7),
            pcrBank = "sha256"
        ).toJson()

        assertEquals(setOf("nonce", "pcrIndices", "pcrBank"), json.keySet())
        assertEquals(b64("nonce"), json.getString("nonce"))
        assertEquals(8, json.getJSONArray("pcrIndices").length())
        assertEquals(7, json.getJSONArray("pcrIndices").getInt(7))
    }

    @Test
    fun `getAttestationQuote params omit an unset bank`() {
        val json = RemoteGetAttestationQuoteParams(
            nonce = "nonce".toByteArray(),
            pcrIndices = listOf(0)
        ).toJson()
        assertFalse(json.has("pcrBank"))
        assertFalse(json.has("backend"))
    }

    @Test
    fun `getAttestationQuote result keys PCR values by index`() {
        val json = JSONObject()
            .put("quoted", b64("tpms-attest"))
            .put("signature", b64("iak-signature"))
            .put(
                "pcrValues",
                JSONObject().put("0", b64("pcr0")).put("7", b64("pcr7"))
            )
            .put("pcrBank", "sha256")
            .put("nonce", b64("nonce"))

        val result = RemoteGetAttestationQuoteResult.fromJson(json)

        assertArrayEquals("tpms-attest".toByteArray(), result.quoted)
        assertArrayEquals("iak-signature".toByteArray(), result.signature)
        assertArrayEquals("nonce".toByteArray(), result.nonce)
        assertEquals("sha256", result.pcrBank)
        assertEquals(setOf(0, 7), result.pcrValues.keys)
        assertArrayEquals("pcr7".toByteArray(), result.pcrValues[7])
    }

    @Test
    fun `getAttestationQuote result refuses a reply that echoes no nonce`() {
        try {
            RemoteGetAttestationQuoteResult.fromJson(
                JSONObject()
                    .put("quoted", b64("q"))
                    .put("signature", b64("s"))
                    .put("pcrBank", "sha256")
            )
            fail("a quote with no nonce must not parse; freshness cannot be checked")
        } catch (e: ProtocolException) {
            assertTrue(e.message!!.contains("nonce"))
        }
    }

    @Test
    fun `getAttestationQuote result round trips`() {
        val original = RemoteGetAttestationQuoteResult(
            quoted = "q".toByteArray(),
            signature = "s".toByteArray(),
            pcrValues = mapOf(0 to "a".toByteArray(), 4 to "b".toByteArray()),
            pcrBank = "sha256",
            nonce = "n".toByteArray()
        )
        assertEquals(original, RemoteGetAttestationQuoteResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // remote.storeEnrollmentCerts
    // -------------------------------------------------------------------------

    @Test
    fun `storeEnrollmentCerts params emit both leaves and the chain`() {
        val json = RemoteStoreEnrollmentCertsParams(
            iakCert = "iak-cert".toByteArray(),
            idevidCert = "idevid-cert".toByteArray(),
            chain = listOf("intermediate".toByteArray(), "root".toByteArray())
        ).toJson()

        assertEquals(setOf("iakCert", "idevidCert", "chain"), json.keySet())
        assertEquals(2, json.getJSONArray("chain").length())
        assertEquals(b64("root"), json.getJSONArray("chain").getString(1))
    }

    @Test
    fun `storeEnrollmentCerts params omit an absent chain`() {
        val json = RemoteStoreEnrollmentCertsParams(
            iakCert = "iak".toByteArray(),
            idevidCert = "idevid".toByteArray()
        ).toJson()
        assertEquals(setOf("iakCert", "idevidCert"), json.keySet())
    }

    @Test
    fun `storeEnrollmentCerts params refuse a request missing a certificate`() {
        try {
            RemoteStoreEnrollmentCertsParams.fromJson(
                JSONObject().put("iakCert", b64("iak"))
            )
            fail("a request with no IDevID certificate must not parse")
        } catch (e: ProtocolException) {
            assertTrue(e.message!!.contains("idevidCert"))
        }
    }

    @Test
    fun `storeEnrollmentCerts result reads the fingerprints the desktop reports`() {
        val result = RemoteStoreEnrollmentCertsResult.fromJson(
            JSONObject()
                .put("stored", true)
                .put("iakCertFingerprint", "aa")
                .put("idevidCertFingerprint", "bb")
        )
        assertTrue(result.stored)
        assertEquals("aa", result.iakCertFingerprint)
        assertEquals("bb", result.idevidCertFingerprint)
    }

    @Test
    fun `storeEnrollmentCerts result treats an absent stored flag as not stored`() {
        val result = RemoteStoreEnrollmentCertsResult.fromJson(JSONObject())
        assertFalse(result.stored)
        assertNull(result.iakCertFingerprint)
    }
}
