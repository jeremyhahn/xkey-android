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
 * Unit tests for the TCG-CSR-IDEVID enrollment payloads in `Messages.kt`:
 * `local.getTCGCSRIDevID`, `local.activateCredential`,
 * `local.getAttestationQuote`, `local.getIAKPublicKey` and
 * `local.storeEnrollmentCerts`.
 *
 * Counterpart: `go-xkms/xkey/pkg/pairing/protocol_attestation.go`. This family
 * carries TPM2 structures (TPM2B_ID_OBJECT, TPMS_ATTEST, TPMT_SIGNATURE, PCR
 * digests) that are opaque byte blobs on the wire, so the tests focus on the
 * base64 encode/decode round trip, the exact key names, the PCR map encoding
 * (integer indices become JSON object keys), and the required-vs-optional
 * behaviour of each parser.
 *
 * `android.util.Base64` is a throwing stub on the JVM, so it is statically
 * mocked and delegated to `java.util.Base64`.
 */
class TcgAttestationMessagesTest {

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
    // LocalGetTCGCSRIDevIDResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetTCGCSRIDevIDResult toJson emits the required keys and omits absent optionals`() {
        val json = LocalGetTCGCSRIDevIDResult(
            csr = "tcg-csr".toByteArray(),
            iakPublicKey = "iak".toByteArray(),
            idevidPublicKey = "idevid".toByteArray()
        ).toJson()

        assertEquals(setOf("csr", "iakPublicKey", "idevidPublicKey"), json.keySet())
        assertEquals(b64("tcg-csr"), json.getString("csr"))
        assertEquals(b64("iak"), json.getString("iakPublicKey"))
        assertEquals(b64("idevid"), json.getString("idevidPublicKey"))
    }

    @Test
    fun `LocalGetTCGCSRIDevIDResult toJson emits the EK certificate and platform metadata when present`() {
        val json = LocalGetTCGCSRIDevIDResult(
            csr = "tcg-csr".toByteArray(),
            ekCert = "ek".toByteArray(),
            iakPublicKey = "iak".toByteArray(),
            idevidPublicKey = "idevid".toByteArray(),
            platformSerial = "SN-1",
            platformModel = "Pixel 8",
            firmwareVersion = "7.2.1"
        ).toJson()

        assertEquals(
            setOf(
                "csr", "ekCert", "iakPublicKey", "idevidPublicKey",
                "platformSerial", "platformModel", "firmwareVersion"
            ),
            json.keySet()
        )
        assertEquals(b64("ek"), json.getString("ekCert"))
        assertEquals("Pixel 8", json.getString("platformModel"))
    }

    @Test
    fun `LocalGetTCGCSRIDevIDResult fromJson leaves an absent ekCert null`() {
        val result = LocalGetTCGCSRIDevIDResult.fromJson(
            JSONObject(
                """{"csr":"${b64("tcg-csr")}","iakPublicKey":"${b64("iak")}",
                    "idevidPublicKey":"${b64("idevid")}"}"""
            )
        )

        assertNull(result.ekCert)
        assertNull(result.platformSerial)
        assertNull(result.platformModel)
        assertNull(result.firmwareVersion)
        assertArrayEquals("tcg-csr".toByteArray(), result.csr)
    }

    @Test
    fun `LocalGetTCGCSRIDevIDResult fromJson raises when the csr is missing`() {
        assertThrowsAny {
            LocalGetTCGCSRIDevIDResult.fromJson(
                JSONObject("""{"iakPublicKey":"${b64("iak")}","idevidPublicKey":"${b64("id")}"}""")
            )
        }
    }

    @Test
    fun `LocalGetTCGCSRIDevIDResult round-trips including its ByteArray equality override`() {
        val original = LocalGetTCGCSRIDevIDResult(
            csr = "tcg-csr".toByteArray(),
            ekCert = "ek".toByteArray(),
            iakPublicKey = "iak".toByteArray(),
            idevidPublicKey = "idevid".toByteArray(),
            platformSerial = "SN-1",
            platformModel = "Pixel 8",
            firmwareVersion = "7.2.1"
        )

        val parsed = LocalGetTCGCSRIDevIDResult.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
    }

    @Test
    fun `LocalGetTCGCSRIDevIDResult equality compares key content not references`() {
        val a = LocalGetTCGCSRIDevIDResult("csr".toByteArray(), null, "iak".toByteArray(), "id".toByteArray())
        val b = LocalGetTCGCSRIDevIDResult("csr".toByteArray(), null, "iak".toByteArray(), "id".toByteArray())
        val different = LocalGetTCGCSRIDevIDResult("csr".toByteArray(), null, "other".toByteArray(), "id".toByteArray())

        assertEquals(a, b)
        assertFalse(a == different)
    }

    // -------------------------------------------------------------------------
    // LocalActivateCredentialParams / Result
    // -------------------------------------------------------------------------

    @Test
    fun `LocalActivateCredentialParams toJson emits exactly credentialBlob and encryptedSecret`() {
        val json = LocalActivateCredentialParams(
            credentialBlob = "blob".toByteArray(),
            encryptedSecret = "secret".toByteArray()
        ).toJson()

        assertEquals(setOf("credentialBlob", "encryptedSecret"), json.keySet())
        assertEquals(b64("blob"), json.getString("credentialBlob"))
        assertEquals(b64("secret"), json.getString("encryptedSecret"))
    }

    @Test
    fun `LocalActivateCredentialParams fromJson rejects a missing credentialBlob with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalActivateCredentialParams.fromJson(
                JSONObject("""{"encryptedSecret":"${b64("secret")}"}""")
            )
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("credentialBlob"))
    }

    @Test
    fun `LocalActivateCredentialParams fromJson rejects a missing encryptedSecret with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalActivateCredentialParams.fromJson(
                JSONObject("""{"credentialBlob":"${b64("blob")}"}""")
            )
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("encryptedSecret"))
    }

    @Test
    fun `LocalActivateCredentialParams round-trips including ByteArray equality`() {
        val original = LocalActivateCredentialParams("blob".toByteArray(), "secret".toByteArray())

        val parsed = LocalActivateCredentialParams.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
        assertArrayEquals("blob".toByteArray(), parsed.credentialBlob)
    }

    @Test
    fun `LocalActivateCredentialResult round-trips the decrypted secret`() {
        val original = LocalActivateCredentialResult("recovered".toByteArray())

        val json = original.toJson()
        val parsed = LocalActivateCredentialResult.fromJson(json)

        assertEquals(setOf("decryptedSecret"), json.keySet())
        assertEquals(b64("recovered"), json.getString("decryptedSecret"))
        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
    }

    @Test
    fun `LocalActivateCredentialResult equality compares secret content not references`() {
        assertEquals(
            LocalActivateCredentialResult("s".toByteArray()),
            LocalActivateCredentialResult("s".toByteArray())
        )
        assertFalse(
            LocalActivateCredentialResult("s".toByteArray()) ==
                LocalActivateCredentialResult("t".toByteArray())
        )
    }

    // -------------------------------------------------------------------------
    // LocalGetAttestationQuoteParams
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetAttestationQuoteParams toJson emits the nonce and the PCR index array`() {
        val json = LocalGetAttestationQuoteParams(
            nonce = "nonce".toByteArray(),
            pcrIndices = listOf(0, 1, 2, 3, 4, 5, 6, 7)
        ).toJson()

        assertEquals(setOf("nonce", "pcrIndices"), json.keySet())
        assertEquals(b64("nonce"), json.getString("nonce"))
        assertEquals(8, json.getJSONArray("pcrIndices").length())
        assertEquals(0, json.getJSONArray("pcrIndices").getInt(0))
        assertEquals(7, json.getJSONArray("pcrIndices").getInt(7))
    }

    @Test
    fun `LocalGetAttestationQuoteParams toJson emits the pcrBank when specified`() {
        val json = LocalGetAttestationQuoteParams("nonce".toByteArray(), listOf(0), "sha384").toJson()

        assertEquals(setOf("nonce", "pcrIndices", "pcrBank"), json.keySet())
        assertEquals("sha384", json.getString("pcrBank"))
    }

    @Test
    fun `LocalGetAttestationQuoteParams fromJson rejects a missing nonce with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalGetAttestationQuoteParams.fromJson(JSONObject("""{"pcrIndices":[0,1]}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("nonce"))
    }

    @Test
    fun `LocalGetAttestationQuoteParams fromJson rejects missing pcrIndices with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalGetAttestationQuoteParams.fromJson(JSONObject("""{"nonce":"${b64("n")}"}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("pcrIndices"))
    }

    @Test
    fun `LocalGetAttestationQuoteParams fromJson accepts an empty PCR selection`() {
        val params = LocalGetAttestationQuoteParams.fromJson(
            JSONObject("""{"nonce":"${b64("n")}","pcrIndices":[]}""")
        )

        assertTrue(params.pcrIndices.isEmpty())
        assertNull(params.pcrBank)
    }

    @Test
    fun `LocalGetAttestationQuoteParams round-trips a DRTM PCR selection`() {
        val original = LocalGetAttestationQuoteParams(
            nonce = "nonce".toByteArray(),
            pcrIndices = listOf(17, 18, 19, 20, 21, 22),
            pcrBank = "sha256"
        )

        val parsed = LocalGetAttestationQuoteParams.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
        assertEquals(listOf(17, 18, 19, 20, 21, 22), parsed.pcrIndices)
    }

    // -------------------------------------------------------------------------
    // LocalGetAttestationQuoteResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetAttestationQuoteResult toJson encodes pcrValues as an index-keyed object`() {
        val json = LocalGetAttestationQuoteResult(
            quoted = "quoted".toByteArray(),
            signature = "sig".toByteArray(),
            pcrValues = mapOf(0 to "pcr0".toByteArray(), 7 to "pcr7".toByteArray()),
            pcrBank = "sha256"
        ).toJson()

        assertEquals(setOf("quoted", "signature", "pcrValues", "pcrBank"), json.keySet())
        assertEquals(setOf("0", "7"), json.getJSONObject("pcrValues").keySet())
        assertEquals(b64("pcr0"), json.getJSONObject("pcrValues").getString("0"))
        assertEquals(b64("pcr7"), json.getJSONObject("pcrValues").getString("7"))
    }

    @Test
    fun `LocalGetAttestationQuoteResult toJson emits the event log when present`() {
        val json = LocalGetAttestationQuoteResult(
            quoted = "quoted".toByteArray(),
            signature = "sig".toByteArray(),
            pcrValues = emptyMap(),
            eventLog = "log".toByteArray(),
            pcrBank = "sha256"
        ).toJson()

        assertEquals(b64("log"), json.getString("eventLog"))
    }

    @Test
    fun `LocalGetAttestationQuoteResult fromJson decodes the pcrValues map back to integer keys`() {
        val result = LocalGetAttestationQuoteResult.fromJson(
            JSONObject(
                """{"quoted":"${b64("quoted")}","signature":"${b64("sig")}",
                    "pcrValues":{"0":"${b64("pcr0")}","23":"${b64("pcr23")}"},
                    "pcrBank":"sha256"}"""
            )
        )

        assertEquals(setOf(0, 23), result.pcrValues.keys)
        assertArrayEquals("pcr0".toByteArray(), result.pcrValues[0])
        assertArrayEquals("pcr23".toByteArray(), result.pcrValues[23])
        assertNull(result.eventLog)
    }

    @Test
    fun `LocalGetAttestationQuoteResult fromJson tolerates an absent pcrValues object`() {
        val result = LocalGetAttestationQuoteResult.fromJson(
            JSONObject(
                """{"quoted":"${b64("q")}","signature":"${b64("s")}","pcrBank":"sha256"}"""
            )
        )

        assertTrue(result.pcrValues.isEmpty())
    }

    @Test
    fun `LocalGetAttestationQuoteResult fromJson raises when quoted is missing`() {
        assertThrowsAny {
            LocalGetAttestationQuoteResult.fromJson(
                JSONObject("""{"signature":"${b64("s")}","pcrBank":"sha256"}""")
            )
        }
    }

    @Test
    fun `LocalGetAttestationQuoteResult round-trips including its ByteArray map equality`() {
        val original = LocalGetAttestationQuoteResult(
            quoted = "quoted".toByteArray(),
            signature = "sig".toByteArray(),
            pcrValues = mapOf(0 to "pcr0".toByteArray(), 7 to "pcr7".toByteArray()),
            eventLog = "log".toByteArray(),
            pcrBank = "sha256"
        )

        val parsed = LocalGetAttestationQuoteResult.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
    }

    @Test
    fun `LocalGetAttestationQuoteResult equality detects a differing PCR digest`() {
        val a = LocalGetAttestationQuoteResult(
            "q".toByteArray(), "s".toByteArray(), mapOf(0 to "x".toByteArray()), null, "sha256"
        )
        val b = LocalGetAttestationQuoteResult(
            "q".toByteArray(), "s".toByteArray(), mapOf(0 to "y".toByteArray()), null, "sha256"
        )

        assertFalse(a == b)
    }

    // -------------------------------------------------------------------------
    // LocalGetIAKPublicKeyResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetIAKPublicKeyResult toJson emits publicKey and algorithm and omits absent optionals`() {
        val json = LocalGetIAKPublicKeyResult(
            publicKey = "iak".toByteArray(),
            algorithm = "ECCP256"
        ).toJson()

        assertEquals(setOf("publicKey", "algorithm"), json.keySet())
        assertEquals(b64("iak"), json.getString("publicKey"))
        assertEquals("ECCP256", json.getString("algorithm"))
    }

    @Test
    fun `LocalGetIAKPublicKeyResult toJson emits publicKeyDer and the TPM2B_NAME when present`() {
        val json = LocalGetIAKPublicKeyResult(
            publicKey = "iak".toByteArray(),
            algorithm = "RSA2048",
            publicKeyDer = "spki".toByteArray(),
            name = "tpm-name".toByteArray()
        ).toJson()

        assertEquals(setOf("publicKey", "algorithm", "publicKeyDer", "name"), json.keySet())
        assertEquals(b64("spki"), json.getString("publicKeyDer"))
        assertEquals(b64("tpm-name"), json.getString("name"))
    }

    @Test
    fun `LocalGetIAKPublicKeyResult fromJson raises when the algorithm is missing`() {
        assertThrowsAny {
            LocalGetIAKPublicKeyResult.fromJson(JSONObject("""{"publicKey":"${b64("iak")}"}"""))
        }
    }

    @Test
    fun `LocalGetIAKPublicKeyResult round-trips including ByteArray equality`() {
        val original = LocalGetIAKPublicKeyResult(
            publicKey = "iak".toByteArray(),
            algorithm = "ECCP384",
            publicKeyDer = "spki".toByteArray(),
            name = "tpm-name".toByteArray()
        )

        val parsed = LocalGetIAKPublicKeyResult.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
    }

    @Test
    fun `LocalGetIAKPublicKeyResult fromJson leaves publicKeyDer and name null when absent`() {
        val result = LocalGetIAKPublicKeyResult.fromJson(
            JSONObject("""{"publicKey":"${b64("iak")}","algorithm":"ECCP256"}""")
        )

        assertNull(result.publicKeyDer)
        assertNull(result.name)
        assertArrayEquals("iak".toByteArray(), result.publicKey)
    }

    // -------------------------------------------------------------------------
    // LocalStoreEnrollmentCertsParams / Result
    // -------------------------------------------------------------------------

    @Test
    fun `LocalStoreEnrollmentCertsParams toJson emits both certificates and omits an absent chain`() {
        val json = LocalStoreEnrollmentCertsParams(
            iakCert = "iak-cert".toByteArray(),
            idevidCert = "idevid-cert".toByteArray()
        ).toJson()

        assertEquals(setOf("iakCert", "idevidCert"), json.keySet())
        assertEquals(b64("iak-cert"), json.getString("iakCert"))
        assertEquals(b64("idevid-cert"), json.getString("idevidCert"))
    }

    @Test
    fun `LocalStoreEnrollmentCertsParams toJson emits the intermediate chain when present`() {
        val json = LocalStoreEnrollmentCertsParams(
            iakCert = "iak-cert".toByteArray(),
            idevidCert = "idevid-cert".toByteArray(),
            chain = listOf("intermediate".toByteArray(), "root".toByteArray())
        ).toJson()

        assertEquals(setOf("iakCert", "idevidCert", "chain"), json.keySet())
        assertEquals(2, json.getJSONArray("chain").length())
        assertEquals(b64("intermediate"), json.getJSONArray("chain").getString(0))
    }

    @Test
    fun `LocalStoreEnrollmentCertsParams fromJson rejects a missing iakCert with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalStoreEnrollmentCertsParams.fromJson(
                JSONObject("""{"idevidCert":"${b64("idevid")}"}""")
            )
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("iakCert"))
    }

    @Test
    fun `LocalStoreEnrollmentCertsParams fromJson rejects a missing idevidCert with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalStoreEnrollmentCertsParams.fromJson(JSONObject("""{"iakCert":"${b64("iak")}"}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("idevidCert"))
    }

    @Test
    fun `LocalStoreEnrollmentCertsParams round-trips including ByteArray equality`() {
        val original = LocalStoreEnrollmentCertsParams(
            iakCert = "iak-cert".toByteArray(),
            idevidCert = "idevid-cert".toByteArray(),
            chain = listOf("intermediate".toByteArray(), "root".toByteArray())
        )

        val parsed = LocalStoreEnrollmentCertsParams.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
        assertEquals(2, parsed.chain!!.size)
    }

    @Test
    fun `LocalStoreEnrollmentCertsResult toJson reports success with both fingerprints`() {
        val json = LocalStoreEnrollmentCertsResult(
            stored = true,
            iakCertFingerprint = "aa11",
            idevidCertFingerprint = "bb22"
        ).toJson()

        assertEquals(setOf("stored", "iakCertFingerprint", "idevidCertFingerprint"), json.keySet())
        assertTrue(json.getBoolean("stored"))
        assertEquals("aa11", json.getString("iakCertFingerprint"))
        assertEquals("bb22", json.getString("idevidCertFingerprint"))
    }

    @Test
    fun `LocalStoreEnrollmentCertsResult toJson omits absent fingerprints`() {
        assertEquals(setOf("stored"), LocalStoreEnrollmentCertsResult(stored = false).toJson().keySet())
    }

    @Test
    fun `LocalStoreEnrollmentCertsResult fromJson raises when stored is missing`() {
        assertThrowsAny { LocalStoreEnrollmentCertsResult.fromJson(JSONObject("{}")) }
    }

    @Test
    fun `LocalStoreEnrollmentCertsResult round-trips through toJson and fromJson`() {
        val original = LocalStoreEnrollmentCertsResult(true, "aa11", "bb22")

        assertEquals(original, LocalStoreEnrollmentCertsResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun assertProtocolException(block: () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("Expected ProtocolException")
        throw IllegalStateException("unreachable")
    }

    private fun assertThrowsAny(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            return
        }
        fail("Expected an exception")
    }
}
