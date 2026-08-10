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
package com.automatethethings.xkey.remote

import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * Unit tests for [RemoteKeyClient], the phone -> desktop `remote.*` JSON-RPC
 * client.
 *
 * The assertions deliberately pin the exact wire strings (method names and
 * parameter keys) because they are a contract with the Go side
 * (`go-xkms/xkey/pkg/pairing/protocol_remote.go`); a rename on either side is a
 * silent interop break, so these tests are the tripwire.
 *
 * The transport is a [ScriptedMessageSender] that parses the outbound request and
 * feeds a scripted reply straight back through a real
 * [BidirectionalMessageRouter], so id correlation is exercised end to end
 * without sockets. Returning `null` from the script models a peer that never
 * answers, which drives the timeout path under `runTest` virtual time.
 */
class RemoteKeyClientTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var client: RemoteKeyClient

    /** The single request the test scripted, for parameter assertions. */
    private val lastRequest: Request get() = sender.lastRequest
    private val lastParams: JSONObject get() = requireNotNull(lastRequest.params)

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        client = RemoteKeyClient(sender, router, requestTimeoutMs = 5_000L)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun succeedWith(resultJson: String) = sender.succeedWith(resultJson)

    private fun failWith(code: Int, message: String) = sender.failWith(code, message)

    private inline fun expectProtocolException(block: () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("expected a ProtocolException")
        throw IllegalStateException("unreachable")
    }

    // -------------------------------------------------------------------------
    // Request framing
    // -------------------------------------------------------------------------

    @Test
    fun `request ids start at one million and increment per request`() = runTest {
        succeedWith("""{"backends":[]}""")

        client.listBackends()
        client.listBackends()
        client.listBackends()

        assertEquals(listOf(1_000_000L, 1_000_001L, 1_000_002L), sender.sent.map { it.id })
    }

    @Test
    fun `listBackends sends remote_listBackends with no params`() = runTest {
        succeedWith(
            """{"backends":[
                 {"name":"tpm","type":"tpm2","hardwareBacked":true,"signing":true,
                  "decryption":false,"symmetricCrypto":false,"keyAgreement":true,
                  "attestation":true},
                 {"name":"soft","type":"software"}
               ]}"""
        )

        val backends = client.listBackends()

        assertEquals("remote.listBackends", lastRequest.method)
        assertNull("listBackends must omit params entirely", lastRequest.params)
        assertEquals(2, backends.size)
        assertEquals("tpm", backends[0].name)
        assertEquals("tpm2", backends[0].type)
        assertTrue(backends[0].hardwareBacked)
        assertTrue(backends[0].keyAgreement)
        assertFalse(backends[0].decryption)
        // Absent capability flags default to false rather than failing to parse.
        assertFalse(backends[1].hardwareBacked)
        assertFalse(backends[1].signing)
    }

    @Test
    fun `listKeys omits the algorithm filter when null`() = runTest {
        succeedWith("""{"keys":[]}""")

        client.listKeys(backend = "tpm2")

        assertEquals("remote.listKeys", lastRequest.method)
        assertEquals("tpm2", lastParams.getString("backend"))
        assertFalse("algorithm is omitempty on the Go side", lastParams.has("algorithm"))
        assertEquals(1, lastParams.length())
    }

    @Test
    fun `listKeys sends the algorithm filter and parses key info`() = runTest {
        succeedWith(
            """{"keys":[{"keyId":"k1","backend":"tpm2","algorithm":"ecdsa-p256",
                        "keySizeBits":256,"label":"signing","createdAt":1700000000}]}"""
        )

        val keys = client.listKeys(backend = "tpm2", algorithm = "ecdsa-p256")

        assertEquals("ecdsa-p256", lastParams.getString("algorithm"))
        assertEquals(1, keys.size)
        assertEquals("k1", keys[0].keyId)
        assertEquals(256, keys[0].keySizeBits)
        assertEquals("signing", keys[0].label)
        assertEquals(1_700_000_000L, keys[0].createdAt)
    }

    @Test
    fun `listKeys tolerates keys missing the optional fields`() = runTest {
        succeedWith("""{"keys":[{"keyId":"k1","backend":"tpm2","algorithm":"rsa-2048"}]}""")

        val keys = client.listKeys(backend = "tpm2")

        assertEquals(0, keys[0].keySizeBits)
        assertEquals("", keys[0].label)
        assertEquals(0L, keys[0].createdAt)
    }

    @Test
    fun `getPublicKey defaults to der format`() = runTest {
        succeedWith("""{"publicKey":"QUJD","format":"der","algorithm":"ecdsa-p256"}""")

        val result = client.getPublicKey(backend = "tpm2", keyId = "k1")

        assertEquals("remote.getPublicKey", lastRequest.method)
        assertEquals("tpm2", lastParams.getString("backend"))
        assertEquals("k1", lastParams.getString("keyId"))
        assertEquals("der", lastParams.getString("format"))
        assertEquals("QUJD", result.publicKey)
        assertEquals("ecdsa-p256", result.algorithm)
    }

    @Test
    fun `getPublicKey honours an explicit pem format`() = runTest {
        succeedWith("""{"publicKey":"-----BEGIN PUBLIC KEY-----","format":"pem","algorithm":"rsa-2048"}""")

        client.getPublicKey(backend = "soft", keyId = "k2", format = "pem")

        assertEquals("pem", lastParams.getString("format"))
    }

    @Test
    fun `sign omits the algorithm override when null`() = runTest {
        succeedWith("""{"signature":"c2ln","algorithm":"ECDSA_SHA256"}""")

        val result = client.sign(backend = "tpm2", keyId = "k1", data = "ZGF0YQ==")

        assertEquals("remote.sign", lastRequest.method)
        assertEquals("ZGF0YQ==", lastParams.getString("data"))
        assertFalse(lastParams.has("algorithm"))
        assertEquals("c2ln", result.signature)
        assertEquals("ECDSA_SHA256", result.algorithm)
    }

    @Test
    fun `sign sends the algorithm override when provided`() = runTest {
        succeedWith("""{"signature":"c2ln","algorithm":"RSA_PSS_SHA256"}""")

        client.sign(backend = "tpm2", keyId = "k1", data = "ZGF0YQ==", algorithm = "RSA_PSS_SHA256")

        assertEquals("RSA_PSS_SHA256", lastParams.getString("algorithm"))
        assertEquals(4, lastParams.length())
    }

    @Test
    fun `verify returns the valid flag from the peer`() = runTest {
        succeedWith("""{"valid":true}""")
        assertTrue(client.verify("tpm2", "k1", "ZGF0YQ==", "c2ln"))

        assertEquals("remote.verify", lastRequest.method)
        assertEquals("c2ln", lastParams.getString("signature"))

        succeedWith("""{"valid":false}""")
        assertFalse(client.verify("tpm2", "k1", "ZGF0YQ==", "c2ln"))
    }

    @Test
    fun `encrypt sends optional aad and algorithm only when set`() = runTest {
        succeedWith("""{"ciphertext":"Y3Q="}""")

        assertEquals("Y3Q=", client.encrypt("soft", "k1", plaintext = "cHQ="))
        assertEquals("remote.encrypt", lastRequest.method)
        assertEquals("cHQ=", lastParams.getString("plaintext"))
        assertEquals(3, lastParams.length())

        client.encrypt("soft", "k1", plaintext = "cHQ=", algorithm = "AES_GCM", aad = "YWFk")
        assertEquals("AES_GCM", lastParams.getString("algorithm"))
        assertEquals("YWFk", lastParams.getString("aad"))
        assertEquals(5, lastParams.length())
    }

    @Test
    fun `decrypt sends the ciphertext and returns the plaintext`() = runTest {
        succeedWith("""{"plaintext":"cHQ="}""")

        assertEquals("cHQ=", client.decrypt("soft", "k1", ciphertext = "Y3Q=", aad = "YWFk"))
        assertEquals("remote.decrypt", lastRequest.method)
        assertEquals("Y3Q=", lastParams.getString("ciphertext"))
        assertEquals("YWFk", lastParams.getString("aad"))
        assertFalse(lastParams.has("algorithm"))
    }

    @Test
    fun `deriveKey sends the peer public key and returns the shared secret`() = runTest {
        succeedWith("""{"sharedSecret":"c2VjcmV0"}""")

        val secret = client.deriveKey("tpm2", "k1", peerPublicKey = "cGVlcg==")

        assertEquals("remote.deriveKey", lastRequest.method)
        assertEquals("cGVlcg==", lastParams.getString("peerPublicKey"))
        assertEquals(3, lastParams.length())
        assertEquals("c2VjcmV0", secret)
    }

    @Test
    fun `generateKey omits keySizeBits when zero and label when null`() = runTest {
        succeedWith(
            """{"keyId":"k9","publicKey":"cHVi","algorithm":"ecdsa-p256",
                "keySizeBits":256,"backend":"tpm2"}"""
        )

        val result = client.generateKey(backend = "tpm2", keyId = "k9", algorithm = "ecdsa-p256")

        assertEquals("remote.generateKey", lastRequest.method)
        assertFalse(lastParams.has("keySizeBits"))
        assertFalse(lastParams.has("label"))
        assertEquals(3, lastParams.length())
        assertEquals("k9", result.keyId)
        assertEquals("cHVi", result.publicKey)
        assertEquals(256, result.keySizeBits)
    }

    @Test
    fun `generateKey sends keySizeBits and label when supplied`() = runTest {
        succeedWith("""{"keyId":"k9","algorithm":"rsa-2048","keySizeBits":2048,"backend":"soft"}""")

        val result = client.generateKey(
            backend = "soft", keyId = "k9", algorithm = "rsa-2048",
            keySizeBits = 2048, label = "my key"
        )

        assertEquals(2048, lastParams.getInt("keySizeBits"))
        assertEquals("my key", lastParams.getString("label"))
        assertNull("publicKey is nullable for non-exportable backends", result.publicKey)
    }

    @Test
    fun `getKeyInfo parses the full key description`() = runTest {
        succeedWith(
            """{"keyId":"k1","backend":"tpm2","algorithm":"ecdsa-p256","keySizeBits":256,
                "label":"idevid","createdAt":42,"hardwareBacked":true,"exportable":false}"""
        )

        val info = client.getKeyInfo("tpm2", "k1")

        assertEquals("remote.getKeyInfo", lastRequest.method)
        assertEquals(2, lastParams.length())
        assertTrue(info.hardwareBacked)
        assertFalse(info.exportable)
        assertEquals("idevid", info.label)
        assertEquals(42L, info.createdAt)
    }

    @Test
    fun `deleteKey returns the deleted flag`() = runTest {
        succeedWith("""{"deleted":true}""")
        assertTrue(client.deleteKey("tpm2", "k1"))
        assertEquals("remote.deleteKey", lastRequest.method)

        succeedWith("""{"deleted":false}""")
        assertFalse(client.deleteKey("tpm2", "k1"))
    }

    // -------------------------------------------------------------------------
    // Error, timeout and transport failures
    // -------------------------------------------------------------------------

    @Test
    fun `an error response becomes a ProtocolException carrying the peer code`() = runTest {
        failWith(ErrorCodes.KEY_NOT_FOUND, "no such key")

        val e = expectProtocolException { client.deleteKey("tpm2", "missing") }

        assertEquals(ErrorCodes.KEY_NOT_FOUND, e.errorCode)
        assertEquals("Remote error: no such key", e.message)
    }

    @Test
    fun `a silent peer times out with an internal error`() = runTest {
        sender.replyWith { null }

        val e = expectProtocolException { client.listBackends() }

        assertEquals(ErrorCodes.INTERNAL_ERROR, e.errorCode)
        assertEquals("Request timed out: remote.listBackends", e.message)
    }

    @Test
    fun `a timed-out request is unregistered so the client recovers`() = runTest {
        sender.replyWith { null }
        expectProtocolException { client.listBackends() }

        // A late reply for the abandoned id must not corrupt the next request.
        router.processMessage("""{"id":1000000,"result":{"backends":[]}}""".toByteArray())
        succeedWith("""{"backends":[{"name":"soft","type":"software"}]}""")

        assertEquals(1, client.listBackends().size)
        assertEquals(1_000_001L, lastRequest.id)
    }

    @Test
    fun `a transport failure propagates as-is`() = runTest {
        sender.replyWith { throw IOException("ble link down") }

        var thrown: Throwable? = null
        try {
            client.listBackends()
        } catch (e: IOException) {
            thrown = e
        }

        assertEquals("ble link down", thrown?.message)
    }

    @Test
    fun `connection loss resolves an in-flight request as an internal error`() = runTest {
        sender.replyWith { router.cancelAllPending(); null }

        val e = expectProtocolException { client.listBackends() }

        assertEquals(ErrorCodes.INTERNAL_ERROR, e.errorCode)
        assertEquals("Remote error: Connection lost", e.message)
    }

    // -------------------------------------------------------------------------
    // Key attestation verification
    // -------------------------------------------------------------------------

    private fun attestKeyResult(
        format: String = "tpm2",
        chain: String = """["$TEST_CERT_B64"]""",
        nonce: String = NONCE
    ) = """{"format":"$format","certificateChain":$chain,"nonce":"$nonce"}"""

    @Test
    fun `attestKey accepts a well-formed chain with an echoed nonce`() = runTest {
        succeedWith(attestKeyResult())

        val result = client.attestKey("tpm2", "k1", NONCE)

        assertEquals("remote.attestKey", lastRequest.method)
        assertEquals(NONCE, lastParams.getString("nonce"))
        assertEquals(3, lastParams.length())
        assertEquals("tpm2", result.format)
        assertEquals(1, result.certificateChain.size)
        assertNull(result.attestationData)
    }

    @Test
    fun `attestKey tolerates an unknown but non-empty format`() = runTest {
        // Forward compatibility: a new backend type must not break the phone.
        succeedWith(attestKeyResult(format = "yubihsm"))

        assertEquals("yubihsm", client.attestKey("tpm2", "k1", NONCE).format)
    }

    @Test
    fun `attestKey rejects a replayed or mismatched nonce`() = runTest {
        succeedWith(attestKeyResult(nonce = "b3RoZXItbm9uY2U="))

        val e = expectProtocolException { client.attestKey("tpm2", "k1", NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
        assertTrue(e.message!!.contains("nonce mismatch"))
    }

    @Test
    fun `attestKey rejects an empty certificate chain`() = runTest {
        succeedWith(attestKeyResult(chain = "[]"))

        val e = expectProtocolException { client.attestKey("tpm2", "k1", NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
        assertEquals("Attestation certificate chain is empty", e.message)
    }

    @Test
    fun `attestKey rejects an empty format`() = runTest {
        succeedWith(attestKeyResult(format = ""))

        val e = expectProtocolException { client.attestKey("tpm2", "k1", NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
        assertEquals("Attestation format is empty", e.message)
    }

    @Test
    fun `attestKey rejects a chain entry that is not valid base64`() = runTest {
        succeedWith(attestKeyResult(chain = """["$TEST_CERT_B64","!!!not-base64!!!"]"""))

        val e = expectProtocolException { client.attestKey("tpm2", "k1", NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
        assertTrue(
            "the failing index must be reported: ${e.message}",
            e.message!!.contains("index 1")
        )
    }

    @Test
    fun `attestKey rejects a chain entry that is not an X509 certificate`() = runTest {
        val notACert = java.util.Base64.getEncoder()
            .encodeToString("this is plainly not a DER certificate".toByteArray())
        succeedWith(attestKeyResult(chain = """["$notACert"]"""))

        val e = expectProtocolException { client.attestKey("tpm2", "k1", NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
    }

    // -------------------------------------------------------------------------
    // Device attestation verification
    // -------------------------------------------------------------------------

    @Test
    fun `attestDevice accepts a software-only laptop with no certificate chain`() = runTest {
        succeedWith(
            """{"format":"software","certificateChain":[],"securityLevel":"software",
                "nonce":"$NONCE","bootStateVerified":false}"""
        )

        val result = client.attestDevice(NONCE)

        assertEquals("remote.attestDevice", lastRequest.method)
        assertEquals(1, lastParams.length())
        assertEquals(NONCE, lastParams.getString("nonce"))
        assertEquals("software", result.securityLevel)
        assertTrue(result.certificateChain.isEmpty())
        assertFalse(result.bootStateVerified)
        assertNull(result.bootHashHex)
        assertNull(result.firmwareVersion)
    }

    @Test
    fun `attestDevice parses the hardware TPM fields`() = runTest {
        succeedWith(
            """{"format":"tpm2","certificateChain":["$TEST_CERT_B64"],"securityLevel":"hardware",
                "nonce":"$NONCE","bootHashHex":"ab12","bootStateVerified":true,
                "firmwareVersion":"7.2.1"}"""
        )

        val result = client.attestDevice(NONCE)

        assertEquals("hardware", result.securityLevel)
        assertEquals("ab12", result.bootHashHex)
        assertTrue(result.bootStateVerified)
        assertEquals("7.2.1", result.firmwareVersion)
    }

    @Test
    fun `attestDevice rejects a mismatched nonce`() = runTest {
        succeedWith(
            """{"format":"tpm2","securityLevel":"hardware","nonce":"b3RoZXI="}"""
        )

        val e = expectProtocolException { client.attestDevice(NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
        assertTrue(e.message!!.contains("Device attestation nonce mismatch"))
    }

    @Test
    fun `attestDevice rejects an explicitly empty format`() = runTest {
        succeedWith("""{"format":"","securityLevel":"hardware","nonce":"$NONCE"}""")

        val e = expectProtocolException { client.attestDevice(NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
        assertEquals("Device attestation format is empty", e.message)
    }

    @Test
    fun `attestDevice rejects an explicitly empty security level`() = runTest {
        succeedWith("""{"format":"tpm2","securityLevel":"","nonce":"$NONCE"}""")

        val e = expectProtocolException { client.attestDevice(NONCE) }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, e.errorCode)
        assertEquals("Device attestation security level is empty", e.message)
    }

    @Test
    fun `attestDevice fills defaults when format and security level are absent`() = runTest {
        // Documents current behaviour: a peer that omits these fields entirely
        // passes verification with the parser's fallbacks rather than being
        // rejected the way an explicit empty string would be.
        succeedWith("""{"nonce":"$NONCE"}""")

        val result = client.attestDevice(NONCE)

        assertEquals("unknown", result.format)
        assertEquals("software", result.securityLevel)
    }

    private companion object {
        /** Base64 nonce echoed back by the scripted peer. */
        const val NONCE = "AAECAwQFBgcICQoLDA0ODw=="

        /**
         * A real self-signed P-256 X.509 certificate (DER, base64) so the
         * certificate-parsing branch runs against genuine ASN.1 rather than a
         * stub. Valid until 2126, so it never expires the test suite.
         */
        const val TEST_CERT_B64 =
            "MIIBlzCCAT2gAwIBAgIUa7dyC68C+loNkjRl2ObjpoqPaeIwCgYIKoZIzj0EAwIwIDEeMBwGA1UE" +
                "AwwVeGtleS10ZXN0LWF0dGVzdGF0aW9uMCAXDTI2MDgwNDE3MzIxMVoYDzIxMjYwNzExMTczMjEx" +
                "WjAgMR4wHAYDVQQDDBV4a2V5LXRlc3QtYXR0ZXN0YXRpb24wWTATBgcqhkjOPQIBBggqhkjOPQMB" +
                "BwNCAARjknCWu53trpHuN0P50IiHFjLNKu2vTKueeQnV3PvVaZe/+ItshGBaPeJNyt71yGUEp/Zu" +
                "qBQWdzu6Nvr461Nyo1MwUTAdBgNVHQ4EFgQUIaADDAgqBqCh3alUo7UKCx9iJygwHwYDVR0jBBgw" +
                "FoAUIaADDAgqBqCh3alUo7UKCx9iJygwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF" +
                "AiEAgyiW6kWusYtA/2vL7azz04PiUqfHHbM3gjvfDw+fvgECIGlYmitwnnoYi0BeksCPjlpC034V" +
                "/QdkZ5F8cJpT75x4"
    }
}
