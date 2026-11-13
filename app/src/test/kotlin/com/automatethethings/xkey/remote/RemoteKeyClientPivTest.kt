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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * Unit tests for the phone -> desktop PIV methods of [RemoteKeyClient].
 *
 * The wire strings are pinned against go-xkms tag `xkey/v0.64.2-alpha`,
 * `pkg/pairingproto/protocol_piv.go`: `RemotePIVListSlotsParams{backend,omitempty}`,
 * `RemotePIVListSlotsResult{slots}`, `PIVSlotInfo{slot, label,omitempty,
 * algorithm,omitempty, has_key, has_certificate, cert_subject,omitempty,
 * cert_expiry,omitempty}`, `RemotePIVGetCertParams{slot, backend,omitempty}`,
 * `RemotePIVGetCertResult{certificate_der, subject,omitempty, issuer,omitempty,
 * expiry,omitempty}`, `RemotePIVSignParams{slot, data, algorithm,omitempty,
 * backend,omitempty}` and `RemotePIVSignResult{signature, algorithm}`. Go
 * `[]byte` fields travel as standard base64.
 */
class RemoteKeyClientPivTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var client: RemoteKeyClient

    private val lastRequest: Request get() = sender.lastRequest
    private val lastParams: JSONObject get() = requireNotNull(lastRequest.params)

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    private val b64 = Base64.getEncoder()

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

    private inline fun expectProtocolException(block: () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("expected a ProtocolException")
        throw IllegalStateException("unreachable")
    }

    private inline fun expectMalformed(block: () -> Unit) {
        val e = expectProtocolException(block)
        assertEquals(ErrorCodes.PARSE_ERROR, e.errorCode)
    }

    // -------------------------------------------------------------------------
    // remote.pivListSlots
    // -------------------------------------------------------------------------

    @Test
    fun `pivListSlots sends no params when no backend is named`() = runTest {
        sender.succeedWith("""{"slots":[]}""")

        val slots = client.pivListSlots()

        assertEquals("remote.pivListSlots", lastRequest.method)
        assertNull("backend is omitempty and the desktop accepts no params", lastRequest.params)
        assertTrue(slots.isEmpty())
    }

    @Test
    fun `pivListSlots sends the backend when named`() = runTest {
        sender.succeedWith("""{"slots":[]}""")

        client.pivListSlots(backend = "tpm2")

        assertEquals(setOf("backend"), lastParams.keySet())
        assertEquals("tpm2", lastParams.getString("backend"))
    }

    @Test
    fun `pivListSlots parses every PIVSlotInfo field`() = runTest {
        sender.succeedWith(
            """{"slots":[
                 {"slot":"9a","label":"PIV Authentication","algorithm":"ECDSA-P256",
                  "has_key":true,"has_certificate":true,"cert_subject":"alice",
                  "cert_expiry":"2027-01-02T03:04:05Z"},
                 {"slot":"9c","has_key":false,"has_certificate":false}
               ]}"""
        )

        val slots = client.pivListSlots()

        assertEquals(2, slots.size)
        val auth = slots[0]
        assertEquals("9a", auth.slot)
        assertEquals("PIV Authentication", auth.label)
        assertEquals("ECDSA-P256", auth.algorithm)
        assertTrue(auth.hasKey)
        assertTrue(auth.hasCertificate)
        assertEquals("alice", auth.certSubject)
        assertEquals("2027-01-02T03:04:05Z", auth.certExpiry)
        val sig = slots[1]
        assertEquals("9c", sig.slot)
        assertNull(sig.label)
        assertNull(sig.algorithm)
        assertFalse(sig.hasKey)
        assertFalse(sig.hasCertificate)
        assertNull(sig.certSubject)
        assertNull(sig.certExpiry)
    }

    @Test
    fun `pivListSlots reads a Go nil slice as no slots`() = runTest {
        sender.succeedWith("""{"slots":null}""")

        assertTrue(client.pivListSlots().isEmpty())
    }

    @Test
    fun `pivListSlots rejects a reply without slots`() = runTest {
        sender.succeedWith("""{}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots rejects slots that is not an array`() = runTest {
        sender.succeedWith("""{"slots":"9a"}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots rejects a slot entry without has_key`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":"9a","has_certificate":false}]}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots rejects a has_key that is not a boolean`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":"9a","has_key":"true","has_certificate":false}]}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots rejects an empty slot id`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":"","has_key":false,"has_certificate":false}]}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots rejects a whitespace-only slot id`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":" ","has_key":false,"has_certificate":false}]}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots rejects a tab and newline slot id`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":"\t\n","has_key":false,"has_certificate":false}]}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots keeps a valid slot id verbatim and lowercase`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":"9a","has_key":false,"has_certificate":false}]}""")
        assertEquals("9a", client.pivListSlots().single().slot)
    }

    @Test
    fun `pivListSlots rejects a numeric label`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":"9a","label":7,"has_key":false,"has_certificate":false}]}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots rejects a slot entry that is not an object`() = runTest {
        sender.succeedWith("""{"slots":["9a"]}""")
        expectMalformed { client.pivListSlots() }
    }

    @Test
    fun `pivListSlots passes the desktop error code through`() = runTest {
        sender.failWith(ErrorCodes.PIV_SLOT_NOT_FOUND, "no storage")

        val e = expectProtocolException { client.pivListSlots() }

        assertEquals(ErrorCodes.PIV_SLOT_NOT_FOUND, e.errorCode)
    }

    // -------------------------------------------------------------------------
    // remote.pivGetCert
    // -------------------------------------------------------------------------

    @Test
    fun `pivGetCert sends only the slot when no backend is named`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64"}""")

        val cert = client.pivGetCert("9a")

        assertEquals("remote.pivGetCert", lastRequest.method)
        assertEquals(setOf("slot"), lastParams.keySet())
        assertEquals("9a", lastParams.getString("slot"))
        assertArrayEquals(Base64.getDecoder().decode(TEST_CERT_B64), cert.certificateDer)
        assertNull(cert.subject)
        assertNull(cert.issuer)
        assertNull(cert.expiry)
    }

    @Test
    fun `pivGetCert sends the backend and parses the optional fields`() = runTest {
        sender.succeedWith(
            """{"certificate_der":"$TEST_CERT_B64","subject":"CN=alice",
                "issuer":"CN=ca","expiry":"2126-07-11T17:32:11Z"}"""
        )

        val cert = client.pivGetCert("9c", backend = "pkcs11")

        assertEquals(setOf("slot", "backend"), lastParams.keySet())
        assertEquals("pkcs11", lastParams.getString("backend"))
        assertEquals("CN=alice", cert.subject)
        assertEquals("CN=ca", cert.issuer)
        assertEquals("2126-07-11T17:32:11Z", cert.expiry)
    }

    @Test
    fun `pivGetCert rejects a reply without certificate_der`() = runTest {
        sender.succeedWith("""{"subject":"CN=alice"}""")
        expectMalformed { client.pivGetCert("9a") }
    }

    @Test
    fun `pivGetCert rejects certificate_der that is not base64`() = runTest {
        sender.succeedWith("""{"certificate_der":"not base64!"}""")
        expectMalformed { client.pivGetCert("9a") }
    }

    @Test
    fun `pivGetCert rejects certificate_der that is not an X509 certificate`() = runTest {
        sender.succeedWith("""{"certificate_der":"${b64.encodeToString(byteArrayOf(1, 2, 3))}"}""")
        expectMalformed { client.pivGetCert("9a") }
    }

    @Test
    fun `pivGetCert rejects a blank slot without sending`() = runTest {
        try {
            client.pivGetCert(" ")
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
        assertTrue(sender.sent.isEmpty())
    }

    // -------------------------------------------------------------------------
    // remote.pivSign
    // -------------------------------------------------------------------------

    @Test
    fun `pivSign sends slot and base64 data and parses the signature`() = runTest {
        val data = "digest".toByteArray()
        val signature = byteArrayOf(0x30, 0x44, 0x02, 0x20)
        sender.succeedWith(
            """{"signature":"${b64.encodeToString(signature)}","algorithm":"ECDSA-P256"}"""
        )

        val result = client.pivSign("9c", data)

        assertEquals("remote.pivSign", lastRequest.method)
        assertEquals(
            "algorithm and backend are omitempty",
            setOf("slot", "data"),
            lastParams.keySet()
        )
        assertEquals("9c", lastParams.getString("slot"))
        assertEquals(b64.encodeToString(data), lastParams.getString("data"))
        assertArrayEquals(signature, result.signature)
        assertEquals("ECDSA-P256", result.algorithm)
    }

    @Test
    fun `pivSign sends the algorithm and backend when named`() = runTest {
        sender.succeedWith("""{"signature":"AQID","algorithm":"RSA-2048"}""")

        client.pivSign("9a", byteArrayOf(9), algorithm = "RSA-2048", backend = "tpm2")

        assertEquals(setOf("slot", "data", "algorithm", "backend"), lastParams.keySet())
        assertEquals("RSA-2048", lastParams.getString("algorithm"))
        assertEquals("tpm2", lastParams.getString("backend"))
    }

    @Test
    fun `pivSign rejects a reply without an algorithm`() = runTest {
        sender.succeedWith("""{"signature":"AQID"}""")
        expectMalformed { client.pivSign("9c", byteArrayOf(1)) }
    }

    @Test
    fun `pivSign rejects an empty signature`() = runTest {
        sender.succeedWith("""{"signature":"","algorithm":"ECDSA-P256"}""")
        expectMalformed { client.pivSign("9c", byteArrayOf(1)) }
    }

    @Test
    fun `pivSign rejects a signature that is not a string`() = runTest {
        sender.succeedWith("""{"signature":[1,2],"algorithm":"ECDSA-P256"}""")
        expectMalformed { client.pivSign("9c", byteArrayOf(1)) }
    }

    @Test
    fun `pivSign rejects empty data without sending`() = runTest {
        try {
            client.pivSign("9c", ByteArray(0))
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `pivSign passes a sign failure code through`() = runTest {
        sender.failWith(ErrorCodes.PIV_SIGN_FAILED, "sign failed")

        val e = expectProtocolException { client.pivSign("9c", byteArrayOf(1)) }

        assertEquals(ErrorCodes.PIV_SIGN_FAILED, e.errorCode)
    }

    // -------------------------------------------------------------------------
    // Request ids
    // -------------------------------------------------------------------------

    @Test
    fun `piv requests take ids from the same counter as the other remote methods`() = runTest {
        sender.replyWith { request ->
            val result = when (request.method) {
                "remote.listBackends" -> """{"backends":[]}"""
                "remote.pivListSlots" -> """{"slots":[]}"""
                else -> """{"signature":"AQID","algorithm":"ECDSA-P256"}"""
            }
            """{"id":${request.id},"result":$result}"""
        }

        client.listBackends()
        client.pivListSlots()
        client.pivSign("9c", byteArrayOf(1))

        val ids = sender.sent.map { it.id }
        assertEquals(listOf(ids[0], ids[0] + 1, ids[0] + 2), ids)
    }

    private companion object {
        /** Self-signed P-256 certificate, shared with [RemoteKeyClientTest]. */
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
