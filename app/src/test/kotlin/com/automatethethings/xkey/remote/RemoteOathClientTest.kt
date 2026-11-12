// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.remote

import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.RequestHandler
import io.mockk.mockk
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Pins remote.oathAdd / remote.oathGenerate against go-xkms
 * `pkg/pairing/protocol_oath.go` at tag xkey/v0.64.2-alpha:
 *
 * - RemoteOATHAddParams{credential: OATHCredentialInfo}
 * - OATHCredentialInfo{name, issuer?, account_name?, secret, type,
 *   algorithm?, digits?, period?, counter?}
 * - RemoteOATHAddResult{success, credential_id, message?}
 * - RemoteOATHGenerateParams{credential_id}
 * - RemoteOATHGenerateResult{code, expires_in?}
 */
class RemoteOathClientTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender

    @Before
    fun setUp() {
        stubAndroidLog()
        router = spyk(BidirectionalMessageRouter(mockk<RequestHandler>()))
        sender = ScriptedMessageSender(router)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun client(s: MessageSender = sender) = RemoteOathClient(s, router)

    private fun totp(secret: String = "JBSWY3DPEHPK3PXP") = RemoteOathClient.Credential(
        name = "GitHub:alice",
        issuer = "GitHub",
        accountName = "alice",
        secret = secret.toCharArray(),
        type = "totp",
        algorithm = "SHA256",
        digits = 8,
        period = 60
    )

    private suspend fun expectProtocolError(block: suspend () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("expected ProtocolException")
        throw AssertionError()
    }

    // --- remote.oathAdd params ---

    @Test
    fun `oathAdd sends the go-xkms RemoteOATHAddParams shape`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-1"}""")

        client().oathAdd(totp())

        val req = sender.lastRequest
        assertEquals(MethodNames.REMOTE_OATH_ADD, req.method)
        assertEquals("remote.oathAdd", req.method)
        val params = req.params!!
        assertEquals(setOf("credential"), params.keySet())
        val cred = params.getJSONObject("credential")
        assertEquals(
            setOf("name", "issuer", "account_name", "secret", "type", "algorithm", "digits", "period"),
            cred.keySet()
        )
        assertEquals("GitHub:alice", cred.getString("name"))
        assertEquals("GitHub", cred.getString("issuer"))
        assertEquals("alice", cred.getString("account_name"))
        assertEquals("JBSWY3DPEHPK3PXP", cred.getString("secret"))
        assertEquals("totp", cred.getString("type"))
        assertEquals("SHA256", cred.getString("algorithm"))
        assertEquals(8, cred.get("digits"))
        assertEquals(60, cred.get("period"))
    }

    @Test
    fun `oathAdd omits empty optional fields like go omitempty`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-1"}""")

        client().oathAdd(
            RemoteOathClient.Credential(
                name = "solo",
                issuer = null,
                accountName = "",
                secret = "JBSWY3DPEHPK3PXP".toCharArray(),
                type = "totp"
            )
        )

        val cred = sender.lastRequest.params!!.getJSONObject("credential")
        assertFalse(cred.has("issuer"))
        assertFalse(cred.has("account_name"))
        assertFalse(cred.has("counter"))
        assertEquals("solo", cred.getString("name"))
    }

    @Test
    fun `oathAdd sends counter for hotp and no period`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-2"}""")

        client().oathAdd(
            RemoteOathClient.Credential(
                name = "bank",
                issuer = "Bank",
                accountName = "bob",
                secret = "GEZDGNBVGY3TQOJQ".toCharArray(),
                type = "hotp",
                counter = 42L
            )
        )

        val cred = sender.lastRequest.params!!.getJSONObject("credential")
        assertEquals("hotp", cred.getString("type"))
        assertEquals(42L, cred.getLong("counter"))
        assertFalse(cred.has("period"))
    }

    @Test
    fun `oathAdd escapes string fields`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-3"}""")

        client().oathAdd(
            RemoteOathClient.Credential(
                name = "a\"b\\c",
                issuer = "Ünï\ncode",
                accountName = "x",
                secret = "JBSWY3DPEHPK3PXP".toCharArray(),
                type = "totp"
            )
        )

        val cred = sender.lastRequest.params!!.getJSONObject("credential")
        assertEquals("a\"b\\c", cred.getString("name"))
        assertEquals("Ünï\ncode", cred.getString("issuer"))
    }

    @Test
    fun `oathAdd zeroes the caller secret and the sent body`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-1"}""")
        val capturing = BodyCapturingSender(sender)
        val cred = totp()

        client(capturing).oathAdd(cred)

        assertTrue(cred.secret.all { it == '\u0000' })
        assertEquals(1, capturing.bodies.size)
        assertTrue(capturing.bodies[0].all { it == 0.toByte() })
        // The router saw the real secret before zeroing.
        assertEquals("JBSWY3DPEHPK3PXP", sender.lastRequest.params!!.getJSONObject("credential").getString("secret"))
    }

    @Test
    fun `oathAdd zeroes the caller secret when the desktop errors`() = runTest {
        sender.failWith(-32603, "boom")
        val cred = totp()

        expectProtocolError { client().oathAdd(cred) }

        assertTrue(cred.secret.all { it == '\u0000' })
    }

    @Test
    fun `oathAdd rejects invalid credentials before sending`() = runTest {
        val bad = listOf(
            totp().copyWith(name = ""),
            totp(secret = ""),
            totp(secret = "not base32!"),
            totp().copyWith(type = "motp"),
            totp().copyWith(algorithm = "MD5"),
            totp().copyWith(digits = 0)
        )
        for (cred in bad) {
            expectProtocolError { client().oathAdd(cred) }
            assertTrue(cred.secret.all { it == '\u0000' })
        }
        assertTrue(sender.sent.isEmpty())
    }

    // --- remote.oathAdd result ---

    @Test
    fun `oathAdd parses RemoteOATHAddResult`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-9","message":"stored"}""")

        val result = client().oathAdd(totp())

        assertTrue(result.success)
        assertEquals("desk-9", result.credentialId)
        assertEquals("stored", result.message)
    }

    @Test
    fun `oathAdd message is optional`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-9"}""")

        assertNull(client().oathAdd(totp()).message)
    }

    @Test
    fun `oathAdd success false throws with the desktop message`() = runTest {
        sender.succeedWith("""{"success":false,"credential_id":"","message":"duplicate"}""")

        val e = expectProtocolError { client().oathAdd(totp()) }

        assertTrue(e.message!!.contains("duplicate"))
    }

    @Test
    fun `oathAdd rejects malformed results`() = runTest {
        val malformed = listOf(
            """{}""",
            """{"credential_id":"desk-1"}""",
            """{"success":"true","credential_id":"desk-1"}""",
            """{"success":1,"credential_id":"desk-1"}""",
            """{"success":true}""",
            """{"success":true,"credential_id":""}""",
            """{"success":true,"credential_id":7}""",
            """{"success":true,"credential_id":null}""",
            """{"success":true,"credential_id":"desk-1","message":5}"""
        )
        for (body in malformed) {
            sender.succeedWith(body)
            try {
                client().oathAdd(totp())
                fail("accepted malformed result $body")
            } catch (_: ProtocolException) {
            }
        }
    }

    @Test
    fun `oathAdd rejects a missing or non-object result`() = runTest {
        for (script in listOf<(com.automatethethings.xkey.protocol.Request) -> String?>(
            { """{"id":${it.id}}""" },
            { """{"id":${it.id},"result":"ok"}""" },
            { """{"id":${it.id},"result":[1]}""" }
        )) {
            sender.replyWith(script)
            expectProtocolError { client().oathAdd(totp()) }
        }
    }

    @Test
    fun `oathAdd maps a desktop error to ProtocolException with its code`() = runTest {
        sender.failWith(-32602, "bad credential")

        val e = expectProtocolError { client().oathAdd(totp()) }

        assertEquals(-32602, e.errorCode)
    }

    @Test
    fun `oathAdd times out`() = runTest {
        sender.neverReply()

        expectProtocolError { RemoteOathClient(sender, router, requestTimeoutMs = 1_000L).oathAdd(totp()) }
    }

    // --- remote.oathGenerate ---

    @Test
    fun `oathGenerate sends the go-xkms RemoteOATHGenerateParams shape`() = runTest {
        sender.succeedWith("""{"code":"123456","expires_in":17}""")

        client().oathGenerate("desk-1")

        val req = sender.lastRequest
        assertEquals(MethodNames.REMOTE_OATH_GENERATE, req.method)
        assertEquals("remote.oathGenerate", req.method)
        assertEquals(setOf("credential_id"), req.params!!.keySet())
        assertEquals("desk-1", req.params!!.getString("credential_id"))
    }

    @Test
    fun `oathGenerate rejects a blank credential id before sending`() = runTest {
        expectProtocolError { client().oathGenerate("") }
        expectProtocolError { client().oathGenerate("  ") }
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `oathGenerate parses code and expiry`() = runTest {
        sender.succeedWith("""{"code":"01234567","expires_in":29}""")

        val result = client().oathGenerate("desk-1")

        assertEquals("01234567", result.code)
        assertEquals(29, result.expiresIn)
    }

    @Test
    fun `oathGenerate expiry is optional for hotp`() = runTest {
        sender.succeedWith("""{"code":"654321"}""")

        assertNull(client().oathGenerate("desk-1").expiresIn)
    }

    @Test
    fun `oathGenerate rejects malformed results`() = runTest {
        val malformed = listOf(
            """{}""",
            """{"code":123456}""",
            """{"code":""}""",
            """{"code":"12ab56"}""",
            """{"code":null}""",
            """{"code":"123456","expires_in":"30"}""",
            """{"code":"123456","expires_in":-1}""",
            """{"code":"123456","expires_in":2.5}""",
            """{"code":"123456","expires_in":true}"""
        )
        for (body in malformed) {
            sender.succeedWith(body)
            try {
                client().oathGenerate("desk-1")
                fail("accepted malformed result $body")
            } catch (_: ProtocolException) {
            }
        }
    }

    @Test
    fun `oathGenerate maps a desktop error`() = runTest {
        sender.failWith(-32602, "unknown credential")

        val e = expectProtocolError { client().oathGenerate("desk-x") }

        assertEquals(-32602, e.errorCode)
        assertTrue(e.message!!.contains("unknown credential"))
    }

    // --- request ids ---

    @Test
    fun `request ids come from one shared counter above the oath base`() = runTest {
        sender.succeedWith("""{"code":"123456","expires_in":5}""")

        client().oathGenerate("a")
        client().oathGenerate("b")
        val first = sender.sent[0].id
        val second = sender.sent[1].id

        assertTrue(first > RemoteOathClient.BASE_REQUEST_ID)
        assertTrue(first < RemoteOathClient.BASE_REQUEST_ID + 1_000_000L)
        assertNotEquals(first, second)
        assertTrue(second > first)
    }

    // --- Base32 helper ---

    @Test
    fun `base32Chars encodes RFC 4648 test vectors without padding`() {
        assertArrayEquals("MZXW6YTBOI".toCharArray(), RemoteOathClient.base32Chars("foobar".toByteArray()))
        assertArrayEquals("MY".toCharArray(), RemoteOathClient.base32Chars("f".toByteArray()))
        assertArrayEquals(CharArray(0), RemoteOathClient.base32Chars(ByteArray(0)))
        assertArrayEquals(
            "JBSWY3DPEHPK3PXP".toCharArray(),
            RemoteOathClient.base32Chars(byteArrayOf(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte()))
        )
    }

    private fun RemoteOathClient.Credential.copyWith(
        name: String = this.name,
        type: String = this.type,
        algorithm: String = this.algorithm,
        digits: Int = this.digits
    ) = RemoteOathClient.Credential(
        name, issuer, accountName, secret.copyOf(), type, algorithm, digits, period, counter
    )

    /** Keeps a reference to each body so the test can see it zeroed. */
    private class BodyCapturingSender(private val delegate: MessageSender) : MessageSender {
        val bodies = mutableListOf<ByteArray>()
        override suspend fun sendEncryptedMessage(data: ByteArray) {
            bodies.add(data)
            delegate.sendEncryptedMessage(data)
        }
    }
}
