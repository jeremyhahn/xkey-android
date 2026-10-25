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
package com.automatethethings.xkey.remote

import android.content.Context
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.sync.SyncEngine
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the two `remote.*` clients sharing a single
 * [BidirectionalMessageRouter], which is exactly how they are wired in
 * `XKeyGattService`: one Noise channel, one router, two independent request-id
 * spaces.
 *
 * `RemoteKeyClientTest` and `RemoteSyncClientTest` each exercise one client in
 * isolation. What neither can show is the interaction: that ids from the two
 * clients never collide on the shared router, that concurrent in-flight requests
 * are resolved strictly by id no matter what order the desktop answers in, and
 * that one client's failure leaves the other's request untouched. Those are the
 * properties that break first when a transport starts pipelining.
 *
 * The suite also covers the router's response-parsing rejections and the value
 * semantics of [RemoteSyncClient.SyncResult], which the UI reports to the user.
 *
 * [SyncEngine] is a MockK constructor mock: the real engine needs Room and the
 * Android Keystore, and its gather/merge behaviour is proved by the instrumented
 * `SyncEngineTest`.
 */
class RemoteClientInteropTest {

    private lateinit var context: Context
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var keyClient: RemoteKeyClient
    private lateinit var syncClient: RemoteSyncClient

    @Before
    fun setUp() {
        stubAndroidLog()
        mockkConstructor(SyncEngine::class)
        coEvery { anyConstructed<SyncEngine>().markSynced() } returns Unit
        coEvery { anyConstructed<SyncEngine>().gatherCertificates() } returns JSONArray()
        coEvery { anyConstructed<SyncEngine>().gatherOath() } returns JSONArray()
        coEvery { anyConstructed<SyncEngine>().gatherPasswords() } returns JSONArray()
        coEvery { anyConstructed<SyncEngine>().mergeCertificates(any()) } returns
            SyncEngine.CertCounts(added = 0, skipped = 0)
        coEvery { anyConstructed<SyncEngine>().mergeOath(any()) } returns
            SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 0)
        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } returns
            SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 0)

        context = mockk()
        every { context.applicationContext } returns context

        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        keyClient = RemoteKeyClient(sender, router, requestTimeoutMs = 5_000L)
        syncClient = RemoteSyncClient(context, sender, router, requestTimeoutMs = 5_000L)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** Replies per method so both clients can share one scripted transport. */
    private fun scriptByMethod(replies: Map<String, String>) {
        sender.replyWith { request ->
            val result = replies[request.method]
                ?: error("no scripted reply for ${request.method}")
            """{"id":${request.id},"result":$result}"""
        }
    }

    private fun bytes(json: String) = json.toByteArray(Charsets.UTF_8)

    // -------------------------------------------------------------------------
    // Shared router: id spaces
    // -------------------------------------------------------------------------

    @Test
    fun `the key and sync clients never issue the same request id`() = runTest {
        scriptByMethod(
            mapOf(
                "remote.listBackends" to """{"backends":[]}""",
                "remote.syncTrustStore" to """{"local":[]}""",
                "remote.syncOATH" to """{"local":[]}""",
                "remote.syncPasswords" to """{"local":[]}""",
                "remote.listKeys" to """{"keys":[]}"""
            )
        )

        keyClient.listBackends()
        syncClient.syncTrustStore()
        keyClient.listKeys("tpm2")
        syncClient.syncAll()

        val ids = sender.sent.map { it.id }
        assertEquals(
            listOf(1_000_000L, 2_000_000L, 1_000_001L, 2_000_001L, 2_000_002L, 2_000_003L),
            ids
        )
        assertEquals("every id on the shared router is unique", ids.size, ids.toSet().size)
    }

    @Test
    fun `the backup client's ids never collide with the key and sync clients'`() = runTest {
        scriptByMethod(
            mapOf(
                "remote.listBackends" to """{"backends":[]}""",
                "remote.syncTrustStore" to """{"local":[]}""",
                "remote.restoreBackup" to """{"success":true,"restored":[]}"""
            )
        )
        val backupClient = RemoteBackupClient(sender, router, requestTimeoutMs = 5_000L)

        keyClient.listBackends()
        backupClient.restoreBackup(bytes("{}"), "pw".toCharArray())
        syncClient.syncTrustStore()
        backupClient.restoreBackup(bytes("{}"), "pw".toCharArray())

        val ids = sender.sent.map { it.id }
        assertEquals("every id on the shared router is unique", ids.size, ids.toSet().size)
        val backupIds = sender.sent.filter { it.method == "remote.restoreBackup" }.map { it.id }
        assertTrue(backupIds.all { it >= RemoteBackupClient.BASE_REQUEST_ID })
    }

    @Test
    fun `a backup reply resolves only the backup request in flight beside a sync`() = runTest {
        val holding = HoldingMessageSender()
        val backupClient = RemoteBackupClient(holding, router, requestTimeoutMs = 5_000L)
        val sync = RemoteSyncClient(context, holding, router, requestTimeoutMs = 5_000L)

        val restore = async { backupClient.restoreBackup(bytes("{}"), "pw".toCharArray()) }
        val certs = async { sync.syncTrustStore() }
        runCurrent()
        assertEquals(2, holding.sent.size)

        router.processMessage(holding.replyFor(1, """{"added":1,"local":[]}"""))
        router.processMessage(holding.replyFor(0, """{"success":true,"restored":["oath"]}"""))

        assertEquals(listOf("oath"), restore.await().restored)
        assertEquals(1, certs.await().first)
    }

    @Test
    fun `each client keeps its own counter after the other has been busy`() = runTest {
        scriptByMethod(
            mapOf(
                "remote.listBackends" to """{"backends":[]}""",
                "remote.syncOATH" to """{"local":[]}"""
            )
        )

        repeat(5) { syncClient.syncOath() }
        keyClient.listBackends()

        assertEquals(1_000_000L, sender.lastRequest.id)
    }

    // -------------------------------------------------------------------------
    // Shared router: concurrency
    // -------------------------------------------------------------------------

    @Test
    fun `concurrent requests are resolved by id whatever order the peer answers in`() = runTest {
        val holding = HoldingMessageSender()
        val client = RemoteKeyClient(holding, router, requestTimeoutMs = 5_000L)

        val backends = async { client.listBackends() }
        val keys = async { client.listKeys("tpm2") }
        val info = async { client.getKeyInfo("tpm2", "k1") }
        runCurrent()

        assertEquals("all three must be in flight at once", 3, holding.sent.size)

        // Answer last-in first-out to prove correlation is by id, not arrival.
        router.processMessage(holding.replyFor(2, """{"keyId":"k1","backend":"tpm2","algorithm":"ecdsa-p256"}"""))
        router.processMessage(holding.replyFor(0, """{"backends":[{"name":"soft","type":"software"}]}"""))
        router.processMessage(holding.replyFor(1, """{"keys":[{"keyId":"k7","backend":"tpm2","algorithm":"rsa-2048"}]}"""))

        assertEquals("k1", info.await().keyId)
        assertEquals("soft", backends.await().single().name)
        assertEquals("k7", keys.await().single().keyId)
    }

    @Test
    fun `an error for one in-flight request does not disturb the other`() = runTest {
        val holding = HoldingMessageSender()
        val client = RemoteKeyClient(holding, router, requestTimeoutMs = 5_000L)

        // runCatching keeps the failure inside its own coroutine; letting an
        // `async` throw would cancel the whole test scope before the assertion.
        val doomed = async { runCatching { client.deleteKey("tpm2", "missing") } }
        val fine = async { client.listBackends() }
        runCurrent()

        router.processMessage(
            bytes("""{"id":${holding.sent[0].id},"error":{"code":-32001,"message":"no such key"}}""")
        )
        router.processMessage(holding.replyFor(1, """{"backends":[]}"""))

        val failure = doomed.await().exceptionOrNull()
        assertTrue("expected a ProtocolException, got $failure", failure is ProtocolException)
        assertEquals(ErrorCodes.KEY_NOT_FOUND, (failure as ProtocolException).errorCode)
        assertTrue("the healthy request still completes", fine.await().isEmpty())
    }

    @Test
    fun `a sync reply cannot resolve a key-client request`() = runTest {
        val holding = HoldingMessageSender()
        val client = RemoteKeyClient(holding, router, requestTimeoutMs = 5_000L)

        val pending = async { client.listBackends() }
        runCurrent()

        // A reply carrying the sync client's id space must be dropped.
        router.processMessage(bytes("""{"id":2000000,"result":{"backends":[]}}"""))
        assertFalse("a foreign id must not resolve this request", pending.isCompleted)

        router.processMessage(holding.replyFor(0, """{"backends":[]}"""))
        assertTrue(pending.await().isEmpty())
    }

    // -------------------------------------------------------------------------
    // Router response rejections
    // -------------------------------------------------------------------------

    @Test
    fun `a reply claiming both a result and an error is discarded`() = runTest {
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(500L, deferred)

        val out = router.processMessage(
            bytes("""{"id":500,"result":{"ok":true},"error":{"code":-32603,"message":"nope"}}""")
        )

        assertNull(out)
        assertFalse("an ambiguous reply must not resolve the request", deferred.isCompleted)
    }

    @Test
    fun `a reply with a negative id is discarded`() = runTest {
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(0L, deferred)

        val out = router.processMessage(bytes("""{"id":-1,"result":{"ok":true}}"""))

        assertNull(out)
        assertFalse(deferred.isCompleted)
    }

    @Test
    fun `a reply whose error omits its code is delivered as an internal error`() = runTest {
        // ErrorObject.fromJson is deliberately lenient so a peer that drops the
        // code still surfaces as a failure rather than hanging the caller.
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(501L, deferred)

        assertNull(router.processMessage(bytes("""{"id":501,"error":{"message":"no code"}}""")))

        val response = deferred.await()
        assertTrue(response.isError())
        assertEquals(ErrorCodes.INTERNAL_ERROR, response.error!!.code)
        assertEquals("no code", response.error!!.message)
    }

    // -------------------------------------------------------------------------
    // Parameter shapes not pinned elsewhere
    // -------------------------------------------------------------------------

    @Test
    fun `verify sends the algorithm override when one is supplied`() = runTest {
        sender.succeedWith("""{"valid":true}""")

        assertTrue(
            keyClient.verify("tpm2", "k1", "ZGF0YQ==", "c2ln", algorithm = "ECDSA_SHA384")
        )

        val params = sender.lastRequest.params!!
        assertEquals("ECDSA_SHA384", params.getString("algorithm"))
        assertEquals(5, params.length())
    }

    @Test
    fun `decrypt sends the algorithm override when one is supplied`() = runTest {
        sender.succeedWith("""{"plaintext":"cHQ="}""")

        keyClient.decrypt("soft", "k1", ciphertext = "Y3Q=", algorithm = "AES_GCM")

        val params = sender.lastRequest.params!!
        assertEquals("AES_GCM", params.getString("algorithm"))
        assertFalse("aad stays omitted when null", params.has("aad"))
        assertEquals(4, params.length())
    }

    @Test
    fun `encrypt sends aad alone when no algorithm override is given`() = runTest {
        sender.succeedWith("""{"ciphertext":"Y3Q="}""")

        keyClient.encrypt("soft", "k1", plaintext = "cHQ=", aad = "YWFk")

        val params = sender.lastRequest.params!!
        assertEquals("YWFk", params.getString("aad"))
        assertFalse(params.has("algorithm"))
        assertEquals(4, params.length())
    }

    @Test
    fun `attestKey accepts every attestation format the phone knows`() = runTest {
        for (format in listOf("tpm2", "pkcs11", "software")) {
            sender.succeedWith(
                """{"format":"$format","certificateChain":["$TEST_CERT_B64"],"nonce":"$NONCE"}"""
            )

            assertEquals(format, keyClient.attestKey("tpm2", "k1", NONCE).format)
        }
    }

    @Test
    fun `attestKey validates every certificate in a multi-entry chain`() = runTest {
        sender.succeedWith(
            """{"format":"tpm2","certificateChain":["$TEST_CERT_B64","$TEST_CERT_B64"],
                "nonce":"$NONCE"}"""
        )

        assertEquals(2, keyClient.attestKey("tpm2", "k1", NONCE).certificateChain.size)
    }

    // -------------------------------------------------------------------------
    // SyncResult value semantics
    // -------------------------------------------------------------------------

    @Test
    fun `two identical sync results are equal and hash alike`() {
        val a = RemoteSyncClient.SyncResult(1, 2, 3, 4, 5, 6)
        val b = RemoteSyncClient.SyncResult(1, 2, 3, 4, 5, 6)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `sync results differing in any single counter are not equal`() {
        val base = RemoteSyncClient.SyncResult(1, 2, 3, 4, 5, 6)

        assertNotEquals(base, base.copy(certsPushed = 9))
        assertNotEquals(base, base.copy(certsPulled = 9))
        assertNotEquals(base, base.copy(oathPushed = 9))
        assertNotEquals(base, base.copy(oathPulled = 9))
        assertNotEquals(base, base.copy(passwordsPushed = 9))
        assertNotEquals(base, base.copy(passwordsPulled = 9))
    }

    @Test
    fun `a sync result destructures in declaration order`() {
        val (certsPushed, certsPulled, oathPushed, oathPulled, pwPushed, pwPulled) =
            RemoteSyncClient.SyncResult(1, 2, 3, 4, 5, 6)

        assertEquals(1, certsPushed)
        assertEquals(2, certsPulled)
        assertEquals(3, oathPushed)
        assertEquals(4, oathPulled)
        assertEquals(5, pwPushed)
        assertEquals(6, pwPulled)
    }

    @Test
    fun `a sync result reports its counters in toString`() {
        val text = RemoteSyncClient.SyncResult(certsPushed = 11, passwordsPulled = 22).toString()

        assertTrue(text, text.contains("11"))
        assertTrue(text, text.contains("22"))
    }

    @Test
    fun `syncAll on two empty stores reports an empty run`() = runTest {
        sender.succeedWith("""{"local":[]}""")

        val result = syncClient.syncAll()

        assertEquals(RemoteSyncClient.SyncResult(), result)
        assertEquals(0, result.totalPushed)
        assertEquals(0, result.totalPulled)
    }

    private companion object {
        /** Base64 nonce echoed back by the scripted peer. */
        const val NONCE = "AAECAwQFBgcICQoLDA0ODw=="

        /**
         * The same self-signed P-256 certificate `RemoteKeyClientTest` uses, so
         * the chain-parsing branch runs against genuine ASN.1. Valid until 2126.
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

/**
 * A transport that records outbound requests and answers nothing on its own, so
 * a test can hold several requests in flight and then release the replies in any
 * order it likes.
 */
private class HoldingMessageSender : MessageSender {

    val sent: MutableList<Request> = mutableListOf()

    override suspend fun sendEncryptedMessage(data: ByteArray) {
        sent += Request.fromJson(data)
    }

    /** Builds a success reply addressed to the [index]-th recorded request. */
    fun replyFor(index: Int, resultJson: String): ByteArray =
        """{"id":${sent[index].id},"result":$resultJson}""".toByteArray(Charsets.UTF_8)
}
