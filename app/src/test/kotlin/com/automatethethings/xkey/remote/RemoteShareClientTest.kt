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
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import com.automatethethings.xkey.crypto.FileEncryptor
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
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
 * Pins the `remote.sharePublicKey`, `remote.shareSymmetric` and
 * `remote.importSharedKey` wire shapes against go-xkms xkey/v0.64.2-alpha
 * `pkg/pairingproto/protocol_sharing.go`. Go `[]byte` fields travel as
 * standard base64 strings, including the PEM fields.
 */

/** Android's org.json has no keySet(); collect the keys() iterator. */
private fun JSONObject.keyNames(): Set<String> = keys().asSequence().toSet()

class RemoteShareClientTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var client: RemoteShareClient

    private val pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    private val certPem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        client = RemoteShareClient(sender, router, requestTimeoutMs = 200)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun b64(s: String) = Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))
    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)
    private fun params(): JSONObject = sender.lastRequest.params!!

    private suspend fun expectProtocolError(block: suspend () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("expected ProtocolException")
        throw AssertionError()
    }

    // ---- remote.sharePublicKey ------------------------------------------

    @Test
    fun `sharePublicKey sends RemoteSharePublicKeyParams with base64 PEM bytes`() = runTest {
        sender.succeedWith("""{"accepted":true,"import_id":"shared-k1","backend":"software"}""")

        val result = client.sharePublicKey(
            RemoteShareClient.PublicKeyShare(
                keyId = "k1",
                publicKeyPem = pem,
                certificatePem = certPem,
                algorithm = "EC",
                label = "my key",
                backend = "pkcs11"
            )
        )

        assertEquals(MethodNames.REMOTE_SHARE_PUBLIC_KEY, sender.lastRequest.method)
        val p = params()
        assertEquals(setOf("key_id", "public_key_pem", "certificate_pem", "algorithm", "label", "backend"), p.keyNames())
        assertEquals("k1", p.getString("key_id"))
        assertEquals(b64(pem), p.getString("public_key_pem"))
        assertEquals(b64(certPem), p.getString("certificate_pem"))
        assertEquals("EC", p.getString("algorithm"))
        assertEquals("my key", p.getString("label"))
        assertEquals("pkcs11", p.getString("backend"))
        assertEquals(RemoteShareClient.ShareResult(true, "shared-k1", "software"), result)
    }

    @Test
    fun `sharePublicKey omits the omitempty fields when absent`() = runTest {
        sender.succeedWith("""{"accepted":true,"import_id":"x","backend":"software"}""")
        client.sharePublicKey(RemoteShareClient.PublicKeyShare("k1", pem, null, "EC", null, null))
        assertEquals(setOf("key_id", "public_key_pem", "algorithm"), params().keyNames())
    }

    @Test
    fun `sharePublicKey refuses empty PEM or algorithm before the wire`() = runTest {
        expectProtocolError { client.sharePublicKey(RemoteShareClient.PublicKeyShare("k1", "", null, "EC", null, null)) }
        expectProtocolError { client.sharePublicKey(RemoteShareClient.PublicKeyShare("k1", pem, null, "", null, null)) }
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `share results with wrong types or missing fields are rejected`() = runTest {
        val bad = listOf(
            """{"accepted":"true","import_id":"x","backend":"software"}""",
            """{"import_id":"x","backend":"software"}""",
            """{"accepted":true,"backend":"software"}""",
            """{"accepted":true,"import_id":7,"backend":"software"}""",
            """{"accepted":true,"import_id":"","backend":"software"}""",
            """{"accepted":true,"import_id":"x"}""",
            """{"accepted":true,"import_id":"x","backend":null}""",
            // A null result never reaches the client: the router reads
            // {"id":n,"result":null} as an inbound request, not a reply.
            "[]"
        )
        for (reply in bad) {
            sender.succeedWith(reply)
            val e = expectProtocolError {
                client.sharePublicKey(RemoteShareClient.PublicKeyShare("k1", pem, null, "EC", null, null))
            }
            assertEquals(reply, ErrorCodes.INTERNAL_ERROR, e.errorCode)
        }
    }

    @Test
    fun `desktop error replies surface as ProtocolException with the code`() = runTest {
        sender.failWith(ErrorCodes.OPERATION_DENIED, "backend not allowed")
        val e = expectProtocolError {
            client.sharePublicKey(RemoteShareClient.PublicKeyShare("k1", pem, null, "EC", null, null))
        }
        assertEquals(ErrorCodes.OPERATION_DENIED, e.errorCode)
    }

    @Test
    fun `a desktop that never answers times out`() = runTest {
        sender.neverReply()
        expectProtocolError {
            client.sharePublicKey(RemoteShareClient.PublicKeyShare("k1", pem, null, "EC", null, null))
        }
    }

    // ---- remote.shareSymmetric ------------------------------------------

    @Test
    fun `shareSymmetric sends RemoteShareSymmetricParams and zeroes the key`() = runTest {
        sender.succeedWith("""{"accepted":true,"import_id":"shared-sym-k2","backend":"software"}""")
        val material = ByteArray(32) { (it + 1).toByte() }
        val expected = material.copyOf()

        val result = client.shareSymmetric(
            keyId = "k2", wrappedKey = material, algorithm = "AES", keySize = 256, label = "aes", backend = null
        )

        assertEquals(MethodNames.REMOTE_SHARE_SYMMETRIC, sender.lastRequest.method)
        val p = params()
        assertEquals(setOf("key_id", "wrapped_key", "algorithm", "key_size", "label"), p.keyNames())
        assertEquals("k2", p.getString("key_id"))
        assertEquals(b64(expected), p.getString("wrapped_key"))
        assertEquals("AES", p.getString("algorithm"))
        assertEquals(256, p.get("key_size"))
        assertEquals("aes", p.getString("label"))
        assertTrue("caller's key bytes are zeroed", material.all { it == 0.toByte() })
        assertEquals(RemoteShareClient.ShareResult(true, "shared-sym-k2", "software"), result)
    }

    @Test
    fun `shareSymmetric zeroes the encoded request it handed the transport`() = runTest {
        var handed: ByteArray? = null
        val capturing = object : MessageSender {
            override suspend fun sendEncryptedMessage(data: ByteArray) {
                handed = data
                val r = Request.fromJson(data)
                router.processMessage("""{"id":${r.id},"result":{"accepted":true,"import_id":"i","backend":"software"}}""".toByteArray())
            }
        }
        RemoteShareClient(capturing, router, 200).shareSymmetric("k", ByteArray(16) { 7 }, "AES", 128, null, null)
        assertTrue(handed!!.all { it == 0.toByte() })
    }

    @Test
    fun `shareSymmetric zeroes the key even when the desktop refuses`() = runTest {
        sender.failWith(ErrorCodes.INVALID_PARAMS, "bad")
        val material = ByteArray(16) { 9 }
        expectProtocolError { client.shareSymmetric("k", material, "AES", 128, null, null) }
        assertTrue(material.all { it == 0.toByte() })
    }

    @Test
    fun `shareSymmetric refuses empty material before the wire`() = runTest {
        expectProtocolError { client.shareSymmetric("k", ByteArray(0), "AES", 0, null, null) }
        assertTrue(sender.sent.isEmpty())
    }

    // ---- remote.importSharedKey -----------------------------------------

    @Test
    fun `importSharedKey sends RemoteImportSharedKeyParams`() = runTest {
        sender.succeedWith("""{"public_key_pem":"${b64(pem)}","algorithm":"EC","key_type":"public","exportable":true}""")
        client.importSharedKey(backend = "pkcs11", keyId = "k3", format = "pem")
        assertEquals(MethodNames.REMOTE_IMPORT_SHARED_KEY, sender.lastRequest.method)
        val p = params()
        assertEquals(setOf("backend", "key_id", "format"), p.keyNames())
        assertEquals("pkcs11", p.getString("backend"))
        assertEquals("k3", p.getString("key_id"))
        assertEquals("pem", p.getString("format"))

        client.importSharedKey(backend = "software", keyId = "k3", format = null)
        assertEquals(setOf("backend", "key_id"), params().keyNames())
    }

    @Test
    fun `importSharedKey parses a public key result`() = runTest {
        sender.succeedWith(
            """{"public_key_pem":"${b64(pem)}","certificate_pem":"${b64(certPem)}","algorithm":"EC","key_type":"public","exportable":true}"""
        )
        val r = client.importSharedKey("software", "k3", null)
        assertEquals(pem, r.publicKeyPem)
        assertEquals(certPem, r.certificatePem)
        assertEquals("EC", r.algorithm)
        assertEquals("public", r.keyType)
        assertNull(r.wrappedKey)
        assertEquals(0, r.keySize)
        assertTrue(r.exportable)
    }

    @Test
    fun `importSharedKey parses a symmetric result with a nil public key`() = runTest {
        val key = ByteArray(32) { 3 }
        sender.succeedWith(
            """{"public_key_pem":null,"algorithm":"AES-256","key_type":"symmetric","wrapped_key":"${b64(key)}","key_size":256,"exportable":true}"""
        )
        val r = client.importSharedKey("software", "k4", null)
        assertNull(r.publicKeyPem)
        assertArrayEquals(key, r.wrappedKey)
        assertEquals(256, r.keySize)
        assertEquals("symmetric", r.keyType)
    }

    @Test
    fun `importSharedKey accepts a result with nothing exportable`() = runTest {
        sender.succeedWith("""{"public_key_pem":null,"algorithm":"","key_type":"","exportable":false}""")
        val r = client.importSharedKey("tpm2", "k5", null)
        assertFalse(r.exportable)
        assertNull(r.publicKeyPem)
    }

    @Test
    fun `importSharedKey refuses empty backend or key id before the wire`() = runTest {
        expectProtocolError { client.importSharedKey("", "k", null) }
        expectProtocolError { client.importSharedKey("software", "", null) }
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `malformed importSharedKey results are rejected`() = runTest {
        val good = """"algorithm":"EC","key_type":"public""""
        val bad = listOf(
            """{"public_key_pem":"${b64(pem)}",$good}""",
            """{"public_key_pem":"${b64(pem)}",$good,"exportable":"yes"}""",
            """{"public_key_pem":"not base64!",$good,"exportable":true}""",
            """{"public_key_pem":42,$good,"exportable":true}""",
            """{"public_key_pem":"${b64(pem)}","key_type":"public","exportable":true}""",
            """{"public_key_pem":"${b64(pem)}","algorithm":"EC","exportable":true}""",
            """{"public_key_pem":null,$good,"wrapped_key":"%%%","exportable":true}""",
            """{"public_key_pem":null,$good,"wrapped_key":"AAAA","key_size":"256","exportable":true}""",
            """{"public_key_pem":null,$good,"certificate_pem":true,"exportable":true}""",
            "[]"
        )
        for (reply in bad) {
            sender.succeedWith(reply)
            val e = expectProtocolError { client.importSharedKey("software", "k", null) }
            assertEquals(reply, ErrorCodes.INTERNAL_ERROR, e.errorCode)
        }
    }

    @Test
    fun `request ids come from one counter shared by every share client`() = runTest {
        sender.succeedWith("""{"accepted":true,"import_id":"x","backend":"software"}""")
        val share = RemoteShareClient.PublicKeyShare("k1", pem, null, "EC", null, null)
        client.sharePublicKey(share)
        RemoteShareClient(sender, router, 200).sharePublicKey(share)
        val (a, b) = sender.sent.map { it.id }
        assertTrue(a >= RemoteShareClient.BASE_REQUEST_ID)
        assertEquals(a + 1, b)
    }

    // ---- SharePermissionLedger retention ----------------------------------

    /**
     * A paired desktop can send `local.deleteKey` for IDs that name no key,
     * with no prompt. None of them leaves state in the revision ledger.
     */
    @Test
    fun `deletes of nonexistent keys leave the revision ledger bounded`() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.exists(any()) } returns false
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.resolveKeystoreAlias(any()) } returns null
        every { keystore.keyExists(any()) } returns false
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        val handler = realHandler(keyDao, keystore)
        val before = SharePermissionLedger.retainedKeyCount()

        repeat(10_000) { i ->
            val request = JSONObject().put("jsonrpc", "2.0").put("id", i).put("method", MethodNames.LOCAL_DELETE_KEY)
                .put("params", JSONObject().put("keyId", "absent-$i"))
            handler.handleRawRequest(request.toString().toByteArray())
        }

        val after = SharePermissionLedger.retainedKeyCount()
        assertTrue("10 000 deletes of absent keys must not grow the ledger ($before -> $after)", after <= before)
    }

    /**
     * A baseline taken before a revoke stays refused after every baseline of
     * its key has completed and the key's ledger entry has been reclaimed.
     */
    @Test
    fun `a stale baseline stays refused after its key is reclaimed`() {
        val keyId = "reclaimed-${System.nanoTime()}"
        val before = SharePermissionLedger.retainedKeyCount()
        val stale = SharePermissionLedger.baseline(keyId)
        runBlocking { SharePermissionLedger.revoking(keyId) { } }
        val completed = SharePermissionLedger.baseline(keyId)
        SharePermissionLedger.requireUnchanged(completed.keyId, completed.revision)
        completed.close()
        stale.close()

        assertEquals("a key with no outstanding baseline must be reclaimed", before, SharePermissionLedger.retainedKeyCount())
        try {
            SharePermissionLedger.requireUnchanged(stale.keyId, stale.revision)
            fail("a baseline taken before the revoke must stay refused after its key is reclaimed")
        } catch (_: SharePermissionRevokedException) {
        }
        // A baseline taken after the reclaim is admitted.
        val fresh = SharePermissionLedger.baseline(keyId)
        SharePermissionLedger.requireUnchanged(fresh.keyId, fresh.revision)
        fresh.close()
    }

    /** Each encryption revokes a fresh ephemeral key ID; none of them is retained. */
    @Test
    fun `repeated encryptions retain no ledger entries`() = runBlocking<Unit> {
        val encryptor = FileEncryptor(mockk(relaxed = true)) { throw IllegalStateException("no keystore") }
        val before = SharePermissionLedger.retainedKeyCount()

        repeat(1_000) {
            try {
                encryptor.encryptForRecipient(ByteArray(0), ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream())
            } catch (_: IllegalStateException) {
            }
        }

        val after = SharePermissionLedger.retainedKeyCount()
        assertTrue("encryptions must not grow the ledger ($before -> $after)", after <= before)
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(keyDao: KeyDao, keystore: KeystoreManager): RequestHandler {
        val context = mockk<Context>(relaxed = true)
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns mockk<KeyguardManager>(relaxed = true)
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        every { context.filesDir } returns Files.createTempDirectory("xkey-files").toFile().apply { deleteOnExit() }
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        return RequestHandler(context, keystore, biometricLauncher = null, sessionAuthManager = null)
    }
}
