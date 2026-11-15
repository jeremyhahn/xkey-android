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

import android.util.Log
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
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
 * Unit tests for [RemoteBackupClient], the phone-initiated
 * `remote.createBackup` / `remote.restoreBackup` client.
 *
 * These pin the wire contract against go-xkms
 * `pkg/pairingproto/protocol_backup.go` (go-xkms #1695): the snake_case field
 * names, base64 for `[]byte`, the required `password`, and the desktop's error
 * codes for these methods. They also pin the password hygiene: no [String] of
 * the password is logged, and the request buffer and the caller's password are
 * zeroed on every exit path.
 */
class RemoteBackupClientTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var transport: CapturingSender
    private lateinit var client: RemoteBackupClient
    private val logged = mutableListOf<String>()

    @Before
    fun setUp() {
        stubAndroidLog()
        every { Log.d(any(), capture(logged)) } returns 0
        every { Log.i(any(), capture(logged)) } returns 0
        every { Log.w(any(), capture(logged)) } returns 0
        every { Log.e(any(), capture(logged)) } returns 0

        router = spyk(BidirectionalMessageRouter(mockk<RequestHandler>()))
        sender = ScriptedMessageSender(router)
        transport = CapturingSender(sender)
        client = RemoteBackupClient(desktopOf(transport, router), requestTimeoutMs = 5_000L)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // --- Fixtures -----------------------------------------------------------

    private val secret = "c0rrect \"horse\" \\ battery"

    private fun password() = secret.toCharArray()

    private val all = RemoteBackupClient.Include(trustStore = true, oath = true, passwords = true)

    private val envelope = """{"version":1,"ciphertext":"AAEC"}""".toByteArray(Charsets.UTF_8)

    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    /** The params of the last request, parsed from the exact bytes sent. */
    private fun sentParams(): JSONObject = sender.lastRequest.params!!

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    private inline fun <reified T : RemoteBackupException> expect(block: () -> Unit): T {
        try {
            block()
        } catch (e: RemoteBackupException) {
            if (e is T) return e
            fail("expected ${T::class.simpleName}, got ${e::class.simpleName}: ${e.message}")
        }
        fail("expected ${T::class.simpleName}")
        throw IllegalStateException("unreachable")
    }

    private fun assertZeroed(chars: CharArray) =
        assertTrue("password chars must be zeroed", chars.all { it == '\u0000' })

    private fun assertBodiesZeroed() {
        assertTrue("a request was sent", transport.bodies.isNotEmpty())
        for (body in transport.bodies) {
            assertTrue("request buffer must be zeroed", body.all { it == 0.toByte() })
        }
    }

    // --- createBackup: wire -------------------------------------------------

    @Test
    fun `createBackup sends exactly the six contract fields in snake_case`() = runTest {
        sender.succeedWith("""{"backup_data":"${b64(envelope)}","backup_id":"phone-1","item_count":3}""")

        client.createBackup(
            password(),
            RemoteBackupClient.Include(trustStore = true, oath = false, passwords = true, ca = false),
            "phone-1"
        )

        assertEquals("remote.createBackup", sender.lastRequest.method)
        val params = sentParams()
        assertEquals(
            setOf("include_trust_store", "include_oath", "include_passwords", "include_ca", "label", "password"),
            params.keySet()
        )
        assertTrue(params.getBoolean("include_trust_store"))
        assertFalse(params.getBoolean("include_oath"))
        assertTrue(params.getBoolean("include_passwords"))
        assertFalse(params.getBoolean("include_ca"))
        assertEquals("phone-1", params.getString("label"))
        assertEquals(secret, params.getString("password"))
    }

    @Test
    fun `createBackup decodes the base64 envelope, id and item count`() = runTest {
        sender.succeedWith("""{"backup_data":"${b64(envelope)}","backup_id":"phone-7","item_count":12}""")

        val result = client.createBackup(password(), all, "phone-7")

        assertArrayEquals(envelope, result.backupData)
        assertEquals("phone-7", result.backupId)
        assertEquals(12, result.itemCount)
    }

    @Test
    fun `createBackup rejects a reply without backup_data`() = runTest {
        sender.succeedWith("""{"backup_id":"phone-7","item_count":1}""")

        expect<RemoteBackupException.MalformedReply> { client.createBackup(password(), all, "phone-7") }
    }

    @Test
    fun `createBackup rejects backup_data that is not base64`() = runTest {
        sender.succeedWith("""{"backup_data":"not base64!","backup_id":"x","item_count":1}""")

        expect<RemoteBackupException.MalformedReply> { client.createBackup(password(), all, "x") }
    }

    // --- restoreBackup: wire ------------------------------------------------

    @Test
    fun `restoreBackup sends exactly backup_data as base64 and password`() = runTest {
        sender.succeedWith("""{"success":true,"restored":["trust_store"]}""")

        client.restoreBackup(envelope, password())

        assertEquals("remote.restoreBackup", sender.lastRequest.method)
        val params = sentParams()
        assertEquals(setOf("backup_data", "password"), params.keySet())
        assertEquals(b64(envelope), params.getString("backup_data"))
        assertArrayEquals(envelope, Base64.getDecoder().decode(params.getString("backup_data")))
        assertEquals(secret, params.getString("password"))
    }

    @Test
    fun `a restore result with items and quarantined entries decodes`() = runTest {
        sender.succeedWith(
            """{"success":false,"restored":["trust_store","oath"],"message":"partial",
               "items":[
                 {"item":"trust_store","restored":4,"quarantined":2,"skipped":0},
                 {"item":"oath","restored":1,"skipped":3,"errors":["dup a","dup b"]}
               ]}"""
        )

        val result = client.restoreBackup(envelope, password())

        assertFalse(result.success)
        assertEquals(listOf("trust_store", "oath"), result.restored)
        assertEquals("partial", result.message)
        assertEquals(
            listOf(
                RemoteBackupClient.RestoreItem("trust_store", restored = 4, quarantined = 2, skipped = 0, errors = emptyList()),
                RemoteBackupClient.RestoreItem("oath", restored = 1, quarantined = 0, skipped = 3, errors = listOf("dup a", "dup b"))
            ),
            result.items
        )
    }

    @Test
    fun `a restore result without items or message decodes to empty`() = runTest {
        sender.succeedWith("""{"success":true,"restored":[]}""")

        val result = client.restoreBackup(envelope, password())

        assertTrue(result.success)
        assertNull(result.message)
        assertTrue(result.items.isEmpty())
    }

    // --- Local refusals -----------------------------------------------------

    @Test
    fun `an empty password is refused with no request sent`() = runTest {
        sender.succeedWith("""{"success":true,"restored":[]}""")

        expect<RemoteBackupException.EmptyPassword> { client.createBackup(CharArray(0), all, "phone-1") }
        expect<RemoteBackupException.EmptyPassword> { client.restoreBackup(envelope, CharArray(0)) }

        assertTrue("nothing may be sent", transport.bodies.isEmpty())
        verify(exactly = 0) { router.registerPendingResponse(any(), any()) }
    }

    @Test
    fun `a backup with no store selected is refused with no request sent`() = runTest {
        val pw = password()

        expect<RemoteBackupException.NothingSelected> {
            client.createBackup(pw, RemoteBackupClient.Include(), "phone-1")
        }

        assertTrue(transport.bodies.isEmpty())
        assertZeroed(pw)
    }

    // --- Error codes --------------------------------------------------------

    @Test
    fun `each desktop backup code maps to its typed error`() = runTest {
        val cases = listOf(
            -32602 to RemoteBackupException.InvalidParams::class,
            -32020 to RemoteBackupException.CreationFailed::class,
            -32021 to RemoteBackupException.WrongPasswordOrDamaged::class,
            -32035 to RemoteBackupException.NotConfigured::class,
            -32038 to RemoteBackupException.ApprovalRequired::class,
            -32603 to RemoteBackupException.Other::class
        )
        for ((code, type) in cases) {
            sender.failWith(code, "nope")
            try {
                client.restoreBackup(envelope, password())
                fail("code $code must throw")
            } catch (e: RemoteBackupException) {
                assertEquals("code $code", type, e::class)
                assertEquals(code, e.code)
            }
        }
    }

    // --- remote.listBackups (go-xkms RemoteListBackups*, BackupInfo) --------

    @Test
    fun `listBackups sends remote listBackups with empty params and no password`() = runTest {
        sender.succeedWith("""{"backups":[]}""")

        client.listBackups()

        assertEquals("remote.listBackups", sender.lastRequest.method)
        assertEquals("RemoteListBackupsParams is struct{}", emptySet<String>(), sentParams().keySet())
    }

    @Test
    fun `listBackups parses each BackupInfo`() = runTest {
        sender.succeedWith(
            """{"backups":[
                {"backup_id":"phone-1","created_at":"2026-11-01T10:00:00Z","label":"weekly","size":4294967296},
                {"backup_id":"phone-2","created_at":"2026-11-02T10:00:00Z","size":512}
            ]}"""
        )

        val backups = client.listBackups()

        assertEquals(
            listOf(
                RemoteBackupClient.BackupInfo("phone-1", "2026-11-01T10:00:00Z", "weekly", 4_294_967_296L),
                RemoteBackupClient.BackupInfo("phone-2", "2026-11-02T10:00:00Z", null, 512L)
            ),
            backups
        )
    }

    @Test
    fun `listBackups reads a nil Go slice as no backups`() = runTest {
        sender.succeedWith("""{"backups":null}""")
        assertEquals(emptyList<RemoteBackupClient.BackupInfo>(), client.listBackups())

        sender.succeedWith("""{}""")
        assertEquals(emptyList<RemoteBackupClient.BackupInfo>(), client.listBackups())
    }

    @Test
    fun `listBackups refuses a backups field that is not a list of objects`() = runTest {
        sender.succeedWith("""{"backups":"phone-1"}""")
        expect<RemoteBackupException.MalformedReply> { client.listBackups() }

        sender.succeedWith("""{"backups":["phone-1"]}""")
        expect<RemoteBackupException.MalformedReply> { client.listBackups() }
    }

    @Test
    fun `listBackups maps the desktop's error codes`() = runTest {
        sender.failWith(-32035, "backup not configured")

        val e = expect<RemoteBackupException.NotConfigured> { client.listBackups() }

        assertEquals(-32035, e.code)
    }

    @Test
    fun `listBackups times out and removes its router entry`() = runTest {
        sender.neverReply()

        expect<RemoteBackupException.TimedOut> { client.listBackups() }

        val id = sender.lastRequest.id
        verify { router.removePendingResponse(id) }
    }

    // --- Password hygiene ---------------------------------------------------

    @Test
    fun `the password never appears in a logged string`() = runTest {
        sender.succeedWith("""{"backup_data":"${b64(envelope)}","backup_id":"p","item_count":1}""")
        client.createBackup(password(), all, "p")
        sender.failWith(-32021, "bad")
        expect<RemoteBackupException.WrongPasswordOrDamaged> { client.restoreBackup(envelope, password()) }

        assertTrue("something was logged", logged.isNotEmpty())
        for (line in logged) {
            assertFalse("logged the password: $line", line.contains("horse"))
            assertFalse("logged the params: $line", line.contains("password"))
        }
    }

    @Test
    fun `the password and request buffer are zeroed after a successful send`() = runTest {
        sender.succeedWith("""{"backup_data":"${b64(envelope)}","backup_id":"p","item_count":1}""")
        val pw = password()

        client.createBackup(pw, all, "p")

        assertZeroed(pw)
        assertBodiesZeroed()
    }

    @Test
    fun `the password and request buffer are zeroed after an error reply`() = runTest {
        sender.failWith(-32021, "bad")
        val pw = password()

        expect<RemoteBackupException.WrongPasswordOrDamaged> { client.restoreBackup(envelope, pw) }

        assertZeroed(pw)
        assertBodiesZeroed()
    }

    @Test
    fun `the password and request buffer are zeroed when the transport fails`() = runTest {
        transport.failNext = true
        val pw = password()

        try {
            client.restoreBackup(envelope, pw)
            fail("a dead link must throw")
        } catch (e: java.io.IOException) {
            // expected
        }

        assertZeroed(pw)
        assertBodiesZeroed()
    }

    @Test
    fun `passwords with quotes, controls and non-ASCII survive JSON encoding`() {
        val tricky = "a\"b\\c\n\t\u0001é€🔑z"
        val body = RemoteBackupClient.encodeRequest(
            42L, "remote.restoreBackup", JSONObject().put("backup_data", "AA=="), tricky.toCharArray()
        )

        val request = Request.fromJson(body)

        assertEquals(42L, request.id)
        assertEquals("remote.restoreBackup", request.method)
        assertEquals(tricky, request.params!!.getString("password"))
        assertEquals("AA==", request.params!!.getString("backup_data"))
    }

    @Test
    fun `a lone surrogate is sent as the replacement character`() {
        val body = RemoteBackupClient.encodeRequest(
            1L, "remote.restoreBackup", JSONObject(), charArrayOf('x', '\uD83D')
        )

        assertEquals("x�", Request.fromJson(body).params!!.getString("password"))
    }

    // --- Router entries and ids ---------------------------------------------

    @Test
    fun `a timed-out request removes its router entry`() = runTest {
        sender.neverReply()
        val pw = password()

        expect<RemoteBackupException.TimedOut> { client.restoreBackup(envelope, pw) }

        val id = sender.lastRequest.id
        verify { router.removePendingResponse(id) }
        assertZeroed(pw)
        assertBodiesZeroed()
    }

    @Test
    fun `a cancelled request removes its router entry and zeroes its buffers`() = runTest {
        sender.neverReply()
        val pw = password()

        val job = launch { client.restoreBackup(envelope, pw) }
        runCurrent()
        job.cancel()
        job.join()

        val id = sender.lastRequest.id
        verify { router.removePendingResponse(id) }
        assertZeroed(pw)
        assertBodiesZeroed()
    }

    @Test
    fun `request ids are unique across client instances and above the other clients' bases`() = runTest {
        sender.succeedWith("""{"success":true,"restored":[]}""")
        val other = RemoteBackupClient(desktopOf(transport, router), requestTimeoutMs = 5_000L)

        client.restoreBackup(envelope, password())
        other.restoreBackup(envelope, password())
        client.restoreBackup(envelope, password())

        val ids = sender.sent.map { it.id }
        assertEquals("no id is reused", ids.size, ids.toSet().size)
        assertTrue(ids.all { it >= RemoteBackupClient.BASE_REQUEST_ID })
        assertEquals("ids only grow", ids.sorted(), ids)
    }
}

/**
 * Records the exact buffer each request is sent in, so a test can check the
 * client zeroed it afterwards, then hands it to [delegate].
 */
private class CapturingSender(private val delegate: MessageSender) : MessageSender {

    val bodies: MutableList<ByteArray> = mutableListOf()

    /** When set, the next send fails as a dead link would. */
    var failNext = false

    override suspend fun sendEncryptedMessage(data: ByteArray) {
        bodies += data
        if (failNext) {
            failNext = false
            throw java.io.IOException("link down")
        }
        delegate.sendEncryptedMessage(data)
    }
}
