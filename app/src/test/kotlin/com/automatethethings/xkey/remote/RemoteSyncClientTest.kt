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

import android.content.Context
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.password.PasswordStoreLockedException
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.sync.SyncEngine
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ui.SyncStatusText
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.time.ZoneOffset
import java.util.Locale

/**
 * Unit tests for [RemoteSyncClient], the phone-initiated (`remote.sync*`) half
 * of bidirectional store synchronization.
 *
 * These pin the wire contract against go-xkms
 * `pkg/pairing/protocol_sync.go` — the method names `remote.syncTrustStore` /
 * `remote.syncOATH` / `remote.syncPasswords`, the request envelopes
 * (`certificates` / `credentials` / `passwords`) and the reply key the phone
 * merges (`local`) — plus the push/pull accounting, the "peer omitted `local`"
 * case, and the error and timeout paths.
 *
 * [SyncEngine] is replaced with a MockK constructor mock: the real engine reads
 * Room and the Android Keystore, neither of which exists on the JVM, and its
 * own gather/merge behaviour is covered by the instrumented `SyncEngineTest`.
 */
class RemoteSyncClientTest {

    private lateinit var context: Context
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var client: RemoteSyncClient

    @Before
    fun setUp() {
        stubAndroidLog()
        mockkConstructor(SyncEngine::class)
        coEvery { anyConstructed<SyncEngine>().markSynced() } returns Unit

        context = mockk()
        every { context.applicationContext } returns context

        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        client = RemoteSyncClient(context, sender, router, requestTimeoutMs = 5_000L)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // --- Fixtures -----------------------------------------------------------

    private fun certificates(vararg fingerprints: String) = JSONArray().apply {
        for (fp in fingerprints) {
            put(JSONObject().put("pem", "-----BEGIN CERTIFICATE-----").put("fingerprint", fp))
        }
    }

    private fun oathCredentials(vararg ids: String) = JSONArray().apply {
        for (id in ids) put(JSONObject().put("id", id).put("secret", "JBSWY3DPEHPK3PXP"))
    }

    private fun passwords(vararg ids: String) = JSONArray().apply {
        for (id in ids) put(JSONObject().put("id", id).put("password", "hunter2"))
    }

    /** Stubs every gather to empty and every merge to zero counts. */
    private fun stubIdleEngine() {
        coEvery { anyConstructed<SyncEngine>().gatherCertificates() } returns JSONArray()
        coEvery { anyConstructed<SyncEngine>().gatherOath() } returns JSONArray()
        coEvery { anyConstructed<SyncEngine>().gatherPasswords() } returns JSONArray()
        coEvery { anyConstructed<SyncEngine>().mergeCertificates(any()) } returns
            SyncEngine.CertCounts(added = 0, skipped = 0)
        coEvery { anyConstructed<SyncEngine>().mergeOath(any()) } returns
            SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 0)
        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } returns
            SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 0)
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

    // --- Trust store --------------------------------------------------------

    @Test
    fun `syncTrustStore pushes local certificates under the certificates key`() = runTest {
        coEvery { anyConstructed<SyncEngine>().gatherCertificates() } returns
            certificates("aa11", "bb22")
        coEvery { anyConstructed<SyncEngine>().mergeCertificates(any()) } returns
            SyncEngine.CertCounts(added = 3, skipped = 1)
        sender.succeedWith("""{"added":2,"skipped":0,"local":[{"fingerprint":"cc33"}]}""")

        val (pushed, pulled) = client.syncTrustStore()

        assertEquals("remote.syncTrustStore", sender.lastRequest.method)
        val certs = sender.lastRequest.params!!.getJSONArray("certificates")
        assertEquals(2, certs.length())
        assertEquals("aa11", certs.getJSONObject(0).getString("fingerprint"))
        assertEquals(2, pushed)
        assertEquals("pulled counts merged additions, not skips", 3, pulled)
    }

    @Test
    fun `syncTrustStore merges the peer's local array`() = runTest {
        coEvery { anyConstructed<SyncEngine>().gatherCertificates() } returns JSONArray()
        val merged = slot<JSONArray>()
        coEvery { anyConstructed<SyncEngine>().mergeCertificates(capture(merged)) } returns
            SyncEngine.CertCounts(added = 1, skipped = 0)
        sender.succeedWith("""{"added":0,"skipped":0,"local":[{"fingerprint":"dd44"}]}""")

        client.syncTrustStore()

        assertEquals(1, merged.captured.length())
        assertEquals("dd44", merged.captured.getJSONObject(0).getString("fingerprint"))
    }

    @Test
    fun `syncTrustStore merges an empty array when the peer omits local`() = runTest {
        coEvery { anyConstructed<SyncEngine>().gatherCertificates() } returns JSONArray()
        val merged = slot<JSONArray>()
        coEvery { anyConstructed<SyncEngine>().mergeCertificates(capture(merged)) } returns
            SyncEngine.CertCounts(added = 0, skipped = 0)
        sender.succeedWith("""{"added":0,"skipped":0}""")

        val (pushed, pulled) = client.syncTrustStore()

        assertEquals(0, merged.captured.length())
        assertEquals(0, pushed)
        assertEquals(0, pulled)
    }

    // --- OATH ---------------------------------------------------------------

    @Test
    fun `syncOath uses the camelCase OATH method name and credentials key`() = runTest {
        coEvery { anyConstructed<SyncEngine>().gatherOath() } returns oathCredentials("a", "b", "c")
        coEvery { anyConstructed<SyncEngine>().mergeOath(any()) } returns
            SyncEngine.ItemCounts(added = 2, updated = 3, skipped = 4)
        // The desktop skipped one of the three offered credentials.
        sender.succeedWith("""{"added":1,"updated":1,"skipped":1,"local":[]}""")

        val (pushed, pulled) = client.syncOath()

        assertEquals("remote.syncOATH", sender.lastRequest.method)
        assertEquals(3, sender.lastRequest.params!!.getJSONArray("credentials").length())
        assertEquals("pushed counts what the desktop accepted, not what was offered", 2, pushed)
        assertEquals("OATH pulls count additions plus updates", 5, pulled)
    }

    // --- Passwords ----------------------------------------------------------

    @Test
    fun `syncPasswords pushes under the passwords key and counts adds plus updates`() = runTest {
        coEvery { anyConstructed<SyncEngine>().gatherPasswords() } returns passwords("p1")
        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } returns
            SyncEngine.ItemCounts(added = 4, updated = 1, skipped = 9)
        sender.succeedWith("""{"added":1,"updated":0,"skipped":0,"local":[]}""")

        val (pushed, pulled) = client.syncPasswords()

        assertEquals("remote.syncPasswords", sender.lastRequest.method)
        assertEquals(1, sender.lastRequest.params!!.getJSONArray("passwords").length())
        assertEquals(1, pushed)
        assertEquals(5, pulled)
    }

    // --- syncAll ------------------------------------------------------------

    @Test
    fun `syncAll runs all three stores in order and records the sync time`() = runTest {
        coEvery { anyConstructed<SyncEngine>().gatherCertificates() } returns certificates("aa")
        coEvery { anyConstructed<SyncEngine>().gatherOath() } returns oathCredentials("o1", "o2")
        coEvery { anyConstructed<SyncEngine>().gatherPasswords() } returns passwords("p1", "p2", "p3")
        coEvery { anyConstructed<SyncEngine>().mergeCertificates(any()) } returns
            SyncEngine.CertCounts(added = 1, skipped = 0)
        coEvery { anyConstructed<SyncEngine>().mergeOath(any()) } returns
            SyncEngine.ItemCounts(added = 1, updated = 1, skipped = 0)
        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } returns
            SyncEngine.ItemCounts(added = 0, updated = 3, skipped = 0)
        // Each store's reply reports what the desktop took: 1, 2 and 3 items.
        sender.succeedWith("""{"added":1,"updated":1,"local":[]}""")

        val result = client.syncAll()

        assertEquals(
            listOf("remote.syncTrustStore", "remote.syncOATH", "remote.syncPasswords"),
            sender.sent.map { it.method }
        )
        // Every reply above reports added=1 + updated=1, so each store pushed 2.
        assertEquals(2, result.certsPushed)
        assertEquals(1, result.certsPulled)
        assertEquals(2, result.oathPushed)
        assertEquals(2, result.oathPulled)
        assertEquals(2, result.passwordsPushed)
        assertEquals(3, result.passwordsPulled)
        assertEquals(6, result.totalPushed)
        assertEquals(6, result.totalPulled)
        coVerify(exactly = 1) { anyConstructed<SyncEngine>().markSynced() }
    }

    @Test
    fun `syncAll does not record a sync time when a store fails`() = runTest {
        stubIdleEngine()
        sender.replyWith { request ->
            if (request.method == "remote.syncOATH") {
                """{"id":${request.id},"error":{"code":-32603,"message":"oath store locked"}}"""
            } else {
                """{"id":${request.id},"result":{"local":[]}}"""
            }
        }

        val e = expectProtocolException { client.syncAll() }

        assertEquals("Remote sync error: oath store locked", e.message)
        assertEquals(ErrorCodes.INTERNAL_ERROR, e.errorCode)
        coVerify(exactly = 0) { anyConstructed<SyncEngine>().markSynced() }
        coVerify(exactly = 0) { anyConstructed<SyncEngine>().gatherPasswords() }
    }

    // --- Audit (issue #221) -------------------------------------------------

    private fun auditedClient() =
        RemoteSyncClient(context, sender, router, requestTimeoutMs = 5_000L, peerDeviceId = DESK_PEER, peerDeviceName = DESK_NAME)

    @Test
    fun `syncOath records one outbound entry`() = runTest {
        mockkObject(AuditLogger)
        stubIdleEngine()
        coEvery { anyConstructed<SyncEngine>().mergeOath(any()) } returns
            SyncEngine.ItemCounts(added = 1, updated = 2, skipped = 4)
        sender.succeedWith("""{"added":3,"updated":0,"local":[]}""")

        auditedClient().syncOath()

        verify(exactly = 1) {
            AuditLogger.logOathSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 3, direction = AuditLogger.SYNC_OUTBOUND,
                added = 1, updated = 2, skipped = 4, success = true, errorMessage = null
            )
        }
    }

    @Test
    fun `syncPasswords records one outbound entry`() = runTest {
        mockkObject(AuditLogger)
        stubIdleEngine()
        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } returns
            SyncEngine.ItemCounts(added = 2, updated = 0, skipped = 1)
        sender.succeedWith("""{"added":1,"updated":1,"local":[]}""")

        auditedClient().syncPasswords()

        verify(exactly = 1) {
            AuditLogger.logPasswordSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 2, direction = AuditLogger.SYNC_OUTBOUND,
                added = 2, updated = 0, skipped = 1, success = true, errorMessage = null
            )
        }
    }

    @Test
    fun `a peer error records a failed outbound entry and still throws`() = runTest {
        mockkObject(AuditLogger)
        stubIdleEngine()
        sender.failWith(code = -32603, message = "oath store locked")

        expectProtocolException { auditedClient().syncOath() }

        verify(exactly = 1) {
            AuditLogger.logOathSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 0, direction = AuditLogger.SYNC_OUTBOUND,
                added = 0, updated = 0, skipped = 0, success = false,
                errorMessage = "remote sync error, code -32603"
            )
        }
    }

    @Test
    fun `a peer error quoting credentials stores only the local description and code`() = runTest {
        mockkObject(AuditLogger)
        stubIdleEngine()
        val secrets = listOf("hunter2-pass", "JBSWY3DPEHPK3PXP", "bank.example.com", "alice-user")
        sender.failWith(code = -32001, message = "refused ${secrets.joinToString(" ")}")
        val stored = mutableListOf<String?>()

        val e = expectProtocolException { auditedClient().syncPasswords() }

        assertEquals(-32001, e.errorCode)
        assertEquals("Remote sync error: refused ${secrets.joinToString(" ")}", e.message)
        verify(exactly = 1) {
            AuditLogger.logPasswordSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 0, direction = AuditLogger.SYNC_OUTBOUND,
                added = 0, updated = 0, skipped = 0, success = false, errorMessage = captureNullable(stored)
            )
        }
        val entry = stored.single()
        assertEquals("remote sync error, code -32001", entry)
        secrets.forEach { assertFalse("audit entry holds $it", entry!!.contains(it)) }
    }

    @Test
    fun `syncAll with a locked vault records the failed password leg and syncs the other stores`() = runTest {
        mockkObject(AuditLogger)
        stubIdleEngine()
        coEvery { anyConstructed<SyncEngine>().gatherPasswords() } throws PasswordStoreLockedException()
        sender.succeedWith("""{"added":0,"updated":0,"local":[]}""")

        val result = auditedClient().syncAll()

        assertEquals(listOf("remote.syncTrustStore", "remote.syncOATH"), sender.sent.map { it.method })
        assertEquals(0, result.passwordsPushed)
        coVerify(exactly = 1) { anyConstructed<SyncEngine>().markSynced() }
        verify(exactly = 1) {
            AuditLogger.logPasswordSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 0, direction = AuditLogger.SYNC_OUTBOUND,
                added = 0, updated = 0, skipped = 0, success = false, errorMessage = "password store is locked"
            )
        }
        verify(exactly = 1) {
            AuditLogger.logOathSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 0, direction = AuditLogger.SYNC_OUTBOUND,
                added = 0, updated = 0, skipped = 0, success = true, errorMessage = null
            )
        }
    }

    @Test
    fun `sync answers as before when the audit logger is not initialized`() = runTest {
        assertFalse(AuditLogger.isInitialized())
        stubIdleEngine()
        coEvery { anyConstructed<SyncEngine>().gatherPasswords() } throws PasswordStoreLockedException()
        sender.succeedWith("""{"added":1,"updated":0,"local":[]}""")

        val result = client.syncAll()

        assertEquals(1, result.certsPushed)
        assertEquals(1, result.oathPushed)
        assertEquals(0, result.passwordsPushed)
    }

    // --- syncStatus (go-xkms RemoteSyncStatus*) -----------------------------

    @Test
    fun `syncStatus sends remote syncStatus with empty params and touches no store`() = runTest {
        sender.succeedWith("""{"device_id":"desk-1","store_checksums":{}}""")

        client.syncStatus()

        assertEquals(listOf("remote.syncStatus"), sender.sent.map { it.method })
        assertEquals("RemoteSyncStatusParams is struct{}", 0, sender.lastRequest.params!!.length())
        coVerify(exactly = 0) { anyConstructed<SyncEngine>().markSynced() }
        coVerify(exactly = 0) { anyConstructed<SyncEngine>().gatherCertificates() }
    }

    @Test
    fun `syncStatus parses last_sync, device_id and store_checksums`() = runTest {
        sender.succeedWith(
            """{"last_sync":"2026-11-12T08:30:00Z","device_id":"desk-1",
                "store_checksums":{"trust_store":"ab12","oath":"cd34","passwords":"ef56"}}"""
        )

        val status = client.syncStatus()

        assertEquals(
            RemoteSyncClient.DesktopSyncStatus(
                lastSync = "2026-11-12T08:30:00Z",
                deviceId = "desk-1",
                storeChecksums = mapOf("trust_store" to "ab12", "oath" to "cd34", "passwords" to "ef56")
            ),
            status
        )
    }

    @Test
    fun `syncStatus reads an omitted last_sync as never and a nil map as no checksums`() = runTest {
        sender.succeedWith("""{"device_id":"desk-1","store_checksums":null}""")

        val status = client.syncStatus()

        assertEquals(null, status.lastSync)
        assertEquals("desk-1", status.deviceId)
        assertEquals(emptyMap<String, String>(), status.storeChecksums)
    }

    @Test
    fun `syncStatus reads an explicit null last_sync as never and an omitted map as no checksums`() = runTest {
        sender.succeedWith("""{"last_sync":null,"device_id":"desk-1"}""")

        val status = client.syncStatus()

        assertEquals(null, status.lastSync)
        assertEquals(emptyMap<String, String>(), status.storeChecksums)
    }

    @Test
    fun `syncStatus refuses wrongly typed or missing fields`() = runTest {
        val malformed = listOf(
            """{}""",
            """{"store_checksums":{}}""",
            """{"device_id":7}""",
            """{"device_id":null}""",
            """{"device_id":"desk-1","last_sync":1731400200}""",
            """{"device_id":"desk-1","last_sync":{}}""",
            """{"device_id":"desk-1","store_checksums":["ab12"]}""",
            """{"device_id":"desk-1","store_checksums":"ab12"}""",
            """{"device_id":"desk-1","store_checksums":{"oath":12}}""",
            """{"device_id":"desk-1","store_checksums":{"oath":null}}"""
        )
        for (reply in malformed) {
            sender.succeedWith(reply)

            val e = expectProtocolException { client.syncStatus() }

            assertEquals(reply, ErrorCodes.INTERNAL_ERROR, e.errorCode)
            assertTrue(reply, e.message!!.startsWith("Malformed remote.syncStatus reply"))
        }
    }

    @Test
    fun `an unreadable status reply shows the desktop's status as unavailable`() = runTest {
        sender.succeedWith("""{"device_id":"desk-1","store_checksums":["ab12"]}""")

        val line = SyncStatusText.desktopLine(
            SyncStatusText.fetch { client.syncStatus() }, ZoneOffset.UTC, Locale.US
        )

        assertEquals(R.string.sync_desktop_status_unavailable, line.message)
    }

    @Test
    fun `syncStatus surfaces an error reply`() = runTest {
        sender.failWith(ErrorCodes.PAIRING_REQUIRED, "not paired")

        val e = expectProtocolException { client.syncStatus() }

        assertEquals(ErrorCodes.PAIRING_REQUIRED, e.errorCode)
    }

    @Test
    fun `syncStatus times out and names the method`() = runTest {
        sender.neverReply()

        val e = expectProtocolException { client.syncStatus() }

        assertEquals("Sync request timed out: remote.syncStatus", e.message)
    }

    @Test
    fun `a status request beside a sync from another client on one router gets its own id and reply`() = runTest {
        stubIdleEngine()
        sender.neverReply()
        // XKeyGattService builds a fresh client for desktopSyncStatus while
        // syncNow's client may still be waiting on a store leg.
        val other = RemoteSyncClient(context, sender, router, requestTimeoutMs = 5_000L)

        val store = async { client.syncTrustStore() }
        runCurrent()
        val status = async { other.syncStatus() }
        runCurrent()

        val (storeRequest, statusRequest) = sender.sent
        assertNotEquals("both requests are pending on one router", storeRequest.id, statusRequest.id)
        router.processMessage(
            """{"id":${statusRequest.id},"result":{"device_id":"desk-1","store_checksums":{}}}""".toByteArray()
        )
        router.processMessage("""{"id":${storeRequest.id},"result":{"added":1,"local":[]}}""".toByteArray())

        assertEquals("desk-1", status.await().deviceId)
        assertEquals(1, store.await().first)
    }

    // --- Failure paths ------------------------------------------------------

    @Test
    fun `an error reply surfaces the peer's code and message`() = runTest {
        stubIdleEngine()
        sender.failWith(ErrorCodes.PAIRING_REQUIRED, "not paired")

        val e = expectProtocolException { client.syncTrustStore() }

        assertEquals(ErrorCodes.PAIRING_REQUIRED, e.errorCode)
        assertEquals("Remote sync error: not paired", e.message)
    }

    @Test
    fun `a silent peer times out and names the method`() = runTest {
        stubIdleEngine()
        sender.neverReply()

        val e = expectProtocolException { client.syncPasswords() }

        assertEquals(ErrorCodes.INTERNAL_ERROR, e.errorCode)
        assertEquals("Sync request timed out: remote.syncPasswords", e.message)
    }

    @Test
    fun `a timed-out sync unregisters its id so the next request succeeds`() = runTest {
        stubIdleEngine()
        sender.neverReply()
        expectProtocolException { client.syncOath() }
        val abandoned = sender.lastRequest.id

        // A late reply for the abandoned id must be discarded, not applied.
        router.processMessage("""{"id":$abandoned,"result":{"local":[]}}""".toByteArray())
        sender.succeedWith("""{"local":[]}""")

        client.syncOath()

        assertEquals(abandoned + 1, sender.lastRequest.id)
    }

    // --- SyncResult ---------------------------------------------------------

    @Test
    fun `SyncResult totals sum every store`() {
        val result = RemoteSyncClient.SyncResult(
            certsPushed = 1, certsPulled = 2,
            oathPushed = 4, oathPulled = 8,
            passwordsPushed = 16, passwordsPulled = 32
        )

        assertEquals(21, result.totalPushed)
        assertEquals(42, result.totalPulled)
    }

    private companion object {
        const val DESK_PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
        const val DESK_NAME = "desk.example.com"
    }
}
