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
package com.automatethethings.xkey.ble

import android.app.Application
import com.automatethethings.xkey.backup.BackupStore
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.RemoteBackupClient
import com.automatethethings.xkey.remote.RemoteBackupException
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.desktopOf
import com.automatethethings.xkey.tcp.TcpHsmServer
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.io.IOException
import java.util.Base64

/**
 * The phone-initiated desktop backup entry points of [XKeyGattService]:
 * [XKeyGattService.createDesktopBackup], [XKeyGattService.restoreDesktopBackup],
 * [XKeyGattService.listDesktopBackups] and
 * [XKeyGattService.latestStoredBackupId].
 *
 * `RemoteBackupClientTest` pins the wire format and the client's own buffer
 * zeroing. These pin what the service adds: the refusal with no desktop, the
 * envelope kept in [BackupStore] under the id handed back, the stored
 * envelope sent on a restore, and the caller's password zeroed on every
 * exit.
 *
 * The service is built without `create()`, which would start Bluetooth, the
 * Keystore and the request handler. A connected desktop is a mocked
 * [TcpHsmServer] on the private `tcpHsmServer` field whose desktop is a
 * [ScriptedMessageSender] over a real [BidirectionalMessageRouter].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class DesktopBackupServiceTest {

    private lateinit var app: Application
    private lateinit var service: XKeyGattService
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender

    private val envelope = """{"version":1,"ciphertext":"AAEC"}""".toByteArray(Charsets.UTF_8)
    private val all = RemoteBackupClient.Include(trustStore = true, oath = true, passwords = true)

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication()
        backupsDir().deleteRecursively()
        service = Robolectric.buildService(XKeyGattService::class.java).get()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
    }

    @After
    fun tearDown() {
        unmockkAll()
        backupsDir().deleteRecursively()
    }

    // --- Fixtures -----------------------------------------------------------

    private fun backupsDir() = File(app.filesDir, "backups")

    private fun password() = "c0rrect horse".toCharArray()

    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    private fun createReply(backupId: String = "desk-1") =
        """{"backup_data":"${b64(envelope)}","backup_id":"$backupId","item_count":3}"""

    private val restoreReply =
        """{"success":true,"restored":["oath"],"items":[{"item":"oath","restored":2}]}"""

    /** Puts a desktop on the TCP transport, the one [XKeyGattService.connectedDesktop] reaches here. */
    private fun connectDesktop() {
        val tcp = mockk<TcpHsmServer>()
        every { tcp.connectedDesktop(any()) } returns desktopOf(sender, router)
        XKeyGattService::class.java.getDeclaredField("tcpHsmServer")
            .apply { isAccessible = true }
            .set(service, tcp)
    }

    private fun store() = BackupStore(app)

    private fun assertZeroed(chars: CharArray) =
        assertTrue("password chars must be zeroed", chars.all { it == '\u0000' })

    private fun assertNothingStored() =
        assertTrue(
            "no backup may be stored",
            backupsDir().listFiles().isNullOrEmpty() || store().latestId() == null
        )

    private inline fun <reified T : Throwable> expect(block: () -> Unit): T {
        try {
            block()
        } catch (e: Throwable) {
            if (e is T) return e
            fail("expected ${T::class.simpleName}, got ${e::class.simpleName}: ${e.message}")
        }
        fail("expected ${T::class.simpleName}")
        throw IllegalStateException("unreachable")
    }

    // --- No desktop ---------------------------------------------------------

    @Test
    fun `create with no desktop throws, sends and stores nothing and zeroes the password`() = runBlocking {
        val pw = password()

        expect<IllegalStateException> { service.createDesktopBackup(pw, all) }

        assertTrue(sender.sent.isEmpty())
        assertNothingStored()
        assertZeroed(pw)
    }

    @Test
    fun `restore with no desktop throws, sends nothing and zeroes the password`() = runBlocking {
        store().store("desk-1", envelope)
        val pw = password()

        expect<IllegalStateException> { service.restoreDesktopBackup("desk-1", pw) }

        assertTrue(sender.sent.isEmpty())
        assertZeroed(pw)
    }

    @Test
    fun `list with no desktop throws and sends nothing`() = runBlocking {
        expect<IllegalStateException> { service.listDesktopBackups() }

        assertTrue(sender.sent.isEmpty())
    }

    // --- Create -------------------------------------------------------------

    @Test
    fun `create keeps the envelope under the desktop's id and zeroes the password`() = runBlocking {
        connectDesktop()
        sender.succeedWith(createReply("desk-1"))
        val pw = password()

        val result = service.createDesktopBackup(pw, all)

        assertEquals("desk-1", result.backupId)
        assertEquals(3, result.itemCount)
        assertArrayEquals(envelope, result.backupData)
        assertArrayEquals(envelope, store().load(result.backupId))
        assertEquals("desk-1", service.latestStoredBackupId())
        assertEquals(1, sender.sent.size)
        assertEquals(MethodNames.REMOTE_CREATE_BACKUP, sender.lastRequest.method)
        assertTrue(sender.lastRequest.params!!.getString("label").startsWith("phone-"))
        assertZeroed(pw)
    }

    @Test
    fun `create with no backup_id in the reply returns the id the envelope was stored under`() = runBlocking {
        connectDesktop()
        sender.succeedWith("""{"backup_data":"${b64(envelope)}","item_count":3}""")

        val result = service.createDesktopBackup(password(), all)

        assertTrue("the returned id must name a backup", result.backupId.isNotBlank())
        assertEquals(3, result.itemCount)
        assertArrayEquals(envelope, result.backupData)
        assertArrayEquals(envelope, store().load(result.backupId))
        assertEquals(result.backupId, service.latestStoredBackupId())

        sender.succeedWith(restoreReply)
        service.restoreDesktopBackup(result.backupId, password())
        assertEquals(b64(envelope), sender.lastRequest.params!!.getString("backup_data"))
    }

    @Test
    fun `latestStoredBackupId is null with nothing stored`() = runBlocking {
        assertNull(service.latestStoredBackupId())
    }

    @Test
    fun `create on an error reply propagates, stores nothing and zeroes the password`() = runBlocking {
        connectDesktop()
        sender.failWith(-32603, "backup failed")
        val pw = password()

        expect<RemoteBackupException> { service.createDesktopBackup(pw, all) }

        assertEquals(1, sender.sent.size)
        assertNothingStored()
        assertZeroed(pw)
    }

    @Test
    fun `create on a send that throws propagates, stores nothing and zeroes the password`() = runBlocking {
        connectDesktop()
        sender.replyWith { throw IOException("link down") }
        val pw = password()

        expect<IOException> { service.createDesktopBackup(pw, all) }

        assertNothingStored()
        assertZeroed(pw)
    }

    @Test
    fun `create whose envelope cannot be stored throws IOException and zeroes the password`() = runBlocking {
        connectDesktop()
        sender.succeedWith(createReply("desk-1"))
        // A plain file where the backups directory goes: no record can be written.
        backupsDir().writeBytes(byteArrayOf(1))
        val pw = password()

        expect<IOException> { service.createDesktopBackup(pw, all) }

        assertEquals(1, sender.sent.size)
        assertTrue("backups is still the plain file", backupsDir().isFile)
        assertZeroed(pw)
    }

    // --- Restore ------------------------------------------------------------

    @Test
    fun `restore of an unknown id throws No stored backup, sends nothing and zeroes the password`() = runBlocking {
        connectDesktop()
        sender.succeedWith(restoreReply)
        val pw = password()

        val e = expect<IllegalStateException> { service.restoreDesktopBackup("missing", pw) }

        assertTrue(e.message!!.contains("No stored backup"))
        assertTrue(sender.sent.isEmpty())
        assertZeroed(pw)
    }

    @Test
    fun `restore sends the stored envelope and zeroes the password`() = runBlocking {
        connectDesktop()
        store().store("other", "other".toByteArray())
        store().store("desk-1", envelope)
        sender.succeedWith(restoreReply)
        val pw = password()

        val result = service.restoreDesktopBackup("desk-1", pw)

        assertTrue(result.success)
        assertEquals(listOf("oath"), result.restored)
        assertEquals(MethodNames.REMOTE_RESTORE_BACKUP, sender.lastRequest.method)
        assertEquals(b64(envelope), sender.lastRequest.params!!.getString("backup_data"))
        assertZeroed(pw)
    }

    @Test
    fun `restore on an error reply propagates and zeroes the password`() = runBlocking {
        connectDesktop()
        store().store("desk-1", envelope)
        sender.failWith(-32603, "restore failed")
        val pw = password()

        expect<RemoteBackupException> { service.restoreDesktopBackup("desk-1", pw) }

        assertEquals(1, sender.sent.size)
        assertZeroed(pw)
    }

    @Test
    fun `restore on a send that throws propagates and zeroes the password`() = runBlocking {
        connectDesktop()
        store().store("desk-1", envelope)
        sender.replyWith { throw IOException("link down") }
        val pw = password()

        expect<IOException> { service.restoreDesktopBackup("desk-1", pw) }

        assertZeroed(pw)
    }

    // --- List ---------------------------------------------------------------

    @Test
    fun `list returns the desktop's backups and sends no password`() = runBlocking {
        connectDesktop()
        sender.succeedWith(
            """{"backups":[{"backup_id":"desk-1","created_at":"2026-11-01T00:00:00Z","label":"phone-1","size":42}]}"""
        )

        val backups = service.listDesktopBackups()

        assertEquals(
            listOf(RemoteBackupClient.BackupInfo("desk-1", "2026-11-01T00:00:00Z", "phone-1", 42L)),
            backups
        )
        assertEquals(MethodNames.REMOTE_LIST_BACKUPS, sender.lastRequest.method)
        assertFalse(sender.lastRequest.params?.has("password") ?: false)
    }
}
