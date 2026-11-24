/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.ui

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.os.Bundle
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.ShareSession
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType as EntitySharingPolicyType
import com.google.android.material.button.MaterialButton
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.security.KeyStore
import java.time.Duration

/** The sheet's paired-desktop section: its status for each gate decision, and a send to the desktop. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class KeySharingBottomSheetDesktopSendTest {

    private lateinit var app: Application
    private lateinit var keyDao: KeyDao
    private lateinit var policyDao: KeySharingPolicyDao
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var service: XKeyGattService
    private var controller: ActivityController<HostActivity>? = null

    private var entity: KeyEntity? = entityWith(EntitySharingPolicyType.ALL_PEERS)
    private var pem: String? = PEM
    private var software: () -> SoftwareKey? = { null }

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication()

        keyDao = mockk(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } answers { entity }
        policyDao = mockk(relaxed = true)
        every { policyDao.getPoliciesForKey(any()) } returns flowOf(emptyList())
        coEvery { policyDao.isKeySharedWithPeer(any(), any()) } returns true
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.keySharingPolicyDao() } returns policyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkConstructor(MasterKey.Builder::class)
        every { anyConstructed<MasterKey.Builder>().setKeyScheme(any()) } answers { self as MasterKey.Builder }
        every { anyConstructed<MasterKey.Builder>().build() } returns mockk()
        mockkStatic(EncryptedSharedPreferences::class)
        every {
            EncryptedSharedPreferences.create(any<Context>(), any<String>(), any<MasterKey>(), any(), any())
        } returns InMemorySharedPreferences()

        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(KeystoreManager::class)
        every { anyConstructed<KeystoreManager>().getPublicKeyPEM(any()) } answers { pem }
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().get(any()) } answers { software() }

        router = BidirectionalMessageRouter(mockk<RequestHandler>(relaxed = true))
        sender = ScriptedMessageSender(router)
        sender.confirmedPeer = PEER
        service = mockk(relaxed = true)
        every { service.shareSession() } answers { currentSession() }
    }

    @After
    fun tearDown() {
        controller?.let { c -> runCatching { c.pause().stop().destroy() } }
        unmockkAll()
    }

    private fun currentSession(): ShareSession? =
        ShareSession.of(listOf(ShareSession.Transport(sender, router))) { s -> s.sameAs(service.shareSession()) }

    // -----------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------

    @Test
    fun `with no service bound the section stays hidden`() {
        shadowOf(app).declareComponentUnbindable(serviceComponent())
        val sheet = open()
        settle()
        assertEquals(View.GONE, container(sheet).visibility)
    }

    @Test
    fun `with no session the section stays hidden`() {
        every { service.shareSession() } returns null
        bindService()
        val sheet = open()
        settle()
        verify(atLeast = 1) { service.shareSession() }
        assertEquals(View.GONE, container(sheet).visibility)
    }

    @Test
    fun `an unconfirmed session shows no peer`() {
        sender.confirmedPeer = null
        val sheet = openBound()
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_no_peer))
        assertEquals(View.GONE, button(sheet).visibility)
    }

    @Test
    fun `a policy that omits the peer shows policy denied`() {
        entity = entityWith(EntitySharingPolicyType.SELECTED_PEERS)
        coEvery { policyDao.isKeySharedWithPeer(KEY_ID, PEER) } returns false
        val sheet = openBound()
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_policy_denied))
        assertEquals(View.GONE, button(sheet).visibility)
    }

    @Test
    fun `a software key that is not exportable shows not exportable and is zeroed`() {
        val material = ByteArray(32) { (it + 1).toByte() }
        software = {
            SoftwareKey(
                keyId = KEY_ID, algorithm = "AES-256-GCM", keyType = "symmetric", keySize = 256,
                exportable = false, shareable = false, material = material
            )
        }
        val sheet = openBound()
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_not_exportable))
        settle()
        assertEquals(View.GONE, button(sheet).visibility)
        assertTrue("the material handed to the sheet must be zeroed", material.all { it == 0.toByte() })
    }

    @Test
    fun `a key that cannot be read shows load failed and no send button`() {
        software = { throw IllegalStateException("store unreadable") }
        val sheet = openBound()
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_load_failed, "store unreadable"))
        assertEquals(View.VISIBLE, container(sheet).visibility)
        assertEquals(View.GONE, button(sheet).visibility)
    }

    @Test
    fun `a key with a public PEM shows ready and the send button`() {
        val sheet = openReady()
        assertEquals(View.VISIBLE, button(sheet).visibility)
        assertTrue(button(sheet).isEnabled)
    }

    // -----------------------------------------------------------------
    // Send
    // -----------------------------------------------------------------

    @Test
    fun `send shows sending with the button disabled until the reply`() {
        sender.neverReply()
        val sheet = openReady()
        button(sheet).performClick()
        assertEquals(app.getString(R.string.sharing_desktop_sending), status(sheet).text.toString())
        assertFalse(button(sheet).isEnabled)

        waitUntil("the request was never sent") { sender.sent.size == 1 }
        assertEquals(app.getString(R.string.sharing_desktop_sending), status(sheet).text.toString())
        assertFalse(button(sheet).isEnabled)

        runBlocking {
            router.processMessage(
                """{"id":${sender.lastRequest.id},"result":{"accepted":true,"import_id":"shared-k","backend":"software"}}"""
                    .toByteArray()
            )
        }
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_sent, "shared-k"))
        assertTrue(button(sheet).isEnabled)
    }

    @Test
    fun `an accepted reply shows sent with the import id`() {
        sender.succeedWith("""{"accepted":true,"import_id":"shared-k","backend":"software"}""")
        val sheet = openReady()
        button(sheet).performClick()
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_sent, "shared-k"))
        assertEquals(1, sender.sent.size)
        assertEquals("remote.sharePublicKey", sender.lastRequest.method)
        assertTrue(button(sheet).isEnabled)
    }

    @Test
    fun `a declined reply shows declined`() {
        sender.succeedWith("""{"accepted":false,"import_id":"","backend":"software"}""")
        val sheet = openReady()
        button(sheet).performClick()
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_declined))
        assertTrue(button(sheet).isEnabled)
    }

    @Test
    fun `a desktop error reply shows failed and enables the button again`() {
        sender.failWith(-32000, "import refused")
        val sheet = openReady()
        button(sheet).performClick()
        val prefix = app.getString(R.string.sharing_desktop_failed, "")
        waitUntil("the failure was never shown") { status(sheet).text.startsWith(prefix) }
        assertTrue(status(sheet).text.toString(), status(sheet).text.contains("import refused"))
        assertTrue(button(sheet).isEnabled)
    }

    @Test
    fun `a timeout shows failed and enables the button again`() {
        sender.neverReply()
        val sheet = openReady()
        button(sheet).performClick()
        waitUntil("the request was never sent") { sender.sent.size == 1 }
        assertFalse(button(sheet).isEnabled)

        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        val prefix = app.getString(R.string.sharing_desktop_failed, "")
        waitUntil("the timeout was never shown") { status(sheet).text.startsWith(prefix) }
        assertTrue(button(sheet).isEnabled)
    }

    @Test
    fun `a session replaced before the send sends nothing and refreshes the section`() {
        val sheet = openReady()
        var replaceOnLoad = true
        software = {
            if (replaceOnLoad) {
                replaceOnLoad = false
                sender.connection = Any()
            }
            null
        }
        button(sheet).performClick()
        waitUntil("the session was never replaced") { !replaceOnLoad }
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_ready))
        settle()
        assertTrue("nothing may be sent on a replaced session", sender.sent.isEmpty())
        assertEquals(View.VISIBLE, button(sheet).visibility)
        assertTrue(button(sheet).isEnabled)
    }

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    @Test
    fun `onStop unbinds the service once`() {
        openReady()
        val c = controller!!
        c.pause().stop()
        settle()
        assertEquals(1, shadowOf(app).unboundServiceConnections.size)
        c.destroy()
        controller = null
        settle()
        assertEquals(1, shadowOf(app).unboundServiceConnections.size)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun serviceComponent() = ComponentName(app, XKeyGattService::class.java)

    private fun bindService() {
        shadowOf(app).setComponentNameAndServiceForBindService(serviceComponent(), service.LocalBinder())
    }

    private fun open(): KeySharingBottomSheet {
        val c = Robolectric.buildActivity(HostActivity::class.java).setup()
        controller = c
        val fm = c.get().supportFragmentManager
        KeySharingBottomSheet.show(fm, KEY_ID)
        fm.executePendingTransactions()
        shadowOf(Looper.getMainLooper()).idle()
        return fm.fragments.filterIsInstance<KeySharingBottomSheet>().single()
    }

    private fun openBound(): KeySharingBottomSheet {
        bindService()
        return open()
    }

    private fun openReady(): KeySharingBottomSheet {
        val sheet = openBound()
        waitForStatus(sheet, app.getString(R.string.sharing_desktop_ready))
        settle()
        assertEquals(View.VISIBLE, container(sheet).visibility)
        assertEquals(View.VISIBLE, button(sheet).visibility)
        return sheet
    }

    private fun button(sheet: KeySharingBottomSheet): MaterialButton {
        val label = app.getString(R.string.sharing_desktop_send_public)
        return findAll(sheet.requireView()).filterIsInstance<MaterialButton>().single { it.text.toString() == label }
    }

    private fun container(sheet: KeySharingBottomSheet): LinearLayout = button(sheet).parent as LinearLayout

    private fun status(sheet: KeySharingBottomSheet): TextView = container(sheet).getChildAt(1) as TextView

    private fun findAll(view: View): List<View> =
        if (view is ViewGroup) listOf(view) + (0 until view.childCount).flatMap { findAll(view.getChildAt(it)) }
        else listOf(view)

    private fun waitForStatus(sheet: KeySharingBottomSheet, expected: String) {
        waitUntil("status never became \"$expected\"; it is \"${status(sheet).text}\"") {
            container(sheet).visibility == View.VISIBLE && status(sheet).text.toString() == expected
        }
    }

    /** Runs the main looper until [done], while the sheet's IO loads finish on their own thread. */
    private fun waitUntil(what: String, done: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5_000
        while (true) {
            shadowOf(Looper.getMainLooper()).idle()
            if (done()) return
            if (System.currentTimeMillis() > deadline) fail(what)
            Thread.sleep(5)
        }
    }

    /** Lets every refresh in flight finish. */
    private fun settle() {
        val until = System.currentTimeMillis() + 200
        while (System.currentTimeMillis() < until) {
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(5)
        }
        shadowOf(Looper.getMainLooper()).idle()
    }

    /** A screen with the app theme, which the Material sheet needs. */
    open class HostActivity : FragmentActivity() {
        override fun onCreate(savedInstanceState: Bundle?) {
            setTheme(R.style.Theme_xKey)
            super.onCreate(savedInstanceState)
        }
    }

    private companion object {
        const val KEY_ID = "desk-key"
        const val PEER = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
        const val PEM = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"

        fun entityWith(policy: EntitySharingPolicyType) = KeyEntity(
            keyId = KEY_ID,
            keyType = "signing",
            algorithm = "EC",
            label = "Desktop key",
            keySizeBits = 256,
            exportable = false,
            shareable = policy != EntitySharingPolicyType.PRIVATE,
            sharingPolicy = policy,
            source = "local"
        )
    }
}
