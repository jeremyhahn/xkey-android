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
package com.automatethethings.xkey.ui

import android.app.Application
import android.widget.ImageButton
import com.automatethethings.xkey.R
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.OTHER_PEER
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.backend
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.idle
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.info
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.key
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.publicKey
import com.google.android.material.appbar.MaterialToolbar
import io.mockk.Called
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.IOException

/**
 * How [DesktopKeysActivity] binds the service, follows the desktop session,
 * goes back, retries and survives recreation.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class DesktopKeysActivityLifecycleTest {

    private lateinit var desktop: DesktopKeysTestService
    private val client get() = desktop.client

    private val tpm = backend()

    @Before
    fun setUp() {
        desktop = DesktopKeysTestService().register()
        coEvery { client.listBackends() } returns listOf(tpm)
        coEvery { client.listKeys("tpm", any()) } returns listOf(key())
        coEvery { client.getKeyInfo("tpm", "k1") } returns info()
        coEvery { client.getPublicKey("tpm", "k1", any()) } returns publicKey()
    }

    @After
    fun tearDown() = unmockkAll()

    private fun DesktopKeysActivity.assertNoSession() {
        assertFalse(shown(R.id.desktopKeysProgress))
        assertFalse(shown(R.id.listDesktopKeys))
        assertFalse(shown(R.id.desktopKeyDetail))
        assertEquals(getString(R.string.desktop_keys_no_session), message())
    }

    private fun DesktopKeysActivity.assertBackends() {
        assertTrue(shown(R.id.listDesktopKeys))
        assertEquals(getString(R.string.desktop_keys_backends_header), text(R.id.textDesktopKeysHeader))
        assertEquals(listOf("tpm"), rows().map { it.first })
    }

    private fun DesktopKeysActivity.assertKeys() {
        assertTrue(shown(R.id.listDesktopKeys))
        assertEquals(getString(R.string.desktop_keys_keys_header, "tpm"), text(R.id.textDesktopKeysHeader))
        assertEquals(listOf("laptop ssh"), rows().map { it.first })
    }

    private fun DesktopKeysActivity.assertDetail() {
        assertTrue(shown(R.id.desktopKeyDetail))
        assertFalse(shown(R.id.listDesktopKeys))
        assertTrue(text(R.id.textDesktopKeyInfo).startsWith("ID: k1"))
    }

    @Test
    fun `a screen opened without a peer shows no session and sends nothing`() {
        val activity = desktop.start(peerExtra = null).get()

        activity.assertNoSession()
        verify { client wasNot Called }
    }

    @Test
    fun `a session with another desktop shows no session and sends nothing`() {
        desktop.peer = OTHER_PEER

        val activity = desktop.start().get()

        activity.assertNoSession()
        verify { client wasNot Called }
    }

    @Test
    fun `no session, or one whose peer is not confirmed yet, shows no session and sends nothing`() {
        // The service reports a session only once its peer is confirmed: an
        // unconfirmed session reaches the screen as no session at all.
        desktop.peer = null

        val activity = desktop.start().get()

        activity.assertNoSession()
        verify { client wasNot Called }
    }

    @Test
    fun `another desktop taking the session clears the screen and the next tap sends nothing`() {
        val activity = desktop.start().get()
        activity.tapRow(0)
        activity.assertKeys()

        desktop.peer = OTHER_PEER
        activity.tapRow(0)

        activity.assertNoSession()
        coVerify(exactly = 0) { client.getKeyInfo(any(), any()) }
    }

    @Test
    fun `one client is adapted once, so every step of the screen goes out on it`() {
        // The controller refuses a source other than the one it opened with:
        // a step reaching the detail proves each step got the same adapted source.
        val activity = desktop.start().get()
        activity.tapRow(0)
        activity.tapRow(0)

        activity.assertDetail()
        coVerify(exactly = 1) { client.listBackends() }
        coVerify(exactly = 1) { client.listKeys("tpm", any()) }
        coVerify(exactly = 1) { client.getKeyInfo("tpm", "k1") }
    }

    @Test
    fun `a new client after a reconnect is refused and gets no request`() {
        val activity = desktop.start().get()
        activity.tapRow(0)
        val reconnected = mockk<RemoteKeyClient>()
        desktop.sessionClient = reconnected

        activity.tapRow(0)

        activity.assertNoSession()
        verify { reconnected wasNot Called }
        coVerify(exactly = 0) { client.getKeyInfo(any(), any()) }
    }

    @Test
    fun `a service connection with a new client shows no session and sends nothing on it`() {
        val activity = desktop.start().get()
        activity.tapRow(0)
        val reconnected = mockk<RemoteKeyClient>()
        desktop.sessionClient = reconnected
        val connection = shadowOf(desktop.app).boundServiceConnections.single()

        connection.onServiceDisconnected(desktop.component)
        connection.onServiceConnected(desktop.component, desktop.binder())
        idle()

        activity.assertNoSession()
        verify { reconnected wasNot Called }
    }


    @Test
    fun `a second service connection on the same session keeps the screen the user is on`() {
        val activity = desktop.start().get()
        activity.tapRow(0)
        activity.tapRow(0)
        activity.assertDetail()
        val connection = shadowOf(desktop.app).boundServiceConnections.single()

        connection.onServiceDisconnected(desktop.component)
        connection.onServiceConnected(desktop.component, desktop.binder())
        idle()

        activity.assertDetail()
        coVerify(exactly = 1) { client.listBackends() }
    }

    @Test
    fun `back walks from detail to keys to backends, then finishes`() {
        val activity = desktop.start().get()
        activity.tapRow(0)
        activity.tapRow(0)
        activity.assertDetail()

        activity.back()
        activity.assertKeys()
        activity.back()
        activity.assertBackends()
        assertFalse(activity.isFinishing)
        activity.back()

        assertTrue(activity.isFinishing)
        coVerify(exactly = 1) { client.listBackends() }
        coVerify(exactly = 1) { client.listKeys("tpm", any()) }
    }

    @Test
    fun `the toolbar's up button goes back one level`() {
        val activity = desktop.start().get()
        activity.tapRow(0)
        val toolbar = activity.findViewById<MaterialToolbar>(R.id.desktopKeysToolbar)

        val up = (0 until toolbar.childCount).map(toolbar::getChildAt).single { it is ImageButton }
        up.performClick()
        idle()

        activity.assertBackends()
        assertFalse(activity.isFinishing)
    }

    @Test
    fun `back cancels a step in flight and its late answer is not shown`() {
        val gate = CompletableDeferred<Unit>()
        coEvery { client.getKeyInfo("tpm", "k1") } coAnswers { gate.await(); info() }
        val activity = desktop.start().get()
        activity.tapRow(0)
        activity.tapRow(0)
        assertTrue(activity.shown(R.id.desktopKeysProgress))

        activity.back()
        gate.complete(Unit)
        idle()

        activity.assertBackends()
        assertFalse(activity.shown(R.id.desktopKeysProgress))
        assertFalse(activity.isFinishing)
        coVerify(exactly = 0) { client.getPublicKey(any(), any(), any()) }
    }

    @Test
    fun `the Snackbar's retry repeats the failed step`() {
        var fail = true
        coEvery { client.listKeys("tpm", any()) } coAnswers { if (fail) throw IOException("link down") else listOf(key()) }
        val activity = desktop.start().get()
        activity.tapRow(0)
        activity.assertBackends()
        val retry = activity.snackbarAction()!!

        fail = false
        retry.performClick()
        idle()

        activity.assertKeys()
        coVerify(exactly = 2) { client.listKeys("tpm", any()) }
        coVerify(exactly = 1) { client.listBackends() }
    }


    @Test
    fun `after a back the Snackbar's retry does not reopen the screen the user left`() {
        var fail = true
        coEvery { client.getKeyInfo("tpm", "k1") } coAnswers { if (fail) throw IOException("link down") else info() }
        val activity = desktop.start().get()
        activity.tapRow(0)
        activity.tapRow(0)
        activity.assertKeys()
        val retry = activity.snackbarAction()!!

        activity.back()
        activity.assertBackends()
        fail = false
        retry.performClick()
        idle()

        activity.assertBackends()
        coVerify(exactly = 1) { client.getKeyInfo("tpm", "k1") }
    }

    @Test
    fun `a refused bind leaves Loading for no session and nothing is unbound`() {
        val controller = desktop.refuseBind().start()
        val activity = controller.get()

        activity.assertNoSession()
        verify { client wasNot Called }

        controller.pause().stop().destroy()
        assertTrue(shadowOf(desktop.app).unboundServiceConnections.isEmpty())
    }

    @Test
    fun `onDestroy unbinds the service once`() {
        val controller = desktop.start()
        val connection = shadowOf(desktop.app).boundServiceConnections.single()

        controller.pause().stop().destroy()

        assertEquals(listOf(connection), shadowOf(desktop.app).unboundServiceConnections)
    }

    @Test
    fun `a recreated screen binds and opens again`() {
        val controller = desktop.start()
        controller.get().tapRow(0)

        controller.recreate()
        idle()

        controller.get().assertBackends()
        coVerify(exactly = 2) { client.listBackends() }
        assertEquals(1, shadowOf(desktop.app).unboundServiceConnections.size)
    }
}
