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
import com.automatethethings.xkey.R
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.RemoteSignResult
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.attestation
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.backend
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.idle
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.info
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.key
import com.automatethethings.xkey.ui.DesktopKeysTestService.Companion.publicKey
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import java.text.DateFormat
import java.util.Date

/** What each state of [DesktopKeysActivity] renders and what each tap sends. */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class DesktopKeysActivityUiTest {

    private lateinit var desktop: DesktopKeysTestService
    private val client get() = desktop.client

    private val tpm = backend()
    private val soft = backend(name = "soft", type = "software", hardwareBacked = false, signing = false, attestation = false)

    @Before
    fun setUp() {
        desktop = DesktopKeysTestService().register()
        coEvery { client.listBackends() } returns listOf(tpm, soft)
        coEvery { client.listKeys("tpm", any()) } returns listOf(key(), key(keyId = "k2", label = ""))
        coEvery { client.getKeyInfo("tpm", "k1") } returns info()
        coEvery { client.getPublicKey("tpm", "k1", any()) } returns publicKey()
    }

    @After
    fun tearDown() = unmockkAll()

    /** Opens the screen and walks to the detail of key k1 of [backendRow]. */
    private fun openDetail(backendRow: Int = 0): DesktopKeysActivity {
        val activity = desktop.start().get()
        activity.tapRow(backendRow)
        activity.tapRow(0)
        return activity
    }

    @Test
    fun `the backend list shows each backend's name, type and hardware or software`() {
        val activity = desktop.start().get()

        assertTrue(activity.shown(R.id.listDesktopKeys))
        assertFalse(activity.shown(R.id.desktopKeysProgress))
        assertEquals(activity.getString(R.string.desktop_keys_backends_header), activity.text(R.id.textDesktopKeysHeader))
        assertEquals(listOf("tpm" to "tpm2 · hardware", "soft" to "software · software"), activity.rows())
        coVerify(exactly = 1) { client.listBackends() }
    }

    @Test
    fun `no backends shows the empty text`() {
        coEvery { client.listBackends() } returns emptyList()

        val activity = desktop.start().get()

        assertFalse(activity.shown(R.id.listDesktopKeys))
        assertTrue(activity.shown(R.id.textDesktopKeysHeader))
        assertEquals(activity.getString(R.string.desktop_keys_no_backends), activity.message())
    }

    @Test
    fun `tapping a backend lists its keys, the key id standing in for an empty label`() {
        val activity = desktop.start().get()

        activity.tapRow(0)

        coVerify(exactly = 1) { client.listKeys("tpm", any()) }
        assertEquals(activity.getString(R.string.desktop_keys_keys_header, "tpm"), activity.text(R.id.textDesktopKeysHeader))
        assertEquals(listOf("laptop ssh" to "ECDSA-P256 · 256 bits", "k2" to "ECDSA-P256 · 256 bits"), activity.rows())
    }

    @Test
    fun `a backend with no keys shows the empty text`() {
        coEvery { client.listKeys("soft", any()) } returns emptyList()
        val activity = desktop.start().get()

        activity.tapRow(1)

        coVerify(exactly = 1) { client.listKeys("soft", any()) }
        assertFalse(activity.shown(R.id.listDesktopKeys))
        assertEquals(activity.getString(R.string.desktop_keys_no_keys), activity.message())
    }

    @Test
    fun `tapping a key shows its fields and public key`() {
        val activity = openDetail()

        coVerify(exactly = 1) { client.getKeyInfo("tpm", "k1") }
        coVerify(exactly = 1) { client.getPublicKey("tpm", "k1", any()) }
        assertTrue(activity.shown(R.id.desktopKeyDetail))
        assertFalse(activity.shown(R.id.listDesktopKeys))
        assertFalse(activity.shown(R.id.textDesktopKeysMessage))
        val created = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(1_700_000_000_000L))
        assertEquals(
            listOf(
                "ID: k1", "Label: laptop ssh", "Backend: tpm", "Algorithm: ECDSA-P256", "Size: 256",
                "Created: $created", "Hardware-backed: yes", "Exportable: no"
            ).joinToString("\n"),
            activity.text(R.id.textDesktopKeyInfo)
        )
        assertEquals("Public key (der)", activity.text(R.id.textDesktopKeyPublicKeyHeader))
        assertEquals("MFkwEwYHKoZI", activity.text(R.id.textDesktopKeyPublicKey))
        assertFalse(activity.shown(R.id.textDesktopKeySignTest))
        assertFalse(activity.shown(R.id.textDesktopKeyAttestation))
    }

    @Test
    fun `an empty label shows the no-label text and a created time of zero or below shows the raw number`() {
        coEvery { client.getKeyInfo("tpm", "k1") } returns info(label = "", createdAt = 0L)
        val activity = openDetail()
        val lines = activity.text(R.id.textDesktopKeyInfo).lines()
        assertTrue(lines.toString(), "Label: (no label)" in lines)
        assertTrue(lines.toString(), "Created: 0" in lines)

        activity.back()
        coEvery { client.getKeyInfo("tpm", "k1") } returns info(createdAt = -5L)
        activity.tapRow(0)
        assertTrue("Created: -5" in activity.text(R.id.textDesktopKeyInfo).lines())
    }

    @Test
    fun `a key without a public half shows why in place of the public key`() {
        coEvery { client.getPublicKey("tpm", "k1", any()) } throws
            ProtocolException("no public key", errorCode = ErrorCodes.UNSUPPORTED_FORMAT)

        val activity = openDetail()

        assertTrue(activity.shown(R.id.desktopKeyDetail))
        assertEquals("Public key (ECDSA-P256)", activity.text(R.id.textDesktopKeyPublicKeyHeader))
        assertEquals(
            activity.getString(R.string.desktop_keys_error_remote, "no public key"),
            activity.text(R.id.textDesktopKeyPublicKey)
        )
    }

    @Test
    fun `sign test and attest buttons show only when the backend supports them`() {
        val full = openDetail()
        assertTrue(full.shown(R.id.buttonDesktopKeySignTest))
        assertTrue(full.shown(R.id.buttonDesktopKeyAttest))

        coEvery { client.listKeys("soft", any()) } returns listOf(key(backend = "soft"))
        coEvery { client.getKeyInfo("soft", "k1") } returns info()
        coEvery { client.getPublicKey("soft", "k1", any()) } returns publicKey()
        full.back()
        full.back()
        full.tapRow(1)
        full.tapRow(0)

        assertTrue(full.shown(R.id.desktopKeyDetail))
        assertFalse(full.shown(R.id.buttonDesktopKeySignTest))
        assertFalse(full.shown(R.id.buttonDesktopKeyAttest))
    }

    @Test
    fun `the sign test signs, verifies and shows a valid signature with its algorithm`() {
        coEvery { client.sign("tpm", "k1", DesktopKeysController.TEST_MESSAGE_BASE64, any()) } returns
            RemoteSignResult(signature = "c2ln", algorithm = "ES256")
        coEvery { client.verify("tpm", "k1", DesktopKeysController.TEST_MESSAGE_BASE64, "c2ln", "ES256") } returns true
        val activity = openDetail()

        activity.tap(R.id.buttonDesktopKeySignTest)

        coVerify(exactly = 1) { client.sign("tpm", "k1", DesktopKeysController.TEST_MESSAGE_BASE64, any()) }
        coVerify(exactly = 1) { client.verify("tpm", "k1", DesktopKeysController.TEST_MESSAGE_BASE64, "c2ln", "ES256") }
        assertTrue(activity.shown(R.id.textDesktopKeySignTest))
        assertEquals(
            activity.getString(R.string.desktop_keys_sign_test_valid, "ES256"),
            activity.text(R.id.textDesktopKeySignTest)
        )
    }

    @Test
    fun `the sign test shows a signature the desktop does not verify as invalid`() {
        coEvery { client.sign("tpm", "k1", any(), any()) } returns RemoteSignResult(signature = "c2ln", algorithm = "ES256")
        coEvery { client.verify("tpm", "k1", any(), "c2ln", "ES256") } returns false
        val activity = openDetail()

        activity.tap(R.id.buttonDesktopKeySignTest)

        assertEquals(
            activity.getString(R.string.desktop_keys_sign_test_invalid, "ES256"),
            activity.text(R.id.textDesktopKeySignTest)
        )
    }

    @Test
    fun `attest sends the key's attestation request and shows format, certificates, data bytes and nonce`() {
        coEvery { client.attestKey("tpm", "k1", any()) } returns attestation()
        val activity = openDetail()

        activity.tap(R.id.buttonDesktopKeyAttest)

        coVerify(exactly = 1) { client.attestKey("tpm", "k1", any()) }
        assertTrue(activity.shown(R.id.textDesktopKeyAttestation))
        assertEquals(
            activity.getString(R.string.desktop_keys_attest_result, "tpm2", 2, 5, "bm9uY2U="),
            activity.text(R.id.textDesktopKeyAttestation)
        )
    }

    @Test
    fun `both buttons are disabled while a step loads and enabled after it`() {
        val gate = CompletableDeferred<Unit>()
        coEvery { client.attestKey("tpm", "k1", any()) } coAnswers { gate.await(); attestation() }
        val activity = openDetail()
        assertTrue(activity.findViewById<android.view.View>(R.id.buttonDesktopKeyAttest).isEnabled)

        activity.tap(R.id.buttonDesktopKeyAttest)

        assertTrue(activity.shown(R.id.desktopKeysProgress))
        assertTrue("the detail stays on screen while loading", activity.shown(R.id.desktopKeyDetail))
        assertFalse(activity.findViewById<android.view.View>(R.id.buttonDesktopKeySignTest).isEnabled)
        assertFalse(activity.findViewById<android.view.View>(R.id.buttonDesktopKeyAttest).isEnabled)

        gate.complete(Unit)
        idle()

        assertFalse(activity.shown(R.id.desktopKeysProgress))
        assertTrue(activity.findViewById<android.view.View>(R.id.buttonDesktopKeySignTest).isEnabled)
        assertTrue(activity.findViewById<android.view.View>(R.id.buttonDesktopKeyAttest).isEnabled)
    }

    @Test
    fun `the first screen shows the loading text until the backends arrive`() {
        val gate = CompletableDeferred<Unit>()
        coEvery { client.listBackends() } coAnswers { gate.await(); listOf(tpm) }

        val activity = desktop.start().get()

        assertTrue(activity.shown(R.id.desktopKeysProgress))
        assertEquals(activity.getString(R.string.desktop_keys_loading), activity.message())
        assertFalse(activity.shown(R.id.listDesktopKeys))

        gate.complete(Unit)
        idle()
        assertEquals(listOf("tpm" to "tpm2 · hardware"), activity.rows())
    }

    @Test
    fun `each desktop error kind shows its own text`() {
        val cases = listOf(
            ProtocolException("gone", errorCode = ErrorCodes.KEY_NOT_FOUND) to
                { a: DesktopKeysActivity -> a.getString(R.string.desktop_keys_error_key_not_found) },
            ProtocolException("no", errorCode = ErrorCodes.BACKEND_DENIED) to
                { a: DesktopKeysActivity -> a.getString(R.string.desktop_keys_error_denied) },
            ProtocolException("what", errorCode = ErrorCodes.METHOD_NOT_FOUND) to
                { a: DesktopKeysActivity -> a.getString(R.string.desktop_keys_error_unsupported) },
            ProtocolException("bad quote", errorCode = ErrorCodes.ATTESTATION_FAILED) to
                { a: DesktopKeysActivity -> a.getString(R.string.desktop_keys_error_attestation, "bad quote") },
            ProtocolException("busy", errorCode = ErrorCodes.INTERNAL_ERROR) to
                { a: DesktopKeysActivity -> a.getString(R.string.desktop_keys_error_remote, "busy") },
            IOException("link down") to
                { a: DesktopKeysActivity -> a.getString(R.string.desktop_keys_error_transport, "link down") }
        )
        val shown = cases.map { (error, _) ->
            coEvery { client.listBackends() } throws error
            desktop.start().get()
        }
        cases.zip(shown).forEach { (case, activity) ->
            val expected = case.second(activity)
            assertEquals(expected, activity.message())
            assertFalse(activity.shown(R.id.desktopKeysProgress))
            assertEquals(expected, activity.snackbarText())
        }
        val distinct = cases.zip(shown).map { (case, activity) -> case.second(activity) }.toSet()
        assertEquals("every kind has its own text", cases.size, distinct.size)
    }

    @Test
    fun `a not-connected error shows the not-connected text`() {
        // The controller clears to NoSession instead of failing with NOT_CONNECTED,
        // so no step reaches this text; render the state the activity would get.
        val activity = desktop.start().get()
        val render = DesktopKeysActivity::class.java.getDeclaredMethod("render", DesktopKeysState::class.java)
        render.isAccessible = true

        render.invoke(activity, DesktopKeysState.Failed(DesktopKeyError.notConnected, null))
        idle()

        assertEquals(activity.getString(R.string.desktop_keys_error_not_connected), activity.message())
    }

    @Test
    fun `a failure over a list keeps the list and shows the error in a Snackbar`() {
        coEvery { client.listKeys("tpm", any()) } throws IOException("link down")
        val activity = desktop.start().get()

        activity.tapRow(0)

        assertTrue(activity.shown(R.id.listDesktopKeys))
        assertEquals(activity.getString(R.string.desktop_keys_backends_header), activity.text(R.id.textDesktopKeysHeader))
        assertEquals(activity.getString(R.string.desktop_keys_error_transport, "link down"), activity.snackbarText())
        assertEquals(activity.getString(R.string.desktop_keys_retry), activity.snackbarAction()?.text?.toString())
    }
}
