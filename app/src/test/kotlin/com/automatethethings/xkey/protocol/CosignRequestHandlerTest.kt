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
package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Looper
import android.util.Log
import androidx.core.content.ContextCompat
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import java.util.Base64

/**
 * `cosign.request` signs a peer's content hash only after the owner approves
 * it on the phone (#177). The request goes through the real
 * [RequestHandler.handleRequest], so the dispatch error mapping is exercised;
 * the database, keystore and biometric launcher are mocked.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CosignRequestHandlerTest {

    private lateinit var keyDao: KeyDao
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var context: Context
    private lateinit var surface: FakeSurface
    private lateinit var prompts: CosignApprovalPrompts

    /**
     * A prompt surface that records each prompt. It answers at once with
     * [autoAnswer], or leaves the prompt open when that is null.
     */
    private class FakeSurface : CosignPromptSurface {
        class Shown(
            val requestId: String,
            val subtitle: String,
            val onResult: (String, CosignPromptOutcome) -> Unit
        ) {
            fun answer(outcome: CosignPromptOutcome) = onResult(requestId, outcome)
        }

        val shown = mutableListOf<Shown>()
        val dismissed = mutableListOf<String>()
        var autoAnswer: CosignPromptOutcome? = CosignPromptOutcome.Approved

        override fun show(
            requestId: String,
            title: String,
            subtitle: String,
            locked: Boolean,
            onResult: (requestId: String, outcome: CosignPromptOutcome) -> Unit
        ) {
            shown += Shown(requestId, subtitle, onResult)
            autoAnswer?.let { onResult(requestId, it) }
        }

        override fun dismiss(requestId: String) {
            dismissed += requestId
        }
    }

    private val peerHex = "ab".repeat(32)
    private val hashHex = "0123456789abcdef".repeat(4)
    private val signature = ByteArray(64) { 7 }
    private val publicKeyDer = ByteArray(91) { 3 }

    private val signingKey = key("cosign-signing", "signing")
    private val fido2Key = key("cosign-fido2", "fido2")

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        keyDao = mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkObject(AuditLogger)
        every { AuditLogger.logCoSignReceived(any(), any()) } just Runs

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystoreManager = mockk(relaxed = true)
        coEvery { keystoreManager.signWithAlgorithm(any(), any(), any()) } returns signature
        every { keystoreManager.getPublicKeyDER(any()) } returns publicKeyDer

        launcher = mockk(relaxed = true)
        surface = FakeSurface()
        prompts = CosignApprovalPrompts(surface, timeoutMs = PROMPT_TIMEOUT_MS)

        coEvery { keyDao.getByKeyId(signingKey.keyId) } returns signingKey
        coEvery { keyDao.getByKeyId(fido2Key.keyId) } returns fido2Key
        coEvery { keyDao.getAll() } returns listOf(signingKey)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    private fun key(keyId: String, keyType: String) = KeyEntity(
        keyId = keyId,
        keyType = keyType,
        algorithm = "ES256",
        label = "",
        keySizeBits = 256,
        source = "local"
    )

    private fun handler(withLauncher: Boolean = true, peer: String? = peerHex): RequestHandler =
        RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = if (withLauncher) launcher else null,
            sessionAuthManager = null,
            cosignApprovalPrompts = if (withLauncher) prompts else null
        ).also { it.setConnectedDevicePublicKeyHex(peer) }

    private fun request(
        hash: String = hashHex,
        keyId: String? = signingKey.keyId,
        hashAlgorithm: String? = "SHA-256",
        id: Long = 177L
    ) = Request(
        id = id,
        method = MethodNames.COSIGN_REQUEST,
        params = JSONObject().apply {
            put("hash", hash)
            if (keyId != null) put("keyId", keyId)
            if (hashAlgorithm != null) put("hashAlgorithm", hashAlgorithm)
            put("from", "initiator")
        }
    )

    private fun assertError(code: Int, response: Response) {
        assertNull("no result on a refusal", response.result)
        assertEquals(code, response.error?.code)
    }

    private fun assertNothingSigned() {
        coVerify(exactly = 0) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    @Test
    fun `an approved prompt signs the hash with the named key`() = runTest {
        val response = handler().handleRequest(request())

        assertNull(response.error)
        assertNotNull(response.result)
        val result = response.result as JSONObject
        assertEquals(Base64.getEncoder().encodeToString(signature), result.getString("signature"))
        assertEquals("ES256", result.getString("algorithm"))
        assertEquals(signingKey.keyId, result.getString("signerName"))
        assertTrue(result.getString("keyFingerprint").isNotEmpty())
        val subtitle = surface.shown.single().subtitle
        assertTrue(
            "the prompt names the hash: $subtitle",
            subtitle.contains(hashHex.take(8))
        )
        coVerify(exactly = 1) {
            keystoreManager.signWithAlgorithm(signingKey.keyId, any(), "ES256")
        }
    }

    @Test
    fun `a cancelled prompt answers BIOMETRIC_FAILED and signs nothing`() = runTest {
        surface.autoAnswer = CosignPromptOutcome.Refused("Authentication cancelled")

        assertError(ErrorCodes.BIOMETRIC_FAILED, handler().handleRequest(request()))
        assertNothingSigned()
    }

    @Test
    fun `no biometric launcher answers BIOMETRIC_FAILED and signs nothing`() = runTest {
        assertError(
            ErrorCodes.BIOMETRIC_FAILED,
            handler(withLauncher = false).handleRequest(request())
        )
        assertNothingSigned()
    }

    @Test
    fun `no confirmed peer answers OPERATION_DENIED`() = runTest {
        assertError(ErrorCodes.OPERATION_DENIED, handler(peer = null).handleRequest(request()))
        assertNothingSigned()
        assertTrue("no prompt for a refused peer", surface.shown.isEmpty())
    }

    @Test
    fun `a named fido2 key answers OPERATION_DENIED`() = runTest {
        assertError(
            ErrorCodes.OPERATION_DENIED,
            handler().handleRequest(request(keyId = fido2Key.keyId))
        )
        assertNothingSigned()
    }

    @Test
    fun `the fallback key skips a fido2 key`() = runTest {
        coEvery { keyDao.getAll() } returns listOf(fido2Key, signingKey)

        val response = handler().handleRequest(request(keyId = null))

        assertNull(response.error)
        coVerify(exactly = 1) {
            keystoreManager.signWithAlgorithm(signingKey.keyId, any(), any())
        }
        coVerify(exactly = 0) {
            keystoreManager.signWithAlgorithm(fido2Key.keyId, any(), any())
        }
    }

    @Test
    fun `the fallback with only a fido2 key finds no signing key`() = runTest {
        coEvery { keyDao.getAll() } returns listOf(fido2Key)

        assertError(
            ErrorCodes.KEY_NOT_FOUND,
            handler().handleRequest(request(keyId = null))
        )
        assertNothingSigned()
    }

    @Test
    fun `a 31-byte hash answers INVALID_PARAMS`() = runTest {
        assertError(
            ErrorCodes.INVALID_PARAMS,
            handler().handleRequest(request(hash = "ab".repeat(31)))
        )
        assertNothingSigned()
    }

    @Test
    fun `an unknown hashAlgorithm answers INVALID_PARAMS`() = runTest {
        assertError(
            ErrorCodes.INVALID_PARAMS,
            handler().handleRequest(request(hashAlgorithm = "MD5"))
        )
        assertNothingSigned()
    }

    private val blePeerHex = "b1".repeat(32)
    private val usbPeerHex = "cc".repeat(32)
    private val strangerHex = "dd".repeat(32)

    /** A handler whose paired-device store knows [paired]. */
    private fun pairedHandler(vararg paired: String): RequestHandler {
        val repo = mockk<PairedDeviceRepository>()
        every { repo.isDeviceKnown(any()) } answers { firstArg<String>() in paired }
        return RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = launcher,
            sessionAuthManager = null,
            pairedDeviceRepository = repo,
            cosignApprovalPrompts = prompts
        )
    }

    /** Handles [request] as if it arrived on the served connection of [peer]. */
    private suspend fun RequestHandler.onConnection(peer: String?, request: Request): Response =
        withContext(RequestHandler.servedConnection(SessionBindingProvider { null }, peer)) {
            handleRequest(request)
        }

    @Test
    fun `tearing down a USB connection leaves a confirmed BLE peer co-signing`() = runTest {
        val handler = pairedHandler(blePeerHex, usbPeerHex)
        // BLE confirms its peer, then USB confirms a different one: the
        // handler-wide identity is the last one confirmed.
        handler.setConnectedDevicePublicKeyHex(blePeerHex)
        handler.setConnectedDevicePublicKeyHex(usbPeerHex)
        // USB tears down and clears the handler-wide identity.
        handler.setConnectedDevicePublicKeyHex(null)

        val response = handler.onConnection(blePeerHex, request())

        assertNull("BLE co-sign still answers: ${response.error?.message}", response.error)
        coVerify(exactly = 1) {
            keystoreManager.signWithAlgorithm(signingKey.keyId, any(), "ES256")
        }
    }

    @Test
    fun `an unconfirmed caller peer is denied though another connection is confirmed`() = runTest {
        val handler = pairedHandler(blePeerHex)
        handler.setConnectedDevicePublicKeyHex(blePeerHex)

        assertError(
            ErrorCodes.OPERATION_DENIED,
            handler.onConnection(strangerHex, request())
        )
        assertNothingSigned()
        assertTrue("no prompt for a refused peer", surface.shown.isEmpty())
    }

    @Test
    fun `a caller session with no peer is denied though another connection is confirmed`() = runTest {
        val handler = pairedHandler(blePeerHex)
        handler.setConnectedDevicePublicKeyHex(blePeerHex)

        assertError(ErrorCodes.OPERATION_DENIED, handler.onConnection(null, request()))
        assertNothingSigned()
    }

    // r3: one prompt at a time, each settled only by its own answer.

    @Test
    fun `a second co-sign waits for the first prompt, then gets its own`() = runTest {
        surface.autoAnswer = null
        val handler = handler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()
        assertEquals("the second waits while the first prompt is up", 1, surface.shown.size)

        surface.shown[0].answer(CosignPromptOutcome.Approved)
        runCurrent()
        assertEquals("the second gets its own prompt", 2, surface.shown.size)
        assertNotEquals(surface.shown[0].requestId, surface.shown[1].requestId)

        // A late answer to the first prompt settles nothing.
        surface.shown[0].answer(CosignPromptOutcome.Approved)
        runCurrent()
        assertTrue("the second still waits for its own answer", second.isActive)

        surface.shown[1].answer(CosignPromptOutcome.Refused("Authentication cancelled"))
        assertNull(first.await().error)
        assertEquals(1L, first.await().id)
        assertError(ErrorCodes.BIOMETRIC_FAILED, second.await())
        assertEquals(2L, second.await().id)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
        assertEquals(surface.shown.map { it.requestId }, surface.dismissed)
    }

    @Test
    fun `a prompt that never settles fails at its timeout and releases the next`() = runTest {
        surface.autoAnswer = null
        val handler = handler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()

        advanceTimeBy(PROMPT_TIMEOUT_MS + 1)
        runCurrent()
        assertError(ErrorCodes.BIOMETRIC_FAILED, first.await())
        assertEquals(listOf(surface.shown[0].requestId), surface.dismissed)
        assertEquals("the timeout releases the next prompt", 2, surface.shown.size)

        surface.shown[1].answer(CosignPromptOutcome.Approved)
        assertNull(second.await().error)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    @Test
    fun `a cancelled caller takes its prompt down and releases the next`() = runTest {
        surface.autoAnswer = null
        val handler = handler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()

        first.cancel()
        runCurrent()
        assertEquals(listOf(surface.shown[0].requestId), surface.dismissed)
        assertEquals(2, surface.shown.size)

        surface.shown[1].answer(CosignPromptOutcome.Approved)
        assertNull(second.await().error)
    }

    private val promptIntent = mockk<Intent>(relaxed = true)
    private val resultReceiver = slot<BroadcastReceiver>()
    private val launchedId = slot<String>()
    private val notifiedId = slot<String>()
    private val notifiedIntents = mutableListOf<Intent?>()
    private val notificationHelper = mockk<BiometricNotificationHelper>(relaxed = true)

    /** A handler on a locked phone whose prompts go through the real activity surface. */
    private fun lockedPhoneHandler(): RequestHandler {
        val keyguard = mockk<KeyguardManager>()
        every { keyguard.isKeyguardLocked } returns true
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns keyguard

        mockkStatic(ContextCompat::class)
        every {
            ContextCompat.registerReceiver(any(), capture(resultReceiver), any(), any<Int>())
        } returns null
        mockkObject(TransparentBiometricActivity.Companion)
        every {
            TransparentBiometricActivity.createIntent(
                any(), capture(launchedId), any(), any(), any(), any()
            )
        } returns promptIntent
        every {
            notificationHelper.showBiometricRequiredNotification(
                any(), any(), capture(notifiedId), any(), any(), captureNullable(notifiedIntents)
            )
        } just Runs

        return RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = launcher,
            sessionAuthManager = null,
            cosignApprovalPrompts = CosignApprovalPrompts(
                ActivityCosignPromptSurface(context, notificationHelper),
                timeoutMs = PROMPT_TIMEOUT_MS
            )
        ).also { it.setConnectedDevicePublicKeyHex(peerHex) }
    }

    /** The broadcast the prompt activity sends when the owner answers [requestId]. */
    private fun promptResult(requestId: String, approved: Boolean): Intent {
        val intent = mockk<Intent>()
        every { intent.action } returns TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT
        every {
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)
        } returns requestId
        every {
            intent.getBooleanExtra(TransparentBiometricActivity.EXTRA_SUCCESS, false)
        } returns approved
        every {
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_ERROR_MESSAGE)
        } returns "Authentication cancelled"
        return intent
    }

    @Test
    fun `the lock-screen notification opens the co-sign's own prompt`() = runTest {
        val response = async { lockedPhoneHandler().handleRequest(request()) }
        runCurrent()

        assertEquals("one request id for both launches", launchedId.captured, notifiedId.captured)
        assertSame("the notification carries the prompt's intent", promptIntent, notifiedIntents.single())
        verify { context.startActivity(promptIntent) }

        // An answer to another prompt (the launcher's numeric ids) settles nothing.
        resultReceiver.captured.onReceive(context, promptResult("1", approved = true))
        runCurrent()
        assertTrue(response.isActive)

        // The owner approves the prompt the notification opened.
        resultReceiver.captured.onReceive(context, promptResult(notifiedId.captured, approved = true))
        assertNull(response.await().error)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(signingKey.keyId, any(), "ES256") }
        verify { context.unregisterReceiver(resultReceiver.captured) }
        verify { notificationHelper.cancelNotification() }
    }

    @Test
    fun `cancelling the lock-screen prompt answers BIOMETRIC_FAILED`() = runTest {
        val response = async { lockedPhoneHandler().handleRequest(request()) }
        runCurrent()

        resultReceiver.captured.onReceive(context, promptResult(notifiedId.captured, approved = false))
        assertError(ErrorCodes.BIOMETRIC_FAILED, response.await())
        assertNothingSigned()
    }

    // r4: a co-sign's prompt is gone before the next one launches.

    /**
     * The single-top prompt activity as the phone shows it. A launch over a
     * visible prompt is dropped (the activity reads its request only when
     * created), a cancel finishes it only for its own request id, and the
     * owner answers whatever prompt is visible.
     */
    private inner class FakeScreen {
        var visible: String? = null
        val receivers = mutableListOf<BroadcastReceiver>()
        private val launchIds = mutableMapOf<Intent, String>()
        private val cancelIds = mutableMapOf<Intent, String>()

        init {
            mockkStatic(ContextCompat::class)
            every {
                ContextCompat.registerReceiver(any(), capture(receivers), any(), any<Int>())
            } returns null
            every { context.unregisterReceiver(any()) } answers {
                receivers.remove(firstArg<BroadcastReceiver>())
                Unit
            }
            mockkObject(TransparentBiometricActivity.Companion)
            every {
                TransparentBiometricActivity.createIntent(any(), any(), any(), any(), any(), any())
            } answers { mockk<Intent>(relaxed = true).also { launchIds[it] = secondArg() } }
            every { TransparentBiometricActivity.createCancelIntent(any(), any()) } answers {
                mockk<Intent>(relaxed = true).also { cancelIds[it] = secondArg() }
            }
            every { context.startActivity(any()) } answers {
                if (visible == null) visible = launchIds[firstArg()]
            }
            every { context.sendBroadcast(any()) } answers {
                val cancelled = cancelIds[firstArg()]
                if (cancelled != null && cancelled == visible) finish(approved = false)
            }
        }

        /** The owner answers the visible prompt. */
        fun answer(approved: Boolean) = finish(approved)

        private fun finish(approved: Boolean) {
            val requestId = checkNotNull(visible) { "no prompt is visible" }
            visible = null
            val result = promptResult(requestId, approved)
            receivers.toList().forEach { it.onReceive(context, result) }
        }
    }

    /** A handler on an unlocked phone whose prompts go through the real activity surface. */
    private fun activityHandler(biometricLauncher: BiometricActivityLauncher = launcher) =
        RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = biometricLauncher,
            sessionAuthManager = null,
            cosignApprovalPrompts = CosignApprovalPrompts(
                ActivityCosignPromptSurface(context, notificationHelper),
                timeoutMs = PROMPT_TIMEOUT_MS
            )
        ).also { it.setConnectedDevicePublicKeyHex(peerHex) }

    @Test
    fun `a cancelled caller's prompt is gone before the next co-sign shows its own`() = runTest {
        val screen = FakeScreen()
        val handler = activityHandler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()
        val firstPrompt = screen.visible
        assertNotNull(firstPrompt)

        first.cancel()
        runCurrent()
        assertNotNull("the next co-sign's prompt is up", screen.visible)
        assertNotEquals("the cancelled prompt is gone", firstPrompt, screen.visible)

        screen.answer(approved = true)
        assertNull(second.await().error)
        assertEquals(2L, second.await().id)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    @Test
    fun `a timed-out prompt is gone before the next co-sign shows its own`() = runTest {
        val screen = FakeScreen()
        val handler = activityHandler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()
        val firstPrompt = screen.visible
        assertNotNull(firstPrompt)

        advanceTimeBy(PROMPT_TIMEOUT_MS + 1)
        runCurrent()
        assertError(ErrorCodes.BIOMETRIC_FAILED, first.await())
        assertNotNull("the next co-sign's prompt is up", screen.visible)
        assertNotEquals("the timed-out prompt is gone", firstPrompt, screen.visible)

        screen.answer(approved = true)
        assertNull(second.await().error)
        assertEquals(2L, second.await().id)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    @Ignore("serialized with the launcher's prompt queue in issue #178")
    @Test
    fun `a co-sign prompt and a launcher prompt each settle by their own prompt`() = runTest {
        val screen = FakeScreen()
        every { AuditLogger.logBiometricSuccess(any()) } just Runs
        val sharedLauncher = BiometricActivityLauncher(context).also { it.register() }
        val handler = activityHandler(sharedLauncher)
        val cosign = async { handler.handleRequest(request(id = 1L)) }
        runCurrent()
        // The prompt local.signFido2Assertion asks for when verification is required.
        val assertion = async {
            runCatching { sharedLauncher.requestAuthentication("xKey", "Sign in to example.com") }
        }
        runCurrent()

        screen.answer(approved = true)
        runCurrent()
        assertNull("the co-sign settles by its own prompt", cosign.await().error)
        assertNotNull("the launcher's prompt follows the co-sign's", screen.visible)

        screen.answer(approved = true)
        runCurrent()
        assertTrue("the assertion settles by its own prompt", assertion.await().isSuccess)
    }

    private companion object {
        const val PROMPT_TIMEOUT_MS = 60_000L
    }
}
