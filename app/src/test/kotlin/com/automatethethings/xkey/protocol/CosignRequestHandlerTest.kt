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
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import io.mockk.Runs

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.CoroutineScope
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * `cosign.request` signs a peer's content hash only after the owner approves
 * it on the phone (#177). The request goes through the real
 * [RequestHandler.handleRequest], so the dispatch error mapping is exercised,
 * and its prompt through a real [BiometricActivityLauncher], so it takes its
 * turn in the one [PromptOwnership] queue with every other prompt; the
 * database, keystore and the prompt activity ([FakeScreen]) are stand-ins.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CosignRequestHandlerTest {

    private lateinit var keyDao: KeyDao
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var context: Context
    private lateinit var screen: FakeScreen

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
        every { AuditLogger.logBiometricSuccess(any()) } just Runs
        every { AuditLogger.logBiometricFailure(any(), any()) } just Runs

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        mockkObject(BiometricNotificationHelper.Companion)
        every { BiometricNotificationHelper.intentData(any()) } returns mockk(relaxed = true)

        keystoreManager = mockk(relaxed = true)
        coEvery { keystoreManager.signWithAlgorithm(any(), any(), any()) } returns signature
        every { keystoreManager.getPublicKeyDER(any()) } returns publicKeyDer

        // The screen first: the launcher registers its result receivers with it.
        screen = FakeScreen()
        launcher = BiometricActivityLauncher(context).also { it.register() }

        coEvery { keyDao.getByKeyId(signingKey.keyId) } returns signingKey
        coEvery { keyDao.getByKeyId(fido2Key.keyId) } returns fido2Key
        coEvery { keyDao.getAll() } returns listOf(signingKey)
    }

    @After
    fun tearDown() {
        PromptOwnership.process.forgetSettled()
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
            sessionAuthManager = null
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
        assertEquals(response.error?.message, code, response.error?.code)
    }

    private fun assertNothingSigned() {
        coVerify(exactly = 0) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
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
            intent.getIntExtra(TransparentBiometricActivity.EXTRA_ERROR_CODE, any())
        } returns BiometricPrompt.ERROR_USER_CANCELED
        every {
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_ERROR_MESSAGE)
        } returns "Authentication cancelled"
        return intent
    }

    /**
     * The single-top prompt activity as the phone shows it, by main's rules.
     * An activity created for a request the process owner does not hold
     * ACTIVE, or one ended unshown, finishes without prompting (its claim);
     * a start that reaches the visible activity replaces it only for a newer
     * ACTIVE launcher request (its onNewIntent), and is dropped otherwise;
     * the owner answers whatever prompt is visible.
     *
     * With [autoAnswer] set the owner answers each prompt as it comes up.
     * With [deferredCreate] startActivity only queues the launch, as on the
     * phone: the activity comes up at [createNext].
     */
    private inner class FakeScreen {
        var autoAnswer: Boolean? = true
        var deferredCreate = false
        var visible: String? = null

        /** Every prompt that came up on the screen, in order. */
        val shown = mutableListOf<String>()

        /** Every prompt started, in order, and the subtitles they were built with. */
        val launched = mutableListOf<String>()
        val subtitles = mutableListOf<String>()
        val intents = mutableListOf<Intent>()

        private val receivers = mutableListOf<BroadcastReceiver>()
        private val launchIds = mutableMapOf<Intent, String>()
        private val launching = ArrayDeque<String>()
        private val endedUnshown = mutableSetOf<String>()

        /** The started prompts whose activities are not created yet. */
        val launchingIds: List<String> get() = launching.toList()

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
            } answers {
                subtitles += arg<String>(3)
                mockk<Intent>(relaxed = true).also { launchIds[it] = secondArg() }
            }
            every { TransparentBiometricActivity.expireUnshown(any()) } answers {
                val requestId = firstArg<String>()
                if (requestId == visible) {
                    false
                } else {
                    endedUnshown += requestId
                    true
                }
            }
            every { context.startActivity(any()) } answers {
                val intent = firstArg<Intent>()
                val requestId = launchIds.getValue(intent)
                launched += requestId
                intents += intent
                if (deferredCreate) launching.addLast(requestId) else create(requestId)
            }
        }

        private fun owns(requestId: String): Boolean {
            val key = if (requestId.toLongOrNull() != null) NotificationKeys.approval(requestId) else requestId
            return PromptOwnership.process.state(key) == PromptOwnership.State.ACTIVE
        }

        private fun create(requestId: String) {
            val current = visible
            if (current != null) {
                if (!TransparentBiometricActivity.isNewer(requestId, current) || !owns(requestId)) return
                // Replaced: it answers cancelled and a fresh instance starts
                visible = null
                deliver(current, approved = false)
            }
            if (requestId in endedUnshown || !owns(requestId)) return
            visible = requestId
            shown += requestId
            autoAnswer?.let { answer(it) }
        }

        /** The oldest started prompt's activity is created. */
        fun createNext() = create(launching.removeFirst())

        /** The owner answers the visible prompt. */
        fun answer(approved: Boolean) {
            val requestId = checkNotNull(visible) { "no prompt is visible" }
            visible = null
            deliver(requestId, approved)
        }

        /** A result broadcast for [requestId], whether or not its prompt is up. */
        fun deliver(requestId: String, approved: Boolean) {
            val result = promptResult(requestId, approved)
            receivers.toList().forEach { it.onReceive(context, result) }
        }
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
        val subtitle = screen.subtitles.single()
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
        screen.autoAnswer = false

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
        assertTrue("no prompt for a refused peer", screen.launched.isEmpty())
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
            pairedDeviceRepository = repo
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
        assertTrue("no prompt for a refused peer", screen.launched.isEmpty())
    }

    @Test
    fun `a caller session with no peer is denied though another connection is confirmed`() = runTest {
        val handler = pairedHandler(blePeerHex)
        handler.setConnectedDevicePublicKeyHex(blePeerHex)

        assertError(ErrorCodes.OPERATION_DENIED, handler.onConnection(null, request()))
        assertNothingSigned()
    }

    // One prompt at a time, each settled only by its own answer.

    @Test
    fun `a second co-sign waits for the first prompt, then gets its own`() = runTest {
        screen.autoAnswer = null
        val handler = handler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()
        assertEquals("the second waits while the first prompt is up", 1, screen.launched.size)
        val firstPrompt = checkNotNull(screen.visible)

        screen.answer(approved = true)
        runCurrent()
        assertEquals("the second gets its own prompt", 2, screen.shown.size)
        assertNotEquals(firstPrompt, screen.visible)

        // A late answer to the first prompt settles nothing.
        screen.deliver(firstPrompt, approved = true)
        runCurrent()
        assertTrue("the second still waits for its own answer", second.isActive)

        screen.answer(approved = false)
        assertNull(first.await().error)
        assertEquals(1L, first.await().id)
        assertError(ErrorCodes.BIOMETRIC_FAILED, second.await())
        assertEquals(2L, second.await().id)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    @Test
    fun `a timed-out prompt is gone before the next co-sign shows its own`() = runTest {
        screen.autoAnswer = null
        val handler = handler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()
        val firstPrompt = checkNotNull(screen.visible)

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

    @Test
    fun `a cancelled caller's prompt is gone before the next co-sign shows its own`() = runTest {
        screen.autoAnswer = null
        val handler = handler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()
        val firstPrompt = checkNotNull(screen.visible)

        first.cancel()
        runCurrent()
        assertNotNull("the next co-sign's prompt is up", screen.visible)
        assertNotEquals("the cancelled prompt is gone", firstPrompt, screen.visible)

        screen.answer(approved = true)
        assertNull(second.await().error)
        assertEquals(2L, second.await().id)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    // The key chosen before the approval signs only as it still is after it.

    /** Starts a co-sign, and once its prompt is up the stored key becomes [now]. */
    private fun kotlinx.coroutines.test.TestScope.approvedWhileKeyBecomes(
        now: KeyEntity?,
        keyId: String? = signingKey.keyId
    ): Response {
        screen.autoAnswer = null
        val response = async { handler().handleRequest(request(keyId = keyId)) }
        runCurrent()
        checkNotNull(screen.visible) { "the co-sign's prompt is up" }
        coEvery { keyDao.getByKeyId(signingKey.keyId) } returns now
        coEvery { keyDao.getAll() } returns listOfNotNull(now)
        screen.answer(approved = true)
        runCurrent()
        return response.getCompleted()
    }

    @Test
    fun `a signing key deleted while its approval waits signs nothing`() = runTest {
        assertError(ErrorCodes.KEY_NOT_FOUND, approvedWhileKeyBecomes(now = null))
        assertNothingSigned()
    }

    @Test
    fun `a signing key replaced under its id while its approval waits signs nothing`() = runTest {
        val replaced = signingKey.copy(id = signingKey.id + 1, publicKeyDer = ByteArray(91) { 9 })
        assertError(ErrorCodes.OPERATION_DENIED, approvedWhileKeyBecomes(now = replaced))
        assertNothingSigned()
    }

    @Test
    fun `a signing key re-policied while its approval waits signs nothing`() = runTest {
        val repolicied = signingKey.copy(
            sharingPolicy = SharingPolicyType.ALL_PEERS,
            policyRevision = signingKey.policyRevision + 1
        )
        assertError(ErrorCodes.OPERATION_DENIED, approvedWhileKeyBecomes(now = repolicied))
        assertNothingSigned()
    }

    @Test
    fun `the fallback signing key is checked again after its approval`() = runTest {
        assertError(ErrorCodes.KEY_NOT_FOUND, approvedWhileKeyBecomes(now = null, keyId = null))
        assertNothingSigned()
    }

    @Test
    fun `a signing key only used elsewhere while its approval waits still signs`() = runTest {
        val used = signingKey.copy(useCount = signingKey.useCount + 1, lastUsedAt = 42L)
        assertNull(approvedWhileKeyBecomes(now = used).error)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(signingKey.keyId, any(), "ES256") }
    }

    // F1: co-sign and FIDO2 prompts share the one queue, in either order.

    /** The prompt local.signFido2Assertion asks for when verification is required. */
    private fun CoroutineScope.passkeyPrompt() = async {
        runCatching {
            launcher.requestAuthentication("xKey Authentication", "Verify your identity to use this passkey")
        }
    }

    @Test
    fun `a FIDO2 prompt after a co-sign waits for the co-sign's to settle`() = runTest {
        screen.autoAnswer = null
        val cosign = async { handler().handleRequest(request(id = 1L)) }
        runCurrent()
        val cosignPrompt = screen.visible
        assertNotNull("the co-sign's prompt is up", cosignPrompt)

        val assertion = passkeyPrompt()
        runCurrent()
        assertEquals("the passkey prompt is not started over the co-sign's", listOf(cosignPrompt), screen.launched)

        screen.answer(approved = true)
        runCurrent()
        assertNull("the co-sign settles by its own prompt", cosign.await().error)
        val passkey = screen.visible
        assertNotNull("the passkey prompt follows the co-sign's", passkey)
        assertNotEquals(cosignPrompt, passkey)

        screen.answer(approved = true)
        runCurrent()
        assertTrue("the assertion settles by its own prompt", assertion.await().isSuccess)
    }

    @Test
    fun `a co-sign after a FIDO2 prompt waits for the FIDO2 one to settle`() = runTest {
        screen.autoAnswer = null
        val assertion = passkeyPrompt()
        runCurrent()
        val passkey = checkNotNull(screen.visible)

        val cosign = async { handler().handleRequest(request(id = 1L)) }
        runCurrent()
        assertEquals("the co-sign's prompt is not started over the passkey's", listOf(passkey), screen.launched)
        assertTrue(cosign.isActive)

        screen.answer(approved = true)
        runCurrent()
        assertTrue("the assertion settles by its own prompt", assertion.await().isSuccess)
        val cosignPrompt = screen.visible
        assertNotNull("the co-sign's prompt follows the passkey's", cosignPrompt)
        assertNotEquals(passkey, cosignPrompt)

        screen.answer(approved = true)
        assertNull("the co-sign settles by its own prompt", cosign.await().error)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    // F2: a withdrawal is the queue's, so an activity coming up late prompts for nothing.

    @Test
    fun `a co-sign withdrawn before its activity comes up never shows, and the next is answered`() = runTest {
        screen.autoAnswer = null
        screen.deferredCreate = true
        val handler = handler()
        val first = async { handler.handleRequest(request(id = 1L)) }
        val second = async { handler.handleRequest(request(id = 2L)) }
        runCurrent()
        val firstPrompt = screen.launchingIds.single()

        // The caller goes away after startActivity, before the activity's onCreate.
        first.cancel()
        runCurrent()
        assertEquals(
            "the withdrawal hands the screen straight to the next co-sign",
            2,
            screen.launchingIds.size
        )
        val secondPrompt = screen.launchingIds.last()
        assertNotEquals(firstPrompt, secondPrompt)

        screen.createNext()
        assertFalse("the withdrawn prompt never shows", firstPrompt in screen.shown)
        assertNull(screen.visible)

        screen.createNext()
        assertEquals("the next co-sign's prompt is its own", secondPrompt, screen.visible)
        screen.answer(approved = true)
        assertNull(second.await().error)
        assertEquals(2L, second.await().id)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    // A locked phone's notification opens the co-sign's own queued prompt.

    private val notifiedKey = slot<String>()
    private val notifiedIntents = mutableListOf<Intent?>()

    /** A handler on a locked phone; its lock-screen notifications are recorded. */
    private fun lockedPhoneHandler(): RequestHandler {
        val keyguard = mockk<KeyguardManager>()
        every { keyguard.isKeyguardLocked } returns true
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns keyguard
        mockkConstructor(BiometricNotificationHelper::class)
        every {
            anyConstructed<BiometricNotificationHelper>().showBiometricRequiredNotification(
                any(), any(), capture(notifiedKey), any(), any(), captureNullable(notifiedIntents)
            )
        } just Runs
        every { anyConstructed<BiometricNotificationHelper>().cancelNotification(any()) } just Runs
        return handler()
    }

    @Test
    fun `the lock-screen notification opens the co-sign's own prompt`() = runTest {
        screen.autoAnswer = null
        val response = async { lockedPhoneHandler().handleRequest(request()) }
        runCurrent()
        val prompt = checkNotNull(screen.visible)

        assertEquals("one key for both launches", NotificationKeys.approval(prompt), notifiedKey.captured)
        assertSame("the notification carries the prompt's intent", screen.intents.single(), notifiedIntents.single())

        // An answer to another prompt settles nothing.
        screen.deliver("${prompt.toLong() + 1000}", approved = true)
        runCurrent()
        assertTrue(response.isActive)

        screen.answer(approved = true)
        assertNull(response.await().error)
        coVerify(exactly = 1) { keystoreManager.signWithAlgorithm(signingKey.keyId, any(), "ES256") }
        verify { anyConstructed<BiometricNotificationHelper>().cancelNotification(notifiedKey.captured) }
    }

    @Test
    fun `cancelling the lock-screen prompt answers BIOMETRIC_FAILED`() = runTest {
        screen.autoAnswer = false
        assertError(ErrorCodes.BIOMETRIC_FAILED, lockedPhoneHandler().handleRequest(request()))
        assertNothingSigned()
    }

    private companion object {
        const val PROMPT_TIMEOUT_MS = 60_000L
    }
}
