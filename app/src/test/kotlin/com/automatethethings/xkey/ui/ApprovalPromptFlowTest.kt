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
import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.os.Looper
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PendingAuthentications
import com.automatethethings.xkey.auth.PendingCryptoSignatures
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.auth.PromptRequestIds
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.time.Duration
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * `local.setKeyPolicy` approvals on a locked phone, end to end through the
 * real pieces (#178): [RequestHandler], [BiometricActivityLauncher], the
 * lock-screen notification its `onLaunch` posts, and
 * [TransparentBiometricActivity] driven through its lifecycle. Only the key
 * store and the audit log are stand-ins.
 *
 * What these pin: the notification's tap opens the prompt of the request it
 * was posted for, and nothing that would recreate a live prompt; a prompt
 * delivered twice prompts once; a newer request reaching the prompt on screen
 * gets a prompt of its own; a prompt that goes away unanswered fails its
 * request; a queued request that is withdrawn or times out leaves the
 * notification of the request on screen alone; and every result reaches
 * exactly the request it names.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class ApprovalPromptFlowTest {

    private lateinit var app: Application
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var notifications: NotificationManager

    private val keyId = "key-178"
    private val peer = "ab".repeat(32)

    /** The stored sharing policy and its revision. */
    private var stored = SharingPolicyType.PRIVATE
    private var storedRevision = 0L

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        app = RuntimeEnvironment.getApplication()
        notifications = app.getSystemService(NotificationManager::class.java)
        shadowOf(app.getSystemService(KeyguardManager::class.java)).setKeyguardLocked(true)

        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(keyId) } answers { key() }
        // The policy store (#193) over the same stored row.
        val policyDao = mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true)
        coEvery { policyDao.keyInstance(keyId) } returns 1L
        coEvery { policyDao.storedPolicy(keyId) } answers { stored }
        coEvery { policyDao.policyRevision(keyId) } answers { storedRevision }
        coEvery { policyDao.policyRow(keyId) } returns null
        coEvery { policyDao.setKeyPolicy(keyId, any()) } answers {
            stored = secondArg()
            storedRevision++
            1
        }
        mockkObject(com.automatethethings.xkey.storage.KeyPolicyStore.Companion)
        every { com.automatethethings.xkey.storage.KeyPolicyStore.of(any()) } answers {
            com.automatethethings.xkey.storage.KeyPolicyStore(
                policyDao,
                object : com.automatethethings.xkey.storage.KeyPolicyStore.Transactor {
                    override suspend fun <T> run(block: suspend () -> T): T = block()
                },
                java.util.concurrent.ConcurrentHashMap()
            )
        }
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkObject(AuditLogger)
        every { AuditLogger.logKeySharingChanged(any(), any(), any(), any(), any()) } just runs
        every { AuditLogger.logBiometricSuccess(any()) } just runs
        every { AuditLogger.logBiometricFailure(any(), any()) } just runs

        launcher = BiometricActivityLauncher(app).also { it.register() }
    }

    @After
    fun tearDown() {
        // Settles whatever a failed test left waiting, so the process-wide
        // prompt queue is free for the next one.
        launcher.unregister()
        assertEquals("every approval let go of its queue entry", 0, PromptOwnership.process.entries)
        Dispatchers.resetMain()
        unmockkAll()
    }

    private fun key() = KeyEntity(
        id = 1L,
        keyId = keyId,
        keyType = "aes",
        algorithm = "AES-256-GCM",
        label = "Work key",
        keySizeBits = 256,
        shareable = stored != SharingPolicyType.PRIVATE,
        sharingPolicy = stored,
        policyRevision = storedRevision,
        source = "local"
    )

    /** A request handler with the real launcher, whose key store has every signing key. */
    private fun newHandler(): RequestHandler = RequestHandler(
        context = app,
        keystoreManager = mockk<KeystoreManager>(relaxed = true) {
            every { generalKeyExists(any()) } returns true
        },
        biometricLauncher = launcher,
        sessionAuthManager = null
    ).also { it.setConnectedDevicePublicKeyHex(peer) }

    /** A peer's request to share the key with every peer, on [handler] (by default one of its own). */
    private fun TestScope.shareWithAllPeers(handler: RequestHandler = newHandler()): Deferred<Response> = async {
        handler.handleRequest(
            Request(
                id = 178L,
                method = MethodNames.LOCAL_SET_KEY_POLICY,
                params = JSONObject().put("keyId", keyId).put("shareable", true)
            )
        )
    }

    /** A `local.sign` request that needs the owner's verification, on [handler]. */
    private fun TestScope.signWithUserVerification(handler: RequestHandler): Deferred<Response> = async {
        handler.handleRequest(
            Request(
                id = 179L,
                method = MethodNames.LOCAL_SIGN,
                params = JSONObject()
                    .put("keyId", "signing-key")
                    .put("data", Base64.getEncoder().encodeToString("payload".toByteArray()))
                    .put("userVerificationRequired", true)
            )
        )
    }

    /** A `local.generateKey` request that needs the owner's verification, on a handler of its own. */
    private fun TestScope.generateKeyWithUserVerification(): Deferred<Response> = async {
        RequestHandler(
            context = app,
            keystoreManager = mockk<KeystoreManager>(relaxed = true) {
                every { generalKeyExists(any()) } returns false
            },
            biometricLauncher = launcher,
            sessionAuthManager = null
        ).also { it.setConnectedDevicePublicKeyHex(peer) }.handleRequest(
            Request(
                id = 180L,
                method = MethodNames.LOCAL_GENERATE_KEY,
                params = JSONObject()
                    .put("keyId", "new-key")
                    .put("algorithm", "ES256")
                    .put("requireUserVerification", true)
            )
        )
    }

    /**
     * Numbers both prompt families, generic approvals and crypto signatures,
     * from 1 again, as in a freshly started process.
     */
    private fun numberBothFamiliesFromOne() {
        for (family in listOf(PendingAuthentications::class.java, PendingCryptoSignatures::class.java)) {
            val counter = family.getDeclaredField("nextRequestId").apply { isAccessible = true }
            (counter.get(null) as AtomicLong).set(0L)
        }
        // Keys start over too, so the owner forgets the ones that settled.
        PromptOwnership.process.forgetSettled()
    }

    /**
     * A process restart: the launcher and its requests, the prompt owner's
     * memory and the prompt activity's records start over, and both families
     * number their requests as a freshly started process does. What survives
     * is what Android holds, the notifications' pending intents.
     */
    private fun TestScope.restartProcess() {
        launcher.unregister()
        runCurrent()
        for (family in listOf(PendingAuthentications::class.java, PendingCryptoSignatures::class.java)) {
            val counter = family.getDeclaredField("nextRequestId").apply { isAccessible = true }
            (counter.get(null) as AtomicLong).set(PromptRequestIds.firstOfProcess())
        }
        PromptOwnership.process.forgetSettled()
        val expired = TransparentBiometricActivity::class.java.getDeclaredField("expired").apply { isAccessible = true }
        (expired.get(null) as MutableSet<*>).clear()
        launcher = BiometricActivityLauncher(app).also { it.register() }
    }

    /** Delivers what the prompts broadcast, and resumes whoever it settled. */
    private fun TestScope.settle() {
        shadowOf(Looper.getMainLooper()).idle()
        runCurrent()
    }

    /** The prompt the launcher started directly, which Android may also block. */
    private fun directStart(): Intent {
        val started = shadowOf(app).nextStartedActivity
        assertNotNull("a prompt was started", started)
        assertEquals(TransparentBiometricActivity::class.java.name, started.component?.className)
        return started
    }

    private fun Intent.requestId(): String? = getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)

    /** The lock-screen notification posted for [requestId], or null when none is up. */
    private fun notificationFor(requestId: String): Notification? =
        shadowOf(notifications).allNotifications.singleOrNull {
            val opens = shadowOf(it.fullScreenIntent).savedIntent
            opens.component?.className == TransparentBiometricActivity::class.java.name &&
                opens.requestId() == requestId
        }

    /** What tapping [requestId]'s notification (or its full-screen intent firing) starts. */
    private fun tapNotification(requestId: String): Intent {
        val notification = notificationFor(requestId)
        assertNotNull("the notification for $requestId is up", notification)
        val tap = shadowOf(notification!!.contentIntent).savedIntent
        assertEquals(tap.toUri(0), shadowOf(notification.fullScreenIntent).savedIntent.toUri(0))
        return tap
    }

    private fun open(prompt: Intent): ActivityController<TransparentBiometricActivity> =
        Robolectric.buildActivity(TransparentBiometricActivity::class.java, prompt).setup()

    private fun ActivityController<TransparentBiometricActivity>.approve() {
        get().promptCallback!!.onAuthenticationSucceeded(mockk(relaxed = true))
    }

    private fun ActivityController<TransparentBiometricActivity>.cancel() {
        get().onBackPressedDispatcher.onBackPressed()
    }

    /** The result broadcasts sent so far, as request id to success. */
    private fun results(): List<Pair<String?, Boolean>> =
        shadowOf(app).broadcastIntents
            .filter { it.action == TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT }
            .map { it.requestId() to it.getBooleanExtra(TransparentBiometricActivity.EXTRA_SUCCESS, false) }

    private fun assertUpdated(response: Response) {
        assertNull(response.error)
        assertEquals(true, response.result?.getBoolean("updated"))
    }

    @Test
    fun `a tap on the lock-screen notification opens the prompt of the request it was posted for`() = runTest {
        val approval = shareWithAllPeers()
        runCurrent()
        val prompt = directStart()
        val id = prompt.requestId()!!

        val tap = tapNotification(id)
        assertEquals("the tap names the waiting request", id, tap.requestId())
        assertEquals(prompt.component, tap.component)
        assertEquals(
            "the tap shows the request's own prompt",
            prompt.getStringExtra(TransparentBiometricActivity.EXTRA_TITLE),
            tap.getStringExtra(TransparentBiometricActivity.EXTRA_TITLE)
        )
        assertEquals(
            "a tap must not recreate a live prompt (which would answer it as closed)",
            0,
            tap.flags and Intent.FLAG_ACTIVITY_CLEAR_TOP
        )

        // The direct start was blocked: the prompt comes up from the tap.
        open(tap).approve()
        settle()

        assertUpdated(approval.await())
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
        assertEquals(listOf(id to true), results())
        assertNull("the answered request's notification is gone", notificationFor(id))
    }

    @Test
    fun `a wake-only prompt from a second connection waits for the approval on screen`() = runTest {
        val approval = shareWithAllPeers()
        runCurrent()
        val prompt = directStart()
        val id = prompt.requestId()!!

        // local.verifyUser's prompt on another connection, as its handler raises it.
        val wakeKey = NotificationKeys.wakeOnly("verifyUser")
        val answered = CompletableDeferred<Unit>()
        val verifyUser = async {
            PromptOwnership.process.turn(wakeKey) {
                BiometricNotificationHelper(app).showBiometricRequiredNotification("verifyUser", null, wakeKey)
                answered.await()
            }
        }
        runCurrent()

        assertNull("no wake notification while the approval holds the screen", notificationFor(wakeKey))
        val wakeStart = TransparentBiometricActivity.createIntent(app, wakeKey, showOnLockScreen = true)
        assertNull("a wake-only start before its turn shows no prompt", open(wakeStart).get().promptCallback)
        assertThrows(IllegalStateException::class.java) {
            BiometricNotificationHelper(app).showBiometricRequiredNotification("verifyUser", null, wakeKey)
        }

        open(prompt).approve()
        settle()
        assertUpdated(approval.await())
        assertEquals(listOf(id to true), results())

        assertNotNull("the wake notification comes on its turn", notificationFor(wakeKey))
        assertNotNull("its prompt shows on its turn", open(tapNotification(wakeKey)).get().promptCallback)
        answered.complete(Unit)
        verifyUser.await()
    }

    @Test
    fun `a direct launch and its notification carry the same intent identity`() = runTest {
        val approval = shareWithAllPeers()
        runCurrent()
        val prompt = directStart()
        val id = prompt.requestId()!!

        val tap = tapNotification(id)
        // Android matches a launch to the live prompt's task by its intent
        // (component and data): with different data, the tap would start a
        // second prompt instead of reaching the one on screen.
        assertNotNull("the direct launch carries the request's data", prompt.data)
        assertEquals("both launches carry the same data", prompt.data, tap.data)
        assertTrue("the tap matches the direct launch", prompt.filterEquals(tap))

        open(tap).approve()
        settle()
        assertUpdated(approval.await())
    }

    @Test
    fun `a prompt delivered again prompts once, and its cancel fails only its own request`() = runTest {
        val approval = shareWithAllPeers()
        runCurrent()
        val prompt = directStart()
        val id = prompt.requestId()!!
        val screen = open(prompt)

        // The notification's tap reaches the singleTop prompt already showing it.
        screen.newIntent(tapNotification(id))
        // So does a late delivery of an older request.
        screen.newIntent(TransparentBiometricActivity.createIntent(app, (id.toLong() - 1).toString()))
        settle()

        assertFalse("the prompt on screen stays up", screen.get().isFinishing)
        assertNull("nothing else was started", shadowOf(app).nextStartedActivity)
        assertEquals("nothing was answered", emptyList<Pair<String?, Boolean>>(), results())
        assertTrue(approval.isActive)

        screen.cancel()
        settle()

        assertEquals(ErrorCodes.BIOMETRIC_FAILED, approval.await().error?.code)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertEquals(listOf(id to false), results())
    }

    @Test
    fun `a newer request reaching the prompt on screen gets a prompt of its own`() = runTest {
        val first = shareWithAllPeers()
        runCurrent()
        val firstPrompt = directStart()
        val firstScreen = open(firstPrompt)
        val second = shareWithAllPeers()
        runCurrent()
        assertNull("the second request waits for its turn", shadowOf(app).nextStartedActivity)

        // The first request's connection closes; its prompt is still up when
        // the second request's turn comes and its start reaches that prompt.
        first.cancel()
        runCurrent()
        val secondPrompt = directStart()
        val secondId = secondPrompt.requestId()!!
        assertNotNull("the second request's notification is up", notificationFor(secondId))
        firstScreen.newIntent(secondPrompt)
        settle()

        assertTrue("the withdrawn prompt goes away", firstScreen.get().isFinishing)
        val handedOn = directStart()
        assertEquals(secondId, handedOn.requestId())
        open(handedOn).approve()
        settle()

        assertUpdated(second.await())
        assertEquals(listOf(firstPrompt.requestId() to false, secondId to true), results())
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
    }

    @Test
    fun `a prompt that goes away unanswered fails its request and brings up the next`() = runTest {
        val first = shareWithAllPeers()
        runCurrent()
        val firstPrompt = directStart()
        val firstScreen = open(firstPrompt)
        val second = shareWithAllPeers()
        runCurrent()

        firstScreen.pause().stop().destroy()
        settle()

        assertEquals(ErrorCodes.BIOMETRIC_FAILED, first.await().error?.code)
        val secondPrompt = directStart()
        val secondId = secondPrompt.requestId()!!
        open(tapNotification(secondId)).approve()
        settle()

        assertUpdated(second.await())
        assertEquals(listOf(firstPrompt.requestId() to false, secondId to true), results())
    }

    @Test
    fun `withdrawing a queued approval leaves the notification of the one on screen`() = runTest {
        val first = shareWithAllPeers()
        runCurrent()
        val id = directStart().requestId()!!
        val second = shareWithAllPeers()
        runCurrent()

        // The queued request's connection closes before its turn.
        second.cancel()
        settle()

        assertNotNull("the prompt on screen keeps its notification", notificationFor(id))
        assertNull("the withdrawn request was never prompted", shadowOf(app).nextStartedActivity)
        open(tapNotification(id)).approve()
        settle()

        assertUpdated(first.await())
        assertEquals(listOf(id to true), results())
        assertNull(notificationFor(id))
    }

    @Test
    fun `a queued approval timing out leaves the notification of the one on screen`() = runTest {
        val first = shareWithAllPeers()
        runCurrent()
        val id = directStart().requestId()!!
        // The owner opened it from the notification and is answering it.
        val prompt = open(tapNotification(id))
        val second = shareWithAllPeers()
        runCurrent()

        advanceTimeBy(PendingAuthentications.QUEUE_DEADLINE_MILLIS + 1)
        settle()

        assertEquals(ErrorCodes.BIOMETRIC_FAILED, second.await().error?.code)
        assertNotNull("the prompt on screen keeps its notification", notificationFor(id))
        assertTrue(first.isActive)
        prompt.approve()
        settle()

        assertUpdated(first.await())
        assertEquals(listOf(id to true), results())
    }

    @Test
    fun `an approval whose notification expires unanswered fails, and the next request gets its prompt`() = runTest {
        val first = shareWithAllPeers()
        runCurrent()
        // Android blocked the direct start: the notification is the only way in.
        val firstPrompt = directStart()
        val id = firstPrompt.requestId()!!
        val second = shareWithAllPeers()
        runCurrent()

        // The owner never looks: the notification expires, well short of the
        // first request's active deadline. The second is launched as the
        // first lets go, so its own active deadline must not pass either.
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        runCurrent()
        settle()

        assertNull("the expired notification is gone", notificationFor(id))
        assertTrue("the ignored approval settled", first.isCompleted)
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, first.await().error?.code)
        assertEquals(SharingPolicyType.PRIVATE, stored)

        val secondPrompt = directStart()
        val secondId = secondPrompt.requestId()!!
        // The blocked start of the expired approval arrives late: it is
        // dismissed without prompting or answering anything.
        val stale = open(firstPrompt)
        assertTrue("the stale prompt goes away", stale.get().isFinishing)
        assertNull(stale.get().promptCallback)

        open(tapNotification(secondId)).approve()
        settle()

        assertUpdated(second.await())
        assertEquals(listOf(secondId to true), results())
    }

    @Test
    fun `withdrawing a queued local sign leaves the notification of the approval on screen`() = runTest {
        // One handler serves both requests, as one does for every connection
        // it is shared by.
        val handler = newHandler()
        val approval = shareWithAllPeers(handler)
        runCurrent()
        val id = directStart().requestId()!!
        val signing = signWithUserVerification(handler)
        runCurrent()
        assertNull("the signing request waits for its turn", shadowOf(app).nextStartedActivity)

        signing.cancel()
        settle()

        assertNotNull("the approval keeps its notification", notificationFor(id))
        open(tapNotification(id)).approve()
        settle()

        assertUpdated(approval.await())
        assertEquals(listOf(id to true), results())
        assertNull(notificationFor(id))
    }

    @Test
    fun `an approval handing the screen to a crypto signature leaves the signature's notification up`() = runTest {
        numberBothFamiliesFromOne()
        val approval = shareWithAllPeers()
        runCurrent()
        val id = directStart().requestId()!!

        // A signature request through the launcher, posting its notification
        // as the request handler does, with a helper of its own.
        val signer = BiometricNotificationHelper(app)
        var signatureKey: String? = null
        var keyAlreadyUp = false
        val signing = async {
            launcher.requestCryptoSignature(
                credentialId = "credential-1",
                dataHash = ByteArray(32),
                title = "xKey Authentication",
                subtitle = "Verify your identity to sign",
                showOnLockScreen = true,
                onLaunch = { key, prompt ->
                    signatureKey = key
                    keyAlreadyUp = shadowOf(notifications).getNotification(key, NOTIFICATION_ID) != null
                    signer.showBiometricRequiredNotification(
                        operationType = "sign",
                        rpName = null,
                        requestId = key,
                        promptIntent = prompt
                    )
                }
            )
        }
        runCurrent()
        assertNull("the signature waits for its turn", signatureKey)

        open(tapNotification(id)).approve()
        settle()

        assertUpdated(approval.await())
        val key = signatureKey
        assertNotNull("the signature got its turn", key)
        assertFalse("its key names no other request's notification", keyAlreadyUp)
        assertEquals(
            CryptoSigningActivity::class.java.name,
            shadowOf(app).nextStartedActivity?.component?.className
        )
        assertNotNull(
            "the signature's notification is still up",
            shadowOf(notifications).getNotification(key, NOTIFICATION_ID)
        )
        assertNull("the approval's is gone", notificationFor(id))
        assertTrue(signing.isActive)
        signing.cancel()
    }

    @Test
    fun `a key generation whose start is blocked fails at its deadline, and a sharing approval then gets its prompt`() =
        runTest {
            val generating = generateKeyWithUserVerification()
            runCurrent()
            // Android blocked the direct start silently, and the owner never
            // sees a notification: nothing will ever answer this prompt.
            val blocked = directStart().requestId()!!
            val sharing = shareWithAllPeers()
            runCurrent()
            assertNull("the approval waits for its turn", shadowOf(app).nextStartedActivity)

            // Only coroutine time passes: no notification timer fires.
            advanceTimeBy(UNANSWERED_MILLIS)
            settle()

            assertTrue("the unseen key generation settled", generating.isCompleted)
            assertEquals(ErrorCodes.BIOMETRIC_FAILED, generating.await().error?.code)
            assertNull("its notification is gone", notificationFor(blocked))

            val approval = directStart().requestId()!!
            open(tapNotification(approval)).approve()
            settle()

            assertUpdated(sharing.await())
            assertEquals(listOf(approval to true), results())
        }

    /**
     * Answers one approval on screen ([answer]: approve or cancel), takes its
     * activity down, and returns the intents that started it: the launcher's
     * own start and its notification's tap, either of which Android may
     * deliver again later.
     */
    private fun TestScope.answerAndDestroy(
        approval: Deferred<Response>,
        answer: ActivityController<TransparentBiometricActivity>.() -> Unit,
    ): List<Intent> {
        val prompt = directStart()
        val tap = tapNotification(prompt.requestId()!!)
        val screen = open(prompt)
        screen.answer()
        settle()
        assertTrue(approval.isCompleted)
        screen.pause().stop().destroy()
        return listOf(prompt, tap)
    }

    /** A late start of [intent] in a fresh activity: it shows no prompt and hands nothing on. */
    private fun TestScope.assertRefusedFresh(intent: Intent) {
        val late = open(intent)
        settle()
        assertTrue("the late start finishes", late.get().isFinishing)
        assertNull("and shows no prompt", late.get().promptCallback)
        assertNull("nothing is handed on", shadowOf(app).nextStartedActivity)
        late.pause().stop().destroy()
    }

    @Test
    fun `a settled approval's launch or tap reaching a fresh activity shows no prompt`() = runTest {
        // Denied first, so the policy is still private for the second request.
        val denied = shareWithAllPeers()
        runCurrent()
        val deniedId = shadowOf(app).peekNextStartedActivity().requestId()!!
        val deniedIntents = answerAndDestroy(denied) { cancel() }
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, denied.await().error?.code)

        val approved = shareWithAllPeers()
        runCurrent()
        val approvedId = shadowOf(app).peekNextStartedActivity().requestId()!!
        val approvedIntents = answerAndDestroy(approved) { approve() }
        assertUpdated(approved.await())

        for (intent in approvedIntents + deniedIntents) assertRefusedFresh(intent)

        assertEquals("nothing more was answered", listOf(deniedId to false, approvedId to true), results())
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
    }

    @Test
    fun `a settled approval's intent arriving while another prompts leaves that prompt alone`() = runTest {
        val first = shareWithAllPeers()
        runCurrent()
        val firstId = shadowOf(app).peekNextStartedActivity().requestId()!!
        val stale = answerAndDestroy(first) { cancel() }
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, first.await().error?.code)

        val second = shareWithAllPeers()
        runCurrent()
        val secondPrompt = directStart()
        val secondId = secondPrompt.requestId()!!
        val screen = open(secondPrompt)
        val callback = screen.get().promptCallback

        for (intent in stale) {
            assertRefusedFresh(intent)
            screen.newIntent(intent)
        }
        // An id newer than the one on screen that the owner does not hold
        // ACTIVE is no hand-off either.
        screen.newIntent(TransparentBiometricActivity.createIntent(app, (secondId.toLong() + 1).toString()))
        settle()

        assertFalse("the prompt on screen stays up", screen.get().isFinishing)
        assertTrue("with its own prompt", callback === screen.get().promptCallback)
        assertNull("nothing is handed on", shadowOf(app).nextStartedActivity)
        assertTrue(second.isActive)

        screen.approve()
        settle()

        assertUpdated(second.await())
        assertEquals(listOf(firstId to false, secondId to true), results())
    }

    @Test
    fun `an approval's notification from before a process restart neither answers nor fails the approval after it`() =
        runTest {
            // The process that posts the old notification starts fresh too.
            restartProcess()
            val before = shareWithAllPeers()
            runCurrent()
            val oldId = directStart().requestId()!!
            val oldTap = tapNotification(oldId)

            restartProcess()
            assertNotNull("the old process's request is gone", before.await().error)

            val after = shareWithAllPeers()
            runCurrent()
            val prompt = directStart()
            val id = prompt.requestId()!!

            // The old notification, still on the lock screen, is opened while
            // the new approval holds the screen.
            assertRefusedFresh(oldTap)
            assertTrue("the new approval is not answered by it", after.isActive)
            assertEquals("nothing was answered", emptyList<Pair<String?, Boolean>>(), results())
            assertEquals(SharingPolicyType.PRIVATE, stored)

            open(prompt).approve()
            settle()

            assertUpdated(after.await())
            assertEquals(listOf(id to true), results())
        }

    private companion object {
        /** The id every lock-screen approval notification is posted under, with its own tag. */
        const val NOTIFICATION_ID = 2001

        /**
         * How long an ignored approval is left: past its notification's 30 s
         * and the screen's hold on an unanswered prompt, inside a queued
         * request's [PendingAuthentications.QUEUE_DEADLINE_MILLIS].
         */
        const val UNANSWERED_MILLIS = 90_000L
    }
}
