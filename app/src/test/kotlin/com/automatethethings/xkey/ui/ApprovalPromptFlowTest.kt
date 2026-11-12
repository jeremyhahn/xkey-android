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
import com.automatethethings.xkey.auth.PendingAuthentications
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
        coEvery { keyDao.compareAndSetSharingPolicy(1L, keyId, any(), any(), any()) } answers {
            if (thirdArg<Long>() == storedRevision && arg<SharingPolicyType>(3) == stored) {
                stored = arg(4)
                storedRevision++
                1
            } else {
                0
            }
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

    /** A peer's request to share the key with every peer, on a handler of its own connection. */
    private fun TestScope.shareWithAllPeers(): Deferred<Response> = async {
        RequestHandler(
            context = app,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = launcher,
            sessionAuthManager = null
        ).also { it.setConnectedDevicePublicKeyHex(peer) }.handleRequest(
            Request(
                id = 178L,
                method = MethodNames.LOCAL_SET_KEY_POLICY,
                params = JSONObject().put("keyId", keyId).put("shareable", true)
            )
        )
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
            shadowOf(it.fullScreenIntent).savedIntent.requestId() == requestId
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
        val second = shareWithAllPeers()
        runCurrent()

        advanceTimeBy(PendingAuthentications.QUEUE_DEADLINE_MILLIS + 1)
        settle()

        assertEquals(ErrorCodes.BIOMETRIC_FAILED, second.await().error?.code)
        assertNotNull("the prompt on screen keeps its notification", notificationFor(id))
        assertTrue(first.isActive)
        open(tapNotification(id)).approve()
        settle()

        assertUpdated(first.await())
        assertEquals(listOf(id to true), results())
    }
}
