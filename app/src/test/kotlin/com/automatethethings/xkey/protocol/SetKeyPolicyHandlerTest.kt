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
import android.content.Context
import android.content.Intent
import android.os.Looper
import android.util.Log
import androidx.biometric.BiometricPrompt
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.BiometricActivityLauncher.BiometricResult
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.auth.PendingAuthentications
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Pins the approval rule for `local.setKeyPolicy` (#178).
 *
 * Widening a key to every peer needs a confirmed peer and the owner's
 * approval on the phone; a refused or impossible prompt leaves the stored
 * policy alone. Narrowing, and a key already open to every peer, need
 * neither. The write is a compare-and-set against the policy the decision
 * was taken on, so a change that lands between the read and the write is
 * never overwritten, and the audit names the policy the write replaced.
 *
 * The confirmed peer is the one of the connection the request arrived on
 * (its CallerSession), not the handler-wide peer another transport may have
 * set or cleared.
 *
 * Requests go through the real [RequestHandler.handleRequest], so the wire
 * error codes are the ones a peer sees. The key store is a small stateful
 * fake over the mocked [KeyDao]; the Android edges are mocked as in
 * [UserVerificationWireErrorTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SetKeyPolicyHandlerTest {

    private lateinit var keyDao: KeyDao
    private lateinit var context: Context
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var keyguard: KeyguardManager

    private val keyId = "key-178"
    private val peer = "ab".repeat(32)
    private val otherPeer = "cd".repeat(32)

    /** The stored sharing policy, or null when the key does not exist. */
    private var stored: SharingPolicyType? = null
    private var storedLabel = "Work key"

    /**
     * The stored row's immutable id. A delete and re-create under the same
     * key id gives the new row a new one.
     */
    private var storedRowId = 1L

    /**
     * The stored row's policy revision: every policy write bumps it, so a
     * policy changed away and back reads the same but is a later revision.
     */
    private var storedRevision = 0L

    /** The denial a failed narrowing left in the key's policy row (#193), or null. */
    private var denial: SharingPolicyType? = null

    private lateinit var policyDao: KeyPolicyDao

    /** The store's policy write; tests that hold a write back replace it. */
    private var write: suspend (SharingPolicyType) -> Int = { policy ->
        if (stored == null) {
            0
        } else {
            writes += policy
            stored = policy
            storedRevision++
            1
        }
    }

    /** Every policy the fake store was asked to write, by any DAO call. */
    private val writes = mutableListOf<SharingPolicyType>()

    /** The request ids the approval prompts were launched for, in launch order. */
    private val prompts = mutableListOf<String>()

    /** Runs once, after the next read has taken its snapshot. */
    private var afterNextRead: (() -> Unit)? = null

    /** Runs once, after the next read of the enforced policy has taken its snapshot. */
    private var afterPolicyRead: (() -> Unit)? = null

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
        coEvery { keyDao.getByKeyId(keyId) } answers {
            val snapshot = stored?.let { key(it, storedLabel) }
            afterNextRead?.also { afterNextRead = null }?.invoke()
            snapshot
        }
        // The policy store (#193) over the same stored row: its writes are
        // the ones these tests watch.
        policyDao = mockk(relaxed = true)
        // No key has a pending deletion.
        io.mockk.coEvery { policyDao.deletion(any()) } returns null
        coEvery { policyDao.keyInstance(keyId) } answers { stored?.let { storedRowId } }
        coEvery { policyDao.storedPolicy(keyId) } answers { stored }
        coEvery { policyDao.policyRevision(keyId) } answers { stored?.let { storedRevision } }
        coEvery { policyDao.policyRow(keyId) } answers {
            val snapshot = stored?.let { KeyPolicyEntity(keyId, storedRowId, it, denial = denial) }
            afterPolicyRead?.also { afterPolicyRead = null }?.invoke()
            snapshot
        }
        coEvery { policyDao.putPolicyRow(any()) } answers { denial = firstArg<KeyPolicyEntity>().denial }
        coEvery { policyDao.setKeyPolicy(keyId, any()) } coAnswers { write(secondArg()) }
        mockkObject(KeyPolicyStore.Companion)
        every { KeyPolicyStore.of(any()) } answers {
            KeyPolicyStore(
                policyDao,
                object : KeyPolicyStore.Transactor {
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

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        keyguard = mockk(relaxed = true)
        every { keyguard.isKeyguardLocked } returns false
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns keyguard
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        launcher = mockk(relaxed = true)

        // The lock-screen notification is the one Android edge these tests
        // watch: it must carry the launcher's own request.
        mockkConstructor(BiometricNotificationHelper::class)
        every {
            anyConstructed<BiometricNotificationHelper>()
                .showBiometricRequiredNotification(any(), any(), any(), any(), any(), any())
        } just runs
        every { anyConstructed<BiometricNotificationHelper>().cancelNotification(any<String>()) } just runs
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    private fun handler(
        withLauncher: Boolean = true,
        confirmedPeer: String? = peer
    ): RequestHandler = RequestHandler(
        context = context,
        keystoreManager = mockk<KeystoreManager>(relaxed = true),
        biometricLauncher = if (withLauncher) launcher else null,
        sessionAuthManager = null
    ).also { it.setConnectedDevicePublicKeyHex(confirmedPeer) }

    private fun key(policy: SharingPolicyType, label: String = "Work key") = KeyEntity(
        id = storedRowId,
        keyId = keyId,
        keyType = "aes",
        algorithm = "AES-256-GCM",
        label = label,
        keySizeBits = 256,
        shareable = policy != SharingPolicyType.PRIVATE,
        sharingPolicy = policy,
        policyRevision = storedRevision,
        source = "local"
    )

    /** Another policy writer (the key's sharing sheet) stores [policy] on the same row. */
    private fun otherWriter(policy: SharingPolicyType) {
        stored = policy
        storedRevision++
    }

    /**
     * Routes the launcher's approval prompts through a real
     * [PendingAuthentications] on a screen of this test's own, mapping a
     * result to the launcher's outcome, so overlapping requests take turns as
     * they do on the phone. Settle a prompt with [PendingAuthentications.complete]
     * on the id in [prompts]. A prompt coming up runs the request's `onLaunch`,
     * as the launcher does.
     */
    private fun promptsTakeTurns(): PendingAuthentications {
        // Each launched prompt is up, as the owner answers it: none is
        // expired at the active deadline.
        val approvals = PendingAuthentications(PromptOwnership(), expirePrompt = { false })
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } coAnswers {
            val onLaunch = arg<(String, Intent) -> Unit>(4)
            val launch = { requestId: String ->
                prompts += requestId
                onLaunch(requestId, mockk())
            }
            when (val result = approvals.await(launch = launch)) {
                is BiometricResult.Success -> Unit
                is BiometricResult.Error -> throw BiometricException(result.code, result.message)
            }
        }
        return approvals
    }

    private val ownerCancels = BiometricResult.Error(BiometricPrompt.ERROR_USER_CANCELED, "cancelled")

    private fun request(shareable: Boolean?) = Request(
        id = 178L,
        method = MethodNames.LOCAL_SET_KEY_POLICY,
        params = JSONObject().put("keyId", keyId).also {
            if (shareable != null) it.put("shareable", shareable)
        }
    )

    /** Handles [request] as one arriving on a served connection whose peer is [callerPeer]. */
    private suspend fun RequestHandler.handleFromCaller(request: Request, callerPeer: String?): Response =
        withContext(RequestHandler.servedConnection(SessionBindingProvider { null }, callerPeer, "caller")) {
            handleRequest(request)
        }

    private fun assertUpdated(response: Response) {
        assertNull(response.error)
        assertEquals(true, response.result?.getBoolean("updated"))
    }

    private fun assertNoPrompt() {
        coVerify(exactly = 0) { launcher.requestAuthentication(any(), any(), any(), any(), any()) }
    }

    private fun assertNothingWrittenOrAudited() {
        assertEquals(emptyList<SharingPolicyType>(), writes)
        verify(exactly = 0) { AuditLogger.logKeySharingChanged(any(), any(), any(), any(), any()) }
    }

    private fun assertAudited(oldPolicy: SharingPolicyType, newPolicy: SharingPolicyType) {
        verify(exactly = 1) { AuditLogger.logKeySharingChanged(any(), any(), any(), any(), any()) }
        verify(exactly = 1) {
            AuditLogger.logKeySharingChanged(keyId, storedLabel, "aes", oldPolicy.name, newPolicy.name)
        }
    }

    @Test
    fun `widening approved on the phone stores ALL_PEERS and audits it`() = runTest {
        stored = SharingPolicyType.PRIVATE

        val response = handler().handleRequest(request(shareable = true))

        assertUpdated(response)
        coVerify(exactly = 1) {
            launcher.requestAuthentication(any(), match { it.contains("Work key") }, any(), any(), any())
        }
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
    }

    @Test
    fun `a request cancelled after its policy write commits still audits the change`() = runTest {
        stored = SharingPolicyType.PRIVATE
        // The store commits the write, then holds its answer back, as Room
        // does between the SQLite commit and the caller resuming.
        val committed = CompletableDeferred<Unit>()
        val answer = CompletableDeferred<Unit>()
        write = { policy ->
            writes += policy
            stored = policy
            storedRevision++
            committed.complete(Unit)
            answer.await()
            1
        }

        val call = async { handler().handleRequest(request(shareable = true)) }
        runCurrent()
        assertTrue(committed.isCompleted)

        // The connection closes before the write's result reaches the request.
        call.cancel()
        answer.complete(Unit)
        call.join()
        // The store's edit outlives the request, on its own scope.
        withContext(Dispatchers.Default) {
            kotlinx.coroutines.withTimeout(5_000) {
                while (writes.isEmpty() || runCatching { assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS) }.isFailure) {
                    kotlinx.coroutines.delay(10)
                }
            }
        }

        assertEquals(SharingPolicyType.ALL_PEERS, stored)
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
    }

    @Test
    fun `the prompt names a key with no label by its id`() = runTest {
        stored = SharingPolicyType.PRIVATE
        storedLabel = ""

        assertUpdated(handler().handleRequest(request(shareable = true)))

        coVerify(exactly = 1) {
            launcher.requestAuthentication(any(), match { it.contains(keyId) }, any(), any(), any())
        }
    }

    @Test
    fun `two overlapping approvals are prompted in turn and both complete`() = runTest {
        stored = SharingPolicyType.PRIVATE
        val approvals = promptsTakeTurns()

        val first = async { handler().handleRequest(request(shareable = true)) }
        val second = async { handler().handleRequest(request(shareable = true)) }
        runCurrent()
        assertEquals("one prompt on screen at a time", 1, prompts.size)

        assertTrue(approvals.complete(prompts[0], BiometricResult.Success))
        runCurrent()
        assertUpdated(first.await())
        assertEquals("the second prompt comes up once the first is answered", 2, prompts.size)

        assertTrue(approvals.complete(prompts[1], BiometricResult.Success))
        runCurrent()
        assertUpdated(second.await())
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
    }

    @Test
    fun `cancelling the first of two overlapping approvals fails only that one`() = runTest {
        stored = SharingPolicyType.PRIVATE
        val approvals = promptsTakeTurns()

        val first = async { handler().handleRequest(request(shareable = true)) }
        val second = async { handler().handleRequest(request(shareable = true)) }
        runCurrent()

        assertTrue(approvals.complete(prompts[0], ownerCancels))
        runCurrent()
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, first.await().error?.code)
        assertEquals(SharingPolicyType.PRIVATE, stored)

        assertEquals(2, prompts.size)
        assertTrue(approvals.complete(prompts[1], BiometricResult.Success))
        runCurrent()
        assertUpdated(second.await())
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
    }

    @Test
    fun `cancelling the second of two overlapping approvals fails only that one`() = runTest {
        stored = SharingPolicyType.PRIVATE
        val approvals = promptsTakeTurns()

        val first = async { handler().handleRequest(request(shareable = true)) }
        val second = async { handler().handleRequest(request(shareable = true)) }
        runCurrent()

        assertTrue(approvals.complete(prompts[0], BiometricResult.Success))
        runCurrent()
        assertUpdated(first.await())

        assertTrue(approvals.complete(prompts[1], ownerCancels))
        runCurrent()
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, second.await().error?.code)
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
    }

    @Test
    fun `an approval still queued at its deadline answers BIOMETRIC_FAILED`() = runTest {
        stored = SharingPolicyType.PRIVATE
        val approvals = promptsTakeTurns()

        val first = async { handler().handleRequest(request(shareable = true)) }
        val second = async { handler().handleRequest(request(shareable = true)) }
        runCurrent()

        advanceTimeBy(PendingAuthentications.QUEUE_DEADLINE_MILLIS + 1)
        runCurrent()
        val timedOut = second.await()
        assertNull(timedOut.result)
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, timedOut.error?.code)
        assertEquals("the queued request never prompted", 1, prompts.size)
        assertTrue("the request on screen still waits for the owner", first.isActive)

        assertTrue(approvals.complete(prompts[0], BiometricResult.Success))
        runCurrent()
        assertUpdated(first.await())
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
    }

    /** No request's lock-screen notification has been taken down. */
    private fun assertNoNotificationCancelled() {
        verify(exactly = 0) { anyConstructed<BiometricNotificationHelper>().cancelNotification(any<String>()) }
    }

    /** Only [requestId]'s notification was taken down, once, by its id. */
    private fun assertOnlyNotificationCancelled(requestId: String) {
        verify(exactly = 1) { anyConstructed<BiometricNotificationHelper>().cancelNotification(any<String>()) }
        verify(exactly = 1) { anyConstructed<BiometricNotificationHelper>().cancelNotification(requestId) }
    }

    @Test
    fun `withdrawing a queued approval leaves the notification of the one on screen`() = runTest {
        stored = SharingPolicyType.PRIVATE
        every { keyguard.isKeyguardLocked } returns true
        val approvals = promptsTakeTurns()

        val first = async { handler().handleRequest(request(shareable = true)) }
        val second = async { handler().handleRequest(request(shareable = true)) }
        runCurrent()
        // The queued request's connection closes before its turn.
        second.cancel()
        runCurrent()

        assertEquals("the queued request was never prompted", 1, prompts.size)
        assertNoNotificationCancelled()
        assertTrue("the request on screen still waits for the owner", first.isActive)

        assertTrue(approvals.complete(prompts[0], BiometricResult.Success))
        runCurrent()
        assertUpdated(first.await())
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
        assertOnlyNotificationCancelled(prompts[0])
    }

    @Test
    fun `a queued approval timing out leaves the notification of the one on screen`() = runTest {
        stored = SharingPolicyType.PRIVATE
        every { keyguard.isKeyguardLocked } returns true
        val approvals = promptsTakeTurns()

        val first = async { handler().handleRequest(request(shareable = true)) }
        val second = async { handler().handleRequest(request(shareable = true)) }
        runCurrent()
        advanceTimeBy(PendingAuthentications.QUEUE_DEADLINE_MILLIS + 1)
        runCurrent()

        assertEquals(ErrorCodes.BIOMETRIC_FAILED, second.await().error?.code)
        assertNoNotificationCancelled()
        assertTrue("the request on screen still waits for the owner", first.isActive)

        assertTrue(approvals.complete(prompts[0], BiometricResult.Success))
        runCurrent()
        assertUpdated(first.await())
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
        assertOnlyNotificationCancelled(prompts[0])
    }

    @Test
    fun `widening the owner cancels answers BIOMETRIC_FAILED and stores nothing`() = runTest {
        stored = SharingPolicyType.PRIVATE
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } throws UserCancelledException()

        val response = handler().handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `widening with no biometric launcher answers BIOMETRIC_FAILED and stores nothing`() = runTest {
        stored = SharingPolicyType.PRIVATE

        val response = handler(withLauncher = false).handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `widening with no confirmed peer answers OPERATION_DENIED without a prompt`() = runTest {
        stored = SharingPolicyType.PRIVATE

        val response = handler(confirmedPeer = null).handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertNoPrompt()
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `narrowing stores PRIVATE with no prompt and audits it`() = runTest {
        stored = SharingPolicyType.ALL_PEERS

        val response = handler().handleRequest(request(shareable = false))

        assertUpdated(response)
        assertNoPrompt()
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertAudited(SharingPolicyType.ALL_PEERS, SharingPolicyType.PRIVATE)
    }

    @Test
    fun `a key already open to every peer is neither prompted for, written nor audited`() = runTest {
        stored = SharingPolicyType.ALL_PEERS

        val response = handler(withLauncher = false).handleRequest(request(shareable = true))

        assertUpdated(response)
        assertNoPrompt()
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `a narrowing that lands after the read is not overwritten back to ALL_PEERS`() = runTest {
        stored = SharingPolicyType.ALL_PEERS
        // The owner narrows the key after this request has read that it
        // enforces ALL_PEERS.
        afterPolicyRead = { otherWriter(SharingPolicyType.PRIVATE) }

        val response = handler().handleRequest(request(shareable = true))

        assertUpdated(response)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertNoPrompt()
        assertNothingWrittenOrAudited()
    }

    /**
     * Round 10 (1): a key stored as ALL_PEERS whose narrowing failed is
     * denied to every peer until a write lands. Asking for ALL_PEERS again
     * lifts that denial, so it needs the owner's approval like any widening.
     */
    @Test
    fun `lifting a failed narrowing's denial needs the owner's approval`() = runTest {
        stored = SharingPolicyType.ALL_PEERS
        denial = SharingPolicyType.PRIVATE
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } throws UserCancelledException()

        val response = handler().handleRequest(request(shareable = true))

        assertEquals(ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
        assertEquals(SharingPolicyType.PRIVATE, denial)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `an approved lift of a denial stores ALL_PEERS and audits the denial it replaced`() = runTest {
        stored = SharingPolicyType.ALL_PEERS
        denial = SharingPolicyType.PRIVATE

        assertUpdated(handler().handleRequest(request(shareable = true)))

        coVerify(exactly = 1) { launcher.requestAuthentication(any(), any(), any(), any(), any()) }
        assertNull(denial)
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
    }

    /**
     * Round 10 (2): the revision check runs inside the write's transaction.
     * A change that commits after the approval and before the write (here,
     * as the transaction reads the key row) refuses the widening.
     */
    @Test
    fun `a change committed between the approval and the write refuses the widening`() = runTest {
        stored = SharingPolicyType.PRIVATE
        var moved = false
        coEvery { policyDao.keyInstance(keyId) } answers {
            if (!moved) {
                otherWriter(SharingPolicyType.ALL_PEERS)
                otherWriter(SharingPolicyType.PRIVATE)
                moved = true
            }
            stored?.let { storedRowId }
        }

        val response = handler().handleRequest(request(shareable = true))

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertNothingWrittenOrAudited()
    }

    /**
     * Round 10 bypass guards: local.setKeyPolicy decides through the store's
     * transaction ([KeyPolicyStore.RemoteDecision]), not a check of its own
     * before the write, its approval rule reads the enforced policy (a
     * denial included), and its audit is the decision's.
     */
    @Test
    fun `local setKeyPolicy decides and audits only through the store's transaction`() {
        val source = listOf(
            java.io.File("src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt"),
            java.io.File("app/src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt")
        ).first { it.isFile }.readText()
        val start = source.indexOf("private suspend fun handleLocalSetKeyPolicy(")
        val body = source.substring(start, source.indexOf("\n    private ", start + 1))
        assertFalse("a revision check outside the transaction", "policyRevision !=" in body)
        assertTrue("keyPolicyStore.enforcedPolicy(entity)" in body)
        assertTrue("decision = decision" in body)
        assertEquals(1, Regex("""KeySharingPeers\.setKeyPolicy\(""").findAll(source).count())
        assertEquals(1, Regex("""logKeySharingChanged\(""").findAll(body).count())
        val decision = body.substring(body.indexOf("KeyPolicyStore.RemoteDecision("), body.indexOf("val landed"))
        assertTrue("the audit is the decision's", "logKeySharingChanged(" in decision)
    }

    @Test
    fun `a change during the approval prompt refuses the widening it was not approved for`() = runTest {
        stored = SharingPolicyType.PRIVATE
        // While the owner is looking at the prompt, the key moves to selected peers.
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } answers {
            stored = SharingPolicyType.SELECTED_PEERS
        }

        val response = handler().handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertEquals(SharingPolicyType.SELECTED_PEERS, stored)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `a narrowing audits the policy its write actually replaced`() = runTest {
        stored = SharingPolicyType.ALL_PEERS
        // Another writer moves the key to selected peers after this request's read.
        afterNextRead = { otherWriter(SharingPolicyType.SELECTED_PEERS) }

        val response = handler().handleRequest(request(shareable = false))

        assertUpdated(response)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertAudited(SharingPolicyType.SELECTED_PEERS, SharingPolicyType.PRIVATE)
    }

    @Test
    fun `an approval taken before the key was shared and revoked again writes nothing`() = runTest {
        stored = SharingPolicyType.PRIVATE
        // While the owner approves widening from PRIVATE, another writer
        // shares the key with every peer and then revokes it back to
        // PRIVATE. The policy reads the same, but the approval predates the
        // revocation, so it must not reopen the key.
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } answers {
            otherWriter(SharingPolicyType.ALL_PEERS)
            otherWriter(SharingPolicyType.PRIVATE)
        }

        val response = handler().handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertEquals(2L, storedRevision)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `a narrowing writes against the revision it re-read`() = runTest {
        stored = SharingPolicyType.ALL_PEERS
        // Revoked and shared again after this request's read: the policy
        // reads ALL_PEERS as before, at a later revision.
        afterNextRead = {
            otherWriter(SharingPolicyType.PRIVATE)
            otherWriter(SharingPolicyType.ALL_PEERS)
        }

        val response = handler().handleRequest(request(shareable = false))

        assertUpdated(response)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertEquals("one write, by this request", 3L, storedRevision)
        assertAudited(SharingPolicyType.ALL_PEERS, SharingPolicyType.PRIVATE)
    }

    @Test
    fun `a key deleted and re-created under the same id during the prompt gets no policy change`() = runTest {
        stored = SharingPolicyType.PRIVATE
        // While the owner approves sharing "Work key", it is deleted and a
        // different key is created under the same id, with the same policy.
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } answers {
            storedRowId = 2L
            storedLabel = "Someone else's key"
        }

        val response = handler().handleRequest(request(shareable = true))

        assertNull(response.result)
        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `a narrowing never writes a key re-created under the same id after the read`() = runTest {
        stored = SharingPolicyType.ALL_PEERS
        afterNextRead = { storedRowId = 2L }

        val response = handler().handleRequest(request(shareable = false))

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
        assertNothingWrittenOrAudited()
    }

    /**
     * Has the launcher open its approval request [requestId] for [prompt], as
     * it does when it shows the prompt, then answer as the owner does:
     * approve, or [refusal].
     */
    private fun launcherOpensRequest(requestId: String, prompt: Intent, refusal: Exception? = null) {
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } answers {
            arg<(String, Intent) -> Unit>(4).invoke(requestId, prompt)
            if (refusal != null) throw refusal
        }
    }

    private fun verifyNotificationOpens(requestId: String, prompt: Intent) {
        verify(exactly = 1) {
            anyConstructed<BiometricNotificationHelper>()
                .showBiometricRequiredNotification(any(), any(), any(), any(), any(), any())
        }
        verify(exactly = 1) {
            anyConstructed<BiometricNotificationHelper>()
                .showBiometricRequiredNotification("share", "Work key", requestId, any(), any(), prompt)
        }
        assertOnlyNotificationCancelled(requestId)
    }

    @Test
    fun `on a locked phone the notification opens the launcher's own approval request`() = runTest {
        stored = SharingPolicyType.PRIVATE
        every { keyguard.isKeyguardLocked } returns true
        val prompt = mockk<Intent>()
        launcherOpensRequest("41", prompt)

        val response = handler().handleRequest(request(shareable = true))

        assertUpdated(response)
        coVerify(exactly = 1) { launcher.requestAuthentication(any(), any(), any(), true, any()) }
        verifyNotificationOpens("41", prompt)
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
        assertAudited(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)
    }

    @Test
    fun `a cancel through the lock-screen notification answers BIOMETRIC_FAILED`() = runTest {
        stored = SharingPolicyType.PRIVATE
        every { keyguard.isKeyguardLocked } returns true
        val prompt = mockk<Intent>()
        launcherOpensRequest("42", prompt, refusal = UserCancelledException())

        val response = handler().handleRequest(request(shareable = true))

        assertEquals(ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
        verifyNotificationOpens("42", prompt)
        assertEquals(SharingPolicyType.PRIVATE, stored)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `an unlocked phone shows no notification`() = runTest {
        stored = SharingPolicyType.PRIVATE
        launcherOpensRequest("43", mockk())

        assertUpdated(handler().handleRequest(request(shareable = true)))

        verify(exactly = 0) {
            anyConstructed<BiometricNotificationHelper>()
                .showBiometricRequiredNotification(any(), any(), any(), any(), any(), any())
        }
    }

    @Test
    fun `an absent shareable changes nothing and needs no prompt`() = runTest {
        stored = SharingPolicyType.PRIVATE

        val response = handler(withLauncher = false).handleRequest(request(shareable = null))

        assertUpdated(response)
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `an unknown key answers KEY_NOT_FOUND`() = runTest {
        stored = null

        val response = handler().handleRequest(request(shareable = true))

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        assertTrue(response.error?.message.orEmpty().contains(keyId))
        assertNothingWrittenOrAudited()
    }

    @Test
    fun `the caller's confirmed peer is enough when the handler-wide peer was cleared`() = runTest {
        stored = SharingPolicyType.PRIVATE
        // Another transport's teardown cleared the handler-wide peer.
        val handler = handler(confirmedPeer = null)

        val response = handler.handleFromCaller(request(shareable = true), callerPeer = peer)

        assertUpdated(response)
        coVerify(exactly = 1) { launcher.requestAuthentication(any(), any(), any(), any(), any()) }
        assertEquals(SharingPolicyType.ALL_PEERS, stored)
    }

    @Test
    fun `a caller with no confirmed peer is denied even when the handler-wide peer is set`() = runTest {
        stored = SharingPolicyType.PRIVATE
        val handler = handler(confirmedPeer = otherPeer)

        val response = handler.handleFromCaller(request(shareable = true), callerPeer = null)

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertNoPrompt()
        assertNothingWrittenOrAudited()
    }

    private val noPeerMessage = "requires a confirmed peer identity"

    private fun shareSymmetric() = Request(
        id = 179L,
        method = MethodNames.LOCAL_SHARE_SYMMETRIC,
        params = JSONObject().put("wrapped_key", "AAAA").put("label", keyId)
    )

    private fun importSharedKey() = Request(
        id = 180L,
        method = MethodNames.LOCAL_IMPORT_SHARED_KEY,
        params = JSONObject().put("key_id", keyId)
    )

    @Test
    fun `shareSymmetric and importSharedKey deny a caller with no peer even when the handler-wide peer is set`() =
        runTest {
            val handler = handler(confirmedPeer = otherPeer)

            for (request in listOf(shareSymmetric(), importSharedKey())) {
                val response = handler.handleFromCaller(request, callerPeer = null)

                assertEquals(request.method, ErrorCodes.OPERATION_DENIED, response.error?.code)
                assertTrue(request.method, response.error?.message.orEmpty().contains(noPeerMessage))
            }
        }

    @Test
    fun `shareSymmetric and importSharedKey accept the caller's peer when the handler-wide peer was cleared`() =
        runTest {
            val handler = handler(confirmedPeer = null)

            for (request in listOf(shareSymmetric(), importSharedKey())) {
                val response = handler.handleFromCaller(request, callerPeer = peer)

                assertFalse(request.method, response.error?.message.orEmpty().contains(noPeerMessage))
            }
        }
}
