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

package com.automatethethings.xkey.transport

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivSlotInfo
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ConnectionChangedException
import com.automatethethings.xkey.remote.DesktopKeyShare
import com.automatethethings.xkey.remote.DesktopShareDecision
import com.automatethethings.xkey.remote.RemoteShareClient
import com.automatethethings.xkey.remote.SharePermissionLedger
import com.automatethethings.xkey.remote.SharePermissionRevokedException
import com.automatethethings.xkey.remote.ShareSession
import com.automatethethings.xkey.remote.SharedKeyStore
import com.automatethethings.xkey.remote.sendOnBoundSession
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PeerNotPairedException
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
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
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Unpairing a desktop revokes its live stream session, and every
 * phone-initiated send revalidates the peer first (#59). The shared
 * [StreamPairingSession] serves TCP and USB alike; here it runs over a
 * loopback socket against [DesktopPeer].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamPairingSessionRevocationTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L
        const val SHARE_TIMEOUT_MS = 1_000L
        const val PEM = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
        val TRANSPORT_SECRETS = setOf("sendKey", "recvKey")
        val REQUEST = """{"jsonrpc":"2.0","id":9,"method":"remote.sync","params":{}}""".toByteArray()

        fun ByteArray.isAllZero(): Boolean = all { it == 0.toByte() }
    }

    private lateinit var context: Context
    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var pairing: StreamPairingSession
    private lateinit var mainThread: ExecutorService
    private lateinit var listener: ServerSocket
    private val connections = ServedConnections()
    private val scope = connections.scope

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>(), any()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())

        context = mockk(relaxed = true)
        prefs = InMemorySharedPreferences()
        repo = PairedDeviceRepository(prefs)
        requestHandler = mockk(relaxed = true)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } answers {
            val id = JSONObject(String(firstArg<ByteArray>())).optLong("id")
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()
        }
        pairing = StreamPairingSession(
            requestHandler = requestHandler,
            messageRouter = null,
            pairingCallback = null,
            pairedDeviceRepository = repo,
            transportLabel = "TEST",
        )
        listener = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
    }

    @After
    fun tearDown() {
        connections.end()
        listener.close()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    // ---------------------------------------------------------------------
    // Unpair of an active connection
    // ---------------------------------------------------------------------

    /**
     * Unpairing the peer of a live session closes the transport, zeroes the
     * session keys, and leaves nothing a later send could use.
     */
    @Test
    fun unpairingTheActivePeerTearsDownTheSession() = runBlocking {
        val phone = connectPaired()
        val keys = phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS }
        assertEquals(TRANSPORT_SECRETS, keys.keys)

        repo.removeDevice(phone.desktop.publicKeyHex)

        phone.desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
        try {
            pairing.sendOnBoundSession(REQUEST)
            fail("a send after the teardown must be refused")
        } catch (e: IOException) {
            // No session left to send on.
        }
    }

    /**
     * The removal lands while a phone-initiated frame is blocked mid-write:
     * that write fails, nothing reaches the desktop, and the keys are zeroed
     * only after the write has released the send lock.
     */
    @Test
    fun unpairingWhileAFrameIsMidSendFailsItAndZeroesAfterIt() = runBlocking {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val keys = phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS }

        gate.armed = true
        val send = scope.async { runCatching { pairing.sendOnBoundSession(REQUEST) } }
        assertTrue("the send never reached the stream", gate.entered.await(5, TimeUnit.SECONDS))
        assertFalse("the keys are live while the frame is mid-send", keys.values.any { it.isAllZero() })

        repo.removeDevice(phone.desktop.publicKeyHex)

        val result = withTimeout(TIMEOUT_MS) { send.await() }
        assertTrue("the in-flight send must fail: $result", result.exceptionOrNull() is IOException)
        phone.desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
    }

    /**
     * A phone-initiated send is paused after its dispatch to the IO
     * dispatcher and before admission; the peer is removed; then the send
     * resumes. Admission and revocation share one lock, so the send is
     * refused: nothing reaches the stream, no nonce is consumed, and the send
     * fails with the typed not-paired error.
     */
    @Test
    fun aSendPausedBeforeAdmissionWhenThePeerIsRemovedWritesNothing() = runBlocking<Unit> {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val paused = CompletableDeferred<Unit>()
        val resume = CompletableDeferred<Unit>()
        pairing.beforeAdmissionForTest = {
            paused.complete(Unit)
            resume.await()
        }
        val send = scope.async { runCatching { pairing.sendOnBoundSession(REQUEST) } }
        withTimeout(TIMEOUT_MS) { paused.await() }
        val writes = gate.writes.get()
        val nonce = phone.noise.sendNonceForTest()

        repo.removeDevice(phone.desktop.publicKeyHex)
        resume.complete(Unit)

        val failure = withTimeout(TIMEOUT_MS) { send.await() }.exceptionOrNull()
        assertTrue("the send must fail as not paired: $failure", failure is PeerNotPairedException)
        assertEquals("nothing may reach the stream", writes, gate.writes.get())
        assertEquals("a refused send must not consume a nonce", nonce, phone.noise.sendNonceForTest())
        phone.desktop.assertClosedByPhone()
        phone.awaitServeEnded()
    }

    /**
     * The sender is cancelled after its frame was encrypted and before it is
     * written, with the peer still paired. The admitted send is not
     * cancellable: the frame still goes out, so the next send decrypts on
     * the desktop and the two sides stay in nonce step.
     */
    @Test
    fun aSenderCancelledAfterAdmissionStillWritesItsFrame() = runBlocking<Unit> {
        val phone = connectPaired()
        val admitted = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        pairing.afterAdmissionForTest = {
            admitted.complete(Unit)
            release.await()
        }
        val sender = scope.launch { pairing.sendOnBoundSession(REQUEST) }
        withTimeout(TIMEOUT_MS) { admitted.await() }

        sender.cancel()
        release.complete(Unit)
        withTimeout(TIMEOUT_MS) { sender.join() }
        pairing.afterAdmissionForTest = null

        pairing.sendOnBoundSession(REQUEST)
        assertEquals("remote.sync", phone.desktop.readEncrypted().getString("method"))
        assertEquals("remote.sync", phone.desktop.readEncrypted().getString("method"))
    }

    /**
     * The peer ends its stream while a phone-initiated write is blocked on it.
     * The teardown closes the streams before it waits on the
     * send lock, so the blocked write fails, serve returns, and the keys are
     * zeroed.
     */
    @Test
    fun anEofWhileAWriteIsBlockedEndsTheConnectionAndZeroesTheKeys() = runBlocking {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val keys = phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS }
        assertEquals(TRANSPORT_SECRETS, keys.keys)

        gate.armed = true
        val send = scope.async { runCatching { pairing.sendOnBoundSession(REQUEST) } }
        assertTrue("the send never reached the stream", gate.entered.await(5, TimeUnit.SECONDS))

        phone.desktop.endOutput()

        phone.awaitServeEnded()
        val result = withTimeout(TIMEOUT_MS) { send.await() }
        assertTrue("the blocked send must fail: $result", result.exceptionOrNull() is IOException)
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
        try {
            pairing.sendOnBoundSession(REQUEST)
            fail("a send after the teardown must be refused")
        } catch (e: IOException) {
            // No session left to send on.
        }
    }

    // ---------------------------------------------------------------------
    // Send-time revalidation
    // ---------------------------------------------------------------------

    /**
     * The record is gone but no notice reached the session (it was wiped
     * behind the repository's back): the send is refused before encryption,
     * the nonce does not move, and nothing is written.
     */
    @Test
    fun aSendToAPeerThatIsNoLongerPairedIsRefusedBeforeEncryption() = runBlocking {
        val phone = connectPaired()
        prefs.edit().clear().apply()
        val nonce = phone.noise.sendNonceForTest()

        try {
            pairing.sendOnBoundSession(REQUEST)
            fail("the send must be refused")
        } catch (e: PeerNotPairedException) {
            assertEquals(phone.desktop.publicKeyHex, e.publicKeyHex)
        }

        assertEquals("a refused send must not consume a nonce", nonce, phone.noise.sendNonceForTest())
        phone.desktop.assertNoFrame()
    }

    // ---------------------------------------------------------------------
    // Removal during the handshake
    // ---------------------------------------------------------------------

    /** The peer's claimed key is unpaired between msg2 and msg3: the handshake is torn down. */
    @Test
    fun unpairingDuringTheHandshakeTearsItDown() = runBlocking {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve(desktop)
        desktop.exchangeIdentity()
        desktop.sendMsg1AndReadMsg2()
        val handshakeSecrets = phone.noise.secretArraysForTest() - "staticPrivateKey"

        repo.removeDevice(desktop.publicKeyHex)

        desktop.assertClosedByPhone()
        assertTrue("serve must fail", phone.awaitServeEnded() != null)
        assertFalse("the session must not be connected", phone.connected.isCompleted)
        handshakeSecrets.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
    }

    /**
     * Unpaired before the phone knows who is connecting: the handshake still
     * completes, but the session is not adopted as paired, so it serves only
     * pairing.confirm and the phone sends it nothing.
     */
    @Test
    fun unpairingBeforeThePeerKeyIsKnownLeavesTheSessionGated() = runBlocking {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve(desktop)

        repo.removeDevice(desktop.publicKeyHex)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        val reply = desktop.request("system.ping")
        assertEquals(ErrorCodes.PAIRING_REQUIRED, reply.getJSONObject("error").getInt("code"))
        try {
            pairing.sendOnBoundSession(REQUEST)
            fail("the send must be refused")
        } catch (e: PeerNotPairedException) {
            // Nothing was written.
        }
        desktop.assertNoFrame()
    }

    /**
     * `local.verifyUser` answers only a confirmed, paired session (#13): an
     * unconfirmed one is refused by the gate, so the handler — and with it
     * the biometric prompt — is never reached.
     */
    @Test
    fun verifyUserOnAnUnconfirmedSessionIsRefusedBeforeTheHandler() = runBlocking {
        val phone = connectUnpaired()
        val nonce = java.util.Base64.getEncoder().encodeToString(ByteArray(32))

        val reply = phone.desktop.request(
            MethodNames.LOCAL_VERIFY_USER,
            params = JSONObject().put("protocolVersion", 2).put("nonce", nonce)
        )

        assertEquals(ErrorCodes.PAIRING_REQUIRED, reply.getJSONObject("error").getInt("code"))
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>(), any(), any()) }
    }

    /**
     * The removal lands inside msg3 processing, after the transport keys are
     * split and before the session is installed. The keys are
     * zero when msg3 returns, and the session never connects.
     */
    @Test
    fun aRemovalBetweenTheSplitAndInstallingTheKeysLeavesNoKeysAndNoConnection() = runBlocking {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve(desktop)
        desktop.exchangeIdentity()
        desktop.sendMsg1AndReadMsg2()
        val split = CompletableDeferred<Map<String, ByteArray>>()
        phone.noise.afterSplitForTest = {
            split.complete(phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS })
            repo.removeDevice(desktop.publicKeyHex)
        }

        desktop.send(desktop.noise.createHandshakeMessage3())

        val keys = withTimeout(TIMEOUT_MS) { split.await() }
        assertEquals(TRANSPORT_SECRETS, keys.keys)
        assertTrue("serve must fail", phone.awaitServeEnded() is PeerNotPairedException)
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
        assertFalse("the session must not be connected", phone.connected.isCompleted)
        desktop.assertClosedByPhone()
    }

    // ---------------------------------------------------------------------
    // Approval outlived by its connection
    // ---------------------------------------------------------------------

    /**
     * The user is asked to approve one desktop; it is removed and a new
     * desktop connects before the user answers yes (the stream
     * counterpart of the BLE guard). The removed peer is not re-added, and the
     * new connection stays gated.
     */
    @Test
    fun anApprovalAnsweredAfterThePeerWasRemovedAndReplacedChangesNothing() = runBlocking<Unit> {
        val asked = CompletableDeferred<Unit>()
        val answer = CompletableDeferred<Boolean>()
        val callback = mockk<PairingConfirmationCallback>()
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } coAnswers {
            asked.complete(Unit)
            answer.await()
        }
        pairing = StreamPairingSession(
            requestHandler = requestHandler,
            messageRouter = null,
            pairingCallback = callback,
            pairedDeviceRepository = repo,
            transportLabel = "TEST",
        )
        val old = connectUnpaired()
        val pending = scope.async { pairing.interceptOrRoute(pairingConfirm(old.desktop.publicKeyHex)) }
        withTimeout(TIMEOUT_MS) { asked.await() }

        repo.removeDevice(old.desktop.publicKeyHex)
        old.desktop.assertClosedByPhone()
        old.awaitServeEnded()
        val replacement = connectUnpaired()

        answer.complete(true)

        assertEquals("the old approval answers nothing", null, withTimeout(TIMEOUT_MS) { pending.await() })
        assertFalse("the removed peer must not be re-added", repo.isDeviceKnown(old.desktop.publicKeyHex))
        verify(exactly = 0) { requestHandler.setConnectedDevicePublicKeyHex(old.desktop.publicKeyHex, any()) }
        val reply = replacement.desktop.request("system.ping")
        assertEquals(ErrorCodes.PAIRING_REQUIRED, reply.getJSONObject("error").getInt("code"))
    }

    // ---------------------------------------------------------------------
    // The confirmed peer a key share is checked against
    // ---------------------------------------------------------------------

    /**
     * A key share is authorized against the peer confirmed on the connection
     * it goes out on. That is this connection's own authenticated peer, never
     * the handler-wide key, and the answer ends with the connection's
     * revocation, before its teardown has run.
     */
    @Test
    fun theConfirmedConnectionIsThisConnectionsOwnPeerUntilItIsRevoked() = runBlocking<Unit> {
        val unconfirmed = connectUnpaired()
        assertNull("an unconfirmed connection confirms no one", pairing.confirmedConnection())
        unconfirmed.desktop.close()
        unconfirmed.awaitServeEnded()

        val phone = connectPaired()
        val confirmed = pairing.confirmedConnection()
        assertEquals(phone.desktop.publicKeyHex, confirmed?.peerPublicKeyHex)

        repo.removeDevice(phone.desktop.publicKeyHex)
        assertNull("a revoked connection confirms no one", pairing.confirmedConnection())
        phone.awaitServeEnded()
    }

    /**
     * A share goes out on the connection it was authorized on, or not at
     * all: a second paired desktop that connects after the check passed for
     * the first, and before the bytes reach the transport, receives nothing.
     */
    @Test
    fun aShareAuthorizedForOnePeerNeverReachesAPeerThatConnectedBeforeTheSend() = runBlocking<Unit> {
        val first = connectPaired()
        var second: Phone? = null
        val router = BidirectionalMessageRouter(requestHandler)
        // The check (same connection, same peer) has passed for the first
        // desktop when this runs; the second one, paired alongside it (so the
        // first is not revoked), connects in that window.
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing.boundSender()!!.second, router))) {
            if (second == null) second = runBlocking { connectPaired(deviceName = "second desktop") }
            true
        }!!
        assertEquals(first.desktop.publicKeyHex, session.peerPublicKeyHex)

        val share = RemoteShareClient.PublicKeyShare("k1", "-----BEGIN PUBLIC KEY-----", null, "ECDSA-P256", null, null)
        val outcome = runCatching { session.client(300).sharePublicKey(share) }

        assertTrue(
            "the share must be refused as a changed connection, got $outcome",
            outcome.exceptionOrNull() is ConnectionChangedException
        )
        val late = second ?: error("the second desktop never connected")
        assertTrue(
            "the second desktop is another peer",
            late.desktop.publicKeyHex != first.desktop.publicKeyHex
        )
        late.desktop.assertNoFrame()
    }

    /**
     * The connection-scoped send works: on the current confirmed connection
     * the frame goes out on that connection's own session and its peer
     * decrypts it.
     */
    @Test
    fun aScopedSendOnTheCurrentConfirmedConnectionReachesItsPeer() = runBlocking<Unit> {
        val phone = connectPaired()
        val confirmed = pairing.confirmedConnection() ?: error("the connection confirms no one")
        // The only scoped send path: a sender bound to this connection.
        val bound = pairing.boundSender()?.second ?: error("no bound sender")

        bound.sendEncryptedMessageOn(confirmed, REQUEST)

        assertEquals("remote.sync", phone.desktop.readEncrypted().getString("method"))
    }

    /**
     * A bound sender carries only its own connection's scoped send: handed
     * the confirmation of a later connection, even the current one, it
     * refuses, and neither desktop receives a frame.
     */
    @Test
    fun aBoundSenderRefusesAnotherConnectionsConfirmation() = runBlocking<Unit> {
        val first = connectPaired()
        val bound = pairing.boundSender()?.second ?: error("no bound sender")
        val second = connectPaired(deviceName = "second desktop")
        val current = pairing.confirmedConnection() ?: error("the connection confirms no one")
        assertEquals(second.desktop.publicKeyHex, current.peerPublicKeyHex)
        assertNull("the first connection no longer confirms anyone", bound.confirmedConnection())

        val outcome = runCatching { bound.sendEncryptedMessageOn(current, REQUEST) }

        assertTrue("got $outcome", outcome.exceptionOrNull() is ConnectionChangedException)
        second.desktop.assertNoFrame()
        first.desktop.assertNoFrame()
    }

    /**
     * The production share path, end to end: a [ShareSession] taken on the
     * shared stream session sends `remote.sharePublicKey` to the confirmed
     * desktop, which decrypts the request.
     */
    @Test
    fun aShareOnTheCurrentConnectionReachesTheConfirmedDesktop() = runBlocking<Unit> {
        val phone = connectPaired()
        val router = BidirectionalMessageRouter(requestHandler)
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing.boundSender()!!.second, router))) { true }!!
        assertEquals(phone.desktop.publicKeyHex, session.peerPublicKeyHex)

        val share = RemoteShareClient.PublicKeyShare("k1", "-----BEGIN PUBLIC KEY-----", null, "ECDSA-P256", null, null)
        // No reply comes back to this router; only the request is checked.
        val sending = scope.async { runCatching { session.client(TIMEOUT_MS).sharePublicKey(share) } }

        val request = phone.desktop.readEncrypted()
        assertEquals("remote.sharePublicKey", request.getString("method"))
        assertEquals("k1", request.getJSONObject("params").getString("key_id"))
        sending.cancel()
    }

    /**
     * Admission itself refuses a scoped send whose connection was replaced
     * after the early check: a second paired desktop that connects at that
     * point receives nothing, and neither does the first.
     */
    @Test
    fun aScopedSendReplacedAfterTheEarlyCheckIsRefusedAtAdmission() = runBlocking<Unit> {
        val first = connectPaired()
        val confirmed = pairing.confirmedConnection() ?: error("the connection confirms no one")
        // The only scoped send path: a sender bound to this connection.
        val bound = pairing.boundSender()?.second ?: error("no bound sender")
        var second: Phone? = null
        pairing.beforeAdmissionForTest = {
            if (second == null) second = connectPaired(deviceName = "second desktop")
        }

        val outcome = runCatching { bound.sendEncryptedMessageOn(confirmed, REQUEST) }
        pairing.beforeAdmissionForTest = null

        val late = second ?: error("the second desktop never connected")
        assertTrue(
            "admission must refuse the replaced connection, got $outcome",
            outcome.exceptionOrNull() is ConnectionChangedException
        )
        late.desktop.assertNoFrame()
        first.desktop.assertNoFrame()
    }

    // ---------------------------------------------------------------------
    // A revoke while a share waits for the transport
    // ---------------------------------------------------------------------

    /**
     * A desktop share has passed every check before the transport and waits
     * for admission (the send lock and the IO dispatcher); the key is set to
     * private meanwhile. Admission refuses it: nothing is written, no nonce
     * is consumed and the share is refused by policy. TCP and USB share this
     * session.
     */
    @Test
    fun aShareWhoseKeyTurnsPrivateWhileItWaitsForAdmissionWritesNothing() = runBlocking<Unit> {
        assertRevokedAtAdmission { it.makePrivate() }
    }

    /** As above, with the peer's grant for the key removed instead. */
    @Test
    fun aShareWhosePeerGrantIsRemovedWhileItWaitsForAdmissionWritesNothing() = runBlocking<Unit> {
        assertRevokedAtAdmission { it.removeGrant() }
    }

    /**
     * Every send of a share client meets the same admission check: a public
     * key, a symmetric key and an import request alike are refused at the
     * transport's admission when the key was revoked after the client
     * authorized the send, with nothing written and no nonce consumed.
     */
    @Test
    fun everyShareClientSendIsRefusedAtAdmissionAfterARevoke() = runBlocking<Unit> {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val router = BidirectionalMessageRouter(requestHandler)
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing.boundSender()!!.second, router))) { true }!!
        val store = SharedKeyStore(phone.desktop.publicKeyHex)
        val client = session.client(SHARE_TIMEOUT_MS) {
            val revision = SharePermissionLedger.revision(store.keyId)
            return@client { SharePermissionLedger.requireUnchanged(store.keyId, revision) }
        }
        // The revoke lands while each send waits inside the transport.
        pairing.beforeAdmissionForTest = { store.makePrivate() }
        val writes = gate.writes.get()
        val nonce = phone.noise.sendNonceForTest()

        val sends = listOf(
            runCatching {
                client.sharePublicKey(RemoteShareClient.PublicKeyShare(store.keyId, PEM, null, "EC", null, null))
            },
            runCatching { client.shareSymmetric(store.keyId, ByteArray(32) { 7 }, "AES", 256, null, null) },
            runCatching { client.importSharedKey("software", store.keyId, null) }
        )
        pairing.beforeAdmissionForTest = null

        sends.forEach {
            assertTrue("refused at admission, got $it", it.exceptionOrNull() is SharePermissionRevokedException)
        }
        assertEquals("nothing may reach the stream", writes, gate.writes.get())
        assertEquals("a refused send must not consume a nonce", nonce, phone.noise.sendNonceForTest())
    }

    /**
     * The legacy `deleteKey` RPC is a revoke like every other key delete: a
     * share of the key paused before admission when the real handler deletes
     * the key is refused there, with nothing written and no nonce consumed,
     * and the key's metadata row goes with its Keystore entry.
     */
    @Test
    fun aShareWhoseKeyIsDeletedByTheLegacyDeleteKeyRpcWhileItWaitsWritesNothing() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        val deleter = realHandler(keyDao)
        var deletedKeyId: String? = null
        assertRevokedAtAdmission { store ->
            deletedKeyId = store.keyId
            val request = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", "deleteKey")
                .put("params", JSONObject().put("credentialId", store.keyId))
            val response = JSONObject(String(deleter.handleRawRequest(request.toString().toByteArray())))
            assertTrue(
                "the delete must succeed, got $response",
                response.optJSONObject("result")?.optBoolean("deleted") == true
            )
        }
        coVerify { keyDao.deleteByKeyId(deletedKeyId!!) }
    }

    /**
     * A key row replaced under a pending share is a revoke: the real
     * `local.generateKey` writes a new PRIVATE row under the shared key's ID
     * while the share waits at admission (a row the handler's existence check
     * did not see, as when it appears during the generation's prompt), and
     * the share is refused, with nothing written and no nonce consumed.
     */
    @Test
    fun aShareWhoseKeyRowGenerateKeyReplacesWhileItWaitsWritesNothing() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        // The DAO's own insert runs; only the Room write under it is mocked.
        coEvery { keyDao.insert(any()) } coAnswers { callOriginal() }
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) } returns ByteArray(91) { 4 }
        val generator = realHandler(keyDao, keystore)
        var response: JSONObject? = null
        assertRevokedAtAdmission { store ->
            response = generate(generator, store.keyId)
        }
        assertTrue(
            "the generation must succeed, got $response",
            response?.optJSONObject("result")?.optString("keyId")?.isNotEmpty() == true
        )
    }

    /**
     * `local.generateKey` refuses an ID that exists in any key store (the
     * general or credential Keystore namespace, the software store, or the
     * metadata table) and writes no row.
     */
    @Test
    fun generateKeyRefusesAnIdThatExistsInAnyKeyStore() = runBlocking<Unit> {
        mockkConstructor(SoftwareKeyStore::class)
        val stores = listOf<(KeystoreManager, KeyDao, String) -> Unit>(
            { keystore, _, id -> every { keystore.generalKeyExists(id) } returns true },
            { keystore, _, id -> every { keystore.keyExists(id) } returns true },
            { _, _, id -> every { anyConstructed<SoftwareKeyStore>().contains(id) } returns true },
            { _, dao, id -> coEvery { dao.exists(id) } returns true },
        )
        stores.forEachIndexed { i, holds ->
            val keyDao = mockk<KeyDao>(relaxed = true)
            val keystore = mockk<KeystoreManager>(relaxed = true)
            every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
            val id = "existing-$i"
            holds(keystore, keyDao, id)
            val response = generate(realHandler(keyDao, keystore), id)
            assertEquals(
                "store $i: an existing ID must be refused, got $response",
                ErrorCodes.KEY_EXISTS,
                response.optJSONObject("error")?.optInt("code")
            )
            coVerify(exactly = 0) { keyDao.insert(any()) }
        }
    }

    /**
     * `local.deleteKey` is one revoke from its first removal: the real handler
     * pauses right after the key's Keystore entry is gone, before its metadata
     * row goes, and a share of the key waiting at admission resumes in that
     * window. The share is refused, with nothing written and no nonce
     * consumed, and the delete then completes.
     */
    @Test
    fun aShareResumedAfterLocalDeleteKeyRemovedTheKeystoreEntryWritesNothing() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        val removed = CompletableDeferred<Unit>()
        val finish = CountDownLatch(1)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        // The Keystore entry goes, then the delete pauses there.
        every { keystore.deleteGeneralKey(any()) } answers {
            removed.complete(Unit)
            finish.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
            true
        }
        val deleter = realHandler(keyDao, keystore)
        var response: JSONObject? = null
        var deletedKeyId: String? = null
        assertRevokedAtAdmissionDuring { store, resumeShare ->
            deletedKeyId = store.keyId
            val request = JSONObject().put("jsonrpc", "2.0").put("id", 3).put("method", "local.deleteKey")
                .put("params", JSONObject().put("keyId", store.keyId))
            val deleting = scope.async(Dispatchers.IO) {
                JSONObject(String(deleter.handleRawRequest(request.toString().toByteArray())))
            }
            try {
                withTimeout(TIMEOUT_MS) { removed.await() }
                resumeShare()
            } finally {
                finish.countDown()
            }
            response = withTimeout(TIMEOUT_MS) { deleting.await() }
        }
        assertTrue(
            "the delete must succeed, got $response",
            response?.optJSONObject("result")?.optBoolean("deleted") == true
        )
        coVerify { keyDao.deleteByKeyId(deletedKeyId!!) }
    }

    /**
     * A delete through the alias form of a key's ID is a revoke of the key
     * itself: the legacy `deleteKey` RPC with `credentialId = xkey_key_<id>`
     * removes the same Keystore entry as `<id>`, so a share of `<id>` waiting
     * at admission is refused, and `<id>`'s metadata row goes too.
     */
    @Test
    fun aShareOfAKeyDeletedThroughItsAliasFormWhileItWaitsWritesNothing() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.keyExists(any()) } returns true
        every { keystore.deleteKey(any()) } returns true
        // The raw alias resolves to itself, as KeystoreManager does for it.
        every { keystore.resolveKeystoreAlias(any()) } answers {
            firstArg<String>().takeIf { it.startsWith("xkey_key_") }
        }
        val deleter = realHandler(keyDao, keystore)
        var deletedKeyId: String? = null
        assertRevokedAtAdmission { store ->
            deletedKeyId = store.keyId
            val request = JSONObject().put("jsonrpc", "2.0").put("id", 4).put("method", "deleteKey")
                .put("params", JSONObject().put("credentialId", "xkey_key_" + store.keyId))
            val response = JSONObject(String(deleter.handleRawRequest(request.toString().toByteArray())))
            assertTrue(
                "the delete must succeed, got $response",
                response.optJSONObject("result")?.optBoolean("deleted") == true
            )
        }
        coVerify { keyDao.deleteByKeyId(deletedKeyId!!) }
    }

    /**
     * A share is bound to the revision it captured before loading its
     * inputs: a key deleted and recreated under the same ID after the share
     * loaded its record and public half, and before admission, is refused
     * there, though the recreated key is shared with the same peer.
     */
    @Test
    fun aKeyDeletedAndRecreatedAfterTheShareLoadedItsInputsIsRefusedAtAdmission() = runBlocking<Unit> {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val router = BidirectionalMessageRouter(requestHandler)
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing.boundSender()!!.second, router))) { true }!!
        val store = SharedKeyStore(phone.desktop.publicKeyHex)
        // The DAO's own writes run; only the Room writes under them are mocked.
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.deleteByKeyId(any()) } coAnswers { callOriginal() }
        coEvery { keyDao.insert(any()) } coAnswers { callOriginal() }

        val baseline = SharePermissionLedger.baseline(store.keyId)
        val loadedEntity = store.entity!!
        val loadedPem = PEM
        // Deleted and recreated, still shared with the peer, after the load.
        keyDao.deleteByKeyId(store.keyId)
        keyDao.insert(loadedEntity.copy(label = "recreated"))
        val writes = gate.writes.get()
        val nonce = phone.noise.sendNonceForTest()

        val outcome = runCatching {
            DesktopKeyShare(session, SHARE_TIMEOUT_MS)
                .send(baseline, loadedEntity, null, loadedPem, null, store.permission, store.current)
        }
        assertEquals(
            "the share must be refused by policy, got $outcome",
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            outcome.getOrNull()
        )
        assertEquals("nothing may reach the stream", writes, gate.writes.get())
        assertEquals("a refused send must not consume a nonce", nonce, phone.noise.sendNonceForTest())
    }

    /**
     * `local.generateKey` opens its revoke before it touches key material: a
     * generation that replaces an ID its existence checks did not see pauses
     * right after the old Keystore entry is removed, a share of that ID
     * waiting at admission resumes in that window, and it is refused.
     */
    @Test
    fun aShareResumedAfterGenerateKeyRemovedTheOldKeystoreEntryWritesNothing() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        val removed = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val keystore = mockk<KeystoreManager>(relaxed = true)
        // The old entry goes, then the generation pauses there.
        coEvery { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) } coAnswers {
            removed.complete(Unit)
            withTimeout(TIMEOUT_MS) { finish.await() }
            ByteArray(91) { 4 }
        }
        val generator = realHandler(keyDao, keystore)
        var response: JSONObject? = null
        assertRevokedAtAdmissionDuring { store, resumeShare ->
            val generating = scope.async(Dispatchers.IO) { generate(generator, store.keyId) }
            try {
                withTimeout(TIMEOUT_MS) { removed.await() }
                resumeShare()
            } finally {
                finish.complete(Unit)
            }
            response = withTimeout(TIMEOUT_MS) { generating.await() }
        }
        assertTrue(
            "the generation must succeed, got $response",
            response?.optJSONObject("result")?.optString("keyId")?.isNotEmpty() == true
        )
    }

    /**
     * `local.generateKey` reserves its ID until it ends: a second generation
     * of the same ID while the first is pending (here, paused inside the
     * generation) is refused with `KEY_EXISTS` and generates nothing.
     */
    @Test
    fun aSecondGenerateKeyOfAnIdIsRefusedWhileTheFirstIsPending() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val calls = AtomicInteger()
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) } coAnswers {
            if (calls.incrementAndGet() == 1) {
                started.complete(Unit)
                withTimeout(TIMEOUT_MS) { finish.await() }
            }
            ByteArray(91) { 4 }
        }
        val generator = realHandler(keyDao, keystore)
        val first = scope.async(Dispatchers.IO) { generate(generator, "pending-generation") }
        val second = try {
            withTimeout(TIMEOUT_MS) { started.await() }
            generate(generator, "pending-generation")
        } finally {
            finish.complete(Unit)
        }
        assertEquals(
            "a second generation of a pending ID must be refused, got $second",
            ErrorCodes.KEY_EXISTS,
            second.optJSONObject("error")?.optInt("code")
        )
        assertEquals("the second generation must generate nothing", 1, calls.get())
        val firstResponse = withTimeout(TIMEOUT_MS) { first.await() }
        assertTrue(
            "the first generation must succeed, got $firstResponse",
            firstResponse.optJSONObject("result")?.optString("keyId")?.isNotEmpty() == true
        )
    }

    /**
     * A PIV slot's key is an ordinary shareable key under the ID
     * `KeyStoreSyncManager` discovers it by, its Keystore alias: the real
     * [PivKeyManager.deleteKey], paused right after it removed the slot's
     * Keystore entry, refuses a share of that ID waiting at admission.
     */
    @Test
    fun aShareOfAPivKeyDeletedWhileItWaitsWritesNothing() = runBlocking<Unit> {
        val slot = PivSlot.KEY_MANAGEMENT
        val keyStore = pivEdges()
        val removed = CompletableDeferred<Unit>()
        val finish = CountDownLatch(1)
        every { keyStore.containsAlias(slot.keystoreAlias) } returns true
        // The entry goes, then the delete pauses there.
        every { keyStore.deleteEntry(slot.keystoreAlias) } answers {
            removed.complete(Unit)
            finish.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
            Unit
        }
        val manager = PivKeyManager(mockk<PivSlotDao>(relaxed = true))
        assertRevokedAtAdmissionDuring(slot.keystoreAlias) { _, resumeShare ->
            val deleting = scope.async(Dispatchers.IO) { manager.deleteKey(slot) }
            try {
                withTimeout(TIMEOUT_MS) { removed.await() }
                resumeShare()
            } finally {
                finish.countDown()
            }
            withTimeout(TIMEOUT_MS) { deleting.await() }
        }
        verify { keyStore.deleteEntry(slot.keystoreAlias) }
    }

    /**
     * The real [PivKeyManager.generateKey] replacing a slot's key, paused
     * inside the generation that overwrites the slot's alias, refuses a share
     * of that slot's ID waiting at admission: the old public key it loaded is
     * never sent.
     */
    @Test
    fun aShareOfAPivKeyReplacedByGenerateKeyWhileItWaitsWritesNothing() = runBlocking<Unit> {
        val slot = PivSlot.DIGITAL_SIGNATURE
        pivEdges()
        val replacing = CompletableDeferred<Unit>()
        val finish = CountDownLatch(1)
        val newKey = keyPair(ByteArray(91) { 5 })
        val manager = PivKeyManager(mockk<PivSlotDao>(relaxed = true)) { _, _ ->
            replacing.complete(Unit)
            finish.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
            newKey
        }
        var generated: PivSlotInfo? = null
        assertRevokedAtAdmissionDuring(slot.keystoreAlias) { _, resumeShare ->
            val generating = scope.async(Dispatchers.IO) { manager.generateKey(slot, PivAlgorithm.ES256) }
            try {
                withTimeout(TIMEOUT_MS) { replacing.await() }
                resumeShare()
            } finally {
                finish.countDown()
            }
            generated = withTimeout(TIMEOUT_MS) { generating.await() }
        }
        assertArrayEquals("the generation must succeed", newKey.public.encoded, generated?.publicKeyDer)
    }

    /**
     * The PIV writers' revoke ends with them: a share of a slot's key started
     * after [PivKeyManager.generateKey] completed sends the new public key.
     */
    @Test
    fun aShareOfAPivKeyStartedAfterGenerateKeyCompletesSendsTheNewKey() = runBlocking<Unit> {
        val slot = PivSlot.CARD_AUTHENTICATION
        pivEdges()
        val newKey = keyPair(ByteArray(91) { 7 })
        val manager = PivKeyManager(mockk<PivSlotDao>(relaxed = true)) { _, _ -> newKey }
        val phone = connectPaired()
        val router = BidirectionalMessageRouter(requestHandler)
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing.boundSender()!!.second, router))) { true }!!
        val store = SharedKeyStore(phone.desktop.publicKeyHex, slot.keystoreAlias)

        val generated = manager.generateKey(slot, PivAlgorithm.ES256)
        val baseline = SharePermissionLedger.baseline(store.keyId)
        val newPem = "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getEncoder().encodeToString(generated.publicKeyDer) + "\n-----END PUBLIC KEY-----\n"
        // No reply comes back to this router; only the request is checked.
        val sending = scope.async {
            runCatching {
                DesktopKeyShare(session, TIMEOUT_MS)
                    .send(baseline, store.entity!!, null, newPem, null, store.permission, store.current)
            }
        }

        val request = phone.desktop.readEncrypted()
        assertEquals("remote.sharePublicKey", request.getString("method"))
        val sentPem = String(Base64.getDecoder().decode(request.getJSONObject("params").getString("public_key_pem")))
        assertEquals("the new public key must be sent", newPem, sentPem)
        sending.cancel()
    }

    /** The Android edges [PivKeyManager] reaches; returns the Keystore it opens. */
    private fun pivEdges(): KeyStore {
        val keyStore = mockk<KeyStore>(relaxed = true)
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
        every { AuditLogger.logKeyCreated(any(), any(), any(), any(), any()) } just runs
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } just runs
        return keyStore
    }

    private fun keyPair(publicDer: ByteArray): KeyPair =
        KeyPair(mockk<PublicKey> { every { encoded } returns publicDer }, mockk<PrivateKey>())

    private suspend fun generate(handler: RequestHandler, keyId: String): JSONObject {
        val request = JSONObject().put("jsonrpc", "2.0").put("id", 2).put("method", "local.generateKey")
            .put(
                "params",
                JSONObject().put("keyId", keyId).put("algorithm", "ES256").put("label", keyId)
                    .put("requireUserVerification", false).put("shareable", false)
            )
        return JSONObject(String(handler.handleRawRequest(request.toString().toByteArray())))
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(
        keyDao: KeyDao,
        keystore: KeystoreManager = mockk<KeystoreManager>(relaxed = true).also {
            every { it.keyExists(any()) } returns true
            every { it.deleteKey(any()) } returns true
        },
    ): RequestHandler {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns mockk<KeyguardManager>(relaxed = true)
        // The software key store opens the Keystore and its directory when built.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        every { context.filesDir } returns Files.createTempDirectory("xkey-files").toFile().apply { deleteOnExit() }
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        return RequestHandler(context, keystore, biometricLauncher = null, sessionAuthManager = null)
    }

    private suspend fun assertRevokedAtAdmission(revoke: suspend (SharedKeyStore) -> Unit) =
        assertRevokedAtAdmissionDuring { store, resumeShare ->
            revoke(store)
            resumeShare()
        }

    /**
     * As [assertRevokedAtAdmission], with [revoke] choosing when the share
     * waiting at admission resumes: `resumeShare` lets it go and returns once
     * the share has finished.
     */
    private suspend fun assertRevokedAtAdmissionDuring(
        keyId: String? = null,
        revoke: suspend (store: SharedKeyStore, resumeShare: suspend () -> Unit) -> Unit
    ) {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val router = BidirectionalMessageRouter(requestHandler)
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing.boundSender()!!.second, router))) { true }!!
        val store = keyId?.let { SharedKeyStore(phone.desktop.publicKeyHex, it) }
            ?: SharedKeyStore(phone.desktop.publicKeyHex)
        val baseline = SharePermissionLedger.baseline(store.keyId)
        val paused = CompletableDeferred<Unit>()
        val resume = CompletableDeferred<Unit>()
        pairing.beforeAdmissionForTest = {
            paused.complete(Unit)
            resume.await()
        }
        val sending = scope.async {
            runCatching {
                DesktopKeyShare(session, SHARE_TIMEOUT_MS)
                    .send(baseline, store.entity, null, PEM, null, store.permission, store.current)
            }
        }
        withTimeout(TIMEOUT_MS) { paused.await() }
        val writes = gate.writes.get()
        val nonce = phone.noise.sendNonceForTest()

        revoke(store) {
            resume.complete(Unit)
            withTimeout(TIMEOUT_MS) { sending.join() }
        }
        resume.complete(Unit)

        val outcome = withTimeout(TIMEOUT_MS) { sending.await() }
        pairing.beforeAdmissionForTest = null
        assertEquals(
            "the share must be refused by policy, got $outcome",
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            outcome.getOrNull()
        )
        assertEquals("nothing may reach the stream", writes, gate.writes.get())
        assertEquals("a refused send must not consume a nonce", nonce, phone.noise.sendNonceForTest())
    }

    // ---------------------------------------------------------------------
    // Re-pairing
    // ---------------------------------------------------------------------

    /**
     * After a removal tore the session down, the same desktop key pairs
     * again: the next connection on the same transport is served, receives
     * the phone's requests, and is itself revoked by a second removal.
     */
    @Test
    fun rePairingTheSameKeyAfterARemovalWorks() = runBlocking<Unit> {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val first = connectPaired(staticPrivateKey = key)
        repo.removeDevice(first.desktop.publicKeyHex)
        first.desktop.assertClosedByPhone()
        first.awaitServeEnded()

        val second = connectPaired(staticPrivateKey = key)
        assertEquals(first.desktop.publicKeyHex, second.desktop.publicKeyHex)
        assertTrue(second.desktop.request("system.ping").getJSONObject("result").getBoolean("ok"))
        pairing.sendOnBoundSession(REQUEST)
        assertEquals("remote.sync", second.desktop.readEncrypted().getString("method"))

        repo.removeDevice(second.desktop.publicKeyHex)
        second.desktop.assertClosedByPhone()
        second.awaitServeEnded()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private inner class Phone(
        val desktop: DesktopPeer,
        val noise: NoiseSession,
        val connected: CompletableDeferred<Unit>,
        private val served: CompletableDeferred<Throwable?>,
    ) {
        /** Waits for [StreamPairingSession.serve] to return; its failure, or null. */
        suspend fun awaitServeEnded(): Throwable? = withTimeout(TIMEOUT_MS) { served.await() }
    }

    /** Pairs a desktop, connects it, completes the handshake and waits for the session. */
    private suspend fun connectPaired(
        gate: GatedOutputStream? = null,
        staticPrivateKey: ByteArray? = null,
        deviceName: String = "desktop",
    ): Phone {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = if (staticPrivateKey != null) DesktopPeer(socket, staticPrivateKey) else DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, deviceName)
        val phone = serve(desktop, gate)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }
        return phone
    }

    /** Connects a desktop that is not paired and completes the handshake; the session is gated. */
    private suspend fun connectUnpaired(): Phone {
        val desktop = DesktopPeer(Socket(listener.inetAddress, listener.localPort))
        val phone = serve(desktop)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }
        return phone
    }

    private fun pairingConfirm(keyHex: String): ByteArray = JSONObject()
        .put("jsonrpc", "2.0")
        .put("id", 3)
        .put("method", "pairing.confirm")
        .put("params", JSONObject().put("deviceName", "desktop").put("publicKeyHex", keyHex))
        .toString()
        .toByteArray()

    /** Accepts [desktop]'s connection and runs the phone's side of it. */
    private suspend fun serve(desktop: DesktopPeer, gate: GatedOutputStream? = null): Phone {
        val accepted = connections.track(listener.accept())
        val noise = NoiseSession().also { it.loadStaticKey(context) }
        val connected = CompletableDeferred<Unit>()
        val served = CompletableDeferred<Throwable?>()
        val output: OutputStream = gate?.also { it.target = accepted.getOutputStream() } ?: accepted.getOutputStream()
        scope.launch {
            val failure = runCatching {
                pairing.serve(
                    input = accepted.getInputStream(),
                    output = output,
                    noiseSession = noise,
                    connectionId = "test:${java.util.UUID.randomUUID()}",
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }.exceptionOrNull()
            accepted.close()
            served.complete(failure)
        }
        return Phone(desktop, noise, connected, served)
    }

    /**
     * Passes writes through until [armed]; then a write blocks until the
     * stream is closed and fails, as a socket write does when the peer is
     * not reading and the connection is torn down.
     */
    private class GatedOutputStream : OutputStream() {
        lateinit var target: OutputStream
        @Volatile var armed = false
        val entered = CountDownLatch(1)

        /** Every write that reached this stream, passed through or blocked. */
        val writes = AtomicInteger()
        private val closed = CountDownLatch(1)

        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            writes.incrementAndGet()
            if (armed) {
                entered.countDown()
                closed.await()
                throw IOException("stream closed")
            }
            target.write(b, off, len)
        }

        override fun flush() = target.flush()

        override fun close() {
            closed.countDown()
            target.close()
        }
    }
}
