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

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.ble.NoiseTestKeyStore
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.ble.sessionBinding
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.TransportMethods
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * pairing.confirm and the unpaired gate of a [StreamPairingSession], over a
 * loopback socket against [DesktopPeer]: the user's decision table, the key
 * a desktop CLAIMS in its params against the key its handshake
 * AUTHENTICATES, and the PAIRING_REQUIRED answer every other request gets
 * before pairing, with its `id` and `generation` echoed.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamPairingConfirmTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L
        const val DEVICE_NAME = "build-desktop"
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var family: TransportMethods
    private lateinit var pairing: StreamPairingSession
    private lateinit var mainThread: ExecutorService
    private lateinit var listener: ServerSocket
    private val connections = ServedConnections()

    @Before
    fun setUp() {
        NoiseTestKeyStore.install()
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
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } answers {
            val id = JSONObject(String(firstArg<ByteArray>())).optLong("id")
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()
        }
        family = mockk(relaxed = true)
        every { family.handles(any()) } answers { firstArg<String>().startsWith("test.") }
        listener = ServerSocket(0, 4, InetAddress.getLoopbackAddress())
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
    // The user's decision
    // ---------------------------------------------------------------------

    /**
     * An approved pairing.confirm prompts with the claimed device name, the
     * first 16 hex characters of the handshake key and the SAS the desktop
     * derives from its own end; the answer is success with the phone's name,
     * and the device is stored under the handshake key.
     */
    @Test
    fun anApprovedConfirmPromptsWithTheDesktopsSasAndStoresTheDevice() = runBlocking {
        val callback = RecordingCallback(approve = true)
        val desktop = pairedOver(callback)

        val reply = desktop.raw(confirmText(id = 21, generation = 210, key = desktop.publicKeyHex))

        assertEquals(
            listOf(listOf(DEVICE_NAME, desktop.publicKeyHex.take(16), desktopSas(desktop))),
            callback.prompts,
        )
        assertEquals(21L, reply.getLong("id"))
        assertEquals(210L, reply.getLong("generation"))
        val result = reply.getJSONObject("result")
        assertTrue(result.getBoolean("confirmed"))
        assertEquals(phoneModelName(), result.getString("deviceName"))
        assertEquals(DEVICE_NAME, repo.getDevice(desktop.publicKeyHex)?.deviceName)
        assertEquals(desktop.publicKeyHex, pairing.confirmedPeerKeyHex())

        val after = desktop.request("local.getCapabilities", id = 22)
        assertTrue(after.getJSONObject("result").getBoolean("ok"))
    }

    /** The claimed key is compared without regard to case; the device is stored lowercase. */
    @Test
    fun anUppercaseClaimedKeyIsAccepted() = runBlocking {
        val callback = RecordingCallback(approve = true)
        val desktop = pairedOver(callback)

        val reply = desktop.raw(confirmText(id = 23, generation = 230, key = desktop.publicKeyHex.uppercase()))

        assertTrue(reply.getJSONObject("result").getBoolean("confirmed"))
        assertEquals(1, callback.prompts.size)
        assertTrue(repo.isDeviceKnown(desktop.publicKeyHex))
        assertFalse(repo.isDeviceKnown(desktop.publicKeyHex.uppercase()))
    }

    /**
     * A pairing.confirm whose claimed key is not the handshake key is
     * refused before any prompt, stores nothing, and ends the connection.
     */
    @Test
    fun aClaimedKeyThatIsNotTheHandshakeKeyIsRejectedWithoutAPrompt() = runBlocking {
        val callback = RecordingCallback(approve = true)
        val desktop = pairedOver(callback)
        val other = "ab".repeat(32)

        val reply = desktop.raw(confirmText(id = 24, generation = 240, key = other))

        assertError(reply, id = 24, generation = 240, code = ErrorCodes.PAIRING_REJECTED)
        assertTrue(callback.prompts.isEmpty())
        assertFalse(repo.isDeviceKnown(desktop.publicKeyHex))
        assertFalse(repo.isDeviceKnown(other))
        assertNull(pairing.confirmedConnection())
        desktop.assertClosedByPhone()
    }

    /** The user declines: PAIRING_REJECTED, nothing stored, and the connection closes after the answer. */
    @Test
    fun aDeclinedConfirmIsRejectedStoresNothingAndCloses() = runBlocking {
        val callback = RecordingCallback(approve = false)
        val desktop = pairedOver(callback)

        val reply = desktop.raw(confirmText(id = 25, generation = 250, key = desktop.publicKeyHex))

        assertError(reply, id = 25, generation = 250, code = ErrorCodes.PAIRING_REJECTED)
        assertEquals(1, callback.prompts.size)
        assertFalse(repo.isDeviceKnown(desktop.publicKeyHex))
        assertNull(pairing.confirmedConnection())
        desktop.assertClosedByPhone()
    }

    /** No approval UI means nothing can grant trust. */
    @Test
    fun aSessionWithoutACallbackRejectsStoresNothingAndCloses() = runBlocking {
        val desktop = pairedOver(callback = null)

        val reply = desktop.raw(confirmText(id = 26, generation = 260, key = desktop.publicKeyHex))

        assertError(reply, id = 26, generation = 260, code = ErrorCodes.PAIRING_REJECTED)
        assertFalse(repo.isDeviceKnown(desktop.publicKeyHex))
        assertNull(pairing.confirmedConnection())
        desktop.assertClosedByPhone()
    }

    /**
     * A desktop already in the store is confirmed by its handshake with no
     * prompt; its pairing.confirm is answered by `confirmAlreadyPaired` and
     * the connection stays open.
     */
    @Test
    fun anAlreadyPairedDesktopIsConfirmedAtTheHandshakeWithoutAPrompt() = runBlocking {
        val callback = RecordingCallback(approve = false)
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "known")
        val phone = serve(callback)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.await() }
        assertEquals(desktop.publicKeyHex, pairing.confirmedPeerKeyHex())

        val reply = desktop.raw(confirmText(id = 27, generation = 270, key = desktop.publicKeyHex))

        assertEquals(27L, reply.getLong("id"))
        assertEquals(270L, reply.getLong("generation"))
        val result = reply.getJSONObject("result")
        assertTrue(result.getBoolean("confirmed"))
        assertEquals(phoneModelName(), result.getString("deviceName"))
        assertTrue(callback.prompts.isEmpty())
        assertEquals("known", repo.getDevice(desktop.publicKeyHex)?.deviceName)
        val after = desktop.request("local.getCapabilities", id = 28)
        assertTrue(after.getJSONObject("result").getBoolean("ok"))
    }

    /** A pairing.confirm with no params is answered PAIRING_REQUIRED and ends the connection. */
    @Test
    fun aConfirmWithoutParamsGetsPairingRequiredAndCloses() = runBlocking {
        val callback = RecordingCallback(approve = true)
        val desktop = pairedOver(callback)

        val reply = desktop.raw("""{"jsonrpc":"2.0","id":29,"generation":290,"method":"pairing.confirm"}""")

        assertError(reply, id = 29, generation = 290, code = ErrorCodes.PAIRING_REQUIRED)
        assertTrue(callback.prompts.isEmpty())
        assertFalse(repo.isDeviceKnown(desktop.publicKeyHex))
        desktop.assertClosedByPhone()
    }

    /** Params without `publicKeyHex` are invalid: PAIRING_REQUIRED, and the connection ends. */
    @Test
    fun aConfirmWithInvalidParamsGetsPairingRequiredAndCloses() = runBlocking {
        val callback = RecordingCallback(approve = true)
        val desktop = pairedOver(callback)

        val reply = desktop.raw(
            """{"jsonrpc":"2.0","id":30,"generation":300,"method":"pairing.confirm",""" +
                """"params":{"deviceName":"$DEVICE_NAME"}}"""
        )

        assertError(reply, id = 30, generation = 300, code = ErrorCodes.PAIRING_REQUIRED)
        assertTrue(callback.prompts.isEmpty())
        assertFalse(repo.isDeviceKnown(desktop.publicKeyHex))
        desktop.assertClosedByPhone()
    }

    /**
     * A second pairing.confirm on a connection whose first is still waiting
     * for the user is refused with PAIRING_REJECTED, and the connection ends
     * once the first is answered.
     */
    @Test
    fun aSecondConfirmWhileTheFirstWaitsIsRejected() = runBlocking {
        val prompted = CompletableDeferred<Unit>()
        val decision = CompletableDeferred<Boolean>()
        val callback = object : PairingConfirmationCallback {
            override suspend fun onPairingConfirmationRequired(deviceName: String, publicKeyFingerprint: String) =
                false

            override suspend fun onPairingConfirmationRequired(
                deviceName: String,
                publicKeyFingerprint: String,
                shortAuthString: String,
            ): Boolean {
                prompted.complete(Unit)
                return decision.await()
            }
        }
        val desktop = pairedOver(callback)
        desktop.send(desktop.noise.encrypt(confirmText(id = 31, generation = 310, key = desktop.publicKeyHex).toByteArray()))
        withTimeout(TIMEOUT_MS) { prompted.await() }

        val second = pairing.interceptOrRoute(
            confirmText(id = 32, generation = 320, key = desktop.publicKeyHex).toByteArray()
        )

        assertError(JSONObject(String(second!!, Charsets.UTF_8)), id = 32, generation = 320, code = ErrorCodes.PAIRING_REJECTED)
        decision.complete(true)
        val first = desktop.readEncrypted()
        assertEquals(31L, first.getLong("id"))
        desktop.assertClosedByPhone()
    }

    // ---------------------------------------------------------------------
    // The gate before pairing
    // ---------------------------------------------------------------------

    /** A normal request before pairing: PAIRING_REQUIRED, `id` and `generation` echoed, the handler untouched. */
    @Test
    fun aRequestBeforePairingGetsPairingRequired() = runBlocking {
        val desktop = pairedOver(RecordingCallback(approve = true))

        val reply = desktop.raw("""{"jsonrpc":"2.0","id":41,"generation":410,"method":"local.getCapabilities"}""")

        assertError(reply, id = 41, generation = 410, code = ErrorCodes.PAIRING_REQUIRED)
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        verify(exactly = 0) { family.handles(any()) }
        coVerify(exactly = 0) { family.handle(any()) }
    }

    /** A transport-family method is gated too: the family is never asked. */
    @Test
    fun aTransportMethodBeforePairingGetsPairingRequired() = runBlocking {
        val desktop = pairedOver(RecordingCallback(approve = true))

        val reply = desktop.raw("""{"jsonrpc":"2.0","id":42,"generation":420,"method":"test.list"}""")

        assertError(reply, id = 42, generation = 420, code = ErrorCodes.PAIRING_REQUIRED)
        verify(exactly = 0) { family.handles(any()) }
        coVerify(exactly = 0) { family.handle(any()) }
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
    }

    /**
     * A request whose id is a numeric string is gated with the id read as
     * its number. (A non-numeric string id is answered with id -1: Response
     * ids are numbers.)
     */
    @Test
    fun aStringIdRequestBeforePairingGetsPairingRequired() = runBlocking {
        val desktop = pairedOver(RecordingCallback(approve = true))

        val reply = desktop.raw("""{"jsonrpc":"2.0","id":"43","generation":430,"method":"local.getCapabilities"}""")

        assertError(reply, id = 43, generation = 430, code = ErrorCodes.PAIRING_REQUIRED)
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        coVerify(exactly = 0) { family.handle(any()) }
    }

    /** A response frame before pairing belongs to no request: it is answered with nothing. */
    @Test
    fun aResponseBeforePairingGetsNoReply() = runBlocking {
        val desktop = pairedOver(RecordingCallback(approve = true))

        desktop.send(desktop.noise.encrypt("""{"jsonrpc":"2.0","id":44,"result":{}}""".toByteArray()))

        desktop.assertNoFrame()
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        val reply = desktop.raw("""{"jsonrpc":"2.0","id":45,"generation":450,"method":"local.getCapabilities"}""")
        assertError(reply, id = 45, generation = 450, code = ErrorCodes.PAIRING_REQUIRED)
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Records every prompt as `[deviceName, keyPrefix, sas]` and answers [approve]. */
    private class RecordingCallback(private val approve: Boolean) : PairingConfirmationCallback {
        val prompts = CopyOnWriteArrayList<List<String>>()

        override suspend fun onPairingConfirmationRequired(deviceName: String, publicKeyFingerprint: String): Boolean {
            prompts += listOf(deviceName, publicKeyFingerprint)
            return approve
        }

        override suspend fun onPairingConfirmationRequired(
            deviceName: String,
            publicKeyFingerprint: String,
            shortAuthString: String,
        ): Boolean {
            prompts += listOf(deviceName, publicKeyFingerprint, shortAuthString)
            return approve
        }
    }

    /** An unknown desktop, handshaken and connected but not yet confirmed. */
    private suspend fun pairedOver(callback: PairingConfirmationCallback?): DesktopPeer {
        val desktop = newDesktop()
        val connected = serve(callback)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { connected.await() }
        assertNull(pairing.confirmedConnection())
        return desktop
    }

    private fun desktopSas(desktop: DesktopPeer): String =
        AttestTranscript.shortAuthString(desktop.noise.sessionBinding())

    private fun newDesktop(): DesktopPeer = DesktopPeer(Socket(listener.inetAddress, listener.localPort))

    /** Sends [json] exactly as written and returns the decrypted reply. */
    private fun DesktopPeer.raw(json: String): JSONObject {
        send(noise.encrypt(json.toByteArray()))
        return readEncrypted()
    }

    private fun confirmText(id: Long, generation: Long, key: String) =
        """{"jsonrpc":"2.0","id":$id,"generation":$generation,"method":"pairing.confirm",""" +
            """"params":{"publicKeyHex":"$key","deviceName":"$DEVICE_NAME"}}"""

    private fun assertError(reply: JSONObject, id: Long, generation: Long, code: Int) {
        assertEquals("id of $reply", id, reply.getLong("id"))
        assertEquals("generation of $reply", generation, reply.getLong("generation"))
        assertFalse("no result in $reply", reply.has("result"))
        assertEquals("code of $reply", code, reply.getJSONObject("error").getInt("code"))
    }

    /** Builds the session with [callback], accepts the next connection and serves it; completes on connect. */
    private suspend fun serve(callback: PairingConfirmationCallback?): CompletableDeferred<Unit> {
        pairing = StreamPairingSession(
            requestHandler = requestHandler,
            messageRouter = null,
            pairingCallback = callback,
            pairedDeviceRepository = repo,
            transportLabel = "TEST",
            transportMethods = listOf(family),
        )
        val session = pairing
        val accepted = connections.track(listener.accept())
        val noise = NoiseSession().also { it.loadStaticKey(context) }
        val connected = CompletableDeferred<Unit>()
        connections.scope.launch {
            runCatching {
                session.serve(
                    input = accepted.getInputStream(),
                    output = accepted.getOutputStream(),
                    noiseSession = noise,
                    connectionId = "test:${java.util.UUID.randomUUID()}",
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }
            accepted.close()
        }
        return connected
    }
}
