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

package com.automatethethings.xkey.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import java.lang.reflect.InvocationTargetException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Every answer [GattServer] writes itself carries the request's `id` exactly
 * as the desktop sent it: `rejectUnpaired`, the `pairing.confirm` refusals of
 * `handlePairingConfirmIfNeeded` (rejected, mismatched key, no store), and
 * the internal error a request that throws while routed is answered with. A
 * JSON-RPC client matches an answer to its request by that value.
 *
 * Drives the server's private message path by reflection, as
 * [GattServerGenerationEchoTest] does.
 */
class GattServerIdEchoTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"

        /** The ids sent, as JSON text: a string, a string of digits, and uint64 max. */
        val IDS = listOf("\"abc\"", "\"12\"", "18446744073709551615")

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        fun pairingConfirm(id: String, keyHex: String): ByteArray =
            ("""{"jsonrpc":"2.0","id":$id,"method":"pairing.confirm",""" +
                """"params":{"deviceName":"desktop","publicKeyHex":"$keyHex"}}""").toByteArray()

        /** The `id` member's value exactly as written, or null when absent. */
        fun rawId(json: String): String? =
            Regex(""""id":("(?:[^"\\]|\\.)*"|-?\d+|null)[,}]""").find(json)?.groupValues?.get(1)
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var callback: PairingConfirmationCallback
    private lateinit var gatt: BluetoothGattServer
    private lateinit var device: BluetoothDevice
    private lateinit var server: GattServer

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
        every { AuditLogger.logPairingApproved(any(), any(), any()) } just runs
        every { AuditLogger.logPairingDenied(any(), any(), any()) } just runs

        context = mockk(relaxed = true)
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        router = BidirectionalMessageRouter(requestHandler)
        callback = mockk()
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        device = mockk(relaxed = true)
        every { device.address } returns ADDRESS
        every { device.name } returns "desktop"
        server = newServer(repo)
    }

    @After
    fun tearDown() {
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    @Test
    fun rejectUnpairedEchoesTheIdAsSent() = runBlocking<Unit> {
        for (id in IDS) {
            reset()
            val desktop = connect(paired = false)

            val answer = ask(desktop, """{"jsonrpc":"2.0","id":$id,"method":"local.generateKey","params":{}}""".toByteArray())

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.PAIRING_REQUIRED, errorCode(answer))
        }
    }

    @Test
    fun aRejectedPairingConfirmEchoesTheIdAsSent() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns false
        for (id in IDS) {
            reset()
            val desktop = connect(paired = false)

            val answer = ask(desktop, pairingConfirm(id, desktop.getLocalStaticPublicKey().hex()))

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
        }
    }

    @Test
    fun aMismatchedPairingKeyEchoesTheIdAsSent() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        for (id in IDS) {
            reset()
            val desktop = connect(paired = false)

            val answer = ask(desktop, pairingConfirm(id, "cd".repeat(32)))

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
        }
    }

    @Test
    fun aPairingConfirmWithoutAStoreEchoesTheIdAsSent() = runBlocking<Unit> {
        server.destroy()
        awaitScopeFinished(server)
        server = newServer(null)
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        for (id in IDS) {
            reset()
            val desktop = connect(paired = false)

            val answer = ask(desktop, pairingConfirm(id, desktop.getLocalStaticPublicKey().hex()))

            assertEquals(id, rawId(answer))
            val code = errorCode(answer)
            assertTrue("code $code", code == ErrorCodes.PAIRING_REJECTED || code == ErrorCodes.PAIRING_REQUIRED)
        }
    }

    /** A request that throws while it is routed is answered with its own id, not 0. */
    @Test
    fun aRequestThatThrowsWhileRoutedEchoesItsIdAsSent() = runBlocking<Unit> {
        server.destroy()
        awaitScopeFinished(server)
        server = newServer(repo, messageRouter = null)
        coEvery { requestHandler.handleRawRequest(any()) } throws IllegalStateException("boom")
        every { requestHandler.createErrorResponse(any(), any(), any()) } answers {
            Response.error(id = firstArg(), code = secondArg(), message = thirdArg()).toJson()
        }
        for (id in IDS) {
            reset()
            val desktop = connect(paired = true)

            val answer = ask(desktop, """{"jsonrpc":"2.0","id":$id,"method":"local.listKeys"}""".toByteArray())

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(answer))
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun newServer(
        store: PairedDeviceRepository?,
        messageRouter: BidirectionalMessageRouter? = router,
    ): GattServer {
        serverStore = store
        serverRouter = messageRouter
        return GattServer(
            context,
            requestHandler,
            messageRouter = messageRouter,
            pairingCallback = callback,
            pairedDeviceRepository = store
        ).also {
            server = it
            setField("gattServer", gatt)
            setField("responseCharacteristic", mockk<BluetoothGattCharacteristic>(relaxed = true))
        }
    }

    private var serverStore: PairedDeviceRepository? = null
    private var serverRouter: BidirectionalMessageRouter? = null

    /** Replaces the server with a fresh one of the same configuration, one handshake per server. */
    private fun reset() {
        server.destroy()
        awaitScopeFinished(server)
        newServer(serverStore, serverRouter)
    }

    /** Handshakes a new desktop, recorded in the store first when [paired]. */
    private suspend fun connect(paired: Boolean): NoiseInitiatorSession {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        if (paired) repo.addDevice(keyHex, "desktop")
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        setField("connectedDevice", device)
        setField("noiseSession", session)
        setField("remotePublicKeyHex", keyHex)
        setField("authenticatedPeerKeyHex", null)
        setField("identityExchangeComplete", true)
        setField("pairingConfirmed", false)
        getField<ConcurrentHashMap<String, Int>>("deviceMtu")[ADDRESS] = 247
        getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[ADDRESS] = true
        getField<ConcurrentHashMap<String, CompletableDeferred<Unit>>>("notificationReady")[ADDRESS] =
            CompletableDeferred(Unit)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value = ConnectionState.Connecting
        call("handleHandshakeMessage", device, desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()
        assertTrue("the handshake completed", server.isSessionEstablished())
        return desktop
    }

    /** Sends [request] on the desktop's session and returns the one decrypted answer. */
    private suspend fun ask(desktop: NoiseInitiatorSession, request: ByteArray): String {
        val fragments = CopyOnWriteArrayList<ByteArray>()
        val characteristic = mockk<BluetoothGattCharacteristic>(relaxed = true)
        every { characteristic.setValue(any<ByteArray>()) } answers {
            fragments.add(firstArg<ByteArray>().copyOf())
            true
        }
        setField("responseCharacteristic", characteristic)

        call("handleApplicationMessage", device, desktop.encrypt(request))

        val reassembler = FragmentReassembler()
        val frame = fragments.mapNotNull { reassembler.addFragment(it) }.single()
        return String(desktop.decrypt(frame), Charsets.UTF_8)
    }

    private fun errorCode(answer: String): Int =
        JSONObject(answer).optJSONObject("error")?.getInt("code")
            ?: throw AssertionError("expected an error, got $answer")

    /** Calls the private suspend member [name] of the server, as its GATT callbacks do. */
    private suspend fun call(name: String, vararg args: Any?): Any? =
        suspendCoroutineUninterceptedOrReturn { continuation ->
            val method = GattServer::class.java.declaredMethods
                .single { it.name == name && it.parameterCount == args.size + 1 }
                .apply { isAccessible = true }
            try {
                method.invoke(server, *args, continuation)
            } catch (e: InvocationTargetException) {
                throw e.targetException
            }
        }

    private fun setField(name: String, value: Any?) {
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.set(server, value)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getField(name: String): T =
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.get(server) as T
}
