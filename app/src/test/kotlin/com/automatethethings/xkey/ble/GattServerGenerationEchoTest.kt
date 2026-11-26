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
 * Every answer [GattServer] writes itself, before the shared handler, carries
 * the request's `generation`: `rejectUnpaired`, `handlePairingConfirmIfNeeded`
 * (approved, known device, rejected, mismatched key, no store) and the
 * already-paired `pairing.confirm`. The desktop drops an answer whose
 * generation does not match its request.
 *
 * Drives the server's private message path by reflection, as
 * [GattServerReconnectTest] does.
 */
class GattServerGenerationEchoTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        /** 2^64-1, the largest uint64 generation, above [Long.MAX_VALUE]. */
        const val UINT64_MAX = "18446744073709551615"

        fun pairingConfirm(id: Long, generation: ULong, keyHex: String): ByteArray =
            ("""{"jsonrpc":"2.0","id":$id,"generation":$generation,"method":"pairing.confirm",""" +
                """"params":{"deviceName":"desktop","publicKeyHex":"$keyHex"}}""").toByteArray()

        /** The `generation` member's number exactly as written, or null when absent. */
        fun rawGeneration(json: String): String? =
            Regex(""""generation":(\d+)[,}]""").find(json)?.groupValues?.get(1)
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
    fun rejectUnpairedEchoesTheGeneration() = runBlocking<Unit> {
        val desktop = connect(paired = false)

        val answer = ask(desktop, """{"jsonrpc":"2.0","id":5,"generation":50,"method":"local.generateKey","params":{}}""".toByteArray())

        assertEquals("50", rawGeneration(answer))
        assertEquals(ErrorCodes.PAIRING_REQUIRED, errorCode(answer))
    }

    @Test
    fun anApprovedPairingConfirmEchoesTheGeneration() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        val desktop = connect(paired = false)

        val answer = ask(desktop, pairingConfirm(6, 60uL, desktop.getLocalStaticPublicKey().hex()))

        assertEquals("60", rawGeneration(answer))
        assertTrue("expected success, got $answer", JSONObject(answer).has("result"))
    }

    @Test
    fun aRejectedPairingConfirmEchoesTheGeneration() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns false
        val desktop = connect(paired = false)

        val answer = ask(desktop, pairingConfirm(7, 70uL, desktop.getLocalStaticPublicKey().hex()))

        assertEquals("70", rawGeneration(answer))
        assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
    }

    @Test
    fun aMismatchedPairingKeyEchoesTheGeneration() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        val desktop = connect(paired = false)

        val answer = ask(desktop, pairingConfirm(8, 80uL, "cd".repeat(32)))

        assertEquals("80", rawGeneration(answer))
        assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
    }

    @Test
    fun aPairingConfirmWithoutAStoreEchoesTheGeneration() = runBlocking<Unit> {
        server.destroy()
        awaitScopeFinished(server)
        server = newServer(null)
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        val desktop = connect(paired = false)

        val answer = ask(desktop, pairingConfirm(9, 90uL, desktop.getLocalStaticPublicKey().hex()))

        assertEquals("90", rawGeneration(answer))
        val code = errorCode(answer)
        assertTrue("code $code", code == ErrorCodes.PAIRING_REJECTED || code == ErrorCodes.PAIRING_REQUIRED)
    }

    @Test
    fun aPairingConfirmOnAnAdoptedSessionEchoesTheGeneration() = runBlocking<Unit> {
        val desktop = connect(paired = true)

        val answer = ask(desktop, pairingConfirm(10, 100uL, desktop.getLocalStaticPublicKey().hex()))

        assertEquals("100", rawGeneration(answer))
        assertTrue(JSONObject(answer).getJSONObject("result").getBoolean("confirmed"))
    }

    // -----------------------------------------------------------------
    // The largest uint64 generation, above Long.MAX_VALUE
    // -----------------------------------------------------------------

    @Test
    fun rejectUnpairedEchoesTheMaxGeneration() = runBlocking<Unit> {
        val desktop = connect(paired = false)

        val answer = ask(
            desktop,
            """{"jsonrpc":"2.0","id":21,"generation":$UINT64_MAX,"method":"local.generateKey","params":{}}""".toByteArray()
        )

        assertMaxGeneration(answer)
        assertEquals(ErrorCodes.PAIRING_REQUIRED, errorCode(answer))
    }

    @Test
    fun anApprovedPairingConfirmEchoesTheMaxGeneration() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        val desktop = connect(paired = false)

        val answer = ask(desktop, pairingConfirm(22, ULong.MAX_VALUE, desktop.getLocalStaticPublicKey().hex()))

        assertMaxGeneration(answer)
        assertTrue("expected success, got $answer", JSONObject(answer).has("result"))
    }

    @Test
    fun aRejectedPairingConfirmEchoesTheMaxGeneration() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns false
        val desktop = connect(paired = false)

        val answer = ask(desktop, pairingConfirm(23, ULong.MAX_VALUE, desktop.getLocalStaticPublicKey().hex()))

        assertMaxGeneration(answer)
        assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
    }

    @Test
    fun aPairingConfirmWithoutAStoreEchoesTheMaxGeneration() = runBlocking<Unit> {
        server.destroy()
        awaitScopeFinished(server)
        server = newServer(null)
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        val desktop = connect(paired = false)

        val answer = ask(desktop, pairingConfirm(24, ULong.MAX_VALUE, desktop.getLocalStaticPublicKey().hex()))

        assertMaxGeneration(answer)
        val code = errorCode(answer)
        assertTrue("code $code", code == ErrorCodes.PAIRING_REJECTED || code == ErrorCodes.PAIRING_REQUIRED)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun newServer(store: PairedDeviceRepository?): GattServer =
        GattServer(
            context,
            requestHandler,
            messageRouter = router,
            pairingCallback = callback,
            pairedDeviceRepository = store
        ).also {
            server = it
            setField("gattServer", gatt)
            setField("responseCharacteristic", mockk<BluetoothGattCharacteristic>(relaxed = true))
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

    /** Asserts [answer] carries generation 2^64-1 digit for digit and parses back to [ULong.MAX_VALUE]. */
    private fun assertMaxGeneration(answer: String) {
        assertEquals(UINT64_MAX, rawGeneration(answer))
        assertEquals(ULong.MAX_VALUE, Response.fromJson(answer).generation)
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
