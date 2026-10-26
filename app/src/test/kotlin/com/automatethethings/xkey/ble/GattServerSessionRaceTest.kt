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
import com.automatethethings.xkey.protocol.RequestHandler
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
import io.mockk.verify
import java.lang.reflect.InvocationTargetException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A desktop unpaired while its BLE session is suspended or mid-handshake
 * leaves nothing behind (#59, Codex 7155): a request waiting for approval is
 * cancelled, an approval answered after the peer was removed and replaced
 * changes nothing, and a handshake revoked after its transport keys were split
 * never installs them or publishes the connected state.
 *
 * As in [GattServerRevocationTest], the connected state is installed by
 * reflection, and the private suspend entry points the GATT callbacks reach
 * are called the same way.
 */
@Suppress("DEPRECATION")
class GattServerSessionRaceTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        const val TIMEOUT_MS = 5_000L
        val GENERATE_KEY = """{"jsonrpc":"2.0","id":5,"method":"local.generateKey","params":{}}""".toByteArray()

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        fun ByteArray.isAllZero(): Boolean = all { it == 0.toByte() }

        fun pairingConfirm(keyHex: String): ByteArray = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 3)
            .put("method", "pairing.confirm")
            .put("params", JSONObject().put("deviceName", "desktop").put("publicKeyHex", keyHex))
            .toString()
            .toByteArray()
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var callback: PairingConfirmationCallback
    private lateinit var gatt: BluetoothGattServer
    private lateinit var device: BluetoothDevice
    private lateinit var server: GattServer

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

        context = mockk(relaxed = true)
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        callback = mockk()
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        device = mockk(relaxed = true)
        every { device.address } returns ADDRESS
        server = GattServer(context, requestHandler, pairingCallback = callback, pairedDeviceRepository = repo)
        setField("gattServer", gatt)
        setField("responseCharacteristic", mockk<BluetoothGattCharacteristic>(relaxed = true))
    }

    @After
    fun tearDown() {
        server.destroy()
        unmockkAll()
    }

    /**
     * A: the desktop is unpaired while its `local.generateKey` waits for the
     * user's approval. The request is cancelled there; approving afterwards
     * runs nothing and answers nothing.
     */
    @Test
    fun unpairingWhileARequestAwaitsApprovalCancelsIt() = runBlocking<Unit> {
        val started = CompletableDeferred<Unit>()
        val approval = CompletableDeferred<Unit>()
        val ran = AtomicBoolean(false)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } coAnswers {
            started.complete(Unit)
            approval.await()
            ran.set(true)
            """{"jsonrpc":"2.0","id":5,"result":{"ok":true}}""".toByteArray()
        }
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        install(handshake(desktop), keyHex, keyHex, pairingConfirmed = true)
        val request = async(Dispatchers.IO) {
            runCatching { call("handleApplicationMessage", device, desktop.encrypt(GENERATE_KEY)) }
        }
        withTimeout(TIMEOUT_MS) { started.await() }

        repo.removeDevice(keyHex)

        val result = withTimeout(TIMEOUT_MS) { request.await() }
        assertTrue("the cancelled request must end quietly: $result", result.isSuccess)
        approval.complete(Unit)
        delay(200)
        assertFalse("an approval after the revocation must run nothing", ran.get())
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        assertNoNotification()
    }

    /**
     * B: the user is asked to approve one desktop; it is removed and a new
     * desktop connects before the user answers yes. The removed peer is not
     * re-added, and the new connection's state is left as it was.
     */
    @Test
    fun anApprovalAnsweredAfterThePeerWasRemovedAndReplacedChangesNothing() = runBlocking<Unit> {
        val asked = CompletableDeferred<Unit>()
        val answer = CompletableDeferred<Boolean>()
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } coAnswers {
            asked.complete(Unit)
            answer.await()
        }
        val old = NoiseInitiatorSession(randomKey())
        val oldKey = old.getLocalStaticPublicKey().hex()
        install(handshake(old), oldKey, oldKey, pairingConfirmed = false)
        val pending = async(Dispatchers.IO) { call("interceptOrRoute", pairingConfirm(oldKey)) }
        withTimeout(TIMEOUT_MS) { asked.await() }

        repo.removeDevice(oldKey)
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        eventually("the old session is gone") { getField<NoiseSession?>("noiseSession") == null }

        val replacement = NoiseInitiatorSession(randomKey())
        val newKey = replacement.getLocalStaticPublicKey().hex()
        val newSession = handshake(replacement)
        install(newSession, newKey, newKey, pairingConfirmed = false)

        answer.complete(true)

        assertNull("the old approval answers nothing", withTimeout(TIMEOUT_MS) { pending.await() })
        assertFalse("the removed peer must not be re-added", repo.isDeviceKnown(oldKey))
        assertSame(newSession, getField("noiseSession"))
        assertEquals(false, getField<Boolean>("pairingConfirmed"))
        assertEquals(newKey, getField<String?>("authenticatedPeerKeyHex"))
        assertEquals(ConnectionState.Connected("desktop", ADDRESS), server.connectionState.value)
        verify(exactly = 0) { requestHandler.setConnectedDevicePublicKeyHex(oldKey) }
        assertNoNotification()
    }

    /**
     * C: the removal lands inside msg3 processing, after the transport keys
     * are split and before they are installed. The handshake resets them
     * before it returns, never publishes the connected state,
     * and the session is torn down.
     */
    @Test
    fun aRemovalBetweenTheSplitAndInstallingTheKeysLeavesNoKeysAndNoConnection() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        install(session, authenticatedPeerKeyHex = null, claimedPeerKeyHex = keyHex, pairingConfirmed = false)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value = ConnectionState.Connecting
        var split: Map<String, ByteArray>? = null
        session.afterSplitForTest = {
            split = session.secretArraysForTest() - "staticPrivateKey"
            repo.removeDevice(keyHex)
        }

        call("handleHandshakeMessage", device, desktop.createHandshakeMessage3())

        val keys = split ?: throw AssertionError("msg3 never reached the split")
        assertTrue("the split produced transport keys", keys.keys.containsAll(setOf("sendKey", "recvKey")))
        keys.forEach { (name, key) -> assertTrue("$name must be zero when msg3 returns", key.isAllZero()) }
        assertFalse(session.isHandshakeComplete())
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        eventually("the session is torn down") { server.connectionState.value == ConnectionState.Disconnected }
        assertNotEquals(ConnectionState.Connected("desktop", ADDRESS), server.connectionState.value)
        assertFalse(server.isSessionEstablished())
        assertNoNotification()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Completes a handshake between [desktop] and a fresh responder, and returns the responder. */
    private suspend fun handshake(desktop: NoiseInitiatorSession): NoiseSession {
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        session.processHandshakeMessage(desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()
        return session
    }

    private fun install(
        session: NoiseSession,
        authenticatedPeerKeyHex: String?,
        claimedPeerKeyHex: String,
        pairingConfirmed: Boolean,
    ) {
        setField("connectedDevice", device)
        setField("noiseSession", session)
        setField("remotePublicKeyHex", claimedPeerKeyHex)
        setField("authenticatedPeerKeyHex", authenticatedPeerKeyHex)
        setField("identityExchangeComplete", true)
        setField("pairingConfirmed", pairingConfirmed)
        getField<ConcurrentHashMap<String, Int>>("deviceMtu")[ADDRESS] = 247
        getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[ADDRESS] = true
        getField<ConcurrentHashMap<String, CompletableDeferred<Unit>>>("notificationReady")[ADDRESS] =
            CompletableDeferred(Unit)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value =
            ConnectionState.Connected("desktop", ADDRESS)
    }

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

    private fun assertNoNotification() {
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any()) }
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) }
    }

    private fun eventually(what: String, check: () -> Boolean) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (!check()) {
            if (System.currentTimeMillis() > deadline) fail("timed out waiting until $what")
            Thread.sleep(10)
        }
    }

    private fun setField(name: String, value: Any?) {
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.set(server, value)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getField(name: String): T =
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.get(server) as T
}
