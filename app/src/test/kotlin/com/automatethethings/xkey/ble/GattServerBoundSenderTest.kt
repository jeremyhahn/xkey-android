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

package com.automatethethings.xkey.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A [com.automatethethings.xkey.remote.ConnectedDesktop] from
 * [GattServer.connectedDesktop] encrypts only on the session whose handshake
 * authenticated its key: once paired desktop B's session replaces desktop
 * A's, a send captured for A fails and nothing is notified to B (ruling 554,
 * #141). The connection state is installed by reflection, as in
 * [GattServerReconnectTest].
 */
@Suppress("DEPRECATION")
class GattServerBoundSenderTest {

    private companion object {
        const val ADDRESS_A = "AA:BB:CC:DD:EE:01"
        const val ADDRESS_B = "AA:BB:CC:DD:EE:02"
        val REQUEST = """{"jsonrpc":"2.0","id":9,"method":"remote.oathAdd","params":{}}""".toByteArray()

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var gatt: BluetoothGattServer
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
        val requestHandler = mockk<RequestHandler>(relaxed = true)
        router = BidirectionalMessageRouter(requestHandler)
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        server = GattServer(context, requestHandler, messageRouter = router, pairedDeviceRepository = repo)
        setField("gattServer", gatt)
    }

    @After
    fun tearDown() {
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    @Test
    fun aSendCapturedForDesktopAFailsOnceBsSessionReplacesItAndBIsNotifiedNothing() = runBlocking<Unit> {
        val a = NoiseInitiatorSession(randomKey())
        connect(a, device(ADDRESS_A))
        val captured = server.connectedDesktop(router)
        assertNotNull(captured)
        assertEquals(a.getLocalStaticPublicKey().hex(), captured!!.peerKeyHex)

        val b = NoiseInitiatorSession(randomKey())
        connect(b, device(ADDRESS_B))
        assertEquals(b.getLocalStaticPublicKey().hex(), server.connectedDesktop(router)!!.peerKeyHex)
        val fragments = captureFragments()

        try {
            captured.sender.sendEncryptedMessage(REQUEST)
            fail("a send captured for A must not go out on B's session")
        } catch (e: IOException) {
            // A's session is no longer the server's.
        }
        assertTrue("nothing may be notified to B", fragments.isEmpty())
    }

    @Test
    fun theBoundSenderStillReachesItsOwnSession() = runBlocking<Unit> {
        val a = NoiseInitiatorSession(randomKey())
        connect(a, device(ADDRESS_A))
        val fragments = captureFragments()

        server.connectedDesktop(router)!!.sender.sendEncryptedMessage(REQUEST)

        val reassembler = FragmentReassembler()
        val frame = fragments.mapNotNull { reassembler.addFragment(it) }.single()
        assertEquals(String(REQUEST), String(a.decrypt(frame)))
    }

    private fun device(address: String): BluetoothDevice = mockk<BluetoothDevice>(relaxed = true).also {
        every { it.address } returns address
        every { it.name } returns "desktop"
    }

    /** A paired desktop on [device] completes a handshake, its msg3 through the server. */
    private suspend fun connect(desktop: NoiseInitiatorSession, device: BluetoothDevice) {
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
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
        getField<ConcurrentHashMap<String, Int>>("deviceMtu")[device.address] = 247
        getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[device.address] = true
        getField<ConcurrentHashMap<String, CompletableDeferred<Unit>>>("notificationReady")[device.address] =
            CompletableDeferred(Unit)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value = ConnectionState.Connecting
        call("handleHandshakeMessage", device, desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()
        assertTrue("the handshake completed", server.isSessionEstablished())
    }

    /** Records every fragment written to the response characteristic, in order. */
    private fun captureFragments(): List<ByteArray> {
        val fragments = CopyOnWriteArrayList<ByteArray>()
        val characteristic = mockk<BluetoothGattCharacteristic>(relaxed = true)
        every { characteristic.setValue(any<ByteArray>()) } answers {
            fragments.add(firstArg<ByteArray>().copyOf())
            true
        }
        setField("responseCharacteristic", characteristic)
        return fragments
    }

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
