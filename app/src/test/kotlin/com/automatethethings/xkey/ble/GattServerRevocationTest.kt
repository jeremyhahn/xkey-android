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
import com.automatethethings.xkey.settings.PeerNotPairedException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Unpairing a desktop revokes its live BLE session, and a phone-initiated
 * send to a peer that is no longer paired is refused before encryption (#59).
 *
 * A [GattServer] is given a connected device, an established [NoiseSession]
 * and a mocked server handle by reflection, as `onConnectionStateChange`,
 * the handshake and the CCCD write would leave them.
 *
 * On the JVM `Build.VERSION.SDK_INT` is 0, so notifications go through the
 * deprecated pre-Tiramisu overload; both overloads are stubbed and checked.
 */
@Suppress("DEPRECATION")
class GattServerRevocationTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        const val TIMEOUT_MS = 5_000L
        val REQUEST = """{"jsonrpc":"2.0","id":9,"method":"remote.sync","params":{}}""".toByteArray()

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
    }

    private lateinit var context: Context
    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var repo: PairedDeviceRepository
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
        prefs = InMemorySharedPreferences()
        repo = PairedDeviceRepository(prefs)
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        device = mockk(relaxed = true)
        every { device.address } returns ADDRESS
        server = GattServer(context, mockk<RequestHandler>(relaxed = true), pairedDeviceRepository = repo)
        setField("gattServer", gatt)
        setField("responseCharacteristic", mockk<BluetoothGattCharacteristic>(relaxed = true))
    }

    @After
    fun tearDown() {
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    /** Unpairing the connected desktop disconnects it and zeroes its session keys. */
    @Test
    fun unpairingTheConnectedDesktopRevokesItsSession() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val session = connectPaired(desktop)
        val secrets = session.secretArraysForTest() - "staticPrivateKey"

        repo.removeDevice(desktop.getLocalStaticPublicKey().hex())

        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        eventually("the session keys are zeroed") { secrets.values.all { it.isAllZero() } }
        assertEquals(ConnectionState.Disconnected, server.connectionState.value)
        try {
            server.sendEncryptedMessage(REQUEST)
            fail("a send after the teardown must be refused")
        } catch (e: IOException) {
            // No session left to send on.
        }
        assertNoNotification()
    }

    /** The record is gone without a notice: the send is refused before encryption and writes nothing. */
    @Test
    fun aSendToADesktopThatIsNoLongerPairedIsRefusedBeforeEncryption() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val session = connectPaired(desktop)
        prefs.edit().clear().apply()
        val nonce = session.sendNonceForTest()

        try {
            server.sendEncryptedMessage(REQUEST)
            fail("the send must be refused")
        } catch (e: PeerNotPairedException) {
            assertEquals(desktop.getLocalStaticPublicKey().hex(), e.publicKeyHex)
        }

        assertEquals("a refused send must consume no nonce", nonce, session.sendNonceForTest())
        assertNoNotification()

        repo.addDevice(desktop.getLocalStaticPublicKey().hex(), "desktop")
        server.sendEncryptedMessage(REQUEST)
        assertEquals(nonce + 1, session.sendNonceForTest())
        verify(atLeast = 1) { gatt.notifyCharacteristicChanged(device, any(), false) }
    }

    /**
     * A send waiting for the desktop to enable notifications has not been
     * admitted when the desktop is unpaired: it is refused having encrypted
     * nothing and sent nothing, and the keys are zeroed.
     */
    @Test
    fun unpairingWhileASendWaitsForNotificationsSendsNothing() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val session = connectPaired(desktop)
        notificationReady()[ADDRESS] = CompletableDeferred()
        val secrets = session.secretArraysForTest() - "staticPrivateKey"
        val send = async(Dispatchers.IO) { runCatching { server.sendEncryptedMessage(REQUEST) } }
        // The window is the check: a send parked on the readiness shows no
        // signal, so it is still waiting after 200 ms.
        delay(200)
        assertTrue("the send waits for notifications", send.isActive)
        assertEquals("nothing is encrypted before admission", 0L, session.sendNonceForTest())

        repo.removeDevice(desktop.getLocalStaticPublicKey().hex())

        val result = withTimeout(TIMEOUT_MS) { send.await() }
        assertTrue("the send must be refused: $result", result.exceptionOrNull() is IOException)
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        eventually("the session keys are zeroed") { secrets.values.all { it.isAllZero() } }
        assertNoNotification()
    }

    /**
     * Finding 4: a send paused inside its critical section, before admission,
     * when the desktop is unpaired is refused there. It encrypts nothing and
     * notifies nothing, and the keys are zeroed once it lets go.
     */
    @Test
    fun aSendPausedBeforeAdmissionWhenThePeerIsRemovedWritesNothing() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        val session = connectPaired(desktop)
        val secrets = session.secretArraysForTest() - "staticPrivateKey"
        val paused = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        server.beforeAdmissionForTest = {
            paused.complete(Unit)
            release.await()
        }
        val send = async(Dispatchers.IO) { runCatching { server.sendEncryptedMessage(REQUEST) } }
        withTimeout(TIMEOUT_MS) { paused.await() }

        repo.removeDevice(keyHex)
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        assertFalse("nothing is zeroed while the send holds the lock", secrets.values.all { it.isAllZero() })
        assertEquals(0L, session.sendNonceForTest())
        release.complete(Unit)

        val result = withTimeout(TIMEOUT_MS) { send.await() }
        val refusal = result.exceptionOrNull()
        assertTrue("the send must be refused as unpaired: $result", refusal is PeerNotPairedException)
        assertEquals(keyHex, (refusal as PeerNotPairedException).publicKeyHex)
        eventually("the session keys are zeroed") { secrets.values.all { it.isAllZero() } }
        assertNoNotification()
    }

    /**
     * Finding 5: the desktop is unpaired while a frame is mid-delivery, its
     * sender blocked inside the stack. The teardown drops the connection
     * without waiting for that sender, the rest of the frame is abandoned,
     * and the keys are zeroed only after the sender lets go.
     */
    @Test
    fun unpairingWhileAFrameIsMidDeliveryAbandonsItAndZeroesAfterIt() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val session = connectPaired(desktop)
        val secrets = session.secretArraysForTest() - "staticPrivateKey"
        val notified = AtomicInteger()
        val blocked = CountDownLatch(1)
        val release = CountDownLatch(1)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } answers {
            if (notified.incrementAndGet() == 1) {
                blocked.countDown()
                release.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
            }
            true
        }
        val send = async(Dispatchers.IO) { runCatching { server.sendEncryptedMessage(largeRequest()) } }
        assertTrue("the first fragment reached the stack", blocked.await(TIMEOUT_MS, TimeUnit.MILLISECONDS))

        repo.removeDevice(desktop.getLocalStaticPublicKey().hex())
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        assertEquals(ConnectionState.Disconnected, server.connectionState.value)
        assertFalse("the keys outlive the blocked sender", secrets.values.all { it.isAllZero() })
        release.countDown()

        val result = withTimeout(TIMEOUT_MS) { send.await() }
        assertTrue("the abandoned frame fails its send: $result", result.exceptionOrNull() is IOException)
        assertEquals("nothing follows the fragment in flight", 1, notified.get())
        eventually("the session keys are zeroed") { secrets.values.all { it.isAllZero() } }
    }

    /**
     * Finding 6: a sender cancelled after its frame was encrypted, without
     * any unpairing, still delivers that frame; the next send decrypts on
     * the desktop after it.
     */
    @Test
    fun aSenderCancelledAfterAdmissionStillDeliversItsFrame() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val session = connectPaired(desktop)
        val fragments = captureFragments()
        val admitted = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        server.afterAdmissionForTest = {
            admitted.complete(Unit)
            release.await()
        }
        val sender = launch(Dispatchers.IO) { server.sendEncryptedMessage(REQUEST) }
        withTimeout(TIMEOUT_MS) { admitted.await() }

        sender.cancel()
        release.complete(Unit)
        sender.join()
        server.afterAdmissionForTest = null
        server.sendEncryptedMessage(REQUEST)

        assertEquals(2L, session.sendNonceForTest())
        val messages = reassemble(fragments)
        assertEquals("both frames were delivered", 2, messages.size)
        messages.forEach { assertTrue(String(desktop.decrypt(it)).contains("remote.sync")) }
        assertEquals(ConnectionState.Connected("desktop", ADDRESS), server.connectionState.value)
    }

    /** A desktop unpaired between msg2 and msg3, known only by its claimed key, is torn down. */
    @Test
    fun unpairingDuringTheHandshakeTearsItDown() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        val session = NoiseSession().also { it.loadStaticKey(context) }
        session.processHandshakeMessage(desktop.createHandshakeMessage1())
        val secrets = session.secretArraysForTest() - "staticPrivateKey"
        install(session, authenticatedPeerKeyHex = null, claimedPeerKeyHex = keyHex)

        repo.removeDevice(keyHex)

        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        eventually("the handshake secrets are zeroed") { secrets.values.all { it.isAllZero() } }
    }

    /** The same desktop key, paired again after a removal, is served on its next session. */
    @Test
    fun rePairingTheSameKeyAfterARemovalWorks() = runBlocking<Unit> {
        val key = randomKey()
        val first = NoiseInitiatorSession(key)
        val keyHex = first.getLocalStaticPublicKey().hex()
        connectPaired(first)
        repo.removeDevice(keyHex)
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        eventually("the first session is gone") { server.connectionState.value == ConnectionState.Disconnected }

        val session = connectPaired(NoiseInitiatorSession(key))
        server.sendEncryptedMessage(REQUEST)
        assertEquals(1L, session.sendNonceForTest())
        verify(atLeast = 1) { gatt.notifyCharacteristicChanged(device, any(), false) }

        repo.removeDevice(keyHex)
        verify(timeout = TIMEOUT_MS, exactly = 2) { gatt.cancelConnection(device) }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Pairs [desktop], completes a handshake with it, and installs the session as connected. */
    private suspend fun connectPaired(desktop: NoiseInitiatorSession): NoiseSession {
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        session.processHandshakeMessage(desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()
        install(session, authenticatedPeerKeyHex = keyHex, claimedPeerKeyHex = keyHex)
        return session
    }

    private fun install(session: NoiseSession, authenticatedPeerKeyHex: String?, claimedPeerKeyHex: String) {
        setField("connectedDevice", device)
        setField("noiseSession", session)
        setField("remotePublicKeyHex", claimedPeerKeyHex)
        setField("authenticatedPeerKeyHex", authenticatedPeerKeyHex)
        setField("identityExchangeComplete", true)
        setField("pairingConfirmed", authenticatedPeerKeyHex != null)
        getField<ConcurrentHashMap<String, Int>>("deviceMtu")[ADDRESS] = 247
        getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[ADDRESS] = true
        notificationReady()[ADDRESS] = CompletableDeferred(Unit)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value =
            ConnectionState.Connected("desktop", ADDRESS)
    }

    /** A request large enough to span several fragments at the installed MTU. */
    private fun largeRequest(): ByteArray =
        """{"jsonrpc":"2.0","id":9,"method":"remote.sync","params":{"pad":"${"x".repeat(1000)}"}}"""
            .toByteArray()

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

    /** Reassembles [fragments] into the frames they carried. */
    private fun reassemble(fragments: List<ByteArray>): List<ByteArray> {
        val reassembler = FragmentReassembler()
        return fragments.mapNotNull { reassembler.addFragment(it) }
    }

    private fun notificationReady(): ConcurrentHashMap<String, CompletableDeferred<Unit>> =
        getField("notificationReady")

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
        assertTrue(what, check())
    }

    private fun setField(name: String, value: Any?) {
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.set(server, value)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getField(name: String): T =
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.get(server) as T

    private fun ByteArray.isAllZero(): Boolean = all { it == 0.toByte() }
}
