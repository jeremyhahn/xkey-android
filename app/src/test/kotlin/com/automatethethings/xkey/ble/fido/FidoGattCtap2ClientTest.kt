/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

package com.automatethethings.xkey.ble.fido

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.CborDecoder
import com.automatethethings.xkey.crypto.CborEncoder
import com.automatethethings.xkey.crypto.GeneratedKeyDiscard
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.protocol.Fido2WireIds
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Collections
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * A CTAP2 BLE client over the FIDO GATT service: requests written to
 * fidoControlPoint through the GATT callbacks a Bluetooth stack calls, replies
 * read from fidoStatus notifications, released one at a time as the stack
 * reports each sent. Only the stack is a fake; [FidoGattServer], its
 * [FidoBleSession], [Ctap2Authenticator] and [AndroidFidoCredentialBackend]
 * are the real ones, the backend over an in-memory database, Keystore and
 * prompt. Every answer is checked as a relying party checks it.
 */
@RunWith(RobolectricTestRunner::class)
class FidoGattCtap2ClientTest {

    @get:Rule
    val releaseMocks = ReleaseMocks()

    // ---- the Bluetooth stack ----

    private val context = mockk<Context>(relaxed = true)
    private val manager = mockk<BluetoothManager>()
    private val stack = mockk<BluetoothGattServer>(relaxed = true)
    private val device = mockk<BluetoothDevice>(relaxed = true)
    private val callback = slot<BluetoothGattServerCallback>()
    private val added = slot<BluetoothGattService>()

    /** Frames the stack accepted for notification on fidoStatus, in order. */
    private val notified = Collections.synchronizedList(mutableListOf<ByteArray>())

    /** Characteristics other than fidoStatus something was notified on. */
    private val notifiedElsewhere = Collections.synchronizedList(mutableListOf<UUID>())

    /** Responses to reads and writes: (status, value). */
    private val responses = Collections.synchronizedList(mutableListOf<Pair<Int, ByteArray?>>())

    /** The first notified frame no reply has consumed yet. */
    private var cursor = 0

    private lateinit var server: FidoGattServer

    // ---- the backend's in-memory stores ----

    private val rows = ConcurrentHashMap<String, KeyEntity>()
    private val metadata = ConcurrentHashMap<String, CredentialMetadataEntity>()
    private val keystoreKeys = ConcurrentHashMap<String, KeyPair>()

    private val keyDao = mockk<KeyDao>(relaxed = true)
    private val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
    private val sharePermission = mockk<SharePermission>()
    private val keystore = mockk<KeystoreManager>(relaxed = true)
    private val prompt = mockk<FidoUserPrompt>()

    @Volatile
    private var promptAnswer = UserCheck.VERIFIED

    /** When set, the prompt suspends on it instead of answering after [PROMPT_MILLIS]. */
    @Volatile
    private var gate: CompletableDeferred<UserCheck>? = null
    private val promptCalls = AtomicInteger()
    private val promptEntered = Semaphore(0)
    private val signCalls = AtomicInteger()
    private val handlerCalls = AtomicInteger()

    private val pendingKeyDeletions = FilePendingKeyDeletions(
        java.io.File.createTempFile("pending-key-deletions", "").also { it.delete(); it.deleteOnExit() }
    )

    private val backend by lazy {
        AndroidFidoCredentialBackend(
            keyDao = keyDao,
            credentialDao = credentialDao,
            sharePermission = sharePermission,
            signCounter = PasskeySignCounter(credentialDao, keyDao),
            keystoreManager = keystore,
            userPrompt = prompt,
            settings = { BiometricSettingsData() },
            pendingKeyDeletions = pendingKeyDeletions
        )
    }

    @Before
    fun setUp() {
        every { device.address } returns "02:00:00:00:00:01"
        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns manager
        every { manager.openGattServer(context, capture(callback)) } returns stack
        every { stack.addService(capture(added)) } answers {
            callback.captured.onServiceAdded(BluetoothGatt.GATT_SUCCESS, added.captured)
            true
        }
        every { stack.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } answers {
            val uuid = arg<BluetoothGattCharacteristic>(1).uuid
            if (uuid == FidoBle.STATUS_UUID) notified += arg<ByteArray>(3) else notifiedElsewhere += uuid
            BluetoothStatusCodes.SUCCESS
        }
        every { stack.sendResponse(any(), any(), any(), any(), any()) } answers {
            responses += arg<Int>(2) to arg<ByteArray?>(4)
            true
        }

        coEvery { keyDao.getFido2ByRpId(any()) } answers { rows.values.filter { it.rpId == firstArg<String>() } }
        coEvery { keyDao.getByKeyId(any()) } answers { rows[firstArg()] }
        coEvery { keyDao.completePasskeyRegistration(any(), any(), any()) } answers {
            val key = firstArg<KeyEntity>()
            val meta = secondArg<CredentialMetadataEntity>()
            val replaced = thirdArg<List<KeyEntity>>()
            replaced.forEach { rows.remove(it.keyId) }
            rows[key.keyId] = key
            metadata[meta.credentialId] = meta
            replaced.map { it.keyId }
        }
        coEvery { keyDao.updateSignCount(any(), any(), any()) } answers {
            rows.computeIfPresent(firstArg()) { _, row -> row.copy(signCount = secondArg()) }
            Unit
        }
        coEvery { credentialDao.getByCredentialId(any()) } answers { metadata[firstArg()] }
        coEvery { credentialDao.updateSignCount(any(), any(), any()) } answers {
            metadata.computeIfPresent(firstArg()) { _, row -> row.copy(signCount = secondArg()) }
            Unit
        }
        coEvery { sharePermission.canShare(any(), null) } answers {
            firstArg<KeyEntity>().sharingPolicy == SharingPolicyType.ALL_PEERS
        }

        // An in-memory Keystore: real P-256 keys, never exported, real ECDSA signatures.
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } answers {
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair()
            keystoreKeys[aliasOf(firstArg())] = pair
            val point = (pair.public as ECPublicKey).w
            CborEncoder.encodeCOSEEC2Key(coordinate(point.affineX), coordinate(point.affineY))
        }
        every { keystore.credentialSecurityLevel(any()) } answers {
            if (keystoreKeys.containsKey(aliasOf(firstArg()))) KeySecurityLevel.TEE else null
        }
        every { keystore.keyRowAlias(any(), any(), any()) } answers { aliasOf(firstArg()) }
        every { keystore.publicKeyDERAt(any()) } answers { keystoreKeys[firstArg()]?.public?.encoded }
        every { keystore.deleteKey(any(), any()) } answers {
            if (secondArg<UserKeyKind>() == UserKeyKind.CREDENTIAL && keystoreKeys.remove(aliasOf(firstArg())) != null) {
                GeneratedKeyDiscard.DELETED
            } else {
                GeneratedKeyDiscard.ABSENT
            }
        }
        coEvery { keystore.signApproved(any(), any(), any(), any()) } answers {
            signCalls.incrementAndGet()
            val pair = keystoreKeys[firstArg()] ?: error("no key under ${firstArg<String>()}")
            check(pair.public.encoded.contentEquals(secondArg<ByteArray>())) { "approved key changed" }
            Signature.getInstance(arg<String>(3)).run {
                initSign(pair.private)
                update(thirdArg<ByteArray>())
                sign()
            }
        }

        every { prompt.available } returns true
        coEvery { prompt.verify(any(), any()) } coAnswers {
            promptCalls.incrementAndGet()
            promptEntered.release()
            val g = gate
            if (g != null) {
                g.await()
            } else {
                // Longer than the session's KEEPALIVE interval, so fidoStatus notifies UP_NEEDED meanwhile.
                delay(PROMPT_MILLIS)
                promptAnswer
            }
        }
        coEvery { prompt.chooseAccount(any(), any()) } returns 0

        val authenticator = Ctap2Authenticator(backend)
        val handler = object : FidoMessageHandler {
            override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray {
                handlerCalls.incrementAndGet()
                return authenticator.handle(request, onUserActionNeeded)
            }
        }
        server = FidoGattServer(context, handler)
        assertTrue(server.start())
        callback.captured.onConnectionStateChange(device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED)
        subscribe()
    }

    @After
    fun tearDown() = server.destroy()

    // ---- G1 ----

    @Test
    fun `G1 MakeCredential then allowList and discoverable GetAssertion over 20-byte frames`() {
        val made = makeCredential(frameSize = DEFAULT_LENGTH)
        val stored = rows.values.single()

        assertArrayEquals(sha256(RP_ID.toByteArray()), made.authData.copyOfRange(0, 32))
        assertEquals(FLAG_UP or FLAG_UV or FLAG_AT, made.flags)
        assertEquals(0L, made.counter)
        assertArrayEquals(Fido2WireIds.wireId(stored.keyId), made.credentialId)
        assertArrayEquals(keystoreKeys[aliasOf(stored.keyId)]!!.public.encoded, made.publicKey.encoded)
        assertTrue(
            "fidoStatus notified KEEPALIVE UP_NEEDED while the prompt waited",
            made.reply.keepalivesUpNeeded > 0
        )

        val first = getAssertion(listOf(made.credentialId), frameSize = DEFAULT_LENGTH)
        assertAssertion(first, made, expectedCounter = 1)
        assertTrue(first.reply.keepalivesUpNeeded > 0)

        val second = getAssertion(null, frameSize = DEFAULT_LENGTH)
        assertAssertion(second, made, expectedCounter = 2)
        assertArrayEquals(USER_HANDLE, (second.response[4L] as Map<*, *>)["id"] as ByteArray)

        // The shared counter: both stores hold it, and the next signer continues from it.
        assertEquals(2L, rows[stored.keyId]!!.signCount)
        assertEquals(2L, metadata[stored.keyId]!!.signCount)
        assertEquals(3L, runBlocking { PasskeySignCounter(credentialDao, keyDao).next(stored.keyId) })
        assertEquals(3, promptCalls.get())

        synchronized(notified) {
            notified.forEach { assertTrue("notification of ${it.size} bytes", it.size <= DEFAULT_LENGTH) }
        }
    }

    // ---- G2 ----

    @Test
    fun `G2 after an MTU of 185 requests and replies use the 182-byte control point length`() {
        callback.captured.onMtuChanged(device, 185)
        val length = readControlPointLength()
        assertEquals(182, length)

        val made = makeCredential(frameSize = length)
        val first = getAssertion(listOf(made.credentialId), frameSize = length)
        assertAssertion(first, made, expectedCounter = 1)
        val second = getAssertion(null, frameSize = length)
        assertAssertion(second, made, expectedCounter = 2)

        synchronized(notified) {
            notified.forEach { assertTrue("notification of ${it.size} bytes", it.size <= length) }
        }
        val replies = listOf(made.reply, first.reply, second.reply)
        assertTrue(
            "a reply longer than one frame: ${replies.map { it.frames.size }}",
            replies.any { it.frames.size > 1 }
        )
    }

    // ---- G3 ----

    @Test
    fun `G3 CANCEL during MakeCredential answers KEEPALIVE_CANCEL once and leaves nothing behind`() {
        gate = CompletableDeferred()
        writeMessage(FidoBle.CMD_MSG, makeCredentialRequest())
        assertTrue("the prompt is up", promptEntered.tryAcquire(10, TimeUnit.SECONDS))
        writeMessage(FidoBle.CMD_CANCEL, ByteArray(0))

        val reply = awaitReply()
        assertEquals(FidoBle.CMD_MSG, reply.command)
        assertEquals(0x2D, Ctap2.ERR_KEEPALIVE_CANCEL)
        assertArrayEquals(byteArrayOf(Ctap2.ERR_KEEPALIVE_CANCEL.toByte()), reply.data)
        assertNothingMoreNotified()

        assertTrue("no key row: ${rows.keys}", rows.isEmpty())
        assertTrue("no metadata row: ${metadata.keys}", metadata.isEmpty())
        val accounted = pendingKeyDeletions.all().map { it.keyId }.toSet() + pendingKeyDeletions.registrations()
        val stray = keystoreKeys.keys.map { it.removePrefix(ALIAS_PREFIX) }.filter { it !in accounted }
        assertTrue("no Keystore key outside the pending deletions: $stray", stray.isEmpty())

        // The next request on the same connection is served.
        gate = null
        val made = makeCredential(frameSize = DEFAULT_LENGTH)
        assertArrayEquals(Fido2WireIds.wireId(rows.values.single().keyId), made.credentialId)
    }

    @Test
    fun `G3 CANCEL during GetAssertion answers KEEPALIVE_CANCEL once and signs nothing`() {
        val made = makeCredential(frameSize = DEFAULT_LENGTH)
        val storedId = rows.values.single().keyId
        val signedBefore = signCalls.get()
        promptEntered.drainPermits()

        gate = CompletableDeferred()
        writeMessage(FidoBle.CMD_MSG, getAssertionRequest(listOf(made.credentialId)))
        assertTrue("the prompt is up", promptEntered.tryAcquire(10, TimeUnit.SECONDS))
        writeMessage(FidoBle.CMD_CANCEL, ByteArray(0))

        val reply = awaitReply()
        assertEquals(FidoBle.CMD_MSG, reply.command)
        assertArrayEquals(byteArrayOf(Ctap2.ERR_KEEPALIVE_CANCEL.toByte()), reply.data)
        assertNothingMoreNotified()

        assertEquals("nothing signed", signedBefore, signCalls.get())
        assertEquals(0L, rows[storedId]!!.signCount)
        assertEquals(0L, metadata[storedId]!!.signCount)

        gate = null
        assertAssertion(getAssertion(listOf(made.credentialId), frameSize = DEFAULT_LENGTH), made, expectedCounter = 1)
    }

    // ---- G4 ----

    @Test
    fun `G4 a CONT frame out of sequence answers ERR_INVALID_SEQ and the next MakeCredential is served`() {
        val frames = FidoBle.fragment(FidoBle.CMD_MSG, makeCredentialRequest(), DEFAULT_LENGTH)
        assertTrue("enough frames to skip one: ${frames.size}", frames.size > 3)
        assertEquals(2, frames[3][0].toInt())
        // CMD, CONT 0, then CONT 2: CONT 1 never arrives.
        write(frames[0])
        write(frames[1])
        write(frames[3])

        val reply = awaitReply()
        assertEquals(FidoBle.CMD_ERROR, reply.command)
        assertArrayEquals(byteArrayOf(FidoBle.ERR_INVALID_SEQ.toByte()), reply.data)
        assertNothingMoreNotified()
        assertEquals(0, handlerCalls.get())
        assertEquals(0, promptCalls.get())
        assertTrue(rows.isEmpty())
        assertTrue(metadata.isEmpty())

        val made = makeCredential(frameSize = DEFAULT_LENGTH)
        assertArrayEquals(Fido2WireIds.wireId(rows.values.single().keyId), made.credentialId)
    }

    // ---- G5 ----

    @Test
    fun `G5 a CMD frame declaring more than MAX_MESSAGE_SIZE answers ERR_INVALID_LEN and the next request is served`() {
        val declared = FidoBle.MAX_MESSAGE_SIZE + 1
        assertEquals(1025, declared)
        write(byteArrayOf(FidoBle.CMD_MSG, (declared shr 8).toByte(), declared.toByte()) + ByteArray(DEFAULT_LENGTH - 3))

        val reply = awaitReply()
        assertEquals(FidoBle.CMD_ERROR, reply.command)
        assertArrayEquals(byteArrayOf(FidoBle.ERR_INVALID_LEN.toByte()), reply.data)
        assertNothingMoreNotified()
        assertEquals("the backend is never reached", 0, handlerCalls.get())
        assertEquals(0, promptCalls.get())
        assertTrue(rows.isEmpty())

        val made = makeCredential(frameSize = DEFAULT_LENGTH)
        assertArrayEquals(Fido2WireIds.wireId(rows.values.single().keyId), made.credentialId)
    }

    // ---- G6 ----

    @Test
    fun `G6 an unknown BLE command answers ERR_INVALID_CMD and the next GetAssertion is served`() {
        val made = makeCredential(frameSize = DEFAULT_LENGTH)
        val handled = handlerCalls.get()

        writeMessage(0x90.toByte(), ByteArray(0))
        val reply = awaitReply()
        assertEquals(FidoBle.CMD_ERROR, reply.command)
        assertArrayEquals(byteArrayOf(FidoBle.ERR_INVALID_CMD.toByte()), reply.data)
        assertNothingMoreNotified()
        assertEquals(handled, handlerCalls.get())

        assertAssertion(getAssertion(listOf(made.credentialId), frameSize = DEFAULT_LENGTH), made, expectedCounter = 1)
    }

    @Test
    fun `G6 an unknown CTAP command answers CTAP1_ERR_INVALID_COMMAND and the next GetAssertion is served`() {
        val made = makeCredential(frameSize = DEFAULT_LENGTH)
        val prompted = promptCalls.get()

        assertEquals(0x01, Ctap2.ERR_INVALID_COMMAND)
        assertEquals(Ctap2.ERR_INVALID_COMMAND, status(byteArrayOf(0x08), frameSize = DEFAULT_LENGTH))
        assertNothingMoreNotified()
        assertEquals(prompted, promptCalls.get())

        assertAssertion(getAssertion(listOf(made.credentialId), frameSize = DEFAULT_LENGTH), made, expectedCounter = 1)
    }

    // ---- relying party checks ----

    private class Made(val authData: ByteArray, val credentialId: ByteArray, val publicKey: PublicKey, val reply: Reply) {
        val flags = authData[32].toInt() and 0xFF
        val counter = BigInteger(1, authData.copyOfRange(33, 37)).toLong()
    }

    private class Assertion(val response: Map<*, *>, val clientDataHash: ByteArray, val reply: Reply) {
        val authData = response[2L] as ByteArray
        val signature = response[3L] as ByteArray
    }

    private fun makeCredentialRequest(): ByteArray = byteArrayOf(Ctap2.CMD_MAKE_CREDENTIAL.toByte()) + CborEncoder.encode(
        mapOf(
            1 to sha256("make-credential-client-data".toByteArray()),
            2 to mapOf("id" to RP_ID, "name" to "Example"),
            3 to mapOf("id" to USER_HANDLE, "name" to "alice", "displayName" to "Alice"),
            4 to listOf(mapOf("alg" to -7, "type" to "public-key")),
            7 to mapOf("rk" to true, "up" to true)
        )
    )

    private fun makeCredential(frameSize: Int): Made {
        val (response, reply) = ok(makeCredentialRequest(), frameSize)
        assertEquals("none", response[1L])
        assertEquals(emptyMap<Any, Any>(), response[3L])
        val authData = response[2L] as ByteArray
        val idLength = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        val credentialId = authData.copyOfRange(55, 55 + idLength)
        val cose = CborDecoder.decode(authData.copyOfRange(55 + idLength, authData.size)) as Map<*, *>
        assertEquals(2L, cose[1L])
        assertEquals(-7L, cose[3L])
        assertEquals(1L, cose[-1L])
        val x = cose[-2L] as ByteArray
        val y = cose[-3L] as ByteArray
        assertEquals(32, x.size)
        assertEquals(32, y.size)
        val publicKey = p256(x, y)
        assertEquals(P256.curve, (publicKey as ECPublicKey).params.curve)
        return Made(authData, credentialId, publicKey, reply)
    }

    private fun getAssertionRequest(allowList: List<ByteArray>?): ByteArray {
        val params = mutableMapOf<Any, Any?>(1 to RP_ID, 2 to CLIENT_DATA_HASH)
        allowList?.let { ids -> params[3] = ids.map { mapOf("id" to it, "type" to "public-key") } }
        params[5] = mapOf("up" to true)
        return byteArrayOf(Ctap2.CMD_GET_ASSERTION.toByte()) + CborEncoder.encode(params)
    }

    private fun getAssertion(allowList: List<ByteArray>?, frameSize: Int): Assertion {
        val (response, reply) = ok(getAssertionRequest(allowList), frameSize)
        return Assertion(response, CLIENT_DATA_HASH, reply)
    }

    private fun assertAssertion(assertion: Assertion, made: Made, expectedCounter: Long) {
        val credential = assertion.response[1L] as Map<*, *>
        assertArrayEquals(made.credentialId, credential["id"] as ByteArray)
        assertEquals("public-key", credential["type"])
        val authData = assertion.authData
        assertEquals(37, authData.size)
        assertArrayEquals(sha256(RP_ID.toByteArray()), authData.copyOfRange(0, 32))
        assertEquals(FLAG_UP or FLAG_UV, authData[32].toInt() and 0xFF)
        assertEquals(expectedCounter, BigInteger(1, authData.copyOfRange(33, 37)).toLong())
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(made.publicKey)
            update(authData + assertion.clientDataHash)
        }
        assertTrue("the ES256 signature verifies with the attested key", verifier.verify(assertion.signature))
    }

    // ---- a minimal CTAP2 BLE client over GATT ----

    /** One whole non-KEEPALIVE reply, its frames, and the KEEPALIVE frames notified before it. */
    private class Reply(val command: Byte, val data: ByteArray, val frames: List<ByteArray>, val keepalives: List<ByteArray>) {
        val keepalivesUpNeeded = keepalives.count { it[3].toInt() == FidoBle.KEEPALIVE_UP_NEEDED }
    }

    private fun characteristic(uuid: UUID) = added.captured.getCharacteristic(uuid)

    private fun subscribe() {
        val cccd = characteristic(FidoBle.STATUS_UUID).getDescriptor(FidoBle.CCCD_UUID)
        callback.captured.onDescriptorWriteRequest(
            device, 1, cccd, false, true, 0, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
    }

    private fun readControlPointLength(): Int {
        callback.captured.onCharacteristicReadRequest(device, 5, 0, characteristic(FidoBle.CONTROL_POINT_LENGTH_UUID))
        val (status, value) = responses.last()
        assertEquals(BluetoothGatt.GATT_SUCCESS, status)
        return ((value!![0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
    }

    private fun write(frame: ByteArray) {
        assertTrue("a write of ${frame.size} bytes", frame.size <= FidoBle.CONTROL_POINT_LENGTH)
        callback.captured.onCharacteristicWriteRequest(
            device, 2, characteristic(FidoBle.CONTROL_POINT_UUID), false, true, 0, frame
        )
    }

    private fun writeMessage(command: Byte, data: ByteArray, frameSize: Int = DEFAULT_LENGTH) =
        FidoBle.fragment(command, data, frameSize).forEach(::write)

    /** Report each notification sent, as the stack does, until none is left. */
    private fun release() {
        var seen = -1
        while (seen != notified.size) {
            seen = notified.size
            callback.captured.onNotificationSent(device, BluetoothGatt.GATT_SUCCESS)
        }
    }

    /** Release notifications until a whole non-KEEPALIVE reply has arrived after [cursor]. */
    private fun awaitReply(timeoutMillis: Long = 10_000): Reply {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            release()
            assertTrue("notified only on fidoStatus: $notifiedElsewhere", notifiedElsewhere.isEmpty())
            val frames = synchronized(notified) { notified.subList(cursor, notified.size).toList() }
            val reassembler = FidoBleReassembler()
            val used = mutableListOf<ByteArray>()
            val keepalives = mutableListOf<ByteArray>()
            for ((i, frame) in frames.withIndex()) {
                if (frame[0] == FidoBle.CMD_KEEPALIVE) {
                    assertEquals("a KEEPALIVE carries one status byte", 4, frame.size)
                    keepalives += frame
                    continue
                }
                used += frame
                when (val result = reassembler.accept(frame)) {
                    is FidoBleReassembler.Result.Complete -> {
                        cursor += i + 1
                        return Reply(result.command, result.data, used, keepalives)
                    }
                    is FidoBleReassembler.Result.Error -> fail("reply frames break the framing: ${result.code}")
                    FidoBleReassembler.Result.Incomplete -> Unit
                }
            }
            Thread.sleep(10)
        }
        throw AssertionError("no reply within $timeoutMillis ms; frames: ${notified.size - cursor}")
    }

    /** Nothing follows the last reply: no second answer, no late KEEPALIVE. */
    private fun assertNothingMoreNotified() {
        repeat(5) {
            Thread.sleep(100)
            release()
        }
        val late = synchronized(notified) { notified.subList(cursor, notified.size).map { it[0] } }
        assertTrue("frames after the reply: $late", late.isEmpty())
    }

    /** One MSG out at [frameSize], its MSG reply back. */
    private fun send(request: ByteArray, frameSize: Int): Reply {
        writeMessage(FidoBle.CMD_MSG, request, frameSize)
        val reply = awaitReply()
        assertEquals("a MSG reply", FidoBle.CMD_MSG, reply.command)
        return reply
    }

    private fun ok(request: ByteArray, frameSize: Int): Pair<Map<*, *>, Reply> {
        val reply = send(request, frameSize)
        assertEquals("CTAP2 status", Ctap2.OK, reply.data[0].toInt() and 0xFF)
        return (CborDecoder.decode(reply.data.copyOfRange(1, reply.data.size)) as Map<*, *>) to reply
    }

    private fun status(request: ByteArray, frameSize: Int): Int {
        val reply = send(request, frameSize)
        assertEquals(1, reply.data.size)
        return reply.data[0].toInt() and 0xFF
    }

    private companion object {
        const val RP_ID = "example.com"
        val USER_HANDLE = byteArrayOf(7, 7, 7, 7)
        val CLIENT_DATA_HASH = ByteArray(32) { (it * 3).toByte() }

        /** The default ATT MTU of 23 less three, before a client negotiates a larger one. */
        const val DEFAULT_LENGTH = 20

        /** Over [FidoBleSession.KEEPALIVE_INTERVAL_MILLIS], the interval the GATT server's session uses. */
        const val PROMPT_MILLIS = 900L

        const val FLAG_UP = 0x01
        const val FLAG_UV = 0x04
        const val FLAG_AT = 0x40

        const val ALIAS_PREFIX = "xkey_credential_"

        fun aliasOf(keyId: String) = "$ALIAS_PREFIX$keyId"

        fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

        fun coordinate(value: BigInteger): ByteArray {
            val bytes = value.toByteArray()
            return when {
                bytes.size == 32 -> bytes
                bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
                else -> ByteArray(32 - bytes.size) + bytes
            }
        }

        val P256: ECParameterSpec = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)

        fun p256(x: ByteArray, y: ByteArray): PublicKey = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), P256))
    }
}
