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

import android.util.Log
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.crypto.CborDecoder
import com.automatethethings.xkey.crypto.CborEncoder
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
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
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
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
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * A CTAP2 BLE client's view of the whole phone stack: frames written to
 * [FidoBleSession] at the control point length, over a real
 * [Ctap2Authenticator] and a real [AndroidFidoCredentialBackend] whose
 * database, Keystore and prompt are in-memory fakes. Every answer is checked
 * as a relying party checks it.
 */
class Ctap2BleClientRoundTripTest {

    @get:Rule
    val releaseMocks = ReleaseMocks()

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
    private val promptCalls = AtomicInteger()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

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

    private val client by lazy { Client(Ctap2Authenticator(backend)) }

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0

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
        coEvery { keystore.signApproved(any(), any(), any(), any()) } answers {
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
            // Long enough that the session sends KEEPALIVE frames meanwhile.
            delay(PROMPT_MILLIS)
            promptAnswer
        }
        coEvery { prompt.chooseAccount(any(), any()) } returns 0
    }

    @After
    fun tearDown() {
        client.session.close()
        scope.cancel()
        unmockkAll()
    }

    @Test
    fun `GetInfo answers the versions, options and algorithm the Commands table lists`() {
        val info = client.ok(byteArrayOf(Ctap2.CMD_GET_INFO.toByte()))

        assertEquals(listOf("FIDO_2_0"), info[1L])
        assertArrayEquals(ByteArray(16), info[3L] as ByteArray)
        assertEquals(mapOf("rk" to true, "up" to true, "uv" to true, "plat" to false), info[4L])
        assertFalse((info[4L] as Map<*, *>).containsKey("clientPin"))
        assertEquals(1024L, info[5L])
        assertEquals(listOf("ble"), info[9L])
        assertEquals(listOf(mapOf("alg" to -7L, "type" to "public-key")), info[10L])
    }

    @Test
    fun `MakeCredential returns attested credential data a relying party can parse`() {
        val made = makeCredential()

        assertArrayEquals(sha256(RP_ID.toByteArray()), made.authData.copyOfRange(0, 32))
        assertEquals(FLAG_UP or FLAG_UV or FLAG_AT, made.flags)
        assertEquals(0L, made.counter)
        assertArrayEquals(ByteArray(16), made.authData.copyOfRange(37, 53))
        val stored = rows.values.single()
        assertArrayEquals(Fido2WireIds.wireId(stored.keyId), made.credentialId)
        // The bytes local.listFido2Credentials lists for the same passkey.
        assertArrayEquals(Base64.getDecoder().decode(Fido2WireIds.encode(stored.keyId)), made.credentialId)
        assertEquals(P256.curve, (made.publicKey as ECPublicKey).params.curve)
        assertArrayEquals(keystoreKeys[aliasOf(stored.keyId)]!!.public.encoded, made.publicKey.encoded)
        assertTrue(stored.isDiscoverable)
        assertEquals(SharingPolicyType.ALL_PEERS, stored.sharingPolicy)
        assertTrue("the client saw KEEPALIVE frames while the prompt was up", client.keepalivesUpNeeded > 0)
    }

    @Test
    fun `allowList then discoverable GetAssertion sign verifiable assertions on the shared counter`() {
        val made = makeCredential()
        val storedId = rows.values.single().keyId

        val first = getAssertion(allowList = listOf(made.credentialId))
        assertAssertion(first, made, expectedCounter = 1)

        val second = getAssertion(allowList = null)
        assertAssertion(second, made, expectedCounter = 2)
        assertArrayEquals(USER_HANDLE, (second.response[4L] as Map<*, *>)["id"] as ByteArray)

        // Both stores hold the counter, and local.signFido2Assertion's counter continues from it.
        assertEquals(2L, rows[storedId]!!.signCount)
        assertEquals(2L, metadata[storedId]!!.signCount)
        assertEquals(3L, runBlocking { PasskeySignCounter(credentialDao, keyDao).next(storedId) })
        assertEquals(3, promptCalls.get())
    }

    @Test
    fun `a declined or impossible prompt signs nothing and leaves the counter`() {
        val made = makeCredential()
        val storedId = rows.values.single().keyId

        promptAnswer = UserCheck.DECLINED
        assertEquals(Ctap2.ERR_OPERATION_DENIED, client.status(getAssertionRequest(listOf(made.credentialId))))
        promptAnswer = UserCheck.UNAVAILABLE
        assertEquals(Ctap2.ERR_OPERATION_DENIED, client.status(getAssertionRequest(null)))

        assertEquals(0L, rows[storedId]!!.signCount)
        promptAnswer = UserCheck.VERIFIED
        assertAssertion(getAssertion(listOf(made.credentialId)), made, expectedCounter = 1)
    }

    @Test
    fun `a request and a response many frames long round trip`() {
        val made = makeCredential()
        // Unknown ids ahead of the real one make the request span many frames.
        val unknown = (1..12).map { i -> ByteArray(32) { i.toByte() } }
        val request = getAssertionRequest(unknown + listOf(made.credentialId))
        assertTrue(request.size in 400..FidoBle.MAX_MESSAGE_SIZE)

        val assertion = getAssertion(unknown + listOf(made.credentialId))

        assertTrue("request frames ${client.lastRequestFrames}", client.lastRequestFrames > 20)
        assertTrue("response frames ${client.lastResponseFrames}", client.lastResponseFrames > 5)
        assertAssertion(assertion, made, expectedCounter = 1)
    }

    // ---- relying party checks ----

    private class Made(val authData: ByteArray, val credentialId: ByteArray, val publicKey: PublicKey) {
        val flags = authData[32].toInt() and 0xFF
        val counter = BigInteger(1, authData.copyOfRange(33, 37)).toLong()
    }

    private class Assertion(val response: Map<*, *>, val clientDataHash: ByteArray) {
        val authData = response[2L] as ByteArray
        val signature = response[3L] as ByteArray
    }

    private fun makeCredential(): Made {
        val request = byteArrayOf(Ctap2.CMD_MAKE_CREDENTIAL.toByte()) + CborEncoder.encode(
            mapOf(
                1 to sha256("make-credential-client-data".toByteArray()),
                2 to mapOf("id" to RP_ID, "name" to "Example"),
                3 to mapOf("id" to USER_HANDLE, "name" to "alice", "displayName" to "Alice"),
                4 to listOf(mapOf("alg" to -7, "type" to "public-key")),
                7 to mapOf("rk" to true, "up" to true)
            )
        )
        val response = client.ok(request)
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
        return Made(authData, credentialId, p256(x, y))
    }

    private fun getAssertionRequest(allowList: List<ByteArray>?, clientDataHash: ByteArray = CLIENT_DATA_HASH): ByteArray {
        val params = mutableMapOf<Any, Any?>(1 to RP_ID, 2 to clientDataHash)
        allowList?.let { ids -> params[3] = ids.map { mapOf("id" to it, "type" to "public-key") } }
        params[5] = mapOf("up" to true)
        return byteArrayOf(Ctap2.CMD_GET_ASSERTION.toByte()) + CborEncoder.encode(params)
    }

    private fun getAssertion(allowList: List<ByteArray>?): Assertion =
        Assertion(client.ok(getAssertionRequest(allowList)), CLIENT_DATA_HASH)

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
        assertTrue("the ES256 signature verifies with the COSE key", verifier.verify(assertion.signature))
    }

    // ---- a minimal CTAP2 BLE client ----

    /** Writes frames at [CONTROL_POINT_LENGTH] and reads notifications of [NOTIFY_LENGTH] bytes. */
    private inner class Client(handler: FidoMessageHandler) {
        private val inbox = LinkedBlockingQueue<ByteArray>()
        var keepalivesUpNeeded = 0
        var lastRequestFrames = 0
        var lastResponseFrames = 0

        val session = FidoBleSession(
            handler = handler,
            scope = scope,
            send = { frame ->
                assertTrue("notification of ${frame.size} bytes", frame.size <= NOTIFY_LENGTH)
                inbox.put(frame)
            },
            maxFrameSize = { NOTIFY_LENGTH },
            keepaliveIntervalMillis = 10
        )

        fun ok(request: ByteArray): Map<*, *> {
            val response = send(request)
            assertEquals("CTAP2 status", Ctap2.OK, response[0].toInt() and 0xFF)
            return CborDecoder.decode(response.copyOfRange(1, response.size)) as Map<*, *>
        }

        fun status(request: ByteArray): Int {
            val response = send(request)
            assertEquals(1, response.size)
            return response[0].toInt() and 0xFF
        }

        /** One MSG out, its MSG response back; KEEPALIVE frames are counted and skipped. */
        fun send(request: ByteArray): ByteArray {
            val frames = split(request)
            lastRequestFrames = frames.size
            frames.forEach { session.onControlPointWrite(it) }
            while (true) {
                val first = next()
                when (first[0]) {
                    FidoBle.CMD_KEEPALIVE -> {
                        assertEquals(3 + 1, first.size)
                        if (first[3].toInt() == FidoBle.KEEPALIVE_UP_NEEDED) keepalivesUpNeeded++
                    }
                    FidoBle.CMD_MSG -> return reassemble(first)
                    else -> fail("unexpected frame command 0x%02x".format(first[0]))
                }
            }
        }

        private fun split(data: ByteArray): List<ByteArray> {
            val frames = mutableListOf<ByteArray>()
            val head = minOf(data.size, CONTROL_POINT_LENGTH - 3)
            frames += byteArrayOf(FidoBle.CMD_MSG, (data.size shr 8).toByte(), data.size.toByte()) + data.copyOfRange(0, head)
            var offset = head
            var seq = 0
            while (offset < data.size) {
                val n = minOf(data.size - offset, CONTROL_POINT_LENGTH - 1)
                frames += byteArrayOf(seq.toByte()) + data.copyOfRange(offset, offset + n)
                offset += n
                seq = (seq + 1) and 0x7F
            }
            return frames
        }

        private fun reassemble(first: ByteArray): ByteArray {
            val length = ((first[1].toInt() and 0xFF) shl 8) or (first[2].toInt() and 0xFF)
            val out = java.io.ByteArrayOutputStream()
            out.write(first, 3, first.size - 3)
            var seq = 0
            var count = 1
            while (out.size() < length) {
                val cont = next()
                assertEquals("CONT frames arrive whole, in order", seq, cont[0].toInt())
                out.write(cont, 1, cont.size - 1)
                seq = (seq + 1) and 0x7F
                count++
            }
            lastResponseFrames = count
            assertEquals(length, out.size())
            return out.toByteArray()
        }

        private fun next(): ByteArray {
            val frame = inbox.poll(10, TimeUnit.SECONDS)
            assertNotNull("a frame within 10 s", frame)
            return frame!!
        }
    }

    private companion object {
        const val RP_ID = "example.com"
        val USER_HANDLE = byteArrayOf(7, 7, 7, 7)
        val CLIENT_DATA_HASH = ByteArray(32) { (it * 3).toByte() }

        /** The default ATT MTU of 23 less three, before a client negotiates a larger one. */
        const val CONTROL_POINT_LENGTH = 20
        const val NOTIFY_LENGTH = 20
        const val PROMPT_MILLIS = 100L

        const val FLAG_UP = 0x01
        const val FLAG_UV = 0x04
        const val FLAG_AT = 0x40

        fun aliasOf(keyId: String) = "xkey_credential_$keyId"

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
