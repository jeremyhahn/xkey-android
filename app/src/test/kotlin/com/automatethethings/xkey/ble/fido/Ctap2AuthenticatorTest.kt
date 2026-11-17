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

import com.automatethethings.xkey.crypto.CborDecoder
import com.automatethethings.xkey.crypto.CborEncoder
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * CTAP2 authenticatorGetInfo, authenticatorGetAssertion and
 * authenticatorMakeCredential, as the BLE transport delivers them: a command
 * byte followed by a CBOR map, answered by a status byte and a CBOR map.
 */
class Ctap2AuthenticatorTest {

    private val rpId = "example.com"
    private val clientDataHash = ByteArray(32) { (it + 1).toByte() }

    /** A credential store with software keys; hidden ids model the sharing policy. */
    private class FakeBackend : FidoCredentialBackend {
        val keys = mutableMapOf<String, KeyPair>()
        val stored = mutableListOf<FidoCredential>()
        val hidden = mutableSetOf<String>()
        var userCheck = UserCheck.VERIFIED
        var checks = 0
        var counter = 0L
        val created = mutableListOf<CredentialRequest>()
        override var userVerificationAvailable = true
        override var strictUserVerification = true

        fun add(
            id: ByteArray,
            rpId: String,
            discoverable: Boolean = true,
            user: ByteArray? = byteArrayOf(7),
            name: String = "alice"
        ) {
            keys[id.hex()] = newKey()
            stored += FidoCredential(id, rpId, user, name, name.replaceFirstChar { it.uppercase() }, discoverable)
        }

        /** The owner's pick among the accounts offered; null declines. */
        var choice: (List<FidoCredential>) -> FidoCredential? = { null }

        /** Every list of accounts the owner was asked to choose from. */
        val offered = mutableListOf<List<FidoCredential>>()

        suspend fun chooseCredential(rpId: String, candidates: List<FidoCredential>): FidoCredential? {
            offered += candidates
            return choice(candidates)
        }

        override suspend fun credentials(rpId: String): List<FidoCredential> =
            stored.filter { it.rpId == rpId && it.id.hex() !in hidden }

        override suspend fun checkUser(rpId: String, registering: Boolean): UserCheck {
            checks++
            return userCheck
        }

        override suspend fun sign(
            credential: FidoCredential,
            authenticatorData: (signCount: Long) -> ByteArray,
            clientDataHash: ByteArray
        ): SignedAssertion {
            val authData = authenticatorData(++counter)
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(keys.getValue(credential.id.hex()).private)
            signer.update(authData + clientDataHash)
            return SignedAssertion(authData, signer.sign())
        }

        override suspend fun create(request: CredentialRequest): NewCredential {
            created += request
            val id = ByteArray(16) { (created.size * 16 + it).toByte() }
            val pair = newKey()
            keys[id.hex()] = pair
            stored += FidoCredential(id, request.rpId, request.userHandle, request.userName,
                request.userDisplayName, request.discoverable)
            val point = (pair.public as ECPublicKey).w
            return NewCredential(id, CborEncoder.encodeCOSEEC2Key(point.affineX.unsigned32(), point.affineY.unsigned32()))
        }

        fun publicKey(id: ByteArray): PublicKey = keys.getValue(id.hex()).public
    }

    private val backend = FakeBackend()
    private val authenticator = Ctap2Authenticator(backend)

    private suspend fun call(command: Int, params: Map<Any, Any?>?): Pair<Int, Map<*, *>?> {
        val request = byteArrayOf(command.toByte()) + (params?.let { CborEncoder.encode(it) } ?: ByteArray(0))
        val response = authenticator.handle(request)
        val status = response[0].toInt() and 0xFF
        val body = if (response.size > 1) CborDecoder.decode(response.copyOfRange(1, response.size)) as Map<*, *> else null
        return status to body
    }

    private fun assertion(allow: List<ByteArray>? = null, options: Map<String, Boolean>? = null, extra: Map<Any, Any?> = emptyMap()): Map<Any, Any?> {
        val m = mutableMapOf<Any, Any?>(1 to rpId, 2 to clientDataHash)
        if (allow != null) m[3] = allow.map { mapOf("id" to it, "type" to "public-key") }
        if (options != null) m[5] = options
        m.putAll(extra)
        return m
    }

    private fun registration(
        algs: List<Int> = listOf(-7),
        exclude: List<ByteArray>? = null,
        options: Map<String, Boolean>? = mapOf("rk" to true)
    ): Map<Any, Any?> {
        val m = mutableMapOf<Any, Any?>(
            1 to clientDataHash,
            2 to mapOf("id" to rpId, "name" to "Example"),
            3 to mapOf("id" to byteArrayOf(1, 2, 3), "name" to "alice", "displayName" to "Alice"),
            4 to algs.map { mapOf("alg" to it, "type" to "public-key") }
        )
        if (exclude != null) m[5] = exclude.map { mapOf("id" to it, "type" to "public-key") }
        if (options != null) m[7] = options
        return m
    }

    // --- authenticatorGetInfo ---

    @Test
    fun `getInfo reports FIDO_2_0, the AAGUID, options, message size and BLE transport`() = runTest {
        val (status, info) = call(Ctap2.CMD_GET_INFO, null)

        assertEquals(Ctap2.OK, status)
        assertEquals(listOf("FIDO_2_0"), info!![1L])
        assertArrayEquals(ByteArray(16), info[3L] as ByteArray)
        val options = info[4L] as Map<*, *>
        assertEquals(true, options["rk"])
        assertEquals(true, options["up"])
        assertEquals(true, options["uv"])
        assertEquals(false, options["plat"])
        assertFalse(options.containsKey("clientPin"))
        assertEquals(FidoBle.MAX_MESSAGE_SIZE.toLong(), info[5L])
        assertEquals(listOf("ble"), info[9L])
        assertEquals(listOf(mapOf("alg" to -7L, "type" to "public-key")), info[10L])
    }

    @Test
    fun `getInfo reports uv false when the phone cannot verify the user`() = runTest {
        backend.userVerificationAvailable = false

        val (_, info) = call(Ctap2.CMD_GET_INFO, null)

        assertEquals(false, (info!![4L] as Map<*, *>)["uv"])
    }

    @Test
    fun `an unknown command answers CTAP1_ERR_INVALID_COMMAND`() = runTest {
        assertEquals(Ctap2.ERR_INVALID_COMMAND, call(0x08, null).first)
        assertEquals(Ctap2.ERR_INVALID_COMMAND, authenticator.handle(ByteArray(0))[0].toInt())
    }

    @Test
    fun `malformed CBOR answers CTAP2_ERR_INVALID_CBOR`() = runTest {
        val response = authenticator.handle(byteArrayOf(Ctap2.CMD_GET_ASSERTION.toByte(), 0x5f))

        assertEquals(Ctap2.ERR_INVALID_CBOR, response[0].toInt())
        assertEquals(1, response.size)
    }

    // --- authenticatorGetAssertion ---

    @Test
    fun `getAssertion signs authenticator data the credential's public key verifies`() = runTest {
        val id = byteArrayOf(10, 11, 12)
        backend.add(id, rpId)

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id), options = mapOf("uv" to true)))

        assertEquals(Ctap2.OK, status)
        val cred = body!![1L] as Map<*, *>
        assertArrayEquals(id, cred["id"] as ByteArray)
        assertEquals("public-key", cred["type"])
        val authData = body[2L] as ByteArray
        assertEquals(37, authData.size)
        assertArrayEquals(sha256(rpId.toByteArray()), authData.copyOfRange(0, 32))
        assertEquals(0x05, authData[32].toInt())
        assertEquals(1, ByteBuffer.wrap(authData, 33, 4).int)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(backend.publicKey(id))
        verifier.update(authData + clientDataHash)
        assertTrue(verifier.verify(body[3L] as ByteArray))
        assertArrayEquals(byteArrayOf(7), (body[4L] as Map<*, *>)["id"] as ByteArray)
        assertEquals(1, backend.checks)
    }

    @Test
    fun `every assertion carries a larger sign counter`() = runTest {
        val id = byteArrayOf(1)
        backend.add(id, rpId)

        val counts = (1..3).map {
            val authData = call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id))).second!![2L] as ByteArray
            ByteBuffer.wrap(authData, 33, 4).int
        }

        assertEquals(listOf(1, 2, 3), counts)
    }

    @Test
    fun `getAssertion without an allow list uses a discoverable credential and returns its user`() = runTest {
        backend.add(byteArrayOf(1), rpId, discoverable = false)
        backend.add(byteArrayOf(2), rpId, discoverable = true, user = byteArrayOf(42))

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion())

        assertEquals(Ctap2.OK, status)
        assertArrayEquals(byteArrayOf(2), (body!![1L] as Map<*, *>)["id"] as ByteArray)
        assertArrayEquals(byteArrayOf(42), (body[4L] as Map<*, *>)["id"] as ByteArray)
    }

    @Test
    fun `with no allow list and two discoverable accounts the owner's pick signs and its user is returned`() = runTest {
        backend.add(byteArrayOf(1), rpId, user = byteArrayOf(41), name = "alice")
        backend.add(byteArrayOf(2), rpId, user = byteArrayOf(42), name = "bob")
        backend.choice = { offered -> offered.single { it.userName == "bob" } }

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion())

        assertEquals(Ctap2.OK, status)
        assertEquals(listOf(listOf("alice", "bob")), backend.offered.map { list -> list.map { it.userName } })
        assertArrayEquals(byteArrayOf(2), (body!![1L] as Map<*, *>)["id"] as ByteArray)
        assertArrayEquals(byteArrayOf(42), (body[4L] as Map<*, *>)["id"] as ByteArray)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(backend.publicKey(byteArrayOf(2)))
        verifier.update((body[2L] as ByteArray) + clientDataHash)
        assertTrue(verifier.verify(body[3L] as ByteArray))
    }

    @Test
    fun `an account choice the owner declines answers CTAP2_ERR_OPERATION_DENIED and signs nothing`() = runTest {
        backend.add(byteArrayOf(1), rpId, user = byteArrayOf(41), name = "alice")
        backend.add(byteArrayOf(2), rpId, user = byteArrayOf(42), name = "bob")
        backend.choice = { null }

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion())

        assertEquals(Ctap2.ERR_OPERATION_DENIED, status)
        assertEquals(null, body)
        assertEquals(1, backend.offered.size)
        assertEquals(0L, backend.counter)
    }

    @Test
    fun `the account chooser offers only the discoverable accounts the policy shows`() = runTest {
        backend.add(byteArrayOf(1), rpId, user = byteArrayOf(41), name = "alice")
        backend.add(byteArrayOf(2), rpId, user = byteArrayOf(42), name = "bob")
        backend.add(byteArrayOf(3), rpId, user = byteArrayOf(43), name = "carol")
        backend.add(byteArrayOf(4), rpId, discoverable = false, user = byteArrayOf(44), name = "dave")
        backend.hidden += byteArrayOf(3).hex()
        backend.choice = { it.first() }

        assertEquals(Ctap2.OK, call(Ctap2.CMD_GET_ASSERTION, assertion()).first)

        assertEquals(listOf(listOf("alice", "bob")), backend.offered.map { list -> list.map { it.userName } })
    }

    @Test
    fun `a single discoverable account signs without a chooser`() = runTest {
        backend.add(byteArrayOf(1), rpId, user = byteArrayOf(41))

        assertEquals(Ctap2.OK, call(Ctap2.CMD_GET_ASSERTION, assertion()).first)

        assertTrue(backend.offered.isEmpty())
    }

    @Test
    fun `getAssertion with no usable credential answers CTAP2_ERR_NO_CREDENTIALS without a prompt`() = runTest {
        backend.add(byteArrayOf(1), "other.example")
        backend.add(byteArrayOf(2), rpId, discoverable = false)

        assertEquals(Ctap2.ERR_NO_CREDENTIALS, call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(byteArrayOf(1)))).first)
        assertEquals(Ctap2.ERR_NO_CREDENTIALS, call(Ctap2.CMD_GET_ASSERTION, assertion()).first)
        assertEquals(0, backend.checks)
    }

    @Test
    fun `a credential the sharing policy hides is never used`() = runTest {
        val id = byteArrayOf(5)
        backend.add(id, rpId)
        backend.hidden += id.hex()

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id)))

        assertEquals(Ctap2.ERR_NO_CREDENTIALS, status)
        assertNull(body)
        assertEquals(0L, backend.counter)
    }

    @Test
    fun `a declined user verification answers CTAP2_ERR_OPERATION_DENIED and signs nothing`() = runTest {
        val id = byteArrayOf(1)
        backend.add(id, rpId)
        backend.userCheck = UserCheck.DECLINED

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id), options = mapOf("uv" to true)))

        assertEquals(Ctap2.ERR_OPERATION_DENIED, status)
        assertNull(body)
        assertEquals(0L, backend.counter)
    }

    @Test
    fun `required user verification the phone cannot perform answers CTAP2_ERR_PIN_REQUIRED`() = runTest {
        val id = byteArrayOf(1)
        backend.add(id, rpId)
        backend.userCheck = UserCheck.UNAVAILABLE

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id), options = mapOf("uv" to true)))

        assertEquals(Ctap2.ERR_PIN_REQUIRED, status)
        assertNull(body)
        assertEquals(0L, backend.counter)
    }

    @Test
    fun `no way to establish user presence answers CTAP2_ERR_OPERATION_DENIED`() = runTest {
        val id = byteArrayOf(1)
        backend.add(id, rpId)
        backend.userCheck = UserCheck.UNAVAILABLE
        backend.strictUserVerification = false

        assertEquals(Ctap2.ERR_OPERATION_DENIED,
            call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id), options = mapOf("uv" to true))).first)
        assertEquals(Ctap2.ERR_OPERATION_DENIED,
            call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id))).first)
        assertEquals(0L, backend.counter)
    }

    @Test
    fun `a pinUvAuthParam is refused because the phone has no clientPin`() = runTest {
        val id = byteArrayOf(1)
        backend.add(id, rpId)

        val (status, _) = call(Ctap2.CMD_GET_ASSERTION,
            assertion(allow = listOf(id), extra = mapOf(6 to ByteArray(16), 7 to 1)))

        assertEquals(Ctap2.ERR_PIN_AUTH_INVALID, status)
        assertEquals(0L, backend.counter)
    }

    @Test
    fun `a silent assertion with up false is refused`() = runTest {
        val id = byteArrayOf(1)
        backend.add(id, rpId)

        val (status, _) = call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(id), options = mapOf("up" to false)))

        assertEquals(Ctap2.ERR_UNSUPPORTED_OPTION, status)
        assertEquals(0, backend.checks)
    }

    @Test
    fun `getAssertion without rpId or a 32-byte clientDataHash answers CTAP2_ERR_MISSING_PARAMETER or INVALID_CBOR`() = runTest {
        assertEquals(Ctap2.ERR_MISSING_PARAMETER, call(Ctap2.CMD_GET_ASSERTION, mapOf(2 to clientDataHash)).first)
        assertEquals(Ctap2.ERR_CBOR_UNEXPECTED_TYPE, call(Ctap2.CMD_GET_ASSERTION, mapOf(1 to rpId, 2 to "x")).first)
        assertEquals(Ctap2.ERR_INVALID_LENGTH, call(Ctap2.CMD_GET_ASSERTION, mapOf(1 to rpId, 2 to ByteArray(31))).first)
    }

    // --- authenticatorMakeCredential ---

    @Test
    fun `makeCredential returns attested credential data with the new public key`() = runTest {
        val (status, body) = call(Ctap2.CMD_MAKE_CREDENTIAL, registration())

        assertEquals(Ctap2.OK, status)
        assertEquals("none", body!![1L])
        assertEquals(emptyMap<Any, Any>(), body[3L])
        val authData = body[2L] as ByteArray
        assertArrayEquals(sha256(rpId.toByteArray()), authData.copyOfRange(0, 32))
        assertEquals(0x45, authData[32].toInt())
        assertEquals(0, ByteBuffer.wrap(authData, 33, 4).int)
        assertArrayEquals(ByteArray(16), authData.copyOfRange(37, 53))
        val idLength = ByteBuffer.wrap(authData, 53, 2).short.toInt()
        val id = authData.copyOfRange(55, 55 + idLength)
        val cose = CborDecoder.decode(authData.copyOfRange(55 + idLength, authData.size)) as Map<*, *>
        assertEquals(-7L, cose[3L])
        assertEquals(backend.publicKey(id), coseToPublicKey(cose))

        val request = backend.created.single()
        assertEquals(rpId, request.rpId)
        assertEquals("Example", request.rpName)
        assertArrayEquals(byteArrayOf(1, 2, 3), request.userHandle)
        assertEquals("alice", request.userName)
        assertEquals("Alice", request.userDisplayName)
        assertTrue(request.discoverable)
    }

    @Test
    fun `a credential made over BLE then signs an assertion`() = runTest {
        val made = call(Ctap2.CMD_MAKE_CREDENTIAL, registration()).second!![2L] as ByteArray
        val id = made.copyOfRange(55, 55 + ByteBuffer.wrap(made, 53, 2).short.toInt())

        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion())

        assertEquals(Ctap2.OK, status)
        assertArrayEquals(id, (body!![1L] as Map<*, *>)["id"] as ByteArray)
        assertArrayEquals(byteArrayOf(1, 2, 3), (body[4L] as Map<*, *>)["id"] as ByteArray)
    }

    @Test
    fun `makeCredential without rk makes a non-discoverable credential`() = runTest {
        call(Ctap2.CMD_MAKE_CREDENTIAL, registration(options = null))

        assertFalse(backend.created.single().discoverable)
    }

    @Test
    fun `makeCredential without ES256 answers CTAP2_ERR_UNSUPPORTED_ALGORITHM`() = runTest {
        val (status, _) = call(Ctap2.CMD_MAKE_CREDENTIAL, registration(algs = listOf(-257, -8)))

        assertEquals(Ctap2.ERR_UNSUPPORTED_ALGORITHM, status)
        assertTrue(backend.created.isEmpty())
        assertEquals(0, backend.checks)
    }

    @Test
    fun `makeCredential with an excluded credential answers CTAP2_ERR_CREDENTIAL_EXCLUDED after presence`() = runTest {
        val id = byteArrayOf(3, 3)
        backend.add(id, rpId)

        val (status, _) = call(Ctap2.CMD_MAKE_CREDENTIAL, registration(exclude = listOf(id)))

        assertEquals(Ctap2.ERR_CREDENTIAL_EXCLUDED, status)
        assertTrue(backend.created.isEmpty())
        assertEquals(1, backend.checks)
    }

    @Test
    fun `makeCredential with up false answers CTAP2_ERR_INVALID_OPTION`() = runTest {
        val (status, _) = call(Ctap2.CMD_MAKE_CREDENTIAL, registration(options = mapOf("up" to false)))

        assertEquals(Ctap2.ERR_INVALID_OPTION, status)
        assertTrue(backend.created.isEmpty())
    }

    @Test
    fun `makeCredential refuses when the user declines or cannot be verified`() = runTest {
        backend.userCheck = UserCheck.DECLINED
        assertEquals(Ctap2.ERR_OPERATION_DENIED,
            call(Ctap2.CMD_MAKE_CREDENTIAL, registration(options = mapOf("uv" to true))).first)

        backend.userCheck = UserCheck.UNAVAILABLE
        assertEquals(Ctap2.ERR_PIN_REQUIRED,
            call(Ctap2.CMD_MAKE_CREDENTIAL, registration(options = mapOf("uv" to true))).first)

        assertTrue(backend.created.isEmpty())
    }

    @Test
    fun `makeCredential without a user id answers CTAP2_ERR_MISSING_PARAMETER`() = runTest {
        val params = registration().toMutableMap()
        params[3] = mapOf("name" to "alice")

        assertEquals(Ctap2.ERR_MISSING_PARAMETER, call(Ctap2.CMD_MAKE_CREDENTIAL, params).first)
    }

    @Test
    fun `the authenticator reports a user action pending while it waits for the user`() = runTest {
        val id = byteArrayOf(1)
        backend.add(id, rpId)
        var notified = 0

        authenticator.handle(
            byteArrayOf(Ctap2.CMD_GET_ASSERTION.toByte()) + CborEncoder.encode(assertion(allow = listOf(id))),
            onUserActionNeeded = { notified++ }
        )

        assertEquals(1, notified)
    }

    private companion object {
        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

        fun newKey(): KeyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

        fun BigInteger.unsigned32(): ByteArray {
            val raw = toByteArray()
            val out = ByteArray(32)
            val n = minOf(raw.size, 32)
            System.arraycopy(raw, raw.size - n, out, 32 - n, n)
            return out
        }

        fun coseToPublicKey(cose: Map<*, *>): PublicKey {
            val params = KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair().public.let { (it as ECPublicKey).params }
            val point = ECPoint(BigInteger(1, cose[-2L] as ByteArray), BigInteger(1, cose[-3L] as ByteArray))
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
        }
    }
}
