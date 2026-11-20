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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every CTAP2 request entity (rp, user, pubKeyCredParams, excludeList,
 * allowList, options, extensions) is validated in full before any prompt,
 * any credential lookup and any credential creation: a malformed entity is
 * refused with its CTAP2 error, and an unsupported one never reaches the
 * backend.
 */
class Ctap2RequestValidationTest {

    private val rpId = "example.com"
    private val clientDataHash = ByteArray(32) { (it + 1).toByte() }
    private val userId = byteArrayOf(1, 2, 3)

    /** Records every backend call; one resident passkey for [rpId] and [userId] is stored. */
    private inner class RecordingBackend : FidoCredentialBackend {
        val residentId = byteArrayOf(9, 9)
        val stored = mutableListOf(FidoCredential(residentId, rpId, userId, "alice", "Alice", true))
        var checks = 0
        var lookups = 0
        var signs = 0
        val created = mutableListOf<CredentialRequest>()
        override val userVerificationAvailable = true
        override val strictUserVerification = true

        override suspend fun credentials(rpId: String): List<FidoCredential> {
            lookups++
            return stored.filter { it.rpId == rpId }
        }

        override suspend fun checkUser(rpId: String, registering: Boolean): UserCheck {
            checks++
            return UserCheck.VERIFIED
        }

        override suspend fun chooseCredential(rpId: String, candidates: List<FidoCredential>) = candidates.first()

        override suspend fun sign(
            credential: FidoCredential,
            authenticatorData: (signCount: Long) -> ByteArray,
            clientDataHash: ByteArray
        ): SignedAssertion {
            signs++
            return SignedAssertion(authenticatorData(1), byteArrayOf(1))
        }

        override suspend fun create(request: CredentialRequest): NewCredential {
            created += request
            // A resident registration replaces the passkey for the same RP and user.
            if (request.discoverable) stored.removeAll { it.rpId == request.rpId && it.userHandle.contentEquals(request.userHandle) }
            val id = byteArrayOf(4, 4)
            stored += FidoCredential(id, request.rpId, request.userHandle, request.userName, request.userDisplayName, request.discoverable)
            return NewCredential(id, CborEncoder.encodeCOSEEC2Key(ByteArray(32), ByteArray(32)))
        }
    }

    private val backend = RecordingBackend()
    private val authenticator = Ctap2Authenticator(backend)

    private suspend fun call(command: Int, params: Map<Any, Any?>): Pair<Int, Map<*, *>?> {
        val response = authenticator.handle(byteArrayOf(command.toByte()) + CborEncoder.encode(params))
        val body = if (response.size > 1) CborDecoder.decode(response.copyOfRange(1, response.size)) as Map<*, *> else null
        return (response[0].toInt() and 0xFF) to body
    }

    private fun registration(
        rp: Any? = mapOf("id" to rpId, "name" to "Example"),
        user: Any? = mapOf("id" to userId, "name" to "alice", "displayName" to "Alice"),
        params: Any? = listOf(mapOf("alg" to -7, "type" to "public-key")),
        exclude: Any? = null,
        extra: Map<Any, Any?> = emptyMap()
    ): Map<Any, Any?> {
        val m = mutableMapOf<Any, Any?>(1 to clientDataHash, 7 to mapOf("rk" to true))
        if (rp != null) m[2] = rp
        if (user != null) m[3] = user
        if (params != null) m[4] = params
        if (exclude != null) m[5] = exclude
        m.putAll(extra)
        return m
    }

    private fun assertion(allow: Any?, extra: Map<Any, Any?> = emptyMap()): Map<Any, Any?> {
        val m = mutableMapOf<Any, Any?>(1 to rpId, 2 to clientDataHash)
        if (allow != null) m[3] = allow
        m.putAll(extra)
        return m
    }

    /** The registration is refused with [expected], with no prompt, lookup or creation; the resident passkey survives. */
    private suspend fun assertRegistrationRefused(label: String, expected: Int, request: Map<Any, Any?>) {
        val (status, body) = call(Ctap2.CMD_MAKE_CREDENTIAL, request)
        assertEquals(label, expected, status)
        assertNull(label, body)
        assertEquals(label, 0, backend.checks)
        assertEquals(label, 0, backend.lookups)
        assertTrue(label, backend.created.isEmpty())
        assertTrue(label, backend.stored.any { it.id.contentEquals(backend.residentId) })
    }

    private suspend fun assertAssertionRefused(label: String, expected: Int, request: Map<Any, Any?>) {
        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, request)
        assertEquals(label, expected, status)
        assertNull(label, body)
        assertEquals(label, 0, backend.checks)
        assertEquals(label, 0, backend.lookups)
        assertEquals(label, 0, backend.signs)
    }

    private fun descriptor(id: Any? = backend.residentId, type: Any? = "public-key"): Map<String, Any?> =
        buildMap {
            if (id != null) put("id", id)
            if (type != null) put("type", type)
        }

    @Test
    fun `an ES256 entry whose type is not public-key is unsupported and replaces no resident passkey`() = runTest {
        assertRegistrationRefused("unsupported type", Ctap2.ERR_UNSUPPORTED_ALGORITHM,
            registration(params = listOf(mapOf("type" to "unsupported", "alg" to -7))))
        assertRegistrationRefused("no params", Ctap2.ERR_UNSUPPORTED_ALGORITHM, registration(params = emptyList<Any>()))

        // ES256 is still chosen from a public-key entry after one of another type.
        val (status, _) = call(Ctap2.CMD_MAKE_CREDENTIAL, registration(params = listOf(
            mapOf("alg" to -7, "type" to "unsupported"),
            mapOf("alg" to -7, "type" to "public-key")
        )))
        assertEquals(Ctap2.OK, status)
        assertEquals(1, backend.created.size)
    }

    @Test
    fun `a malformed pubKeyCredParams entry is refused even beside a supported one`() = runTest {
        val good = mapOf("alg" to -7, "type" to "public-key")
        val cases = listOf(
            "no type" to (mapOf("alg" to -7) to Ctap2.ERR_MISSING_PARAMETER),
            "type not text" to (mapOf("alg" to -7, "type" to 1) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "no alg" to (mapOf("type" to "public-key") to Ctap2.ERR_MISSING_PARAMETER),
            "alg not integer" to (mapOf("alg" to "ES256", "type" to "public-key") to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "entry not a map" to ("public-key" to Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        )
        for ((label, case) in cases) {
            val (entry, expected) = case
            assertRegistrationRefused(label, expected, registration(params = listOf(entry)))
            assertRegistrationRefused("$label, before ES256", expected, registration(params = listOf(entry, good)))
            assertRegistrationRefused("$label, after ES256", expected, registration(params = listOf(good, entry)))
        }
        assertRegistrationRefused("params not a list", Ctap2.ERR_CBOR_UNEXPECTED_TYPE, registration(params = good))
        assertRegistrationRefused("params missing", Ctap2.ERR_MISSING_PARAMETER, registration(params = null))
    }

    @Test
    fun `a malformed rp is refused before any prompt`() = runTest {
        val cases = listOf(
            "rp missing" to (null to Ctap2.ERR_MISSING_PARAMETER),
            "rp not a map" to (rpId to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "rp id missing" to (mapOf("name" to "Example") to Ctap2.ERR_MISSING_PARAMETER),
            "rp id not text" to (mapOf("id" to rpId.toByteArray()) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "rp id empty" to (mapOf("id" to "") to Ctap2.ERR_INVALID_LENGTH),
            "rp name not text" to (mapOf("id" to rpId, "name" to 5) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "rp icon not text" to (mapOf("id" to rpId, "icon" to true) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        )
        for ((label, case) in cases) {
            assertRegistrationRefused(label, case.second, registration(rp = case.first))
        }
    }

    @Test
    fun `a malformed user is refused before any prompt`() = runTest {
        val cases = listOf(
            "user missing" to (null to Ctap2.ERR_MISSING_PARAMETER),
            "user not a map" to ("alice" to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "user id not bytes" to (mapOf("id" to "123") to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "user id empty" to (mapOf("id" to ByteArray(0)) to Ctap2.ERR_INVALID_LENGTH),
            "user id over 64 bytes" to (mapOf("id" to ByteArray(65)) to Ctap2.ERR_INVALID_LENGTH),
            "user name not text" to (mapOf("id" to userId, "name" to 1) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "displayName not text" to (mapOf("id" to userId, "displayName" to byteArrayOf(1)) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
            "user icon not text" to (mapOf("id" to userId, "icon" to 2) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        )
        for ((label, case) in cases) {
            assertRegistrationRefused(label, case.second, registration(user = case.first))
        }
    }

    /** Malformed credential descriptors, as excludeList or allowList entries. */
    private fun malformedDescriptors(): List<Pair<String, Pair<Any, Int>>> = listOf(
        "not a map" to (backend.residentId to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
        "no type" to (descriptor(type = null) to Ctap2.ERR_MISSING_PARAMETER),
        "type not text" to (descriptor(type = 1) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
        "no id" to (descriptor(id = null) to Ctap2.ERR_MISSING_PARAMETER),
        "id not bytes" to (descriptor(id = "9999") to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
        "id over 1023 bytes" to (descriptor(id = ByteArray(1024)) to Ctap2.ERR_INVALID_LENGTH),
        "transports not a list" to (descriptor() + mapOf("transports" to "ble") to Ctap2.ERR_CBOR_UNEXPECTED_TYPE),
        "transport not text" to (descriptor() + mapOf("transports" to listOf(1)) to Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
    )

    @Test
    fun `a malformed excludeList descriptor is refused before any prompt or lookup`() = runTest {
        for ((label, case) in malformedDescriptors()) {
            assertRegistrationRefused(label, case.second, registration(exclude = listOf(descriptor(id = byteArrayOf(7)), case.first)))
        }
    }

    @Test
    fun `a malformed allowList descriptor is refused before any prompt or lookup`() = runTest {
        for ((label, case) in malformedDescriptors()) {
            assertAssertionRefused(label, case.second, assertion(allow = listOf(descriptor(), case.first)))
        }
    }

    @Test
    fun `an allowList descriptor of another type names no credential and is not discovery`() = runTest {
        val (status, body) = call(Ctap2.CMD_GET_ASSERTION, assertion(allow = listOf(descriptor(type = "unsupported"))))
        assertEquals(Ctap2.ERR_NO_CREDENTIALS, status)
        assertNull(body)
        assertEquals(0, backend.checks)
        assertEquals(0, backend.signs)
    }

    @Test
    fun `an excludeList descriptor of another type excludes nothing`() = runTest {
        val (status, _) = call(Ctap2.CMD_MAKE_CREDENTIAL, registration(exclude = listOf(descriptor(type = "unsupported"))))
        assertEquals(Ctap2.OK, status)
        assertEquals(1, backend.created.size)
    }

    @Test
    fun `options and extensions with a key that is not text are refused`() = runTest {
        for ((label, extra) in listOf("options" to mapOf<Any, Any?>(7 to mapOf(1 to true)), "extensions" to mapOf<Any, Any?>(6 to mapOf(1 to true)))) {
            assertRegistrationRefused("makeCredential $label", Ctap2.ERR_CBOR_UNEXPECTED_TYPE, registration(extra = extra))
        }
        for ((label, extra) in listOf("options" to mapOf<Any, Any?>(5 to mapOf(1 to true)), "extensions" to mapOf<Any, Any?>(4 to mapOf(1 to true)))) {
            assertAssertionRefused("getAssertion $label", Ctap2.ERR_CBOR_UNEXPECTED_TYPE, assertion(allow = null, extra = extra))
        }
    }

    @Test
    fun `an rpId that is empty is refused before any lookup`() = runTest {
        assertAssertionRefused("empty rpId", Ctap2.ERR_INVALID_LENGTH, assertion(allow = null, extra = mapOf(1 to "")))
    }
}
