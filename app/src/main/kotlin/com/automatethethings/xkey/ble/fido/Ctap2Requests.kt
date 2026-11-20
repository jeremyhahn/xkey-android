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
import com.automatethethings.xkey.crypto.CborDecodingException

/** A request the validator refused; [status] is the CTAP2 status to answer. */
internal class Ctap2RequestException(val status: Int) : Exception()

/** authenticatorMakeCredential, validated in full. */
internal class MakeCredentialRequest(
    val clientDataHash: ByteArray,
    val rpId: String,
    val rpName: String?,
    val userHandle: ByteArray,
    val userName: String?,
    val userDisplayName: String?,
    /** The public-key credential ids to exclude, or null when there are none. */
    val excludeList: List<ByteArray>?,
    val options: Map<String, Boolean>
)

/** authenticatorGetAssertion, validated in full. */
internal class GetAssertionRequest(
    val rpId: String,
    val clientDataHash: ByteArray,
    /**
     * The public-key credential ids the client allows, or null for discovery
     * (no allowList, or an empty one). A list whose descriptors are all of
     * another type is empty, never null: it names no credential.
     */
    val allowList: List<ByteArray>?,
    val options: Map<String, Boolean>
)

/**
 * The one place a CTAP2 request is decoded and validated. Every entity a
 * command reads (rp, user, pubKeyCredParams, excludeList, allowList, options,
 * extensions) is checked in full here: required members present, every
 * member of its CBOR type, the lengths WebAuthn caps (user handle 1 to 64
 * bytes, credential id 1 to 1023 bytes). A missing member is
 * CTAP2_ERR_MISSING_PARAMETER, a member of the wrong type
 * CTAP2_ERR_CBOR_UNEXPECTED_TYPE, a length out of range
 * CTAP2_ERR_INVALID_LENGTH. Only a request that passes reaches a command, so
 * nothing is prompted for, looked up or stored before the whole request is
 * known to be well formed.
 *
 * An empty optional container of its expected type means the same as an
 * absent one (an empty allowList is discovery); one of another type, empty or
 * not, is CTAP2_ERR_CBOR_UNEXPECTED_TYPE. A credential descriptor or a
 * credential parameter whose type is not "public-key" is ignored, as CTAP 2.1
 * says, after it is checked: it names no credential and selects no algorithm.
 */
internal object Ctap2Requests {

    /** The longest user handle WebAuthn allows. */
    const val MAX_USER_HANDLE = 64

    /** The longest credential id WebAuthn allows. */
    const val MAX_CREDENTIAL_ID = 1023

    private const val PUBLIC_KEY = "public-key"

    fun makeCredential(request: ByteArray): MakeCredentialRequest {
        val params = decode(request)
        val clientDataHash = params.clientDataHash(1L)
        val rp = params.map(2L)
        val rpId = rp.text("id")
        if (rpId.isEmpty()) fail(Ctap2.ERR_INVALID_LENGTH)
        val rpName = rp.optionalText("name")
        rp.optionalText("icon")
        val user = params.map(3L)
        val userHandle = user.bytes("id")
        if (userHandle.isEmpty() || userHandle.size > MAX_USER_HANDLE) fail(Ctap2.ERR_INVALID_LENGTH)
        val userName = user.optionalText("name")
        val userDisplayName = user.optionalText("displayName")
        user.optionalText("icon")
        val algorithms = params.list(4L).map { credentialParameter(it) }
        val excludeList = params.descriptors(5L)?.takeIf { it.isNotEmpty() }
        params.extensions(6L)
        val options = params.options(7L)
        refusePinUvAuth(params, 8L)
        params.optionalUnsigned(9L)
        params.optionalUnsigned(10L)

        if (algorithms.none { (type, alg) -> type == PUBLIC_KEY && alg == Ctap2.ALG_ES256.toLong() }) {
            fail(Ctap2.ERR_UNSUPPORTED_ALGORITHM)
        }
        if (options["up"] == false) fail(Ctap2.ERR_INVALID_OPTION)
        return MakeCredentialRequest(
            clientDataHash, rpId, rpName, userHandle, userName, userDisplayName, excludeList, options
        )
    }

    fun getAssertion(request: ByteArray): GetAssertionRequest {
        val params = decode(request)
        val rpId = params.text(1L)
        if (rpId.isEmpty()) fail(Ctap2.ERR_INVALID_LENGTH)
        val clientDataHash = params.clientDataHash(2L)
        val allowList = params.descriptors(3L)
        params.extensions(4L)
        val options = params.options(5L)
        refusePinUvAuth(params, 6L)
        params.optionalUnsigned(7L)

        if (options["up"] == false) fail(Ctap2.ERR_UNSUPPORTED_OPTION)
        return GetAssertionRequest(rpId, clientDataHash, allowList, options)
    }

    private fun fail(status: Int): Nothing = throw Ctap2RequestException(status)

    /**
     * The one read of a request field: null when [key] is absent. No CTAP2
     * field this authenticator reads is nullable, so a field present as CBOR
     * null is CTAP2_ERR_CBOR_UNEXPECTED_TYPE, never the same as an omitted
     * one (a null allowList is not discovery).
     */
    private fun Map<*, *>.present(key: Any): Any? {
        if (!containsKey(key)) return null
        return this[key] ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
    }

    /** A required field: CTAP2_ERR_MISSING_PARAMETER when absent. */
    private fun Map<*, *>.required(key: Any): Any = present(key) ?: fail(Ctap2.ERR_MISSING_PARAMETER)

    /** The command's parameter map; an empty optional container is dropped later, by type. */
    private fun decode(request: ByteArray): Map<*, *> {
        if (request.size < 2) fail(Ctap2.ERR_MISSING_PARAMETER)
        val decoded = try {
            CborDecoder.decode(request.copyOfRange(1, request.size))
        } catch (e: CborDecodingException) {
            fail(Ctap2.ERR_INVALID_CBOR)
        }
        return decoded as? Map<*, *> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
    }

    /** No clientPin: any pinUvAuthParam fails verification. */
    private fun refusePinUvAuth(params: Map<*, *>, key: Long) {
        if (params.containsKey(key)) fail(Ctap2.ERR_PIN_AUTH_INVALID)
    }

    /** One PublicKeyCredentialParameters entry: its type and its algorithm, both required. */
    private fun credentialParameter(entry: Any?): Pair<String, Long> {
        val map = entry as? Map<*, *> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        val type = map.text("type")
        val alg = map.required("alg") as? Long ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        return type to alg
    }

    private fun Map<*, *>.text(key: Any): String = required(key) as? String ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.bytes(key: Any): ByteArray = required(key) as? ByteArray ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.map(key: Any): Map<*, *> = required(key) as? Map<*, *> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.list(key: Any): List<*> = required(key) as? List<*> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.optionalText(key: Any): String? {
        val value = present(key) ?: return null
        return value as? String ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
    }

    private fun Map<*, *>.optionalUnsigned(key: Any) {
        val value = present(key) ?: return
        if (value !is Long || value < 0) fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
    }

    private fun Map<*, *>.clientDataHash(key: Any): ByteArray {
        val hash = bytes(key)
        if (hash.size != 32) fail(Ctap2.ERR_INVALID_LENGTH)
        return hash
    }

    /** An optional map whose keys are text; null when absent or empty. */
    private fun Map<*, *>.optionalTextKeyedMap(key: Any): Map<*, *>? {
        val value = present(key) ?: return null
        val map = value as? Map<*, *> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        if (map.keys.any { it !is String }) fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        return map.takeIf { it.isNotEmpty() }
    }

    private fun Map<*, *>.extensions(key: Any) {
        optionalTextKeyedMap(key)
    }

    private fun Map<*, *>.options(key: Any): Map<String, Boolean> {
        val options = optionalTextKeyedMap(key) ?: return emptyMap()
        return options.entries.associate { (name, value) ->
            name as String to (value as? Boolean ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE))
        }
    }

    /**
     * A list of PublicKeyCredentialDescriptor: null when absent or empty,
     * otherwise the ids of its "public-key" descriptors. Every descriptor is
     * checked, whatever its type.
     */
    private fun Map<*, *>.descriptors(key: Any): List<ByteArray>? {
        val value = present(key) ?: return null
        val list = value as? List<*> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        if (list.isEmpty()) return null
        return list.mapNotNull { entry ->
            val descriptor = entry as? Map<*, *> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
            val type = descriptor.text("type")
            val id = descriptor.bytes("id")
            if (id.isEmpty() || id.size > MAX_CREDENTIAL_ID) fail(Ctap2.ERR_INVALID_LENGTH)
            descriptor.present("transports")?.let { transports ->
                val names = transports as? List<*> ?: fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
                if (names.any { it !is String }) fail(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
            }
            id.takeIf { type == PUBLIC_KEY }
        }
    }
}
