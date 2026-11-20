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

import com.automatethethings.xkey.credential.UserVerificationCompliance
import com.automatethethings.xkey.credential.UserVerificationRequiredException
import com.automatethethings.xkey.credential.UvRequirement
import com.automatethethings.xkey.crypto.CborDecoder
import com.automatethethings.xkey.crypto.CborDecodingException
import com.automatethethings.xkey.crypto.CborEncoder
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.coroutines.cancellation.CancellationException

/** CTAP2 command bytes and status codes (CTAP 2.1, "Status codes"). */
object Ctap2 {
    const val CMD_MAKE_CREDENTIAL = 0x01
    const val CMD_GET_ASSERTION = 0x02
    const val CMD_GET_INFO = 0x04

    const val OK = 0x00
    const val ERR_INVALID_COMMAND = 0x01
    const val ERR_INVALID_LENGTH = 0x03
    const val ERR_CBOR_UNEXPECTED_TYPE = 0x11
    const val ERR_INVALID_CBOR = 0x12
    const val ERR_MISSING_PARAMETER = 0x14
    const val ERR_CREDENTIAL_EXCLUDED = 0x19
    const val ERR_UNSUPPORTED_ALGORITHM = 0x26
    const val ERR_OPERATION_DENIED = 0x27
    const val ERR_UNSUPPORTED_OPTION = 0x2B
    const val ERR_INVALID_OPTION = 0x2C
    const val ERR_KEEPALIVE_CANCEL = 0x2D
    const val ERR_NO_CREDENTIALS = 0x2E
    const val ERR_PIN_AUTH_INVALID = 0x33
    const val ERR_PIN_REQUIRED = 0x36
    const val ERR_OTHER = 0x7F

    /** COSE algorithm ES256, the only one this authenticator creates. */
    const val ALG_ES256 = -7
}

/**
 * A passkey the backend offers to a BLE client. [selection] is what the
 * backend read about it when it listed it, before any prompt: it signs with
 * that key only, and only while it still holds. The authenticator hands back
 * the same object it was given, never a copy.
 */
class FidoCredential(
    val id: ByteArray,
    val rpId: String,
    val userHandle: ByteArray?,
    val userName: String?,
    val userDisplayName: String?,
    val discoverable: Boolean,
    val selection: FidoCredentialSelection? = null
)

/** A backend's own record of a listed credential, opaque to the authenticator. */
interface FidoCredentialSelection

/** The outcome of asking the phone's user to approve a ceremony. */
enum class UserCheck {
    /** The user passed a biometric or device-credential prompt. */
    VERIFIED,

    /** The user cancelled or failed the prompt. */
    DECLINED,

    /** The phone has no way to prompt (nothing enrolled, no prompt available). */
    UNAVAILABLE
}

/** A new passkey's parameters, as authenticatorMakeCredential received them. */
class CredentialRequest(
    val rpId: String,
    val rpName: String?,
    val userHandle: ByteArray,
    val userName: String?,
    val userDisplayName: String?,
    val discoverable: Boolean
)

/** A passkey just created: its id and its COSE_Key public key. */
class NewCredential(val id: ByteArray, val cosePublicKey: ByteArray)

/** Authenticator data and the signature over it and the client data hash. */
class SignedAssertion(val authenticatorData: ByteArray, val signature: ByteArray)

/** The backend refused; [status] is the CTAP2 status to answer. */
class FidoRefusedException(val status: Int, message: String) : Exception(message)

/**
 * What the authenticator needs from the phone. The Android implementation is
 * [AndroidFidoCredentialBackend]; it is the one place where the sharing policy,
 * the sign counter, user verification and Keystore meet this transport.
 */
interface FidoCredentialBackend {
    /** Whether [checkUser] can verify the user at all (getInfo option `uv`). */
    val userVerificationAvailable: Boolean

    /** The owner's strict user verification setting. */
    val strictUserVerification: Boolean

    /**
     * Passkeys for [rpId] the sharing policy shows a BLE client and that can
     * sign now: one that cannot is left out, never listed. Every candidate
     * the authenticator considers comes from this one list.
     */
    suspend fun credentials(rpId: String): List<FidoCredential>

    /** Prompt the user to approve a ceremony for [rpId]. */
    suspend fun checkUser(rpId: String, registering: Boolean): UserCheck

    /**
     * Ask the owner on the phone which of [candidates] (two or more
     * discoverable passkeys for [rpId], each named by its user name and
     * display name) signs. Returns the one chosen, or null when the owner
     * declines or the phone cannot ask.
     */
    suspend fun chooseCredential(rpId: String, candidates: List<FidoCredential>): FidoCredential?

    /**
     * Advance [credential]'s counter, build authenticator data with it, and
     * sign `authenticatorData || clientDataHash` with the credential's key.
     *
     * @throws FidoRefusedException if the credential is gone or no longer shared.
     */
    suspend fun sign(
        credential: FidoCredential,
        authenticatorData: (signCount: Long) -> ByteArray,
        clientDataHash: ByteArray
    ): SignedAssertion

    /** Create and store an ES256 passkey. */
    suspend fun create(request: CredentialRequest): NewCredential
}

/** Turns one reassembled FIDO BLE MSG into its response. */
interface FidoMessageHandler {
    /**
     * @param request a CTAP2 command byte followed by its CBOR parameters.
     * @param onUserActionNeeded called when the handler starts waiting for the user.
     * @return a CTAP2 status byte followed by the CBOR response, if any.
     */
    suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit = {}): ByteArray
}

/**
 * A CTAP2 authenticator: authenticatorGetInfo, authenticatorGetAssertion and
 * authenticatorMakeCredential over a [FidoCredentialBackend].
 *
 * Every assertion and registration asks the user on the phone first, so user
 * presence is always real. When the prompt passes, the user was verified and
 * the UV flag says so; when it is declined the answer is
 * CTAP2_ERR_OPERATION_DENIED; when the phone cannot prompt and the client
 * required verification, [UserVerificationCompliance] refuses and the answer
 * is CTAP2_ERR_PIN_REQUIRED; otherwise CTAP2_ERR_OPERATION_DENIED, because
 * nothing can establish presence. No refusal signs anything.
 */
class Ctap2Authenticator(
    private val backend: FidoCredentialBackend,
    private val aaguid: ByteArray = ByteArray(16)
) : FidoMessageHandler {

    private class CtapError(val status: Int) : Exception()

    override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray {
        if (request.isEmpty()) return status(Ctap2.ERR_INVALID_COMMAND)
        return try {
            when (request[0].toInt() and 0xFF) {
                Ctap2.CMD_GET_INFO -> response(getInfo())
                Ctap2.CMD_GET_ASSERTION ->
                    response(getAssertion(decodeParams(request, GET_ASSERTION_OPTIONAL), onUserActionNeeded))
                Ctap2.CMD_MAKE_CREDENTIAL ->
                    response(makeCredential(decodeParams(request, MAKE_CREDENTIAL_OPTIONAL), onUserActionNeeded))
                else -> status(Ctap2.ERR_INVALID_COMMAND)
            }
        } catch (e: CtapError) {
            status(e.status)
        } catch (e: FidoRefusedException) {
            status(e.status)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            status(Ctap2.ERR_OTHER)
        }
    }

    /**
     * The one place a request's parameters are decoded. Each optional
     * container parameter ([optional]: allowList, excludeList, extensions,
     * options) is first checked against its expected CBOR type: a value of
     * any other type, empty or not, is CTAP2_ERR_CBOR_UNEXPECTED_TYPE. Only
     * then is an empty container of the expected type dropped, so it means
     * the same as an absent one: an empty allowList is discovery, never "no
     * credential allowed", and an empty excludeList excludes nothing. Every
     * command reads its parameters only from what this returns.
     */
    private fun decodeParams(request: ByteArray, optional: Map<Long, OptionalType>): Map<*, *> {
        if (request.size < 2) throw CtapError(Ctap2.ERR_MISSING_PARAMETER)
        val decoded = try {
            CborDecoder.decode(request.copyOfRange(1, request.size))
        } catch (e: CborDecodingException) {
            throw CtapError(Ctap2.ERR_INVALID_CBOR)
        }
        val params = decoded as? Map<*, *> ?: throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        return params.filterNot { (key, value) ->
            val expected = (key as? Long)?.let { optional[it] } ?: return@filterNot false
            val empty = when (expected) {
                OptionalType.LIST -> (value as? List<*> ?: throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)).isEmpty()
                OptionalType.MAP -> (value as? Map<*, *> ?: throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)).isEmpty()
            }
            empty
        }
    }

    private fun getInfo(): Map<Any, Any?> = mapOf(
        1 to listOf("FIDO_2_0"),
        3 to aaguid,
        4 to mapOf(
            "rk" to true,
            "up" to true,
            "uv" to backend.userVerificationAvailable,
            "plat" to false
        ),
        5 to FidoBle.MAX_MESSAGE_SIZE,
        9 to listOf("ble"),
        10 to listOf(mapOf("alg" to Ctap2.ALG_ES256, "type" to "public-key"))
    )

    private suspend fun getAssertion(params: Map<*, *>, onUserActionNeeded: () -> Unit): Map<Any, Any?> {
        val rpId = params.text(1L)
        val clientDataHash = params.clientDataHash(2L)
        val allowList = params.descriptorIds(3L)
        val options = params.options(5L)
        refusePinUvAuth(params, 6L)
        if (options["up"] == false) throw CtapError(Ctap2.ERR_UNSUPPORTED_OPTION)
        val uvRequested = options["uv"] == true

        val available = backend.credentials(rpId)
        val candidates = if (allowList != null) {
            available.filter { cred -> allowList.any { it.contentEquals(cred.id) } }
        } else {
            available.filter { it.discoverable }
        }
        val credential = pick(rpId, candidates, discovered = allowList == null, onUserActionNeeded)

        val verified = approve(rpId, registering = false, uvRequested, onUserActionNeeded)
        val flags = UserVerificationCompliance.flags(userPresent = true, userVerified = verified)
        val rpIdHash = sha256(rpId.toByteArray(Charsets.UTF_8))
        val signed = backend.sign(
            credential,
            { count -> rpIdHash + flags + count.toUInt32() },
            clientDataHash
        )

        val response = mutableMapOf<Any, Any?>(
            1 to mapOf("id" to credential.id, "type" to "public-key"),
            2 to signed.authenticatorData,
            3 to signed.signature
        )
        credential.userHandle?.let { response[4] = mapOf("id" to it) }
        return response
    }

    private suspend fun makeCredential(params: Map<*, *>, onUserActionNeeded: () -> Unit): Map<Any, Any?> {
        // Attestation "none" signs nothing, but the hash must still be well formed.
        params.clientDataHash(1L)
        val rp = params.map(2L)
        val rpId = rp.text("id")
        val user = params.map(3L)
        val userHandle = user["id"] as? ByteArray ?: missingOrWrongType(user["id"])
        val algorithms = params.list(4L).map {
            ((it as? Map<*, *>)?.get("alg") as? Long) ?: throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
        }
        val excludeList = params.descriptorIds(5L)
        val options = params.options(7L)
        refusePinUvAuth(params, 8L)

        if (Ctap2.ALG_ES256.toLong() !in algorithms) throw CtapError(Ctap2.ERR_UNSUPPORTED_ALGORITHM)
        if (options["up"] == false) throw CtapError(Ctap2.ERR_INVALID_OPTION)
        val uvRequested = options["uv"] == true

        val existing = if (excludeList != null) backend.credentials(rpId) else emptyList()
        val excluded = excludeList?.any { id -> existing.any { it.id.contentEquals(id) } } == true

        val verified = approve(rpId, registering = true, uvRequested, onUserActionNeeded)
        if (excluded) throw CtapError(Ctap2.ERR_CREDENTIAL_EXCLUDED)

        val made = backend.create(
            CredentialRequest(
                rpId = rpId,
                rpName = rp["name"] as? String,
                userHandle = userHandle,
                userName = user["name"] as? String,
                userDisplayName = user["displayName"] as? String,
                discoverable = options["rk"] == true
            )
        )
        val flags = UserVerificationCompliance.flags(
            userPresent = true,
            userVerified = verified,
            attestedCredentialData = true
        )
        val authData = sha256(rpId.toByteArray(Charsets.UTF_8)) + flags + 0L.toUInt32() +
            aaguid + byteArrayOf((made.id.size shr 8).toByte(), made.id.size.toByte()) +
            made.id + made.cosePublicKey
        return mapOf(1 to "none", 2 to authData, 3 to emptyMap<Any, Any?>())
    }

    /**
     * The credential an assertion signs with. An allow list names the
     * client's own choice, and a single discoverable passkey needs none; with
     * several discoverable passkeys the owner picks the account on the phone,
     * and only one of those offered can be picked. A declined choice is
     * CTAP2_ERR_OPERATION_DENIED.
     */
    private suspend fun pick(
        rpId: String,
        candidates: List<FidoCredential>,
        discovered: Boolean,
        onUserActionNeeded: () -> Unit
    ): FidoCredential {
        if (candidates.isEmpty()) throw CtapError(Ctap2.ERR_NO_CREDENTIALS)
        if (!discovered || candidates.size == 1) return candidates.first()
        onUserActionNeeded()
        val chosen = backend.chooseCredential(rpId, candidates)
        return candidates.firstOrNull { chosen != null && it.id.contentEquals(chosen.id) }
            ?: throw CtapError(Ctap2.ERR_OPERATION_DENIED)
    }

    /**
     * Ask the user on the phone. Returns whether the user was verified;
     * throws the refusal otherwise.
     */
    private suspend fun approve(
        rpId: String,
        registering: Boolean,
        uvRequested: Boolean,
        onUserActionNeeded: () -> Unit
    ): Boolean {
        onUserActionNeeded()
        return when (backend.checkUser(rpId, registering)) {
            UserCheck.VERIFIED -> true
            UserCheck.DECLINED -> throw CtapError(Ctap2.ERR_OPERATION_DENIED)
            UserCheck.UNAVAILABLE -> {
                try {
                    UserVerificationCompliance.enforce(
                        requirement = if (uvRequested) UvRequirement.REQUIRED else UvRequirement.DISCOURAGED,
                        verificationPerformed = false,
                        strict = backend.strictUserVerification,
                        ceremony = if (registering) "Passkey registration for $rpId" else "Passkey assertion for $rpId"
                    )
                } catch (e: UserVerificationRequiredException) {
                    throw CtapError(Ctap2.ERR_PIN_REQUIRED)
                }
                // Without a prompt nothing shows a person is there.
                throw CtapError(Ctap2.ERR_OPERATION_DENIED)
            }
        }
    }

    /** No clientPin: any pinUvAuthParam fails verification. */
    private fun refusePinUvAuth(params: Map<*, *>, key: Long) {
        if (params.containsKey(key)) throw CtapError(Ctap2.ERR_PIN_AUTH_INVALID)
    }

    private fun response(body: Map<Any, Any?>): ByteArray = byteArrayOf(Ctap2.OK.toByte()) + CborEncoder.encode(body)

    private fun status(code: Int): ByteArray = byteArrayOf(code.toByte())

    /** The CBOR container type an optional parameter must have. */
    private enum class OptionalType { LIST, MAP }

    private companion object {
        /** authenticatorGetAssertion's optional containers: allowList (array), extensions and options (maps). */
        val GET_ASSERTION_OPTIONAL = mapOf(3L to OptionalType.LIST, 4L to OptionalType.MAP, 5L to OptionalType.MAP)

        /** authenticatorMakeCredential's optional containers: excludeList (array), extensions and options (maps). */
        val MAKE_CREDENTIAL_OPTIONAL = mapOf(5L to OptionalType.LIST, 6L to OptionalType.MAP, 7L to OptionalType.MAP)

        fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

        fun Long.toUInt32(): ByteArray = ByteBuffer.allocate(4).putInt(toInt()).array()

        fun missingOrWrongType(value: Any?): Nothing =
            throw CtapError(if (value == null) Ctap2.ERR_MISSING_PARAMETER else Ctap2.ERR_CBOR_UNEXPECTED_TYPE)

        fun Map<*, *>.text(key: Any): String = this[key] as? String ?: missingOrWrongType(this[key])

        fun Map<*, *>.map(key: Any): Map<*, *> = this[key] as? Map<*, *> ?: missingOrWrongType(this[key])

        fun Map<*, *>.list(key: Any): List<*> = this[key] as? List<*> ?: missingOrWrongType(this[key])

        fun Map<*, *>.clientDataHash(key: Any): ByteArray {
            val hash = this[key] as? ByteArray ?: missingOrWrongType(this[key])
            if (hash.size != 32) throw CtapError(Ctap2.ERR_INVALID_LENGTH)
            return hash
        }

        fun Map<*, *>.options(key: Any): Map<*, *> {
            val value = this[key] ?: return emptyMap<Any, Any>()
            val options = value as? Map<*, *> ?: throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
            if (options.values.any { it !is Boolean }) throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
            return options
        }

        /** The ids of a list of PublicKeyCredentialDescriptor, or null when absent. */
        fun Map<*, *>.descriptorIds(key: Any): List<ByteArray>? {
            val value = this[key] ?: return null
            val list = value as? List<*> ?: throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
            return list.map { d ->
                val descriptor = d as? Map<*, *> ?: throw CtapError(Ctap2.ERR_CBOR_UNEXPECTED_TYPE)
                descriptor["id"] as? ByteArray ?: missingOrWrongType(descriptor["id"])
            }
        }
    }
}
