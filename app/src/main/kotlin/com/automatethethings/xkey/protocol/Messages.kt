package com.automatethethings.xkey.protocol

import com.automatethethings.xkey.util.getStringOrNull
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener
import java.math.BigInteger
import java.util.Base64

/**
 * xKey protocol message types.
 *
 * This file defines the JSON-RPC 2.0 style messages used for communication
 * between xKey desktop clients and the Android authenticator.
 *
 * All messages are JSON encoded and transmitted over the encrypted BLE channel.
 */

/**
 * Represents a protocol request message.
 *
 * @property id Unique request identifier
 * @property method Method name to invoke
 * @property params Optional method parameters
 * @property generation The initiator's request generation (go-xkms#128), a
 *   uint64 the response echoes verbatim; null when the request carried none
 */
data class Request(
    val id: Long,
    val method: String,
    val params: JSONObject? = null,
    val generation: ULong? = null
) {
    companion object {
        /**
         * Parses a Request from JSON bytes.
         *
         * @throws ProtocolException if parsing fails
         */
        fun fromJson(json: ByteArray): Request {
            return fromJson(String(json, Charsets.UTF_8))
        }

        /**
         * Parses a Request from JSON string.
         *
         * @throws ProtocolException if parsing fails
         */
        fun fromJson(json: String): Request {
            try {
                val obj = JSONObject(json)

                val id = obj.optLong("id", -1)
                if (id < 0) {
                    throw ProtocolException("Missing or invalid 'id' field")
                }

                val method = obj.getStringOrNull("method")
                    ?: throw ProtocolException("Missing 'method' field")

                val params = if (obj.has("params") && !obj.isNull("params")) {
                    obj.getJSONObject("params")
                } else {
                    null
                }

                return Request(id, method, params, readGeneration(json))
            } catch (e: JSONException) {
                throw ProtocolException("Invalid JSON: ${e.message}", e)
            }
        }
    }

    /**
     * Converts this request to JSON bytes.
     */
    fun toJson(): ByteArray {
        return toJsonString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Converts this request to JSON string.
     */
    fun toJsonString(): String {
        val obj = JSONObject()
        obj.put("id", id)
        if (generation != null) {
            obj.put(GENERATION_KEY, generation.toJsonNumber())
        }
        obj.put("method", method)
        if (params != null) {
            obj.put("params", params)
        }
        return obj.toString()
    }
}

/** The envelope member carrying a request's generation (go-xkms#128). */
const val GENERATION_KEY = "generation"

/** A JSON integer as a uint64 is written: no sign, no leading zero, no fraction or exponent. */
private val UINT64_LITERAL = Regex("0|[1-9][0-9]*")

/**
 * The top-level `generation` of the JSON message [json], or null when it has
 * none or it is not a uint64.
 *
 * The phone copies the value into its response and never computes with it,
 * so it is read from the message text, not from a parsed [JSONObject]: the
 * Android platform org.json parses an integer literal above [Long.MAX_VALUE]
 * into a Double, which rounds it. The members before it are walked with the
 * same tokener, so a generation is still read from a message that is
 * malformed only after it.
 */
fun readGeneration(json: String): ULong? {
    val literal = try {
        topLevelLiteral(json, GENERATION_KEY)
    } catch (e: JSONException) {
        null
    } ?: return null
    if (!UINT64_LITERAL.matches(literal)) return null
    return literal.toULongOrNull()
}

/**
 * The raw text of the value of the top-level member [key] of the JSON object
 * [json], up to the next `,` or `}`; null when the object has no such member.
 * Every org.json the app runs on, the bundled one and Android's, has these
 * [JSONTokener] calls.
 */
private fun topLevelLiteral(json: String, key: String): String? {
    val tokener = JSONTokener(json)
    if (tokener.nextClean() != '{') return null
    while (true) {
        val next = tokener.nextClean()
        if (next == '}' || next == '\u0000') return null
        tokener.back()
        val name = tokener.nextValue() as? String ?: return null
        if (tokener.nextClean() != ':') return null
        if (name == key) {
            if (tokener.nextClean() == '\u0000') return null
            tokener.back()
            return tokener.nextTo(",}")
        }
        tokener.nextValue()
        if (tokener.nextClean() != ',') return null
    }
}

/**
 * This uint64 as the value org.json writes digit for digit: a [Long] when it
 * fits, otherwise a [BigInteger]. A boxed [ULong] is not a [Number], so
 * org.json would quote it.
 */
private fun ULong.toJsonNumber(): Number =
    if (this <= Long.MAX_VALUE.toULong()) toLong() else BigInteger(toString())

/**
 * Represents a protocol response message.
 *
 * @property id Request identifier this response corresponds to
 * @property result Successful result data
 * @property error Error information if request failed
 * @property generation The generation of the request this answers, copied
 *   verbatim; null when the request carried none
 */
data class Response(
    val id: Long,
    val result: JSONObject? = null,
    val error: ErrorObject? = null,
    val generation: ULong? = null
) {
    init {
        require(result != null || error != null) {
            "Response must have either result or error"
        }
        require(!(result != null && error != null)) {
            "Response cannot have both result and error"
        }
    }

    companion object {
        /**
         * Creates a successful response.
         */
        fun success(id: Long, result: JSONObject, generation: ULong? = null): Response {
            return Response(id, result = result, error = null, generation = generation)
        }

        /**
         * Creates an error response.
         */
        fun error(
            id: Long,
            code: Int,
            message: String,
            data: JSONObject? = null,
            generation: ULong? = null
        ): Response {
            return Response(id, result = null, error = ErrorObject(code, message, data), generation = generation)
        }

        /**
         * Creates an error response from an ErrorObject.
         */
        fun error(id: Long, error: ErrorObject, generation: ULong? = null): Response {
            return Response(id, result = null, error = error, generation = generation)
        }

        /**
         * Parses a Response from JSON bytes.
         */
        fun fromJson(json: ByteArray): Response {
            return fromJson(String(json, Charsets.UTF_8))
        }

        /**
         * Parses a Response from JSON string.
         */
        fun fromJson(json: String): Response {
            try {
                val obj = JSONObject(json)

                val id = obj.optLong("id", -1)
                if (id < 0) {
                    throw ProtocolException("Missing or invalid 'id' field")
                }

                val hasResult = obj.has("result") && !obj.isNull("result")
                val hasError = obj.has("error") && !obj.isNull("error")

                if (!hasResult && !hasError) {
                    throw ProtocolException("Response must have 'result' or 'error'")
                }

                val result = if (hasResult) obj.getJSONObject("result") else null
                val error = if (hasError) ErrorObject.fromJson(obj.getJSONObject("error")) else null

                return Response(id, result, error, readGeneration(json))
            } catch (e: JSONException) {
                throw ProtocolException("Invalid JSON: ${e.message}", e)
            }
        }
    }

    /**
     * Converts this response to JSON bytes.
     */
    fun toJson(): ByteArray {
        return toJsonString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Converts this response to JSON string.
     */
    fun toJsonString(): String {
        val obj = JSONObject()
        obj.put("id", id)
        if (generation != null) {
            obj.put(GENERATION_KEY, generation.toJsonNumber())
        }
        if (result != null) {
            obj.put("result", result)
        }
        if (error != null) {
            obj.put("error", error.toJson())
        }
        return obj.toString()
    }

    /**
     * Returns true if this is a successful response.
     */
    fun isSuccess(): Boolean = result != null

    /**
     * Returns true if this is an error response.
     */
    fun isError(): Boolean = error != null
}

/**
 * Represents an error in a response.
 *
 * @property code Error code
 * @property message Human-readable error message
 * @property data Optional additional error data
 */
data class ErrorObject(
    val code: Int,
    val message: String,
    val data: JSONObject? = null
) {
    companion object {
        /**
         * Parses an ErrorObject from JSON.
         */
        fun fromJson(obj: JSONObject): ErrorObject {
            val code = obj.optInt("code", ErrorCodes.INTERNAL_ERROR)
            val message = obj.optString("message", "Unknown error")
            val data = if (obj.has("data") && !obj.isNull("data")) {
                obj.getJSONObject("data")
            } else {
                null
            }
            return ErrorObject(code, message, data)
        }
    }

    /**
     * Converts this error to JSON.
     */
    fun toJson(): JSONObject {
        val obj = JSONObject()
        obj.put("code", code)
        obj.put("message", message)
        if (data != null) {
            obj.put("data", data)
        }
        return obj
    }
}

/**
 * Standard error codes for the xKey protocol.
 */
object ErrorCodes {
    // JSON-RPC standard errors
    const val PARSE_ERROR = -32700
    const val INVALID_REQUEST = -32600
    const val METHOD_NOT_FOUND = -32601
    const val INVALID_PARAMS = -32602
    const val INTERNAL_ERROR = -32603

    // xKey-specific errors
    const val KEY_NOT_FOUND = -32001
    const val USER_CANCELLED = -32002
    const val BIOMETRIC_FAILED = -32003
    const val BIOMETRIC_NOT_ENROLLED = -32004
    const val BIOMETRIC_LOCKOUT = -32005
    const val KEY_GENERATION_FAILED = -32006
    const val SIGNING_FAILED = -32007
    const val ENCRYPTION_FAILED = -32008
    const val DECRYPTION_FAILED = -32009
    const val INVALID_ALGORITHM = -32010
    const val STRONGBOX_UNAVAILABLE = -32011
    const val SESSION_EXPIRED = -32012
    const val RATE_LIMITED = -32013
    const val HMAC_FAILED = -32014
    const val ECDH_FAILED = -32015
    const val EXPORT_FAILED = -32016
    const val ATTESTATION_FAILED = -32023
    const val BACKEND_DENIED = -32018
    const val OPERATION_DENIED = -32019
    const val STORAGE_FULL = -32020
    const val KEY_EXISTS = -32021
    const val UNSUPPORTED_FORMAT = -32022
    const val PAIRING_REJECTED = -32017
    const val DEVICE_ATTESTATION_REQUIRED = -32024

    /** A request arrived before the peer completed pairing.confirm. */
    const val PAIRING_REQUIRED = -32025

    /**
     * A method family exists but its collaborator was not supplied on this
     * transport, so the request can never succeed here.
     *
     * Distinct from [INTERNAL_ERROR], which means a bug: a peer seeing this
     * knows the feature is unavailable rather than that the phone failed.
     *
     * Numbered above the shared -32001..-32034 block. It originally reused
     * -32026, which is [PIV_SLOT_NOT_FOUND] here and `ErrorCodePIVSlotNotFound`
     * on the desktop, so a PIV handler refusing for want of a key manager was
     * indistinguishable on the wire from one reporting an empty slot.
     */
    const val FEATURE_UNAVAILABLE = -32035

    /**
     * The method is understood but this platform cannot implement it at all.
     *
     * Sent when a peer asks the phone for a TPM2 operation. Android has no TPM
     * and never will, so the phone answers plainly rather than failing in a way
     * that reads as a transient fault the caller should retry. A caller seeing
     * this must switch to a mechanism the platform does support -- see
     * `local.getDeviceEnrollmentRequest`, which proves the same properties with
     * Android Keystore attestation.
     *
     * Answering these with a *success* is the dangerous alternative: credential
     * activation exists precisely so a CA can prove the requester holds the
     * hardware it claims, so faking it hands out certificates on no evidence.
     */
    const val NOT_APPLICABLE = -32036

    /**
     * A device attestation request did not speak protocol version 2.
     *
     * Version 1 proved freshness by embedding the pairing nonce in the attested
     * key's own certificate, which forced a new key per pairing and so could
     * never carry a stable device identity (go-xkms#129). Version 2 replaced it
     * with a live signature over a transcript.
     *
     * The two are not interchangeable and this prover never falls back: a peer
     * asking for version 1 gets a refusal, not a version 1 answer. Silently
     * downgrading would let anyone who can ask for the weaker exchange have it,
     * which is the whole value of a flag day thrown away. Mirrors the desktop's
     * `ErrAttestProtocolDowngrade`.
     */
    const val ATTEST_PROTOCOL_DOWNGRADE = -32037

    // Password vault errors (go-xkms docs/password-vault/api.md). A malformed
    // credential is INVALID_PARAMS and an unknown ID is KEY_NOT_FOUND.

    /** PasswordStoreUnlock arrived before any vault factor was enrolled. */
    const val VAULT_NOT_INITIALIZED = -32038

    /**
     * The credential unwrapped no enrolled factor. The message never says which
     * part was wrong, so a guesser learns nothing from the refusal.
     */
    const val VAULT_CREDENTIAL_REJECTED = -32039

    /** The vault is initialized and locked; unlock it before using the store. */
    const val PASSWORD_STORE_LOCKED = -32040

    // PIV errors
    const val PIV_SLOT_NOT_FOUND = -32026
    const val PIV_SLOT_OCCUPIED = -32027
    const val PIV_SIGN_FAILED = -32028
    const val PIV_INVALID_SLOT = -32029

    // PIN errors
    const val PIN_REQUIRED = -32032
    const val PIN_INCORRECT = -32033
    const val PIN_LOCKED = -32034
}

/**
 * Parameters for the generateKey method.
 *
 * @property credentialId Base64-encoded credential identifier
 * @property algorithm COSE algorithm identifier
 * @property requireUserVerification Whether biometric auth is required for use
 * @property preferStrongBox Whether to prefer StrongBox if available
 */
data class GenerateKeyParams(
    val credentialId: String,
    val algorithm: Int,
    val requireUserVerification: Boolean = true,
    val preferStrongBox: Boolean = true
) {
    companion object {
        fun fromJson(params: JSONObject): GenerateKeyParams {
            val credentialId = params.getStringOrNull("credentialId")
                ?: throw ProtocolException("Missing 'credentialId' parameter", errorCode = ErrorCodes.INVALID_PARAMS)

            val algorithm = params.optInt("algorithm", 0)
            if (algorithm == 0) {
                throw ProtocolException("Missing 'algorithm' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            }

            return GenerateKeyParams(
                credentialId = credentialId,
                algorithm = algorithm,
                requireUserVerification = params.optBoolean("requireUserVerification", true),
                preferStrongBox = params.optBoolean("preferStrongBox", true)
            )
        }
    }

    /**
     * Decodes the credential ID to bytes.
     */
    fun getCredentialIdBytes(): ByteArray {
        return Base64.getDecoder().decode(credentialId)
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("credentialId", credentialId)
            put("algorithm", algorithm)
            put("requireUserVerification", requireUserVerification)
            put("preferStrongBox", preferStrongBox)
        }
    }
}

/**
 * Result of the generateKey method.
 *
 * @property publicKey Base64-encoded COSE public key
 * @property attestation Base64-encoded attestation (optional)
 * @property strongBoxBacked Whether the key is backed by StrongBox
 */
data class GenerateKeyResult(
    val publicKey: String,
    val attestation: String? = null,
    val strongBoxBacked: Boolean = false
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("publicKey", publicKey)
            if (attestation != null) {
                put("attestation", attestation)
            }
            put("strongBoxBacked", strongBoxBacked)
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): GenerateKeyResult {
            return GenerateKeyResult(
                publicKey = obj.getString("publicKey"),
                attestation = obj.getStringOrNull("attestation"),
                strongBoxBacked = obj.optBoolean("strongBoxBacked", false)
            )
        }
    }
}

/**
 * Parameters for the sign method.
 *
 * @property credentialId Base64-encoded credential identifier
 * @property dataHash Base64-encoded SHA-256 hash to sign
 * @property userVerificationRequired Whether biometric verification is required
 */
data class SignParams(
    val credentialId: String,
    val dataHash: String,
    val userVerificationRequired: Boolean = true
) {
    companion object {
        fun fromJson(params: JSONObject): SignParams {
            val credentialId = params.getStringOrNull("credentialId")
                ?: throw ProtocolException("Missing 'credentialId' parameter", errorCode = ErrorCodes.INVALID_PARAMS)

            val dataHash = params.getStringOrNull("dataHash")
                ?: throw ProtocolException("Missing 'dataHash' parameter", errorCode = ErrorCodes.INVALID_PARAMS)

            return SignParams(
                credentialId = credentialId,
                dataHash = dataHash,
                userVerificationRequired = params.optBoolean("userVerificationRequired", true)
            )
        }
    }

    /**
     * Decodes the credential ID to bytes.
     */
    fun getCredentialIdBytes(): ByteArray {
        return Base64.getDecoder().decode(credentialId)
    }

    /**
     * Decodes the data hash to bytes.
     */
    fun getDataHashBytes(): ByteArray {
        return Base64.getDecoder().decode(dataHash)
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("credentialId", credentialId)
            put("dataHash", dataHash)
            put("userVerificationRequired", userVerificationRequired)
        }
    }
}

/**
 * Result of the sign method.
 *
 * @property signature Base64-encoded signature
 * @property userVerified Whether biometric verification was performed
 */
data class SignResult(
    val signature: String,
    val userVerified: Boolean
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("signature", signature)
            put("userVerified", userVerified)
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): SignResult {
            return SignResult(
                signature = obj.getString("signature"),
                userVerified = obj.optBoolean("userVerified", false)
            )
        }
    }
}

/**
 * Parameters for the deleteKey method.
 *
 * @property credentialId Base64-encoded credential identifier
 */
data class DeleteKeyParams(
    val credentialId: String
) {
    companion object {
        fun fromJson(params: JSONObject): DeleteKeyParams {
            val credentialId = params.getStringOrNull("credentialId")
                ?: throw ProtocolException("Missing 'credentialId' parameter", errorCode = ErrorCodes.INVALID_PARAMS)

            return DeleteKeyParams(credentialId)
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("credentialId", credentialId)
        }
    }
}

/**
 * Parameters for the loadKey method.
 *
 * @property credentialId Base64-encoded credential identifier
 */
data class LoadKeyParams(
    val credentialId: String
) {
    companion object {
        fun fromJson(params: JSONObject): LoadKeyParams {
            val credentialId = params.getStringOrNull("credentialId")
                ?: throw ProtocolException("Missing 'credentialId' parameter", errorCode = ErrorCodes.INVALID_PARAMS)

            return LoadKeyParams(credentialId)
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("credentialId", credentialId)
        }
    }
}

/**
 * Result of the loadKey method.
 *
 * @property exists Whether the key exists
 * @property publicKey Base64-encoded public key (if exists)
 * @property algorithm COSE algorithm identifier (if exists)
 */
data class LoadKeyResult(
    val exists: Boolean,
    val publicKey: String? = null,
    val algorithm: Int? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("exists", exists)
            if (publicKey != null) {
                put("publicKey", publicKey)
            }
            if (algorithm != null) {
                put("algorithm", algorithm)
            }
        }
    }
}

/**
 * Result of the getInfo method.
 *
 * @property version Protocol version
 * @property deviceName Device name
 * @property hasStrongBox Whether StrongBox is available
 * @property hasBiometrics Whether biometrics are available and enrolled
 * @property credentialCount Number of stored credentials
 */
data class GetInfoResult(
    val version: String,
    val deviceName: String,
    val hasStrongBox: Boolean,
    val hasBiometrics: Boolean,
    val credentialCount: Int,
    /** Advertised COSE algorithms; go-xkms reads this as `supportedAlgorithms`. */
    val supportedAlgorithms: List<Int> = CoseAlgorithms.SUPPORTED,
    /** Upper bound on stored credentials, reported to go-xkms as `maxCredentials`. */
    val maxCredentials: Int = DEFAULT_MAX_CREDENTIALS
) {
    /**
     * Serializes to go-xkms's `GetInfoResult` (`pairing/protocol.go`), which
     * needs `supportedAlgorithms`, `maxCredentials` and `currentCredentials`.
     * The `hasStrongBox`/`hasBiometrics`/`credentialCount` keys are the legacy
     * Android spelling and stay for older peers.
     */
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("version", version)
            put("deviceName", deviceName)
            put("supportedAlgorithms", org.json.JSONArray(supportedAlgorithms))
            put("maxCredentials", maxCredentials)
            put("currentCredentials", credentialCount)
            put("hasStrongBox", hasStrongBox)
            put("hasBiometrics", hasBiometrics)
            put("credentialCount", credentialCount)
        }
    }

    companion object {
        /** No hard Keystore limit exists; this is the advertised ceiling. */
        const val DEFAULT_MAX_CREDENTIALS = 100
    }
}

/**
 * Exception thrown for protocol errors.
 */
class ProtocolException(
    message: String,
    cause: Throwable? = null,
    val errorCode: Int = ErrorCodes.INTERNAL_ERROR
) : Exception(message, cause)

/**
 * COSE algorithm identifiers.
 */
object CoseAlgorithms {
    const val ES256 = -7      // ECDSA w/ SHA-256
    const val ES384 = -35     // ECDSA w/ SHA-384
    const val ES512 = -36     // ECDSA w/ SHA-512
    const val EDDSA = -8      // EdDSA
    const val RS256 = -257    // RSASSA-PKCS1-v1_5 w/ SHA-256
    const val RS384 = -258    // RSASSA-PKCS1-v1_5 w/ SHA-384
    const val RS512 = -259    // RSASSA-PKCS1-v1_5 w/ SHA-512

    // Symmetric (COSE/IANA registry): AES-GCM content + HMAC MAC algorithms.
    const val A128GCM = 1     // AES-GCM 128
    const val A192GCM = 2     // AES-GCM 192
    const val A256GCM = 3     // AES-GCM 256
    const val HMAC_256 = 5    // HMAC w/ SHA-256
    const val HMAC_384 = 6    // HMAC w/ SHA-384
    const val HMAC_512 = 7    // HMAC w/ SHA-512

    /**
     * Returns true if the algorithm is supported.
     */
    fun isSupported(algorithm: Int): Boolean {
        return algorithm in setOf(ES256, ES384, ES512, RS256)
    }

    /**
     * Returns the algorithm name string for a COSE algorithm identifier.
     */
    fun getAlgorithmName(algorithm: Int): String {
        return when (algorithm) {
            ES256 -> "ES256"
            ES384 -> "ES384"
            ES512 -> "ES512"
            EDDSA -> "EdDSA"
            RS256 -> "RS256"
            RS384 -> "RS384"
            RS512 -> "RS512"
            A128GCM -> "AES-128"
            A192GCM -> "AES-192"
            A256GCM -> "AES-256"
            HMAC_256 -> "HMAC-SHA256"
            HMAC_384 -> "HMAC-SHA384"
            HMAC_512 -> "HMAC-SHA512"
            else -> throw ProtocolException(
                "Unknown algorithm: $algorithm",
                errorCode = ErrorCodes.INVALID_ALGORITHM
            )
        }
    }

    /**
     * Resolves an algorithm identifier received on the wire to its COSE integer.
     *
     * The go-xkms pairing contract sends `algorithm` as a name string (e.g.
     * "ES256", "AES-256", "HMAC-SHA256"); base/legacy callers may send the COSE
     * integer (as a number or numeric string). Both forms are accepted.
     */
    /** Algorithms this authenticator advertises to a peer. */
    val SUPPORTED: List<Int> = listOf(ES256, ES384, ES512, RS256, RS384, RS512)

    fun fromName(value: String): Int {
        value.trim().toIntOrNull()?.let { return it }
        return when (value.trim().uppercase().replace("_", "-")) {
            "ES256" -> ES256
            "ES384" -> ES384
            "ES512" -> ES512
            "EDDSA" -> EDDSA
            "RS256" -> RS256
            "RS384" -> RS384
            "RS512" -> RS512
            "AES-128", "AES128", "A128GCM", "AES128-GCM", "AES-128-GCM" -> A128GCM
            "AES-192", "AES192", "A192GCM", "AES192-GCM", "AES-192-GCM" -> A192GCM
            "AES-256", "AES256", "A256GCM", "AES256-GCM", "AES-256-GCM" -> A256GCM
            "HMAC-SHA256", "HMAC256", "HS256" -> HMAC_256
            "HMAC-SHA384", "HMAC384", "HS384" -> HMAC_384
            "HMAC-SHA512", "HMAC512", "HS512" -> HMAC_512
            else -> throw ProtocolException(
                "Unknown algorithm: $value",
                errorCode = ErrorCodes.INVALID_ALGORITHM
            )
        }
    }

    /**
     * Returns the key size in bits for a COSE algorithm.
     */
    fun getKeySizeBits(algorithm: Int): Int {
        return when (algorithm) {
            ES256 -> 256
            ES384 -> 384
            ES512 -> 521
            RS256 -> 2048
            RS384 -> 3072
            RS512 -> 4096
            else -> throw ProtocolException(
                "Unknown algorithm: $algorithm",
                errorCode = ErrorCodes.INVALID_ALGORITHM
            )
        }
    }

    /**
     * Returns the curve name for an EC algorithm.
     */
    fun getCurveName(algorithm: Int): String {
        return when (algorithm) {
            ES256 -> "secp256r1"
            ES384 -> "secp384r1"
            ES512 -> "secp521r1"
            else -> throw ProtocolException(
                "Unsupported algorithm: $algorithm",
                errorCode = ErrorCodes.INVALID_ALGORITHM
            )
        }
    }
}

// ============================================================
// Extended protocol message types for local.* methods
// ============================================================

/**
 * Method name constants for the extended protocol.
 */
object MethodNames {
    // Original methods (unnamespaced for backward compat)
    const val GENERATE_KEY = "generateKey"
    const val SIGN = "sign"
    const val DELETE_KEY = "deleteKey"
    const val LOAD_KEY = "loadKey"
    const val GET_INFO = "getInfo"
    const val PING = "ping"
    const val LIST_KEYS = "listKeys"

    // Extended local.* methods (laptop -> phone)
    const val LOCAL_GENERATE_KEY = "local.generateKey"
    const val LOCAL_SIGN = "local.sign"
    const val LOCAL_DECRYPT = "local.decrypt"
    const val LOCAL_SYMMETRIC_ENCRYPT = "local.symmetricEncrypt"
    const val LOCAL_SYMMETRIC_DECRYPT = "local.symmetricDecrypt"
    const val LOCAL_HMAC = "local.hmac"
    const val LOCAL_ECDH = "local.ecdh"
    const val LOCAL_GET_PUBLIC_KEY = "local.getPublicKey"
    const val LOCAL_LIST_KEYS = "local.listKeys"
    const val LOCAL_GET_KEY_INFO = "local.getKeyInfo"
    const val LOCAL_DELETE_KEY = "local.deleteKey"
    const val LOCAL_SET_KEY_POLICY = "local.setKeyPolicy"
    const val LOCAL_ATTEST_KEY = "local.attestKey"
    const val LOCAL_ATTEST_DEVICE = "local.attestDevice"
    const val LOCAL_VERIFY_USER = "local.verifyUser"
    const val LOCAL_GET_CAPABILITIES = "local.getCapabilities"
    const val LOCAL_LIST_FIDO2_CREDENTIALS = "local.listFido2Credentials"
    const val LOCAL_SIGN_FIDO2_ASSERTION = "local.signFido2Assertion"

    // Remote methods (phone -> laptop via xkmsd bridge)
    const val REMOTE_LIST_BACKENDS = "remote.listBackends"
    const val REMOTE_LIST_KEYS = "remote.listKeys"
    const val REMOTE_GET_PUBLIC_KEY = "remote.getPublicKey"
    const val REMOTE_SIGN = "remote.sign"
    const val REMOTE_VERIFY = "remote.verify"
    const val REMOTE_ENCRYPT = "remote.encrypt"
    const val REMOTE_DECRYPT = "remote.decrypt"
    const val REMOTE_DERIVE_KEY = "remote.deriveKey"
    const val REMOTE_GENERATE_KEY = "remote.generateKey"
    const val REMOTE_GET_KEY_INFO = "remote.getKeyInfo"
    const val REMOTE_DELETE_KEY = "remote.deleteKey"
    const val REMOTE_ATTEST_KEY = "remote.attestKey"
    const val REMOTE_ATTEST_DEVICE = "remote.attestDevice"

    // Pairing confirmation (laptop -> phone)
    const val PAIRING_CONFIRM = "pairing.confirm"

    // Notifications (phone -> laptop, fire-and-forget)
    const val LOCAL_BIOMETRIC_PENDING = "local.biometricPending"

    // IDevID Certificate Exchange Methods (local.* - laptop/phone CA exchange)
    const val LOCAL_GET_CA_BUNDLE = "local.getCABundle"
    const val LOCAL_GET_IDEVID_CERTIFICATE = "local.getIDevIDCertificate"
    const val LOCAL_REQUEST_IDEVID_ISSUANCE = "local.requestIDevIDIssuance"
    const val LOCAL_GENERATE_IDEVID_CSR = "local.generateIDevIDCSR"
    const val LOCAL_STORE_IDEVID_CERTIFICATE = "local.storeIDevIDCertificate"

    // Android-native device enrollment (local.* - desktop/xkms is the CA,
    // this phone is the enrollee). The TCG family below cannot serve this
    // direction: it is specified in TPM2 primitives -- an endorsement key, a
    // TPMT_PUBLIC IAK, a credential activation -- and Android has none of them.
    const val LOCAL_GET_DEVICE_ENROLLMENT_REQUEST = "local.getDeviceEnrollmentRequest"
    const val LOCAL_STORE_DEVICE_CREDENTIAL = "local.storeDeviceCredential"

    // TCG-CSR-IDEVID Attestation Enrollment Methods
    // These methods support TPM2-based device identity enrollment following the
    // TCG specification for Initial Device Identifier (IDevID) certificates.
    const val LOCAL_GET_TCG_CSR_IDEVID = "local.getTCGCSRIDevID"
    const val LOCAL_ACTIVATE_CREDENTIAL = "local.activateCredential"
    const val LOCAL_GET_ATTESTATION_QUOTE = "local.getAttestationQuote"
    const val LOCAL_GET_IAK_PUBLIC_KEY = "local.getIAKPublicKey"
    const val LOCAL_STORE_ENROLLMENT_CERTS = "local.storeEnrollmentCerts"

    // TCG-CSR-IDEVID enrollment driven from this phone (phone -> desktop).
    //
    // The namespace names the enrollee, not the sender: `local.*` asks the
    // recipient of the message to enrol, `remote.*` asks the desktop to. When
    // this phone is the Certificate Authority the desktop is the enrollee, so
    // the ceremony is `remote.*` throughout. The desktop's bridge routes only
    // these four; the `local.*` twins above are the other direction, where the
    // desktop is the CA and the phone enrols.
    //
    // There is deliberately no remote.getIAKPublicKey or
    // remote.generateIDevIDCSR: both public keys arrive inside the
    // remote.getTCGCSRIDevID result, which is what the TCG ceremony specifies.
    const val REMOTE_GET_TCG_CSR_IDEVID = "remote.getTCGCSRIDevID"
    const val REMOTE_ACTIVATE_CREDENTIAL = "remote.activateCredential"
    const val REMOTE_GET_ATTESTATION_QUOTE = "remote.getAttestationQuote"
    const val REMOTE_STORE_ENROLLMENT_CERTS = "remote.storeEnrollmentCerts"

    // OATH methods (laptop -> phone OATH credential management)
    const val LOCAL_OATH_LIST = "local.oathList"
    const val LOCAL_OATH_GENERATE = "local.oathGenerate"
    const val LOCAL_OATH_ADD = "local.oathAdd"
    const val LOCAL_OATH_REMOVE = "local.oathRemove"

    // OATH remote methods (phone -> laptop sync)
    const val REMOTE_OATH_ADD = "remote.oathAdd"
    const val REMOTE_OATH_GENERATE = "remote.oathGenerate"

    // Sync methods (laptop <-> phone bidirectional sync)
    const val LOCAL_SYNC_TRUST_STORE = "local.syncTrustStore"
    const val LOCAL_SYNC_OATH = "local.syncOATH"
    const val LOCAL_SYNC_PASSWORDS = "local.syncPasswords"
    const val LOCAL_SYNC_STATUS = "local.syncStatus"
    const val REMOTE_SYNC_TRUST_STORE = "remote.syncTrustStore"
    const val REMOTE_SYNC_OATH = "remote.syncOATH"
    const val REMOTE_SYNC_PASSWORDS = "remote.syncPasswords"
    const val REMOTE_SYNC_ALL = "remote.syncAll"
    const val REMOTE_SYNC_STATUS = "remote.syncStatus"

    // Backup methods
    const val LOCAL_CREATE_BACKUP = "local.createBackup"
    const val LOCAL_RESTORE_BACKUP = "local.restoreBackup"
    const val REMOTE_CREATE_BACKUP = "remote.createBackup"
    const val REMOTE_RESTORE_BACKUP = "remote.restoreBackup"
    const val REMOTE_LIST_BACKUPS = "remote.listBackups"

    // Key-sharing methods
    const val LOCAL_SHARE_PUBLIC_KEY = "local.sharePublicKey"
    const val LOCAL_SHARE_SYMMETRIC = "local.shareSymmetric"
    const val LOCAL_IMPORT_SHARED_KEY = "local.importSharedKey"
    const val REMOTE_SHARE_PUBLIC_KEY = "remote.sharePublicKey"
    const val REMOTE_SHARE_SYMMETRIC = "remote.shareSymmetric"
    const val REMOTE_IMPORT_SHARED_KEY = "remote.importSharedKey"

    // Co-signing methods (phone <-> phone via BLE)
    const val COSIGN_REQUEST = "cosign.request"
    const val COSIGN_RESPONSE = "cosign.response"

    // PIN management methods (laptop -> phone)
    const val LOCAL_PIN_VERIFY = "local.pinVerify"
    const val LOCAL_PIN_STATUS = "local.pinStatus"
    const val LOCAL_PIN_SET = "local.pinSet"
    const val LOCAL_PIN_CHANGE = "local.pinChange"
    const val LOCAL_PIN_RESET_LOCKOUT = "local.pinResetLockout"

    // PIV methods (laptop -> phone)
    const val LOCAL_PIV_GENERATE_KEY = "local.pivGenerateKey"
    const val LOCAL_PIV_IMPORT_CERT = "local.pivImportCert"
    const val LOCAL_PIV_LIST_SLOTS = "local.pivListSlots"
    const val LOCAL_PIV_SIGN = "local.pivSign"
    const val LOCAL_PIV_GET_CERT = "local.pivGetCert"

    // PIV remote methods (phone -> laptop)
    const val REMOTE_PIV_LIST_SLOTS = "remote.pivListSlots"
    const val REMOTE_PIV_SIGN = "remote.pivSign"
    const val REMOTE_PIV_GET_CERT = "remote.pivGetCert"
}

/**
 * Key type constants.
 */
object KeyTypes {
    const val FIDO2 = "fido2"
    const val TLS = "tls"
    const val SIGNING = "signing"
    const val ENCRYPTION = "encryption"
    const val SECRET = "secret"
    const val HMAC = "hmac"
    const val CA = "ca"
    const val ATTESTATION = "attestation"

    /**
     * The key type implied by a COSE algorithm, used when the peer omits
     * `keyType`. go-xkms has no such field, so its requests carry only an
     * algorithm and the type has to be inferred.
     */
    fun forAlgorithm(algorithm: Int): String = when (algorithm) {
        CoseAlgorithms.A128GCM, CoseAlgorithms.A192GCM, CoseAlgorithms.A256GCM -> SECRET
        CoseAlgorithms.HMAC_256, CoseAlgorithms.HMAC_384, CoseAlgorithms.HMAC_512 -> HMAC
        else -> SIGNING
    }
}

/**
 * Public key export format constants.
 */
object ExportFormats {
    const val DER = "der"
    const val PEM = "pem"
    const val SSH = "ssh"
    const val COSE = "cose"
}

/**
 * Parameters for local.generateKey method.
 *
 * Extends the original GenerateKeyParams with key type and label.
 */
data class LocalGenerateKeyParams(
    val keyId: String,
    val keyType: String,
    val algorithm: Int,
    val label: String,
    val requireUserVerification: Boolean = true,
    val preferStrongBox: Boolean = true,
    val shareable: Boolean = false,
    /** When true, generate a software-backed (exportable) key instead of a hardware Keystore key. */
    val exportable: Boolean = false,
    // FIDO2-specific
    val rpId: String? = null,
    val rpName: String? = null,
    val userId: String? = null,
    val userName: String? = null,
    val userDisplayName: String? = null,
    val isDiscoverable: Boolean = false
) {
    companion object {
        fun fromJson(params: JSONObject): LocalGenerateKeyParams {
            val keyId = params.getStringOrNull("keyId")
                ?: throw ProtocolException("Missing 'keyId' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            // go-xkms sends `algorithm` as a name string ("ES256", "AES-256",
            // "HMAC-SHA256"); base callers may send the COSE integer. Accept both.
            val algoRaw = params.opt("algorithm")
            val algorithm = when (algoRaw) {
                is Number -> algoRaw.toInt()
                is String -> if (algoRaw.isBlank()) 0 else CoseAlgorithms.fromName(algoRaw)
                else -> 0
            }
            if (algorithm == 0) {
                throw ProtocolException("Missing 'algorithm' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            }

            // go-xkms LocalGenerateKeyParams has no `keyType` field, so it must
            // be optional: derive it from the algorithm when absent. Requiring
            // it made every xkmsd phone-backend key creation fail.
            val keyType = params.getStringOrNull("keyType")
                ?: KeyTypes.forAlgorithm(algorithm)

            return LocalGenerateKeyParams(
                keyId = keyId,
                keyType = keyType,
                algorithm = algorithm,
                label = params.optString("label", keyId),
                requireUserVerification = params.optBoolean("requireUserVerification", true),
                preferStrongBox = params.optBoolean("preferStrongBox", true),
                shareable = params.optBoolean("shareable", false),
                exportable = params.optBoolean("exportable", false),
                rpId = params.getStringOrNull("rpId"),
                rpName = params.getStringOrNull("rpName"),
                userId = params.getStringOrNull("userId"),
                userName = params.getStringOrNull("userName"),
                userDisplayName = params.getStringOrNull("userDisplayName"),
                isDiscoverable = params.optBoolean("isDiscoverable", false)
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("keyType", keyType)
            put("algorithm", algorithm)
            put("label", label)
            put("requireUserVerification", requireUserVerification)
            put("preferStrongBox", preferStrongBox)
            put("shareable", shareable)
            put("exportable", exportable)
            rpId?.let { put("rpId", it) }
            rpName?.let { put("rpName", it) }
            userId?.let { put("userId", it) }
            userName?.let { put("userName", it) }
            userDisplayName?.let { put("userDisplayName", it) }
            put("isDiscoverable", isDiscoverable)
        }
    }
}

/**
 * Result of local.generateKey method.
 */
data class LocalGenerateKeyResult(
    val keyId: String,
    val publicKey: String,         // Base64-encoded DER public key
    val publicKeyCose: String?,    // Base64-encoded COSE public key (for FIDO2)
    val algorithm: String,
    val keySizeBits: Int,
    val strongBoxBacked: Boolean,
    val softwareBacked: Boolean = false
) {
    /**
     * Serializes to the go-xkms wire contract (`LocalGenerateKeyResult`):
     * `publicKeyDer`/`publicKeyCose` (omitted when empty) and a
     * `securityLevel` of "software", "strongbox", or "tee".
     */
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            if (publicKey.isNotEmpty()) put("publicKeyDer", publicKey)
            publicKeyCose?.let { put("publicKeyCose", it) }
            put("algorithm", algorithm)
            put("keySizeBits", keySizeBits)
            put(
                "securityLevel",
                when {
                    softwareBacked -> "software"
                    strongBoxBacked -> "strongbox"
                    else -> "tee"
                }
            )
        }
    }
}

/**
 * Parameters for local.sign method (extended).
 */
data class LocalSignParams(
    val keyId: String,
    val data: String,              // Base64-encoded data to sign
    val algorithm: String,         // "ES256", "ES384", "RS256", etc.
    val userVerificationRequired: Boolean = true
) {
    companion object {
        fun fromJson(params: JSONObject): LocalSignParams {
            return LocalSignParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                data = params.getStringOrNull("data")
                    ?: throw ProtocolException("Missing 'data'", errorCode = ErrorCodes.INVALID_PARAMS),
                // go-xkms LocalSignParams marks `algorithm` omitempty: it is an
                // optional override, defaulting to the key's own algorithm.
                algorithm = params.getStringOrNull("algorithm") ?: "",
                userVerificationRequired = params.optBoolean("userVerificationRequired", true)
            )
        }
    }

    fun getDataBytes(): ByteArray = Base64.getDecoder().decode(data)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("data", data)
            put("algorithm", algorithm)
            put("userVerificationRequired", userVerificationRequired)
        }
    }
}

/**
 * Result of local.sign method.
 */
data class LocalSignResult(
    val signature: String,         // Base64-encoded signature
    val algorithm: String,
    val userVerified: Boolean
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("signature", signature)
            put("algorithm", algorithm)
            put("userVerified", userVerified)
        }
    }
}

/**
 * Parameters for local.decrypt (RSA decryption).
 */
data class LocalDecryptParams(
    val keyId: String,
    val ciphertext: String         // Base64-encoded ciphertext
) {
    companion object {
        fun fromJson(params: JSONObject): LocalDecryptParams {
            return LocalDecryptParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                ciphertext = params.getStringOrNull("ciphertext")
                    ?: throw ProtocolException("Missing 'ciphertext'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }

    fun getCiphertextBytes(): ByteArray = Base64.getDecoder().decode(ciphertext)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("ciphertext", ciphertext)
        }
    }
}

/**
 * Result of local.decrypt.
 */
data class LocalDecryptResult(
    val plaintext: String          // Base64-encoded plaintext
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("plaintext", plaintext)
        }
    }
}

/**
 * Parameters for local.symmetricEncrypt / local.symmetricDecrypt.
 */
data class LocalSymmetricParams(
    val keyId: String,
    val data: String,              // Base64-encoded input data
    val aad: String? = null        // Base64-encoded additional authenticated data
) {
    companion object {
        fun fromJson(params: JSONObject): LocalSymmetricParams {
            return LocalSymmetricParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                // go-xkms names these `plaintext` (encrypt) and `ciphertext`
                // (decrypt); `data` is this app's older name, still accepted so
                // an older peer keeps working.
                data = params.getStringOrNull("plaintext")
                    ?: params.getStringOrNull("ciphertext")
                    ?: params.getStringOrNull("data")
                    ?: throw ProtocolException(
                        "Missing 'plaintext'/'ciphertext'", errorCode = ErrorCodes.INVALID_PARAMS
                    ),
                aad = params.getStringOrNull("aad")
            )
        }
    }

    fun getDataBytes(): ByteArray = Base64.getDecoder().decode(data)
    fun getAadBytes(): ByteArray? = aad?.let { Base64.getDecoder().decode(it) }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("data", data)
            aad?.let { put("aad", it) }
        }
    }
}

/**
 * Result of local.symmetricEncrypt / local.symmetricDecrypt.
 */
data class LocalSymmetricResult(
    val data: String,              // Base64-encoded output data
    /**
     * Wire field name for the payload. go-xkms reads `ciphertext` from an
     * encrypt result and `plaintext` from a decrypt result; `data` is emitted
     * alongside so an older peer keeps working.
     */
    val payloadField: String = FIELD_CIPHERTEXT
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put(payloadField, data)
            put("data", data)
        }
    }

    companion object {
        /** Encrypt results carry `ciphertext`. */
        const val FIELD_CIPHERTEXT = "ciphertext"

        /** Decrypt results carry `plaintext`. */
        const val FIELD_PLAINTEXT = "plaintext"
    }
}

/**
 * Parameters for local.hmac.
 */
data class LocalHMACParams(
    val keyId: String,
    val data: String               // Base64-encoded data to authenticate
) {
    companion object {
        fun fromJson(params: JSONObject): LocalHMACParams {
            return LocalHMACParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                data = params.getStringOrNull("data")
                    ?: throw ProtocolException("Missing 'data'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }

    fun getDataBytes(): ByteArray = Base64.getDecoder().decode(data)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("data", data)
        }
    }
}

/**
 * Result of local.hmac.
 */
data class LocalHMACResult(
    val mac: String                // Base64-encoded HMAC
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("mac", mac)
        }
    }
}

/**
 * Parameters for local.ecdh.
 */
data class LocalECDHParams(
    val keyId: String,
    val peerPublicKey: String      // Base64-encoded DER peer public key
) {
    companion object {
        fun fromJson(params: JSONObject): LocalECDHParams {
            return LocalECDHParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                peerPublicKey = params.getStringOrNull("peerPublicKey")
                    ?: throw ProtocolException("Missing 'peerPublicKey'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }

    fun getPeerPublicKeyBytes(): ByteArray = Base64.getDecoder().decode(peerPublicKey)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("peerPublicKey", peerPublicKey)
        }
    }
}

/**
 * Result of local.ecdh.
 */
data class LocalECDHResult(
    val sharedSecret: String       // Base64-encoded shared secret
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("sharedSecret", sharedSecret)
        }
    }
}

/**
 * Parameters for local.getPublicKey.
 */
data class LocalGetPublicKeyParams(
    val keyId: String,
    val format: String = ExportFormats.DER  // "der", "pem", "ssh", "cose"
) {
    companion object {
        fun fromJson(params: JSONObject): LocalGetPublicKeyParams {
            return LocalGetPublicKeyParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                format = params.optString("format", ExportFormats.DER)
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("format", format)
        }
    }
}

/**
 * Result of local.getPublicKey.
 */
data class LocalGetPublicKeyResult(
    val publicKey: String,         // Base64-encoded (for DER/COSE) or text (for PEM/SSH)
    val format: String,
    val algorithm: String
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("publicKey", publicKey)
            put("format", format)
            put("algorithm", algorithm)
        }
    }
}

/**
 * Parameters for local.listKeys (extended).
 */
data class LocalListKeysParams(
    val keyType: String? = null,   // Filter by key type (null = all)
    val source: String? = null     // Filter by source (null = all)
) {
    companion object {
        fun fromJson(params: JSONObject?): LocalListKeysParams {
            return LocalListKeysParams(
                keyType = params?.getStringOrNull("keyType"),
                source = params?.getStringOrNull("source")
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            keyType?.let { put("keyType", it) }
            source?.let { put("source", it) }
        }
    }
}

/**
 * Key info for list results.
 */
data class KeyInfo(
    val keyId: String,
    val keyType: String,
    val algorithm: String,
    val label: String,
    val keySizeBits: Int,
    val strongBoxBacked: Boolean,
    val shareable: Boolean,
    val source: String,
    val useCount: Long,
    val createdAt: Long,
    val lastUsedAt: Long,
    // FIDO2 fields
    val rpId: String? = null,
    val rpName: String? = null,
    val userName: String? = null,
    val userDisplayName: String? = null,
    val isDiscoverable: Boolean = false,
    val signCount: Long = 0
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("keyType", keyType)
            put("algorithm", algorithm)
            put("label", label)
            put("keySizeBits", keySizeBits)
            put("strongBoxBacked", strongBoxBacked)
            put("shareable", shareable)
            put("source", source)
            put("useCount", useCount)
            put("createdAt", createdAt)
            put("lastUsedAt", lastUsedAt)
            rpId?.let { put("rpId", it) }
            rpName?.let { put("rpName", it) }
            userName?.let { put("userName", it) }
            userDisplayName?.let { put("userDisplayName", it) }
            put("isDiscoverable", isDiscoverable)
            put("signCount", signCount)
        }
    }
}

/**
 * Result of local.listKeys.
 */
data class LocalListKeysResult(
    val keys: List<KeyInfo>,
    val count: Int
) {
    fun toJson(): JSONObject {
        val keysArray = JSONArray()
        for (key in keys) {
            keysArray.put(key.toJson())
        }
        return JSONObject().apply {
            put("keys", keysArray)
            put("count", count)
        }
    }
}

/**
 * Parameters for local.getKeyInfo.
 */
data class LocalGetKeyInfoParams(
    val keyId: String
) {
    companion object {
        fun fromJson(params: JSONObject): LocalGetKeyInfoParams {
            return LocalGetKeyInfoParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }
}

/**
 * Parameters for local.setKeyPolicy.
 */
data class LocalSetKeyPolicyParams(
    val keyId: String,
    val shareable: Boolean? = null
) {
    companion object {
        fun fromJson(params: JSONObject): LocalSetKeyPolicyParams {
            return LocalSetKeyPolicyParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                shareable = if (params.has("shareable")) params.getBoolean("shareable") else null
            )
        }
    }
}

/**
 * Parameters for local.attestKey.
 */
data class LocalAttestKeyParams(
    val keyId: String,
    val nonce: String              // Base64-encoded challenge nonce
) {
    companion object {
        fun fromJson(params: JSONObject): LocalAttestKeyParams {
            return LocalAttestKeyParams(
                keyId = params.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId'", errorCode = ErrorCodes.INVALID_PARAMS),
                nonce = params.getStringOrNull("nonce")
                    ?: throw ProtocolException("Missing 'nonce'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }

    fun getNonceBytes(): ByteArray = Base64.getDecoder().decode(nonce)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("nonce", nonce)
        }
    }
}

/**
 * Result of local.attestKey.
 */
data class LocalAttestKeyResult(
    val certificateChain: List<String>,  // Base64-encoded X.509 certificates
    val securityLevel: String,           // "tee", "strongbox", "software"
    val nonce: String                    // Echo of the challenge nonce
) {
    fun toJson(): JSONObject {
        val chainArray = JSONArray()
        for (cert in certificateChain) {
            chainArray.put(cert)
        }
        return JSONObject().apply {
            put("certificateChain", chainArray)
            put("securityLevel", securityLevel)
            put("nonce", nonce)
        }
    }
}

/**
 * Parameters for `local.attestDevice` — device attestation protocol **version 2**
 * (go-xkms#129).
 *
 * @property protocolVersion Always [AttestTranscript.PROTOCOL_VERSION]. A request
 *   carrying anything else is refused rather than answered at the older version.
 * @property nonce Base64-encoded 32-byte challenge, drawn by the desktop.
 * @property purpose `"pair"` on a first pairing, `"reattest"` on a reconnect or an
 *   explicit re-attest. Signed, so a signature gathered during pairing cannot
 *   satisfy a reconnect.
 *
 * ## The request deliberately carries no channel binding
 *
 * An earlier draft of version 2 sent the desktop's own `channelBinding` here for
 * diagnostics, with the spec forbidding the prover from echoing it. That was a
 * footgun: a 32-byte field of that name reads as "sign this" when it means the
 * exact opposite, and a prover that echoed it would produce a signature the
 * verifier **accepts** — the relayed signature verifies even though the phone
 * never committed to the session it was actually on. The verifier cannot detect
 * the mistake.
 *
 * The field was removed from the wire (go-xkms#129 addendum) so that echoing is
 * structurally impossible rather than merely forbidden. The binding is derived
 * locally, from this device's own Noise session, and never received.
 */
data class LocalAttestDeviceParams(
    val protocolVersion: Int,
    val nonce: String,
    val purpose: String
) {
    companion object {
        fun fromJson(params: JSONObject): LocalAttestDeviceParams {
            val version = params.optInt("protocolVersion", 0)
            if (version != AttestTranscript.PROTOCOL_VERSION) {
                throw ProtocolException(
                    "Device attestation protocol version ${AttestTranscript.PROTOCOL_VERSION} " +
                        "is required; this request asked for " +
                        if (version == 0) "none" else "$version",
                    errorCode = ErrorCodes.ATTEST_PROTOCOL_DOWNGRADE
                )
            }

            val purpose = params.getStringOrNull("purpose")
                ?: throw ProtocolException("Missing 'purpose'", errorCode = ErrorCodes.INVALID_PARAMS)
            if (purpose != AttestTranscript.PURPOSE_PAIR && purpose != AttestTranscript.PURPOSE_REATTEST) {
                throw ProtocolException(
                    "Unknown attestation purpose '$purpose'",
                    errorCode = ErrorCodes.INVALID_PARAMS
                )
            }

            return LocalAttestDeviceParams(
                protocolVersion = version,
                nonce = params.getStringOrNull("nonce")
                    ?: throw ProtocolException("Missing 'nonce'", errorCode = ErrorCodes.INVALID_PARAMS),
                purpose = purpose
            )
        }
    }

    /**
     * The 32-byte challenge, refusing any other length.
     *
     * A short nonce is a weak challenge, and the transcript layout is fixed
     * width — accepting one would produce a signature over bytes the desktop
     * cannot reconstruct.
     */
    fun getNonceBytes(): ByteArray {
        val bytes = Base64.getDecoder().decode(nonce)
        if (bytes.size != AttestTranscript.BINDING_SIZE) {
            throw ProtocolException(
                "'nonce' must be ${AttestTranscript.BINDING_SIZE} bytes, got ${bytes.size}",
                errorCode = ErrorCodes.INVALID_PARAMS
            )
        }
        return bytes
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("protocolVersion", protocolVersion)
            put("nonce", nonce)
            put("purpose", purpose)
        }
    }
}

/**
 * Result of `local.attestDevice` — device attestation protocol **version 2**
 * (go-xkms#129).
 *
 * Three things travel together and all three are required for the desktop to
 * accept: [certificateChain] proves the Device Attestation Key lives in hardware
 * on a verified-boot device, [signature] proves the exchange is live, and the
 * fingerprint the desktop derives from `certificateChain[0]` says which device
 * this is.
 *
 * The desktop reads every security claim out of the **signed attestation
 * extension** in the leaf, never from the sibling JSON. [securityLevel],
 * [bootState], [deviceLocked] and the `verifiedBoot*` fields are carried for
 * display, and the echoed [nonce] and [purpose] are advisory — the verifier
 * rebuilds the transcript from what it asked for, so nothing here is trusted on
 * this device's word.
 *
 * @property protocolVersion Always [AttestTranscript.PROTOCOL_VERSION].
 * @property format Attestation format, always "android-keystore".
 * @property certificateChain Base64-encoded X.509 chain, leaf first; `[0]` is the
 *   Device Attestation Key.
 * @property securityLevel Security level: "software", "tee", or "strongbox".
 * @property nonce Echoed challenge nonce.
 * @property purpose Echoed purpose, "pair" or "reattest".
 * @property signature Base64 ASN.1 DER ECDSA over the [AttestTranscript.build]
 *   transcript.
 * @property signatureAlgorithm Always "ES256".
 * @property bootState Boot state: 0=VERIFIED, 1=SELF_SIGNED, 2=UNVERIFIED, 3=FAILED.
 * @property deviceLocked Whether bootloader is locked.
 * @property verifiedBootKey Base64-encoded public key hash.
 * @property verifiedBootHash Base64-encoded boot partition hash.
 */
data class LocalAttestDeviceResult(
    val protocolVersion: Int,
    val format: String,
    val certificateChain: List<String>,
    val securityLevel: String,
    val nonce: String,
    val purpose: String,
    val signature: String,
    val signatureAlgorithm: String,
    val bootState: Int,
    val deviceLocked: Boolean,
    val verifiedBootKey: String,
    val verifiedBootHash: String
) {
    fun toJson(): JSONObject {
        val chainArray = JSONArray()
        for (cert in certificateChain) {
            chainArray.put(cert)
        }
        return JSONObject().apply {
            put("protocolVersion", protocolVersion)
            put("format", format)
            put("certificateChain", chainArray)
            put("securityLevel", securityLevel)
            put("nonce", nonce)
            put("purpose", purpose)
            put("signature", signature)
            put("signatureAlgorithm", signatureAlgorithm)
            put("bootState", bootState)
            put("deviceLocked", deviceLocked)
            put("verifiedBootKey", verifiedBootKey)
            put("verifiedBootHash", verifiedBootHash)
        }
    }
}

/**
 * Parameters for `local.verifyUser` — on-demand user verification (owner ruling
 * 167, go-xkms `pkg/pairingproto/verify_user.go`).
 *
 * The desktop asks for proof that this phone's user was verified **now**, before
 * it mints a CTAP 2.1 `pinUvAuthToken` "via UV". Like `local.attestDevice` the
 * request carries no channel binding and no purpose: the binding is derived from
 * this device's own Noise session and the purpose is fixed to
 * [AttestTranscript.PURPOSE_VERIFY_USER].
 *
 * @property protocolVersion Always [AttestTranscript.PROTOCOL_VERSION].
 * @property nonce Base64-encoded 32-byte challenge, drawn by the desktop.
 */
data class LocalVerifyUserParams(
    val protocolVersion: Int,
    val nonce: String
) {
    companion object {
        /**
         * Parses and validates the params. Any version other than
         * [AttestTranscript.PROTOCOL_VERSION], and any nonce that is not 32
         * bytes of valid base64, is [ErrorCodes.INVALID_PARAMS].
         */
        fun fromJson(params: JSONObject): LocalVerifyUserParams {
            val version = params.optInt("protocolVersion", 0)
            if (version != AttestTranscript.PROTOCOL_VERSION) {
                throw ProtocolException(
                    "local.verifyUser requires protocolVersion ${AttestTranscript.PROTOCOL_VERSION}; " +
                        "this request asked for " + if (version == 0) "none" else "$version",
                    errorCode = ErrorCodes.INVALID_PARAMS
                )
            }
            val parsed = LocalVerifyUserParams(
                protocolVersion = version,
                nonce = params.getStringOrNull("nonce")
                    ?: throw ProtocolException("Missing 'nonce'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
            parsed.getNonceBytes()
            return parsed
        }
    }

    /** The 32-byte challenge, refusing any other length or undecodable text. */
    fun getNonceBytes(): ByteArray {
        val bytes = try {
            Base64.getDecoder().decode(nonce)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException("'nonce' is not valid base64", errorCode = ErrorCodes.INVALID_PARAMS)
        }
        if (bytes.size != AttestTranscript.BINDING_SIZE) {
            throw ProtocolException(
                "'nonce' must be ${AttestTranscript.BINDING_SIZE} bytes, got ${bytes.size}",
                errorCode = ErrorCodes.INVALID_PARAMS
            )
        }
        return bytes
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("protocolVersion", protocolVersion)
            put("nonce", nonce)
        }
    }
}

/**
 * Result of `local.verifyUser` — on-demand user verification (owner ruling 167).
 *
 * @property protocolVersion Always [AttestTranscript.PROTOCOL_VERSION].
 * @property certificateChain Base64-encoded X.509 chain of the User Verification
 *   Key, leaf first, root last. Sent in every result; the pairing record does
 *   not hold it.
 * @property signature Base64 ASN.1 DER ECDSA by the UVK over the
 *   [AttestTranscript.PURPOSE_VERIFY_USER] transcript, made behind a fresh
 *   Class 3 biometric.
 * @property signatureAlgorithm Always "ES256".
 */
data class LocalVerifyUserResult(
    val protocolVersion: Int,
    val certificateChain: List<String>,
    val signature: String,
    val signatureAlgorithm: String
) {
    companion object {
        fun fromJson(json: JSONObject): LocalVerifyUserResult {
            val chain = json.getJSONArray("certificateChain")
            return LocalVerifyUserResult(
                protocolVersion = json.getInt("protocolVersion"),
                certificateChain = List(chain.length()) { chain.getString(it) },
                signature = json.getString("signature"),
                signatureAlgorithm = json.getString("signatureAlgorithm")
            )
        }
    }

    fun toJson(): JSONObject {
        val chainArray = JSONArray()
        for (cert in certificateChain) {
            chainArray.put(cert)
        }
        return JSONObject().apply {
            put("protocolVersion", protocolVersion)
            put("certificateChain", chainArray)
            put("signature", signature)
            put("signatureAlgorithm", signatureAlgorithm)
        }
    }
}

/**
 * Parameters for remote.attestDevice - request laptop/desktop device attestation.
 *
 * @property nonce Base64-encoded 32-byte challenge nonce.
 */
data class RemoteAttestDeviceParams(
    val nonce: String
) {
    companion object {
        fun fromJson(params: JSONObject): RemoteAttestDeviceParams {
            return RemoteAttestDeviceParams(
                nonce = params.getStringOrNull("nonce")
                    ?: throw ProtocolException("Missing 'nonce'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }

    fun getNonceBytes(): ByteArray = Base64.getDecoder().decode(nonce)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("nonce", nonce)
        }
    }
}

/**
 * Result of remote.attestDevice - laptop/desktop device attestation.
 *
 * @property format Attestation format: "tpm2", "software", etc.
 * @property certificateChain Base64-encoded attestation certificate chain.
 * @property securityLevel Security level: "hardware" (TPM), "software".
 * @property nonce Echoed challenge nonce.
 * @property bootHashHex Platform boot hash for comparison.
 * @property bootStateVerified Whether secure boot was verified.
 * @property firmwareVersion TPM firmware version (if TPM2).
 */
data class RemoteAttestDeviceResult(
    val format: String,
    val certificateChain: List<String>,
    val securityLevel: String,
    val nonce: String,
    val bootHashHex: String?,
    val bootStateVerified: Boolean,
    val firmwareVersion: String?
) {
    companion object {
        fun fromJson(json: JSONObject): RemoteAttestDeviceResult {
            val chainArray = json.optJSONArray("certificateChain") ?: JSONArray()
            val certs = mutableListOf<String>()
            for (i in 0 until chainArray.length()) {
                certs.add(chainArray.getString(i))
            }
            return RemoteAttestDeviceResult(
                format = json.optString("format", "unknown"),
                certificateChain = certs,
                securityLevel = json.optString("securityLevel", "software"),
                nonce = json.optString("nonce", ""),
                bootHashHex = json.getStringOrNull("bootHashHex"),
                bootStateVerified = json.optBoolean("bootStateVerified", false),
                firmwareVersion = json.getStringOrNull("firmwareVersion")
            )
        }
    }

    fun toJson(): JSONObject {
        val chainArray = JSONArray()
        for (cert in certificateChain) {
            chainArray.put(cert)
        }
        return JSONObject().apply {
            put("format", format)
            put("certificateChain", chainArray)
            put("securityLevel", securityLevel)
            put("nonce", nonce)
            bootHashHex?.let { put("bootHashHex", it) }
            put("bootStateVerified", bootStateVerified)
            firmwareVersion?.let { put("firmwareVersion", it) }
        }
    }
}

/**
 * Result of local.getCapabilities.
 */
data class LocalGetCapabilitiesResult(
    val algorithms: List<String>,
    val keyTypes: List<String>,
    val hasStrongBox: Boolean,
    val hasBiometrics: Boolean,
    val supportsAttestation: Boolean,
    val supportsECDH: Boolean,
    val supportsSymmetric: Boolean,
    val supportsHMAC: Boolean,
    val maxKeys: Int,
    /** Reported to go-xkms as `version`. */
    val version: String = "",
    /** Reported to go-xkms as `deviceName`. */
    val deviceName: String = "",
    /** Reported to go-xkms as `currentKeyCount`. */
    val currentKeyCount: Int = 0,
    /** Export formats this device can produce; go-xkms `supportedFormats`. */
    val supportedFormats: List<String> = listOf(
        ExportFormats.DER, ExportFormats.PEM, ExportFormats.SSH, ExportFormats.COSE
    )
) {
    /**
     * Serializes to go-xkms's `LocalGetCapabilitiesResult`
     * (`pairing/protocol_local.go`), which reads `supportedAlgorithms`,
     * `strongBoxAvailable`, `attestationSupport`, `currentKeyCount`,
     * `supportedFormats`, `version` and `deviceName`. The original camelCase
     * keys remain for older Android peers.
     */
    fun toJson(): JSONObject {
        val algoArray = JSONArray()
        for (algo in algorithms) {
            algoArray.put(algo)
        }
        val typesArray = JSONArray()
        for (type in keyTypes) {
            typesArray.put(type)
        }
        val formatsArray = JSONArray()
        for (format in supportedFormats) {
            formatsArray.put(format)
        }
        return JSONObject().apply {
            put("version", version)
            put("deviceName", deviceName)
            put("supportedAlgorithms", algoArray)
            put("strongBoxAvailable", hasStrongBox)
            put("maxKeys", maxKeys)
            put("currentKeyCount", currentKeyCount)
            put("supportedFormats", formatsArray)
            put("attestationSupport", supportsAttestation)
            put("algorithms", algoArray)
            put("keyTypes", typesArray)
            put("hasStrongBox", hasStrongBox)
            put("hasBiometrics", hasBiometrics)
            put("supportsAttestation", supportsAttestation)
            put("supportsECDH", supportsECDH)
            put("supportsSymmetric", supportsSymmetric)
            put("supportsHMAC", supportsHMAC)
        }
    }
}

/**
 * Parameters for local.listFido2Credentials.
 *
 * @property rpId Relying party identifier to filter credentials.
 */
data class LocalListFido2CredentialsParams(
    val rpId: String
) {
    companion object {
        fun fromJson(params: JSONObject): LocalListFido2CredentialsParams {
            return LocalListFido2CredentialsParams(
                rpId = params.getStringOrNull("rpId")
                    ?: throw ProtocolException("Missing 'rpId'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("rpId", rpId)
        }
    }
}

/**
 * FIDO2 credential information for discovery results.
 *
 * @property credentialId Base64-encoded credential ID.
 * @property rpId Relying party identifier.
 * @property rpName Relying party display name.
 * @property userId Base64-encoded user handle.
 * @property userName User's account name.
 * @property userDisplayName User's display name.
 * @property isDiscoverable Whether this is a discoverable (resident) credential.
 * @property createdAt Timestamp when the credential was created.
 */
data class Fido2CredentialInfo(
    val credentialId: String,
    val rpId: String,
    val rpName: String?,
    val userId: String?,
    val userName: String?,
    val userDisplayName: String?,
    val isDiscoverable: Boolean,
    val createdAt: Long
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("credentialId", credentialId)
            put("rpId", rpId)
            rpName?.let { put("rpName", it) }
            userId?.let { put("userId", it) }
            userName?.let { put("userName", it) }
            userDisplayName?.let { put("userDisplayName", it) }
            put("isDiscoverable", isDiscoverable)
            put("createdAt", createdAt)
        }
    }
}

/**
 * Result of local.listFido2Credentials.
 *
 * @property credentials List of FIDO2 credential information.
 */
data class LocalListFido2CredentialsResult(
    val credentials: List<Fido2CredentialInfo>
) {
    fun toJson(): JSONObject {
        val credArray = JSONArray()
        for (cred in credentials) {
            credArray.put(cred.toJson())
        }
        return JSONObject().apply {
            put("credentials", credArray)
        }
    }
}

/**
 * Parameters for local.signFido2Assertion.
 *
 * @property credentialId Base64-encoded credential identifier.
 * @property clientDataHash Base64-encoded client data hash.
 * @property rpId Relying party identifier.
 * @property userVerificationRequired Whether UV is required.
 */
data class LocalSignFido2AssertionParams(
    val credentialId: String,
    val clientDataHash: String,
    val rpId: String,
    val userVerificationRequired: Boolean = true
) {
    companion object {
        fun fromJson(params: JSONObject): LocalSignFido2AssertionParams {
            return LocalSignFido2AssertionParams(
                credentialId = params.getStringOrNull("credentialId")
                    ?: throw ProtocolException("Missing 'credentialId'", errorCode = ErrorCodes.INVALID_PARAMS),
                clientDataHash = params.getStringOrNull("clientDataHash")
                    ?: throw ProtocolException("Missing 'clientDataHash'", errorCode = ErrorCodes.INVALID_PARAMS),
                rpId = params.getStringOrNull("rpId")
                    ?: throw ProtocolException("Missing 'rpId'", errorCode = ErrorCodes.INVALID_PARAMS),
                userVerificationRequired = params.optBoolean("userVerificationRequired", true)
            )
        }
    }

    fun getCredentialIdBytes(): ByteArray = Base64.getDecoder().decode(credentialId)
    fun getClientDataHashBytes(): ByteArray = Base64.getDecoder().decode(clientDataHash)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("credentialId", credentialId)
            put("clientDataHash", clientDataHash)
            put("rpId", rpId)
            put("userVerificationRequired", userVerificationRequired)
        }
    }
}

/**
 * Result of local.signFido2Assertion.
 *
 * @property authenticatorData Base64-encoded authenticator data.
 * @property signature Base64-encoded assertion signature.
 * @property userHandle Base64-encoded user handle.
 * @property signCount Updated signature counter.
 */
data class LocalSignFido2AssertionResult(
    val authenticatorData: String,
    val signature: String,
    val userHandle: String?,
    val signCount: Long
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("authenticatorData", authenticatorData)
            put("signature", signature)
            userHandle?.let { put("userHandle", it) }
            put("signCount", signCount)
        }
    }
}

// ============================================================
// Remote protocol message types for remote.* methods
// (phone -> laptop via xkmsd bridge)
// ============================================================

/**
 * Information about a xkmsd backend available on the laptop.
 */
data class RemoteBackendInfo(
    val name: String,
    val type: String,              // "tpm2", "pkcs11", "software", "awskms", etc.
    val hardwareBacked: Boolean,
    val signing: Boolean,
    val decryption: Boolean,
    val symmetricCrypto: Boolean,
    val keyAgreement: Boolean,
    val attestation: Boolean
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("name", name)
            put("type", type)
            put("hardwareBacked", hardwareBacked)
            put("signing", signing)
            put("decryption", decryption)
            put("symmetricCrypto", symmetricCrypto)
            put("keyAgreement", keyAgreement)
            put("attestation", attestation)
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteBackendInfo {
            return RemoteBackendInfo(
                name = obj.getString("name"),
                type = obj.getString("type"),
                hardwareBacked = obj.optBoolean("hardwareBacked", false),
                signing = obj.optBoolean("signing", false),
                decryption = obj.optBoolean("decryption", false),
                symmetricCrypto = obj.optBoolean("symmetricCrypto", false),
                keyAgreement = obj.optBoolean("keyAgreement", false),
                attestation = obj.optBoolean("attestation", false)
            )
        }
    }
}

/**
 * Result of remote.listBackends.
 */
data class RemoteListBackendsResult(
    val backends: List<RemoteBackendInfo>
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteListBackendsResult {
            val backendsArray = obj.getJSONArray("backends")
            val backends = (0 until backendsArray.length()).map {
                RemoteBackendInfo.fromJson(backendsArray.getJSONObject(it))
            }
            return RemoteListBackendsResult(backends = backends)
        }
    }

    fun toJson(): JSONObject {
        val arr = JSONArray()
        for (b in backends) {
            arr.put(b.toJson())
        }
        return JSONObject().apply {
            put("backends", arr)
        }
    }
}

/**
 * Parameters for remote.listKeys.
 */
data class RemoteListKeysParams(
    val backend: String,
    val algorithm: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            algorithm?.let { put("algorithm", it) }
        }
    }
}

/**
 * Information about a key on a xkmsd backend.
 */
data class RemoteKeyInfo(
    val keyId: String,
    val backend: String,
    val algorithm: String,
    val keySizeBits: Int,
    val label: String,
    val createdAt: Long
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("backend", backend)
            put("algorithm", algorithm)
            put("keySizeBits", keySizeBits)
            put("label", label)
            put("createdAt", createdAt)
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteKeyInfo {
            return RemoteKeyInfo(
                keyId = obj.getString("keyId"),
                backend = obj.getString("backend"),
                algorithm = obj.getString("algorithm"),
                keySizeBits = obj.optInt("keySizeBits", 0),
                label = obj.optString("label", ""),
                createdAt = obj.optLong("createdAt", 0)
            )
        }
    }
}

/**
 * Result of remote.listKeys.
 */
data class RemoteListKeysResult(
    val keys: List<RemoteKeyInfo>
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteListKeysResult {
            val keysArray = obj.getJSONArray("keys")
            val keys = (0 until keysArray.length()).map {
                RemoteKeyInfo.fromJson(keysArray.getJSONObject(it))
            }
            return RemoteListKeysResult(keys = keys)
        }
    }

    fun toJson(): JSONObject {
        val arr = JSONArray()
        for (k in keys) {
            arr.put(k.toJson())
        }
        return JSONObject().apply {
            put("keys", arr)
        }
    }
}

/**
 * Parameters for remote.getPublicKey.
 */
data class RemoteGetPublicKeyParams(
    val backend: String,
    val keyId: String,
    val format: String = "der"      // "der" or "pem"
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("format", format)
        }
    }
}

/**
 * Result of remote.getPublicKey.
 */
data class RemoteGetPublicKeyResult(
    val publicKey: String,           // Base64-encoded (DER) or PEM text
    val format: String,
    val algorithm: String
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteGetPublicKeyResult {
            return RemoteGetPublicKeyResult(
                publicKey = obj.getString("publicKey"),
                format = obj.getString("format"),
                algorithm = obj.getString("algorithm")
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("publicKey", publicKey)
            put("format", format)
            put("algorithm", algorithm)
        }
    }
}

/**
 * Parameters for remote.sign.
 */
data class RemoteSignParams(
    val backend: String,
    val keyId: String,
    val data: String,                // Base64-encoded data to sign
    val algorithm: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("data", data)
            algorithm?.let { put("algorithm", it) }
        }
    }
}

/**
 * Result of remote.sign.
 */
data class RemoteSignResult(
    val signature: String,           // Base64-encoded signature
    val algorithm: String
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteSignResult {
            return RemoteSignResult(
                signature = obj.getString("signature"),
                algorithm = obj.getString("algorithm")
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("signature", signature)
            put("algorithm", algorithm)
        }
    }
}

/**
 * Parameters for remote.verify.
 */
data class RemoteVerifyParams(
    val backend: String,
    val keyId: String,
    val data: String,                // Base64-encoded data
    val signature: String,           // Base64-encoded signature
    val algorithm: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("data", data)
            put("signature", signature)
            algorithm?.let { put("algorithm", it) }
        }
    }
}

/**
 * Result of remote.verify.
 */
data class RemoteVerifyResult(
    val valid: Boolean
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteVerifyResult {
            return RemoteVerifyResult(valid = obj.getBoolean("valid"))
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("valid", valid)
        }
    }
}

/**
 * Parameters for remote.encrypt.
 */
data class RemoteEncryptParams(
    val backend: String,
    val keyId: String,
    val plaintext: String,           // Base64-encoded plaintext
    val algorithm: String? = null,
    val aad: String? = null          // Base64-encoded AAD
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("plaintext", plaintext)
            algorithm?.let { put("algorithm", it) }
            aad?.let { put("aad", it) }
        }
    }
}

/**
 * Result of remote.encrypt.
 */
data class RemoteEncryptResult(
    val ciphertext: String           // Base64-encoded ciphertext
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteEncryptResult {
            return RemoteEncryptResult(ciphertext = obj.getString("ciphertext"))
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("ciphertext", ciphertext)
        }
    }
}

/**
 * Parameters for remote.decrypt.
 */
data class RemoteDecryptParams(
    val backend: String,
    val keyId: String,
    val ciphertext: String,          // Base64-encoded ciphertext
    val algorithm: String? = null,
    val aad: String? = null          // Base64-encoded AAD
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("ciphertext", ciphertext)
            algorithm?.let { put("algorithm", it) }
            aad?.let { put("aad", it) }
        }
    }
}

/**
 * Result of remote.decrypt.
 */
data class RemoteDecryptResult(
    val plaintext: String            // Base64-encoded plaintext
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteDecryptResult {
            return RemoteDecryptResult(plaintext = obj.getString("plaintext"))
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("plaintext", plaintext)
        }
    }
}

/**
 * Parameters for remote.deriveKey (ECDH key agreement).
 */
data class RemoteDeriveKeyParams(
    val backend: String,
    val keyId: String,
    val peerPublicKey: String        // Base64-encoded DER peer public key
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("peerPublicKey", peerPublicKey)
        }
    }
}

/**
 * Result of remote.deriveKey.
 */
data class RemoteDeriveKeyResult(
    val sharedSecret: String         // Base64-encoded shared secret
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteDeriveKeyResult {
            return RemoteDeriveKeyResult(sharedSecret = obj.getString("sharedSecret"))
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("sharedSecret", sharedSecret)
        }
    }
}

/**
 * Parameters for remote.generateKey.
 */
data class RemoteGenerateKeyParams(
    val backend: String,
    val keyId: String,
    val algorithm: String,
    val keySizeBits: Int = 0,
    val label: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("algorithm", algorithm)
            if (keySizeBits > 0) put("keySizeBits", keySizeBits)
            label?.let { put("label", it) }
        }
    }
}

/**
 * Result of remote.generateKey.
 */
data class RemoteGenerateKeyResult(
    val keyId: String,
    val publicKey: String?,          // Base64-encoded DER public key
    val algorithm: String,
    val keySizeBits: Int,
    val backend: String
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteGenerateKeyResult {
            return RemoteGenerateKeyResult(
                keyId = obj.getString("keyId"),
                publicKey = obj.getStringOrNull("publicKey"),
                algorithm = obj.getString("algorithm"),
                keySizeBits = obj.optInt("keySizeBits", 0),
                backend = obj.getString("backend")
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            publicKey?.let { put("publicKey", it) }
            put("algorithm", algorithm)
            put("keySizeBits", keySizeBits)
            put("backend", backend)
        }
    }
}

/**
 * Parameters for remote.getKeyInfo.
 */
data class RemoteGetKeyInfoParams(
    val backend: String,
    val keyId: String
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
        }
    }
}

/**
 * Result of remote.getKeyInfo.
 */
data class RemoteGetKeyInfoResult(
    val keyId: String,
    val backend: String,
    val algorithm: String,
    val keySizeBits: Int,
    val label: String,
    val createdAt: Long,
    val hardwareBacked: Boolean,
    val exportable: Boolean
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteGetKeyInfoResult {
            return RemoteGetKeyInfoResult(
                keyId = obj.getString("keyId"),
                backend = obj.getString("backend"),
                algorithm = obj.getString("algorithm"),
                keySizeBits = obj.optInt("keySizeBits", 0),
                label = obj.optString("label", ""),
                createdAt = obj.optLong("createdAt", 0),
                hardwareBacked = obj.optBoolean("hardwareBacked", false),
                exportable = obj.optBoolean("exportable", false)
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("keyId", keyId)
            put("backend", backend)
            put("algorithm", algorithm)
            put("keySizeBits", keySizeBits)
            put("label", label)
            put("createdAt", createdAt)
            put("hardwareBacked", hardwareBacked)
            put("exportable", exportable)
        }
    }
}

/**
 * Parameters for remote.deleteKey.
 */
data class RemoteDeleteKeyParams(
    val backend: String,
    val keyId: String
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
        }
    }
}

/**
 * Result of remote.deleteKey.
 */
data class RemoteDeleteKeyResult(
    val deleted: Boolean
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteDeleteKeyResult {
            return RemoteDeleteKeyResult(deleted = obj.getBoolean("deleted"))
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("deleted", deleted)
        }
    }
}

/**
 * Parameters for remote.attestKey.
 */
data class RemoteAttestKeyParams(
    val backend: String,
    val keyId: String,
    val nonce: String                // Base64-encoded challenge nonce
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("backend", backend)
            put("keyId", keyId)
            put("nonce", nonce)
        }
    }
}

/**
 * Result of remote.attestKey.
 */
data class RemoteAttestKeyResult(
    val format: String,              // "tpm2", "pkcs11", etc.
    val certificateChain: List<String>,  // Base64-encoded certificates
    val attestationData: String?,    // Base64-encoded backend-specific data
    val nonce: String                // Echoed challenge nonce
) {
    companion object {
        fun fromJson(obj: JSONObject): RemoteAttestKeyResult {
            val chainArray = obj.getJSONArray("certificateChain")
            val chain = (0 until chainArray.length()).map { chainArray.getString(it) }
            return RemoteAttestKeyResult(
                format = obj.getString("format"),
                certificateChain = chain,
                attestationData = obj.getStringOrNull("attestationData"),
                nonce = obj.getString("nonce")
            )
        }
    }

    fun toJson(): JSONObject {
        val chainArray = JSONArray()
        for (cert in certificateChain) {
            chainArray.put(cert)
        }
        return JSONObject().apply {
            put("format", format)
            put("certificateChain", chainArray)
            attestationData?.let { put("attestationData", it) }
            put("nonce", nonce)
        }
    }
}

// ============================================================
// Pairing confirmation protocol types
// ============================================================

/**
 * Parameters for pairing.confirm method.
 *
 * @property deviceName Display name of the remote device requesting pairing.
 * @property publicKeyHex Hex-encoded Noise static public key of the remote device.
 */
data class PairingConfirmParams(
    val deviceName: String,
    val publicKeyHex: String
) {
    companion object {
        fun fromJson(params: JSONObject): PairingConfirmParams {
            return PairingConfirmParams(
                deviceName = params.optString("deviceName", "Unknown"),
                publicKeyHex = params.getStringOrNull("publicKeyHex")
                    ?: throw ProtocolException("Missing 'publicKeyHex'", errorCode = ErrorCodes.INVALID_PARAMS)
            )
        }
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("deviceName", deviceName)
            put("publicKeyHex", publicKeyHex)
        }
    }
}

/**
 * Result of pairing.confirm method.
 *
 * @property confirmed Whether the user accepted the pairing.
 * @property deviceName The local device name (phone).
 */
data class PairingConfirmResult(
    val confirmed: Boolean,
    val deviceName: String
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("confirmed", confirmed)
            put("deviceName", deviceName)
        }
    }
}

/**
 * Parameters for local.biometricPending notification.
 * Sent from phone to laptop when biometric authentication is required.
 *
 * @property operation The operation type requiring biometric ("sign", "decrypt", "attestKey", etc.)
 * @property rpName The relying party name for context, or null if unavailable.
 * @property timeoutSecs How long the phone will wait for biometric approval.
 */
data class LocalBiometricPendingParams(
    val operation: String,
    val rpName: String?,
    val timeoutSecs: Int = 30
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("operation", operation)
            rpName?.let { put("rpName", it) }
            put("timeoutSecs", timeoutSecs)
        }
    }
}

// ============================================================
// IDevID Certificate Exchange Protocol Types
// (Corresponds to xkey/pkg/phone/protocol_idevid.go)
// ============================================================

/**
 * Parameters for local.getCABundle method.
 * Requests the CA bundle from the phone for populating the Go side's
 * trust store with Android CA certificates.
 *
 * @property includeRoot Whether to include the root CA certificate.
 * @property format Desired format: "pem" or "der". Default is "pem".
 */
data class LocalGetCABundleParams(
    val includeRoot: Boolean? = null,
    val format: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            includeRoot?.let { put("includeRoot", it) }
            format?.let { put("format", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetCABundleParams {
            return LocalGetCABundleParams(
                includeRoot = if (obj.has("includeRoot")) obj.getBoolean("includeRoot") else null,
                format = if (obj.has("format") && !obj.isNull("format")) obj.getString("format") else null
            )
        }
    }
}

/**
 * Result of local.getCABundle method.
 *
 * @property bundlePem CA bundle in PEM format (concatenated certificates).
 * @property certificates Individual certificates in DER format.
 * @property count Number of certificates in the bundle.
 * @property rootSubject Subject DN of the root CA certificate.
 */
data class LocalGetCABundleResult(
    val bundlePem: ByteArray? = null,
    val certificates: List<ByteArray>,
    val count: Int,
    val rootSubject: String? = null
) {
    fun toJson(): JSONObject {
        val certsArray = JSONArray()
        for (cert in certificates) {
            certsArray.put(android.util.Base64.encodeToString(cert, android.util.Base64.NO_WRAP))
        }
        return JSONObject().apply {
            bundlePem?.let {
                put("bundlePem", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
            }
            put("certificates", certsArray)
            put("count", count)
            rootSubject?.let { put("rootSubject", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetCABundleResult {
            val certsArray = obj.optJSONArray("certificates")
            val certs = if (certsArray != null) {
                (0 until certsArray.length()).map {
                    android.util.Base64.decode(certsArray.getString(it), android.util.Base64.NO_WRAP)
                }
            } else {
                emptyList()
            }
            return LocalGetCABundleResult(
                bundlePem = if (obj.has("bundlePem") && !obj.isNull("bundlePem")) {
                    android.util.Base64.decode(obj.getString("bundlePem"), android.util.Base64.NO_WRAP)
                } else {
                    null
                },
                certificates = certs,
                count = obj.optInt("count", certs.size),
                rootSubject = if (obj.has("rootSubject") && !obj.isNull("rootSubject")) {
                    obj.getString("rootSubject")
                } else {
                    null
                }
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGetCABundleResult

        if (bundlePem != null) {
            if (other.bundlePem == null) return false
            if (!bundlePem.contentEquals(other.bundlePem)) return false
        } else if (other.bundlePem != null) return false

        if (certificates.size != other.certificates.size) return false
        for (i in certificates.indices) {
            if (!certificates[i].contentEquals(other.certificates[i])) return false
        }
        if (count != other.count) return false
        if (rootSubject != other.rootSubject) return false

        return true
    }

    override fun hashCode(): Int {
        var result = bundlePem?.contentHashCode() ?: 0
        for (cert in certificates) {
            result = 31 * result + cert.contentHashCode()
        }
        result = 31 * result + count
        result = 31 * result + (rootSubject?.hashCode() ?: 0)
        return result
    }
}

/**
 * Parameters for local.getIDevIDCertificate method.
 * Retrieves the IDevID certificate chain from the Go side.
 *
 * @property nonce Optional challenge nonce for freshness verification.
 */
data class LocalGetIDevIDCertificateParams(
    val nonce: ByteArray? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            nonce?.let {
                put("nonce", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
            }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetIDevIDCertificateParams {
            return LocalGetIDevIDCertificateParams(
                nonce = if (obj.has("nonce") && !obj.isNull("nonce")) {
                    android.util.Base64.decode(obj.getString("nonce"), android.util.Base64.NO_WRAP)
                } else {
                    null
                }
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGetIDevIDCertificateParams

        if (nonce != null) {
            if (other.nonce == null) return false
            if (!nonce.contentEquals(other.nonce)) return false
        } else if (other.nonce != null) return false

        return true
    }

    override fun hashCode(): Int {
        return nonce?.contentHashCode() ?: 0
    }
}

/**
 * Result of local.getIDevIDCertificate method.
 *
 * @property hasCertificate Whether an IDevID certificate exists.
 * @property certificateChain Certificate chain in DER format [leaf, intermediate..., root].
 * @property nonce Echoed challenge nonce (if provided in params).
 * @property certificateInfo Parsed certificate metadata.
 */
data class LocalGetIDevIDCertificateResult(
    val hasCertificate: Boolean,
    val certificateChain: List<ByteArray>? = null,
    val nonce: ByteArray? = null,
    val certificateInfo: IDevIDCertificateInfo? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("hasCertificate", hasCertificate)
            certificateChain?.let { chain ->
                val chainArray = JSONArray()
                for (cert in chain) {
                    chainArray.put(android.util.Base64.encodeToString(cert, android.util.Base64.NO_WRAP))
                }
                put("certificateChain", chainArray)
            }
            nonce?.let {
                put("nonce", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
            }
            certificateInfo?.let { put("certificateInfo", it.toJson()) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetIDevIDCertificateResult {
            val chainArray = obj.optJSONArray("certificateChain")
            val chain = if (chainArray != null) {
                (0 until chainArray.length()).map {
                    android.util.Base64.decode(chainArray.getString(it), android.util.Base64.NO_WRAP)
                }
            } else {
                null
            }
            return LocalGetIDevIDCertificateResult(
                hasCertificate = obj.optBoolean("hasCertificate", false),
                certificateChain = chain,
                nonce = if (obj.has("nonce") && !obj.isNull("nonce")) {
                    android.util.Base64.decode(obj.getString("nonce"), android.util.Base64.NO_WRAP)
                } else {
                    null
                },
                certificateInfo = obj.optJSONObject("certificateInfo")?.let {
                    IDevIDCertificateInfo.fromJson(it)
                }
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGetIDevIDCertificateResult

        if (hasCertificate != other.hasCertificate) return false
        if (certificateChain != null) {
            if (other.certificateChain == null) return false
            if (certificateChain.size != other.certificateChain.size) return false
            for (i in certificateChain.indices) {
                if (!certificateChain[i].contentEquals(other.certificateChain[i])) return false
            }
        } else if (other.certificateChain != null) return false
        if (nonce != null) {
            if (other.nonce == null) return false
            if (!nonce.contentEquals(other.nonce)) return false
        } else if (other.nonce != null) return false
        if (certificateInfo != other.certificateInfo) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hasCertificate.hashCode()
        certificateChain?.forEach { cert ->
            result = 31 * result + cert.contentHashCode()
        }
        result = 31 * result + (nonce?.contentHashCode() ?: 0)
        result = 31 * result + (certificateInfo?.hashCode() ?: 0)
        return result
    }
}

/**
 * Metadata about an IDevID certificate.
 *
 * @property serialNumber Certificate serial number as hex string.
 * @property issuer Certificate issuer DN.
 * @property subject Certificate subject DN.
 * @property notBefore Certificate validity start time (Unix timestamp).
 * @property notAfter Certificate validity end time (Unix timestamp).
 * @property algorithm Signature algorithm used.
 * @property publicKeyAlgorithm Subject public key algorithm.
 * @property keySizeBits Subject public key size in bits.
 * @property fingerprint SHA-256 fingerprint of the certificate (hex-encoded).
 * @property isCa Whether this is a CA certificate.
 * @property keyUsage Certificate key usage descriptions.
 * @property extKeyUsage Extended key usage descriptions.
 * @property hardwareSerial Device hardware serial from the certificate subject.
 */
data class IDevIDCertificateInfo(
    val serialNumber: String,
    val issuer: String,
    val subject: String,
    val notBefore: Long,
    val notAfter: Long,
    val algorithm: String,
    val publicKeyAlgorithm: String,
    val keySizeBits: Int,
    val fingerprint: String,
    val isCa: Boolean = false,
    val keyUsage: List<String>? = null,
    val extKeyUsage: List<String>? = null,
    val hardwareSerial: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("serialNumber", serialNumber)
            put("issuer", issuer)
            put("subject", subject)
            put("notBefore", notBefore)
            put("notAfter", notAfter)
            put("algorithm", algorithm)
            put("publicKeyAlgorithm", publicKeyAlgorithm)
            put("keySizeBits", keySizeBits)
            put("fingerprint", fingerprint)
            put("isCa", isCa)
            keyUsage?.let { put("keyUsage", JSONArray(it)) }
            extKeyUsage?.let { put("extKeyUsage", JSONArray(it)) }
            hardwareSerial?.let { put("hardwareSerial", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): IDevIDCertificateInfo {
            return IDevIDCertificateInfo(
                serialNumber = obj.getString("serialNumber"),
                issuer = obj.getString("issuer"),
                subject = obj.getString("subject"),
                notBefore = obj.getLong("notBefore"),
                notAfter = obj.getLong("notAfter"),
                algorithm = obj.getString("algorithm"),
                publicKeyAlgorithm = obj.getString("publicKeyAlgorithm"),
                keySizeBits = obj.getInt("keySizeBits"),
                fingerprint = obj.getString("fingerprint"),
                isCa = obj.optBoolean("isCa", false),
                keyUsage = obj.optJSONArray("keyUsage")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }
                },
                extKeyUsage = obj.optJSONArray("extKeyUsage")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }
                },
                hardwareSerial = if (obj.has("hardwareSerial") && !obj.isNull("hardwareSerial")) {
                    obj.getString("hardwareSerial")
                } else {
                    null
                }
            )
        }
    }
}

/**
 * Subject fields for IDevID CSR generation.
 *
 * @property commonName CN field (typically device identifier).
 * @property organization O field.
 * @property organizationalUnit OU field.
 * @property serialNumber Device serial number (serialNumber attribute).
 * @property country C field.
 * @property locality L field.
 * @property province ST field.
 */
data class IDevIDSubject(
    val commonName: String? = null,
    val organization: String? = null,
    val organizationalUnit: String? = null,
    val serialNumber: String? = null,
    val country: String? = null,
    val locality: String? = null,
    val province: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            commonName?.let { put("commonName", it) }
            organization?.let { put("organization", it) }
            organizationalUnit?.let { put("organizationalUnit", it) }
            serialNumber?.let { put("serialNumber", it) }
            country?.let { put("country", it) }
            locality?.let { put("locality", it) }
            province?.let { put("province", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): IDevIDSubject {
            return IDevIDSubject(
                commonName = if (obj.has("commonName") && !obj.isNull("commonName")) {
                    obj.getString("commonName")
                } else null,
                organization = if (obj.has("organization") && !obj.isNull("organization")) {
                    obj.getString("organization")
                } else null,
                organizationalUnit = if (obj.has("organizationalUnit") && !obj.isNull("organizationalUnit")) {
                    obj.getString("organizationalUnit")
                } else null,
                serialNumber = if (obj.has("serialNumber") && !obj.isNull("serialNumber")) {
                    obj.getString("serialNumber")
                } else null,
                country = if (obj.has("country") && !obj.isNull("country")) {
                    obj.getString("country")
                } else null,
                locality = if (obj.has("locality") && !obj.isNull("locality")) {
                    obj.getString("locality")
                } else null,
                province = if (obj.has("province") && !obj.isNull("province")) {
                    obj.getString("province")
                } else null
            )
        }
    }
}

/**
 * Parameters for local.requestIDevIDIssuance method.
 * Requests the Android CA to issue an IDevID certificate for the Go side.
 *
 * @property csr Certificate Signing Request in DER format (PKCS#10 or TCG-CSR-IDEVID).
 * @property csrFormat CSR format: "pkcs10" or "tcg-csr-idevid". Default is "pkcs10".
 * @property attestationData Optional attestation evidence to bind CSR to hardware-backed key.
 * @property validityDays Requested certificate validity in days (CA may override).
 */
data class LocalRequestIDevIDIssuanceParams(
    val csr: ByteArray,
    val csrFormat: String? = null,
    val attestationData: ByteArray? = null,
    val validityDays: Int? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("csr", android.util.Base64.encodeToString(csr, android.util.Base64.NO_WRAP))
            csrFormat?.let { put("csrFormat", it) }
            attestationData?.let {
                put("attestationData", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
            }
            validityDays?.let { put("validityDays", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalRequestIDevIDIssuanceParams {
            val csrB64 = obj.getStringOrNull("csr")
                ?: throw ProtocolException("Missing 'csr' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            return LocalRequestIDevIDIssuanceParams(
                csr = android.util.Base64.decode(csrB64, android.util.Base64.NO_WRAP),
                csrFormat = if (obj.has("csrFormat") && !obj.isNull("csrFormat")) {
                    obj.getString("csrFormat")
                } else null,
                attestationData = if (obj.has("attestationData") && !obj.isNull("attestationData")) {
                    android.util.Base64.decode(obj.getString("attestationData"), android.util.Base64.NO_WRAP)
                } else null,
                validityDays = if (obj.has("validityDays")) obj.getInt("validityDays") else null
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalRequestIDevIDIssuanceParams

        if (!csr.contentEquals(other.csr)) return false
        if (csrFormat != other.csrFormat) return false
        if (attestationData != null) {
            if (other.attestationData == null) return false
            if (!attestationData.contentEquals(other.attestationData)) return false
        } else if (other.attestationData != null) return false
        if (validityDays != other.validityDays) return false

        return true
    }

    override fun hashCode(): Int {
        var result = csr.contentHashCode()
        result = 31 * result + (csrFormat?.hashCode() ?: 0)
        result = 31 * result + (attestationData?.contentHashCode() ?: 0)
        result = 31 * result + (validityDays ?: 0)
        return result
    }
}

/**
 * Result of local.requestIDevIDIssuance method.
 *
 * @property issued Whether the certificate was successfully issued.
 * @property certificate Issued IDevID certificate in DER format.
 * @property certificateChain Full certificate chain in DER format [leaf, intermediate..., root].
 * @property certificateInfo Parsed certificate metadata.
 * @property errorCode Machine-readable error code if issuance failed.
 * @property errorMessage Human-readable error message if issuance failed.
 */
data class LocalRequestIDevIDIssuanceResult(
    val issued: Boolean,
    val certificate: ByteArray? = null,
    val certificateChain: List<ByteArray>? = null,
    val certificateInfo: IDevIDCertificateInfo? = null,
    val errorCode: String? = null,
    val errorMessage: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("issued", issued)
            certificate?.let {
                put("certificate", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
            }
            certificateChain?.let { chain ->
                val chainArray = JSONArray()
                for (cert in chain) {
                    chainArray.put(android.util.Base64.encodeToString(cert, android.util.Base64.NO_WRAP))
                }
                put("certificateChain", chainArray)
            }
            certificateInfo?.let { put("certificateInfo", it.toJson()) }
            errorCode?.let { put("errorCode", it) }
            errorMessage?.let { put("errorMessage", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalRequestIDevIDIssuanceResult {
            val chainArray = obj.optJSONArray("certificateChain")
            val chain = if (chainArray != null) {
                (0 until chainArray.length()).map {
                    android.util.Base64.decode(chainArray.getString(it), android.util.Base64.NO_WRAP)
                }
            } else null
            return LocalRequestIDevIDIssuanceResult(
                issued = obj.optBoolean("issued", false),
                certificate = if (obj.has("certificate") && !obj.isNull("certificate")) {
                    android.util.Base64.decode(obj.getString("certificate"), android.util.Base64.NO_WRAP)
                } else null,
                certificateChain = chain,
                certificateInfo = obj.optJSONObject("certificateInfo")?.let {
                    IDevIDCertificateInfo.fromJson(it)
                },
                errorCode = if (obj.has("errorCode") && !obj.isNull("errorCode")) {
                    obj.getString("errorCode")
                } else null,
                errorMessage = if (obj.has("errorMessage") && !obj.isNull("errorMessage")) {
                    obj.getString("errorMessage")
                } else null
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalRequestIDevIDIssuanceResult

        if (issued != other.issued) return false
        if (certificate != null) {
            if (other.certificate == null) return false
            if (!certificate.contentEquals(other.certificate)) return false
        } else if (other.certificate != null) return false
        if (certificateChain != null) {
            if (other.certificateChain == null) return false
            if (certificateChain.size != other.certificateChain.size) return false
            for (i in certificateChain.indices) {
                if (!certificateChain[i].contentEquals(other.certificateChain[i])) return false
            }
        } else if (other.certificateChain != null) return false
        if (certificateInfo != other.certificateInfo) return false
        if (errorCode != other.errorCode) return false
        if (errorMessage != other.errorMessage) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issued.hashCode()
        result = 31 * result + (certificate?.contentHashCode() ?: 0)
        certificateChain?.forEach { cert ->
            result = 31 * result + cert.contentHashCode()
        }
        result = 31 * result + (certificateInfo?.hashCode() ?: 0)
        result = 31 * result + (errorCode?.hashCode() ?: 0)
        result = 31 * result + (errorMessage?.hashCode() ?: 0)
        return result
    }
}

/**
 * Parameters for local.generateIDevIDCSR method.
 * Generates an IDevID CSR on the Go side for submission to the Android CA.
 *
 * @property backend xkmsd backend to use for key generation. Empty uses default.
 * @property keyId Existing key to use. Empty generates a new key.
 * @property algorithm Key algorithm for new key generation (ES256, ES384, RS2048, etc.).
 * @property subject Requested certificate subject fields.
 * @property csrFormat Output format: "pkcs10" or "tcg-csr-idevid". Default is "pkcs10".
 */
data class LocalGenerateIDevIDCSRParams(
    val backend: String? = null,
    val keyId: String? = null,
    val algorithm: String? = null,
    val subject: IDevIDSubject? = null,
    val csrFormat: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            backend?.let { put("backend", it) }
            keyId?.let { put("keyId", it) }
            algorithm?.let { put("algorithm", it) }
            subject?.let { put("subject", it.toJson()) }
            csrFormat?.let { put("csrFormat", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGenerateIDevIDCSRParams {
            return LocalGenerateIDevIDCSRParams(
                backend = if (obj.has("backend") && !obj.isNull("backend")) {
                    obj.getString("backend")
                } else null,
                keyId = if (obj.has("keyId") && !obj.isNull("keyId")) {
                    obj.getString("keyId")
                } else null,
                algorithm = if (obj.has("algorithm") && !obj.isNull("algorithm")) {
                    obj.getString("algorithm")
                } else null,
                subject = obj.optJSONObject("subject")?.let { IDevIDSubject.fromJson(it) },
                csrFormat = if (obj.has("csrFormat") && !obj.isNull("csrFormat")) {
                    obj.getString("csrFormat")
                } else null
            )
        }
    }
}

/**
 * Result of local.generateIDevIDCSR method.
 *
 * @property csr Generated Certificate Signing Request in DER format.
 * @property csrFormat Format of the CSR: "pkcs10" or "tcg-csr-idevid".
 * @property keyId Identifier of the key used for the CSR.
 * @property backend xkmsd backend where the key resides.
 * @property algorithm Key algorithm.
 * @property publicKey DER-encoded public key.
 */
data class LocalGenerateIDevIDCSRResult(
    val csr: ByteArray,
    val csrFormat: String,
    val keyId: String,
    val backend: String,
    val algorithm: String,
    val publicKey: ByteArray? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("csr", android.util.Base64.encodeToString(csr, android.util.Base64.NO_WRAP))
            put("csrFormat", csrFormat)
            put("keyId", keyId)
            put("backend", backend)
            put("algorithm", algorithm)
            publicKey?.let {
                put("publicKey", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
            }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGenerateIDevIDCSRResult {
            val csrB64 = obj.getStringOrNull("csr")
                ?: throw ProtocolException("Missing 'csr' in result", errorCode = ErrorCodes.INTERNAL_ERROR)
            return LocalGenerateIDevIDCSRResult(
                csr = android.util.Base64.decode(csrB64, android.util.Base64.NO_WRAP),
                csrFormat = obj.getString("csrFormat"),
                keyId = obj.getString("keyId"),
                backend = obj.getString("backend"),
                algorithm = obj.getString("algorithm"),
                publicKey = if (obj.has("publicKey") && !obj.isNull("publicKey")) {
                    android.util.Base64.decode(obj.getString("publicKey"), android.util.Base64.NO_WRAP)
                } else null
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGenerateIDevIDCSRResult

        if (!csr.contentEquals(other.csr)) return false
        if (csrFormat != other.csrFormat) return false
        if (keyId != other.keyId) return false
        if (backend != other.backend) return false
        if (algorithm != other.algorithm) return false
        if (publicKey != null) {
            if (other.publicKey == null) return false
            if (!publicKey.contentEquals(other.publicKey)) return false
        } else if (other.publicKey != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = csr.contentHashCode()
        result = 31 * result + csrFormat.hashCode()
        result = 31 * result + keyId.hashCode()
        result = 31 * result + backend.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (publicKey?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * Parameters for local.storeIDevIDCertificate method.
 * Stores the issued IDevID certificate and chain on the Go side.
 *
 * @property certificate IDevID certificate in DER format.
 * @property chain Certificate chain in DER format (excluding leaf) [intermediate..., root].
 * @property keyId Key identifier the certificate belongs to.
 * @property backend xkmsd backend where the key resides.
 */
data class LocalStoreIDevIDCertificateParams(
    val certificate: ByteArray,
    val chain: List<ByteArray>? = null,
    val keyId: String,
    val backend: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("certificate", android.util.Base64.encodeToString(certificate, android.util.Base64.NO_WRAP))
            chain?.let { chainList ->
                val chainArray = JSONArray()
                for (cert in chainList) {
                    chainArray.put(android.util.Base64.encodeToString(cert, android.util.Base64.NO_WRAP))
                }
                put("chain", chainArray)
            }
            put("keyId", keyId)
            backend?.let { put("backend", it) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalStoreIDevIDCertificateParams {
            val certB64 = obj.getStringOrNull("certificate")
                ?: throw ProtocolException("Missing 'certificate' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val chainArray = obj.optJSONArray("chain")
            val chain = if (chainArray != null) {
                (0 until chainArray.length()).map {
                    android.util.Base64.decode(chainArray.getString(it), android.util.Base64.NO_WRAP)
                }
            } else null
            return LocalStoreIDevIDCertificateParams(
                certificate = android.util.Base64.decode(certB64, android.util.Base64.NO_WRAP),
                chain = chain,
                keyId = obj.getStringOrNull("keyId")
                    ?: throw ProtocolException("Missing 'keyId' parameter", errorCode = ErrorCodes.INVALID_PARAMS),
                backend = if (obj.has("backend") && !obj.isNull("backend")) {
                    obj.getString("backend")
                } else null
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalStoreIDevIDCertificateParams

        if (!certificate.contentEquals(other.certificate)) return false
        if (chain != null) {
            if (other.chain == null) return false
            if (chain.size != other.chain.size) return false
            for (i in chain.indices) {
                if (!chain[i].contentEquals(other.chain[i])) return false
            }
        } else if (other.chain != null) return false
        if (keyId != other.keyId) return false
        if (backend != other.backend) return false

        return true
    }

    override fun hashCode(): Int {
        var result = certificate.contentHashCode()
        chain?.forEach { cert ->
            result = 31 * result + cert.contentHashCode()
        }
        result = 31 * result + keyId.hashCode()
        result = 31 * result + (backend?.hashCode() ?: 0)
        return result
    }
}

/**
 * Result of local.storeIDevIDCertificate method.
 *
 * @property stored Whether the certificate was successfully stored.
 * @property certificateInfo Parsed certificate metadata.
 */
data class LocalStoreIDevIDCertificateResult(
    val stored: Boolean,
    val certificateInfo: IDevIDCertificateInfo? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("stored", stored)
            certificateInfo?.let { put("certificateInfo", it.toJson()) }
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalStoreIDevIDCertificateResult {
            return LocalStoreIDevIDCertificateResult(
                stored = obj.optBoolean("stored", false),
                certificateInfo = obj.optJSONObject("certificateInfo")?.let {
                    IDevIDCertificateInfo.fromJson(it)
                }
            )
        }
    }
}

// ============================================================
// Android-native device enrollment (this phone is the enrollee)
// (Corresponds to xkey/pkg/pairing/protocol_device_enrollment.go)
// ============================================================

/** Wire tag for the evidence format below, so a verifier never guesses. */
const val ATTESTATION_FORMAT_ANDROID_KEY = "android-key-attestation"

/**
 * Parameters for local.getDeviceEnrollmentRequest.
 *
 * @property nonce CA-chosen challenge, base64. It is embedded in the
 *   attestation extension by the TEE, which is what makes the returned
 *   evidence fresh rather than a recording of an earlier ceremony.
 * @property subject Optional subject DN the CA wants on the certificate. The
 *   CA is free to ignore it -- it names the subject on the certificate it
 *   issues -- but honouring the device's preference keeps the CSR meaningful.
 */
data class LocalGetDeviceEnrollmentRequestParams(
    val nonce: String,
    val subject: String? = null
) {
    fun getNonceBytes(): ByteArray = Base64.getDecoder().decode(nonce)

    fun toJson(): JSONObject = JSONObject().apply {
        put("nonce", nonce)
        subject?.let { put("subject", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetDeviceEnrollmentRequestParams =
            LocalGetDeviceEnrollmentRequestParams(
                nonce = obj.getString("nonce"),
                subject = obj.getStringOrNull("subject")
            )
    }
}

/**
 * Result of local.getDeviceEnrollmentRequest: everything a CA needs to decide
 * whether to issue this phone a device credential.
 *
 * This is the Android counterpart of a TCG-CSR-IDEVID, and it carries the same
 * two things by different means. The CSR is the request -- a public key the
 * device wants certified, self-signed to prove it holds the private half. The
 * attestation chain is the evidence, and it does the work a TPM splits across
 * an EK certificate and a credential activation:
 *
 *  - It chains to a Google hardware root, so the key demonstrably lives in a
 *    keystore the OS cannot forge.
 *  - Its RootOfTrust records verified-boot state and bootloader lock, which is
 *    what a PCR quote is for.
 *  - Its `attestationApplicationId` is written by the TEE, not the app, and
 *    names the package and signing certificate digests -- so it identifies
 *    *which application on which device*, something a TPM quote cannot say.
 *  - The CA's nonce is inside the extension, so it cannot be replayed.
 *
 * @property format Always [ATTESTATION_FORMAT_ANDROID_KEY]. Present so a
 *   verifier rejects rather than misreads evidence it does not understand.
 * @property csr PKCS#10 certification request, DER.
 * @property attestationChain Attestation certificates, leaf first, each DER
 *   base64-encoded. The leaf certifies the CSR's key.
 * @property securityLevel Where the key lives: "software", "trusted_environment"
 *   or "strongbox". Advisory -- the CA must read the chain, not trust this.
 * @property platformModel Device model, for the operator's benefit.
 * @property platformSerial Serial, when the device will disclose one.
 */
data class LocalGetDeviceEnrollmentRequestResult(
    val csr: ByteArray,
    val attestationChain: List<String>,
    val securityLevel: String,
    val format: String = ATTESTATION_FORMAT_ANDROID_KEY,
    val platformModel: String? = null,
    val platformSerial: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("format", format)
        put("csr", Base64.getEncoder().encodeToString(csr))
        put("attestationChain", JSONArray(attestationChain))
        put("securityLevel", securityLevel)
        platformModel?.let { put("platformModel", it) }
        platformSerial?.let { put("platformSerial", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetDeviceEnrollmentRequestResult {
            val chain = obj.getJSONArray("attestationChain")
            return LocalGetDeviceEnrollmentRequestResult(
                csr = Base64.getDecoder().decode(obj.getString("csr")),
                attestationChain = (0 until chain.length()).map { chain.getString(it) },
                securityLevel = obj.getString("securityLevel"),
                format = obj.optString("format", ATTESTATION_FORMAT_ANDROID_KEY),
                platformModel = obj.getStringOrNull("platformModel"),
                platformSerial = obj.getStringOrNull("platformSerial")
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as LocalGetDeviceEnrollmentRequestResult
        if (!csr.contentEquals(other.csr)) return false
        if (attestationChain != other.attestationChain) return false
        if (securityLevel != other.securityLevel) return false
        if (format != other.format) return false
        if (platformModel != other.platformModel) return false
        if (platformSerial != other.platformSerial) return false
        return true
    }

    override fun hashCode(): Int {
        var result = csr.contentHashCode()
        result = 31 * result + attestationChain.hashCode()
        result = 31 * result + securityLevel.hashCode()
        result = 31 * result + format.hashCode()
        result = 31 * result + (platformModel?.hashCode() ?: 0)
        result = 31 * result + (platformSerial?.hashCode() ?: 0)
        return result
    }
}

/**
 * Parameters for local.storeDeviceCredential: the credential the CA issued in
 * response to a [LocalGetDeviceEnrollmentRequestResult].
 *
 * @property certificate The issued certificate, DER base64.
 * @property chain Issuer certificates, base64 DER, ordered issuer-first up to
 *   the root, so the phone can present a complete path later.
 */
data class LocalStoreDeviceCredentialParams(
    val certificate: String,
    val chain: List<String> = emptyList()
) {
    fun getCertificateBytes(): ByteArray = Base64.getDecoder().decode(certificate)

    fun toJson(): JSONObject = JSONObject().apply {
        put("certificate", certificate)
        if (chain.isNotEmpty()) put("chain", JSONArray(chain))
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalStoreDeviceCredentialParams {
            val chain = if (obj.has("chain") && !obj.isNull("chain")) {
                val arr = obj.getJSONArray("chain")
                (0 until arr.length()).map { arr.getString(it) }
            } else emptyList()
            return LocalStoreDeviceCredentialParams(
                certificate = obj.getString("certificate"),
                chain = chain
            )
        }
    }
}

/**
 * Result of local.storeDeviceCredential.
 *
 * @property stored Whether the credential was accepted and persisted.
 * @property fingerprint SHA-256 of the stored certificate, hex.
 * @property notAfter Expiry in epoch milliseconds. The CA sets this from its
 *   own policy, and it is what drives re-enrollment: when the credential
 *   lapses the device must present fresh attestation to obtain another.
 */
data class LocalStoreDeviceCredentialResult(
    val stored: Boolean,
    val fingerprint: String,
    val notAfter: Long
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("stored", stored)
        put("fingerprint", fingerprint)
        put("notAfter", notAfter)
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalStoreDeviceCredentialResult =
            LocalStoreDeviceCredentialResult(
                stored = obj.getBoolean("stored"),
                fingerprint = obj.getString("fingerprint"),
                notAfter = obj.getLong("notAfter")
            )
    }
}

// ============================================================
// TCG-CSR-IDEVID Attestation Enrollment Protocol Types
// (Corresponds to xkey/pkg/phone/protocol_attestation.go)
// ============================================================

/**
 * Result of local.getTCGCSRIDevID request.
 *
 * Contains the TCG-CSR-IDEVID enrollment package for submission to a Certificate
 * Authority. The CSR is a TCG-defined structure containing the device's TPM-backed
 * identity keys and platform information.
 *
 * The enrollment flow:
 *  1. Device generates this CSR containing EK cert, IAK and IDevID public keys
 *  2. CA verifies EK certificate against TPM manufacturer roots
 *  3. CA performs credential activation challenge (see [LocalActivateCredentialParams])
 *  4. CA may request attestation quote (see [LocalGetAttestationQuoteParams])
 *  5. CA issues IAK and IDevID certificates
 *
 * @property csr Packed TCG-CSR-IDEVID structure (DER-encoded ASN.1).
 * @property ekCert Endorsement Key certificate in DER format. May be null if not provisioned.
 * @property iakPublicKey Initial Attestation Key public key (TPMT_PUBLIC in TPM2B format).
 * @property idevidPublicKey Initial Device Identity Key public key (TPMT_PUBLIC in TPM2B format).
 * @property platformSerial Device platform serial number, if available.
 * @property platformModel Device platform model identifier, if available.
 * @property firmwareVersion TPM firmware version string.
 */
data class LocalGetTCGCSRIDevIDResult(
    val csr: ByteArray,
    val ekCert: ByteArray? = null,
    val iakPublicKey: ByteArray,
    val idevidPublicKey: ByteArray,
    val platformSerial: String? = null,
    val platformModel: String? = null,
    val firmwareVersion: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("csr", android.util.Base64.encodeToString(csr, android.util.Base64.NO_WRAP))
        ekCert?.let {
            put("ekCert", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
        }
        put("iakPublicKey", android.util.Base64.encodeToString(iakPublicKey, android.util.Base64.NO_WRAP))
        put("idevidPublicKey", android.util.Base64.encodeToString(idevidPublicKey, android.util.Base64.NO_WRAP))
        platformSerial?.let { put("platformSerial", it) }
        platformModel?.let { put("platformModel", it) }
        firmwareVersion?.let { put("firmwareVersion", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetTCGCSRIDevIDResult {
            return LocalGetTCGCSRIDevIDResult(
                csr = android.util.Base64.decode(obj.getString("csr"), android.util.Base64.NO_WRAP),
                ekCert = if (obj.has("ekCert") && !obj.isNull("ekCert")) {
                    android.util.Base64.decode(obj.getString("ekCert"), android.util.Base64.NO_WRAP)
                } else null,
                iakPublicKey = android.util.Base64.decode(obj.getString("iakPublicKey"), android.util.Base64.NO_WRAP),
                idevidPublicKey = android.util.Base64.decode(obj.getString("idevidPublicKey"), android.util.Base64.NO_WRAP),
                platformSerial = if (obj.has("platformSerial") && !obj.isNull("platformSerial")) {
                    obj.getString("platformSerial")
                } else null,
                platformModel = if (obj.has("platformModel") && !obj.isNull("platformModel")) {
                    obj.getString("platformModel")
                } else null,
                firmwareVersion = if (obj.has("firmwareVersion") && !obj.isNull("firmwareVersion")) {
                    obj.getString("firmwareVersion")
                } else null
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGetTCGCSRIDevIDResult

        if (!csr.contentEquals(other.csr)) return false
        if (ekCert != null) {
            if (other.ekCert == null) return false
            if (!ekCert.contentEquals(other.ekCert)) return false
        } else if (other.ekCert != null) return false
        if (!iakPublicKey.contentEquals(other.iakPublicKey)) return false
        if (!idevidPublicKey.contentEquals(other.idevidPublicKey)) return false
        if (platformSerial != other.platformSerial) return false
        if (platformModel != other.platformModel) return false
        if (firmwareVersion != other.firmwareVersion) return false

        return true
    }

    override fun hashCode(): Int {
        var result = csr.contentHashCode()
        result = 31 * result + (ekCert?.contentHashCode() ?: 0)
        result = 31 * result + iakPublicKey.contentHashCode()
        result = 31 * result + idevidPublicKey.contentHashCode()
        result = 31 * result + (platformSerial?.hashCode() ?: 0)
        result = 31 * result + (platformModel?.hashCode() ?: 0)
        result = 31 * result + (firmwareVersion?.hashCode() ?: 0)
        return result
    }
}

/**
 * Parameters for local.activateCredential method.
 *
 * Contains the credential activation challenge from the Certificate Authority.
 * The CA creates these values by encrypting a secret to the device's Endorsement Key (EK).
 * Successful activation proves the device possesses the genuine TPM with the claimed EK.
 *
 * @property credentialBlob TPM2B_ID_OBJECT containing the encrypted credential.
 *                          Created by the CA using TPM2_MakeCredential with the EK's public key.
 * @property encryptedSecret TPM2B_ENCRYPTED_SECRET containing the seed value encrypted
 *                           under the EK's public key.
 */
data class LocalActivateCredentialParams(
    val credentialBlob: ByteArray,
    val encryptedSecret: ByteArray
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("credentialBlob", android.util.Base64.encodeToString(credentialBlob, android.util.Base64.NO_WRAP))
        put("encryptedSecret", android.util.Base64.encodeToString(encryptedSecret, android.util.Base64.NO_WRAP))
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalActivateCredentialParams {
            val credentialBlobB64 = obj.getStringOrNull("credentialBlob")
                ?: throw ProtocolException("Missing 'credentialBlob' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val encryptedSecretB64 = obj.getStringOrNull("encryptedSecret")
                ?: throw ProtocolException("Missing 'encryptedSecret' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            return LocalActivateCredentialParams(
                credentialBlob = android.util.Base64.decode(credentialBlobB64, android.util.Base64.NO_WRAP),
                encryptedSecret = android.util.Base64.decode(encryptedSecretB64, android.util.Base64.NO_WRAP)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalActivateCredentialParams

        if (!credentialBlob.contentEquals(other.credentialBlob)) return false
        if (!encryptedSecret.contentEquals(other.encryptedSecret)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credentialBlob.contentHashCode()
        result = 31 * result + encryptedSecret.contentHashCode()
        return result
    }
}

/**
 * Result of local.activateCredential method.
 *
 * Contains the decrypted secret proving TPM possession. The CA compares this
 * against the original secret it encrypted to verify successful activation,
 * authenticating the device as having a genuine TPM from the claimed manufacturer.
 *
 * @property decryptedSecret The secret value recovered from the credential.
 */
data class LocalActivateCredentialResult(
    val decryptedSecret: ByteArray
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("decryptedSecret", android.util.Base64.encodeToString(decryptedSecret, android.util.Base64.NO_WRAP))
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalActivateCredentialResult {
            return LocalActivateCredentialResult(
                decryptedSecret = android.util.Base64.decode(obj.getString("decryptedSecret"), android.util.Base64.NO_WRAP)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalActivateCredentialResult

        return decryptedSecret.contentEquals(other.decryptedSecret)
    }

    override fun hashCode(): Int {
        return decryptedSecret.contentHashCode()
    }
}

/**
 * Parameters for local.getAttestationQuote method.
 *
 * The CA specifies which PCRs to include and provides a fresh nonce to prevent
 * replay attacks. The resulting quote provides signed evidence of the platform's state.
 *
 * @property nonce Fresh random value (typically 32 bytes) from the CA for freshness.
 * @property pcrIndices PCR register indices to include in the quote.
 *                      Common selections:
 *                        - [0,1,2,3,4,5,6,7] for SRTM (Static Root of Trust for Measurement)
 *                        - [0,1,2,3,4,5,6,7,8,9] for full boot chain
 *                        - [17,18,19,20,21,22] for DRTM (Dynamic Root of Trust)
 * @property pcrBank Hash algorithm for PCR values: "sha256" (default), "sha384", "sha512", "sha1".
 */
data class LocalGetAttestationQuoteParams(
    val nonce: ByteArray,
    val pcrIndices: List<Int>,
    val pcrBank: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("nonce", android.util.Base64.encodeToString(nonce, android.util.Base64.NO_WRAP))
        put("pcrIndices", JSONArray(pcrIndices))
        pcrBank?.let { put("pcrBank", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetAttestationQuoteParams {
            val nonceB64 = obj.getStringOrNull("nonce")
                ?: throw ProtocolException("Missing 'nonce' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val pcrArray = obj.optJSONArray("pcrIndices")
                ?: throw ProtocolException("Missing 'pcrIndices' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val pcrIndices = mutableListOf<Int>()
            for (i in 0 until pcrArray.length()) {
                pcrIndices.add(pcrArray.getInt(i))
            }
            return LocalGetAttestationQuoteParams(
                nonce = android.util.Base64.decode(nonceB64, android.util.Base64.NO_WRAP),
                pcrIndices = pcrIndices,
                pcrBank = if (obj.has("pcrBank") && !obj.isNull("pcrBank")) {
                    obj.getString("pcrBank")
                } else null
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGetAttestationQuoteParams

        if (!nonce.contentEquals(other.nonce)) return false
        if (pcrIndices != other.pcrIndices) return false
        if (pcrBank != other.pcrBank) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nonce.contentHashCode()
        result = 31 * result + pcrIndices.hashCode()
        result = 31 * result + (pcrBank?.hashCode() ?: 0)
        return result
    }
}

/**
 * Result of local.getAttestationQuote method.
 *
 * Contains the TPM2 attestation quote providing cryptographic evidence of the
 * platform's state. The quote is signed by the Initial Attestation Key (IAK).
 *
 * @property quoted TPMS_ATTEST structure containing the quote information
 *                  (nonce, PCR selection, PCR digest). Serialized in TPM2B_ATTEST format.
 * @property signature TPMT_SIGNATURE over the quoted data, signed by the IAK.
 *                     Algorithm matches the IAK's key type (RSA-PSS or ECDSA).
 * @property pcrValues Actual PCR values for the requested indices.
 *                     Map keys are PCR indices, values are hash digests.
 * @property eventLog TCG event log (optional). Contains measurement events
 *                    that led to current PCR state. May be null if not supported.
 * @property pcrBank Hash algorithm used for PCR values.
 */
data class LocalGetAttestationQuoteResult(
    val quoted: ByteArray,
    val signature: ByteArray,
    val pcrValues: Map<Int, ByteArray>,
    val eventLog: ByteArray? = null,
    val pcrBank: String
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("quoted", android.util.Base64.encodeToString(quoted, android.util.Base64.NO_WRAP))
        put("signature", android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP))
        val pcrValuesObj = JSONObject()
        pcrValues.forEach { (index, value) ->
            pcrValuesObj.put(index.toString(), android.util.Base64.encodeToString(value, android.util.Base64.NO_WRAP))
        }
        put("pcrValues", pcrValuesObj)
        eventLog?.let {
            put("eventLog", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
        }
        put("pcrBank", pcrBank)
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetAttestationQuoteResult {
            val pcrValuesObj = obj.optJSONObject("pcrValues")
            val pcrValues = mutableMapOf<Int, ByteArray>()
            pcrValuesObj?.keys()?.forEach { key ->
                pcrValues[key.toInt()] = android.util.Base64.decode(
                    pcrValuesObj.getString(key),
                    android.util.Base64.NO_WRAP
                )
            }
            return LocalGetAttestationQuoteResult(
                quoted = android.util.Base64.decode(obj.getString("quoted"), android.util.Base64.NO_WRAP),
                signature = android.util.Base64.decode(obj.getString("signature"), android.util.Base64.NO_WRAP),
                pcrValues = pcrValues,
                eventLog = if (obj.has("eventLog") && !obj.isNull("eventLog")) {
                    android.util.Base64.decode(obj.getString("eventLog"), android.util.Base64.NO_WRAP)
                } else null,
                pcrBank = obj.getString("pcrBank")
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGetAttestationQuoteResult

        if (!quoted.contentEquals(other.quoted)) return false
        if (!signature.contentEquals(other.signature)) return false
        if (pcrValues.size != other.pcrValues.size) return false
        for ((key, value) in pcrValues) {
            val otherValue = other.pcrValues[key] ?: return false
            if (!value.contentEquals(otherValue)) return false
        }
        if (eventLog != null) {
            if (other.eventLog == null) return false
            if (!eventLog.contentEquals(other.eventLog)) return false
        } else if (other.eventLog != null) return false
        if (pcrBank != other.pcrBank) return false

        return true
    }

    override fun hashCode(): Int {
        var result = quoted.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + pcrValues.entries.fold(0) { acc, entry ->
            acc + entry.key.hashCode() + entry.value.contentHashCode()
        }
        result = 31 * result + (eventLog?.contentHashCode() ?: 0)
        result = 31 * result + pcrBank.hashCode()
        return result
    }
}

/**
 * Result of local.getIAKPublicKey method.
 *
 * This method takes no parameters. It retrieves the Initial Attestation Key's
 * public key for use by the CA in verifying quote signatures during enrollment.
 *
 * @property publicKey IAK public key. Format depends on algorithm:
 *                     RSA2048/RSA3072: PKCS#1 RSAPublicKey DER
 *                     ECCP256/ECCP384: SEC1 uncompressed point
 *                     Wrapped in TPM2B_PUBLIC for TPM-native consumers.
 * @property algorithm Key algorithm: "RSA2048", "RSA3072", "ECCP256", "ECCP384".
 * @property publicKeyDer Public key in standard DER encoding (SubjectPublicKeyInfo format).
 * @property name TPM2B_NAME of the IAK. Cryptographic name uniquely identifying this key.
 */
data class LocalGetIAKPublicKeyResult(
    val publicKey: ByteArray,
    val algorithm: String,
    val publicKeyDer: ByteArray? = null,
    val name: ByteArray? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("publicKey", android.util.Base64.encodeToString(publicKey, android.util.Base64.NO_WRAP))
        put("algorithm", algorithm)
        publicKeyDer?.let {
            put("publicKeyDer", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
        }
        name?.let {
            put("name", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalGetIAKPublicKeyResult {
            return LocalGetIAKPublicKeyResult(
                publicKey = android.util.Base64.decode(obj.getString("publicKey"), android.util.Base64.NO_WRAP),
                algorithm = obj.getString("algorithm"),
                publicKeyDer = if (obj.has("publicKeyDer") && !obj.isNull("publicKeyDer")) {
                    android.util.Base64.decode(obj.getString("publicKeyDer"), android.util.Base64.NO_WRAP)
                } else null,
                name = if (obj.has("name") && !obj.isNull("name")) {
                    android.util.Base64.decode(obj.getString("name"), android.util.Base64.NO_WRAP)
                } else null
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalGetIAKPublicKeyResult

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (algorithm != other.algorithm) return false
        if (publicKeyDer != null) {
            if (other.publicKeyDer == null) return false
            if (!publicKeyDer.contentEquals(other.publicKeyDer)) return false
        } else if (other.publicKeyDer != null) return false
        if (name != null) {
            if (other.name == null) return false
            if (!name.contentEquals(other.name)) return false
        } else if (other.name != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (publicKeyDer?.contentHashCode() ?: 0)
        result = 31 * result + (name?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * Parameters for local.storeEnrollmentCerts method.
 *
 * The CA calls this after successful enrollment to provision the device with
 * its identity certificates. These certificates enable future attestation operations.
 *
 * @property iakCert X.509 certificate for the Initial Attestation Key (DER-encoded).
 *                   Used to sign future attestation quotes.
 * @property idevidCert X.509 certificate for the Initial Device Identity Key (DER-encoded).
 *                      Provides the device's permanent cryptographic identity.
 * @property chain Intermediate CA certificates (DER-encoded) in order from issuer to root.
 *                 Allows the device to present a complete certificate chain.
 */
data class LocalStoreEnrollmentCertsParams(
    val iakCert: ByteArray,
    val idevidCert: ByteArray,
    val chain: List<ByteArray>? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("iakCert", android.util.Base64.encodeToString(iakCert, android.util.Base64.NO_WRAP))
        put("idevidCert", android.util.Base64.encodeToString(idevidCert, android.util.Base64.NO_WRAP))
        chain?.let { chainList ->
            put("chain", JSONArray(chainList.map { cert ->
                android.util.Base64.encodeToString(cert, android.util.Base64.NO_WRAP)
            }))
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalStoreEnrollmentCertsParams {
            val iakCertB64 = obj.getStringOrNull("iakCert")
                ?: throw ProtocolException("Missing 'iakCert' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val idevidCertB64 = obj.getStringOrNull("idevidCert")
                ?: throw ProtocolException("Missing 'idevidCert' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val chainArray = obj.optJSONArray("chain")
            val chain = if (chainArray != null) {
                (0 until chainArray.length()).map { i ->
                    android.util.Base64.decode(chainArray.getString(i), android.util.Base64.NO_WRAP)
                }
            } else null
            return LocalStoreEnrollmentCertsParams(
                iakCert = android.util.Base64.decode(iakCertB64, android.util.Base64.NO_WRAP),
                idevidCert = android.util.Base64.decode(idevidCertB64, android.util.Base64.NO_WRAP),
                chain = chain
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalStoreEnrollmentCertsParams

        if (!iakCert.contentEquals(other.iakCert)) return false
        if (!idevidCert.contentEquals(other.idevidCert)) return false
        if (chain != null) {
            if (other.chain == null) return false
            if (chain.size != other.chain.size) return false
            for (i in chain.indices) {
                if (!chain[i].contentEquals(other.chain[i])) return false
            }
        } else if (other.chain != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = iakCert.contentHashCode()
        result = 31 * result + idevidCert.contentHashCode()
        result = 31 * result + (chain?.fold(0) { acc, bytes -> acc + bytes.contentHashCode() } ?: 0)
        return result
    }
}

/**
 * Result of local.storeEnrollmentCerts method.
 *
 * Confirms whether the enrollment certificates were successfully stored on the device.
 *
 * @property stored Whether the certificates were successfully stored.
 * @property iakCertFingerprint SHA-256 fingerprint of the stored IAK certificate (hex-encoded).
 * @property idevidCertFingerprint SHA-256 fingerprint of the stored IDevID certificate (hex-encoded).
 */
data class LocalStoreEnrollmentCertsResult(
    val stored: Boolean,
    val iakCertFingerprint: String? = null,
    val idevidCertFingerprint: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("stored", stored)
        iakCertFingerprint?.let { put("iakCertFingerprint", it) }
        idevidCertFingerprint?.let { put("idevidCertFingerprint", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): LocalStoreEnrollmentCertsResult {
            return LocalStoreEnrollmentCertsResult(
                stored = obj.getBoolean("stored"),
                iakCertFingerprint = if (obj.has("iakCertFingerprint") && !obj.isNull("iakCertFingerprint")) {
                    obj.getString("iakCertFingerprint")
                } else null,
                idevidCertFingerprint = if (obj.has("idevidCertFingerprint") && !obj.isNull("idevidCertFingerprint")) {
                    obj.getString("idevidCertFingerprint")
                } else null
            )
        }
    }
}

// ============================================================
// TCG-CSR-IDEVID enrollment, phone as Certificate Authority
// (Corresponds to xkey/pkg/pairing/protocol_remote.go and
//  xkey/pkg/pairing/protocol_attestation.go on the desktop.)
//
// The JSON tags below are the wire contract. The Kotlin here and the Go there
// share no generated code, so a renamed key is a silent break: it deserializes
// to a zero value on the far side rather than failing.
// ============================================================

/**
 * Parameters for remote.getTCGCSRIDevID.
 *
 * @property backend Names the desktop's hardware backend. Omitted means "tpm2".
 */
data class RemoteGetTCGCSRIDevIDParams(
    val backend: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        backend?.let { put("backend", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteGetTCGCSRIDevIDParams =
            RemoteGetTCGCSRIDevIDParams(backend = obj.getStringOrNull("backend"))
    }
}

/**
 * Result of remote.getTCGCSRIDevID: the desktop's complete enrollment package.
 *
 * Both public keys arrive here, in TPM2B_PUBLIC form with no size prefix, which
 * is why the ceremony needs no separate key-fetch step. The CA verifies the CSR
 * signature with [idevidPublicKey] and binds its credential challenge to the
 * Name computed from [iakPublicKey].
 *
 * @property csr Packed TCG-CSR-IDEVID (TCG DevID specification, Section 13.1).
 * @property ekCert DER endorsement key certificate; absent when the TPM carries none.
 * @property iakPublicKey Initial Attestation Key public area.
 * @property idevidPublicKey Initial Device Identity Key public area.
 * @property platformManufacturer TPM manufacturer identifier.
 * @property platformModel Platform model, as the CSR reports it.
 * @property platformSerial Platform serial, as the CSR reports it.
 */
data class RemoteGetTCGCSRIDevIDResult(
    val csr: ByteArray,
    val ekCert: ByteArray? = null,
    val iakPublicKey: ByteArray,
    val idevidPublicKey: ByteArray,
    val platformManufacturer: String = "",
    val platformModel: String = "",
    val platformSerial: String = ""
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("csr", android.util.Base64.encodeToString(csr, android.util.Base64.NO_WRAP))
        ekCert?.let {
            put("ekCert", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
        }
        put("iakPublicKey", android.util.Base64.encodeToString(iakPublicKey, android.util.Base64.NO_WRAP))
        put("idevidPublicKey", android.util.Base64.encodeToString(idevidPublicKey, android.util.Base64.NO_WRAP))
        put("platformManufacturer", platformManufacturer)
        put("platformModel", platformModel)
        put("platformSerial", platformSerial)
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteGetTCGCSRIDevIDResult {
            val csrB64 = obj.getStringOrNull("csr")
                ?: throw ProtocolException("Missing 'csr' in result", errorCode = ErrorCodes.INVALID_PARAMS)
            val iakB64 = obj.getStringOrNull("iakPublicKey")
                ?: throw ProtocolException("Missing 'iakPublicKey' in result", errorCode = ErrorCodes.INVALID_PARAMS)
            val idevidB64 = obj.getStringOrNull("idevidPublicKey")
                ?: throw ProtocolException("Missing 'idevidPublicKey' in result", errorCode = ErrorCodes.INVALID_PARAMS)
            return RemoteGetTCGCSRIDevIDResult(
                csr = android.util.Base64.decode(csrB64, android.util.Base64.NO_WRAP),
                ekCert = obj.getStringOrNull("ekCert")?.let {
                    android.util.Base64.decode(it, android.util.Base64.NO_WRAP)
                },
                iakPublicKey = android.util.Base64.decode(iakB64, android.util.Base64.NO_WRAP),
                idevidPublicKey = android.util.Base64.decode(idevidB64, android.util.Base64.NO_WRAP),
                platformManufacturer = obj.getStringOrNull("platformManufacturer") ?: "",
                platformModel = obj.getStringOrNull("platformModel") ?: "",
                platformSerial = obj.getStringOrNull("platformSerial") ?: ""
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RemoteGetTCGCSRIDevIDResult

        if (!csr.contentEquals(other.csr)) return false
        if (ekCert != null) {
            if (other.ekCert == null) return false
            if (!ekCert.contentEquals(other.ekCert)) return false
        } else if (other.ekCert != null) return false
        if (!iakPublicKey.contentEquals(other.iakPublicKey)) return false
        if (!idevidPublicKey.contentEquals(other.idevidPublicKey)) return false
        if (platformManufacturer != other.platformManufacturer) return false
        if (platformModel != other.platformModel) return false
        if (platformSerial != other.platformSerial) return false

        return true
    }

    override fun hashCode(): Int {
        var result = csr.contentHashCode()
        result = 31 * result + (ekCert?.contentHashCode() ?: 0)
        result = 31 * result + iakPublicKey.contentHashCode()
        result = 31 * result + idevidPublicKey.contentHashCode()
        result = 31 * result + platformManufacturer.hashCode()
        result = 31 * result + platformModel.hashCode()
        result = 31 * result + platformSerial.hashCode()
        return result
    }
}

/**
 * Parameters for remote.activateCredential: the CA's TPM2_MakeCredential
 * challenge.
 *
 * @property backend Names the desktop's hardware backend. Omitted means "tpm2".
 * @property credentialBlob TPMS_ID_OBJECT contents, bound to the IAK Name.
 * @property encryptedSecret The seed encrypted to the endorsement key.
 */
data class RemoteActivateCredentialParams(
    val credentialBlob: ByteArray,
    val encryptedSecret: ByteArray,
    val backend: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        backend?.let { put("backend", it) }
        put("credentialBlob", android.util.Base64.encodeToString(credentialBlob, android.util.Base64.NO_WRAP))
        put("encryptedSecret", android.util.Base64.encodeToString(encryptedSecret, android.util.Base64.NO_WRAP))
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteActivateCredentialParams {
            val blobB64 = obj.getStringOrNull("credentialBlob")
                ?: throw ProtocolException("Missing 'credentialBlob' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val secretB64 = obj.getStringOrNull("encryptedSecret")
                ?: throw ProtocolException("Missing 'encryptedSecret' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            return RemoteActivateCredentialParams(
                credentialBlob = android.util.Base64.decode(blobB64, android.util.Base64.NO_WRAP),
                encryptedSecret = android.util.Base64.decode(secretB64, android.util.Base64.NO_WRAP),
                backend = obj.getStringOrNull("backend")
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RemoteActivateCredentialParams

        if (!credentialBlob.contentEquals(other.credentialBlob)) return false
        if (!encryptedSecret.contentEquals(other.encryptedSecret)) return false
        if (backend != other.backend) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credentialBlob.contentHashCode()
        result = 31 * result + encryptedSecret.contentHashCode()
        result = 31 * result + (backend?.hashCode() ?: 0)
        return result
    }
}

/**
 * Result of remote.activateCredential.
 *
 * @property decryptedSecret What the desktop's TPM recovered. The CA requires
 *   this to equal the secret it generated; anything else fails enrollment.
 */
data class RemoteActivateCredentialResult(
    val decryptedSecret: ByteArray
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("decryptedSecret", android.util.Base64.encodeToString(decryptedSecret, android.util.Base64.NO_WRAP))
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteActivateCredentialResult {
            val b64 = obj.getStringOrNull("decryptedSecret")
                ?: throw ProtocolException("Missing 'decryptedSecret' in result", errorCode = ErrorCodes.INVALID_PARAMS)
            return RemoteActivateCredentialResult(
                decryptedSecret = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as RemoteActivateCredentialResult
        return decryptedSecret.contentEquals(other.decryptedSecret)
    }

    override fun hashCode(): Int = decryptedSecret.contentHashCode()
}

/**
 * Parameters for remote.getAttestationQuote.
 *
 * @property backend Names the desktop's hardware backend. Omitted means "tpm2".
 * @property nonce Fresh random challenge; the desktop echoes it back.
 * @property pcrIndices PCR registers to quote.
 * @property pcrBank PCR hash bank. Omitted means "sha256". The desktop refuses
 *   a bank other than the attestation key's own.
 */
data class RemoteGetAttestationQuoteParams(
    val nonce: ByteArray,
    val pcrIndices: List<Int>,
    val pcrBank: String? = null,
    val backend: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        backend?.let { put("backend", it) }
        put("nonce", android.util.Base64.encodeToString(nonce, android.util.Base64.NO_WRAP))
        put("pcrIndices", JSONArray(pcrIndices))
        pcrBank?.let { put("pcrBank", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteGetAttestationQuoteParams {
            val nonceB64 = obj.getStringOrNull("nonce")
                ?: throw ProtocolException("Missing 'nonce' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val pcrArray = obj.optJSONArray("pcrIndices")
                ?: throw ProtocolException("Missing 'pcrIndices' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val indices = (0 until pcrArray.length()).map { pcrArray.getInt(it) }
            return RemoteGetAttestationQuoteParams(
                nonce = android.util.Base64.decode(nonceB64, android.util.Base64.NO_WRAP),
                pcrIndices = indices,
                pcrBank = obj.getStringOrNull("pcrBank"),
                backend = obj.getStringOrNull("backend")
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RemoteGetAttestationQuoteParams

        if (!nonce.contentEquals(other.nonce)) return false
        if (pcrIndices != other.pcrIndices) return false
        if (pcrBank != other.pcrBank) return false
        if (backend != other.backend) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nonce.contentHashCode()
        result = 31 * result + pcrIndices.hashCode()
        result = 31 * result + (pcrBank?.hashCode() ?: 0)
        result = 31 * result + (backend?.hashCode() ?: 0)
        return result
    }
}

/**
 * Result of remote.getAttestationQuote.
 *
 * Unlike its `local.*` twin this carries no event log: the desktop bridge does
 * not send one.
 *
 * @property quoted TPMS_ATTEST structure signed by the IAK.
 * @property signature The IAK's signature over [quoted].
 * @property pcrValues PCR digests keyed by register index.
 * @property pcrBank The bank the values came from.
 * @property nonce The challenge, echoed. A CA that does not compare this to
 *   what it sent is accepting replays.
 */
data class RemoteGetAttestationQuoteResult(
    val quoted: ByteArray,
    val signature: ByteArray,
    val pcrValues: Map<Int, ByteArray>,
    val pcrBank: String,
    val nonce: ByteArray
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("quoted", android.util.Base64.encodeToString(quoted, android.util.Base64.NO_WRAP))
        put("signature", android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP))
        val values = JSONObject()
        pcrValues.forEach { (index, value) ->
            values.put(index.toString(), android.util.Base64.encodeToString(value, android.util.Base64.NO_WRAP))
        }
        put("pcrValues", values)
        put("pcrBank", pcrBank)
        put("nonce", android.util.Base64.encodeToString(nonce, android.util.Base64.NO_WRAP))
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteGetAttestationQuoteResult {
            val quotedB64 = obj.getStringOrNull("quoted")
                ?: throw ProtocolException("Missing 'quoted' in result", errorCode = ErrorCodes.INVALID_PARAMS)
            val signatureB64 = obj.getStringOrNull("signature")
                ?: throw ProtocolException("Missing 'signature' in result", errorCode = ErrorCodes.INVALID_PARAMS)
            val nonceB64 = obj.getStringOrNull("nonce")
                ?: throw ProtocolException("Missing 'nonce' in result", errorCode = ErrorCodes.INVALID_PARAMS)
            val valuesObj = obj.optJSONObject("pcrValues")
            val values = mutableMapOf<Int, ByteArray>()
            valuesObj?.keys()?.forEach { key ->
                values[key.toInt()] =
                    android.util.Base64.decode(valuesObj.getString(key), android.util.Base64.NO_WRAP)
            }
            return RemoteGetAttestationQuoteResult(
                quoted = android.util.Base64.decode(quotedB64, android.util.Base64.NO_WRAP),
                signature = android.util.Base64.decode(signatureB64, android.util.Base64.NO_WRAP),
                pcrValues = values,
                pcrBank = obj.getStringOrNull("pcrBank") ?: "",
                nonce = android.util.Base64.decode(nonceB64, android.util.Base64.NO_WRAP)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RemoteGetAttestationQuoteResult

        if (!quoted.contentEquals(other.quoted)) return false
        if (!signature.contentEquals(other.signature)) return false
        if (pcrValues.size != other.pcrValues.size) return false
        for ((key, value) in pcrValues) {
            val otherValue = other.pcrValues[key] ?: return false
            if (!value.contentEquals(otherValue)) return false
        }
        if (pcrBank != other.pcrBank) return false
        if (!nonce.contentEquals(other.nonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = quoted.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + pcrValues.entries.fold(0) { acc, entry ->
            acc + entry.key.hashCode() + entry.value.contentHashCode()
        }
        result = 31 * result + pcrBank.hashCode()
        result = 31 * result + nonce.contentHashCode()
        return result
    }
}

/**
 * Parameters for remote.storeEnrollmentCerts: the certificates this phone
 * issued, handed back for provisioning into the desktop's TPM.
 *
 * @property backend Names the desktop's hardware backend. Omitted means "tpm2".
 * @property iakCert DER Initial Attestation Key certificate.
 * @property idevidCert DER Initial Device Identity certificate.
 * @property chain DER intermediates. The desktop parses them but stores only
 *   the two leaves.
 */
data class RemoteStoreEnrollmentCertsParams(
    val iakCert: ByteArray,
    val idevidCert: ByteArray,
    val chain: List<ByteArray>? = null,
    val backend: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        backend?.let { put("backend", it) }
        put("iakCert", android.util.Base64.encodeToString(iakCert, android.util.Base64.NO_WRAP))
        put("idevidCert", android.util.Base64.encodeToString(idevidCert, android.util.Base64.NO_WRAP))
        chain?.let { certs ->
            put("chain", JSONArray(certs.map {
                android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)
            }))
        }
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteStoreEnrollmentCertsParams {
            val iakB64 = obj.getStringOrNull("iakCert")
                ?: throw ProtocolException("Missing 'iakCert' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val idevidB64 = obj.getStringOrNull("idevidCert")
                ?: throw ProtocolException("Missing 'idevidCert' parameter", errorCode = ErrorCodes.INVALID_PARAMS)
            val chainArray = obj.optJSONArray("chain")
            val chain = if (chainArray != null) {
                (0 until chainArray.length()).map {
                    android.util.Base64.decode(chainArray.getString(it), android.util.Base64.NO_WRAP)
                }
            } else null
            return RemoteStoreEnrollmentCertsParams(
                iakCert = android.util.Base64.decode(iakB64, android.util.Base64.NO_WRAP),
                idevidCert = android.util.Base64.decode(idevidB64, android.util.Base64.NO_WRAP),
                chain = chain,
                backend = obj.getStringOrNull("backend")
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RemoteStoreEnrollmentCertsParams

        if (!iakCert.contentEquals(other.iakCert)) return false
        if (!idevidCert.contentEquals(other.idevidCert)) return false
        if (chain != null) {
            if (other.chain == null) return false
            if (chain.size != other.chain.size) return false
            for (i in chain.indices) {
                if (!chain[i].contentEquals(other.chain[i])) return false
            }
        } else if (other.chain != null) return false
        if (backend != other.backend) return false

        return true
    }

    override fun hashCode(): Int {
        var result = iakCert.contentHashCode()
        result = 31 * result + idevidCert.contentHashCode()
        result = 31 * result + (chain?.fold(0) { acc, bytes -> acc + bytes.contentHashCode() } ?: 0)
        result = 31 * result + (backend?.hashCode() ?: 0)
        return result
    }
}

/**
 * Result of remote.storeEnrollmentCerts.
 *
 * @property stored Whether both certificates reached the desktop's TPM.
 * @property iakCertFingerprint Hex SHA-256 digest of the stored IAK certificate.
 * @property idevidCertFingerprint Hex SHA-256 digest of the stored IDevID certificate.
 */
data class RemoteStoreEnrollmentCertsResult(
    val stored: Boolean,
    val iakCertFingerprint: String? = null,
    val idevidCertFingerprint: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("stored", stored)
        iakCertFingerprint?.let { put("iakCertFingerprint", it) }
        idevidCertFingerprint?.let { put("idevidCertFingerprint", it) }
    }

    companion object {
        fun fromJson(obj: JSONObject): RemoteStoreEnrollmentCertsResult =
            RemoteStoreEnrollmentCertsResult(
                stored = obj.optBoolean("stored", false),
                iakCertFingerprint = obj.getStringOrNull("iakCertFingerprint"),
                idevidCertFingerprint = obj.getStringOrNull("idevidCertFingerprint")
            )
    }
}
