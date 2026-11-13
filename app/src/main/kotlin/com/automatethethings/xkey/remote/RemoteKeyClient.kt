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
package com.automatethethings.xkey.remote

import android.util.Log
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.protocol.RemoteAttestDeviceParams
import com.automatethethings.xkey.protocol.RemoteAttestDeviceResult
import com.automatethethings.xkey.protocol.RemoteAttestKeyParams
import com.automatethethings.xkey.protocol.RemoteAttestKeyResult
import com.automatethethings.xkey.protocol.RemoteBackendInfo
import com.automatethethings.xkey.protocol.RemoteDecryptParams
import com.automatethethings.xkey.protocol.RemoteDecryptResult
import com.automatethethings.xkey.protocol.RemoteDeleteKeyParams
import com.automatethethings.xkey.protocol.RemoteDeleteKeyResult
import com.automatethethings.xkey.protocol.RemoteDeriveKeyParams
import com.automatethethings.xkey.protocol.RemoteDeriveKeyResult
import com.automatethethings.xkey.protocol.RemoteEncryptParams
import com.automatethethings.xkey.protocol.RemoteEncryptResult
import com.automatethethings.xkey.protocol.RemoteGenerateKeyParams
import com.automatethethings.xkey.protocol.RemoteGenerateKeyResult
import com.automatethethings.xkey.protocol.RemoteGetKeyInfoParams
import com.automatethethings.xkey.protocol.RemoteGetKeyInfoResult
import com.automatethethings.xkey.protocol.RemoteGetPublicKeyParams
import com.automatethethings.xkey.protocol.RemoteGetPublicKeyResult
import com.automatethethings.xkey.protocol.RemoteKeyInfo
import com.automatethethings.xkey.protocol.RemoteListBackendsResult
import com.automatethethings.xkey.protocol.RemoteListKeysParams
import com.automatethethings.xkey.protocol.RemoteListKeysResult
import com.automatethethings.xkey.protocol.RemoteSignParams
import com.automatethethings.xkey.protocol.RemoteSignResult
import com.automatethethings.xkey.protocol.RemoteVerifyParams
import com.automatethethings.xkey.protocol.RemoteVerifyResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * Client for sending outbound `remote.*` JSON-RPC requests to the laptop's
 * xkmsd backends over the existing Noise-encrypted channel.
 *
 * This enables the phone to use keys managed by the laptop (TPM2, PKCS#11,
 * software, cloud KMS) through the same secure channel used for BLE/USB
 * communication.
 *
 * All methods are suspend functions and block until the laptop responds or
 * the request times out.
 *
 * Thread safety: Request IDs use [AtomicLong] for lock-free generation.
 * Pending requests are tracked by [BidirectionalMessageRouter].
 *
 * @param desktop The laptop's established session: a sender bound to its
 *   connection and the router that correlates responses with requests.
 * @param requestTimeoutMs Timeout for each request in milliseconds (default: 30s).
 */
class RemoteKeyClient(
    desktop: ConnectedDesktop,
    private val requestTimeoutMs: Long = 30_000L
) {
    /** Bound to [desktop]'s connection: a reply-awaiting call never reaches another desktop. */
    private val messageSender: MessageSender = desktop.sender
    private val messageRouter: BidirectionalMessageRouter = desktop.router
    companion object {
        private const val TAG = "RemoteKeyClient"

        /**
         * Starting ID for outbound requests. High value avoids collision
         * with the laptop's request IDs which start from 1.
         */
        private const val BASE_REQUEST_ID = 1_000_000L

        /** Known attestation formats for sanity-check validation. */
        private val knownAttestationFormats = setOf("tpm2", "pkcs11", "software")
    }

    private val nextRequestId = AtomicLong(BASE_REQUEST_ID)

    /**
     * Sends a JSON-RPC request and waits for the response.
     *
     * @param method The JSON-RPC method name (e.g., "remote.listBackends").
     * @param params Optional method parameters.
     * @return The successful response.
     * @throws ProtocolException if the response is an error or times out.
     */
    private suspend fun sendRequest(method: String, params: JSONObject? = null): Response {
        val id = nextRequestId.getAndIncrement()
        val request = Request(id, method, params)
        val deferred = CompletableDeferred<Response>()

        messageRouter.registerPendingResponse(id, deferred)

        try {
            Log.d(TAG, "Sending request: id=$id, method=$method")
            messageSender.sendEncryptedMessage(request.toJson())

            val response = withTimeout(requestTimeoutMs) { deferred.await() }

            if (response.isError()) {
                val error = response.error!!
                throw ProtocolException(
                    "Remote error: ${error.message}",
                    errorCode = error.code
                )
            }

            return response
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            Log.e(TAG, "Request timed out: id=$id, method=$method")
            throw ProtocolException(
                "Request timed out: $method",
                errorCode = ErrorCodes.INTERNAL_ERROR
            )
        } finally {
            messageRouter.removePendingResponse(id)
        }
    }

    // ================================================================
    // Public API methods
    // ================================================================

    /**
     * Lists all available xkmsd backends on the laptop.
     *
     * @return Information about each available backend.
     */
    suspend fun listBackends(): List<RemoteBackendInfo> {
        val response = sendRequest(MethodNames.REMOTE_LIST_BACKENDS)
        val result = RemoteListBackendsResult.fromJson(response.result!!)
        return result.backends
    }

    /**
     * Lists keys in a specific xkmsd backend.
     *
     * @param backend The backend name (e.g., "tpm2", "software").
     * @param algorithm Optional algorithm filter.
     * @return List of keys in the backend.
     */
    suspend fun listKeys(backend: String, algorithm: String? = null): List<RemoteKeyInfo> {
        val params = RemoteListKeysParams(backend = backend, algorithm = algorithm)
        val response = sendRequest(MethodNames.REMOTE_LIST_KEYS, params.toJson())
        val result = RemoteListKeysResult.fromJson(response.result!!)
        return result.keys
    }

    /**
     * Gets the public key of a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param format The export format ("der" or "pem").
     * @return The public key and metadata.
     */
    suspend fun getPublicKey(
        backend: String,
        keyId: String,
        format: String = "der"
    ): RemoteGetPublicKeyResult {
        val params = RemoteGetPublicKeyParams(backend = backend, keyId = keyId, format = format)
        val response = sendRequest(MethodNames.REMOTE_GET_PUBLIC_KEY, params.toJson())
        return RemoteGetPublicKeyResult.fromJson(response.result!!)
    }

    /**
     * Signs data with a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param data Base64-encoded data to sign.
     * @param algorithm Optional algorithm override.
     * @return The signature and algorithm used.
     */
    suspend fun sign(
        backend: String,
        keyId: String,
        data: String,
        algorithm: String? = null
    ): RemoteSignResult {
        val params = RemoteSignParams(
            backend = backend, keyId = keyId, data = data, algorithm = algorithm
        )
        val response = sendRequest(MethodNames.REMOTE_SIGN, params.toJson())
        return RemoteSignResult.fromJson(response.result!!)
    }

    /**
     * Verifies a signature with a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param data Base64-encoded signed data.
     * @param signature Base64-encoded signature.
     * @param algorithm Optional algorithm override.
     * @return Whether the signature is valid.
     */
    suspend fun verify(
        backend: String,
        keyId: String,
        data: String,
        signature: String,
        algorithm: String? = null
    ): Boolean {
        val params = RemoteVerifyParams(
            backend = backend, keyId = keyId, data = data,
            signature = signature, algorithm = algorithm
        )
        val response = sendRequest(MethodNames.REMOTE_VERIFY, params.toJson())
        val result = RemoteVerifyResult.fromJson(response.result!!)
        return result.valid
    }

    /**
     * Encrypts data with a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param plaintext Base64-encoded plaintext.
     * @param algorithm Optional algorithm override.
     * @param aad Optional Base64-encoded additional authenticated data.
     * @return Base64-encoded ciphertext.
     */
    suspend fun encrypt(
        backend: String,
        keyId: String,
        plaintext: String,
        algorithm: String? = null,
        aad: String? = null
    ): String {
        val params = RemoteEncryptParams(
            backend = backend, keyId = keyId, plaintext = plaintext,
            algorithm = algorithm, aad = aad
        )
        val response = sendRequest(MethodNames.REMOTE_ENCRYPT, params.toJson())
        val result = RemoteEncryptResult.fromJson(response.result!!)
        return result.ciphertext
    }

    /**
     * Decrypts data with a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param ciphertext Base64-encoded ciphertext.
     * @param algorithm Optional algorithm override.
     * @param aad Optional Base64-encoded additional authenticated data.
     * @return Base64-encoded plaintext.
     */
    suspend fun decrypt(
        backend: String,
        keyId: String,
        ciphertext: String,
        algorithm: String? = null,
        aad: String? = null
    ): String {
        val params = RemoteDecryptParams(
            backend = backend, keyId = keyId, ciphertext = ciphertext,
            algorithm = algorithm, aad = aad
        )
        val response = sendRequest(MethodNames.REMOTE_DECRYPT, params.toJson())
        val result = RemoteDecryptResult.fromJson(response.result!!)
        return result.plaintext
    }

    /**
     * Performs ECDH key agreement with a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param peerPublicKey Base64-encoded DER peer public key.
     * @return Base64-encoded shared secret.
     */
    suspend fun deriveKey(
        backend: String,
        keyId: String,
        peerPublicKey: String
    ): String {
        val params = RemoteDeriveKeyParams(
            backend = backend, keyId = keyId, peerPublicKey = peerPublicKey
        )
        val response = sendRequest(MethodNames.REMOTE_DERIVE_KEY, params.toJson())
        val result = RemoteDeriveKeyResult.fromJson(response.result!!)
        return result.sharedSecret
    }

    /**
     * Generates a new key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param algorithm The algorithm (e.g., "ecdsa-p256", "rsa-2048").
     * @param keySizeBits Optional key size in bits.
     * @param label Optional human-readable label.
     * @return The generated key information.
     */
    suspend fun generateKey(
        backend: String,
        keyId: String,
        algorithm: String,
        keySizeBits: Int = 0,
        label: String? = null
    ): RemoteGenerateKeyResult {
        val params = RemoteGenerateKeyParams(
            backend = backend, keyId = keyId, algorithm = algorithm,
            keySizeBits = keySizeBits, label = label
        )
        val response = sendRequest(MethodNames.REMOTE_GENERATE_KEY, params.toJson())
        return RemoteGenerateKeyResult.fromJson(response.result!!)
    }

    /**
     * Gets detailed information about a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @return Detailed key information.
     */
    suspend fun getKeyInfo(backend: String, keyId: String): RemoteGetKeyInfoResult {
        val params = RemoteGetKeyInfoParams(backend = backend, keyId = keyId)
        val response = sendRequest(MethodNames.REMOTE_GET_KEY_INFO, params.toJson())
        return RemoteGetKeyInfoResult.fromJson(response.result!!)
    }

    /**
     * Deletes a key from a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @return True if the key was deleted.
     */
    suspend fun deleteKey(backend: String, keyId: String): Boolean {
        val params = RemoteDeleteKeyParams(backend = backend, keyId = keyId)
        val response = sendRequest(MethodNames.REMOTE_DELETE_KEY, params.toJson())
        val result = RemoteDeleteKeyResult.fromJson(response.result!!)
        return result.deleted
    }

    /**
     * Requests attestation for a key in a xkmsd backend.
     *
     * @param backend The backend name.
     * @param keyId The key identifier.
     * @param nonce Base64-encoded challenge nonce.
     * @return The attestation result with certificate chain.
     */
    suspend fun attestKey(
        backend: String,
        keyId: String,
        nonce: String
    ): RemoteAttestKeyResult {
        val params = RemoteAttestKeyParams(backend = backend, keyId = keyId, nonce = nonce)
        val response = sendRequest(MethodNames.REMOTE_ATTEST_KEY, params.toJson())
        val result = RemoteAttestKeyResult.fromJson(response.result!!)

        verifyAttestationResult(result, nonce)

        return result
    }

    /**
     * Requests device-level attestation from the connected laptop/desktop.
     *
     * This provides information about the laptop's security posture, including
     * whether hardware security (TPM2) is available and a stable device fingerprint
     * for trust tracking.
     *
     * @param nonce Base64-encoded 32-byte challenge nonce.
     * @return The device attestation result.
     */
    suspend fun attestDevice(nonce: String): RemoteAttestDeviceResult {
        val params = RemoteAttestDeviceParams(nonce = nonce)
        val response = sendRequest(MethodNames.REMOTE_ATTEST_DEVICE, params.toJson())
        val result = RemoteAttestDeviceResult.fromJson(response.result!!)

        verifyDeviceAttestationResult(result, nonce)

        return result
    }

    // ================================================================
    // Attestation verification
    // ================================================================

    /**
     * Verifies basic integrity of an attestation result from the laptop.
     *
     * Checks nonce freshness, certificate chain presence, format validity,
     * and certificate parsability. Full cryptographic chain verification
     * (e.g., verifying TPM2 EK cert roots to a manufacturer CA) is performed
     * on the Go side.
     *
     * @param result The attestation result to verify.
     * @param expectedNonce The nonce that was sent in the request.
     * @throws ProtocolException if verification fails.
     */
    private fun verifyAttestationResult(result: RemoteAttestKeyResult, expectedNonce: String) {
        // 1. Nonce freshness: the echoed nonce must match what we sent
        if (result.nonce != expectedNonce) {
            throw ProtocolException(
                "Attestation nonce mismatch: expected echoed nonce does not match request",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }

        // 2. Certificate chain must be present
        if (result.certificateChain.isEmpty()) {
            throw ProtocolException(
                "Attestation certificate chain is empty",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }

        // 3. Format validation: warn on unknown formats but allow forward compatibility
        val format = result.format
        if (format.isEmpty()) {
            throw ProtocolException(
                "Attestation format is empty",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }
        if (format !in knownAttestationFormats) {
            Log.w(TAG, "Unknown attestation format: $format (known: $knownAttestationFormats)")
        }

        // 4. Parse each certificate to ensure the chain contains valid X.509 certs
        val certFactory = CertificateFactory.getInstance("X.509")
        val decoder = Base64.getDecoder()
        for ((index, certBase64) in result.certificateChain.withIndex()) {
            try {
                val certBytes = decoder.decode(certBase64)
                certFactory.generateCertificate(ByteArrayInputStream(certBytes))
            } catch (e: IllegalArgumentException) {
                throw ProtocolException(
                    "Attestation certificate at index $index has invalid Base64 encoding",
                    cause = e,
                    errorCode = ErrorCodes.ATTESTATION_FAILED
                )
            } catch (e: java.security.cert.CertificateException) {
                throw ProtocolException(
                    "Attestation certificate at index $index is not a valid X.509 certificate",
                    cause = e,
                    errorCode = ErrorCodes.ATTESTATION_FAILED
                )
            }
        }
    }

    /**
     * Verifies basic integrity of a device attestation result from the laptop.
     *
     * Device attestation is simpler than key attestation - it verifies nonce
     * freshness and validates the format. Certificate chain is optional for
     * software-only laptops.
     *
     * @param result The device attestation result to verify.
     * @param expectedNonce The nonce that was sent in the request.
     * @throws ProtocolException if verification fails.
     */
    private fun verifyDeviceAttestationResult(result: RemoteAttestDeviceResult, expectedNonce: String) {
        // 1. Nonce freshness: the echoed nonce must match what we sent
        if (result.nonce != expectedNonce) {
            throw ProtocolException(
                "Device attestation nonce mismatch: expected echoed nonce does not match request",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }

        // 2. Format validation
        val format = result.format
        if (format.isEmpty()) {
            throw ProtocolException(
                "Device attestation format is empty",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }

        // 3. Security level must be present
        val securityLevel = result.securityLevel
        if (securityLevel.isEmpty()) {
            throw ProtocolException(
                "Device attestation security level is empty",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }

        Log.d(TAG, "Device attestation verified: format=$format, securityLevel=$securityLevel")
    }
}
