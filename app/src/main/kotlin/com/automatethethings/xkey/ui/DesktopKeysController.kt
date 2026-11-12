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
package com.automatethethings.xkey.ui

import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.RemoteAttestKeyResult
import com.automatethethings.xkey.protocol.RemoteBackendInfo
import com.automatethethings.xkey.protocol.RemoteGetKeyInfoResult
import com.automatethethings.xkey.protocol.RemoteGetPublicKeyResult
import com.automatethethings.xkey.protocol.RemoteKeyInfo
import com.automatethethings.xkey.protocol.RemoteSignResult
import com.automatethethings.xkey.remote.RemoteKeyClient
import kotlinx.coroutines.CancellationException
import java.io.IOException
import java.security.SecureRandom
import java.util.Base64

/**
 * The `remote.*` calls the desktop keys screen makes. [of] adapts the real
 * [RemoteKeyClient]; tests supply a fake.
 */
interface DesktopKeysSource {
    suspend fun listBackends(): List<RemoteBackendInfo>
    suspend fun listKeys(backend: String): List<RemoteKeyInfo>
    suspend fun getKeyInfo(backend: String, keyId: String): RemoteGetKeyInfoResult
    suspend fun getPublicKey(backend: String, keyId: String): RemoteGetPublicKeyResult
    suspend fun sign(backend: String, keyId: String, data: String): RemoteSignResult
    suspend fun verify(backend: String, keyId: String, data: String, signature: String, algorithm: String): Boolean
    suspend fun attestKey(backend: String, keyId: String, nonce: String): RemoteAttestKeyResult

    companion object {
        /** The source that sends each call to the desktop through [client]. */
        fun of(client: RemoteKeyClient): DesktopKeysSource = object : DesktopKeysSource {
            override suspend fun listBackends() = client.listBackends()
            override suspend fun listKeys(backend: String) = client.listKeys(backend)
            override suspend fun getKeyInfo(backend: String, keyId: String) = client.getKeyInfo(backend, keyId)
            override suspend fun getPublicKey(backend: String, keyId: String) =
                client.getPublicKey(backend, keyId)
            override suspend fun sign(backend: String, keyId: String, data: String) =
                client.sign(backend, keyId, data)
            override suspend fun verify(
                backend: String, keyId: String, data: String, signature: String, algorithm: String
            ) = client.verify(backend, keyId, data, signature, algorithm)
            override suspend fun attestKey(backend: String, keyId: String, nonce: String) =
                client.attestKey(backend, keyId, nonce)
        }
    }
}

/** A failure the screen shows, typed by what went wrong on the desktop link. */
data class DesktopKeyError(val kind: Kind, val code: Int?, val detail: String) {
    enum class Kind {
        /** No desktop session is up. */
        NOT_CONNECTED,
        /** The desktop knows no such key. */
        KEY_NOT_FOUND,
        /** The desktop or its backend refused the operation. */
        DENIED,
        /** The desktop does not offer this method. */
        UNSUPPORTED,
        /** The key's attestation did not check out. */
        ATTESTATION_FAILED,
        /** Any other error the desktop answered with, or a timeout. */
        REMOTE,
        /** The link failed before an answer came back. */
        TRANSPORT
    }

    companion object {
        /** Maps a thrown failure to the error the screen shows. */
        fun from(e: Exception): DesktopKeyError = when (e) {
            is ProtocolException -> DesktopKeyError(
                when (e.errorCode) {
                    ErrorCodes.KEY_NOT_FOUND -> Kind.KEY_NOT_FOUND
                    ErrorCodes.BACKEND_DENIED, ErrorCodes.OPERATION_DENIED -> Kind.DENIED
                    ErrorCodes.METHOD_NOT_FOUND -> Kind.UNSUPPORTED
                    ErrorCodes.ATTESTATION_FAILED -> Kind.ATTESTATION_FAILED
                    else -> Kind.REMOTE
                },
                e.errorCode,
                e.message ?: ""
            )
            is IOException -> DesktopKeyError(Kind.TRANSPORT, null, e.message ?: e.javaClass.simpleName)
            else -> DesktopKeyError(Kind.REMOTE, null, e.message ?: e.javaClass.simpleName)
        }

        val notConnected = DesktopKeyError(Kind.NOT_CONNECTED, null, "")
    }
}

/** The result of signing [DesktopKeysController.TEST_MESSAGE] and verifying the signature. */
data class SignTestResult(val algorithm: String, val signature: String, val valid: Boolean)

/** The fields of a `remote.attestKey` answer the screen shows. */
data class AttestationSummary(
    val format: String,
    val certificateCount: Int,
    val attestationDataBytes: Int,
    val nonce: String
) {
    companion object {
        fun of(result: RemoteAttestKeyResult) = AttestationSummary(
            format = result.format,
            certificateCount = result.certificateChain.size,
            attestationDataBytes = result.attestationData?.let { decodedLength(it) } ?: 0,
            nonce = result.nonce
        )

        private fun decodedLength(base64: String): Int =
            try {
                Base64.getDecoder().decode(base64).size
            } catch (e: IllegalArgumentException) {
                0
            }
    }
}

/** What the desktop keys screen shows. */
sealed class DesktopKeysState {
    /** No desktop session: nothing can be listed. */
    data object NoSession : DesktopKeysState()

    /** A request is in flight; [previous] is what was shown before it. */
    data class Loading(val previous: DesktopKeysState?) : DesktopKeysState()

    data class Backends(val backends: List<RemoteBackendInfo>) : DesktopKeysState()

    data class Keys(val backend: RemoteBackendInfo, val keys: List<RemoteKeyInfo>) : DesktopKeysState()

    data class Detail(
        val backend: RemoteBackendInfo,
        val info: RemoteGetKeyInfoResult,
        val publicKey: RemoteGetPublicKeyResult,
        val signTest: SignTestResult? = null,
        val attestation: AttestationSummary? = null
    ) : DesktopKeysState()

    /** The last request failed with [error]; [previous] is still on screen. */
    data class Failed(val error: DesktopKeyError, val previous: DesktopKeysState?) : DesktopKeysState()
}

/**
 * The view-free state logic of [DesktopKeysActivity]: backends, then the keys
 * of a backend, then one key's detail with a sign-then-verify test and its
 * attestation.
 *
 * Each step publishes [DesktopKeysState.Loading], then the result or a
 * [DesktopKeysState.Failed] carrying a typed [DesktopKeyError]. Cancellation
 * is rethrown, never shown as a failure.
 *
 * @param source the desktop link, or null while no desktop session is up.
 * @param nonce the attestation challenge, 32 random bytes by default.
 * @param onState called with every state the screen must show.
 */
class DesktopKeysController(
    private val source: () -> DesktopKeysSource?,
    private val nonce: () -> ByteArray = { ByteArray(32).also(SecureRandom()::nextBytes) },
    private val onState: (DesktopKeysState) -> Unit = {}
) {
    companion object {
        /** The fixed message the sign-then-verify test signs. */
        const val TEST_MESSAGE = "xKey desktop key test"

        private val encoder = Base64.getEncoder()
        val TEST_MESSAGE_BASE64: String = encoder.encodeToString(TEST_MESSAGE.toByteArray(Charsets.UTF_8))
    }

    /** The state on screen now. */
    var state: DesktopKeysState = DesktopKeysState.Loading(null)
        private set

    private var backends: DesktopKeysState.Backends? = null
    private var keys: DesktopKeysState.Keys? = null

    /** The content state under any loading or failure, if one is shown. */
    private val content: DesktopKeysState?
        get() = when (val s = state) {
            is DesktopKeysState.Loading -> s.previous
            is DesktopKeysState.Failed -> s.previous
            else -> s
        }

    /** Opens the screen: lists the desktop's backends (`remote.listBackends`). */
    suspend fun open(): DesktopKeysState = run { client ->
        DesktopKeysState.Backends(client.listBackends()).also { backends = it; keys = null }
    }

    /** Lists the keys of [backend] (`remote.listKeys`). */
    suspend fun chooseBackend(backend: RemoteBackendInfo): DesktopKeysState = run { client ->
        DesktopKeysState.Keys(backend, client.listKeys(backend.name)).also { keys = it }
    }

    /** Shows [key]: its info and public key (`remote.getKeyInfo`, `remote.getPublicKey`). */
    suspend fun chooseKey(key: RemoteKeyInfo): DesktopKeysState {
        val backend = keys?.backend ?: return state
        return run { client ->
            DesktopKeysState.Detail(
                backend = backend,
                info = client.getKeyInfo(backend.name, key.keyId),
                publicKey = client.getPublicKey(backend.name, key.keyId)
            )
        }
    }

    /**
     * Signs [TEST_MESSAGE] with the shown key, then asks the desktop to verify
     * the signature with the algorithm it signed with.
     */
    suspend fun signTest(): DesktopKeysState {
        val detail = content as? DesktopKeysState.Detail ?: return state
        return run { client ->
            val keyId = detail.info.keyId
            val signed = client.sign(detail.backend.name, keyId, TEST_MESSAGE_BASE64)
            val valid = client.verify(
                detail.backend.name, keyId, TEST_MESSAGE_BASE64, signed.signature, signed.algorithm
            )
            detail.copy(signTest = SignTestResult(signed.algorithm, signed.signature, valid))
        }
    }

    /** Attests the shown key with a fresh nonce (`remote.attestKey`). */
    suspend fun attest(): DesktopKeysState {
        val detail = content as? DesktopKeysState.Detail ?: return state
        return run { client ->
            val challenge = encoder.encodeToString(nonce())
            val result = client.attestKey(detail.backend.name, detail.info.keyId, challenge)
            detail.copy(attestation = AttestationSummary.of(result))
        }
    }

    /**
     * Goes up one level without a request: detail to keys, keys to backends.
     *
     * @return false when there is no level above, so the screen should close.
     */
    fun back(): Boolean {
        val up = when (content) {
            is DesktopKeysState.Detail -> keys
            is DesktopKeysState.Keys -> backends
            else -> null
        } ?: return false
        publish(up)
        return true
    }

    private suspend fun run(block: suspend (DesktopKeysSource) -> DesktopKeysState): DesktopKeysState {
        val client = source() ?: return publish(DesktopKeysState.NoSession)
        val previous = content
        val loading = DesktopKeysState.Loading(previous)
        publish(loading)
        val next = try {
            block(client)
        } catch (e: CancellationException) {
            // Restore the screen only if nothing (such as back) replaced the loading state.
            if (state === loading) publish(previous ?: loading)
            throw e
        } catch (e: Exception) {
            DesktopKeysState.Failed(DesktopKeyError.from(e), previous)
        }
        return publish(next)
    }

    private fun publish(next: DesktopKeysState): DesktopKeysState {
        state = next
        onState(next)
        return next
    }
}
