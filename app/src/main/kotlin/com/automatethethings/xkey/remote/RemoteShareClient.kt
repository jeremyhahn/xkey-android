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
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import org.json.JSONObject
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * Client for the phone-initiated key-sharing methods on the paired desktop:
 * `remote.sharePublicKey`, `remote.shareSymmetric` and `remote.importSharedKey`.
 *
 * Wire shapes follow go-xkms `pkg/pairingproto` (xkey/v0.64.2-alpha,
 * `protocol_sharing.go`). Every Go `[]byte` field, the PEM fields included,
 * travels as a standard base64 string. Replies are parsed strictly: a missing
 * field, a wrong JSON type or bad base64 is a [ProtocolException] with
 * [ErrorCodes.INTERNAL_ERROR], never a defaulted value.
 *
 * This client does not decide whether a key may leave the phone; callers go
 * through [DesktopKeyShare], which applies [DesktopShareGate] first.
 */
class RemoteShareClient(
    private val messageSender: MessageSender,
    private val messageRouter: BidirectionalMessageRouter,
    private val requestTimeoutMs: Long = 30_000L
) {

    /** `RemoteSharePublicKeyParams`; null optionals are omitted (omitempty). */
    data class PublicKeyShare(
        val keyId: String,
        val publicKeyPem: String,
        val certificatePem: String?,
        val algorithm: String,
        val label: String?,
        val backend: String?
    )

    /** `RemoteSharePublicKeyResult` / `RemoteShareSymmetricResult`. */
    data class ShareResult(val accepted: Boolean, val importId: String, val backend: String)

    /** `RemoteImportSharedKeyResult`. [wrappedKey] belongs to the caller, who must zero it. */
    class ImportedKey(
        val publicKeyPem: String?,
        val certificatePem: String?,
        val algorithm: String,
        val keyType: String,
        val wrappedKey: ByteArray?,
        val keySize: Int,
        val exportable: Boolean
    )

    /** Sends the phone's public key (and certificate) to the desktop for import. */
    suspend fun sharePublicKey(share: PublicKeyShare): ShareResult {
        if (share.publicKeyPem.isEmpty()) invalid("public_key_pem is empty")
        if (share.algorithm.isEmpty()) invalid("algorithm is empty")
        val params = JSONObject()
            .put("key_id", share.keyId)
            .put("public_key_pem", b64(share.publicKeyPem))
            .put("algorithm", share.algorithm)
        share.certificatePem?.takeIf { it.isNotEmpty() }?.let { params.put("certificate_pem", b64(it)) }
        share.label?.takeIf { it.isNotEmpty() }?.let { params.put("label", it) }
        share.backend?.takeIf { it.isNotEmpty() }?.let { params.put("backend", it) }
        val id = nextRequestId.getAndIncrement()
        val body = Request(id, MethodNames.REMOTE_SHARE_PUBLIC_KEY, params).toJson()
        return parseShareResult(send(id, MethodNames.REMOTE_SHARE_PUBLIC_KEY, body))
    }

    /**
     * Sends symmetric key material to the desktop for import.
     *
     * [wrappedKey] and the encoded request are zeroed before this returns,
     * whatever the outcome; the material is never held in a [String].
     */
    suspend fun shareSymmetric(
        keyId: String,
        wrappedKey: ByteArray,
        algorithm: String,
        keySize: Int,
        label: String?,
        backend: String?
    ): ShareResult {
        var body: ByteArray? = null
        try {
            if (wrappedKey.isEmpty()) invalid("wrapped_key is empty")
            if (algorithm.isEmpty()) invalid("algorithm is empty")
            val params = JSONObject()
                .put("key_id", keyId)
                .put("algorithm", algorithm)
                .put("key_size", keySize)
            label?.takeIf { it.isNotEmpty() }?.let { params.put("label", it) }
            backend?.takeIf { it.isNotEmpty() }?.let { params.put("backend", it) }
            val id = nextRequestId.getAndIncrement()
            body = encodeWithSecret(id, MethodNames.REMOTE_SHARE_SYMMETRIC, params, "wrapped_key", wrappedKey)
            return parseShareResult(send(id, MethodNames.REMOTE_SHARE_SYMMETRIC, body))
        } finally {
            wrappedKey.fill(0)
            body?.fill(0)
        }
    }

    /** Asks the desktop to export key [keyId] from [backend] to the phone. */
    suspend fun importSharedKey(backend: String, keyId: String, format: String?): ImportedKey {
        if (backend.isEmpty()) invalid("backend is empty")
        if (keyId.isEmpty()) invalid("key_id is empty")
        val params = JSONObject().put("backend", backend).put("key_id", keyId)
        format?.takeIf { it.isNotEmpty() }?.let { params.put("format", it) }
        val id = nextRequestId.getAndIncrement()
        val body = Request(id, MethodNames.REMOTE_IMPORT_SHARED_KEY, params).toJson()
        return parseImportedKey(send(id, MethodNames.REMOTE_IMPORT_SHARED_KEY, body))
    }

    private suspend fun send(id: Long, method: String, body: ByteArray): JSONObject {
        val deferred = CompletableDeferred<Response>()
        messageRouter.registerPendingResponse(id, deferred)
        try {
            Log.d(TAG, "Sending share request: id=$id, method=$method")
            messageSender.sendEncryptedMessage(body)
            val response = withTimeout(requestTimeoutMs) { deferred.await() }
            response.error?.let { throw ProtocolException("Remote error: ${it.message}", errorCode = it.code) }
            return response.result ?: malformed("$method: empty result")
        } catch (e: TimeoutCancellationException) {
            throw ProtocolException("Request timed out: $method", errorCode = ErrorCodes.INTERNAL_ERROR)
        } finally {
            messageRouter.removePendingResponse(id)
        }
    }

    internal companion object {
        private const val TAG = "RemoteShareClient"

        /**
         * Distinct from the other outbound clients' bases (RemoteKeyClient
         * 1_000_000, RemoteSyncClient 2_000_000, enrollment 3_000_000,
         * RemoteBackupClient 4_000_000) so ids on one router never collide.
         * The counter is shared by every instance, as RemoteBackupClient's is.
         */
        const val BASE_REQUEST_ID = 6_000_000L

        private val nextRequestId = AtomicLong(BASE_REQUEST_ID)

        private fun b64(text: String): String =
            Base64.getEncoder().encodeToString(text.toByteArray(Charsets.UTF_8))

        private fun invalid(why: String): Nothing =
            throw ProtocolException(why, errorCode = ErrorCodes.INVALID_PARAMS)

        private fun malformed(why: String): Nothing =
            throw ProtocolException("Malformed share reply: $why", errorCode = ErrorCodes.INTERNAL_ERROR)

        /**
         * The request as UTF-8 with `"[field]":"<base64 of secret>"` written
         * straight into the returned buffer, so no [String] of the secret is
         * made. [Request] puts params last, so the text ends with params' `}`
         * and the envelope's `}`; the field goes before params' brace. The
         * caller owns the buffer and must zero it.
         */
        fun encodeWithSecret(id: Long, method: String, params: JSONObject, field: String, secret: ByteArray): ByteArray {
            val head = Request(id, method, params).toJsonString()
            check(head.endsWith("}}")) { "unexpected request shape" }
            val prefix = head.substring(0, head.length - 2).toByteArray(Charsets.UTF_8)
            val sep = (if (params.length() == 0) "\"" else ",\"") + field + "\":\""
            val sepBytes = sep.toByteArray(Charsets.UTF_8)
            val encoded = Base64.getEncoder().encode(secret)
            try {
                val tail = "\"}}".toByteArray(Charsets.UTF_8)
                val out = ByteArray(prefix.size + sepBytes.size + encoded.size + tail.size)
                var at = 0
                for (part in arrayOf(prefix, sepBytes, encoded, tail)) {
                    part.copyInto(out, at)
                    at += part.size
                }
                return out
            } finally {
                encoded.fill(0)
            }
        }

        fun parseShareResult(result: JSONObject): ShareResult {
            val accepted = result.opt("accepted") as? Boolean ?: malformed("accepted is not a boolean")
            val importId = result.opt("import_id") as? String ?: malformed("import_id is not a string")
            val backend = result.opt("backend") as? String ?: malformed("backend is not a string")
            if (accepted && importId.isEmpty()) malformed("accepted without an import_id")
            return ShareResult(accepted, importId, backend)
        }

        fun parseImportedKey(result: JSONObject): ImportedKey {
            val algorithm = result.opt("algorithm") as? String ?: malformed("algorithm is not a string")
            val keyType = result.opt("key_type") as? String ?: malformed("key_type is not a string")
            val exportable = result.opt("exportable") as? Boolean ?: malformed("exportable is not a boolean")
            val keySize = when (val v = result.opt("key_size")) {
                null, JSONObject.NULL -> 0
                is Int -> v
                else -> malformed("key_size is not an integer")
            }
            val publicKeyPem = optBytes(result, "public_key_pem")?.toString(Charsets.UTF_8)
            val certificatePem = optBytes(result, "certificate_pem")?.toString(Charsets.UTF_8)
            val wrappedKey = optBytes(result, "wrapped_key")
            return ImportedKey(publicKeyPem, certificatePem, algorithm, keyType, wrappedKey, keySize, exportable)
        }

        /** A Go `[]byte`: absent or null is nil, otherwise strict base64. */
        private fun optBytes(obj: JSONObject, name: String): ByteArray? =
            when (val v = obj.opt(name)) {
                null, JSONObject.NULL -> null
                is String -> try {
                    Base64.getDecoder().decode(v)
                } catch (e: IllegalArgumentException) {
                    malformed("$name is not base64")
                }
                else -> malformed("$name is not a base64 string")
            }
    }
}

/** What [DesktopShareGate] allows for one key and the connected desktop. */
enum class DesktopShareDecision {
    /** The session has no confirmed peer identity. */
    NO_PEER,

    /** No recorded policy, or the key's policy does not admit this peer. */
    POLICY_DENIED,

    /** A hardware key with no public half to read. */
    NOT_FOUND,

    /** The public half may be sent (`remote.sharePublicKey`). */
    PUBLIC_KEY,

    /** A software key not marked exportable and shareable in both stores. */
    NOT_EXPORTABLE,

    /**
     * Symmetric material the rules would release, but no wrapping path
     * matches the desktop's import (see [DesktopShareGate.SYMMETRIC_WRAP_PATH_MATCHES]).
     */
    SYMMETRIC_NO_WRAP_PATH
}

/**
 * The phone's `local.*` sharing rules applied to an outbound share:
 *
 *  1. a confirmed peer identity is required;
 *  2. the key's recorded policy must admit that peer (PRIVATE never,
 *     ALL_PEERS always, SELECTED_PEERS only when the peer is listed); a key
 *     with no record is unshareable;
 *  3. a hardware key shares its public half only;
 *  4. software material only when both stores mark it exportable and shareable.
 *
 * These are the rules protocol/Handler.kt applies to `local.importSharedKey`.
 */
object DesktopShareGate {

    /**
     * False at go-xkms xkey/v0.64.2-alpha: the desktop bridge hands
     * `wrapped_key` to xkmsd's BYOK ImportKey, which expects material wrapped
     * under the key and import token from GetImportParameters, and the
     * pairing protocol has no method that gives the phone those. Raw material
     * would be rejected or misread, so symmetric keys are never sent.
     */
    const val SYMMETRIC_WRAP_PATH_MATCHES = false

    suspend fun decide(
        entity: KeyEntity?,
        software: SoftwareKey?,
        publicKeyPem: String?,
        peerPublicKeyHex: String?,
        isKeySharedWithPeer: suspend (keyId: String, peerPublicKeyHex: String) -> Boolean
    ): DesktopShareDecision {
        if (peerPublicKeyHex.isNullOrEmpty()) return DesktopShareDecision.NO_PEER
        if (entity == null) return DesktopShareDecision.POLICY_DENIED
        val admitted = when (entity.sharingPolicy) {
            SharingPolicyType.PRIVATE -> false
            SharingPolicyType.ALL_PEERS -> true
            SharingPolicyType.SELECTED_PEERS -> isKeySharedWithPeer(entity.keyId, peerPublicKeyHex)
        }
        if (!admitted) return DesktopShareDecision.POLICY_DENIED
        if (software != null) {
            val exportable = entity.exportable && entity.shareable && software.exportable && software.shareable
            return if (!exportable) DesktopShareDecision.NOT_EXPORTABLE else DesktopShareDecision.SYMMETRIC_NO_WRAP_PATH
        }
        return if (publicKeyPem.isNullOrEmpty()) DesktopShareDecision.NOT_FOUND else DesktopShareDecision.PUBLIC_KEY
    }
}

/**
 * One desktop session as it stood at one moment: the transport a share goes
 * out on and the peer identity confirmed on that same session.
 *
 * The phone's request handler holds one confirmed peer key for all its
 * transports, so it cannot say which session confirmed it. [of] keeps that
 * key only while exactly one transport is live. With several live, the
 * session has no peer it can vouch for and every share is refused.
 */
class ShareSession private constructor(
    val sender: MessageSender,
    val router: BidirectionalMessageRouter,
    val peerPublicKeyHex: String?,
    private val stillCurrent: (ShareSession) -> Boolean
) {

    /** A transport with an established session. */
    class Transport(val sender: MessageSender, val router: BidirectionalMessageRouter)

    /** True while this is still the session the phone would send on, with the same peer. */
    fun isCurrent(): Boolean = stillCurrent(this)

    /** Same transport, same router and same confirmed peer. */
    fun sameAs(other: ShareSession?): Boolean =
        other != null && other.sender === sender && other.router === router &&
            other.peerPublicKeyHex == peerPublicKeyHex

    /**
     * A client on this session whose every send re-checks [isCurrent] just
     * before the bytes go to the transport, which encrypts them.
     */
    internal fun client(requestTimeoutMs: Long): RemoteShareClient =
        RemoteShareClient(GuardedSender(), router, requestTimeoutMs)

    private inner class GuardedSender : MessageSender {
        override suspend fun sendEncryptedMessage(data: ByteArray) {
            if (!isCurrent()) throw SessionChangedException()
            sender.sendEncryptedMessage(data)
        }
    }

    companion object {
        /**
         * The session on the first of [live] (the caller's transport order),
         * or null when none is live. [confirmedPeerHex] is the phone's one
         * confirmed peer key; it is kept only when [live] has one transport.
         */
        fun of(
            live: List<Transport>,
            confirmedPeerHex: String?,
            stillCurrent: (ShareSession) -> Boolean
        ): ShareSession? {
            val active = live.firstOrNull() ?: return null
            val peer = confirmedPeerHex?.takeIf { live.size == 1 && it.isNotEmpty() }
            return ShareSession(active.sender, active.router, peer, stillCurrent)
        }
    }
}

/** The session a share was authorized on was replaced before the send. */
internal class SessionChangedException : java.io.IOException("the desktop session changed before the send")

/**
 * Sends one of the phone's keys to the paired desktop on [session], after
 * [DesktopShareGate] has checked it against the peer confirmed on that
 * session. Nothing reaches the wire unless the gate answers
 * [DesktopShareDecision.PUBLIC_KEY] and the session is still current.
 */
class DesktopKeyShare(
    private val session: ShareSession,
    private val requestTimeoutMs: Long = 30_000L
) {

    sealed class Outcome {
        /** The desktop accepted the key (`accepted` true). */
        data class Sent(val result: RemoteShareClient.ShareResult) : Outcome()

        /** The desktop answered but did not import the key (`accepted` false). */
        data class Declined(val result: RemoteShareClient.ShareResult) : Outcome()
        data class Refused(val decision: DesktopShareDecision) : Outcome()

        /** The session was replaced before the key was sent; nothing left the phone. */
        data object SessionChanged : Outcome()
    }

    /** [software]'s material is zeroed before this returns, whatever the outcome. */
    suspend fun send(
        entity: KeyEntity?,
        software: SoftwareKey?,
        publicKeyPem: String?,
        certificatePem: String?,
        isKeySharedWithPeer: suspend (keyId: String, peerPublicKeyHex: String) -> Boolean
    ): Outcome {
        try {
            val decision = DesktopShareGate.decide(
                entity, software, publicKeyPem, session.peerPublicKeyHex, isKeySharedWithPeer
            )
            if (!session.isCurrent()) return Outcome.SessionChanged
            if (decision != DesktopShareDecision.PUBLIC_KEY || entity == null || publicKeyPem == null) {
                return Outcome.Refused(decision)
            }
            val result = try {
                session.client(requestTimeoutMs).sharePublicKey(
                    RemoteShareClient.PublicKeyShare(
                        keyId = entity.keyId,
                        publicKeyPem = publicKeyPem,
                        certificatePem = certificatePem,
                        algorithm = entity.algorithm,
                        label = entity.label,
                        backend = null
                    )
                )
            } catch (e: SessionChangedException) {
                return Outcome.SessionChanged
            }
            return if (result.accepted) Outcome.Sent(result) else Outcome.Declined(result)
        } finally {
            software?.material.let { it?.fill(0) }
        }
    }
}

/**
 * The desktop session as it changes: emits [probe]'s answer on start, then
 * again each time a poll finds a different session. A desktop connecting,
 * its peer being confirmed, a move to another transport and the desktop
 * going away each emit once. The service exposes no confirm event, so the
 * session is polled every [periodMs] while collected.
 */
fun shareSessionChanges(periodMs: Long = 500L, probe: () -> ShareSession?): Flow<ShareSession?> = flow {
    var last: ShareSession? = null
    var started = false
    while (true) {
        val now = probe()
        if (!started || !sameSession(now, last)) {
            emit(now)
            last = now
            started = true
        }
        delay(periodMs)
    }
}
private fun sameSession(a: ShareSession?, b: ShareSession?): Boolean = if (a == null) b == null else a.sameAs(b)
