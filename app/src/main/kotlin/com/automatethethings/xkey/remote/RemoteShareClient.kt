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
import com.automatethethings.xkey.ca.DeviceIdentity
import com.automatethethings.xkey.crypto.FileEncryptor
import com.automatethethings.xkey.crypto.KeystoreUserVerificationKey
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
 *     with no record, and the phone's identity keys ([isIdentityKey]), are
 *     unshareable;
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

    /**
     * The SELECTED_PEERS grant check an outbound share passes to [decide]
     * and [DesktopKeyShare.send], built from the grant rows
     * ([isKeySharedWithPeer]) and the pairing record ([isRevocationPending]).
     * As in protocol/Handler.kt's canShareKeyWithPeer, a peer whose unpair
     * revocation is pending (#174) has no grant: it may have been re-paired
     * under the same key before its old rows were deleted.
     */
    fun peerGrant(
        isKeySharedWithPeer: suspend (keyId: String, peerPublicKeyHex: String) -> Boolean,
        isRevocationPending: (peerPublicKeyHex: String) -> Boolean
    ): suspend (keyId: String, peerPublicKeyHex: String) -> Boolean = { keyId, peer ->
        !isRevocationPending(peer) && isKeySharedWithPeer(keyId, peer)
    }

    /**
     * The phone's own identity keys: DeviceIdentity's enrollment keys and the
     * user-verification key. Their writers replace them outside
     * [SharePermissionLedger], so a share could not tell a retired key from
     * the current one; they are never shared.
     */
    fun isIdentityKey(keyId: String): Boolean =
        keyId.startsWith(DeviceIdentity.ALIAS_PREFIX) || keyId == KeystoreUserVerificationKey.ALIAS

    /**
     * FileEncryptor's ephemeral agreement keys, deleted when their one
     * encryption ends. Discovery no longer gives them rows; a row an earlier
     * build gave one is still never shared.
     */
    fun isEphemeralKey(keyId: String): Boolean = keyId.startsWith(FileEncryptor.EPHEMERAL_KEY_PREFIX)

    suspend fun decide(
        entity: KeyEntity?,
        software: SoftwareKey?,
        publicKeyPem: String?,
        peerPublicKeyHex: String?,
        isKeySharedWithPeer: suspend (keyId: String, peerPublicKeyHex: String) -> Boolean
    ): DesktopShareDecision {
        if (peerPublicKeyHex.isNullOrEmpty()) return DesktopShareDecision.NO_PEER
        if (entity == null || isIdentityKey(entity.keyId) || isEphemeralKey(entity.keyId)) {
            return DesktopShareDecision.POLICY_DENIED
        }
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
 * out on and the peer identity confirmed on that same connection.
 *
 * The peer comes from the transport's own connection
 * ([MessageSender.confirmedConnection]), never from the request handler's one
 * peer key: that key belongs to whichever session last confirmed, and a
 * revoked session whose teardown is still pending leaves it set.
 */
class ShareSession private constructor(
    val sender: MessageSender,
    val router: BidirectionalMessageRouter,
    private val confirmed: ConfirmedConnection?,
    private val stillCurrent: (ShareSession) -> Boolean
) {

    /** A transport with an established session. */
    class Transport(val sender: MessageSender, val router: BidirectionalMessageRouter)

    /** The peer confirmed on this session's connection, or null when it confirms no one. */
    val peerPublicKeyHex: String? get() = confirmed?.peerPublicKeyHex

    /**
     * True while this is still the session the phone would send on: the
     * transport still reaches the same connection, confirmed for the same peer.
     */
    fun isCurrent(): Boolean = sameConnection(sender.confirmedConnection()) && stillCurrent(this)

    /** Same transport, same router and the same connection confirmed for the same peer. */
    fun sameAs(other: ShareSession?): Boolean =
        other != null && other.sender === sender && other.router === router && sameConnection(other.confirmed)

    private fun sameConnection(other: ConfirmedConnection?): Boolean =
        if (confirmed == null) other == null else confirmed.sameAs(other)

    /**
     * A client on this session whose every send re-checks [isCurrent] and
     * then goes out on this session's own connection alone
     * ([MessageSender.sendEncryptedMessageOn]): the transport refuses it at
     * encryption admission if another connection, even another peer, has
     * replaced that one since the check.
     *
     * [authorize] applies to every send of the client (`sharePublicKey`,
     * `shareSymmetric`, `importSharedKey`). It runs before the send enters the
     * transport and may suspend (it re-reads the store), and throws to stop
     * the send. It returns the admission check the transport runs inside its
     * admission critical section, after every wait and immediately before the
     * nonce is consumed ([MessageSender.sendEncryptedMessageOn]); that check
     * is what makes a revoke committed while the send waited win.
     */
    internal fun client(
        requestTimeoutMs: Long,
        authorize: suspend () -> (() -> Unit) = { {} }
    ): RemoteShareClient = RemoteShareClient(GuardedSender(authorize), router, requestTimeoutMs)

    private inner class GuardedSender(private val authorize: suspend () -> (() -> Unit)) : MessageSender {
        override suspend fun sendEncryptedMessage(data: ByteArray) {
            val on = confirmed ?: throw SessionChangedException()
            if (!isCurrent()) throw SessionChangedException()
            val admit = authorize()
            // The re-read suspends: the session may have changed meanwhile.
            if (!isCurrent()) throw SessionChangedException()
            sender.sendEncryptedMessageOn(on, data, admit)
        }
    }

    companion object {
        /**
         * The session on the first of [live] (the caller's transport order),
         * or null when none is live, with the peer confirmed on that
         * transport's own connection.
         */
        fun of(
            live: List<Transport>,
            stillCurrent: (ShareSession) -> Boolean
        ): ShareSession? {
            val active = live.firstOrNull() ?: return null
            val confirmed = active.sender.confirmedConnection()?.takeIf { it.peerPublicKeyHex.isNotEmpty() }
            return ShareSession(active.sender, active.router, confirmed, stillCurrent)
        }
    }
}

/** The session a share was authorized on was replaced before the send. */
internal class SessionChangedException : ConnectionChangedException("the desktop session changed before the send")

/** The key's sharing permission no longer admits the peer: it was revoked before the send was admitted. */
internal class SharePermissionRevokedException(keyId: String) :
    SecurityException("the sharing permission for key $keyId was revoked before the send")

/**
 * Orders every revoke of a key's sharing permission with the transport
 * admission of a pending share of that key.
 *
 * The store cannot be read at admission: the transport admits a send under
 * its own lock, where nothing may suspend. So a share reads the store before
 * it enters the transport, after taking a [revision] of the key, and the
 * transport's admission calls [requireUnchanged] with that revision. Every
 * writer that narrows what a key may be shared with (its policy, a peer
 * grant, the key itself) commits through [revoking], which marks the key
 * under this ledger's lock before the write and moves its revision after it.
 * Admission and the revoke writers meet on that one lock:
 * - a revoke that started before admission refuses the send, whether its
 *   write has committed yet or not;
 * - a revoke that starts after admission is ordered after the send, whose
 *   nonce is already consumed.
 */
internal object SharePermissionLedger {

    private val lock = Any()
    private val revisions = HashMap<String, Long>()
    private val inFlight = HashMap<String, Int>()

    /** The key's revision now; take it before reading the key's permission from the store. */
    fun revision(keyId: String): Long = synchronized(lock) { revisions[keyId] ?: 0L }

    /**
     * A key's revision taken before any of its share inputs (record, public
     * half, software material) were read. A share carries it to admission.
     */
    class Baseline internal constructor(val keyId: String, val revision: Long) : AutoCloseable {
        override fun close() {}
    }

    /** Key IDs the ledger holds state for. */
    internal fun retainedKeyCount(): Int = synchronized(lock) { revisions.size + inFlight.size }

    /** Takes [keyId]'s [Baseline]; call before loading anything a share of it sends. */
    fun baseline(keyId: String): Baseline = Baseline(keyId, revision(keyId))

    /**
     * Admission check: no revoke of [keyId] is in flight and none has
     * committed since [revision] was taken. Synchronous, for the transport's
     * admission critical section.
     *
     * @throws SharePermissionRevokedException otherwise
     */
    fun requireUnchanged(keyId: String, revision: Long) = synchronized(lock) {
        if ((inFlight[keyId] ?: 0) > 0 || (revisions[keyId] ?: 0L) != revision) {
            throw SharePermissionRevokedException(keyId)
        }
    }

    /** Runs [write], a change that narrows or removes [keyId]'s sharing permission, as a revoke. */
    suspend fun <T> revoking(keyId: String, write: suspend () -> T): T {
        synchronized(lock) { inFlight[keyId] = (inFlight[keyId] ?: 0) + 1 }
        try {
            return write()
        } finally {
            synchronized(lock) {
                revisions[keyId] = (revisions[keyId] ?: 0L) + 1
                val left = (inFlight[keyId] ?: 1) - 1
                if (left == 0) inFlight.remove(keyId) else inFlight[keyId] = left
            }
        }
    }
}

/**
 * Sends one of the phone's keys to the paired desktop on [session], after
 * [DesktopShareGate] has checked it against the peer confirmed on that
 * session. Nothing reaches the wire unless the gate answers
 * [DesktopShareDecision.PUBLIC_KEY] and the session is still current.
 *
 * The gate runs twice: once on the caller's snapshot, and again just before
 * the share enters the transport, on the key as the store holds it then
 * ([currentEntity][send]) and the peer grants as they stand then. The
 * transport's admission then checks [SharePermissionLedger] for a revoke
 * since the [SharePermissionLedger.Baseline] the caller took before it
 * loaded any of the key's inputs. A permission revoked, or the key deleted
 * or replaced, after that baseline, including while the share waited inside
 * the transport, refuses it with [DesktopShareDecision.POLICY_DENIED] and
 * nothing is sent.
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

    /**
     * [baseline] is the key's [SharePermissionLedger.Baseline], taken before
     * any of [entity], [software], [publicKeyPem] and [certificatePem] was
     * loaded; the transport admits the send only while it holds, and a
     * baseline for another key refuses the send.
     * [software]'s material is zeroed before this returns, whatever the outcome.
     * [currentEntity] reads the key's record from the store, not a snapshot.
     */
    internal suspend fun send(
        baseline: SharePermissionLedger.Baseline,
        entity: KeyEntity?,
        software: SoftwareKey?,
        publicKeyPem: String?,
        certificatePem: String?,
        isKeySharedWithPeer: suspend (keyId: String, peerPublicKeyHex: String) -> Boolean,
        currentEntity: suspend (keyId: String) -> KeyEntity?
    ): Outcome {
        try {
            val decision = DesktopShareGate.decide(
                entity, software, publicKeyPem, session.peerPublicKeyHex, isKeySharedWithPeer
            )
            if (!session.isCurrent()) return Outcome.SessionChanged
            if (decision != DesktopShareDecision.PUBLIC_KEY || entity == null || publicKeyPem == null) {
                return Outcome.Refused(decision)
            }
            if (baseline.keyId != entity.keyId) return Outcome.Refused(DesktopShareDecision.POLICY_DENIED)
            val peer = session.peerPublicKeyHex
            val result = try {
                session.client(requestTimeoutMs) {
                    val now = DesktopShareGate.decide(
                        currentEntity(entity.keyId), null, publicKeyPem, peer, isKeySharedWithPeer
                    )
                    if (now != DesktopShareDecision.PUBLIC_KEY) throw SharePermissionRevokedException(entity.keyId)
                    // The baseline predates the inputs: a revoke, delete or
                    // replacement committed since they were loaded is caught here.
                    return@client { SharePermissionLedger.requireUnchanged(baseline.keyId, baseline.revision) }
                }.sharePublicKey(
                    RemoteShareClient.PublicKeyShare(
                        keyId = entity.keyId,
                        publicKeyPem = publicKeyPem,
                        certificatePem = certificatePem,
                        algorithm = shareAlgorithm(publicKeyPem, entity.algorithm),
                        label = entity.label,
                        backend = null
                    )
                )
            } catch (e: ConnectionChangedException) {
                return Outcome.SessionChanged
            } catch (e: SharePermissionRevokedException) {
                return Outcome.Refused(DesktopShareDecision.POLICY_DENIED)
            }
            return if (result.accepted) Outcome.Sent(result) else Outcome.Declined(result)
        } finally {
            software?.material.let { it?.fill(0) }
        }
    }

    /**
     * The algorithm of the key [publicKeyPem] holds. The keys row's
     * [recorded] algorithm can be stale: a PIV slot replaced with a key of
     * another algorithm updates only its slot record. An EC key is named by
     * its curve; an RSA key keeps a recorded RSA algorithm; a PEM neither
     * parses as keeps [recorded].
     */
    private fun shareAlgorithm(publicKeyPem: String, recorded: String): String {
        val der = try {
            java.util.Base64.getMimeDecoder().decode(
                publicKeyPem.lineSequence().filterNot { it.startsWith("-----") }.joinToString("")
            )
        } catch (e: IllegalArgumentException) {
            return recorded
        }
        val key = listOf("EC", "RSA").firstNotNullOfOrNull { type ->
            try {
                java.security.KeyFactory.getInstance(type)
                    .generatePublic(java.security.spec.X509EncodedKeySpec(der))
            } catch (e: java.security.GeneralSecurityException) {
                null
            }
        }
        return when (key) {
            is java.security.interfaces.ECPublicKey -> {
                val bits = key.params.order.bitLength()
                when {
                    bits <= 256 -> "ES256"
                    bits <= 384 -> "ES384"
                    else -> "ES512"
                }
            }
            is java.security.interfaces.RSAPublicKey -> if (recorded.startsWith("RS")) recorded else "RS256"
            else -> recorded
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
