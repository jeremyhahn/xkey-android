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
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * Phone-initiated (outbound) backup client: asks the paired desktop to create
 * an encrypted backup of chosen stores (`remote.createBackup`) or to restore
 * one (`remote.restoreBackup`), and lists the backups the desktop holds
 * (`remote.listBackups`).
 *
 * The desktop derives the backup key from [password] the way
 * `xkey backup create --password` does and hands the encrypted envelope back;
 * it never keeps it. The phone stores the envelope as an opaque blob.
 *
 * Wire contract: go-xkms `pkg/pairingproto/protocol_backup.go`
 * (RemoteCreateBackup* / RemoteRestoreBackup* / RemoteListBackups*, BackupInfo;
 * pinned at tag `xkey/v0.64.2-alpha`). Since go-xkms #1695 the `password`
 * field is required on create and restore: a request without one, or with an
 * empty one, is refused with -32602. `remote.listBackups` carries no password
 * and empty params.
 *
 * ## Password handling
 *
 * The password is never turned into a [String]. It is written as a JSON string
 * straight into a request buffer this client allocates and owns, and that
 * buffer and the caller's [CharArray] are both zeroed before each call
 * returns, on success, error, timeout and cancellation alike. Nothing about
 * the request parameters is logged.
 *
 * Requires an active paired connection: [messageSender] and [messageRouter]
 * are the live transport's, the same send path [RemoteSyncClient] uses.
 */
class RemoteBackupClient(
    desktop: ConnectedDesktop,
    private val requestTimeoutMs: Long = 60_000L
) {
    /** Bound to [desktop]'s connection: a reply-awaiting call never reaches another desktop. */
    private val messageSender: MessageSender = desktop.sender
    private val messageRouter: BidirectionalMessageRouter = desktop.router

    /** Which stores a backup carries. At least one must be true. */
    data class Include(
        val trustStore: Boolean = false,
        val oath: Boolean = false,
        val passwords: Boolean = false,
        val ca: Boolean = false
    ) {
        val any: Boolean get() = trustStore || oath || passwords || ca
    }

    /**
     * The desktop's reply to `remote.createBackup`. [backupData] is the JSON
     * encoding of a `backup.EncryptedBackup` envelope.
     */
    class CreateResult(
        val backupData: ByteArray,
        val backupId: String,
        val itemCount: Int
    )

    /** One store's outcome in a restore. */
    data class RestoreItem(
        val item: String,
        val restored: Int,
        /** Pending desktop review, not a failure. */
        val quarantined: Int,
        val skipped: Int,
        val errors: List<String>
    )

    /**
     * The desktop's reply to `remote.restoreBackup`. [success] is true only
     * when no item skipped an entry.
     */
    data class RestoreResult(
        val success: Boolean,
        val restored: List<String>,
        val message: String?,
        val items: List<RestoreItem>
    )

    /**
     * One backup the desktop holds, from `remote.listBackups` (go-xkms
     * `BackupInfo`). [createdAt] is the desktop's text as sent; [label] is
     * null when the desktop omitted it; [size] is in bytes.
     */
    data class BackupInfo(
        val backupId: String,
        val createdAt: String,
        val label: String?,
        val size: Long
    )

    /**
     * Asks the desktop to create a backup of the stores in [include], labelled
     * [label] (the desktop uses the label as the backup id).
     *
     * [password] is zeroed before this returns, whatever the outcome.
     *
     * @throws RemoteBackupException.EmptyPassword before any request is sent
     *   when [password] is empty.
     * @throws RemoteBackupException.NothingSelected before any request is
     *   sent when [include] selects no store.
     * @throws RemoteBackupException on an error reply, a timeout or a reply
     *   the phone cannot read.
     */
    suspend fun createBackup(password: CharArray, include: Include, label: String): CreateResult {
        try {
            if (password.isEmpty()) throw RemoteBackupException.EmptyPassword()
            if (!include.any) throw RemoteBackupException.NothingSelected()
            val params = JSONObject()
                .put("include_trust_store", include.trustStore)
                .put("include_oath", include.oath)
                .put("include_passwords", include.passwords)
                .put("include_ca", include.ca)
            if (label.isNotEmpty()) params.put("label", label)
            val result = sendRequest(MethodNames.REMOTE_CREATE_BACKUP, params, password)
            return decodeCreateResult(result)
        } finally {
            password.fill('\u0000')
        }
    }

    /**
     * Asks the desktop to restore [envelope], a backup created earlier, under
     * [password].
     *
     * [password] is zeroed before this returns, whatever the outcome.
     *
     * @throws RemoteBackupException.EmptyPassword before any request is sent
     *   when [password] is empty.
     * @throws RemoteBackupException.WrongPasswordOrDamaged when the password
     *   is wrong or the envelope is damaged; the desktop does not tell them
     *   apart.
     * @throws RemoteBackupException on any other error reply, a timeout or a
     *   reply the phone cannot read.
     */
    suspend fun restoreBackup(envelope: ByteArray, password: CharArray): RestoreResult {
        try {
            if (password.isEmpty()) throw RemoteBackupException.EmptyPassword()
            val params = JSONObject()
                .put("backup_data", Base64.getEncoder().encodeToString(envelope))
            val result = sendRequest(MethodNames.REMOTE_RESTORE_BACKUP, params, password)
            return decodeRestoreResult(result)
        } finally {
            password.fill('\u0000')
        }
    }

    /**
     * Asks the desktop which backups it holds (`remote.listBackups`). The
     * request has empty params and no password. A `null` or missing
     * `backups` (a nil Go slice) is an empty list.
     *
     * @throws RemoteBackupException on an error reply, a timeout or a reply
     *   the phone cannot read.
     */
    suspend fun listBackups(): List<BackupInfo> {
        val result = send(MethodNames.REMOTE_LIST_BACKUPS) { id ->
            Request(id, MethodNames.REMOTE_LIST_BACKUPS, JSONObject()).toJson()
        }
        return decodeListResult(result)
    }

    private suspend fun sendRequest(method: String, params: JSONObject, password: CharArray): JSONObject =
        send(method) { id -> encodeRequest(id, method, params, password) }

    /**
     * Sends the request [encode] builds for a fresh id and returns its
     * result. The buffer is zeroed after the send, whatever it holds.
     */
    private suspend fun send(method: String, encode: (Long) -> ByteArray): JSONObject {
        val id = nextRequestId.getAndIncrement()
        val deferred = CompletableDeferred<Response>()
        var body: ByteArray? = null
        try {
            messageRouter.registerPendingResponse(id, deferred)
            body = encode(id)
            Log.d(TAG, "Sending backup request: id=$id, method=$method")
            messageSender.sendEncryptedMessage(body)
            val response = withTimeout(requestTimeoutMs) { deferred.await() }
            val error = response.error
            if (error != null) throw RemoteBackupException.fromError(error.code, error.message)
            return response.result ?: throw RemoteBackupException.MalformedReply("empty result")
        } catch (e: TimeoutCancellationException) {
            throw RemoteBackupException.TimedOut(method)
        } finally {
            body?.fill(0)
            messageRouter.removePendingResponse(id)
        }
    }

    private fun decodeListResult(result: JSONObject): List<BackupInfo> {
        if (result.isNull("backups")) return emptyList()
        val backups = result.optJSONArray("backups")
            ?: throw RemoteBackupException.MalformedReply("backups is not a list")
        return (0 until backups.length()).map { i ->
            val info = backups.optJSONObject(i)
                ?: throw RemoteBackupException.MalformedReply("backups is not a list of objects")
            BackupInfo(
                backupId = info.optString("backup_id", ""),
                createdAt = info.optString("created_at", ""),
                label = info.optString("label", "").ifEmpty { null },
                size = info.optLong("size", 0L)
            )
        }
    }

    private fun decodeCreateResult(result: JSONObject): CreateResult {
        val encoded = result.optString("backup_data", "")
        if (encoded.isEmpty()) throw RemoteBackupException.MalformedReply("backup_data missing")
        val data = try {
            Base64.getDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw RemoteBackupException.MalformedReply("backup_data is not base64")
        }
        return CreateResult(
            backupData = data,
            backupId = result.optString("backup_id", ""),
            itemCount = result.optInt("item_count", 0)
        )
    }

    private fun decodeRestoreResult(result: JSONObject): RestoreResult {
        try {
            val items = result.optJSONArray("items") ?: JSONArray()
            return RestoreResult(
                success = result.optBoolean("success", false),
                restored = stringList(result.optJSONArray("restored")),
                message = result.optString("message", "").ifEmpty { null },
                items = (0 until items.length()).map { i ->
                    val item = items.getJSONObject(i)
                    RestoreItem(
                        item = item.optString("item", ""),
                        restored = item.optInt("restored", 0),
                        quarantined = item.optInt("quarantined", 0),
                        skipped = item.optInt("skipped", 0),
                        errors = stringList(item.optJSONArray("errors"))
                    )
                }
            )
        } catch (e: JSONException) {
            throw RemoteBackupException.MalformedReply("items is not a list of objects")
        }
    }

    private fun stringList(array: JSONArray?): List<String> =
        if (array == null) emptyList() else (0 until array.length()).map { array.getString(it) }

    internal companion object {
        private const val TAG = "RemoteBackupClient"

        /**
         * Distinct from RemoteKeyClient's 1_000_000, RemoteSyncClient's
         * 2_000_000 and the enrollment client's 3_000_000 bases so ids from
         * clients sharing one router never collide. The counter is shared by
         * every instance, so a client built for a later backup never reuses an
         * id an earlier one sent.
         */
        const val BASE_REQUEST_ID = 4_000_000L

        private val nextRequestId = AtomicLong(BASE_REQUEST_ID)

        /**
         * The request `{"id":…,"method":…,"params":{…,"password":"…"}}` as
         * UTF-8, with [password] written as a JSON string straight into the
         * returned buffer: no [String] of it, and no intermediate copy, is
         * ever made. The caller owns the buffer and must zero it.
         */
        fun encodeRequest(id: Long, method: String, params: JSONObject, password: CharArray): ByteArray {
            val head = Request(id, method, params).toJsonString()
            // Request puts params last, so its text ends with params' "}" and
            // the envelope's "}". The password goes before params' brace.
            check(head.endsWith("}}")) { "unexpected request shape" }
            val separator = if (params.length() == 0) "" else ","
            val prefix = (head.substring(0, head.length - 2) + separator + "\"password\":\"")
                .toByteArray(Charsets.UTF_8)
            val suffix = "\"}}".toByteArray(Charsets.UTF_8)
            val out = ByteArray(prefix.size + escapedLength(password) + suffix.size)
            prefix.copyInto(out)
            val end = writeEscaped(password, out, prefix.size)
            suffix.copyInto(out, end)
            return out
        }

        /** UTF-8 length of [chars] as the body of a JSON string. */
        private fun escapedLength(chars: CharArray): Int {
            var n = 0
            var i = 0
            while (i < chars.size) {
                val c = chars[i]
                n += when {
                    c == '"' || c == '\\' -> 2
                    c < ' ' -> 6
                    c.code < 0x80 -> 1
                    c.code < 0x800 -> 2
                    Character.isHighSurrogate(c) && i + 1 < chars.size &&
                        Character.isLowSurrogate(chars[i + 1]) -> { i++; 4 }
                    else -> 3
                }
                i++
            }
            return n
        }

        /**
         * Writes [chars] as the body of a JSON string into [out] from [start];
         * returns the index after the last byte written. A lone surrogate is
         * written as U+FFFD, as Go's encoding/json would read it.
         */
        private fun writeEscaped(chars: CharArray, out: ByteArray, start: Int): Int {
            var p = start
            var i = 0
            while (i < chars.size) {
                val c = chars[i]
                when {
                    c == '"' || c == '\\' -> {
                        out[p++] = '\\'.code.toByte(); out[p++] = c.code.toByte()
                    }
                    c < ' ' -> {
                        out[p++] = '\\'.code.toByte(); out[p++] = 'u'.code.toByte()
                        out[p++] = '0'.code.toByte(); out[p++] = '0'.code.toByte()
                        out[p++] = HEX[c.code shr 4]; out[p++] = HEX[c.code and 0xF]
                    }
                    c.code < 0x80 -> out[p++] = c.code.toByte()
                    c.code < 0x800 -> {
                        out[p++] = (0xC0 or (c.code shr 6)).toByte()
                        out[p++] = (0x80 or (c.code and 0x3F)).toByte()
                    }
                    Character.isHighSurrogate(c) && i + 1 < chars.size &&
                        Character.isLowSurrogate(chars[i + 1]) -> {
                        val cp = Character.toCodePoint(c, chars[++i])
                        out[p++] = (0xF0 or (cp shr 18)).toByte()
                        out[p++] = (0x80 or ((cp shr 12) and 0x3F)).toByte()
                        out[p++] = (0x80 or ((cp shr 6) and 0x3F)).toByte()
                        out[p++] = (0x80 or (cp and 0x3F)).toByte()
                    }
                    else -> {
                        val cp = if (Character.isSurrogate(c)) 0xFFFD else c.code
                        out[p++] = (0xE0 or (cp shr 12)).toByte()
                        out[p++] = (0x80 or ((cp shr 6) and 0x3F)).toByte()
                        out[p++] = (0x80 or (cp and 0x3F)).toByte()
                    }
                }
                i++
            }
            return p
        }

        private val HEX = "0123456789abcdef".toByteArray(Charsets.US_ASCII)
    }
}

/**
 * The desktop's error codes for `remote.createBackup` / `remote.restoreBackup`
 * replies (go-xkms `pkg/pairingproto/protocol.go`, mapped by
 * `xkey/pkg/pairing/bridge.go` `mapErrorToRPC`).
 *
 * These are the laptop's codes, not the phone's own
 * [com.automatethethings.xkey.protocol.ErrorCodes], which uses -32020, -32021
 * and -32038 for other conditions. Never merge the two.
 */
object RemoteBackupErrorCodes {
    /** go-xkms `pkg/pairingproto/protocol.go`: bad params, including an empty or missing password. */
    const val INVALID_PARAMS = -32602

    /** go-xkms `pkg/pairingproto/protocol.go`: the desktop could not create the backup. */
    const val BACKUP_FAILED = -32020

    /** go-xkms `pkg/pairingproto/protocol.go`: a wrong password or a damaged envelope; not told apart. */
    const val RESTORE_FAILED = -32021

    /** go-xkms `pkg/pairingproto/protocol.go`: backup is not configured on this desktop. */
    const val BACKUP_NOT_CONFIGURED = -32035

    /** go-xkms `pkg/pairingproto/protocol.go`: exporting OATH or passwords needs desktop approval. */
    const val APPROVAL_REQUIRED = -32038
}

/** A typed failure of a phone-initiated backup or restore. */
sealed class RemoteBackupException(message: String, val code: Int? = null) : Exception(message) {
    /** Refused on the phone: the password is empty. Nothing was sent. */
    class EmptyPassword : RemoteBackupException("backup password is empty")

    /** Refused on the phone: no store was selected. Nothing was sent. */
    class NothingSelected : RemoteBackupException("no store selected for the backup")

    /** -32602: the desktop refused the parameters (password required or bad request). */
    class InvalidParams(peerMessage: String) :
        RemoteBackupException("desktop refused the request: $peerMessage", RemoteBackupErrorCodes.INVALID_PARAMS)

    /** -32020: the desktop could not create the backup. */
    class CreationFailed(peerMessage: String) :
        RemoteBackupException("backup creation failed: $peerMessage", RemoteBackupErrorCodes.BACKUP_FAILED)

    /** -32021: the password is wrong or the backup is damaged. */
    class WrongPasswordOrDamaged(peerMessage: String) :
        RemoteBackupException("wrong password or damaged backup: $peerMessage", RemoteBackupErrorCodes.RESTORE_FAILED)

    /** -32035: backup is not configured on the desktop. */
    class NotConfigured(peerMessage: String) :
        RemoteBackupException("backup not configured on the desktop: $peerMessage", RemoteBackupErrorCodes.BACKUP_NOT_CONFIGURED)

    /** -32038: the desktop must approve exporting OATH or passwords. */
    class ApprovalRequired(peerMessage: String) :
        RemoteBackupException("approve the export on the desktop: $peerMessage", RemoteBackupErrorCodes.APPROVAL_REQUIRED)

    /** Any other error code. */
    class Other(code: Int, peerMessage: String) :
        RemoteBackupException("desktop error $code: $peerMessage", code)

    /** The desktop did not answer in time. */
    class TimedOut(method: String) : RemoteBackupException("backup request timed out: $method")

    /** The desktop's reply could not be read. */
    class MalformedReply(detail: String) : RemoteBackupException("unreadable backup reply: $detail")

    companion object {
        /** Maps a `remote.*Backup` error reply to its typed failure. */
        fun fromError(code: Int, peerMessage: String): RemoteBackupException = when (code) {
            RemoteBackupErrorCodes.INVALID_PARAMS -> InvalidParams(peerMessage)
            RemoteBackupErrorCodes.BACKUP_FAILED -> CreationFailed(peerMessage)
            RemoteBackupErrorCodes.RESTORE_FAILED -> WrongPasswordOrDamaged(peerMessage)
            RemoteBackupErrorCodes.BACKUP_NOT_CONFIGURED -> NotConfigured(peerMessage)
            RemoteBackupErrorCodes.APPROVAL_REQUIRED -> ApprovalRequired(peerMessage)
            else -> Other(code, peerMessage)
        }
    }
}
