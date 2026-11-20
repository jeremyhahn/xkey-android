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
package com.automatethethings.xkey.media

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import com.automatethethings.xkey.R
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * A capture waiting for the user's access: the signature to embed and who
 * signs it. [data] is null while the capture is not hashed or signed yet,
 * because only MediaStore's redacted view was readable (no location access):
 * it is hashed from its original and signed by [MediaWriteAuthorizations.publishGranted].
 */
data class PendingMediaWrite(
    val uri: String,
    val filePath: String?,
    val keyId: String,
    val keyLabel: String,
    val data: ContentAuthenticityData?
)

/**
 * The captures the auto-signer signed but may not write yet: another app
 * owns them, so the user grants write access first. A capture whose original
 * was not readable (no location access) waits here unsigned, and is hashed
 * from its original and signed once it is. They are kept under
 * the app's files, so a process death loses none; a notification, or the
 * media-signing settings entry when notifications are off ([settingsEntry]),
 * opens [MediaWriteRequestActivity], which asks for every one in one write request
 * ([request]) and then publishes the granted ones ([publishGranted]) or drops
 * them on a refusal ([deny]).
 */
object MediaWriteAuthorizations {

    private const val TAG = "MediaWriteAuth"
    private const val FILE = "media-write-requests.json"
    private const val CHANNEL_ID = "media_write_requests"
    private const val NOTIFICATION_ID = 2003

    private val lock = Any()

    private fun store(context: Context) = File(context.filesDir, FILE)

    /** The one read of the queue's text; tests make it fail. */
    @Volatile
    internal var readStore: (File) -> String = { it.readText() }

    /**
     * Every capture waiting for write access, oldest first. A queue that
     * cannot be read throws [java.io.IOException]; it is never taken as empty.
     */
    fun pending(context: Context): List<PendingMediaWrite> = synchronized(lock) { read(context) }

    /**
     * Queue [write], replacing an earlier one for the same media. When the
     * queue cannot be read this throws [java.io.IOException] and changes
     * nothing, so the caller reports [write] as not queued.
     */
    fun add(context: Context, write: PendingMediaWrite): Unit = synchronized(lock) {
        save(context, read(context).filterNot { it.uri == write.uri } + write)
    }

    /** Forget every queued capture. */
    fun clear(context: Context): Unit = synchronized(lock) { store(context).delete() }

    /**
     * What publishing the queue needs: every queued capture ([uris]) and the
     * write request the user approves for those that need a grant ([intent],
     * asking for [requested]). A null [intent] means none needs one (before
     * Android 11 xKey writes media itself, and MediaStore has no write
     * request there): the queue is published at once.
     */
    class WriteRequest(val uris: List<String>, val requested: List<String>, val intent: PendingIntent?)

    /** The write request for every queued capture, or null when none waits. */
    fun request(context: Context): WriteRequest? {
        val uris = pending(context).map { it.uri }
        if (uris.isEmpty()) return null
        val needGrant = uris.filter {
            MediaPublisher.writeAccess(context, Uri.parse(it)) == MediaPublisher.MediaWriteAccess.NEEDS_GRANT
        }
        if (needGrant.isEmpty()) return WriteRequest(uris, emptyList(), null)
        return WriteRequest(uris, needGrant, MediaPublisher.writeRequest(context, needGrant.map(Uri::parse)))
    }

    /**
     * Sign every queued capture the user granted write access to, calling
     * [onSigned] for each; one still without a grant stays queued, and so
     * does one whose write failed ([MediaPublishException]): its media is
     * whole again, so the next request retries it. A capture queued unsigned
     * is hashed from its original and signed first ([signedFromOriginal]);
     * while only the redacted view is readable (no location access) it stays
     * queued, unsigned. Any other failure to read, stage or embed keeps it
     * queued too; only a permanent refusal ([permanentRefusal]: it changed
     * since it was signed, is gone, cannot be hashed, or its key is gone)
     * drops it, as its signature matches nothing. A signature that differs
     * from the capture only because it was made over the redacted view
     * ([signedOverRedactedView]) is no change: the capture is signed again
     * from its original.
     */
    suspend fun publishGranted(context: Context, onSigned: (PendingMediaWrite) -> Unit) {
        // A retry: captures an earlier write was interrupted in are whole first.
        MediaPublisher.recoverInterruptedWrites(context)
        for (queued in pending(context)) {
            var write = queued
            val outcome = try {
                write = signedFromOriginal(context, write)
                try {
                    XmpMetadataHelper.signMedia(context, Uri.parse(write.uri), write.filePath, requireNotNull(write.data))
                } catch (e: XmpMetadataHelper.SourceChangedException) {
                    if (!signedOverRedactedView(context, write)) throw e
                    Log.w(TAG, "${write.uri} was signed over its redacted view; it is signed again from its original")
                    write = signedFromOriginal(context, write.copy(data = null))
                    XmpMetadataHelper.signMedia(context, Uri.parse(write.uri), write.filePath, requireNotNull(write.data))
                }
            } catch (e: MediaPublishException) {
                Log.w(TAG, "Writing ${write.uri} failed; it stays queued", e)
                // The capture is whole and the retry stages afresh; a copy that could not be put back is kept.
                if (e.original == null) e.kept.delete()
                continue
            } catch (e: MediaPublisher.RecoveryPendingException) {
                // Part-written and not put back yet: nothing was staged, and the
                // request stays queued so a later grant can restore and sign it.
                Log.w(TAG, "${write.uri} is not restored yet; it stays queued", e)
                continue
            } catch (e: MediaPublisher.UserActionRequiredException) {
                // Android 10 asks the user at the write: nothing was written,
                // and the caller launches the question, then publishes again.
                throw e
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Signing suspends: a cancelled publication ends here, the rest still queued.
                throw e
            } catch (e: Exception) {
                if (!permanentRefusal(e)) {
                    // A read, staging or embedding failure (a full disk, a
                    // provider that is busy), or an original not readable
                    // yet: nothing was written, and the auto-signer will not
                    // offer this capture again, so the queue is its only retry.
                    Log.w(TAG, "Signing ${write.uri} failed; it stays queued", e)
                    continue
                }
                Log.w(TAG, "Not signing ${write.uri}", e)
                null
            }
            if (outcome == XmpMetadataHelper.MediaSignResult.NeedsWriteAuthorization) continue
            remove(context, write.uri)
            if (outcome == XmpMetadataHelper.MediaSignResult.Signed) onSigned(write)
        }
    }

    /**
     * [write] with its signature. One queued unsigned is hashed from its
     * original ([AutoSignHash.contentHashOriginal]) and signed
     * ([AutoSigner.sign]), and the queue keeps it signed so a later retry
     * signs it no second time. While only the redacted view is readable this
     * throws [MediaPublisher.OriginalUnavailableException] and hashes nothing.
     */
    private suspend fun signedFromOriginal(context: Context, write: PendingMediaWrite): PendingMediaWrite {
        if (write.data != null) return write
        val contentHash = AutoSignHash.contentHashOriginal(context, Uri.parse(write.uri))
        val signed = write.copy(data = AutoSigner.sign(context, write.keyId, contentHash))
        add(context, signed)
        return signed
    }

    /**
     * Whether [write]'s signature covers MediaStore's redacted view of its
     * capture (location left out) rather than the capture as it is: its hash
     * is the redacted view's. That is no edit of the capture, so it is never
     * a reason to drop it.
     */
    private fun signedOverRedactedView(context: Context, write: PendingMediaWrite): Boolean {
        val uri = Uri.parse(write.uri)
        val original = MediaPublisher.originalUri(context, uri) ?: return false
        if (original == uri) return false
        val redacted = try {
            AutoSignHash.contentHashUri(context.contentResolver, uri)
        } catch (e: Exception) {
            return false
        }
        return write.data?.contentHash.equals(redacted, ignoreCase = true)
    }

    /**
     * The user refused the write request for [requested]: those captures
     * stay unsigned and leave the queue. Any queued after the request was
     * shown are kept for the next one, and so is one a granted write left
     * part-written: only a later grant can put it back. Android 10 has no
     * grant to check: the user refused the write MediaStore asked about.
     */
    fun deny(context: Context, requested: Collection<String>) {
        val refused = pending(context).filter {
            it.uri in requested &&
                !MediaPublisher.recoveryPending(context, Uri.parse(it.uri)) &&
                (Build.VERSION.SDK_INT < Build.VERSION_CODES.R ||
                    MediaPublisher.writeAccess(context, Uri.parse(it.uri)) == MediaPublisher.MediaWriteAccess.NEEDS_GRANT)
        }
        refused.forEach { remove(context, it.uri) }
    }

    /**
     * A failure no retry can mend: the capture changed since it was signed
     * (its signature matches nothing), is gone, cannot be hashed, or the key
     * it is to be signed with is gone. Every other failure, an original not
     * readable yet included, is retried from the queue.
     */
    private fun permanentRefusal(e: Exception): Boolean =
        e is XmpMetadataHelper.SourceChangedException ||
            e is java.io.FileNotFoundException ||
            e is MediaTooFragmentedException ||
            e is AutoSignHash.TooLargeException ||
            e is com.automatethethings.xkey.crypto.KeyNotFoundException

    /** The settings entry for captures waiting for write access: how many wait, and the [intent] that asks for them. */
    class SettingsEntry(val count: Int, val intent: Intent)

    /** The one way into [MediaWriteRequestActivity]: the notification and the settings entry both open it. */
    fun requestIntent(context: Context): Intent = Intent(context, MediaWriteRequestActivity::class.java)

    /**
     * The settings entry for the waiting captures, or null when none waits or
     * the queue cannot be read. It does not depend on the notification, which
     * may be refused (POST_NOTIFICATIONS) or turned off.
     */
    fun settingsEntry(context: Context): SettingsEntry? {
        val count = try {
            pending(context).size
        } catch (e: java.io.IOException) {
            Log.w(TAG, "Cannot read the write-request queue", e)
            return null
        }
        return if (count == 0) null else SettingsEntry(count, requestIntent(context))
    }

    /**
     * The runtime permission to ask for when auto-signing is turned on, so
     * the write-access notification can be posted: POST_NOTIFICATIONS on
     * Android 13+ until it is granted, otherwise null.
     */
    fun notificationPermissionToRequest(context: Context): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return null
        val permission = android.Manifest.permission.POST_NOTIFICATIONS
        val granted = androidx.core.content.ContextCompat.checkSelfPermission(context, permission) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
        return if (granted) null else permission
    }

    /** Tell the user captures wait for write access; tapping it opens the request. */
    fun notifyPending(context: Context) {
        val count = try {
            pending(context).size
        } catch (e: java.io.IOException) {
            // The queue is kept; the notification stays as it was until it reads again.
            Log.w(TAG, "Cannot read the write-request queue", e)
            return
        }
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (count == 0) {
            manager.cancel(NOTIFICATION_ID)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Media signing access", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val intent = requestIntent(context).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val open = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle("Allow xKey to sign new media")
            .setContentText("$count new captures wait for your access to be signed")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            manager.notify(NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            Log.w(TAG, "Cannot post the write-access notification", e)
        }
    }

    /** Drop [uri] from the queue; a queue that cannot be read is left whole and this throws. */
    private fun remove(context: Context, uri: String): Unit = synchronized(lock) {
        save(context, read(context).filterNot { it.uri == uri })
    }

    /**
     * The queue as stored, or empty only when there is no store. A store
     * that cannot be read or parsed throws [java.io.IOException] and is left
     * as it is: treating it as empty would let [add] or [remove] replace it
     * and lose every capture still waiting for write access.
     */
    private fun read(context: Context): List<PendingMediaWrite> {
        val file = store(context)
        if (!file.exists()) return emptyList()
        return try {
            val array = JSONArray(readStore(file))
            (0 until array.length()).map { i ->
                val o = array.getJSONObject(i)
                PendingMediaWrite(
                    uri = o.getString("uri"),
                    filePath = if (o.isNull("filePath")) null else o.getString("filePath"),
                    keyId = o.getString("keyId"),
                    keyLabel = o.getString("keyLabel"),
                    data = if (o.isNull("data")) null else ContentAuthenticityData.fromJsonString(o.getString("data"))
                )
            }
        } catch (e: java.io.IOException) {
            throw e
        } catch (e: Exception) {
            throw java.io.IOException("the write-request queue cannot be parsed", e)
        }
    }

    private fun save(context: Context, writes: List<PendingMediaWrite>) {
        val file = store(context)
        if (writes.isEmpty()) {
            file.delete()
            return
        }
        val array = JSONArray()
        writes.forEach { w ->
            array.put(
                JSONObject()
                    .put("uri", w.uri)
                    .put("filePath", w.filePath ?: JSONObject.NULL)
                    .put("keyId", w.keyId)
                    .put("keyLabel", w.keyLabel)
                    .put("data", w.data?.toJsonString() ?: JSONObject.NULL)
            )
        }
        val temp = File(file.path + ".tmp")
        temp.writeText(array.toString())
        if (!temp.renameTo(file)) {
            temp.delete()
            throw java.io.IOException("cannot save ${file.path}")
        }
    }
}
