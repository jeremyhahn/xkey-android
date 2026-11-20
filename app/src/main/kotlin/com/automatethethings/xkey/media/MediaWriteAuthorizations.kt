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

/** A signed capture waiting for the user's write access: the signature to embed and who signed it. */
data class PendingMediaWrite(
    val uri: String,
    val filePath: String?,
    val keyId: String,
    val keyLabel: String,
    val data: ContentAuthenticityData
)

/**
 * The captures the auto-signer signed but may not write yet: another app
 * owns them, so the user grants write access first. They are kept under
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

    /** A write request shown to the user: the captures it asks for ([uris]) and its [intent]. */
    class WriteRequest(val uris: List<String>, val intent: PendingIntent)

    /** The write request for every queued capture, or null when none waits. */
    fun request(context: Context): WriteRequest? {
        val uris = pending(context).map { it.uri }
        if (uris.isEmpty()) return null
        return WriteRequest(uris, MediaPublisher.writeRequest(context, uris.map(Uri::parse)))
    }

    /**
     * Sign every queued capture the user granted write access to, calling
     * [onSigned] for each; one still without a grant stays queued, and so
     * does one whose write failed ([MediaPublishException]): its media is
     * whole again, so the next request retries it. Any other failure to read,
     * stage or embed keeps it queued too; only a permanent refusal
     * ([permanentRefusal]: it changed since it was signed, is gone, or cannot
     * be hashed) drops it, as its signature matches nothing.
     */
    fun publishGranted(context: Context, onSigned: (PendingMediaWrite) -> Unit) {
        // A retry: captures an earlier write was interrupted in are whole first.
        MediaPublisher.recoverInterruptedWrites(context)
        for (write in pending(context)) {
            val outcome = try {
                XmpMetadataHelper.signMedia(context, Uri.parse(write.uri), write.filePath, write.data)
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
            } catch (e: Exception) {
                if (!permanentRefusal(e)) {
                    // A read, staging or embedding failure (a full disk, a
                    // provider that is busy): nothing was signed, and the
                    // auto-signer will not offer this capture again, so the
                    // queue is its only retry.
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
     * The user refused the write request for [requested]: those captures
     * stay unsigned and leave the queue. Any queued after the request was
     * shown are kept for the next one, and so is one a granted write left
     * part-written: only a later grant can put it back.
     */
    fun deny(context: Context, requested: Collection<String>) {
        val refused = pending(context).filter {
            it.uri in requested &&
                !MediaPublisher.recoveryPending(context, Uri.parse(it.uri)) &&
                MediaPublisher.writeAccess(context, Uri.parse(it.uri)) == MediaPublisher.MediaWriteAccess.NEEDS_GRANT
        }
        refused.forEach { remove(context, it.uri) }
    }

    /**
     * A failure no retry can mend: the capture changed since it was signed
     * (its signature matches nothing), is gone, or cannot be hashed. Every
     * other failure is retried from the queue.
     */
    private fun permanentRefusal(e: Exception): Boolean =
        e is XmpMetadataHelper.SourceChangedException ||
            e is java.io.FileNotFoundException ||
            e is MediaTooFragmentedException

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
            .setContentText("$count captured by another app wait for write access")
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
                    data = ContentAuthenticityData.fromJsonString(o.getString("data"))
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
                    .put("data", w.data.toJsonString())
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
