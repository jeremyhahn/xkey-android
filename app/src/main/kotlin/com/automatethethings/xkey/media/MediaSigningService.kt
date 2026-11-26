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

package com.automatethethings.xkey.media

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ContentResolver
import android.content.Intent
import android.content.pm.ServiceInfo
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.provider.MediaStore
import android.util.Log
import androidx.core.app.NotificationCompat
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.MediaSigningSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.time.Instant

/**
 * The content hash the automatic signer signs, kept apart from the service so
 * the signing-to-verification round trip can be tested on the JVM.
 *
 * Memory stays bounded for every capture: media other than JPEG is hashed by
 * streaming, and a JPEG is read into memory only up to
 * [MAX_CANONICAL_JPEG_BYTES].
 */
internal object AutoSignHash {

    /**
     * Largest JPEG the automatic signer canonicalises: 32 MiB, above any
     * phone camera's JPEG output. Canonicalising needs the file in memory
     * (about three times this at peak: the read buffer, its copy and the
     * canonical bytes), so a larger JPEG is refused with
     * [TooLargeException] rather than risking the app heap.
     */
    const val MAX_CANONICAL_JPEG_BYTES = 32 * 1024 * 1024

    /** A JPEG above [limit] bytes, which the automatic signer refuses to sign. */
    class TooLargeException(val limit: Int) :
        java.io.IOException("JPEG is larger than $limit bytes, the most the automatic signer canonicalises")

    /**
     * The stored `contentHash` for [data], typed by [mimeType]: the canonical
     * hash ([MediaHasher.hashCanonical]). The signature is embedded in the
     * file after hashing, so a whole-file hash would never match again, and
     * the in-band check ([MediaHasher.contentHashMatches]) accepts only the
     * canonical one.
     */
    fun contentHash(data: ByteArray, mimeType: String?): String =
        MediaHasher.hashCanonical(data, mimeType)

    /**
     * [contentHash] over the content at [uri], typed by [mimeType] (the
     * resolver's type unless given). Content [MediaHasher.isJpeg] says is not
     * a JPEG, by the type or its first bytes, is hashed whole by streaming:
     * its signature goes to a sidecar, and for it the canonical hash is the
     * whole-file hash. A JPEG above [limit] bytes throws [TooLargeException].
     */
    fun contentHashUri(
        contentResolver: ContentResolver,
        uri: Uri,
        limit: Int = MAX_CANONICAL_JPEG_BYTES,
        mimeType: String? = contentResolver.getType(uri)
    ): String {
        val input = contentResolver.openInputStream(uri)?.buffered()
            ?: throw IllegalArgumentException("Cannot open URI: $uri")
        return input.use { stream ->
            stream.mark(MediaHasher.JPEG_HEAD_SIZE)
            val head = MediaHasher.readFully(stream, MediaHasher.JPEG_HEAD_SIZE)
            stream.reset()
            if (MediaHasher.isJpeg(mimeType, head = head)) {
                contentHash(readAtMost(stream, limit), MediaHasher.JPEG_MIME_TYPE)
            } else {
                MediaHasher.hashStream(stream)
            }
        }
    }

    /**
     * The type to hash the file at [filePath] as, decided the way
     * [XmpMetadataHelper.writeSignature] decides where its signature goes: a
     * file [MediaHasher.isJpegFile] says is a JPEG gets the signature
     * embedded, so it is hashed canonically as a JPEG; any other file gets a
     * sidecar, so it is hashed whole (null).
     */
    fun hashTypeForPath(filePath: String): String? =
        if (MediaHasher.isJpegFile(filePath)) MediaHasher.JPEG_MIME_TYPE else null

    /** All of [input], or [TooLargeException] as soon as it passes [limit] bytes. */
    private fun readAtMost(input: java.io.InputStream, limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n == -1) return out.toByteArray()
            total += n
            if (total > limit) throw TooLargeException(limit)
            out.write(buffer, 0, n)
        }
    }
}

/**
 * Runs the automatic signer at most once per capture.
 *
 * One capture delivers a burst of MediaStore events (insert, pending
 * cleared, rescan), and each arrives before the first has finished its
 * [delayMs] wait. The URI is claimed when the event arrives, not when the
 * signature is written, so the burst starts one job: one signature, one
 * audit row, one writer on the file.
 *
 * The signing block returns [Outcome.DONE] when the capture is finished
 * with (signed, or a failure audited) and [Outcome.RETRY] when it was
 * skipped and a later event may try again; a skipped or throwing attempt
 * releases the claim.
 */
internal class AutoSignQueue(
    private val scope: CoroutineScope,
    private val delayMs: Long,
    private val onError: (String, Throwable) -> Unit = { _, _ -> }
) {
    enum class Outcome { DONE, RETRY }

    private val claimed: MutableSet<String> =
        java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap())

    /** The signing job for [uri], or null when it is already claimed. */
    fun submit(uri: String, sign: suspend () -> Outcome): Job? {
        if (!claimed.add(uri)) return null
        trim()
        return scope.launch {
            var outcome = Outcome.RETRY
            try {
                delay(delayMs)
                outcome = sign()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                onError(uri, e)
            } catch (e: OutOfMemoryError) {
                // Hashing is bounded, so this is a backstop: one capture
                // that cannot be signed must not take the process down.
                onError(uri, e)
            } finally {
                if (outcome != Outcome.DONE) claimed.remove(uri)
            }
        }
    }

    /** Keeps the set bounded; it is unordered, so any half goes. */
    private fun trim() {
        if (claimed.size <= MAX_CLAIMED) return
        val iterator = claimed.iterator()
        repeat(MAX_CLAIMED / 2) { if (iterator.hasNext()) { iterator.next(); iterator.remove() } }
    }

    private companion object {
        const val MAX_CLAIMED = 1000
    }
}

class MediaSigningService : Service() {

    companion object {
        private const val TAG = "MediaSigningService"
        private const val CHANNEL_ID = "media_signing_channel"
        private const val NOTIFICATION_ID = 2002
        private const val WAKE_LOCK_TAG = "xkey:media_signing"
        private const val SIGN_DELAY_MS = 500L
    }

    private lateinit var keystoreManager: KeystoreManager
    private lateinit var settingsRepository: MediaSigningSettingsRepository
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var wakeLock: PowerManager.WakeLock? = null
    private var imageObserver: ContentObserver? = null
    private var videoObserver: ContentObserver? = null
    /**
     * Claims each capture's URI when its first MediaStore event arrives, so
     * a repeated notification for the same item is ignored.
     */
    private val signingQueue = AutoSignQueue(
        serviceScope,
        SIGN_DELAY_MS,
        onError = { uri, e -> Log.e(TAG, "Failed to auto-sign media: $uri", e) }
    )

    /**
     * Every in-flight signing coroutine, so [onDestroy] cancels all of them
     * rather than only the most recently started one.
     */
    private val signingJobs = java.util.Collections.newSetFromMap(
        java.util.concurrent.ConcurrentHashMap<Job, Boolean>()
    )

    override fun onCreate() {
        super.onCreate()
        keystoreManager = KeystoreManager(this)
        settingsRepository = MediaSigningSettingsRepository(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // The type must be passed here as well as declared in the manifest. On
        // API 34+ a start without it registers as typeless, which the system logs
        // and which forfeits the dataSync allowances the manifest asks for.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification())
        }
        // START_STICKY means this runs again on redelivery, and a second
        // startService call reaches it too. Without releasing first, the
        // previous observers stay registered and keep signing after onDestroy.
        releaseWakeLock()
        unregisterObservers()
        acquireWakeLock()
        registerObservers()
        Log.i(TAG, "Media signing service started")
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterObservers()
        releaseWakeLock()
        // Cancelling the scope, not only the jobs in flight, means a change
        // already dispatched to an observer starts no new signing after this.
        serviceScope.cancel()
        signingJobs.forEach { it.cancel() }
        signingJobs.clear()
        Log.i(TAG, "Media signing service stopped")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun registerObservers() {
        val handler = Handler(Looper.getMainLooper())

        imageObserver = object : ContentObserver(handler) {
            override fun onChange(selfChange: Boolean, uri: Uri?) {
                uri?.let { handleNewMedia(it, "image") }
            }
        }
        videoObserver = object : ContentObserver(handler) {
            override fun onChange(selfChange: Boolean, uri: Uri?) {
                uri?.let { handleNewMedia(it, "video") }
            }
        }

        contentResolver.registerContentObserver(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            true,
            imageObserver!!
        )
        contentResolver.registerContentObserver(
            MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
            true,
            videoObserver!!
        )
    }

    private fun unregisterObservers() {
        imageObserver?.let { contentResolver.unregisterContentObserver(it) }
        videoObserver?.let { contentResolver.unregisterContentObserver(it) }
        imageObserver = null
        videoObserver = null
    }

    private fun handleNewMedia(uri: Uri, mediaType: String) {
        val uriString = uri.toString()
        // Claimed here, before the delay, so a burst of events for one
        // capture starts one job (AutoSignQueue).
        val job = signingQueue.submit(uriString) { signNewMedia(uri, mediaType) } ?: return
        signingJobs += job
        job.invokeOnCompletion { signingJobs -= job }
    }

    /**
     * Signs one capture. [AutoSignQueue.Outcome.RETRY] when it was skipped
     * (signing off, no key) or the content could not be read yet (a
     * pending capture throws), so a later event may try again.
     */
    private suspend fun signNewMedia(uri: Uri, mediaType: String): AutoSignQueue.Outcome {
        val uriString = uri.toString()
        val settings = settingsRepository.getSettings()
        if (!settings.autoSignEnabled) return AutoSignQueue.Outcome.RETRY
        if (mediaType == "image" && !settings.signPhotos) return AutoSignQueue.Outcome.RETRY
        if (mediaType == "video" && !settings.signVideos) return AutoSignQueue.Outcome.RETRY

        val keyId = settings.signingKeyId ?: return AutoSignQueue.Outcome.RETRY

        // Get key info from database
        val db = XKeyDatabase.getInstance(this@MediaSigningService)
        val keyEntity = db.keyDao().getByKeyId(keyId) ?: run {
            Log.w(TAG, "Signing key not found: $keyId")
            return AutoSignQueue.Outcome.RETRY
        }

        // The path decides where the signature goes, and so which hash it
        // must carry; without one the content type decides, and a write
        // the app is refused goes to the private store.
        val filePath = getFilePathFromUri(uri)
        val hashType = if (filePath != null) AutoSignHash.hashTypeForPath(filePath) else contentResolver.getType(uri)
        // A non-JPEG row with no path yet is retried once the row has its path.
        if (filePath == null && !MediaHasher.isJpeg(hashType)) return AutoSignQueue.Outcome.RETRY

        // Hash the media content
        val contentHash = try {
            AutoSignHash.contentHashUri(contentResolver, uri, mimeType = hashType)
        } catch (e: AutoSignHash.TooLargeException) {
            // Refused, not failed: record it once so a repeated
            // MediaStore event does not audit it again.
            Log.w(TAG, "Not auto-signing $uri: ${e.message}")
            AuditLogger.logKeyUsed(
                keyId = keyId,
                keyLabel = keyEntity.label,
                keyType = keyEntity.keyType,
                operation = "media_auto_sign",
                success = false,
                errorMessage = e.message
            )
            return AutoSignQueue.Outcome.DONE
        }

        // From here a failure is audited and the capture is done: retrying
        // on every later MediaStore event would fail the same way, and a
        // log line alone leaves the user believing the capture is signed.
        val where = try {
            val data = signContentHash(keyId, keyEntity, contentHash)
            XmpMetadataHelper.persistSignature(data) { writeIntoMedia(uri, filePath, hashType, data) }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "Auto-signing $uri failed: ${e.javaClass.simpleName}")
            AuditLogger.logKeyUsed(
                keyId = keyId,
                keyLabel = keyEntity.label,
                keyType = keyEntity.keyType,
                operation = "media_auto_sign",
                success = false,
                errorMessage = e.javaClass.simpleName
            )
            return AutoSignQueue.Outcome.DONE
        }

        AuditLogger.logMediaAutoSigned(keyId, keyEntity.label, uriString)
        Log.i(TAG, "Auto-signed $mediaType ($where): $uri")
        return AutoSignQueue.Outcome.DONE
    }

    /**
     * The signature data for [contentHash] under the configured key. The key
     * fingerprinted and the key signed with are one lookup: the public key
     * under the alias the signature is made with.
     */
    private suspend fun signContentHash(
        keyId: String,
        keyEntity: com.automatethethings.xkey.storage.entity.KeyEntity,
        contentHash: String
    ): ContentAuthenticityData {
        val hashBytes = contentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val alias = KeystoreManager.generalKeyAlias(keyId)
        val pubKeyDer = keystoreManager.publicKeyDERAt(alias)
            ?: throw com.automatethethings.xkey.crypto.KeyNotFoundException(keyId)
        val signature = keystoreManager.signApproved(
            alias,
            pubKeyDer,
            hashBytes,
            KeystoreManager.jcaSignatureAlgorithm(keyEntity.algorithm)
        )
        val entry = SignatureEntry(
            keyFingerprint = MediaHasher.hashBytes(pubKeyDer),
            signerName = keyEntity.label,
            algorithm = keyEntity.algorithm,
            value = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
            timestamp = Instant.now().toString(),
            role = SignerRole.CREATOR
        )
        return ContentAuthenticityData(contentHash = contentHash, signatures = listOf(entry))
    }

    /**
     * Writes [data] into the capture itself: at [filePath] when there is one
     * (embedded in a JPEG, a sidecar otherwise), else a JPEG through the
     * ContentResolver. On API 30+ another app's capture refuses the write
     * (EACCES, SecurityException), and [XmpMetadataHelper.persistSignature]
     * keeps the signature privately.
     */
    private fun writeIntoMedia(uri: Uri, filePath: String?, hashType: String?, data: ContentAuthenticityData) {
        if (filePath != null) {
            XmpMetadataHelper.writeSignature(filePath, data)
        } else if (MediaHasher.isJpeg(hashType)) {
            XmpMetadataHelper.writeSignature(contentResolver, uri, data)
        } else {
            throw java.io.FileNotFoundException("no file path for $uri")
        }
    }

    private fun getFilePathFromUri(uri: Uri): String? {
        // Query MediaStore for DATA column (file path)
        try {
            @Suppress("DEPRECATION")
            val projection = arrayOf(MediaStore.MediaColumns.DATA)
            contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val columnIndex = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATA)
                    return cursor.getString(columnIndex)
                }
            }
        } catch (_: Exception) {}
        return null
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.media_signing_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.media_signing_channel_description)
        }
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.media_signing_notification_title))
            .setContentText(getString(R.string.media_signing_notification_text))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun acquireWakeLock() {
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            WAKE_LOCK_TAG
        ).apply {
            acquire(10 * 60 * 1000L) // 10 minutes max
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) it.release()
        }
        wakeLock = null
    }
}
