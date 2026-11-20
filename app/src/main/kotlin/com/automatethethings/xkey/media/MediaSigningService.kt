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
import android.content.Context
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
import com.automatethethings.xkey.crypto.KeyNotFoundException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.MediaSigningSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.time.Instant

/**
 * The content hash the automatic signer signs, kept apart from the service so
 * the signing-to-verification round trip can be tested on the JVM.
 *
 * Memory stays bounded for every capture: a JPEG is read into memory only up
 * to [MAX_CANONICAL_JPEG_BYTES], an MP4/MOV, PNG or WebP only up to
 * [XmpMetadataHelper.maxEmbedBytes], and anything larger or of another type
 * is hashed by streaming.
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

    /**
     * Media the automatic signer refuses to sign: a JPEG above [limit] bytes,
     * or larger media that already carries an embedded signature.
     */
    class TooLargeException(
        val limit: Int,
        message: String = "JPEG is larger than $limit bytes, the most the automatic signer canonicalises"
    ) : java.io.IOException(message)

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
     * [contentHash] over the content at [uri], typed by the resolver, in the
     * domain verification uses. A JPEG above [limit] bytes throws
     * [TooLargeException].
     *
     * An MP4/MOV, PNG or WebP may already carry an embedded signature (an
     * import, or a capture notified again after a restart), which the
     * canonical hash leaves out and [XmpMetadataHelper.writeSignature]
     * replaces. Up to [embedLimit] bytes it is read into memory and hashed
     * canonically. A larger one is hashed whole while streaming: unsigned,
     * its canonical hash is its plain hash, and the writer embeds it
     * streaming ([XmpContainers.embedFile]); if it already carries an embedded
     * signature, which only an in-memory rewrite replaces, it is refused with
     * [TooLargeException] and the existing signature is kept.
     *
     * Any other media goes to a sidecar and is hashed whole by streaming
     * ([MediaHasher.hashUri]).
     */
    fun contentHashUri(
        contentResolver: ContentResolver,
        uri: Uri,
        limit: Int = MAX_CANONICAL_JPEG_BYTES,
        embedLimit: Int = XmpMetadataHelper.maxEmbedBytes
    ): String = contentHashOf(contentResolver.getType(uri), limit, embedLimit) {
        contentResolver.openInputStream(uri) ?: throw IllegalArgumentException("Cannot open URI: $uri")
    }

    /**
     * The one hash of a capture xKey signs: [contentHashUri] over its
     * original bytes, location included ([MediaPublisher.openOriginal]),
     * never MediaStore's redacted view, whose hash the original read when it
     * is written would not match. Without location access it throws
     * [MediaPublisher.OriginalUnavailableException] and hashes nothing: the
     * capture waits until the original is readable.
     */
    fun contentHashOriginal(
        context: Context,
        uri: Uri,
        limit: Int = MAX_CANONICAL_JPEG_BYTES,
        embedLimit: Int = XmpMetadataHelper.maxEmbedBytes
    ): String {
        if (MediaPublisher.originalUri(context, uri) == null) throw MediaPublisher.OriginalUnavailableException(uri)
        return contentHashOf(context.contentResolver.getType(uri), limit, embedLimit) {
            MediaPublisher.openOriginal(context, uri)
        }
    }

    /**
     * [contentHashUri] over [file], typed [mimeType]: the hash the signer
     * computes, for media already copied out of its provider. Co-signing
     * checks a staged copy's payload with it, so the hash the witness signed
     * is the payload's own and never only what its signature data says.
     */
    fun contentHashFile(
        file: java.io.File,
        mimeType: String?,
        limit: Int = MAX_CANONICAL_JPEG_BYTES,
        embedLimit: Int = XmpMetadataHelper.maxEmbedBytes
    ): String = contentHashOf(mimeType, limit, embedLimit) { file.inputStream() }

    /** The one place the signer's content hash is computed, over the media [open] streams from its start. */
    private fun contentHashOf(
        mimeType: String?,
        limit: Int,
        embedLimit: Int,
        open: () -> java.io.InputStream
    ): String {
        if (MediaHasher.isCanonicalisedJpeg(mimeType)) {
            return contentHash(open().use { readAtMost(it, limit) }, mimeType)
        }
        val format = XmpContainers.formatOf(mimeType) ?: return open().use { MediaHasher.hashStream(it) }
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val bytes = open().use { readOrDigest(it, embedLimit, digest) }
        if (bytes != null) return contentHash(bytes, mimeType)
        val carried = open().use { XmpContainers.read(it.buffered(), format) }
        if (carried != null) {
            throw TooLargeException(
                embedLimit,
                "media is larger than $embedLimit bytes and already carries an embedded signature"
            )
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

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

    /**
     * All of [input] while it stays within [limit] bytes; past that, null,
     * with every byte fed to [digest] and never more than [limit] bytes held.
     */
    private fun readOrDigest(
        input: java.io.InputStream,
        limit: Int,
        digest: java.security.MessageDigest
    ): ByteArray? {
        var out: java.io.ByteArrayOutputStream? = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n == -1) return out?.toByteArray()
            digest.update(buffer, 0, n)
            total += n
            if (total > limit) out = null else out?.write(buffer, 0, n)
        }
    }
}

/**
 * The automatic signer's handling of one capture, kept apart from the
 * service so it can be tested on the JVM: hash its original
 * ([AutoSignHash.contentHashOriginal]), sign that hash ([sign]) and write the
 * signature ([XmpMetadataHelper.signMedia]). A capture whose original is not
 * readable yet (no location access) or that needs the user's write access is
 * queued ([MediaWriteAuthorizations]); the queue is its only retry.
 */
internal object AutoSigner {

    enum class Outcome { Signed, AwaitingAccess }

    /**
     * Signs a content hash with the key [keyId]. The one signing step for
     * captures, at capture time and for a queued capture hashed later; tests
     * replace it.
     */
    @Volatile
    var sign: suspend (Context, String, String) -> ContentAuthenticityData = { context, keyId, contentHash ->
        // Suspends in its caller's coroutine: the service's IO scope, or the request screen's publication.
        val key = XKeyDatabase.getInstance(context).keyDao().getByKeyId(keyId) ?: throw KeyNotFoundException(keyId)
        signHash(KeystoreManager(context), key, contentHash)
    }

    /** [contentHash] signed with [key]: the signature data embedded in the capture. */
    suspend fun signHash(keystoreManager: KeystoreManager, key: KeyEntity, contentHash: String): ContentAuthenticityData {
        val hashBytes = contentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        // The key fingerprinted and the key signed with are one lookup: the
        // public key under the alias the signature is made with.
        val alias = KeystoreManager.generalKeyAlias(key.keyId)
        val pubKeyDer = keystoreManager.publicKeyDERAt(alias) ?: throw KeyNotFoundException(key.keyId)
        val signature = keystoreManager.signApproved(
            alias,
            pubKeyDer,
            hashBytes,
            KeystoreManager.jcaSignatureAlgorithm(key.algorithm)
        )
        val entry = SignatureEntry(
            keyFingerprint = MediaHasher.hashBytes(pubKeyDer),
            signerName = key.label,
            algorithm = key.algorithm,
            value = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
            timestamp = Instant.now().toString(),
            role = SignerRole.CREATOR
        )
        return ContentAuthenticityData(contentHash = contentHash, signatures = listOf(entry))
    }

    /**
     * Sign the capture at [uri] (its file [filePath] when MediaStore names
     * one) with [keyId]. Its original is hashed, never the redacted view:
     * without location access nothing is hashed or signed, and it is queued
     * unsigned until the user grants that access. A capture that needs write
     * access is queued with its signature. A JPEG too large to canonicalise
     * throws [AutoSignHash.TooLargeException].
     */
    suspend fun signCapture(context: Context, uri: Uri, filePath: String?, keyId: String, keyLabel: String): Outcome {
        val contentHash = try {
            AutoSignHash.contentHashOriginal(context, uri)
        } catch (e: MediaPublisher.OriginalUnavailableException) {
            MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), filePath, keyId, keyLabel, null))
            MediaWriteAuthorizations.notifyPending(context)
            return Outcome.AwaitingAccess
        }
        val data = sign(context, keyId, contentHash)
        // The signature lives in the media's own metadata. A capture another
        // app owns (the camera's) is written only through its content URI
        // once the user grants access: until then it is queued and the user
        // is asked, never renamed over by path.
        // Android 10 has no write request: MediaStore asks at the write, and
        // the write request screen launches that question, so it is queued too.
        val signed = try {
            XmpMetadataHelper.signMedia(context, uri, filePath, data)
        } catch (_: MediaPublisher.UserActionRequiredException) {
            XmpMetadataHelper.MediaSignResult.NeedsWriteAuthorization
        }
        if (signed == XmpMetadataHelper.MediaSignResult.NeedsWriteAuthorization) {
            MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), filePath, keyId, keyLabel, data))
            MediaWriteAuthorizations.notifyPending(context)
            return Outcome.AwaitingAccess
        }
        return Outcome.Signed
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

    private lateinit var settingsRepository: MediaSigningSettingsRepository
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var wakeLock: PowerManager.WakeLock? = null
    private var imageObserver: ContentObserver? = null
    private var videoObserver: ContentObserver? = null
    /**
     * URIs already signed, so a repeated MediaStore notification for the same
     * item is ignored. Concurrent because a burst capture delivers several
     * events that are handled on [Dispatchers.IO] at the same time.
     */
    private val processedUris: MutableSet<String> =
        java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap())

    /**
     * Every in-flight signing coroutine, so [onDestroy] cancels all of them
     * rather than only the most recently started one.
     */
    private val signingJobs = java.util.Collections.newSetFromMap(
        java.util.concurrent.ConcurrentHashMap<Job, Boolean>()
    )

    override fun onCreate() {
        super.onCreate()
        settingsRepository = MediaSigningSettingsRepository(this)
        createNotificationChannel()
        // A granted write an earlier process died in: its capture is put back.
        serviceScope.launch {
            runCatching { MediaPublisher.recoverInterruptedWrites(applicationContext) }
                .onFailure { Log.w(TAG, "Recovering interrupted media writes failed", it) }
        }
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
        if (processedUris.contains(uriString)) return

        val job = serviceScope.launch {
            try {
                // Small delay to ensure file is fully written
                delay(SIGN_DELAY_MS)

                val settings = settingsRepository.getSettings()
                if (!settings.autoSignEnabled) return@launch
                if (mediaType == "image" && !settings.signPhotos) return@launch
                if (mediaType == "video" && !settings.signVideos) return@launch

                val keyId = settings.signingKeyId ?: return@launch

                // Get key info from database
                val db = XKeyDatabase.getInstance(this@MediaSigningService)
                val keyEntity = db.keyDao().getByKeyId(keyId) ?: run {
                    Log.w(TAG, "Signing key not found: $keyId")
                    return@launch
                }

                // Hash the original (never MediaStore's redacted view), sign
                // and write; a capture still waiting for location or write
                // access is queued, and the queue is its retry.
                val filePath = getFilePathFromUri(uri)
                val outcome = try {
                    AutoSigner.signCapture(this@MediaSigningService, uri, filePath, keyId, keyEntity.label)
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
                    processedUris.add(uriString)
                    return@launch
                }
                if (outcome == AutoSigner.Outcome.AwaitingAccess) {
                    processedUris.add(uriString)
                    Log.i(TAG, "Queued $mediaType $uri; it is signed once the user grants access")
                    return@launch
                }

                processedUris.add(uriString)
                // Keep set bounded
                if (processedUris.size > 1000) {
                    val iterator = processedUris.iterator()
                    repeat(500) { if (iterator.hasNext()) { iterator.next(); iterator.remove() } }
                }

                AuditLogger.logMediaAutoSigned(keyId, keyEntity.label, uriString)
                Log.i(TAG, "Auto-signed $mediaType: $uri")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to auto-sign media: $uri", e)
            } catch (e: OutOfMemoryError) {
                // Hashing is bounded, so this is a backstop: one capture
                // that cannot be signed must not take the process down.
                Log.e(TAG, "Out of memory auto-signing media: $uri", e)
            }
        }
        signingJobs += job
        job.invokeOnCompletion { signingJobs -= job }
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
