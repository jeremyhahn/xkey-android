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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.time.Instant

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

                // Hash the media content
                val contentHash = MediaHasher.hashUri(contentResolver, uri)
                val hashBytes = contentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

                // Sign with the configured key
                val signature = keystoreManager.signWithAlgorithm(keyId, hashBytes, keyEntity.algorithm)
                val signatureBase64 = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP)

                // Compute key fingerprint
                val pubKeyDer = keystoreManager.getPublicKeyDER(keyId)
                val keyFingerprint = if (pubKeyDer != null) {
                    MediaHasher.hashBytes(pubKeyDer)
                } else keyId

                // Build signature data
                val entry = SignatureEntry(
                    keyFingerprint = keyFingerprint,
                    signerName = keyEntity.label,
                    algorithm = keyEntity.algorithm,
                    value = signatureBase64,
                    timestamp = Instant.now().toString(),
                    role = SignerRole.CREATOR
                )
                val data = ContentAuthenticityData(
                    contentHash = contentHash,
                    signatures = listOf(entry)
                )

                // The signature lives in the file's own metadata, so without a
                // path there is nowhere to put it. Leaving the URI unprocessed
                // lets a later event retry it; recording it as auto-signed would
                // put a claim in the audit log that nothing backs.
                val filePath = getFilePathFromUri(uri) ?: run {
                    Log.w(TAG, "No file path for $uri; cannot persist a signature")
                    return@launch
                }
                XmpMetadataHelper.writeSignature(filePath, data)

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
