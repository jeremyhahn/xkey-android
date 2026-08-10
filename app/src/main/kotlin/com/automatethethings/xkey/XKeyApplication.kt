package com.automatethethings.xkey

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.automatethethings.xkey.audit.AuditLogger

/**
 * xKey Application class.
 *
 * Handles application-level initialization including notification channels,
 * audit logging, and dependency injection setup.
 */
class XKeyApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        initializeAuditLogger()
    }

    /**
     * Initialize the audit logging system.
     */
    private fun initializeAuditLogger() {
        AuditLogger.initialize(this)
    }

    /**
     * Creates notification channels for the app.
     * Required for Android 8.0 (API 26) and above.
     *
     * Two channels are created:
     * - Low-priority channel for the foreground service status
     * - High-priority channel for biometric authentication requests
     */
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(NotificationManager::class.java)

            // Foreground service channel (low priority)
            val serviceChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(serviceChannel)

            // Biometric request channel (high priority for lock screen visibility)
            val biometricChannel = NotificationChannel(
                BIOMETRIC_CHANNEL_ID,
                getString(R.string.biometric_channel_name),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.biometric_channel_description)
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 250, 250, 250)
                enableLights(true)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setShowBadge(true)
            }
            notificationManager.createNotificationChannel(biometricChannel)
        }
    }

    companion object {
        /** Low-priority channel for foreground service status. */
        const val NOTIFICATION_CHANNEL_ID = "xkey_service"

        /** High-priority channel for biometric authentication requests. */
        const val BIOMETRIC_CHANNEL_ID = "xkey_biometric"
    }
}
