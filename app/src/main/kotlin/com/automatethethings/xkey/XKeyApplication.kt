package com.automatethethings.xkey

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystorePqcBackend
import com.automatethethings.xkey.crypto.PqcHardware
import com.automatethethings.xkey.crypto.PqcSoftwareKeyStore
import com.automatethethings.xkey.settings.PairedDeviceGrantCleanup
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.ui.ClipboardFocusRetry
import com.automatethethings.xkey.ui.PromptActivityTracker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * xKey Application class.
 *
 * Handles application-level initialization including notification channels,
 * audit logging, and dependency injection setup.
 */
class XKeyApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        // Pairing and biometric prompts are hosted by whichever screen is in front.
        registerActivityLifecycleCallbacks(PromptActivityTracker)
        createNotificationChannels()
        initializeAuditLogger()
        registerPqcSoftwareStore(this)
        registerPqcHardware()
        registerGrantCleanup()
        // Finish a copied secret's pending clipboard clear from any screen.
        registerActivityLifecycleCallbacks(ClipboardFocusRetry)
        replayOwedKeyDeletions()
    }

    /**
     * Key material whose delete failed, or whose process died after its key
     * row was deleted, keeps a tombstone; it is deleted here, at start-up
     * (#193 r9).
     */
    private fun replayOwedKeyDeletions() {
        val app = this
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            replayOwedKeyDeletionsAtStartup(
                openStore = { KeyPolicyStore.of(XKeyDatabase.getInstance(app), com.automatethethings.xkey.crypto.KeystoreManager(app)) },
                replay = { store -> com.automatethethings.xkey.storage.replayKeyDeletions(app, store) }
            )
        }
    }

    /**
     * Initialize the audit logging system.
     */
    private fun initializeAuditLogger() {
        AuditLogger.initialize(this)
    }

    /**
     * Registers the Android Keystore ML-DSA backend and starts its probe on
     * an application-lifetime IO scope. Startup never waits for it: until
     * the probe ends no hardware ML-DSA set is offered.
     */
    private fun registerPqcHardware() {
        val backend = KeystorePqcBackend()
        PqcHardware.backend = backend
        backend.startProbe(CoroutineScope(SupervisorJob() + Dispatchers.IO))
    }

    /**
     * A device that stops being paired loses its per-key sharing grants
     * (#174). Registered here, once per process, because the Activity that
     * unpairs and the services that evict each build their own repository;
     * its removal listeners are process-wide. Revocations a previous process
     * left pending (it died, or the delete failed) are replayed here.
     */
    private fun registerGrantCleanup() {
        val app = this
        val repository by lazy { PairedDeviceRepository(app) }
        val cleanup = PairedDeviceGrantCleanup(
            policyDao = { XKeyDatabase.getInstance(app).keySharingPolicyDao() },
            repository = { repository },
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        )
        PairedDeviceRepository.addRemovalListener(cleanup)
        cleanup.replayPending()
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

        /**
         * Registers the app's software ML-DSA store before any screen runs,
         * so a PIV key manager built without one (a PIV slot screen reopened
         * alone after the process died) still finds it.
         */
        internal fun registerPqcSoftwareStore(context: Context) {
            PqcSoftwareKeyStore.registerShared(context)
        }
    }
}

/**
 * The start-up replay of owed key deletes (#193 r9), safe to run on a bare
 * coroutine: opening the store ([openStore]: the database and the Keystore)
 * may throw, and such a failure is logged, never thrown, so it cannot crash
 * the process. Nothing is replayed then, and the owed deletes stay recorded
 * for the next start (Codex round 3 on #270).
 *
 * @return Whether the store opened and [replay] ran.
 */
internal suspend fun replayOwedKeyDeletionsAtStartup(
    openStore: () -> KeyPolicyStore,
    replay: suspend (KeyPolicyStore) -> Unit
): Boolean {
    val store = try {
        openStore()
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        android.util.Log.e("XKeyApplication", "Opening the key store for the delete replay failed; replayed next start", e)
        return false
    }
    replay(store)
    return true
}
