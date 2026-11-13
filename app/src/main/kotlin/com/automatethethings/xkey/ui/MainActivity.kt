package com.automatethethings.xkey.ui

import android.Manifest
import android.animation.AnimatorSet
import android.animation.ObjectAnimator

import android.bluetooth.BluetoothManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.VisibleForTesting
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.core.view.doOnLayout
import androidx.core.view.updateLayoutParams
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ble.ServiceState
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.ca.CertificateDao
import com.automatethethings.xkey.databinding.ActivityMainBinding
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.time.Clock
import java.time.ZoneId
import java.util.Locale

/**
 * Main activity for xKey - Premium Security Key Experience.
 *
 * Features a stunning, security-focused home screen with:
 * - Animated hero section with pulsing status indicator
 * - Glass morphism status card with smooth state transitions
 * - Premium navigation cards with elegant ripple effects
 * - Connection duration tracking
 * - Hardware capability visualization
 *
 * Design Language:
 * - Primary: Deep Navy (#1A237E) - Trust and authority
 * - Secondary: Warm Gold (#FFB300) - Premium distinction
 * - Tertiary: Rich Teal (#00897B) - Security verification
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var pairedDeviceRepository: PairedDeviceRepository
    private lateinit var trustStoreRepository: TrustStoreRepository
    private lateinit var certificateDao: CertificateDao

    // Animation controllers
    private var pulseAnimator: AnimatorSet? = null
    private var connectionStartTime: Long = 0L
    private var connectionDurationUpdater: Runnable? = null

    // Service binding state
    private var gattService: XKeyGattService? = null
    private var serviceBound = false

    // Dashboard card visibility state
    private var isAuthRequestActive = false
    private var isDeviceConnected = false

    // Required Bluetooth permissions based on SDK version
    private val requiredPermissions: Array<String>
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_SCAN
            )
        } else {
            arrayOf(
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN
            )
        }

    // Permission launcher
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (allGranted) {
            startGattService()
        } else {
            showPermissionDeniedMessage()
        }
    }

    // Service connection callback
    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as XKeyGattService.LocalBinder
            gattService = binder.getService()
            serviceBound = true

            // Set activity reference for biometric prompts
            gattService?.setActivity(this@MainActivity)

            // Start observing service state
            observeServiceState()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            gattService = null
            serviceBound = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Enable edge-to-edge display
        WindowCompat.setDecorFitsSystemWindows(window, false)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        pairedDeviceRepository = PairedDeviceRepository(this)
        trustStoreRepository = TrustStoreRepository(this)
        certificateDao = XKeyDatabase.getInstance(this).certificateDao()

        setupUI()
        setupAnimations()
        checkDeviceCapabilities()
        // Auto-start BLE service if permissions are already granted
        if (hasRequiredPermissions() && !serviceBound) {
            startGattService()
        }

        // Handle USB accessory attached intent
        handleUsbAccessoryIntent(intent)

        // Check battery optimization after a delay
        binding.root.postDelayed({
            checkBatteryOptimization()
        }, 2000)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleUsbAccessoryIntent(intent)
    }

    /**
     * Handles USB_ACCESSORY_ATTACHED intents by forwarding to XKeyGattService.
     */
    private fun handleUsbAccessoryIntent(intent: Intent?) {
        if (intent?.action == UsbManager.ACTION_USB_ACCESSORY_ATTACHED) {
            @Suppress("DEPRECATION")
            val accessory = intent.getParcelableExtra<UsbAccessory>(UsbManager.EXTRA_ACCESSORY)
            if (accessory != null) {
                Log.d("MainActivity", "USB accessory attached: ${accessory.manufacturer} ${accessory.model}")
                // Ensure service is started before forwarding
                if (!serviceBound) {
                    startGattService()
                }
                gattService?.onUsbAccessoryAttached(accessory)
            }
        }
    }

    /**
     * Sets up the premium UI with click listeners and initial state.
     */
    private fun setupUI() {
        // BLE Toggle Switch - replaces the old Start/Stop button
        bindBleSwitchListener()

        // Key Management card
        binding.cardKeyManagement.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, KeyManagementActivity::class.java))
        }

        // Paired Devices card
        binding.cardPairedDevices.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, PairedDevicesActivity::class.java))
        }

        // Settings card
        binding.cardSettings.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        // Trust Store card
        binding.cardTrustStore.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, TrustStoreActivity::class.java))
        }

        // Certificates card
        binding.cardCertificates.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, CertificateManagementActivity::class.java))
        }

        // Authenticator card
        binding.cardAuthenticator.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, OathActivity::class.java))
        }

        // Passkeys card
        binding.cardPasskeys.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, PasskeysActivity::class.java))
        }

        // Contacts card
        binding.cardContacts.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, ContactManagementActivity::class.java))
        }

        // Passwords card
        binding.cardPasswords.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, PasswordManagementActivity::class.java))
        }

        // Sync Now card (phone-initiated bidirectional sync with the connected desktop)
        binding.cardSyncNow.setOnClickListener {
            animateCardPress(it)
            val service = gattService
            if (!serviceBound || service == null) {
                Snackbar.make(binding.root, R.string.sync_not_connected, Snackbar.LENGTH_LONG).show()
                return@setOnClickListener
            }
            Snackbar.make(binding.root, R.string.sync_in_progress, Snackbar.LENGTH_SHORT).show()
            lifecycleScope.launch {
                try {
                    val result = service.syncNow()
                    // The desktop's own view of sync (remote.syncStatus); a
                    // failure here leaves the completed sync reported as is.
                    val status = SyncStatusText.fetch(service::desktopSyncStatus)
                    val line = SyncStatusText.desktopLine(status, ZoneId.systemDefault(), Locale.getDefault())
                    Snackbar.make(
                        binding.root,
                        getString(R.string.sync_complete, result.totalPushed, result.totalPulled) + "\n" +
                            getString(line.message, line.arg),
                        Snackbar.LENGTH_LONG
                    ).apply { setTextMaxLines(3) }.show()
                } catch (e: Exception) {
                    Snackbar.make(
                        binding.root,
                        getString(R.string.sync_failed, e.message ?: "error"),
                        Snackbar.LENGTH_LONG
                    ).show()
                }
            }
        }

        // Desktop Backup card (phone-initiated remote.createBackup / remote.restoreBackup)
        val desktopBackup = DesktopBackupDialogs(this, binding.root) {
            gattService?.takeIf { serviceBound }
        }
        binding.cardDesktopBackup.setOnClickListener {
            animateCardPress(it)
            desktopBackup.show()
        }

        // Audit Log card
        binding.cardAuditLog.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, AuditLogActivity::class.java))
        }
        observeRecentActivity()

        // PIV Smart Card card
        binding.cardPivSmartCard.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, PivActivity::class.java))
        }

        // PIN Management card
        binding.cardPinManagement.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, PinManagementActivity::class.java))
        }

        // Co-Sign card
        binding.cardCoSign.setOnClickListener {
            animateCardPress(it)
            startActivity(Intent(this, CoSignActivity::class.java))
        }

        buildTabHeaders()
        setupBottomNavigation()

        // Set initial UI state
        updateConnectionStatus(ConnectionStatus.DISCONNECTED)
        updateAdvertisingStatus(false)
        updatePairedDevicesCount()
        updateTrustStoreCount()
        updateCertificateCount()
        updateOathCount()
        updatePasskeysCount()
        updateBleStatusText(false)
    }

    /**
     * Updates the BLE status text next to the switch.
     */
    private fun updateBleStatusText(isActive: Boolean) {
        binding.textBleStatus.text = if (isActive) {
            getString(R.string.ble_switch_on)
        } else {
            getString(R.string.ble_switch_off)
        }
    }

    /**
     * Sets up smooth animations for the hero section.
     */
    private fun setupAnimations() {
        // Initial subtle scale animation for the status icon
        val iconView = binding.imageStatusIcon
        val scaleX = ObjectAnimator.ofFloat(iconView, View.SCALE_X, 1f, 1.05f, 1f)
        val scaleY = ObjectAnimator.ofFloat(iconView, View.SCALE_Y, 1f, 1.05f, 1f)

        scaleX.repeatCount = ObjectAnimator.INFINITE
        scaleY.repeatCount = ObjectAnimator.INFINITE
        scaleX.duration = 3000
        scaleY.duration = 3000
        scaleX.interpolator = AccelerateDecelerateInterpolator()
        scaleY.interpolator = AccelerateDecelerateInterpolator()

        pulseAnimator = AnimatorSet().apply {
            playTogether(scaleX, scaleY)
        }
    }

    /**
     * Starts the pulsing animation when advertising.
     */
    private fun startPulseAnimation() {
        pulseAnimator?.cancel()

        val iconView = binding.imageStatusIcon
        val outerRing = binding.viewStatusRingOuter
        val innerRing = binding.viewStatusRingInner

        // Icon pulse
        val iconScaleX = ObjectAnimator.ofFloat(iconView, View.SCALE_X, 1f, 1.1f, 1f)
        val iconScaleY = ObjectAnimator.ofFloat(iconView, View.SCALE_Y, 1f, 1.1f, 1f)

        // Outer ring pulse (expanding)
        val outerScaleX = ObjectAnimator.ofFloat(outerRing, View.SCALE_X, 1f, 1.15f, 1f)
        val outerScaleY = ObjectAnimator.ofFloat(outerRing, View.SCALE_Y, 1f, 1.15f, 1f)
        val outerAlpha = ObjectAnimator.ofFloat(outerRing, View.ALPHA, 1f, 0.6f, 1f)

        // Inner ring pulse
        val innerScaleX = ObjectAnimator.ofFloat(innerRing, View.SCALE_X, 1f, 1.08f, 1f)
        val innerScaleY = ObjectAnimator.ofFloat(innerRing, View.SCALE_Y, 1f, 1.08f, 1f)

        listOf(iconScaleX, iconScaleY, outerScaleX, outerScaleY, outerAlpha, innerScaleX, innerScaleY).forEach {
            it.repeatCount = ObjectAnimator.INFINITE
            it.duration = 1500
            it.interpolator = AccelerateDecelerateInterpolator()
        }

        pulseAnimator = AnimatorSet().apply {
            playTogether(iconScaleX, iconScaleY, outerScaleX, outerScaleY, outerAlpha, innerScaleX, innerScaleY)
            start()
        }
    }

    /**
     * Stops the pulsing animation.
     */
    private fun stopPulseAnimation() {
        pulseAnimator?.cancel()

        // Reset views to default state with smooth animation
        listOf(binding.imageStatusIcon, binding.viewStatusRingOuter, binding.viewStatusRingInner).forEach { view ->
            view.animate()
                .scaleX(1f)
                .scaleY(1f)
                .alpha(1f)
                .setDuration(300)
                .start()
        }
    }

    /**
     * Starts the connected state animation (subtle glow effect).
     */
    private fun startConnectedAnimation() {
        pulseAnimator?.cancel()

        val innerRing = binding.viewStatusRingInner

        // Subtle breathing glow for connected state
        val glowAlpha = ObjectAnimator.ofFloat(innerRing, View.ALPHA, 0.8f, 1f, 0.8f)
        glowAlpha.repeatCount = ObjectAnimator.INFINITE
        glowAlpha.duration = 2000
        glowAlpha.interpolator = LinearInterpolator()

        pulseAnimator = AnimatorSet().apply {
            play(glowAlpha)
            start()
        }
    }

    /**
     * Animates a card press with subtle scale effect.
     */
    private fun animateCardPress(view: View) {
        view.animate()
            .scaleX(0.98f)
            .scaleY(0.98f)
            .setDuration(80)
            .withEndAction {
                view.animate()
                    .scaleX(1f)
                    .scaleY(1f)
                    .setDuration(80)
                    .start()
            }
            .start()
    }

    /**
     * Checks device capabilities and displays them in the Device Information card.
     */
    private fun checkDeviceCapabilities() {
        // Device Model
        val deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}"
        binding.textDeviceModel.text = deviceModel

        // Android Version
        val androidVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
        binding.textAndroidVersion.text = androidVersion

        // Security Patch Level
        val securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Build.VERSION.SECURITY_PATCH
        } else {
            getString(R.string.device_info_not_available)
        }
        binding.textSecurityPatch.text = securityPatch

        // BLE Device Name (what peers see during pairing)
        val btAdapter = (getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        val deviceName = try { btAdapter?.name } catch (_: SecurityException) { null } ?: Build.MODEL
        binding.textDeviceName.text = deviceName

        // BLE MAC Address - Android 6.0+ returns fake 02:00:00:00:00:00 due to MAC randomization
        binding.textBleAddress.text = getString(R.string.device_info_ble_address_randomized)

        // Check StrongBox availability
        val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            false
        }
        updateCapabilityRow(
            binding.iconStrongBoxInfo,
            binding.textStrongBoxInfo,
            hasStrongBox
        )
        // Keep old bindings working for backward compatibility
        updateCapabilityRow(
            binding.iconStrongBox,
            binding.textStrongBoxStatus,
            hasStrongBox
        )

        // Check TEE availability (all modern Android devices have TEE)
        val hasTee = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
        updateCapabilityRow(
            binding.iconTeeInfo,
            binding.textTeeInfo,
            hasTee
        )

        // Check biometric availability
        val biometricManager = BiometricManager.from(this)
        val biometricAvailable = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
        updateCapabilityRow(
            binding.iconBiometricsInfo,
            binding.textBiometricsInfo,
            biometricAvailable
        )
        // Keep old bindings working for backward compatibility
        updateCapabilityRow(
            binding.iconBiometrics,
            binding.textBiometricsStatus,
            biometricAvailable
        )

        // Check BLE availability (for hidden backward compat views)
        val hasBle = packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)
        updateCapabilityRow(
            binding.iconBluetoothLE,
            binding.textBluetoothLEStatus,
            hasBle
        )

        // Update hidden textDeviceInfo for backward compatibility
        val capabilities = StringBuilder()
        capabilities.append("StrongBox: ${if (hasStrongBox) "Available" else "Not Available"}\n")
        capabilities.append("TEE: ${if (hasTee) "Available" else "Not Available"}\n")
        capabilities.append("Biometrics: ${if (biometricAvailable) "Available" else "Not Available"}\n")
        capabilities.append("Bluetooth LE: ${if (hasBle) "Available" else "Not Available"}")
        binding.textDeviceInfo.text = capabilities.toString()
    }

    /**
     * Updates a capability row with appropriate styling.
     */
    private fun updateCapabilityRow(icon: ImageView, statusText: TextView, available: Boolean) {
        val (statusString, colorRes) = if (available) {
            "Available" to R.color.security_verified
        } else {
            "Not Available" to R.color.security_neutral
        }

        statusText.text = statusString
        statusText.setTextColor(ContextCompat.getColor(this, colorRes))
        icon.imageTintList = ContextCompat.getColorStateList(this, colorRes)
    }

    /**
     * Updates the paired devices count display.
     */
    private fun updatePairedDevicesCount() {
        val deviceCount = pairedDeviceRepository.getAllDevices().size
        binding.textPairedDevicesCount.text = resources.getQuantityString(
            R.plurals.paired_devices_summary_count,
            deviceCount,
            deviceCount
        )
    }

    /**
     * Updates the trust store certificate count display.
     */
    private fun updateTrustStoreCount() {
        lifecycleScope.launch {
            val certCount = trustStoreRepository.getAllCertificates().size
            binding.textTrustStoreCount.text = if (certCount == 0) {
                getString(R.string.trust_store_summary_none)
            } else {
                resources.getQuantityString(
                    R.plurals.trust_store_card_count,
                    certCount,
                    certCount
                )
            }
        }
    }

    /**
     * Updates the certificate count display on the home screen card.
     */
    private fun updateCertificateCount() {
        lifecycleScope.launch {
            val totalCount = certificateDao.countAll()
            val expiredCount = certificateDao.countExpired()
            binding.textCertificateCount.text = when {
                totalCount == 0 -> getString(R.string.certificate_count_zero)
                expiredCount > 0 -> getString(R.string.certificate_count_with_expired, totalCount, expiredCount)
                else -> getString(R.string.certificate_count, totalCount)
            }
        }
    }

    /**
     * Updates the OATH credential count display on the home screen card.
     */
    private fun updateOathCount() {
        lifecycleScope.launch {
            val count = XKeyDatabase.getInstance(this@MainActivity).oathCredentialDao().count()
            binding.textOathCount.text = when (count) {
                0 -> getString(R.string.oath_card_description)
                1 -> getString(R.string.oath_count_one)
                else -> getString(R.string.oath_count, count)
            }
        }
    }

    /**
     * Updates the passkeys count display on the home screen card.
     */
    private fun updatePasskeysCount() {
        lifecycleScope.launch {
            val count = XKeyDatabase.getInstance(this@MainActivity).keyDao().countByType("fido2")
            binding.textPasskeysCount.text = when (count) {
                0 -> getString(R.string.passkeys_card_description)
                1 -> getString(R.string.passkeys_count_one)
                else -> getString(R.string.passkeys_count, count)
            }
        }
    }

    /**
     * Checks if the app is exempt from battery optimization.
     */
    private fun checkBatteryOptimization() {
        // This runs from a delayed Handler post; the activity may have finished
        // (navigated away, rotated, or torn down) before it fires. Showing a
        // dialog on a dead window throws BadTokenException, so bail out first.
        if (isFinishing || isDestroyed) return
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.battery_optimization_title)
                .setMessage(R.string.battery_optimization_message)
                .setPositiveButton(R.string.battery_optimization_settings) { _, _ ->
                    try {
                        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                            data = Uri.parse("package:$packageName")
                        }
                        startActivity(intent)
                    } catch (e: Exception) {
                        try {
                            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                        } catch (e2: Exception) {
                            Snackbar.make(
                                binding.root,
                                R.string.battery_optimization_error,
                                Snackbar.LENGTH_LONG
                            ).show()
                        }
                    }
                }
                .setNegativeButton(R.string.battery_optimization_later, null)
                .show()
        }
    }

    override fun onResume() {
        super.onResume()
        gattService?.setActivity(this)
        updatePairedDevicesCount()
        updateTrustStoreCount()
        updateCertificateCount()
        updateOathCount()
        updatePasskeysCount()
    }

    override fun onPause() {
        super.onPause()
        gattService?.setActivity(null)
    }

    override fun onDestroy() {
        super.onDestroy()
        pulseAnimator?.cancel()
        stopConnectionDurationUpdater()

        if (serviceBound) {
            gattService?.setActivity(null)
            unbindService(serviceConnection)
            serviceBound = false
        }
    }

    /**
     * Checks if all required permissions are granted.
     */
    private fun hasRequiredPermissions(): Boolean {
        return requiredPermissions.all { permission ->
            ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
        }
    }

    /**
     * Checks permissions and starts the GATT service if granted.
     */
    private fun checkPermissionsAndStart() {
        if (hasRequiredPermissions()) {
            startGattService()
        } else {
            permissionLauncher.launch(requiredPermissions)
        }
    }

    /**
     * Starts the xKey GATT service as a foreground service.
     */
    private fun startGattService() {
        val intent = Intent(this, XKeyGattService::class.java).apply {
            action = XKeyGattService.ACTION_START_ADVERTISING
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }

        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        AuditLogger.logServiceStarted()
    }

    /**
     * Stops the xKey GATT service.
     */
    private fun stopGattService() {
        gattService?.stopAdvertising()

        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }

        stopService(Intent(this, XKeyGattService::class.java))
        gattService = null

        updateConnectionStatus(ConnectionStatus.DISCONNECTED)
        updateAdvertisingStatus(false)
        stopPulseAnimation()
        stopConnectionDurationUpdater()
        AuditLogger.logServiceStopped("user_initiated")
    }

    /**
     * Observes the service state flow and updates the UI accordingly.
     */
    private fun observeServiceState() {
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                gattService?.serviceState?.collectLatest { state ->
                    handleServiceStateChange(state)
                }
            }
        }
    }

    companion object {
        /** The clock the Recent Activity times are measured against; tests replace it. */
        @VisibleForTesting
        internal var recentActivityClock: Clock = Clock.systemDefaultZone()
    }

    /**
     * Shows the newest audit entries in the Audit Log card's Recent Activity
     * section; tapping the card opens the full audit screen. The relative
     * times are recomputed once a minute while the activity is resumed.
     */
    private fun observeRecentActivity() {
        val dao = XKeyDatabase.getInstance(this).auditLogDao()
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                RecentActivityRows.observe(dao, recentActivityClock).collectLatest { rows ->
                    renderRecentActivity(rows)
                }
            }
        }
    }

    private fun renderRecentActivity(rows: List<RecentActivityRow>) {
        val container = binding.layoutRecentActivityRows
        container.removeAllViews()
        val secondary = UIHelpers.resolveThemeColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant)
        val error = UIHelpers.resolveThemeColor(this, androidx.appcompat.R.attr.colorError)
        rows.forEach { row ->
            when (row) {
                is RecentActivityRow.Empty -> container.addView(TextView(this).apply {
                    text = getString(row.messageRes)
                    textSize = 13f
                    setTextColor(secondary)
                })
                is RecentActivityRow.Entry -> {
                    val label = getString(row.labelRes)
                    val time = getString(row.timeRes, row.timeCount)
                    container.addView(TextView(this).apply {
                        text = row.keyLabel?.let { getString(R.string.recent_activity_pair, label, it) } ?: label
                        textSize = 14f
                        setPadding(0, UIHelpers.dpToPxInt(this@MainActivity, 6), 0, 0)
                    })
                    container.addView(TextView(this).apply {
                        text = getString(R.string.recent_activity_pair, getString(row.outcomeRes), time)
                        textSize = 12f
                        setTextColor(if (row.success) secondary else error)
                    })
                }
            }
        }
    }

    /**
     * Handles service state changes with smooth UI transitions.
     */
    private fun handleServiceStateChange(state: ServiceState) {
        runOnUiThread {
            when (state) {
                is ServiceState.Stopped -> {
                    updateConnectionStatus(ConnectionStatus.DISCONNECTED)
                    updateAdvertisingStatus(false)
                    updateConnectedDeviceInfo(null, null)
                    stopPulseAnimation()
                    stopConnectionDurationUpdater()
                }
                is ServiceState.Ready -> {
                    updateConnectionStatus(ConnectionStatus.DISCONNECTED)
                    updateAdvertisingStatus(false)
                    updateConnectedDeviceInfo(null, null)
                    stopPulseAnimation()
                }
                is ServiceState.Advertising -> {
                    updateConnectionStatus(ConnectionStatus.ADVERTISING)
                    updateAdvertisingStatus(true)
                    updateConnectedDeviceInfo(null, null)
                    startPulseAnimation()
                }
                is ServiceState.Connecting -> {
                    updateConnectionStatus(ConnectionStatus.CONNECTING)
                    updateAdvertisingStatus(true)
                }
                is ServiceState.Connected -> {
                    updateConnectionStatus(ConnectionStatus.CONNECTED)
                    updateAdvertisingStatus(false)
                    updateConnectedDeviceInfo(state.deviceName, state.deviceAddress)
                    startConnectedAnimation()
                    startConnectionDurationUpdater()
                    AuditLogger.logConnectionEstablished(
                        deviceId = state.deviceAddress,
                        deviceName = state.deviceName,
                        connectionType = "BLE"
                    )
                }
                is ServiceState.Error -> {
                    showError(state.message)
                }
            }
        }
    }

    /**
     * Updates the connection status UI elements with smooth transitions.
     */
    private fun updateConnectionStatus(status: ConnectionStatus) {
        val (statusText, descriptionText, indicatorColorRes, heroStatusText) = when (status) {
            ConnectionStatus.DISCONNECTED -> StatusUIConfig(
                getString(R.string.status_disconnected),
                getString(R.string.connection_indicator_disconnected),
                R.color.status_disconnected,
                getString(R.string.status_disconnected)
            )
            ConnectionStatus.ADVERTISING -> StatusUIConfig(
                getString(R.string.status_advertising),
                getString(R.string.advertising_waiting),
                R.color.status_advertising,
                getString(R.string.status_advertising)
            )
            ConnectionStatus.CONNECTING -> StatusUIConfig(
                getString(R.string.status_connecting),
                getString(R.string.connection_indicator_connecting),
                R.color.status_advertising,
                getString(R.string.status_connecting)
            )
            ConnectionStatus.CONNECTED -> StatusUIConfig(
                getString(R.string.status_connected),
                getString(R.string.connection_indicator_connected),
                R.color.status_connected,
                getString(R.string.status_connected)
            )
            ConnectionStatus.AUTHENTICATING -> StatusUIConfig(
                getString(R.string.status_authenticating),
                getString(R.string.auth_request_processing),
                R.color.status_connected,
                getString(R.string.status_authenticating)
            )
        }

        // Update hero section with fade animation
        binding.textStatusLarge.apply {
            animate().alpha(0f).setDuration(150).withEndAction {
                text = heroStatusText
                animate().alpha(1f).setDuration(150).start()
            }.start()
        }

        binding.textStatusDescription.apply {
            animate().alpha(0f).setDuration(150).withEndAction {
                text = descriptionText
                animate().alpha(0.85f).setDuration(150).start()
            }.start()
        }

        // Update status card
        binding.textConnectionStatus.text = statusText
        binding.textConnectionDescription.text = descriptionText

        // Update indicator color with smooth transition
        val indicator = binding.viewConnectionIndicator.background as? GradientDrawable
            ?: GradientDrawable().also { binding.viewConnectionIndicator.background = it }
        indicator.shape = GradientDrawable.OVAL
        indicator.setColor(ContextCompat.getColor(this, indicatorColorRes))

        // Update button state
        val isActive = status != ConnectionStatus.DISCONNECTED
        updateButtonState(isActive)
    }

    /**
     * Attaches the BLE toggle's checked-change listener.
     *
     * Checking the switch starts advertising (starting and binding the service
     * first if it is not running yet); unchecking it stops the service. The single
     * source of truth for that behaviour lives here because [updateButtonState]
     * detaches the listener to set the switch silently and must reattach exactly
     * the same one afterwards.
     */
    private fun bindBleSwitchListener() {
        binding.switchBle.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                if (serviceBound && gattService != null) {
                    if (gattService?.isAdvertising() != true) {
                        gattService?.startAdvertising()
                    }
                } else {
                    checkPermissionsAndStart()
                }
            } else {
                if (serviceBound && gattService != null) {
                    stopGattService()
                }
            }
            updateBleStatusText(isChecked)
        }
    }

    /**
     * Updates the BLE switch state and status text.
     */
    private fun updateButtonState(isActive: Boolean) {
        // Update switch without triggering the listener
        binding.switchBle.setOnCheckedChangeListener(null)
        binding.switchBle.isChecked = isActive
        bindBleSwitchListener()
        updateBleStatusText(isActive)
    }

    /**
     * Updates the advertising status display.
     */
    private fun updateAdvertisingStatus(isAdvertising: Boolean) {
        binding.textAdvertisingStatus.apply {
            text = if (isAdvertising) {
                getString(R.string.advertising_on)
            } else {
                getString(R.string.advertising_off)
            }
            visibility = View.VISIBLE
        }
    }

    /**
     * Updates the connected device information display with smooth reveal.
     */
    private fun updateConnectedDeviceInfo(deviceName: String?, deviceAddress: String?) {
        isDeviceConnected = deviceName != null && deviceAddress != null
        if (isDeviceConnected) {
            binding.textConnectedDeviceName.text = deviceName
            binding.textConnectedDeviceAddress.text = deviceAddress
            binding.cardConnectedDevice.apply {
                if (visibility != View.VISIBLE) {
                    alpha = 0f
                    visibility = View.VISIBLE
                    animate().alpha(1f).setDuration(300).start()
                }
            }
        } else {
            binding.cardConnectedDevice.apply {
                if (visibility == View.VISIBLE) {
                    animate().alpha(0f).setDuration(200).withEndAction {
                        visibility = View.GONE
                    }.start()
                }
            }
        }
    }

    /**
     * Starts the connection duration updater.
     */
    private fun startConnectionDurationUpdater() {
        connectionStartTime = System.currentTimeMillis()
        binding.textConnectionDuration.visibility = View.VISIBLE

        connectionDurationUpdater = object : Runnable {
            override fun run() {
                val elapsed = System.currentTimeMillis() - connectionStartTime
                val seconds = (elapsed / 1000) % 60
                val minutes = (elapsed / (1000 * 60)) % 60
                val hours = elapsed / (1000 * 60 * 60)

                val durationText = when {
                    hours > 0 -> "Connected for ${hours}h ${minutes}m"
                    minutes > 0 -> "Connected for ${minutes}m ${seconds}s"
                    else -> "Connected for ${seconds}s"
                }
                binding.textConnectionDuration.text = durationText
                binding.root.postDelayed(this, 1000)
            }
        }
        binding.root.post(connectionDurationUpdater!!)
    }

    /**
     * Stops the connection duration updater.
     */
    private fun stopConnectionDurationUpdater() {
        connectionDurationUpdater?.let {
            binding.root.removeCallbacks(it)
        }
        connectionDurationUpdater = null
        binding.textConnectionDuration.visibility = View.GONE
    }

    /**
     * Shows an authentication request card with premium styling.
     */
    fun showAuthenticationRequest(origin: String) {
        runOnUiThread {
            isAuthRequestActive = true
            binding.textAuthRequestOrigin.text = origin
            binding.cardAuthRequest.apply {
                if (visibility != View.VISIBLE) {
                    alpha = 0f
                    visibility = View.VISIBLE
                    animate()
                        .alpha(1f)
                        .translationY(0f)
                        .setDuration(300)
                        .start()
                }
            }
            updateConnectionStatus(ConnectionStatus.AUTHENTICATING)
        }
    }

    /**
     * Hides the authentication request card.
     */
    fun hideAuthenticationRequest() {
        runOnUiThread {
            isAuthRequestActive = false
            binding.cardAuthRequest.apply {
                animate()
                    .alpha(0f)
                    .setDuration(200)
                    .withEndAction {
                        visibility = View.GONE
                    }
                    .start()
            }
            if (serviceBound && gattService?.isConnected() == true) {
                updateConnectionStatus(ConnectionStatus.CONNECTED)
            }
        }
    }

    /**
     * Shows an error message with premium snackbar styling.
     */
    private fun showError(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(ContextCompat.getColor(this, R.color.error))
            .setTextColor(ContextCompat.getColor(this, R.color.on_error))
            .show()
    }

    /**
     * Shows a permission denied message.
     */
    private fun showPermissionDeniedMessage() {
        Snackbar.make(
            binding.root,
            getString(R.string.permission_denied),
            Snackbar.LENGTH_LONG
        ).setAction(getString(R.string.button_retry)) {
            permissionLauncher.launch(requiredPermissions)
        }.show()
    }

    /**
     * Builds gradient tab headers for each tab container,
     * matching the premium toolbar pattern used in other activities.
     */
    private fun buildTabHeaders() {
        data class TabHeaderConfig(
            val container: LinearLayout,
            val iconRes: Int,
            val titleRes: Int,
            val subtitleRes: Int
        )

        val tabs = listOf(
            TabHeaderConfig(
                binding.containerApps,
                R.drawable.ic_apps,
                R.string.tab_apps_title,
                R.string.tab_apps_subtitle
            ),
            TabHeaderConfig(
                binding.containerStore,
                R.drawable.ic_key_modern,
                R.string.tab_store_title,
                R.string.tab_store_subtitle
            ),
            TabHeaderConfig(
                binding.containerManagement,
                R.drawable.ic_admin,
                R.string.tab_management_title,
                R.string.tab_management_subtitle
            )
        )

        val gradientStart = ContextCompat.getColor(this, R.color.gradient_primary_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_primary_end)
        val onPrimary = ContextCompat.getColor(this, R.color.on_primary)

        for (tab in tabs) {
            val header = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                val gradient = GradientDrawable(
                    GradientDrawable.Orientation.LEFT_RIGHT,
                    intArrayOf(gradientStart, gradientEnd)
                )
                val bottomRadius = UIHelpers.dpToPx(this@MainActivity, 20f)
                gradient.cornerRadii = floatArrayOf(
                    0f, 0f, 0f, 0f,
                    bottomRadius, bottomRadius, bottomRadius, bottomRadius
                )
                background = gradient
                setPadding(
                    UIHelpers.dpToPxInt(this@MainActivity, 20),
                    UIHelpers.dpToPxInt(this@MainActivity, 20),
                    UIHelpers.dpToPxInt(this@MainActivity, 20),
                    UIHelpers.dpToPxInt(this@MainActivity, 16)
                )
            }

            // Icon + title row
            val titleRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            }

            val icon = ImageView(this).apply {
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(this@MainActivity, 28),
                    UIHelpers.dpToPxInt(this@MainActivity, 28)
                )
                setImageResource(tab.iconRes)
                imageTintList = android.content.res.ColorStateList.valueOf(onPrimary)
            }

            val title = TextView(this).apply {
                text = getString(tab.titleRes)
                setTextColor(onPrimary)
                textSize = 20f
                typeface = android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    marginStart = UIHelpers.dpToPxInt(this@MainActivity, 12)
                }
            }

            titleRow.addView(icon)
            titleRow.addView(title)
            header.addView(titleRow)

            // Subtitle
            val subtitle = TextView(this).apply {
                text = getString(tab.subtitleRes)
                setTextColor(UIHelpers.applyAlpha(onPrimary, 0.85f))
                textSize = 14f
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(this@MainActivity, 4)
                }
            }
            header.addView(subtitle)

            tab.container.addView(header, 0)
        }
    }

    /**
     * Sets up the bottom navigation bar with tab switching logic.
     */
    private fun setupBottomNavigation() {
        // The bar is drawn over the scroll view, whose viewport otherwise runs to
        // the bottom of the screen. Anything scrolled to the very end of a tab then
        // comes to rest underneath the bar: visible enough for Espresso to consider
        // it displayed, but with its centre covered, so taps land on the bar instead.
        // End the viewport at the top of the bar. The height is measured rather than
        // hard-coded because it grows with the gesture-navigation inset.
        binding.bottomNavigation.doOnLayout { nav ->
            binding.nestedScrollView.updateLayoutParams<ViewGroup.MarginLayoutParams> {
                bottomMargin = nav.height
            }
        }

        binding.bottomNavigation.setOnItemSelectedListener { item ->
            setTabVisibility(item.itemId)
            binding.nestedScrollView.scrollTo(0, 0)
            true
        }
        // Default to Dashboard tab
        setTabVisibility(R.id.nav_dashboard)
    }

    /**
     * Controls card visibility based on the selected bottom navigation tab.
     *
     * Tab mapping:
     * - Dashboard: Hero + Device Info + Connected Device (if connected) + Auth Request (if active)
     * - Apps:      containerApps (Authenticator, Passkeys, PIV Smart Card)
     * - Store:     containerStore (Key Management, Certificates, Trust Store, Contacts)
     * - Manage:    containerManagement (PIN, Co-Sign, Paired Devices, Audit Log, Settings)
     */
    private fun setTabVisibility(tabId: Int) {
        val isDashboard = tabId == R.id.nav_dashboard

        // Dashboard-only views
        binding.heroSection.visibility = if (isDashboard) View.VISIBLE else View.GONE
        binding.cardDeviceInformation.visibility = if (isDashboard) View.VISIBLE else View.GONE
        binding.cardConnectedDevice.visibility =
            if (isDashboard && isDeviceConnected) View.VISIBLE else View.GONE
        binding.cardAuthRequest.visibility =
            if (isDashboard && isAuthRequestActive) View.VISIBLE else View.GONE

        // Tab containers
        binding.containerApps.visibility =
            if (tabId == R.id.nav_applications) View.VISIBLE else View.GONE
        binding.containerStore.visibility =
            if (tabId == R.id.nav_store) View.VISIBLE else View.GONE
        binding.containerManagement.visibility =
            if (tabId == R.id.nav_management) View.VISIBLE else View.GONE
    }

    /**
     * Connection status states.
     */
    enum class ConnectionStatus {
        DISCONNECTED,
        ADVERTISING,
        CONNECTING,
        CONNECTED,
        AUTHENTICATING
    }

    /**
     * Data class for status UI configuration.
     */
    private data class StatusUIConfig(
        val statusText: String,
        val descriptionText: String,
        val indicatorColorRes: Int,
        val heroStatusText: String
    )

}
