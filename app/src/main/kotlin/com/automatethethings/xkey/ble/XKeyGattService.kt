package com.automatethethings.xkey.ble

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.fragment.app.FragmentActivity
import com.automatethethings.xkey.XKeyApplication
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.SessionBindingProvider
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.ui.MainActivity
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.automatethethings.xkey.remote.RemoteBackupClient
import com.automatethethings.xkey.backup.BackupStore
import com.automatethethings.xkey.usb.PasswordStoreMethods
import com.automatethethings.xkey.usb.SealStoreMethods
import com.automatethethings.xkey.storage.SealStore
import com.automatethethings.xkey.usb.UsbAccessoryServer
import com.automatethethings.xkey.usb.UsbAccessoryServerSlot
import com.automatethethings.xkey.password.FilePasswordVaultFactorStore
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordVault
import com.automatethethings.xkey.password.PinSettingsVaultUnlockAttemptStore
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.EnrolledDeviceRepository
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.lang.ref.WeakReference

/**
 * Foreground service that manages the BLE GATT server for xKey operations.
 *
 * This service:
 * - Manages the BLE GATT server lifecycle
 * - Controls BLE advertising for device discovery
 * - Handles xKey protocol requests via the RequestHandler
 * - Maintains foreground service status for reliable BLE operation
 *
 * Usage:
 * 1. Start the service using startService() or bindService()
 * 2. Call startAdvertising() to begin accepting connections
 * 3. The service will handle incoming requests automatically
 * 4. Call stopAdvertising() to stop accepting new connections
 */
class XKeyGattService : Service(), PairingConfirmationCallback {
    companion object {
        private const val TAG = "XKeyGattService"
        private const val NOTIFICATION_ID = 1001
        private const val PASSWORD_VAULT_DIR = "password_vault"
        private const val SEAL_STORE_DIR = "seal_store"

        // Intent actions
        const val ACTION_START_ADVERTISING = "com.automatethethings.xkey.action.START_ADVERTISING"
        const val ACTION_STOP_ADVERTISING = "com.automatethethings.xkey.action.STOP_ADVERTISING"
    }

    // Service binder
    private val binder = LocalBinder()

    // Coroutine scope for service operations
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Bluetooth components
    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null

    // BLE components
    private var gattServer: GattServer? = null
    private var advertiser: Advertiser? = null

    // Protocol handler
    private var requestHandler: RequestHandler? = null
    private var keystoreManager: KeystoreManager? = null
    private var bleMessageRouter: BidirectionalMessageRouter? = null

    private var tcpMessageRouter: BidirectionalMessageRouter? = null

    // Auth and settings components
    private var biometricLauncher: BiometricActivityLauncher? = null
    private var sessionAuthManager: SessionAuthManager? = null
    private var settingsRepository: BiometricSettingsRepository? = null
    private var currentSettings: BiometricSettingsData = BiometricSettingsData()

    // USB HSM components
    private val usbServerSlot = UsbAccessoryServerSlot()
    private var usbHsmSettingsRepository: UsbHsmSettingsRepository? = null
    private var tcpHsmServer: TcpHsmServer? = null
    private var pairedDeviceRepository: PairedDeviceRepository? = null

    // WakeLock for keeping BLE radio active during background operation
    private var wakeLock: PowerManager.WakeLock? = null

    // Guard against concurrent startAdvertising() calls
    @Volatile
    private var isStartingAdvertising = false

    // Activity reference for biometric prompts
    private var activityRef: WeakReference<FragmentActivity>? = null

    // Service state
    private val _serviceState = MutableStateFlow<ServiceState>(ServiceState.Stopped)
    val serviceState: StateFlow<ServiceState> = _serviceState.asStateFlow()

    /**
     * Binder for local service binding.
     */
    inner class LocalBinder : Binder() {
        fun getService(): XKeyGattService = this@XKeyGattService
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Service created")

        initializeBluetooth()
        initializeComponents()
    }

    override fun onBind(intent: Intent?): IBinder {
        Log.d(TAG, "Service bound")
        return binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}, flags=$flags")

        startForegroundService()

        // Handle intent actions
        when (intent?.action) {
            ACTION_START_ADVERTISING -> startAdvertising()
            ACTION_STOP_ADVERTISING -> stopAdvertising()
            null -> {
                // Service restarted by system (START_STICKY) after being killed.
                // Auto-resume advertising to ensure BLE connectivity remains available
                // even when the app is not in foreground.
                Log.i(TAG, "Service restarted by system, auto-resuming advertising")
                startAdvertising()
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        Log.d(TAG, "Service destroyed")

        AuditLogger.logServiceStopped("service_destroyed")

        releaseWakeLock()
        stopAdvertising()
        cleanupComponents()
        serviceScope.cancel()

        super.onDestroy()
    }

    /**
     * Acquires a partial wake lock to keep the BLE radio active while the phone
     * is locked or sleeping. This ensures reliable connectivity for background
     * cryptographic operations.
     *
     * The wake lock is non-reference-counted and will be released when the
     * service is destroyed or when explicitly released.
     */
    private fun acquireWakeLock() {
        if (wakeLock != null) return

        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "xKey:BLEService"
        ).apply {
            setReferenceCounted(false)
            acquire()
        }
        Log.d(TAG, "Acquired partial wake lock for BLE service")
    }

    /**
     * Releases the partial wake lock if held.
     */
    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                Log.d(TAG, "Released partial wake lock")
            }
        }
        wakeLock = null
    }

    /**
     * Initializes Bluetooth components.
     */
    private fun initializeBluetooth() {
        Log.i(TAG, "initializeBluetooth() called")
        try {
            bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as? BluetoothManager
            Log.d(TAG, "BluetoothManager obtained: ${bluetoothManager != null}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get BluetoothManager", e)
            _serviceState.value = ServiceState.Error("Failed to get Bluetooth service: ${e.message}")
            return
        }

        try {
            bluetoothAdapter = bluetoothManager?.adapter
            Log.d(TAG, "BluetoothAdapter obtained: ${bluetoothAdapter != null}")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException getting adapter - check Bluetooth permissions", e)
            _serviceState.value = ServiceState.Error("Bluetooth permission denied")
            return
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get BluetoothAdapter", e)
            _serviceState.value = ServiceState.Error("Failed to get Bluetooth adapter: ${e.message}")
            return
        }

        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth not available (adapter is null)")
            _serviceState.value = ServiceState.Error("Bluetooth not available")
            return
        }

        try {
            val enabled = bluetoothAdapter!!.isEnabled
            Log.d(TAG, "Bluetooth enabled: $enabled")
            if (!enabled) {
                Log.e(TAG, "Bluetooth not enabled")
                _serviceState.value = ServiceState.Error("Bluetooth not enabled")
                return
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException checking Bluetooth state - check permissions", e)
            _serviceState.value = ServiceState.Error("Bluetooth permission denied")
            return
        }

        Log.i(TAG, "Bluetooth initialization successful")
    }

    /**
     * Initializes xKey components.
     */
    private fun initializeComponents() {
        // Initialize keystore manager
        keystoreManager = KeystoreManager(this)

        // Initialize auth components
        biometricLauncher = BiometricActivityLauncher(this).also { it.register() }
        sessionAuthManager = SessionAuthManager()
        settingsRepository = BiometricSettingsRepository(this)

        // Initialize paired device repository first (needed by RequestHandler)
        pairedDeviceRepository = PairedDeviceRepository(this)

        // Initialize request handler with auth components
        requestHandler = RequestHandler(
            context = this,
            keystoreManager = keystoreManager!!,
            biometricLauncher = biometricLauncher,
            sessionAuthManager = sessionAuthManager,
            pairedDeviceRepository = pairedDeviceRepository,
            pinManager = PinManager(PinSettingsRepository(this)),
            pivKeyManager = PivKeyManager(XKeyDatabase.getInstance(this).pivSlotDao())
        )

        // Initialize bidirectional message router for remote.* requests
        bleMessageRouter = BidirectionalMessageRouter(requestHandler!!)
        // The enrollment collaborators. Without them GattServer skips
        // post-pairing enrollment outright, so a phone configured as its own
        // Certificate Authority would never issue anything.
        val enrollmentCA = AndroidCA(this).apply {
            certificateDao = XKeyDatabase.getInstance(this@XKeyGattService).certificateDao()
        }
        gattServer = GattServer(
            context = this,
            requestHandler = requestHandler!!,
            messageRouter = bleMessageRouter,
            pairingCallback = this,
            pairedDeviceRepository = pairedDeviceRepository,
            trustedComputingSettingsRepository = TrustedComputingSettingsRepository(this),
            androidCA = enrollmentCA,
            enrolledDeviceRepository = EnrolledDeviceRepository(this),
            trustStoreRepository = TrustStoreRepository(this)
        )

        // Initialize advertiser
        advertiser = Advertiser(bluetoothAdapter)

        // Observe settings changes
        serviceScope.launch {
            settingsRepository?.settingsFlow?.collect { settings ->
                currentSettings = settings
                requestHandler?.updateSettings(settings)
            }
        }

        // Observe connection state changes
        serviceScope.launch {
            gattServer?.connectionState?.collectLatest { state ->
                handleConnectionStateChange(state)
            }
        }

        // Observe advertising state changes
        serviceScope.launch {
            advertiser?.advertisingState?.collectLatest { state ->
                handleAdvertisingStateChange(state)
            }
        }

        // Initialize USB HSM settings
        usbHsmSettingsRepository = UsbHsmSettingsRepository(this)

        // Start/stop the TCP pairing server in response to the setting (loopback :8444,
        // for ADB-forwarded / emulator connections). Collectors receive the current
        // value immediately, so this also applies the persisted setting at startup.
        serviceScope.launch {
            usbHsmSettingsRepository?.settingsFlow?.collect { settings ->
                if (settings.tcpHsmEnabled) startTcpHsmServer() else stopTcpHsmServer()
            }
        }

        _serviceState.value = ServiceState.Ready
        Log.d(TAG, "Components initialized")
    }

    /**
     * Cleans up components on service destruction.
     */
    private fun cleanupComponents() {
        onUsbAccessoryDetached()
        stopTcpHsmServer()
        usbHsmSettingsRepository = null

        gattServer?.destroy()
        gattServer = null
        pairedDeviceRepository = null
        bleMessageRouter = null

        advertiser?.stopAdvertising()
        advertiser = null

        requestHandler = null
        keystoreManager = null

        // Clean up auth components
        biometricLauncher?.unregister()
        biometricLauncher = null
        sessionAuthManager = null

        _serviceState.value = ServiceState.Stopped
    }

    /**
     * Starts BLE advertising and GATT server.
     *
     * This also acquires a partial wake lock to keep the BLE radio active
     * even when the phone screen is off or the device is in Doze mode.
     */
    fun startAdvertising() {
        Log.d(TAG, "Starting advertising")

        if (isStartingAdvertising) {
            Log.w(TAG, "Already starting advertising, ignoring duplicate call")
            return
        }
        isStartingAdvertising = true

        val server = gattServer
        val adv = advertiser

        if (server == null || adv == null) {
            Log.e(TAG, "Components not initialized")
            _serviceState.value = ServiceState.Error("Components not initialized")
            isStartingAdvertising = false
            return
        }

        // Validate Bluetooth state before proceeding
        if (bluetoothAdapter?.isEnabled != true) {
            Log.e(TAG, "Bluetooth not enabled, cannot start advertising")
            _serviceState.value = ServiceState.Error("Bluetooth not enabled")
            isStartingAdvertising = false
            return
        }

        // Acquire wake lock to keep BLE active while advertising
        acquireWakeLock()

        // Start GATT server on background thread (start() blocks waiting for service to be added)
        serviceScope.launch(Dispatchers.IO) {
            try {
                // Start GATT server
                if (!server.isRunning()) {
                    var started = server.start()
                    if (!started) {
                        // Retry once after a short delay for transient Bluetooth failures
                        Log.w(TAG, "GATT server start failed, retrying after 500ms...")
                        kotlinx.coroutines.delay(500)
                        started = server.start()
                    }
                    if (!started) {
                        Log.e(TAG, "Failed to start GATT server")
                        _serviceState.value = ServiceState.Error("Failed to start GATT server")
                        releaseWakeLock()
                        return@launch
                    }
                }

                // Start advertising (must be on main thread for BLE APIs)
                launch(Dispatchers.Main) {
                    val advStarted = adv.startAdvertising()
                    if (!advStarted) {
                        Log.e(TAG, "Failed to start advertising")
                        // Don't return - GATT server is still running
                    }

                    _serviceState.value = ServiceState.Advertising
                    updateNotification()
                }
            } finally {
                isStartingAdvertising = false
            }
        }
    }

    /**
     * Stops BLE advertising and releases the wake lock.
     */
    fun stopAdvertising() {
        Log.d(TAG, "Stopping advertising")

        advertiser?.stopAdvertising()
        gattServer?.stop()
        releaseWakeLock()

        _serviceState.value = ServiceState.Ready
        updateNotification()
    }

    /**
     * Sets the activity for biometric prompts.
     *
     * Call this when the activity becomes available (e.g., in onResume).
     *
     * @param activity The activity to use for biometric prompts
     */
    fun setActivity(activity: FragmentActivity?) {
        activityRef = if (activity != null) WeakReference(activity) else null
        requestHandler?.setActivity(activity)
    }

    /**
     * Handles connection state changes.
     */
    private fun handleConnectionStateChange(state: ConnectionState) {
        Log.d(TAG, "Connection state changed: $state")

        when (state) {
            is ConnectionState.Connected -> {
                _serviceState.value = ServiceState.Connected(state.deviceName, state.deviceAddress)
                updateNotification()
                AuditLogger.logConnectionEstablished(
                    deviceId = state.deviceAddress,
                    deviceName = state.deviceName,
                    connectionType = "BLE"
                )
            }
            is ConnectionState.Connecting -> {
                _serviceState.value = ServiceState.Connecting
                updateNotification()
            }
            is ConnectionState.Disconnected -> {
                // Log disconnection before clearing session
                val previousState = _serviceState.value
                if (previousState is ServiceState.Connected) {
                    AuditLogger.logConnectionClosed(
                        deviceId = previousState.deviceAddress,
                        deviceName = previousState.deviceName,
                        reason = "disconnected"
                    )
                }

                // Clear session on disconnect
                sessionAuthManager?.clearSession()

                if (advertiser?.isAdvertising() == true) {
                    _serviceState.value = ServiceState.Advertising
                } else {
                    _serviceState.value = ServiceState.Ready
                }
                updateNotification()
            }
        }
    }

    /**
     * Handles advertising state changes.
     */
    private fun handleAdvertisingStateChange(state: AdvertisingState) {
        Log.d(TAG, "Advertising state changed: $state")

        when (state) {
            is AdvertisingState.Advertising -> {
                if (_serviceState.value !is ServiceState.Connected &&
                    _serviceState.value !is ServiceState.Connecting) {
                    _serviceState.value = ServiceState.Advertising
                }
            }
            is AdvertisingState.Stopped -> {
                if (_serviceState.value is ServiceState.Advertising) {
                    _serviceState.value = ServiceState.Ready
                }
            }
            is AdvertisingState.Error -> {
                Log.e(TAG, "Advertising error: ${state.error} - ${state.message}")
            }
        }
    }

    /**
     * Starts the foreground service with notification.
     */
    private fun startForegroundService() {
        val notification = createNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        AuditLogger.logServiceStarted()
    }

    /**
     * Updates the notification with current state.
     */
    private fun updateNotification() {
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
        notificationManager.notify(NOTIFICATION_ID, createNotification())
    }

    /**
     * Creates the foreground service notification.
     */
    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val (title, text) = when (val state = _serviceState.value) {
            is ServiceState.Stopped -> "xKey" to "Service stopped"
            is ServiceState.Ready -> "xKey" to "Ready"
            is ServiceState.Advertising -> "xKey" to "Waiting for connection..."
            is ServiceState.Connecting -> "xKey" to "Connecting..."
            is ServiceState.Connected -> "xKey" to "Connected to ${state.deviceName}"
            is ServiceState.Error -> "xKey" to "Error: ${state.message}"
        }

        return NotificationCompat.Builder(this, XKeyApplication.NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    /**
     * Returns whether the service is currently advertising.
     */
    fun isAdvertising(): Boolean = advertiser?.isAdvertising() == true

    /**
     * Returns whether a device is connected.
     */
    fun isConnected(): Boolean = gattServer?.isSessionEstablished() == true

    /**
     * Returns the connection state flow for observing state changes.
     */
    fun getConnectionState(): StateFlow<ConnectionState>? = gattServer?.connectionState

    /**
     * Returns the current session ID based on the connected device address.
     *
     * @return The connected device address as session ID, or null if not connected
     */
    fun getCurrentSessionId(): String? {
        return gattServer?.getConnectedDevice()?.address
    }

    /**
     * Returns the paired device repository for use by Settings UI.
     */
    fun getPairedDeviceRepository(): PairedDeviceRepository? = pairedDeviceRepository

    /**
     * Returns the public key hex of the currently connected device, if any.
     */
    fun getConnectedDevicePublicKeyHex(): String? = requestHandler?.getConnectedDevicePublicKeyHex()

    /**
     * Answers the requests a desktop sends over a session this phone opens with
     * [BleClient], through the same [RequestHandler] that serves every other
     * transport. Null until the handler exists, which [BleClient] treats as
     * "refuse".
     */
    fun phoneInitiatedRequestHandler(): PhoneInitiatedRequestHandler? {
        val handler = requestHandler ?: return null
        return object : PhoneInitiatedRequestHandler {
            override suspend fun handle(
                request: ByteArray,
                binding: SessionBindingProvider,
                peerPublicKeyHex: String?
            ): ByteArray = handler.handleRawRequest(request, binding, peerPublicKeyHex)
        }
    }

    /**
     * Called when a USB accessory is attached and native USB mode is enabled.
     *
     * Creates and starts a [UsbAccessoryServer] with the same [RequestHandler]
     * used by BLE and TCP transports.
     *
     * @param accessory The attached USB accessory.
     */
    fun onUsbAccessoryAttached(accessory: android.hardware.usb.UsbAccessory) {
        if (usbServerSlot.isActive) {
            Log.w(TAG, "USB accessory server already active, ignoring attach")
            return
        }
        val handler = requestHandler ?: run {
            Log.e(TAG, "RequestHandler not initialized, cannot handle USB accessory")
            return
        }

        // Check if native USB is enabled before accepting the accessory
        serviceScope.launch {
            val settings = usbHsmSettingsRepository?.getSettings()
            if (settings?.nativeUsbEnabled != true) {
                Log.i(TAG, "Native USB mode is disabled, ignoring USB accessory")
                return@launch
            }

            val usbRouter = BidirectionalMessageRouter(handler)
            // The password and seal stores are served over USB only, so their
            // methods go to this session rather than the RequestHandler BLE and
            // TCP share. A vault per session: every new USB connection starts
            // locked, while its failed-unlock counter persists with the PINs'.
            val passwordVault = PasswordVault(
                FilePasswordVaultFactorStore(java.io.File(filesDir, PASSWORD_VAULT_DIR)),
                PinSettingsVaultUnlockAttemptStore(PinSettingsRepository(this@XKeyGattService))
            )
            val storeMethods = listOf(
                PasswordStoreMethods(
                    PasswordRepository(XKeyDatabase.getInstance(this@XKeyGattService).passwordDao()),
                    passwordVault
                ),
                SealStoreMethods(SealStore(java.io.File(filesDir, SEAL_STORE_DIR)))
            )
            // The slot drops a server that closes, so the next attach builds
            // a fresh one without a service restart (#134).
            usbServerSlot.open(
                context = this@XKeyGattService,
                accessory = accessory,
                requestHandler = handler,
                router = usbRouter,
                pairingCallback = this@XKeyGattService,
                pairedDeviceRepository = pairedDeviceRepository,
                storeMethods = storeMethods,
            ) ?: run {
                Log.w(TAG, "USB accessory server already active, ignoring attach")
                return@launch
            }
            Log.i(TAG, "USB accessory server started")
            AuditLogger.logConnectionEstablished(
                deviceId = accessory.toString(),
                deviceName = "${accessory.manufacturer} ${accessory.model}",
                connectionType = "USB"
            )
        }
    }

    /**
     * Called when the USB accessory is detached.
     */
    fun onUsbAccessoryDetached() {
        usbServerSlot.clear()
        Log.i(TAG, "USB accessory server stopped")
    }

    /**
     * Starts the TCP pairing server (loopback :8444) for ADB-forwarded and
     * emulator connections. Idempotent. Shares the [RequestHandler] and pairing
     * protocol with the BLE and USB transports.
     */
    private fun startTcpHsmServer() {
        if (tcpHsmServer != null) return
        val handler = requestHandler ?: run {
            Log.e(TAG, "RequestHandler not initialized, cannot start TCP server")
            return
        }
        val tcpRouter = BidirectionalMessageRouter(handler)
        tcpMessageRouter = tcpRouter
        tcpHsmServer = TcpHsmServer(
            handler, tcpRouter, this, pairedDeviceRepository
        ).also { it.start(this) }
        Log.i(TAG, "TCP HSM server started on loopback:${TcpHsmServer.DEFAULT_PORT}")
    }

    /**
     * Stops the TCP pairing server if running.
     */
    private fun stopTcpHsmServer() {
        tcpHsmServer?.stop()
        tcpHsmServer = null
        tcpMessageRouter = null
    }

    /**
     * Returns the active connection's message sender and router across whichever
     * transport currently has an established session (BLE / TCP / USB), or null
     * if no desktop is connected. Single source for outbound `remote.*` clients.
     */
    private fun activeTransport(): Pair<com.automatethethings.xkey.remote.MessageSender, BidirectionalMessageRouter>? {
        gattServer?.let { server ->
            if (server.isSessionEstablished()) {
                bleMessageRouter?.let { return server to it }
            }
        }
        tcpHsmServer?.let { server ->
            if (server.state.value is com.automatethethings.xkey.tcp.TcpHsmState.Connected) {
                tcpMessageRouter?.let { return server to it }
            }
        }
        usbServerSlot.current()?.let { return it }
        return null
    }

    /**
     * Runs a phone-initiated bidirectional sync (trust store, OATH, passwords)
     * with the connected desktop over the active transport.
     *
     * @throws IllegalStateException if no desktop is currently connected.
     */
    suspend fun syncNow(): com.automatethethings.xkey.remote.RemoteSyncClient.SyncResult {
        val (sender, router) = activeTransport()
            ?: throw IllegalStateException("No desktop connected; pair and connect before syncing")
        val client = com.automatethethings.xkey.remote.RemoteSyncClient(applicationContext, sender, router)
        Log.i(TAG, "Starting phone-initiated sync")
        return client.syncAll()
    }

    /**
     * Asks the connected desktop for an encrypted backup of the stores in
     * [include] under [password] (`remote.createBackup`) over the active
     * transport, and keeps the returned envelope in [BackupStore] under the
     * desktop's backup id.
     *
     * [password] is zeroed before this returns, whatever the outcome.
     *
     * @throws IllegalStateException if no desktop is currently connected.
     * @throws com.automatethethings.xkey.remote.RemoteBackupException if the
     *   desktop refuses or fails the backup.
     * @throws java.io.IOException if the send fails or the envelope cannot be
     *   stored.
     */
    suspend fun createDesktopBackup(
        password: CharArray,
        include: RemoteBackupClient.Include
    ): RemoteBackupClient.CreateResult {
        try {
            val (sender, router) = activeTransport()
                ?: throw IllegalStateException("No desktop connected; pair and connect before a backup")
            Log.i(TAG, "Starting phone-initiated backup")
            val result = RemoteBackupClient(sender, router)
                .createBackup(password, include, "phone-${System.currentTimeMillis()}")
            withContext(Dispatchers.IO) {
                BackupStore(applicationContext).store(result.backupId, result.backupData)
            }
            return result
        } finally {
            password.fill('\u0000')
        }
    }

    /**
     * Id of the most recently stored backup envelope, or null if none.
     *
     * @throws java.io.IOException if the stored backups cannot be read, or a
     *   legacy record cannot be migrated (for example, the disk is full).
     */
    suspend fun latestStoredBackupId(): String? =
        withContext(Dispatchers.IO) { BackupStore(applicationContext).latestId() }

    /**
     * Asks the connected desktop to restore the stored backup [backupId] under
     * [password] (`remote.restoreBackup`) over the active transport.
     *
     * [password] is zeroed before this returns, whatever the outcome.
     *
     * @throws IllegalStateException if no desktop is connected or no backup
     *   is stored under [backupId].
     * @throws com.automatethethings.xkey.remote.RemoteBackupException if the
     *   desktop refuses or fails the restore.
     * @throws java.io.IOException if the stored backup cannot be read or the
     *   send fails.
     */
    suspend fun restoreDesktopBackup(backupId: String, password: CharArray): RemoteBackupClient.RestoreResult {
        try {
            val (sender, router) = activeTransport()
                ?: throw IllegalStateException("No desktop connected; pair and connect before a restore")
            val envelope = withContext(Dispatchers.IO) { BackupStore(applicationContext).load(backupId) }
                ?: throw IllegalStateException("No stored backup $backupId")
            Log.i(TAG, "Starting phone-initiated restore")
            return RemoteBackupClient(sender, router).restoreBackup(envelope, password)
        } finally {
            password.fill('\u0000')
        }
    }

    /**
     * Requests device attestation from the connected laptop/desktop.
     *
     * This performs a remote.attestDevice request to get the laptop's security
     * posture and stores the result in PairedDeviceRepository.
     *
     * @param publicKeyHex The public key hex of the device to attest.
     * @return True if attestation succeeded, false otherwise.
     * @throws IllegalStateException if not connected to the specified device.
     */
    suspend fun requestDeviceAttestation(publicKeyHex: String): Boolean {
        val connectedKey = requestHandler?.getConnectedDevicePublicKeyHex()
        if (connectedKey != publicKeyHex) {
            Log.w(TAG, "Cannot attest device $publicKeyHex - not connected (connected: $connectedKey)")
            return false
        }

        // Determine which transport is active and has a message router.
        val (messageSender, messageRouter) = activeTransport() ?: run {
            Log.e(TAG, "No active transport for device attestation")
            return false
        }

        val remoteClient = RemoteKeyClient(messageSender, messageRouter)

        return try {
            // Generate random nonce
            val nonce = ByteArray(32)
            java.security.SecureRandom().nextBytes(nonce)
            val nonceB64 = java.util.Base64.getEncoder().encodeToString(nonce)

            Log.d(TAG, "Requesting device attestation for $publicKeyHex")
            val result = remoteClient.attestDevice(nonceB64)

            // Store the PEER's boot state. deviceFingerprint is intentionally
            // omitted: it is the phone's own attested-key SPKI bound at pairing
            // and echoed on reconnect (#93), not the peer's boot hash. Passing
            // the boot hash here previously corrupted the reconnect binding.
            pairedDeviceRepository?.updateDeviceAttestation(
                publicKeyHex = publicKeyHex,
                bootHashHex = result.bootHashHex ?: "",
                securityLevel = result.securityLevel,
                bootStateVerified = result.bootStateVerified
            )

            Log.i(TAG, "Device attestation succeeded: format=${result.format}, " +
                    "securityLevel=${result.securityLevel}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Device attestation failed", e)
            false
        }
    }

    /**
     * Shows a Material dialog for pairing confirmation.
     *
     * If no activity is bound, rejects by default (security: no unattended pairing).
     */
    override suspend fun onPairingConfirmationRequired(
        deviceName: String,
        publicKeyFingerprint: String
    ): Boolean = showPairingDialog(
        getString(R.string.pairing_dialog_message, deviceName, publicKeyFingerprint)
    )

    /**
     * Shows the pairing dialog with the SAS, so the user can check it against
     * the code `xkey device pair` printed on the desktop before allowing.
     */
    override suspend fun onPairingConfirmationRequired(
        deviceName: String,
        publicKeyFingerprint: String,
        shortAuthString: String
    ): Boolean = showPairingDialog(
        getString(R.string.pairing_dialog_message_sas, deviceName, publicKeyFingerprint, shortAuthString)
    )

    private suspend fun showPairingDialog(message: String): Boolean {
        val activity = activityRef?.get() ?: run {
            Log.w(TAG, "No activity available for pairing dialog, rejecting")
            return false
        }

        return withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { continuation ->
                MaterialAlertDialogBuilder(activity)
                    .setTitle(getString(R.string.pairing_dialog_title))
                    .setMessage(message)
                    .setPositiveButton(getString(R.string.pairing_dialog_allow)) { _, _ ->
                        if (continuation.isActive) continuation.resume(true)
                    }
                    .setNegativeButton(getString(R.string.pairing_dialog_deny)) { _, _ ->
                        if (continuation.isActive) continuation.resume(false)
                    }
                    .setOnCancelListener {
                        if (continuation.isActive) continuation.resume(false)
                    }
                    .setCancelable(false)
                    .show()
            }
        }
    }
}

/**
 * Represents the state of the xKey service.
 */
sealed class ServiceState {
    /** Service is stopped */
    data object Stopped : ServiceState()

    /** Service is ready but not advertising */
    data object Ready : ServiceState()

    /** Service is advertising and waiting for connections */
    data object Advertising : ServiceState()

    /** A device is connecting (handshake in progress) */
    data object Connecting : ServiceState()

    /** A device is connected */
    data class Connected(
        val deviceName: String,
        val deviceAddress: String
    ) : ServiceState()

    /** An error occurred */
    data class Error(val message: String) : ServiceState()
}
