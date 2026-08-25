package com.automatethethings.xkey.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.MessageSender
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.PairingConfirmParams
import com.automatethethings.xkey.protocol.PairingConfirmResult
import com.automatethethings.xkey.protocol.Response as ProtocolResponse
import com.automatethethings.xkey.protocol.SessionBinding
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.CertificateAuthoritySource
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.CertificateProfile
import com.automatethethings.xkey.ca.EnrolledDevice
import com.automatethethings.xkey.ca.EnrolledDeviceRepository
import com.automatethethings.xkey.ca.EnrollmentRefusal
import com.automatethethings.xkey.ca.EnrollmentRefusalRecord
import com.automatethethings.xkey.crypto.TcgCsrException
import com.automatethethings.xkey.crypto.TcgCsrIDevID
import com.automatethethings.xkey.crypto.TpmAlg
import com.automatethethings.xkey.crypto.TpmMakeCredential
import com.automatethethings.xkey.crypto.TpmQuoteException
import com.automatethethings.xkey.crypto.TpmCertifyVerifier
import com.automatethethings.xkey.crypto.TpmQuoteVerifier
import com.automatethethings.xkey.protocol.RemoteActivateCredentialParams
import com.automatethethings.xkey.protocol.RemoteActivateCredentialResult
import com.automatethethings.xkey.protocol.RemoteGetAttestationQuoteParams
import com.automatethethings.xkey.protocol.RemoteGetAttestationQuoteResult
import com.automatethethings.xkey.protocol.RemoteGetTCGCSRIDevIDParams
import com.automatethethings.xkey.protocol.RemoteGetTCGCSRIDevIDResult
import com.automatethethings.xkey.protocol.RemoteStoreEnrollmentCertsParams
import com.automatethethings.xkey.protocol.RemoteStoreEnrollmentCertsResult
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.truststore.VerificationResult
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import java.security.interfaces.RSAPublicKey
import com.automatethethings.xkey.protocol.Request as ProtocolRequest
import com.automatethethings.xkey.util.getStringOrNull
import org.json.JSONObject
import java.util.Base64
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * BLE GATT server for xKey protocol.
 *
 * Handles connections from xKey desktop clients, manages the Noise protocol
 * encrypted session, and dispatches protocol requests to the handler.
 *
 * Thread safety: All state mutations are protected by mutex locks.
 * The GATT callbacks run on the Binder thread pool.
 */
class GattServer(
    private val context: Context,
    private val requestHandler: RequestHandler,
    private val messageRouter: BidirectionalMessageRouter? = null,
    private val pairingCallback: PairingConfirmationCallback? = null,
    private val pairedDeviceRepository: com.automatethethings.xkey.settings.PairedDeviceRepository? = null,
    private val trustedComputingSettingsRepository: TrustedComputingSettingsRepository? = null,
    private val androidCA: AndroidCA? = null,
    private val enrolledDeviceRepository: EnrolledDeviceRepository? = null,
    private val trustStoreRepository: TrustStoreRepository? = null
) : MessageSender {
    // Extension function for hex encoding
    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG = "XKeyGattServer"

        // xKey BLE Service UUID
        val XKEY_SERVICE_UUID: UUID = UUID.fromString("f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0")

        // Characteristic UUIDs
        val CONTROL_POINT_UUID: UUID = UUID.fromString("f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00001")
        val RESPONSE_UUID: UUID = UUID.fromString("f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00002")
        val STATUS_UUID: UUID = UUID.fromString("f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00003")

        // Client Characteristic Configuration Descriptor
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        // Default MTU (minimum guaranteed)
        private const val DEFAULT_MTU = 23

        // Maximum MTU we support
        private const val MAX_MTU = 517

        // Pre-handshake identity exchange constants
        private const val IDENTITY_MSG_VERSION: Byte = 0x01
        private const val IDENTITY_MSG_SIZE = 33  // 1-byte version + 32-byte public key
        private const val IDENTITY_ACK_KNOWN: Byte = 0x01
        private const val IDENTITY_ACK_UNKNOWN: Byte = 0x00
        private const val FINGERPRINT_SIZE = 32

        // Outbound enrollment request IDs live in their own range so they never
        // collide with the laptop's IDs or with RemoteKeyClient (1_000_000) and
        // RemoteSyncClient (2_000_000), which share the same message router.
        private const val ENROLLMENT_BASE_REQUEST_ID = 3_000_000L

        // TPM quote generation and CSR signing on the laptop can be slow.
        private const val ENROLLMENT_REQUEST_TIMEOUT_MS = 30_000L

        // A quote nonce has to be unguessable, not merely unique; 32 bytes
        // matches the digest size the desktop's attestation key works in.
        private const val ENROLLMENT_NONCE_SIZE = 32

        // PCRs 0-7 are the SRTM measurements: firmware, option ROMs, boot
        // configuration and the boot manager. They are what a baseline is for.
        private val ENROLLMENT_PCR_INDICES = listOf(0, 1, 2, 3, 4, 5, 6, 7)

        // Recorded only after credential activation and a verified quote have
        // both passed, which is what separates it from a bare CA signature.
        private const val TRUST_LEVEL_FULL_ATTESTATION = "full-attestation"

        // How long a send waits for the peer to write the CCCD before giving up.
        private const val NOTIFICATION_READY_TIMEOUT_MS = 5_000L
    }

    /** Allocates IDs for outbound enrollment requests. */
    private val enrollmentRequestId = AtomicLong(ENROLLMENT_BASE_REQUEST_ID)

    // Coroutine scope for async operations
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // State management
    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    // Bluetooth components
    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var gattServer: BluetoothGattServer? = null

    // Service and characteristics
    private var flexKeyService: BluetoothGattService? = null
    private var controlPointCharacteristic: BluetoothGattCharacteristic? = null
    private var responseCharacteristic: BluetoothGattCharacteristic? = null
    private var statusCharacteristic: BluetoothGattCharacteristic? = null

    // Connected device state
    private var connectedDevice: BluetoothDevice? = null
    private var noiseSession: NoiseSession? = null

    // MTU negotiated per device
    private val deviceMtu = ConcurrentHashMap<String, Int>()

    // Fragment reassembly per device
    private val fragmentBuffer = ConcurrentHashMap<String, FragmentReassembler>()

    // Notification subscription state per device
    private val notificationEnabled = ConcurrentHashMap<String, Boolean>()

    // CompletableDeferred to synchronize notification readiness
    private val notificationReady = ConcurrentHashMap<String, CompletableDeferred<Unit>>()

    // Tracks whether the current connection has completed pairing confirmation.
    @Volatile
    private var pairingConfirmed = false

    /**
     * The peer's static public key as authenticated by the Noise XX transcript.
     * This — not anything the peer asserts in a request body — is the identity
     * the session trusts.
     */
    @Volatile
    private var authenticatedPeerKeyHex: String? = null

    // Tracks whether the pre-handshake identity exchange has completed.
    // The identity exchange allows us to identify the connecting device before
    // the Noise handshake and set the prologue for trusted device binding.
    @Volatile
    private var identityExchangeComplete = false

    // The remote device's public key received during identity exchange.
    // Used to look up the device in PairedDeviceRepository and compute prologue.
    @Volatile
    private var remotePublicKeyHex: String? = null

    // Mutex for state management
    private val stateMutex = Mutex()

    /**
     * Serializes encrypt-then-send so concurrent senders cannot interleave.
     * A Noise cipherstate numbers each message with a monotonic nonce, so two
     * coroutines encrypting at once can put those messages on the wire out of
     * order and the peer will fail to decrypt. Mirrors
     * `StreamPairingSession.sendMutex`.
     */
    private val sendMutex = Mutex()

    // Server running state
    @Volatile
    private var isRunning = false

    // Guard against concurrent start() calls
    @Volatile
    private var isStarting = false

    // Latch to wait for service to be added
    @Volatile
    private var serviceAddedLatch: CountDownLatch? = null

    /**
     * Starts the GATT server and begins accepting connections.
     *
     * @return true when the server is running, false on any failure.
     */
    @SuppressLint("MissingPermission")
    @Synchronized
    fun start(): Boolean {
        Log.i(TAG, "start() called")
        if (isRunning) {
            Log.w(TAG, "GATT server already running")
            return true
        }
        if (isStarting) {
            Log.w(TAG, "GATT server already starting, ignoring concurrent start()")
            return false
        }
        isStarting = true

        try {
            bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            Log.d(TAG, "BluetoothManager: ${bluetoothManager != null}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get BluetoothManager", e)
            isStarting = false
            return false
        }

        try {
            bluetoothAdapter = bluetoothManager?.adapter
            Log.d(TAG, "BluetoothAdapter: ${bluetoothAdapter != null}, enabled: ${bluetoothAdapter?.isEnabled}")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException getting Bluetooth adapter - check permissions", e)
            isStarting = false
            return false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get BluetoothAdapter", e)
            isStarting = false
            return false
        }

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.e(TAG, "Bluetooth is not available or not enabled (adapter=${bluetoothAdapter}, enabled=${bluetoothAdapter?.isEnabled})")
            isStarting = false
            return false
        }

        try {
            Log.d(TAG, "Opening GATT server...")
            gattServer = bluetoothManager?.openGattServer(context, gattCallback)
            Log.d(TAG, "openGattServer result: ${gattServer != null}")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException opening GATT server - check BLUETOOTH_CONNECT permission", e)
            isStarting = false
            return false
        } catch (e: Exception) {
            Log.e(TAG, "Exception opening GATT server", e)
            isStarting = false
            return false
        }

        if (gattServer == null) {
            Log.e(TAG, "Failed to open GATT server (returned null)")
            isStarting = false
            return false
        }

        if (!setupService()) {
            Log.e(TAG, "Failed to setup GATT service")
            isStarting = false
            stop()
            return false
        }

        // Wait for service to be added (addService is asynchronous)
        val latch = serviceAddedLatch
        if (latch != null) {
            Log.d(TAG, "Waiting for service to be added...")
            val added = latch.await(5, TimeUnit.SECONDS)
            if (!added) {
                Log.e(TAG, "Timeout waiting for service to be added")
                isStarting = false
                stop()
                return false
            }
            Log.d(TAG, "Service added successfully")
            // Small delay to ensure service is fully registered in BLE stack
            Thread.sleep(100)
        }

        isRunning = true
        isStarting = false

        // Log all registered services for debugging
        gattServer?.services?.forEach { svc ->
            Log.i(TAG, "Registered GATT service: ${svc.uuid}")
        }

        Log.i(TAG, "GATT server started successfully with ${gattServer?.services?.size ?: 0} services")
        return true
    }

    /**
     * Stops the GATT server and disconnects all clients.
     */
    @SuppressLint("MissingPermission")
    fun stop() {
        isRunning = false

        // Synchronous cleanup to prevent race conditions with subsequent start() calls.
        // clearServices() and close() are fast operations that don't need to be in a coroutine.
        connectedDevice?.let { device ->
            try { gattServer?.cancelConnection(device) } catch (_: Exception) {}
        }
        connectedDevice = null
        noiseSession = null
        pairingConfirmed = false
        identityExchangeComplete = false
        remotePublicKeyHex = null
        authenticatedPeerKeyHex = null
        messageRouter?.cancelAllPending()

        gattServer?.clearServices()
        gattServer?.close()
        gattServer = null

        fragmentBuffer.clear()
        deviceMtu.clear()
        notificationEnabled.clear()
        notificationReady.values.forEach { it.cancel() }
        notificationReady.clear()
        serviceAddedLatch = null

        scope.launch { _connectionState.value = ConnectionState.Disconnected }

        Log.i(TAG, "GATT server stopped")
    }

    /**
     * Releases all resources.
     */
    fun destroy() {
        stop()
        scope.cancel()
    }

    /**
     * Creates and adds the xKey GATT service.
     */
    @SuppressLint("MissingPermission")
    private fun setupService(): Boolean {
        // Create latch to wait for service to be added
        serviceAddedLatch = CountDownLatch(1)

        Log.i(TAG, "Setting up GATT service with UUID: $XKEY_SERVICE_UUID")
        Log.i(TAG, "UUID string representation: ${XKEY_SERVICE_UUID.toString()}")

        // Create the service
        flexKeyService = BluetoothGattService(
            XKEY_SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )
        Log.i(TAG, "BluetoothGattService created with UUID: ${flexKeyService?.uuid}")

        // Control Point characteristic - client writes requests here
        // Note: We use PERMISSION_WRITE (not PERMISSION_WRITE_ENCRYPTED) because
        // encryption is handled at the application layer via the Noise XX protocol.
        // BLE link encryption requires OS-level bonding which is fragile across
        // app reinstalls and Android RPA rotation.
        controlPointCharacteristic = BluetoothGattCharacteristic(
            CONTROL_POINT_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        // Response characteristic - server notifies responses here
        responseCharacteristic = BluetoothGattCharacteristic(
            RESPONSE_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or
                    BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        ).apply {
            // Add CCCD for notifications
            addDescriptor(BluetoothGattDescriptor(
                CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or
                        BluetoothGattDescriptor.PERMISSION_WRITE
            ))
        }

        // Status characteristic - connection and session status
        statusCharacteristic = BluetoothGattCharacteristic(
            STATUS_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or
                    BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        ).apply {
            addDescriptor(BluetoothGattDescriptor(
                CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or
                        BluetoothGattDescriptor.PERMISSION_WRITE
            ))
        }

        // Add characteristics to service
        flexKeyService?.addCharacteristic(controlPointCharacteristic)
        flexKeyService?.addCharacteristic(responseCharacteristic)
        flexKeyService?.addCharacteristic(statusCharacteristic)

        // Add service to server
        Log.i(TAG, "Adding service to GATT server...")
        return try {
            val addResult = gattServer?.addService(flexKeyService)
            Log.i(TAG, "addService returned: $addResult")
            addResult == true
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException adding service - check BLUETOOTH_CONNECT permission", e)
            false
        } catch (e: Exception) {
            Log.e(TAG, "Exception adding service", e)
            false
        }
    }

    /**
     * GATT server callback implementation.
     */
    private val gattCallback = object : BluetoothGattServerCallback() {

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            val deviceAddress = device.address
            Log.i(TAG, "Connection state changed: device=$deviceAddress, status=$status, newState=$newState")

            scope.launch {
                Log.i(TAG, "Processing connection state change for ${device.address}")
                stateMutex.withLock {
                    Log.i(TAG, "Acquired mutex for connection handling, newState=$newState")
                    when (newState) {
                        BluetoothProfile.STATE_CONNECTED -> {
                            handleDeviceConnected(device)
                        }
                        BluetoothProfile.STATE_DISCONNECTED -> {
                            handleDeviceDisconnected(device)
                        }
                    }
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            Log.d(TAG, "MTU changed: device=${device.address}, mtu=$mtu")
            deviceMtu[device.address] = mtu.coerceIn(DEFAULT_MTU, MAX_MTU)
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            Log.d(TAG, "Read request: device=${device.address}, characteristic=${characteristic.uuid}")

            when (characteristic.uuid) {
                STATUS_UUID -> {
                    val statusValue = getStatusValue()
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        statusValue.copyOfRange(offset.coerceAtMost(statusValue.size), statusValue.size)
                    )
                }
                RESPONSE_UUID -> {
                    // Response characteristic is primarily for notifications
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        ByteArray(0)
                    )
                }
                else -> {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_READ_NOT_PERMITTED,
                        0,
                        null
                    )
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            Log.d(TAG, "Write request: device=${device.address}, characteristic=${characteristic.uuid}, " +
                    "length=${value?.size}, responseNeeded=$responseNeeded")

            if (characteristic.uuid != CONTROL_POINT_UUID) {
                if (responseNeeded) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_WRITE_NOT_PERMITTED,
                        0,
                        null
                    )
                }
                return
            }

            if (value == null || value.isEmpty()) {
                if (responseNeeded) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH,
                        0,
                        null
                    )
                }
                return
            }

            // Send response first to avoid blocking
            if (responseNeeded) {
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    0,
                    null
                )
            }

            // Process the data asynchronously
            scope.launch {
                processIncomingData(device, value)
            }
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor
        ) {
            Log.d(TAG, "Descriptor read request: device=${device.address}, descriptor=${descriptor.uuid}")

            if (descriptor.uuid == CCCD_UUID) {
                val isEnabled = notificationEnabled[device.address] == true
                val value = if (isEnabled) {
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                } else {
                    BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                }
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    value
                )
            } else {
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_READ_NOT_PERMITTED,
                    0,
                    null
                )
            }
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            Log.d(TAG, "Descriptor write request: device=${device.address}, descriptor=${descriptor.uuid}")

            if (descriptor.uuid == CCCD_UUID && value != null) {
                val enable = value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ||
                        value.contentEquals(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
                notificationEnabled[device.address] = enable
                if (enable) {
                    notificationReady[device.address]?.complete(Unit)
                }
                Log.d(TAG, "Notifications ${if (enable) "enabled" else "disabled"} for ${device.address}")

                if (responseNeeded) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        0,
                        null
                    )
                }
            } else if (responseNeeded) {
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_WRITE_NOT_PERMITTED,
                    0,
                    null
                )
            }
        }

        @SuppressLint("MissingPermission")
        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            Log.d(TAG, "Notification sent: device=${device.address}, status=$status")
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            val isSuccess = status == BluetoothGatt.GATT_SUCCESS
            Log.i(TAG, "onServiceAdded callback: uuid=${service.uuid}, status=$status, success=$isSuccess")
            Log.i(TAG, "Expected UUID: $XKEY_SERVICE_UUID")
            Log.i(TAG, "UUID match: ${service.uuid == XKEY_SERVICE_UUID}")
            Log.i(TAG, "Service type: ${service.type} (PRIMARY=${BluetoothGattService.SERVICE_TYPE_PRIMARY})")
            Log.i(TAG, "Service characteristics count: ${service.characteristics.size}")
            service.characteristics.forEach { char ->
                Log.i(TAG, "  Characteristic: ${char.uuid}")
            }
            if (service.uuid == XKEY_SERVICE_UUID) {
                Log.i(TAG, "xKey service added successfully, counting down latch")
                serviceAddedLatch?.countDown()
            } else {
                Log.w(TAG, "Service UUID mismatch! Expected $XKEY_SERVICE_UUID but got ${service.uuid}")
            }
        }
    }

    /**
     * Handles a new device connection.
     */
    @SuppressLint("MissingPermission")
    private suspend fun handleDeviceConnected(device: BluetoothDevice) {
        Log.i(TAG, "Device connecting: ${device.address}, GATT services: ${gattServer?.services?.size ?: 0}")
        gattServer?.services?.forEach { svc ->
            Log.i(TAG, "Available service for client: ${svc.uuid}")
        }

        // Only allow one connection at a time
        if (connectedDevice != null && connectedDevice?.address != device.address) {
            Log.w(TAG, "Rejecting connection from ${device.address}, already connected to ${connectedDevice?.address}")
            gattServer?.cancelConnection(device)
            return
        }

        connectedDevice = device
        deviceMtu[device.address] = DEFAULT_MTU
        fragmentBuffer[device.address] = FragmentReassembler()
        notificationReady[device.address] = CompletableDeferred()
        pairingConfirmed = false
        identityExchangeComplete = false
        remotePublicKeyHex = null
        authenticatedPeerKeyHex = null

        // Create new Noise session
        Log.i(TAG, "Creating Noise session...")
        try {
            val session = NoiseSession()
            Log.i(TAG, "NoiseSession created")

            // Load static key to prepare for handshake.
            // The prologue will be set during the pre-handshake identity exchange
            // when we receive the initiator's public key and can look up the device.
            session.loadStaticKey(context)
            Log.i(TAG, "Static key loaded")

            noiseSession = session
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create Noise session", e)
            throw e
        }

        val deviceName = device.name ?: "Unknown"
        _connectionState.value = ConnectionState.Connecting

        Log.i(TAG, "Device connected: $deviceName (${device.address})")
        // The peer drives the handshake; it is processed in processIncomingData.
    }

    /**
     * Handles device disconnection.
     */
    private suspend fun handleDeviceDisconnected(device: BluetoothDevice) {
        if (connectedDevice?.address != device.address) {
            return
        }

        Log.i(TAG, "Device disconnected: ${device.address}")

        // Cancel any pending outbound requests
        messageRouter?.cancelAllPending()

        // Clear connected device public key from request handler
        requestHandler.setConnectedDevicePublicKeyHex(null)
        requestHandler.setSessionBindingProvider(null)

        connectedDevice = null
        noiseSession = null
        deviceMtu.remove(device.address)
        fragmentBuffer.remove(device.address)
        notificationEnabled.remove(device.address)
        notificationReady.remove(device.address)?.cancel()
        pairingConfirmed = false
        identityExchangeComplete = false
        remotePublicKeyHex = null
        authenticatedPeerKeyHex = null

        _connectionState.value = ConnectionState.Disconnected
    }

    /**
     * Processes incoming data from a device.
     */
    private suspend fun processIncomingData(device: BluetoothDevice, data: ByteArray) {
        val reassembler = fragmentBuffer[device.address] ?: run {
            Log.w(TAG, "No fragment buffer for device ${device.address}")
            return
        }

        // Add fragment to reassembler
        val completeMessage = reassembler.addFragment(data) ?: return

        Log.d(TAG, "Complete message received: ${completeMessage.size} bytes")

        // Check if we are in handshake phase
        val session = noiseSession
        if (session == null) {
            Log.w(TAG, "No Noise session for device ${device.address}")
            return
        }

        // Handle pre-handshake identity exchange
        if (!identityExchangeComplete) {
            handleIdentityExchange(device, completeMessage)
            return
        }

        if (!session.isHandshakeComplete()) {
            // Process handshake message
            handleHandshakeMessage(device, completeMessage)
        } else {
            // Process encrypted application message
            handleApplicationMessage(device, completeMessage)
        }
    }

    /**
     * Handles pre-handshake identity exchange.
     *
     * The identity exchange allows us to identify the connecting device before
     * the Noise handshake and set the prologue for trusted device binding.
     *
     * Protocol:
     * 1. Go sends: [0x01, public_key_32_bytes] (33 bytes)
     * 2. We look up the device by public key
     * 3. If known, we send: [0x01, device_fingerprint_32_bytes] (33 bytes)
     *    If new, we send: [0x00] (1 byte)
     * 4. Both sides compute prologue and proceed with Noise handshake
     */
    @SuppressLint("MissingPermission")
    private suspend fun handleIdentityExchange(device: BluetoothDevice, message: ByteArray) {
        Log.d(TAG, "handleIdentityExchange: received ${message.size} bytes")

        // Validate identity message format
        if (message.size != IDENTITY_MSG_SIZE) {
            Log.e(TAG, "Invalid identity message size: ${message.size}, expected $IDENTITY_MSG_SIZE")
            // Fall back to treating as handshake (backwards compatibility)
            identityExchangeComplete = true
            handleHandshakeMessage(device, message)
            return
        }

        val version = message[0]
        if (version != IDENTITY_MSG_VERSION) {
            Log.e(TAG, "Invalid identity message version: $version, expected $IDENTITY_MSG_VERSION")
            identityExchangeComplete = true
            handleHandshakeMessage(device, message)
            return
        }

        // Extract public key
        val publicKey = message.sliceArray(1 until message.size)
        val publicKeyHex = publicKey.toHexString()
        remotePublicKeyHex = publicKeyHex
        Log.i(TAG, "Identity exchange: received public key ${publicKeyHex.take(16)}...")

        // Look up device in paired device repository
        val pairedDevice = pairedDeviceRepository?.getDevice(publicKeyHex)
        val session = noiseSession

        if (pairedDevice != null && session != null) {
            // Known device - send fingerprint and set prologue
            val fingerprint = pairedDevice.deviceFingerprint
            Log.i(TAG, "Identity exchange: known device '${pairedDevice.deviceName}', fingerprint=${fingerprint?.take(16)}...")

            if (fingerprint != null && fingerprint.length == FINGERPRINT_SIZE * 2) {
                // Send known device response with fingerprint
                val fingerprintBytes = fingerprint.hexStringToByteArray()
                val response = ByteArray(1 + FINGERPRINT_SIZE)
                response[0] = IDENTITY_ACK_KNOWN
                fingerprintBytes.copyInto(response, 1)
                sendResponse(device, response)

                // Compute and set prologue: SHA256(go_public_key || android_fingerprint || "xkey-v1")
                val prologue = computePrologueFromIdentity(publicKey, fingerprintBytes)
                session.setPrologue(prologue)
                session.reset()  // Re-initialize handshake state with new prologue
                Log.d(TAG, "Identity exchange: prologue set (${prologue.size} bytes)")
            } else {
                // Known device but no fingerprint stored - treat as new
                Log.w(TAG, "Identity exchange: known device but no fingerprint, treating as new")
                sendResponse(device, byteArrayOf(IDENTITY_ACK_UNKNOWN))
            }
        } else {
            // Unknown device - send unknown response
            Log.i(TAG, "Identity exchange: new device")
            sendResponse(device, byteArrayOf(IDENTITY_ACK_UNKNOWN))
        }

        identityExchangeComplete = true
        Log.i(TAG, "Identity exchange complete")
    }

    /**
     * Computes the Noise prologue from identity exchange data.
     * Prologue = SHA256(initiator_public_key || responder_fingerprint || "xkey-v1")
     */
    private fun computePrologueFromIdentity(publicKey: ByteArray, fingerprint: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(publicKey)
        digest.update(fingerprint)
        digest.update("xkey-v1".toByteArray(Charsets.UTF_8))
        return digest.digest()
    }

    /**
     * The static keys and prologue `local.attestDevice` binds its attestation to
     * (go-xkms#129 §5).
     *
     * This end is always the Noise **responder** over GATT — the desktop opens
     * the handshake — so the peer's static key is the initiator's. Null before
     * the handshake authenticates a peer, which the handler treats as "cannot
     * bind" and refuses rather than attesting to no channel.
     */
    private fun sessionBinding(session: NoiseSession): SessionBinding? {
        val initiator = session.getRemoteStaticKey() ?: return null
        val responder = session.getStaticPublicKey() ?: return null
        return SessionBinding(initiator, responder, session.getPrologue())
    }

    /**
     * Converts a hex string to byte array.
     */
    private fun String.hexStringToByteArray(): ByteArray {
        val len = this.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    /**
     * Handles a Noise handshake message.
     */
    @SuppressLint("MissingPermission")
    private suspend fun handleHandshakeMessage(device: BluetoothDevice, message: ByteArray) {
        val session = noiseSession ?: return

        try {
            val response = session.processHandshakeMessage(message)

            if (response != null) {
                sendResponse(device, response)
            }

            if (session.isHandshakeComplete()) {
                val deviceName = device.name ?: "Unknown"
                authenticatedPeerKeyHex = session.getRemoteStaticKey()?.toHexString()
                requestHandler.setSessionBindingProvider { sessionBinding(session) }
                _connectionState.value = ConnectionState.Connected(deviceName, device.address)
                Log.i(TAG, "Noise handshake complete with ${device.address}")

                // Send status notification
                sendStatusNotification(device)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Handshake processing failed", e)
            stateMutex.withLock {
                handleDeviceDisconnected(device)
            }
        }
    }

    /**
     * Handles an encrypted application message.
     */
    @SuppressLint("MissingPermission")
    private suspend fun handleApplicationMessage(device: BluetoothDevice, encryptedMessage: ByteArray) {
        Log.i(TAG, "handleApplicationMessage: received ${encryptedMessage.size} bytes from ${device.address}")

        val session = noiseSession ?: run {
            Log.e(TAG, "handleApplicationMessage: noiseSession is null!")
            return
        }

        // Decryption is handled outside the block below because a failure is
        // fatal in Noise: the receive nonce has already advanced, so every later
        // frame on this session would fail too. Answering with an error and
        // keeping the session alive leaves a connection that can never recover.
        val plaintext = try {
            session.decrypt(encryptedMessage)
        } catch (e: Exception) {
            Log.e(TAG, "Decryption failed; tearing down the session", e)
            handleDeviceDisconnected(device)
            try { gattServer?.cancelConnection(device) } catch (_: Exception) {}
            return
        }

        try {
            // The plaintext is a full JSON-RPC request and can carry key
            // material, passwords and OATH secrets, so it is never logged.
            Log.d(TAG, "Decrypted message: ${plaintext.size} bytes")

            val response: ByteArray? = interceptOrRoute(plaintext)
            if (response == null) {
                // This was a response to our outbound request, no reply needed
                Log.d(TAG, "Incoming message was a response to outbound request")
                return
            }
            Log.d(TAG, "Got response: ${response.size} bytes")

            // Encrypt and send response
            Log.d(TAG, "Encrypting response...")
            sendMutex.withLock {
                val encryptedResponse = session.encrypt(response)
                Log.d(TAG, "Sending encrypted response: ${encryptedResponse.size} bytes")
                sendResponse(device, encryptedResponse)
            }
            Log.i(TAG, "handleApplicationMessage: response sent successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to process application message", e)
            // Send error response if possible
            try {
                val errorResponse = requestHandler.createErrorResponse(
                    id = 0,
                    code = -32603,
                    message = "Internal error: ${e.message}"
                )
                val session2 = noiseSession
                if (session2 != null) {
                    sendMutex.withLock {
                        val encrypted = session2.encrypt(errorResponse)
                        sendResponse(device, encrypted)
                    }
                }
            } catch (e2: Exception) {
                Log.e(TAG, "Failed to send error response", e2)
            }
        }
    }

    /**
     * Intercepts pairing.confirm before normal routing, otherwise routes via the
     * message router (bidirectional) or directly to the request handler.
     *
     * @return The response bytes to send back, or null if nothing should be sent.
     */
    private suspend fun interceptOrRoute(plaintext: ByteArray): ByteArray? {
        // A completed Noise XX handshake proves only that the peer holds *a*
        // key, not that the user approved it. Until pairing is confirmed, the
        // only request that may run is pairing.confirm itself; everything else
        // is refused. Without this, any peer that can reach the transport
        // could sign, list keys, or export shared material unapproved.
        if (pairingEnforced && !pairingConfirmed) {
            handlePairingConfirmIfNeeded(plaintext)?.let { return it }
            return rejectUnpaired(plaintext)
        }

        Log.d(TAG, "Processing request...")
        val router = messageRouter
        return if (router != null) router.processMessage(plaintext)
        else requestHandler.handleRawRequest(plaintext)
    }

    /**
     * Marks the session confirmed when the authenticated peer is already a
     * trusted device, so a reconnect does not need another `pairing.confirm`.
     * Approval still comes from the paired-device store — an unknown peer is
     * left gated.
     */
    private fun adoptExistingPairing() {
        val repo = pairedDeviceRepository ?: return
        val peerKeyHex = authenticatedPeerKeyHex ?: return
        if (!repo.isDeviceKnown(peerKeyHex)) return

        pairingConfirmed = true
        requestHandler.setConnectedDevicePublicKeyHex(peerKeyHex)
        Log.i(TAG, "Peer is already paired; session confirmed without pairing.confirm")
    }

    /**
     * Whether this server can enforce pairing. A server constructed without a
     * paired-device repository has no notion of approval, so it cannot gate on
     * it.
     */
    private val pairingEnforced: Boolean
        get() = pairedDeviceRepository != null

    /**
     * Refuses a request that arrived before pairing was confirmed. Responses to
     * our own outbound requests are not refused — they carry no method and
     * belong to the router.
     */
    private fun rejectUnpaired(plaintext: ByteArray): ByteArray? {
        val json = try {
            JSONObject(String(plaintext, Charsets.UTF_8))
        } catch (e: Exception) {
            Log.w(TAG, "Dropping unparseable pre-pairing message")
            return null
        }
        val method = json.getStringOrNull("method") ?: return null // a response, not a request

        Log.w(TAG, "Refusing '$method' from an unpaired peer")
        return ProtocolResponse.error(
            json.optLong("id", -1),
            ErrorCodes.PAIRING_REQUIRED,
            "Device is not paired; send pairing.confirm first"
        ).toJson()
    }

    /**
     * Intercepts pairing.confirm messages and handles them before normal routing.
     *
     * @return The response bytes if this was a pairing.confirm message, null otherwise.
     */
    private suspend fun handlePairingConfirmIfNeeded(plaintext: ByteArray): ByteArray? {
        val json = try {
            JSONObject(String(plaintext, Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }

        val method = json.getStringOrNull("method") ?: return null
        if (method != MethodNames.PAIRING_CONFIRM) return null

        val id = json.optLong("id", -1)
        val params = json.optJSONObject("params") ?: return null
        val pairingParams = try {
            PairingConfirmParams.fromJson(params)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid pairing.confirm params", e)
            return null
        }

        Log.i(TAG, "Received pairing.confirm from \"${pairingParams.deviceName}\"")

        val repo = pairedDeviceRepository!!
        val callback = pairingCallback

        // Identity comes from the Noise transcript, never from the request
        // body. A peer that completes the handshake with its own key cannot
        // claim to be a device the user already trusts.
        val peerKeyHex = authenticatedPeerKeyHex
        if (peerKeyHex == null) {
            Log.e(TAG, "No authenticated peer key; refusing pairing")
            return ProtocolResponse.error(
                id, ErrorCodes.PAIRING_REJECTED, "No authenticated peer identity"
            ).toJson()
        }
        if (!pairingParams.publicKeyHex.equals(peerKeyHex, ignoreCase = true)) {
            Log.e(
                TAG,
                "pairing.confirm claimed a different key than the one authenticated " +
                    "by the handshake; refusing"
            )
            AuditLogger.logPairingDenied(
                deviceId = peerKeyHex,
                deviceName = pairingParams.deviceName,
                reason = "public_key_mismatch"
            )
            return ProtocolResponse.error(
                id, ErrorCodes.PAIRING_REJECTED, "Claimed public key does not match the authenticated peer"
            ).toJson()
        }

        val confirmed = if (repo.isDeviceKnown(peerKeyHex)) {
            Log.i(TAG, "Device is known, auto-accepting pairing")
            true
        } else {
            // No approval UI available means nothing can grant trust.
            callback?.onPairingConfirmationRequired(
                pairingParams.deviceName,
                peerKeyHex.take(16)
            ) ?: false
        }

        if (confirmed) {
            // Always upsert device — addDevice removes stale entries matching by key,
            // BLE address, or device name, preventing duplicates on re-pairing
            repo.addDevice(peerKeyHex, pairingParams.deviceName, connectedDevice?.address)
            pairingConfirmed = true

            // Log pairing approval
            AuditLogger.logPairingApproved(
                deviceId = peerKeyHex,
                deviceName = pairingParams.deviceName,
                fingerprint = peerKeyHex.take(16)
            )

            // Notify the request handler of the connected device's public key
            // so PAIRED_DEVICES_SKIP attestation policy can check device trust
            requestHandler.setConnectedDevicePublicKeyHex(peerKeyHex)

            val deviceName = android.os.Build.MODEL
            val result = PairingConfirmResult(confirmed = true, deviceName = deviceName)
            val response = ProtocolResponse.success(id, result.toJson())
            val responseBytes = response.toJson()

            // Initiate post-pairing enrollment if trusted computing is enabled
            scope.launch {
                try {
                    performPostPairingEnrollment(peerKeyHex, pairingParams.deviceName)
                } catch (e: Exception) {
                    Log.e(TAG, "Post-pairing enrollment failed", e)
                    // Don't disconnect - enrollment failure shouldn't break pairing
                }
            }

            return responseBytes
        } else {
            // Rejected - send error and schedule disconnect
            Log.w(TAG, "User rejected pairing from \"${pairingParams.deviceName}\"")

            // Log pairing denial
            AuditLogger.logPairingDenied(
                deviceId = peerKeyHex,
                deviceName = pairingParams.deviceName,
                reason = "user_rejected"
            )

            val response = ProtocolResponse.error(
                id, ErrorCodes.PAIRING_REJECTED, "Pairing rejected by user"
            )
            val responseBytes = response.toJson()

            // Schedule disconnect after sending the rejection response
            scope.launch {
                kotlinx.coroutines.delay(500) // Give time for response to be sent
                stateMutex.withLock {
                    connectedDevice?.let { handleDeviceDisconnected(it) }
                }
            }

            return responseBytes
        }
    }

    /**
     * Runs TCG device enrollment against a freshly paired desktop, with this
     * phone acting as its Certificate Authority.
     *
     * The ceremony is the single-pass IAK and IDevID installation of TCG "TPM 2.0
     * Keys for Device Identity and Attestation", Section 6.2:
     *
     *  1. `remote.getTCGCSRIDevID` obtains the enrollment package.
     *  2. It is verified: the CSR parses, the public areas it carries are the
     *     ones the result advertises, the EK certificate parses and is in date
     *     and chains to a trusted TPM vendor root wherever the trust store holds
     *     one, and the CSR's own signature binds the IDevID key to what it signed.
     *  3. Credential activation. A random secret is sealed to the endorsement key
     *     and bound to the IAK's Name by a software TPM2_MakeCredential, and the
     *     desktop has to return exactly that secret. This is the step that gives
     *     the EK certificate meaning: everything else in the package is public,
     *     so without it a stolen EK certificate is enough to enrol.
     *  4. `remote.getAttestationQuote` with a freshly random nonce. The quote is
     *     verified under the IAK and required to be bound to that nonce.
     *  5. The IAK and IDevID certificates are issued.
     *  6. `remote.storeEnrollmentCerts` hands both back, and the device is
     *     recorded locally with the EK fingerprint and the verified quote.
     *
     * Nothing is signed before step 4 has passed, so a desktop that cannot prove
     * possession of the TPM it claims leaves with no certificate. Every check
     * refuses by name rather than warning and continuing.
     *
     * The namespace is `remote.*` throughout. In this protocol the namespace
     * names the enrollee, not the sender, and here the enrollee is the desktop;
     * `local.*` is the mirror ceremony in which this phone enrols against the
     * desktop's authority.
     *
     * @param publicKeyHex The desktop's Noise static public key (hex-encoded)
     * @param deviceName The desktop's device name
     */
    private suspend fun performPostPairingEnrollment(publicKeyHex: String, deviceName: String) {
        val settingsRepo = trustedComputingSettingsRepository ?: return
        val settings = settingsRepo.getSettings()

        if (!settings.enabled) {
            Log.d(TAG, "Trusted computing disabled, skipping enrollment")
            return
        }

        // Only this phone's own CA can issue during post-pairing enrollment.
        // With xkms selected the desktop drives its own enrollment against that
        // server, and with no authority configured there is nothing to issue.
        if (settings.caSource != CertificateAuthoritySource.THIS_DEVICE) {
            Log.i(
                TAG,
                "Certificate authority is ${settings.caSource}; this phone does not issue here"
            )
            return
        }

        val ca = androidCA
        val enrolledRepo = enrolledDeviceRepository

        if (ca == null || enrolledRepo == null) {
            Log.w(TAG, "AndroidCA or EnrolledDeviceRepository not configured, skipping enrollment")
            return
        }

        Log.i(TAG, "Starting TCG enrollment for $deviceName")

        try {
            // Step 1: the enrollment package. Both public keys and the EK
            // certificate arrive here, which is why the ceremony needs no
            // separate key-fetch round trips.
            val packageResult = RemoteGetTCGCSRIDevIDResult.fromJson(
                sendRequestAndWaitForResponse(
                    MethodNames.REMOTE_GET_TCG_CSR_IDEVID,
                    RemoteGetTCGCSRIDevIDParams().toJson()
                )
            )
            Log.d(
                TAG,
                "Received TCG-CSR-IDEVID: ${packageResult.csr.size} bytes from " +
                    "${packageResult.platformManufacturer} ${packageResult.platformModel}"
            )

            // Step 2: verify the package before anything else is asked of it.
            val csr = try {
                TcgCsrIDevID.parse(packageResult.csr)
            } catch (e: TcgCsrException) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage("TCG-CSR-IDEVID does not parse: ${e.message}")
                )
            }

            // The result's copies of the public areas are convenience fields. If
            // they disagree with the signed CSR, the package has been tampered
            // with in transit or assembled from two different devices.
            if (!MessageDigest.isEqual(csr.attestPub, packageResult.iakPublicKey)) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage(
                        "IAK public area does not match the one inside the CSR"
                    )
                )
            }
            if (!MessageDigest.isEqual(csr.signingPub, packageResult.idevidPublicKey)) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage(
                        "IDevID public area does not match the one inside the CSR"
                    )
                )
            }

            try {
                csr.verifySelfSignature()
            } catch (e: TcgCsrException) {
                // The self-signature covers the CSR's own body: when it does not
                // verify, the package disagrees with itself. Nothing has been
                // asked of the device yet, so this says nothing about what it
                // holds.
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage("CSR verification failed: ${e.message}")
                )
            }

            val ekCertificate = verifyEndorsementKey(csr, packageResult, publicKeyHex, deviceName)
            val ekFingerprint = MessageDigest.getInstance("SHA-256")
                .digest(ekCertificate.encoded).toHexString()

            // Verification above parsed both public areas and refused the CSR
            // if either was unreadable, so these are resolved and sound.
            val iak = csr.iak
            val idevid = csr.idevid

            // Step 3: credential activation. Only a TPM holding both this
            // endorsement key and this attestation key can recover the secret.
            // An EK this side cannot wrap a secret to is an interoperability
            // problem, not a device that failed to prove anything: no challenge
            // was ever put to it.
            val ekPublicKey = ekCertificate.publicKey as? RSAPublicKey
                ?: refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.ActivationUnsupported(
                        "EK certificate carries a ${ekCertificate.publicKey.algorithm} key; " +
                            "credential activation needs an RSA endorsement key"
                    )
                )
            val challenge = try {
                TpmMakeCredential.make(ekPublicKey, iak.name())
            } catch (e: Exception) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.ActivationUnsupported(
                        "could not build a credential challenge: ${e.message}"
                    )
                )
            }

            val activated = RemoteActivateCredentialResult.fromJson(
                sendRequestAndWaitForResponse(
                    MethodNames.REMOTE_ACTIVATE_CREDENTIAL,
                    RemoteActivateCredentialParams(
                        credentialBlob = challenge.credentialBlob,
                        encryptedSecret = challenge.encryptedSecret
                    ).toJson()
                )
            )
            // The device answered, and answered wrongly. This is the one
            // refusal that means the device does not hold what it claims.
            if (!MessageDigest.isEqual(activated.decryptedSecret, challenge.secret)) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.ActivationMismatch(
                        "credential activation returned a different secret; the device does not " +
                            "hold the private endorsement key for the certificate it presented"
                    )
                )
            }
            Log.i(TAG, "Credential activation proved TPM possession for $deviceName")

            // Step 4: a fresh quote, bound to a nonce this phone chose.
            val nonce = ByteArray(ENROLLMENT_NONCE_SIZE)
                .also { java.security.SecureRandom().nextBytes(it) }
            // A nameAlg with no PCR bank is a property of the package's IAK, not
            // of a quote: no quote has been asked for and none can be, because
            // there is no bank to ask about.
            val pcrBank = TpmAlg.bankName(iak.nameAlg)
                ?: refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage(
                        "IAK names itself with hash 0x%04x, which has no PCR bank".format(iak.nameAlg)
                    )
                )
            val quote = RemoteGetAttestationQuoteResult.fromJson(
                sendRequestAndWaitForResponse(
                    MethodNames.REMOTE_GET_ATTESTATION_QUOTE,
                    RemoteGetAttestationQuoteParams(
                        nonce = nonce,
                        pcrIndices = ENROLLMENT_PCR_INDICES,
                        // The desktop quotes in the attestation key's own bank and
                        // rejects any other, because PCR values from a different
                        // bank cannot hash to the digest inside the signed quote.
                        pcrBank = pcrBank
                    ).toJson()
                )
            )

            if (!MessageDigest.isEqual(quote.nonce, nonce)) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.QuoteInvalid("quote echoed a nonce this CA did not send")
                )
            }
            if (quote.pcrValues.isEmpty()) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.QuoteInvalid("quote carries no PCR values")
                )
            }
            val missingPcrs = ENROLLMENT_PCR_INDICES.filterNot { quote.pcrValues.containsKey(it) }
            if (missingPcrs.isNotEmpty()) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.QuoteInvalid("quote omits PCRs $missingPcrs")
                )
            }
            try {
                TpmQuoteVerifier.verify(iak, quote.quoted, quote.signature, nonce)
            } catch (e: TpmQuoteException) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.QuoteInvalid(
                        "attestation quote failed verification: ${e.message}"
                    )
                )
            }
            Log.i(
                TAG,
                "Attestation quote verified for $deviceName: ${quote.pcrValues.size} PCRs " +
                    "in the ${quote.pcrBank} bank"
            )

            // Step 5: the signing key must be certified by the attestation key.
            //
            // Everything up to here is about the IAK: activation proved it sits
            // in the TPM holding the endorsement key, and the quote proved it
            // signs that TPM's current state. None of it says anything about the
            // IDevID. The CSR's self-signature proves only possession of the
            // IDevID private key, which is equally true of a key generated in
            // software -- so without this a device with a genuine TPM could be
            // issued a device identity certificate over a software key.
            //
            // The nonce is not checked here: this certification is produced when
            // the IDevID is created, long before this CA chose a challenge.
            // Freshness for the ceremony comes from activation and the quote,
            // both of which are bound to values this CA picked in this session.
            try {
                TpmCertifyVerifier.verify(
                    attester = iak,
                    subject = idevid,
                    certifyInfo = csr.sgnCertifyInfo,
                    signature = csr.sgnCertifyInfoSig
                )
            } catch (e: TpmQuoteException) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.SigningKeyNotCertified(
                        "the IDevID is not certified by the IAK: ${e.message}"
                    )
                )
            }
            Log.i(TAG, "IDevID certification binds the signing key to the IAK for $deviceName")

            // Step 6: issue. Everything above has passed, so this device has
            // proved it is the TPM its certificate names.
            val iakCertificate = ca.issueForPublicKey(
                publicKey = iak.publicKey,
                subject = enrollmentSubject(deviceName, publicKeyHex, "IAK"),
                profile = CertificateProfile.IDevID()
            )
            val idevidCertificate = ca.issueForPublicKey(
                publicKey = idevid.publicKey,
                subject = enrollmentSubject(deviceName, publicKeyHex, "IDevID"),
                profile = CertificateProfile.IDevID()
            )
            Log.i(TAG, "Issued IAK and IDevID certificates for $deviceName")

            // Step 7: hand both back, then record what was verified.
            val stored = RemoteStoreEnrollmentCertsResult.fromJson(
                sendRequestAndWaitForResponse(
                    MethodNames.REMOTE_STORE_ENROLLMENT_CERTS,
                    RemoteStoreEnrollmentCertsParams(
                        iakCert = iakCertificate.certificate,
                        idevidCert = idevidCertificate.certificate,
                        chain = ca.getCABundle()
                    ).toJson()
                )
            )
            if (!stored.stored) {
                // The certificates are already signed and are recorded locally
                // regardless; the desktop simply has not provisioned them.
                Log.w(TAG, "Desktop did not store the enrollment certificates for $deviceName")
            }

            val enrolledDevice = EnrolledDevice(
                deviceId = publicKeyHex,
                publicKeyHex = publicKeyHex,
                ekCertificateFingerprint = ekFingerprint,
                ekCertificateDER = ekCertificate.encoded,
                ekVerifiedAt = System.currentTimeMillis(),
                iakCertificateDER = iakCertificate.certificate,
                idevidCertificateDER = idevidCertificate.certificate,
                idevidCertificateChain = idevidCertificate.chain,
                initialQuote = quote.quoted,
                initialQuoteSignature = quote.signature,
                initialPCRs = serializePCRValues(quote.pcrValues),
                initialEventLog = null,
                enrolledAt = System.currentTimeMillis(),
                trustLevel = TRUST_LEVEL_FULL_ATTESTATION
            )
            enrolledRepo.enroll(enrolledDevice)

            pairedDeviceRepository?.updateDeviceIDevID(
                publicKeyHex = publicKeyHex,
                certificateDER = idevidCertificate.certificate,
                certificateChain = idevidCertificate.chain,
                trustLevel = TRUST_LEVEL_FULL_ATTESTATION,
                subjectDN = idevidCertificate.subjectDN,
                notAfter = idevidCertificate.notAfter
            )

            AuditLogger.logDeviceAttested(deviceId = publicKeyHex, deviceName = deviceName)
            Log.i(TAG, "Enrollment completed for $deviceName")
        } catch (e: EnrollmentRefusedException) {
            Log.e(TAG, "Enrollment refused for $deviceName: ${e.message}")
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Enrollment failed for $deviceName", e)
            throw e
        }
    }

    /**
     * Raised when a verification step fails. Distinct from a transport or
     * protocol failure: this one means the desktop answered, and the answer was
     * not good enough to certify.
     */
    private class EnrollmentRefusedException(val refusal: EnrollmentRefusal) :
        Exception("${refusal.auditName}: ${refusal.detail}")

    /**
     * Ends enrollment with [refusal]. Returns [Nothing] so it can stand in an
     * expression position and the compiler knows nothing after it runs.
     *
     * The refusal is written twice: to the audit log, which is the durable
     * security record, and beside the enrollment list, which is where the
     * device's own screen reads it from. The second write is what lets a user
     * see why a laptop has no certificate without reading logcat, and it
     * replaces any earlier refusal for the same device.
     */
    private fun refuseEnrollment(
        deviceId: String,
        deviceName: String,
        refusal: EnrollmentRefusal
    ): Nothing {
        AuditLogger.logDeviceEnrollmentRefused(
            deviceId = deviceId,
            deviceName = deviceName,
            refusalCase = refusal.auditName,
            detail = refusal.detail
        )
        enrolledDeviceRepository?.recordRefusal(
            EnrollmentRefusalRecord(
                deviceId = deviceId,
                deviceName = deviceName,
                refusal = refusal,
                refusedAt = System.currentTimeMillis()
            )
        )
        throw EnrollmentRefusedException(refusal)
    }

    /**
     * Resolves and checks the endorsement key certificate for [csr].
     *
     * The certificate may arrive twice, once beside the CSR and once inside it.
     * When both are present they have to agree: the copy inside is covered by
     * the CSR signature and the copy outside is not, so a mismatch means the
     * unsigned one was substituted.
     *
     * Chain validation is done against the trust store's TPM vendor roots. A
     * store with no anchors cannot refute the certificate, so enrollment
     * continues and says so; a store that has anchors and rejects the chain
     * ends enrollment.
     */
    private suspend fun verifyEndorsementKey(
        csr: TcgCsrIDevID,
        packageResult: RemoteGetTCGCSRIDevIDResult,
        publicKeyHex: String,
        deviceName: String
    ): java.security.cert.X509Certificate {
        val embedded = csr.ekCert.takeIf { it.isNotEmpty() }
        val alongside = packageResult.ekCert?.takeIf { it.isNotEmpty() }

        val ekBytes = embedded ?: alongside
            ?: refuseEnrollment(
                publicKeyHex, deviceName,
                EnrollmentRefusal.UntrustedEndorsement(
                    "enrollment package carries no EK certificate"
                )
            )

        if (embedded != null && alongside != null) {
            val embeddedCert = try {
                TcgCsrIDevID.parseCertificate(embedded)
            } catch (e: TcgCsrException) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage(
                        "EK certificate inside the CSR does not parse: ${e.message}"
                    )
                )
            }
            val alongsideCert = try {
                TcgCsrIDevID.parseCertificate(alongside)
            } catch (e: TcgCsrException) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage(
                        "EK certificate beside the CSR does not parse: ${e.message}"
                    )
                )
            }
            if (!MessageDigest.isEqual(embeddedCert.encoded, alongsideCert.encoded)) {
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.MalformedPackage(
                        "the two copies of the EK certificate disagree"
                    )
                )
            }
        }

        val ekCertificate = try {
            TcgCsrIDevID.parseCertificate(ekBytes)
        } catch (e: TcgCsrException) {
            refuseEnrollment(
                publicKeyHex, deviceName,
                EnrollmentRefusal.MalformedPackage("EK certificate does not parse: ${e.message}")
            )
        }

        try {
            ekCertificate.checkValidity()
        } catch (e: Exception) {
            refuseEnrollment(
                publicKeyHex, deviceName,
                EnrollmentRefusal.UntrustedEndorsement(
                    "EK certificate is not currently valid: ${e.message}"
                )
            )
        }

        val trustStore = trustStoreRepository
        if (trustStore == null) {
            Log.w(TAG, "No trust store configured; EK certificate chain was not checked")
            return ekCertificate
        }

        when (val result = trustStore.verifyIDevIDChain(listOf(ekCertificate.encoded))) {
            is VerificationResult.Valid ->
                Log.i(TAG, "EK certificate chains to a trusted root (${result.trustLevel})")

            is VerificationResult.NoTrustAnchors ->
                Log.w(
                    TAG,
                    "Trust store holds no TPM vendor roots; EK certificate for $deviceName " +
                        "was accepted without a chain check"
                )

            is VerificationResult.SelfSigned ->
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.UntrustedEndorsement("EK certificate is self-signed")
                )

            is VerificationResult.Invalid ->
                refuseEnrollment(
                    publicKeyHex, deviceName,
                    EnrollmentRefusal.UntrustedEndorsement(
                        "EK certificate does not chain to a trusted TPM vendor root: ${result.error}"
                    )
                )
        }
        return ekCertificate
    }

    /**
     * The subject name for an enrollment certificate. The Noise public key is
     * the serial: it is what the rest of the app keys a paired device on, so a
     * certificate that names it can be tied back to a session.
     */
    private fun enrollmentSubject(
        deviceName: String,
        publicKeyHex: String,
        organizationalUnit: String
    ): X500Name = X500NameBuilder(BCStyle.INSTANCE).apply {
        addRDN(BCStyle.O, "xKey")
        addRDN(BCStyle.OU, organizationalUnit)
        addRDN(BCStyle.SERIALNUMBER, publicKeyHex)
        addRDN(BCStyle.CN, deviceName.ifBlank { publicKeyHex })
    }.build()

    /**
     * Sends a JSON-RPC request to the connected laptop and waits for the response.
     *
     * Correlation is delegated to [BidirectionalMessageRouter], which resolves
     * the pending deferred when the reply for this id arrives in the message
     * loop and completes every outstanding one on disconnect.
     *
     * @param method The method name
     * @param params The parameters as a JSONObject
     * @return The result JSONObject from the response
     * @throws java.io.IOException if there is no session, device, or router
     * @throws ProtocolException if the peer returns an error or does not reply in time
     */
    private suspend fun sendRequestAndWaitForResponse(method: String, params: JSONObject): JSONObject {
        val router = messageRouter
            ?: throw java.io.IOException("No message router; cannot correlate responses")

        val id = enrollmentRequestId.getAndIncrement()
        val deferred = CompletableDeferred<ProtocolResponse>()
        router.registerPendingResponse(id, deferred)

        try {
            sendEncryptedMessage(ProtocolRequest(id = id, method = method, params = params).toJson())

            val response = withTimeout(ENROLLMENT_REQUEST_TIMEOUT_MS) { deferred.await() }

            response.error?.let { error ->
                throw ProtocolException("Remote error: ${error.message}", errorCode = error.code)
            }
            return response.result
                ?: throw ProtocolException("Response for $method carried no result")
        } catch (e: TimeoutCancellationException) {
            throw ProtocolException("Request timed out: $method", errorCode = ErrorCodes.INTERNAL_ERROR)
        } finally {
            router.removePendingResponse(id)
        }
    }

    /**
     * Serialize PCR values map to a ByteArray for storage.
     * Format: [count:4][index0:4][len0:4][value0:len0][index1:4][len1:4][value1:len1]...
     */
    private fun serializePCRValues(pcrValues: Map<Int, ByteArray>): ByteArray {
        val buffer = java.io.ByteArrayOutputStream()
        val dataOut = java.io.DataOutputStream(buffer)

        dataOut.writeInt(pcrValues.size)
        for ((index, value) in pcrValues) {
            dataOut.writeInt(index)
            dataOut.writeInt(value.size)
            dataOut.write(value)
        }

        return buffer.toByteArray()
    }

    /**
     * Sends an encrypted message to the connected device.
     *
     * Used by [RemoteKeyClient] for outbound remote.* requests.
     *
     * @param data The plaintext message bytes to encrypt and send.
     * @throws java.io.IOException if no active session or device is connected.
     */
    override suspend fun sendEncryptedMessage(data: ByteArray) {
        val session = noiseSession
            ?: throw java.io.IOException("No active Noise session")
        val device = connectedDevice
            ?: throw java.io.IOException("No connected device")
        sendMutex.withLock {
            val encrypted = session.encrypt(data)
            sendResponse(device, encrypted)
        }
    }

    /**
     * Sends a response to a device.
     *
     * The server handle is read once and carried through every fragment. A
     * [stop] landing midway would otherwise change what each fragment is sent
     * on: the remainder would be dropped silently and the peer left waiting on
     * a message that never ends.
     */
    @SuppressLint("MissingPermission")
    private suspend fun sendResponse(device: BluetoothDevice, response: ByteArray) {
        val characteristic = responseCharacteristic ?: return
        val server = gattServer ?: return

        // Wait for CCCD notification to be enabled (up to 5s).
        // stop() and handleDeviceDisconnected *cancel* this deferred, and an
        // await on a cancelled deferred throws CancellationException rather
        // than returning null. Letting it propagate would reach
        // handleApplicationMessage's catch, which would try to answer over the
        // connection that just went away and throw again.
        val awaited = runCatching {
            withTimeoutOrNull(NOTIFICATION_READY_TIMEOUT_MS) {
                notificationReady[device.address]?.await()
            }
        }
        if (awaited.isFailure) {
            Log.i(TAG, "Connection to ${device.address} closed while waiting to send; dropping response")
            return
        }

        if (notificationEnabled[device.address] != true) {
            Log.e(TAG, "Notifications not enabled for ${device.address} after waiting")
            return
        }

        val mtu = deviceMtu[device.address] ?: DEFAULT_MTU
        // Max payload per fragment: ATT value limit (MTU-3) minus fragment header (7 bytes)
        val maxPayloadSize = minOf(mtu - 3, 512) - FragmentReassembler.HEADER_SIZE
        if (maxPayloadSize < Fragmenter.MIN_PAYLOAD_SIZE) {
            // At the BLE default MTU of 23 this arithmetic yields 13, below the
            // fragmenter's floor, and constructing one would throw from inside a
            // coroutine — leaving the peer with no reply and no explanation.
            Log.e(
                TAG,
                "MTU $mtu leaves only $maxPayloadSize bytes per fragment; the peer must " +
                    "negotiate at least ${Fragmenter.MIN_PAYLOAD_SIZE + FragmentReassembler.HEADER_SIZE + 3}"
            )
            return
        }
        val fragmenter = Fragmenter(maxPayloadSize)

        Log.d(TAG, "sendResponse: response_size=${response.size}, mtu=$mtu")
        if (response.size <= 64) {
            Log.d(TAG, "sendResponse: response_hex=${response.joinToString("") { "%02x".format(it) }}")
        }

        val fragments = fragmenter.fragment(response)
        Log.d(TAG, "Sending ${fragments.size} fragment(s) to ${device.address}")

        for ((index, fragment) in fragments.withIndex()) {
            if (!sendNotification(server, device, characteristic, fragment)) {
                Log.w(
                    TAG,
                    "Fragment ${index + 1}/${fragments.size} could not be delivered to " +
                        "${device.address}; abandoning the response"
                )
                return
            }
            // Add inter-fragment delay for large responses to prevent BLE stack overflow
            if (fragments.size > 10 && index < fragments.size - 1) {
                delay(5)
            }
        }
    }

    /**
     * Sends one notification on the caller's server handle.
     *
     * Fragmented sends pass the handle they captured so a teardown cannot split
     * a message across two of them.
     *
     * @return false when the stack would not take the notification, so a
     *         fragment loop can stop rather than send the rest into nothing.
     */
    @SuppressLint("MissingPermission")
    private fun sendNotification(
        server: BluetoothGattServer,
        device: BluetoothDevice,
        characteristic: BluetoothGattCharacteristic,
        data: ByteArray
    ): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            server.notifyCharacteristicChanged(device, characteristic, false, data) ==
                android.bluetooth.BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = data
            @Suppress("DEPRECATION")
            server.notifyCharacteristicChanged(device, characteristic, false)
        }
    } catch (e: Exception) {
        // A handle closed under us throws rather than reporting a status.
        Log.w(TAG, "Notification to ${device.address} was refused by the stack", e)
        false
    }

    /**
     * Sends a single-frame notification on the current server handle.
     */
    @SuppressLint("MissingPermission")
    private fun sendNotification(
        device: BluetoothDevice,
        characteristic: BluetoothGattCharacteristic,
        data: ByteArray
    ): Boolean {
        val server = gattServer ?: return false
        return sendNotification(server, device, characteristic, data)
    }

    /**
     * Sends a status notification to a device.
     */
    @SuppressLint("MissingPermission")
    private fun sendStatusNotification(device: BluetoothDevice) {
        val characteristic = statusCharacteristic ?: return
        val statusValue = getStatusValue()
        sendNotification(device, characteristic, statusValue)
    }

    /**
     * Returns the current status value.
     */
    private fun getStatusValue(): ByteArray {
        val state = _connectionState.value
        return when (state) {
            is ConnectionState.Disconnected -> byteArrayOf(0x00)
            is ConnectionState.Connecting -> byteArrayOf(0x01)
            is ConnectionState.Connected -> byteArrayOf(0x02)
        }
    }

    /**
     * Returns whether the server is currently running.
     */
    fun isRunning(): Boolean = isRunning

    /**
     * Returns the currently connected device, if any.
     */
    fun getConnectedDevice(): BluetoothDevice? = connectedDevice

    /**
     * Returns whether the Noise session is established.
     */
    fun isSessionEstablished(): Boolean = noiseSession?.isHandshakeComplete() == true
}

/**
 * Represents the connection state of the GATT server.
 */
sealed class ConnectionState {
    /**
     * No device is connected.
     */
    data object Disconnected : ConnectionState()

    /**
     * A device is connecting (Noise handshake in progress).
     */
    data object Connecting : ConnectionState()

    /**
     * A device is fully connected with encrypted session.
     */
    data class Connected(
        val deviceName: String,
        val deviceAddress: String
    ) : ConnectionState()
}
