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
package com.automatethethings.xkey.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * BLE central (client) for connecting to xKey desktop GATT servers.
 *
 * This class enables the phone to scan for and connect to laptops/desktops
 * that are advertising as xKey GATT servers. It handles:
 * - BLE scanning for devices advertising XKEY_SERVICE_UUID
 * - GATT client connection and service discovery
 * - Noise protocol handshake as INITIATOR (phone initiates to laptop)
 * - Encrypted request/response communication
 * - Message fragmentation for BLE MTU constraints
 *
 * Thread safety: Uses mutex locks and coroutines for synchronization.
 */
class BleClient(
    private val context: Context
) {
    companion object {
        private const val TAG = "BleClient"

        // Timeouts in milliseconds
        private const val DEFAULT_SCAN_TIMEOUT_MS = 10_000L
        private const val CONNECTION_TIMEOUT_MS = 30_000L
        private const val SERVICE_DISCOVERY_TIMEOUT_MS = 10_000L
        private const val HANDSHAKE_TIMEOUT_MS = 30_000L
        private const val REQUEST_TIMEOUT_MS = 60_000L
        private const val MTU_REQUEST_TIMEOUT_MS = 5_000L

        // Default MTU (minimum guaranteed)
        private const val DEFAULT_MTU = 23

        // Maximum MTU we request
        private const val REQUESTED_MTU = 517

        /**
         * The smallest MTU that can still carry one fragment.
         *
         * An ATT write costs 3 bytes of overhead and every fragment costs a
         * [FragmentReassembler.HEADER_SIZE] header, so anything below this
         * leaves less than [Fragmenter.MIN_PAYLOAD_SIZE] for the payload and
         * the fragmenter refuses to be built at all. At the BLE default of 23
         * the budget is 13 bytes, so a failed negotiation is fatal to every
         * later send — including the identity frame, before Noise even starts.
         * [GattServer.sendResponse] guards the same arithmetic on the way out.
         */
        const val MIN_USABLE_MTU =
            Fragmenter.MIN_PAYLOAD_SIZE + FragmentReassembler.HEADER_SIZE + 3

        // Pre-handshake identity exchange constants
        private const val IDENTITY_MSG_VERSION: Byte = 0x01
        private const val IDENTITY_MSG_SIZE = 33  // 1-byte version + 32-byte public key
        private const val IDENTITY_ACK_KNOWN: Byte = 0x01
        private const val IDENTITY_ACK_UNKNOWN: Byte = 0x00
        private const val FINGERPRINT_SIZE = 32
    }

    // Coroutine scope for async operations
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Connection state flow for UI updates
    private val _connectionState = MutableStateFlow<ClientConnectionState>(ClientConnectionState.Disconnected)
    val connectionState: StateFlow<ClientConnectionState> = _connectionState.asStateFlow()

    // Bluetooth components
    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bleScanner: BluetoothLeScanner? = null

    // GATT connection
    private var gattConnection: BluetoothGatt? = null
    private var connectedDevice: BluetoothDevice? = null

    // Discovered characteristics
    private var controlPointCharacteristic: BluetoothGattCharacteristic? = null
    private var responseCharacteristic: BluetoothGattCharacteristic? = null
    private var statusCharacteristic: BluetoothGattCharacteristic? = null

    // Noise session for encryption (initiator mode)
    private var noiseSession: NoiseInitiatorSession? = null

    // Negotiated MTU
    @Volatile
    private var negotiatedMtu: Int = DEFAULT_MTU

    // Fragment reassembly for incoming messages
    private val fragmentReassembler = FragmentReassembler()

    /**
     * Inbound fragments, in the order the stack delivered them.
     *
     * The BLE stack notifies on one thread and in order, but a coroutine
     * launched per notification does not run in order. [FragmentReassembler]
     * resets its buffer whenever a first fragment lands on a non-empty one, so
     * a reordered pair silently discards the whole message and the waiting
     * request blocks until its 60-second timeout. Buffering them here and
     * draining with a single consumer keeps arrival order while leaving the
     * GATT callback non-blocking.
     */
    private val inboundFragments = Channel<ByteArray>(Channel.UNLIMITED)

    // Pending response for the request/response pattern. Guarded by
    // pendingResponseLock; see takePendingResponse for why it is taken rather
    // than merely completed.
    private var pendingResponse: CompletableDeferred<ByteArray>? = null

    private val pendingResponseLock = Any()

    // Mutex for state management
    private val stateMutex = Mutex()

    // Scanning state
    private val isScanning = AtomicBoolean(false)
    private var scanDeferred: CompletableDeferred<List<ScanResult>>? = null
    private val discoveredDevices = ConcurrentHashMap<String, ScanResult>()

    // Connection completion
    private var connectionDeferred: CompletableDeferred<Unit>? = null
    private var servicesDiscoveredDeferred: CompletableDeferred<Unit>? = null
    private var mtuDeferred: CompletableDeferred<Int>? = null
    private var notificationEnabledDeferred: CompletableDeferred<Unit>? = null

    // Handshake message channel
    private val handshakeResponseChannel = Channel<ByteArray>(Channel.BUFFERED)

    init {
        // One consumer, so fragments are reassembled in arrival order.
        scope.launch {
            for (fragment in inboundFragments) {
                try {
                    val completeMessage = fragmentReassembler.addFragment(fragment)
                    if (completeMessage != null) {
                        handleCompleteMessage(completeMessage)
                    }
                } catch (e: FragmentException) {
                    Log.e(TAG, "Fragment error", e)
                }
            }
        }
    }

    /**
     * Scans for xKey devices advertising the service UUID.
     *
     * @param timeoutMs Scan duration in milliseconds (default 10 seconds)
     * @return List of discovered devices
     * @throws BleClientException if scanning fails
     */
    @SuppressLint("MissingPermission")
    suspend fun scan(timeoutMs: Long = DEFAULT_SCAN_TIMEOUT_MS): List<ScanResult> {
        if (isScanning.get()) {
            throw BleClientException("Scan already in progress")
        }

        initializeBluetooth()

        val scanner = bleScanner ?: throw BleClientException("BLE scanner not available")

        discoveredDevices.clear()
        scanDeferred = CompletableDeferred()
        isScanning.set(true)

        val scanFilter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(GattServer.XKEY_SERVICE_UUID))
            .build()

        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE)
            .setNumOfMatches(ScanSettings.MATCH_NUM_MAX_ADVERTISEMENT)
            .setReportDelay(0)
            .build()

        Log.i(TAG, "Starting scan for xKey devices (timeout=${timeoutMs}ms)")

        try {
            scanner.startScan(listOf(scanFilter), scanSettings, scanCallback)

            withTimeout(timeoutMs) {
                // Wait for timeout or early completion
                scanDeferred?.await()
            }
        } catch (e: TimeoutCancellationException) {
            // Expected - scan completed via timeout
            Log.d(TAG, "Scan timeout reached")
        } finally {
            stopScan()
        }

        val results = discoveredDevices.values.toList()
        Log.i(TAG, "Scan complete: found ${results.size} device(s)")
        return results
    }

    /**
     * Connects to an xKey device and performs Noise handshake.
     *
     * @param address Bluetooth device address
     * @param localStaticKey Local Noise static key (32 bytes)
     * @param expectedRemoteKey Expected remote static key for verification (optional)
     * @return true if connection and handshake succeeded
     * @throws BleClientException if connection fails
     */
    @SuppressLint("MissingPermission")
    suspend fun connect(
        address: String,
        localStaticKey: ByteArray,
        expectedRemoteKey: ByteArray? = null
    ): Boolean {
        if (gattConnection != null) {
            throw BleClientException("Already connected")
        }

        initializeBluetooth()

        val adapter = bluetoothAdapter ?: throw BleClientException("Bluetooth adapter not available")

        val device = try {
            adapter.getRemoteDevice(address)
        } catch (e: IllegalArgumentException) {
            throw BleClientException("Invalid device address: $address", e)
        }

        Log.i(TAG, "Connecting to ${device.name ?: "Unknown"} ($address)")
        _connectionState.value = ClientConnectionState.Connecting(address)

        return stateMutex.withLock {
            try {
                // Connect to GATT server
                connectGatt(device)

                // Discover services
                discoverServices()

                // Request higher MTU
                requestMtu()

                // Enable notifications on response characteristic
                enableNotifications()

                // Initialize Noise session as initiator
                initializeNoiseSession(localStaticKey)

                // Perform Noise handshake
                performHandshake(expectedRemoteKey)

                val deviceName = device.name ?: "Unknown"
                _connectionState.value = ClientConnectionState.Connected(deviceName, address)
                Log.i(TAG, "Connected and handshake complete with $deviceName ($address)")

                true
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed", e)
                disconnectInternal()
                _connectionState.value = ClientConnectionState.Disconnected
                throw BleClientException("Connection failed: ${e.message}", e)
            }
        }
    }

    /**
     * Sends an encrypted request and waits for the response.
     *
     * @param request Plaintext request bytes
     * @return Decrypted response bytes
     * @throws BleClientException if not connected or request fails
     */
    suspend fun sendRequest(request: ByteArray): ByteArray {
        val session = noiseSession ?: throw BleClientException("Not connected - no active session")
        val controlPoint = controlPointCharacteristic
            ?: throw BleClientException("Not connected - control point not available")

        Log.d(TAG, "Sending request: ${request.size} bytes")

        return stateMutex.withLock {
            // Held for the whole exchange so this request owns the waiter it
            // installed; the teardown paths only ever discard their own.
            val pending = installPendingResponse()
            try {
                // Encrypt the request
                val encrypted = session.encrypt(request)
                Log.d(TAG, "Encrypted request: ${encrypted.size} bytes")

                // Fragment and send
                sendFragmentedMessage(controlPoint, encrypted)

                // Wait for response with timeout
                val encryptedResponse = withTimeout(REQUEST_TIMEOUT_MS) {
                    pending.await()
                }

                // Decrypt the response
                val decrypted = session.decrypt(encryptedResponse)
                Log.d(TAG, "Received response: ${decrypted.size} bytes")

                decrypted
            } catch (e: TimeoutCancellationException) {
                discardPendingResponse(pending)
                throw BleClientException("Request timed out", e)
            } catch (e: Exception) {
                discardPendingResponse(pending)
                throw BleClientException("Request failed: ${e.message}", e)
            }
        }
    }

    /**
     * Disconnects from the connected device.
     */
    @SuppressLint("MissingPermission")
    fun disconnect() {
        scope.launch {
            stateMutex.withLock {
                disconnectInternal()
            }
        }
    }

    /**
     * Returns whether a connection is active with completed handshake.
     */
    fun isConnected(): Boolean = noiseSession?.isHandshakeComplete() == true

    /**
     * Returns the remote device's static public key after handshake.
     */
    fun getRemoteStaticKey(): ByteArray? = noiseSession?.getRemoteStaticKey()

    /**
     * Releases all resources: stops any scan, tears down the GATT connection
     * and its notification registrations, fails pending operations and cancels
     * the internal coroutine scope.
     *
     * Teardown runs before the scope is cancelled and inside a [NonCancellable]
     * context, so it completes even when the caller's job is already being
     * cancelled. Handing it to [scope] instead would let the cancellation below
     * drop it and leak the GATT connection.
     *
     * The client is not reusable afterwards.
     */
    @SuppressLint("MissingPermission")
    suspend fun destroy() {
        // Fail pending GATT callbacks first. They are awaited on the caller's
        // coroutine rather than on `scope`, so an in-flight connect() would
        // otherwise keep holding stateMutex until its own timeout expires.
        val cause = BleClientException("BleClient destroyed")
        scanDeferred?.completeExceptionally(cause)
        scanDeferred = null
        connectionDeferred?.completeExceptionally(cause)
        connectionDeferred = null
        servicesDiscoveredDeferred?.completeExceptionally(cause)
        servicesDiscoveredDeferred = null
        mtuDeferred?.completeExceptionally(cause)
        mtuDeferred = null
        notificationEnabledDeferred?.completeExceptionally(cause)
        notificationEnabledDeferred = null
        writeCompletionCallback = null

        withContext(NonCancellable) {
            stopScan()
            stateMutex.withLock {
                disconnectInternal()
            }
        }

        handshakeResponseChannel.close()
        inboundFragments.close()
        _connectionState.value = ClientConnectionState.Disconnected
        scope.cancel()
    }

    // --- Private Implementation ---

    private fun initializeBluetooth() {
        if (bluetoothManager == null) {
            bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
                ?: throw BleClientException("Bluetooth service not available")
        }

        if (bluetoothAdapter == null) {
            bluetoothAdapter = bluetoothManager?.adapter
                ?: throw BleClientException("Bluetooth adapter not available")
        }

        if (!bluetoothAdapter!!.isEnabled) {
            throw BleClientException("Bluetooth is not enabled")
        }

        if (bleScanner == null) {
            bleScanner = bluetoothAdapter?.bluetoothLeScanner
                ?: throw BleClientException("BLE scanner not available")
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopScan() {
        if (isScanning.compareAndSet(true, false)) {
            try {
                bleScanner?.stopScan(scanCallback)
                Log.d(TAG, "Scan stopped")
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping scan", e)
            }
        }
        scanDeferred?.complete(discoveredDevices.values.toList())
        scanDeferred = null
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val address = device.address

            if (!discoveredDevices.containsKey(address)) {
                @SuppressLint("MissingPermission")
                val name = device.name ?: "Unknown"
                Log.i(TAG, "Discovered device: $name ($address) RSSI=${result.rssi}")
                discoveredDevices[address] = result
            }
        }

        override fun onScanFailed(errorCode: Int) {
            val message = when (errorCode) {
                SCAN_FAILED_ALREADY_STARTED -> "Scan already started"
                SCAN_FAILED_APPLICATION_REGISTRATION_FAILED -> "Application registration failed"
                SCAN_FAILED_INTERNAL_ERROR -> "Internal error"
                SCAN_FAILED_FEATURE_UNSUPPORTED -> "Feature unsupported"
                else -> "Unknown error (code=$errorCode)"
            }
            Log.e(TAG, "Scan failed: $message")
            isScanning.set(false)
            scanDeferred?.completeExceptionally(BleClientException("Scan failed: $message"))
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun connectGatt(device: BluetoothDevice) {
        connectionDeferred = CompletableDeferred()
        connectedDevice = device

        gattConnection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        } else {
            @Suppress("DEPRECATION")
            device.connectGatt(context, false, gattCallback)
        }

        if (gattConnection == null) {
            throw BleClientException("Failed to initiate GATT connection")
        }

        withTimeout(CONNECTION_TIMEOUT_MS) {
            connectionDeferred!!.await()
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun discoverServices() {
        servicesDiscoveredDeferred = CompletableDeferred()

        val gatt = gattConnection ?: throw BleClientException("Not connected")

        if (!gatt.discoverServices()) {
            throw BleClientException("Failed to initiate service discovery")
        }

        withTimeout(SERVICE_DISCOVERY_TIMEOUT_MS) {
            servicesDiscoveredDeferred!!.await()
        }

        // Find our service and characteristics
        val service = gatt.getService(GattServer.XKEY_SERVICE_UUID)
            ?: throw BleClientException("xKey service not found")

        controlPointCharacteristic = service.getCharacteristic(GattServer.CONTROL_POINT_UUID)
            ?: throw BleClientException("Control point characteristic not found")

        responseCharacteristic = service.getCharacteristic(GattServer.RESPONSE_UUID)
            ?: throw BleClientException("Response characteristic not found")

        statusCharacteristic = service.getCharacteristic(GattServer.STATUS_UUID)

        Log.d(TAG, "Service discovery complete - all characteristics found")
    }

    /**
     * Negotiates the ATT MTU and refuses the connection if what comes back
     * cannot carry a fragment.
     *
     * A refused, failed or timed-out negotiation leaves the BLE default of 23,
     * which is 10 bytes short of what one fragment needs. Continuing would let
     * the shortfall surface three layers down as the fragmenter's `require`
     * firing on the identity frame, so the caller would be told "Payload size
     * must be at least 20 bytes" for what is really a link that cannot carry
     * xKey traffic. It is refused here, with the real cause.
     */
    @SuppressLint("MissingPermission")
    private suspend fun requestMtu() {
        val gatt = gattConnection ?: throw BleClientException("Not connected")

        mtuDeferred = CompletableDeferred()

        if (!gatt.requestMtu(REQUESTED_MTU)) {
            Log.w(TAG, "The stack refused to start MTU negotiation")
            negotiatedMtu = DEFAULT_MTU
        } else {
            try {
                withTimeout(MTU_REQUEST_TIMEOUT_MS) {
                    negotiatedMtu = mtuDeferred!!.await()
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "MTU request timed out")
                negotiatedMtu = DEFAULT_MTU
            }
        }

        if (negotiatedMtu < MIN_USABLE_MTU) {
            throw BleClientException(
                "MTU negotiation left $negotiatedMtu bytes, too small to carry a " +
                    "fragment; xKey needs at least $MIN_USABLE_MTU"
            )
        }

        Log.d(TAG, "Negotiated MTU: $negotiatedMtu")
    }

    @SuppressLint("MissingPermission")
    private suspend fun enableNotifications() {
        val gatt = gattConnection ?: throw BleClientException("Not connected")
        val responseChar = responseCharacteristic ?: throw BleClientException("Response characteristic not found")

        notificationEnabledDeferred = CompletableDeferred()

        // Enable local notifications
        if (!gatt.setCharacteristicNotification(responseChar, true)) {
            throw BleClientException("Failed to enable local notifications")
        }

        // Write to CCCD to enable remote notifications
        val cccd = responseChar.getDescriptor(GattServer.CCCD_UUID)
            ?: throw BleClientException("CCCD descriptor not found")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val status = gatt.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            if (status != BluetoothGatt.GATT_SUCCESS) {
                throw BleClientException("Failed to write CCCD descriptor")
            }
        } else {
            @Suppress("DEPRECATION")
            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            @Suppress("DEPRECATION")
            if (!gatt.writeDescriptor(cccd)) {
                throw BleClientException("Failed to write CCCD descriptor")
            }
        }

        withTimeout(5_000L) {
            notificationEnabledDeferred!!.await()
        }

        Log.d(TAG, "Notifications enabled on response characteristic")
    }

    private suspend fun initializeNoiseSession(localStaticKey: ByteArray) {
        noiseSession = NoiseInitiatorSession(localStaticKey)
        Log.d(TAG, "Noise initiator session initialized")
    }

    private suspend fun performHandshake(expectedRemoteKey: ByteArray?) {
        val session = noiseSession ?: throw BleClientException("Noise session not initialized")
        val controlPoint = controlPointCharacteristic
            ?: throw BleClientException("Control point characteristic not found")

        Log.i(TAG, "Starting Noise handshake as initiator")

        try {
            withTimeout(HANDSHAKE_TIMEOUT_MS) {
                // Step 1: Send identity message (pre-handshake)
                val identityMsg = session.createIdentityMessage()
                Log.d(TAG, "Sending identity message: ${identityMsg.size} bytes")
                sendFragmentedMessage(controlPoint, identityMsg)

                // Wait for identity acknowledgment
                val identityAck = handshakeResponseChannel.receive()
                session.processIdentityAck(identityAck)
                Log.d(TAG, "Identity exchange complete")

                // Step 2: Send handshake message 1 (-> e)
                val msg1 = session.createHandshakeMessage1()
                Log.d(TAG, "Sending handshake message 1: ${msg1.size} bytes")
                sendFragmentedMessage(controlPoint, msg1)

                // Step 3: Receive handshake message 2 (<- e, ee, s, es)
                val msg2 = handshakeResponseChannel.receive()
                Log.d(TAG, "Received handshake message 2: ${msg2.size} bytes")
                session.processHandshakeMessage2(msg2)

                // Step 4: Send handshake message 3 (-> s, se)
                val msg3 = session.createHandshakeMessage3()
                Log.d(TAG, "Sending handshake message 3: ${msg3.size} bytes")
                sendFragmentedMessage(controlPoint, msg3)

                // Handshake complete
                session.finalizeHandshake()
            }
        } catch (e: TimeoutCancellationException) {
            throw BleClientException("Handshake timed out", e)
        }

        // Verify remote key if expected
        if (expectedRemoteKey != null) {
            val remoteKey = session.getRemoteStaticKey()
            if (remoteKey == null || !remoteKey.contentEquals(expectedRemoteKey)) {
                throw BleClientException("Remote key mismatch - possible MITM attack")
            }
            Log.d(TAG, "Remote key verified successfully")
        }

        Log.i(TAG, "Noise handshake complete")
    }

    @SuppressLint("MissingPermission")
    private suspend fun sendFragmentedMessage(
        characteristic: BluetoothGattCharacteristic,
        message: ByteArray
    ) {
        val gatt = gattConnection ?: throw BleClientException("Not connected")

        // Calculate max payload size: MTU - 3 (ATT overhead)
        val maxPayloadSize = minOf(negotiatedMtu - 3, 512) - FragmentReassembler.HEADER_SIZE
        if (maxPayloadSize < Fragmenter.MIN_PAYLOAD_SIZE) {
            // requestMtu refuses such a link, so reaching here means the MTU
            // was lowered under a live connection. Say so rather than let the
            // fragmenter's require() throw an unrelated-sounding message.
            throw BleClientException(
                "MTU $negotiatedMtu leaves only $maxPayloadSize bytes per fragment; " +
                    "xKey needs at least $MIN_USABLE_MTU"
            )
        }
        val fragmenter = Fragmenter(maxPayloadSize)

        val fragments = fragmenter.fragment(message)
        Log.d(TAG, "Sending ${fragments.size} fragment(s)")

        for ((index, fragment) in fragments.withIndex()) {
            sendCharacteristicWrite(gatt, characteristic, fragment)

            // Small delay between fragments to prevent BLE stack overflow
            if (fragments.size > 1 && index < fragments.size - 1) {
                kotlinx.coroutines.delay(10)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun sendCharacteristicWrite(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        data: ByteArray
    ) = suspendCancellableCoroutine { cont ->
        writeCompletionCallback = { status ->
            if (status == BluetoothGatt.GATT_SUCCESS) {
                cont.resume(Unit)
            } else {
                cont.resumeWithException(BleClientException("Write failed with status: $status"))
            }
        }

        val success = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            // The API-33 overload returns a BluetoothStatusCodes value, not a
            // BluetoothGatt status.
            gatt.writeCharacteristic(characteristic, data, writeType) ==
                android.bluetooth.BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = data
            @Suppress("DEPRECATION")
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            @Suppress("DEPRECATION")
            gatt.writeCharacteristic(characteristic)
        }

        if (!success) {
            writeCompletionCallback = null
            cont.resumeWithException(BleClientException("Failed to initiate write"))
        }
    }

    // Callback for write completion
    private var writeCompletionCallback: ((Int) -> Unit)? = null

    private val gattCallback = object : BluetoothGattCallback() {

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            Log.d(TAG, "Connection state changed: status=$status, newState=$newState")

            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.i(TAG, "Connected to GATT server")
                    connectionDeferred?.complete(Unit)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.i(TAG, "Disconnected from GATT server")
                    connectionDeferred?.completeExceptionally(
                        BleClientException("Connection failed with status: $status")
                    )
                    scope.launch {
                        stateMutex.withLock {
                            disconnectInternal()
                        }
                        _connectionState.value = ClientConnectionState.Disconnected
                    }
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            Log.d(TAG, "Services discovered: status=$status")

            if (status == BluetoothGatt.GATT_SUCCESS) {
                servicesDiscoveredDeferred?.complete(Unit)
            } else {
                servicesDiscoveredDeferred?.completeExceptionally(
                    BleClientException("Service discovery failed with status: $status")
                )
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            Log.d(TAG, "MTU changed: mtu=$mtu, status=$status")

            if (status == BluetoothGatt.GATT_SUCCESS) {
                mtuDeferred?.complete(mtu)
            } else {
                mtuDeferred?.complete(DEFAULT_MTU)
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            Log.d(TAG, "Descriptor write: uuid=${descriptor.uuid}, status=$status")

            if (descriptor.uuid == GattServer.CCCD_UUID) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    notificationEnabledDeferred?.complete(Unit)
                } else {
                    notificationEnabledDeferred?.completeExceptionally(
                        BleClientException("Failed to enable notifications: status=$status")
                    )
                }
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            handleCharacteristicWrite(status)
        }

        private fun handleCharacteristicWrite(status: Int) {
            Log.d(TAG, "Characteristic write: status=$status")
            writeCompletionCallback?.invoke(status)
            writeCompletionCallback = null
        }

        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            @Suppress("DEPRECATION")
            handleCharacteristicChanged(characteristic.value)
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            handleCharacteristicChanged(value)
        }

        private fun handleCharacteristicChanged(value: ByteArray) {
            if (value.isEmpty()) return

            // Hand off without blocking the stack's callback thread. The
            // channel is unbounded, so this only fails once destroy() closed
            // it, which is not a fragment worth reporting.
            if (inboundFragments.trySend(value).isFailure) {
                Log.d(TAG, "Dropping a fragment that arrived after teardown")
            }
        }
    }

    private fun handleCompleteMessage(message: ByteArray) {
        Log.d(TAG, "Complete message received: ${message.size} bytes")

        val session = noiseSession

        // Check if we're still in handshake phase
        if (session == null || !session.isHandshakeComplete()) {
            // Route to handshake channel
            scope.launch {
                handshakeResponseChannel.send(message)
            }
        } else {
            // Route to the request that is waiting, if one still is. Taking
            // the deferred rather than completing it in place means a
            // duplicated or late reply cannot satisfy a request that a later
            // one already superseded.
            val waiter = takePendingResponse()
            if (waiter == null) {
                Log.w(TAG, "Discarding a response no request is waiting for")
            } else {
                waiter.complete(message)
            }
        }
    }

    /**
     * Installs a fresh deferred for the request about to be sent, cancelling
     * any deferred it displaces so its owner is failed rather than stranded.
     */
    private fun installPendingResponse(): CompletableDeferred<ByteArray> {
        val deferred = CompletableDeferred<ByteArray>()
        val displaced = synchronized(pendingResponseLock) {
            pendingResponse.also { pendingResponse = deferred }
        }
        displaced?.cancel()
        return deferred
    }

    /** Removes and returns the waiting deferred, or null if there is none. */
    private fun takePendingResponse(): CompletableDeferred<ByteArray>? =
        synchronized(pendingResponseLock) {
            pendingResponse.also { pendingResponse = null }
        }

    /**
     * Cancels [deferred] and clears the field only if it is still the one
     * installed, so a failing request cannot discard its successor's waiter.
     */
    private fun discardPendingResponse(deferred: CompletableDeferred<ByteArray>) {
        synchronized(pendingResponseLock) {
            if (pendingResponse === deferred) pendingResponse = null
        }
        deferred.cancel()
    }

    @SuppressLint("MissingPermission")
    private fun disconnectInternal() {
        // Cancel pending operations
        takePendingResponse()?.cancel()

        // Clean up GATT connection
        gattConnection?.let { gatt ->
            try {
                gatt.disconnect()
                gatt.close()
            } catch (e: Exception) {
                Log.e(TAG, "Error closing GATT connection", e)
            }
        }
        gattConnection = null
        connectedDevice = null

        // Clear characteristics
        controlPointCharacteristic = null
        responseCharacteristic = null
        statusCharacteristic = null

        // Clear session
        noiseSession = null

        // Reset fragment reassembler
        fragmentReassembler.reset()

        // Reset MTU
        negotiatedMtu = DEFAULT_MTU

        Log.d(TAG, "Disconnected and cleaned up")
    }
}

/**
 * Connection state for the BLE client.
 */
sealed class ClientConnectionState {
    /**
     * Not connected to any device.
     */
    data object Disconnected : ClientConnectionState()

    /**
     * Connecting to a device.
     */
    data class Connecting(val address: String) : ClientConnectionState()

    /**
     * Connected with encrypted session established.
     */
    data class Connected(
        val deviceName: String,
        val deviceAddress: String
    ) : ClientConnectionState()
}

/**
 * Exception thrown for BLE client errors.
 */
class BleClientException(
    message: String,
    cause: Throwable? = null
) : IOException(message, cause)

/**
 * Noise session for initiator (client) side of XX handshake.
 *
 * The XX handshake pattern:
 * -> e
 * <- e, ee, s, es
 * -> s, se
 *
 * This class handles the initiator side where the phone sends the first message.
 */
class NoiseInitiatorSession(
    private val localStaticPrivateKey: ByteArray
) {
    companion object {
        private const val TAG = "NoiseInitiator"
        private const val PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256"
        private const val KEY_SIZE = 32
        private const val TAG_SIZE = 16

        // Identity message constants
        private const val IDENTITY_MSG_VERSION: Byte = 0x01
    }

    // Local static keypair
    private val localStaticPublicKey: ByteArray

    // Ephemeral keypair
    private var ephemeralPrivateKey: ByteArray? = null
    private var ephemeralPublicKey: ByteArray? = null

    // Remote keys
    private var remoteEphemeralKey: ByteArray? = null
    private var remoteStaticKey: ByteArray? = null

    // Symmetric state
    private var chainingKey: ByteArray = ByteArray(KEY_SIZE)
    private var handshakeHash: ByteArray = ByteArray(KEY_SIZE)
    private var encryptionKey: ByteArray? = null
    private var handshakeNonce: Long = 0

    // Session keys
    private var sendKey: ByteArray? = null
    private var recvKey: ByteArray? = null
    private var sendNonce: Long = 0
    private var recvNonce: Long = 0

    // State
    private var handshakeComplete = false
    private var prologue: ByteArray = ByteArray(0)

    // Random
    private val secureRandom = java.security.SecureRandom()

    init {
        // Compute public key from private key
        localStaticPublicKey = x25519ScalarMultBase(localStaticPrivateKey)
        initializeHandshakeState()
    }

    /**
     * Creates the pre-handshake identity message.
     * Format: [0x01, public_key_32_bytes] (33 bytes)
     */
    fun createIdentityMessage(): ByteArray {
        val message = ByteArray(1 + KEY_SIZE)
        message[0] = IDENTITY_MSG_VERSION
        localStaticPublicKey.copyInto(message, 1)
        return message
    }

    /**
     * Processes the identity acknowledgment from responder.
     */
    fun processIdentityAck(ack: ByteArray) {
        if (ack.isEmpty()) {
            throw NoiseException("Empty identity acknowledgment")
        }

        val status = ack[0]
        if (status == 0x01.toByte() && ack.size >= 33) {
            // Known device - extract fingerprint and compute prologue
            val fingerprint = ack.sliceArray(1 until ack.size)
            prologue = computePrologue(localStaticPublicKey, fingerprint)
            Log.d(TAG, "Identity ack: known device, prologue set")
            // Reinitialize with new prologue
            initializeHandshakeState()
        } else {
            // New device
            Log.d(TAG, "Identity ack: new device")
        }
    }

    private fun computePrologue(publicKey: ByteArray, fingerprint: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(publicKey)
        digest.update(fingerprint)
        digest.update("xkey-v1".toByteArray(Charsets.UTF_8))
        return digest.digest()
    }

    /**
     * Creates handshake message 1 (-> e).
     */
    fun createHandshakeMessage1(): ByteArray {
        // Generate ephemeral key
        generateEphemeralKey()

        // MixHash(e)
        mixHash(ephemeralPublicKey!!)

        // MixHash(empty payload) - for protocol compliance
        val emptyPayload = ByteArray(0)
        mixHash(emptyPayload)

        Log.d(TAG, "Created msg1 (${ephemeralPublicKey!!.size} bytes)")

        // Return ephemeral public key
        return ephemeralPublicKey!!.copyOf()
    }

    /**
     * Processes handshake message 2 (<- e, ee, s, es).
     */
    fun processHandshakeMessage2(message: ByteArray) {
        // Expected: e (32) + encrypted_s (48) + encrypted_empty_payload (16) = 96 bytes
        if (message.size < 96) {
            throw NoiseException("Message 2 too short: ${message.size}")
        }

        // Extract remote ephemeral key (e)
        remoteEphemeralKey = message.sliceArray(0 until KEY_SIZE)

        // MixHash(remote_e)
        mixHash(remoteEphemeralKey!!)

        // ee - DH(e, re)
        val eeSecret = x25519(ephemeralPrivateKey!!, remoteEphemeralKey!!)
        mixKey(eeSecret)

        // Decrypt remote static key
        val encryptedS = message.sliceArray(KEY_SIZE until KEY_SIZE + KEY_SIZE + TAG_SIZE)
        remoteStaticKey = decryptAndHash(encryptedS)

        // es - DH(e, rs)
        val esSecret = x25519(ephemeralPrivateKey!!, remoteStaticKey!!)
        mixKey(esSecret)

        // Decrypt empty payload
        if (message.size >= 96) {
            val encryptedPayload = message.sliceArray(KEY_SIZE + KEY_SIZE + TAG_SIZE until message.size)
            decryptAndHash(encryptedPayload)
        }
    }

    /**
     * Creates handshake message 3 (-> s, se).
     */
    fun createHandshakeMessage3(): ByteArray {
        // s - encrypt our static key
        val encryptedS = encryptAndHash(localStaticPublicKey)

        // se - DH(s, re)
        val seSecret = x25519(localStaticPrivateKey, remoteEphemeralKey!!)
        mixKey(seSecret)

        // Encrypt empty payload
        val encryptedPayload = encryptAndHash(ByteArray(0))

        // Combine: encrypted_s (48) + encrypted_empty_payload (16) = 64 bytes
        return encryptedS + encryptedPayload
    }

    /**
     * Finalizes the handshake and derives transport keys.
     */
    fun finalizeHandshake() {
        splitSymmetricState()
        handshakeComplete = true
        Log.i(TAG, "Handshake finalized - transport keys derived")
    }

    /**
     * Encrypts plaintext for transport.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val key = sendKey ?: throw NoiseException("Session not established")

        val nonce = java.nio.ByteBuffer.allocate(12)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putInt(0)
            .putLong(sendNonce++)
            .array()

        val cipher = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = javax.crypto.spec.SecretKeySpec(key, "ChaCha20")
        val ivSpec = javax.crypto.spec.IvParameterSpec(nonce)
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, ivSpec)

        return cipher.doFinal(plaintext)
    }

    /**
     * Decrypts ciphertext from transport.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        val key = recvKey ?: throw NoiseException("Session not established")

        val nonce = java.nio.ByteBuffer.allocate(12)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putInt(0)
            .putLong(recvNonce++)
            .array()

        val cipher = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = javax.crypto.spec.SecretKeySpec(key, "ChaCha20")
        val ivSpec = javax.crypto.spec.IvParameterSpec(nonce)
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec)

        return cipher.doFinal(ciphertext)
    }

    fun isHandshakeComplete(): Boolean = handshakeComplete

    fun getRemoteStaticKey(): ByteArray? = remoteStaticKey

    fun getLocalStaticPublicKey(): ByteArray = localStaticPublicKey

    // --- Private crypto helpers ---

    private fun initializeHandshakeState() {
        // h = SHA256(protocol_name) padded/truncated to 32 bytes
        val protocolBytes = PROTOCOL_NAME.toByteArray()
        if (protocolBytes.size <= KEY_SIZE) {
            handshakeHash = ByteArray(KEY_SIZE)
            System.arraycopy(protocolBytes, 0, handshakeHash, 0, protocolBytes.size)
        } else {
            handshakeHash = sha256(protocolBytes)
        }

        // ck = h
        chainingKey = handshakeHash.copyOf()

        // MixHash(prologue)
        mixHash(prologue)

        // Reset encryption key and nonce
        encryptionKey = ByteArray(KEY_SIZE)
        handshakeNonce = 0

        Log.d(TAG, "Handshake state initialized")
    }

    private fun generateEphemeralKey() {
        ephemeralPrivateKey = ByteArray(KEY_SIZE).also { secureRandom.nextBytes(it) }
        // Clamp per X25519 spec
        ephemeralPrivateKey!![0] = (ephemeralPrivateKey!![0].toInt() and 248).toByte()
        ephemeralPrivateKey!![31] = (ephemeralPrivateKey!![31].toInt() and 127).toByte()
        ephemeralPrivateKey!![31] = (ephemeralPrivateKey!![31].toInt() or 64).toByte()
        ephemeralPublicKey = x25519ScalarMultBase(ephemeralPrivateKey!!)
    }

    private fun x25519ScalarMultBase(scalar: ByteArray): ByteArray {
        val basePoint = ByteArray(32)
        basePoint[0] = 9
        return x25519ScalarMultPure(scalar, basePoint)
    }

    private fun x25519(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        return try {
            val privKeySpec = java.security.spec.PKCS8EncodedKeySpec(wrapX25519PrivateKey(privateKey))
            val pubKeySpec = java.security.spec.X509EncodedKeySpec(wrapX25519PublicKey(publicKey))

            val keyFactory = java.security.KeyFactory.getInstance("X25519")
            val privKey = keyFactory.generatePrivate(privKeySpec)
            val pubKey = keyFactory.generatePublic(pubKeySpec)

            val keyAgreement = javax.crypto.KeyAgreement.getInstance("X25519")
            keyAgreement.init(privKey)
            keyAgreement.doPhase(pubKey, true)
            keyAgreement.generateSecret()
        } catch (e: Exception) {
            Log.e(TAG, "X25519 via Java failed, using pure impl", e)
            x25519ScalarMultPure(privateKey, publicKey)
        }
    }

    private fun x25519ScalarMultPure(k: ByteArray, u: ByteArray): ByteArray {
        val p = java.math.BigInteger.ONE.shiftLeft(255).subtract(java.math.BigInteger.valueOf(19))

        val kClamped = k.copyOf()
        kClamped[0] = (kClamped[0].toInt() and 248).toByte()
        kClamped[31] = (kClamped[31].toInt() and 127).toByte()
        kClamped[31] = (kClamped[31].toInt() or 64).toByte()

        val uInt = decodeLittleEndian(u).mod(p)

        var x1 = uInt
        var x2 = java.math.BigInteger.ONE
        var z2 = java.math.BigInteger.ZERO
        var x3 = uInt
        var z3 = java.math.BigInteger.ONE

        var swap = java.math.BigInteger.ZERO

        for (t in 254 downTo 0) {
            val kT = kClamped[t / 8].toInt().ushr(t % 8).and(1)
            val kTBig = java.math.BigInteger.valueOf(kT.toLong())

            swap = swap.xor(kTBig)
            val (cx2, cx3) = cswap(swap, x2, x3)
            val (cz2, cz3) = cswap(swap, z2, z3)
            x2 = cx2; x3 = cx3; z2 = cz2; z3 = cz3
            swap = kTBig

            val a = x2.add(z2).mod(p)
            val aa = a.multiply(a).mod(p)
            val b = x2.subtract(z2).mod(p)
            val bb = b.multiply(b).mod(p)
            val e = aa.subtract(bb).mod(p)
            val c = x3.add(z3).mod(p)
            val d = x3.subtract(z3).mod(p)
            val da = d.multiply(a).mod(p)
            val cb = c.multiply(b).mod(p)
            x3 = da.add(cb).mod(p).pow(2).mod(p)
            z3 = x1.multiply(da.subtract(cb).mod(p).pow(2)).mod(p)
            x2 = aa.multiply(bb).mod(p)
            val a24 = java.math.BigInteger.valueOf(121665)
            z2 = e.multiply(aa.add(a24.multiply(e))).mod(p)
        }

        val (fx2, _) = cswap(swap, x2, x3)
        val (fz2, _) = cswap(swap, z2, z3)
        x2 = fx2; z2 = fz2

        val result = x2.multiply(z2.modPow(p.subtract(java.math.BigInteger.valueOf(2)), p)).mod(p)
        return encodeLittleEndian(result)
    }

    private fun decodeLittleEndian(b: ByteArray): java.math.BigInteger {
        return java.math.BigInteger(1, b.reversedArray())
    }

    private fun encodeLittleEndian(n: java.math.BigInteger): ByteArray {
        var bytes = n.toByteArray()
        if (bytes.size > 32 && bytes[0] == 0.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        val result = ByteArray(32)
        val offset = 32 - bytes.size
        System.arraycopy(bytes, 0, result, offset, bytes.size)
        return result.reversedArray()
    }

    private fun cswap(
        swap: java.math.BigInteger,
        a: java.math.BigInteger,
        b: java.math.BigInteger
    ): Pair<java.math.BigInteger, java.math.BigInteger> {
        return if (swap == java.math.BigInteger.ONE) Pair(b, a) else Pair(a, b)
    }

    private fun wrapX25519PrivateKey(raw: ByteArray): ByteArray {
        val header = byteArrayOf(
            0x30, 0x2e,
            0x02, 0x01, 0x00,
            0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x04, 0x22,
            0x04, 0x20
        )
        return header + raw
    }

    private fun wrapX25519PublicKey(raw: ByteArray): ByteArray {
        val header = byteArrayOf(
            0x30, 0x2a,
            0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x03, 0x21, 0x00
        )
        return header + raw
    }

    private fun sha256(data: ByteArray): ByteArray {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data)
    }

    private fun mixHash(data: ByteArray) {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(handshakeHash)
        digest.update(data)
        handshakeHash = digest.digest()
    }

    private fun mixKey(inputKeyMaterial: ByteArray) {
        val (ck, k) = hkdf2(chainingKey, inputKeyMaterial)
        chainingKey = ck
        encryptionKey = k
        handshakeNonce = 0
    }

    private fun hkdf2(salt: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
        mac.update(byteArrayOf(0x01))
        val t1 = mac.doFinal()

        mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
        mac.update(t1)
        mac.update(byteArrayOf(0x02))
        val t2 = mac.doFinal()

        return Pair(t1, t2)
    }

    private fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val nonce = java.nio.ByteBuffer.allocate(12)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putInt(0)
            .putLong(handshakeNonce)
            .array()

        val cipher = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = javax.crypto.spec.SecretKeySpec(encryptionKey!!, "ChaCha20")
        val ivSpec = javax.crypto.spec.IvParameterSpec(nonce)
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        cipher.updateAAD(handshakeHash)
        val ciphertext = cipher.doFinal(plaintext)

        mixHash(ciphertext)
        handshakeNonce++

        return ciphertext
    }

    private fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val nonce = java.nio.ByteBuffer.allocate(12)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putInt(0)
            .putLong(handshakeNonce)
            .array()

        val cipher = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = javax.crypto.spec.SecretKeySpec(encryptionKey!!, "ChaCha20")
        val ivSpec = javax.crypto.spec.IvParameterSpec(nonce)
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec)
        cipher.updateAAD(handshakeHash)

        val plaintext = cipher.doFinal(ciphertext)

        mixHash(ciphertext)
        handshakeNonce++
        return plaintext
    }

    private fun splitSymmetricState() {
        val (k1, k2) = hkdf2(chainingKey, ByteArray(0))

        // Initiator: k1 for sending, k2 for receiving
        sendKey = k1
        recvKey = k2
        sendNonce = 0
        recvNonce = 0
    }
}
