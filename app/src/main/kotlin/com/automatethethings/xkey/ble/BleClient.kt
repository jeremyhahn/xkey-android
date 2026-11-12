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
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.Response as ProtocolResponse
import com.automatethethings.xkey.protocol.readGeneration
import com.automatethethings.xkey.protocol.SessionBinding
import com.automatethethings.xkey.protocol.SessionBindingProvider
import com.automatethethings.xkey.util.getStringOrNull
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.util.Collections
import java.util.WeakHashMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
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
 * - Requests the desktop sends back over the same session — it asks
 *   `local.attestDevice` right after the handshake and refuses the session
 *   without a verified answer — answered by [inboundRequests]
 * - Message fragmentation for BLE MTU constraints
 *
 * Thread safety: Uses mutex locks and coroutines for synchronization.
 *
 * @param inboundRequests answers the desktop's requests; null refuses them all,
 *   which a desktop that requires attestation treats as a failed session.
 */
class BleClient(
    private val context: Context,
    private val inboundRequests: PhoneInitiatedRequestHandler? = null,
    /**
     * Asks the user to compare the session's SAS with the desktop's. A session
     * this phone opens is trusted only once it answers yes; with none, every
     * session is refused (no unattended trust).
     */
    private val pairingConfirmation: PairingConfirmationCallback? = null
) {
    companion object {
        private const val TAG = "BleClient"

        /**
         * The SAS of a session this phone opened: the phone is the Noise
         * initiator, the desktop the responder. The desktop derives the same
         * code from the same transcript, so the two match unless a machine in
         * the middle ran two handshakes.
         *
         * @throws IllegalStateException if [binding] is null (no completed handshake).
         */
        fun shortAuthStringFor(binding: SessionBinding?): String =
            AttestTranscript.shortAuthString(binding)

        // Timeouts in milliseconds
        private const val DEFAULT_SCAN_TIMEOUT_MS = 10_000L
        private const val CONNECTION_TIMEOUT_MS = 30_000L
        private const val SERVICE_DISCOVERY_TIMEOUT_MS = 10_000L
        private const val HANDSHAKE_TIMEOUT_MS = 30_000L
        private const val REQUEST_TIMEOUT_MS = 60_000L
        private const val MTU_REQUEST_TIMEOUT_MS = 5_000L
        // How long a disconnect waits for the fragments queued ahead of it
        // before it wakes the request still waiting (#63).
        private const val DRAIN_DEADLINE_MS = 5_000L

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

    // GATT connection: the one being set up, then the one [connection] carries.
    // Written under connectionLock, where the GATT callbacks read it to tell a
    // stale GATT object's callback from the current one's; see ownsGatt.
    @Volatile
    private var gattConnection: BluetoothGatt? = null

    /**
     * The GATT objects this client has moved on from, under [connectionLock].
     * While a connection is being dialled [gattConnection] is still null, so
     * this is what tells a late callback from an earlier connection from the
     * dialled connection's own. Weak, so a closed GATT object is not kept.
     */
    private val retiredGatts: MutableSet<BluetoothGatt> =
        Collections.newSetFromMap(WeakHashMap())
    private var connectedDevice: BluetoothDevice? = null

    // Discovered characteristics
    private var controlPointCharacteristic: BluetoothGattCharacteristic? = null
    private var responseCharacteristic: BluetoothGattCharacteristic? = null
    private var statusCharacteristic: BluetoothGattCharacteristic? = null

    /**
     * The established connection, or null between connections. Installed by
     * [initializeNoiseSession] and cleared by [disconnectInternal], always
     * through [replaceConnection]; never changed field by field. Its own
     * GATT object's disconnect ends it first, through [swapConnection] and
     * [releaseConnection], before the teardown waits for [stateMutex].
     *
     * A write belongs to the [Connection] it captured, and reaches the stack
     * only while that is still this one: see [sendCharacteristicWrite].
     */
    @Volatile
    private var connection: Connection? = null

    /**
     * Makes replacing [connection] atomic with admitting a write to it and
     * with taking an acknowledgement for it, and makes a GATT callback's check
     * that its GATT object is still the client's atomic with what it takes:
     * see [ownsGatt].
     *
     * Lock order: [stateMutex] -> [writeMutex] -> [connectionLock]. This is a
     * plain monitor and the leaf: nothing suspends, takes a mutex or waits on
     * another thread while holding it. The completion a write installed is
     * invoked only after it is released, because invoking it resumes a writer
     * that may at once need the lock for its next fragment.
     *
     * A replacement does not take [writeMutex]: a writer parked on an
     * acknowledgement the dropped link will never send would hold it, and the
     * disconnect would wait on it forever. Admitting each fragment under this
     * lock instead is what keeps a writer from reaching a connection it did
     * not start on.
     */
    private val connectionLock = Any()

    /**
     * Test seam: called at each [WriteStep] of an encrypted write, so a test
     * can pause a writer there and change the connection under it. Always
     * null in production.
     */
    @Volatile
    internal var writeStepHook: ((WriteStep) -> Unit)? = null

    /**
     * Test seam: called with the new state in onConnectionStateChange, once
     * the callback's GATT object has been checked and what it completes or
     * fails has been taken (on a disconnect, its own connection ended but not
     * yet released), outside [connectionLock]. Always null in production.
     */
    @Volatile
    internal var stateChangeHook: ((Int) -> Unit)? = null

    // Negotiated MTU
    @Volatile
    private var negotiatedMtu: Int = DEFAULT_MTU

    /**
     * Test seam: called on the inbound consumer with each fragment it has
     * taken, before it checks the fragment's connection, so a test can hold
     * the consumer there and change the connection under it. Always null in
     * production.
     */
    @Volatile
    internal var inboundFragmentHook: (() -> Unit)? = null

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
     *
     * Each is tagged with the [Connection] it arrived on, so the consumer
     * reassembles it in that connection's own buffer: see [Inbound]. The
     * stack's disconnect is queued behind them, so a reply that arrived before
     * it still reaches its request (#63).
     */
    private val inboundFragments = Channel<Inbound>(Channel.UNLIMITED)

    // Pending response for the request/response pattern, and the connection
    // its request went out on, so a disconnect wakes only its own connection's
    // waiter. Both guarded by pendingResponseLock; see takePendingResponse for
    // why it is taken rather than merely completed.
    private var pendingResponse: CompletableDeferred<ByteArray>? = null
    private var pendingResponseConnection: Connection? = null

    private val pendingResponseLock = Any()

    // Mutex for state management
    private val stateMutex = Mutex()

    // Serialises encrypt-then-send. The send nonce must reach the wire in the
    // order it was taken, and sendCharacteristicWrite has a single completion
    // slot. Separate from stateMutex, which sendRequest holds while it waits:
    // the answer to a desktop request has to go out in the meantime.
    private val writeMutex = Mutex()

    // Scanning state
    private val isScanning = AtomicBoolean(false)
    private var scanDeferred: CompletableDeferred<List<ScanResult>>? = null
    private val discoveredDevices = ConcurrentHashMap<String, ScanResult>()

    // Connection completion
    private var connectionDeferred: CompletableDeferred<Unit>? = null
    private var servicesDiscoveredDeferred: CompletableDeferred<Unit>? = null
    private var mtuDeferred: CompletableDeferred<Int>? = null
    private var notificationEnabledDeferred: CompletableDeferred<Unit>? = null

    init {
        // One consumer, so fragments are reassembled in arrival order.
        scope.launch {
            for (event in inboundFragments) {
                inboundFragmentHook?.invoke()
                val source = event.connection
                when (event) {
                    // Every fragment of its connection is ahead of it, so a
                    // reply among them has already reached its request. Only
                    // now is a request still waiting on it woken (#63).
                    is Inbound.Disconnected -> takePendingResponse(source)?.cancel()
                    // Reassembled in its own connection's buffer, so a
                    // fragment queued before its connection ended never starts
                    // or finishes a message of the next one. Only this
                    // consumer touches a connection's buffer, so no reset can
                    // race it. Once its connection has ended, the message is
                    // only a reply: see handleCompleteMessage.
                    is Inbound.Fragment -> try {
                        val completeMessage = source.reassembler.addFragment(event.bytes)
                        if (completeMessage != null) {
                            handleCompleteMessage(source, completeMessage)
                        }
                    } catch (e: FragmentException) {
                        Log.e(TAG, "Fragment error", e)
                    }
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

                // Trusted only once the user confirms the SAS (#137).
                confirmShortAuthString(deviceName)

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
        val current = connection ?: throw BleClientException("Not connected - no active session")
        val session = current.session
        if (!current.trusted) {
            throw BleClientException("Not connected - the session's SAS is not confirmed")
        }

        if (controlPointCharacteristic == null) {
            throw BleClientException("Not connected - control point not available")
        }

        Log.d(TAG, "Sending request: ${request.size} bytes")

        return stateMutex.withLock {
            // Held for the whole exchange so this request owns the waiter it
            // installed; the teardown paths only ever discard their own. Bound
            // to the connection whose session it encrypts with: that
            // connection's disconnect wakes it without waiting for this mutex.
            val pending = installPendingResponse(current)
            try {
                // Encrypt, fragment and send
                sendEncrypted(session, request)

                // Wait for response with timeout. handleCompleteMessage has
                // already decrypted it: it decrypts everything, in order, to
                // tell a reply from a request the desktop sent.
                val decrypted = withTimeout(REQUEST_TIMEOUT_MS) {
                    pending.await()
                }
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
    fun isConnected(): Boolean =
        connection?.let { it.session.isHandshakeComplete() && it.trusted } == true

    /**
     * Returns the remote device's static public key after handshake.
     */
    fun getRemoteStaticKey(): ByteArray? = connection?.session?.getRemoteStaticKey()

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
        failWrite(connection?.pendingWrite?.getAndSet(null), "BleClient destroyed")

        withContext(NonCancellable) {
            stopScan()
            stateMutex.withLock {
                disconnectInternal()
            }
        }

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
        val connected = CompletableDeferred<Unit>()
        synchronized(connectionLock) { connectionDeferred = connected }
        connectedDevice = device

        // The stack can report the dial's state before connectGatt returns,
        // while gattConnection is still null: see ownsGatt.
        val dialled = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        } else {
            @Suppress("DEPRECATION")
            device.connectGatt(context, false, gattCallback)
        }
        synchronized(connectionLock) { gattConnection = dialled }

        if (dialled == null) {
            throw BleClientException("Failed to initiate GATT connection")
        }

        withTimeout(CONNECTION_TIMEOUT_MS) {
            connected.await()
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

    private fun initializeNoiseSession(localStaticKey: ByteArray) {
        val gatt = gattConnection ?: throw BleClientException("Not connected")
        val controlPoint = controlPointCharacteristic
            ?: throw BleClientException("Control point characteristic not found")
        replaceConnection(
            Connection(
                gatt = gatt,
                controlPoint = controlPoint,
                session = NoiseInitiatorSession(localStaticKey),
                requests = SupervisorJob(scope.coroutineContext[Job])
            )
        )
        Log.d(TAG, "Noise initiator session initialized")
    }

    /**
     * Makes [next] the connection, or ends the current one when it is null.
     *
     * The swap and taking the old connection's write completion are one step
     * under [connectionLock], so no write is admitted to the old connection
     * after it, and an acknowledgement for the old GATT object can no longer
     * take a completion. Outside the lock, the old connection is released:
     * see [releaseConnection].
     */
    private fun replaceConnection(next: Connection?) {
        val ended = synchronized(connectionLock) { swapConnection(next) }
        releaseConnection(ended, "its connection was replaced")
    }

    /**
     * Makes [next] the connection and returns the one it replaced, with the
     * write completion taken from it in the same step; null if there was
     * none. Call under [connectionLock].
     */
    private fun swapConnection(next: Connection?): Pair<Connection, ((Int) -> Unit)?>? {
        val previous = connection
        connection = next
        return previous?.let { it to it.pendingWrite.getAndSet(null) }
    }

    /**
     * Releases a connection [swapConnection] ended, outside [connectionLock]:
     * cancels its request workers, fails the write it left unacknowledged —
     * no ack is coming for it on a connection that has ended — and wakes the
     * request waiting for a reply on it, unless [wakeWaiter] is false because
     * the inbound consumer will once it has drained the connection's
     * fragments (#63).
     */
    private fun releaseConnection(
        ended: Pair<Connection, ((Int) -> Unit)?>?,
        reason: String,
        wakeWaiter: Boolean = true
    ) {
        val (previous, orphaned) = ended ?: return
        previous.requests.cancel()
        failWrite(orphaned, reason)
        if (wakeWaiter) takePendingResponse(previous)?.cancel()
    }

    private suspend fun performHandshake(expectedRemoteKey: ByteArray?) {
        val current = connection ?: throw BleClientException("Noise session not initialized")
        val session = current.session

        Log.i(TAG, "Starting Noise handshake as initiator")

        try {
            withTimeout(HANDSHAKE_TIMEOUT_MS) {
                // Step 1: Send identity message (pre-handshake)
                val identityMsg = session.createIdentityMessage()
                Log.d(TAG, "Sending identity message: ${identityMsg.size} bytes")
                sendFragmentedMessage(current, identityMsg)

                // Wait for identity acknowledgment
                val identityAck = current.handshakeResponses.receive()
                session.processIdentityAck(identityAck)
                Log.d(TAG, "Identity exchange complete")

                // Step 2: Send handshake message 1 (-> e)
                val msg1 = session.createHandshakeMessage1()
                Log.d(TAG, "Sending handshake message 1: ${msg1.size} bytes")
                sendFragmentedMessage(current, msg1)

                // Step 3: Receive handshake message 2 (<- e, ee, s, es)
                val msg2 = current.handshakeResponses.receive()
                Log.d(TAG, "Received handshake message 2: ${msg2.size} bytes")
                session.processHandshakeMessage2(msg2)

                // Verify remote key if expected. Message 2 carries it, so a
                // mismatch aborts before message 3 completes the handshake and
                // the desktop can send this phone anything.
                if (expectedRemoteKey != null) {
                    val remoteKey = session.getRemoteStaticKey()
                    if (remoteKey == null || !remoteKey.contentEquals(expectedRemoteKey)) {
                        throw BleClientException("Remote key mismatch - possible MITM attack")
                    }
                    Log.d(TAG, "Remote key verified successfully")
                }

                // Step 4: Send handshake message 3 (-> s, se). Transport keys
                // are derived before it goes out: the desktop sends
                // local.attestDevice the moment it reads message 3, and a
                // request landing before finalizeHandshake would be mistaken
                // for a handshake reply.
                //
                // writeMutex is held from finalization until the stack
                // acknowledges message 3's last write. The answer to that
                // request goes out under the same lock, so it waits for
                // message 3 instead of taking the single write-completion slot
                // from it while the stack is still busy with its write.
                val msg3 = session.createHandshakeMessage3()
                writeMutex.withLock {
                    session.finalizeHandshake()
                    Log.d(TAG, "Sending handshake message 3: ${msg3.size} bytes")
                    sendFragmentedMessage(current, msg3)
                }
            }
        } catch (e: TimeoutCancellationException) {
            throw BleClientException("Handshake timed out", e)
        }

        Log.i(TAG, "Noise handshake complete")
    }

    /**
     * Shows the user this session's SAS and waits for the answer. Nothing on
     * the wire: the code comes from the session binding the handshake left,
     * which the desktop derives too. Until the answer, the desktop's requests
     * wait in [dispatchInboundRequest]; a no (or no one to ask) refuses the
     * session, and [connect]'s failure path disconnects it.
     */
    private suspend fun confirmShortAuthString(deviceName: String) {
        val current = connection ?: throw BleClientException("Noise session not initialized")
        val confirmed = try {
            val binding = current.session.sessionBinding()
                ?: throw BleClientException("No session binding to derive the SAS from")
            val sas = shortAuthStringFor(binding)
            val peerKeyHex = binding.responderStaticPublicKey.joinToString("") { "%02x".format(it) }
            val callback = pairingConfirmation
            if (callback == null) {
                Log.w(TAG, "No one to confirm the SAS, refusing the session")
                false
            } else {
                callback.onPairingConfirmationRequired(deviceName, peerKeyHex.take(16), sas)
            }
        } catch (e: Throwable) {
            current.sasConfirmed.complete(false)
            throw e
        }

        current.trusted = confirmed
        current.sasConfirmed.complete(confirmed)
        if (!confirmed) {
            throw BleClientException("Short authentication string not confirmed")
        }
        Log.i(TAG, "SAS confirmed by the user")
    }

    /** Fragments [message] and writes it on [target], one fragment at a time. */
    private suspend fun sendFragmentedMessage(target: Connection, message: ByteArray) {
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
            sendCharacteristicWrite(target, fragment)

            // Small delay between fragments to prevent BLE stack overflow
            if (fragments.size > 1 && index < fragments.size - 1) {
                kotlinx.coroutines.delay(10)
            }
        }
    }

    /**
     * Writes one fragment on [target] and suspends until the stack
     * acknowledges it.
     *
     * The write is admitted under [connectionLock], before its completion is
     * installed or anything reaches the stack, and only while its coroutine
     * is active and [target] is still the client's connection. A cancelled
     * continuation still runs this block, so without the first check a
     * cancelled worker would write anyway; without the second, a writer that
     * outlived its connection would write the old session's ciphertext on a
     * link the client has moved on from.
     */
    private suspend fun sendCharacteristicWrite(
        target: Connection,
        data: ByteArray
    ) = suspendCancellableCoroutine<Unit> { cont ->
        val completion: (Int) -> Unit = { status ->
            if (status == BluetoothGatt.GATT_SUCCESS) {
                cont.resume(Unit)
            } else {
                cont.resumeWithException(BleClientException("Write failed with status: $status"))
            }
        }
        // Null when refused; otherwise whether the stack took the write, and
        // the completion it displaced.
        val admission = synchronized(connectionLock) {
            if (!cont.isActive || target !== connection) {
                null
            } else {
                writeStepHook?.invoke(WriteStep.WRITE_ADMITTED)
                val stale = target.pendingWrite.getAndSet(completion)
                // A writer that gives up -- a timeout, a cancelled request --
                // takes only its own callback with it, never one a later
                // writer has installed.
                cont.invokeOnCancellation { target.pendingWrite.compareAndSet(completion, null) }
                startWrite(target, data) to stale
            }
        }

        if (admission == null) {
            // Nothing reached the stack. A cancelled continuation ignores
            // this; a live one learns its connection has gone.
            cont.resumeWithException(BleClientException("The connection this write belongs to has ended"))
            return@suspendCancellableCoroutine
        }
        val (started, stale) = admission
        if (stale != null) {
            // Every path that ends a write takes its own callback out, so this
            // is a write the stack never acknowledged. Its ack is not coming:
            // fail it rather than leave its writer parked.
            Log.w(TAG, "Replaced the completion of a write that was never acknowledged")
            stale(BluetoothGatt.GATT_FAILURE)
        }
        // Only while the slot is still this write's: whatever took it out --
        // an ack, a replacement, a teardown -- has resumed the writer already.
        if (!started && target.pendingWrite.compareAndSet(completion, null)) {
            cont.resumeWithException(BleClientException("Failed to initiate write"))
        }
    }

    /** Hands [data] to the stack on [target]; true if the write started. */
    @SuppressLint("MissingPermission")
    private fun startWrite(target: Connection, data: ByteArray): Boolean {
        val characteristic = target.controlPoint
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            // The API-33 overload returns a BluetoothStatusCodes value, not a
            // BluetoothGatt status.
            target.gatt.writeCharacteristic(characteristic, data, writeType) ==
                android.bluetooth.BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = data
            @Suppress("DEPRECATION")
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            @Suppress("DEPRECATION")
            target.gatt.writeCharacteristic(characteristic)
        }
    }

    /** Fails [completion], if any: no ack is coming for its write now. */
    private fun failWrite(completion: ((Int) -> Unit)?, reason: String) {
        if (completion == null) return
        Log.w(TAG, "Failing the write in flight: $reason")
        completion(BluetoothGatt.GATT_FAILURE)
    }

    /**
     * Whether [gatt] is this client's own: the GATT object of the connection
     * it has or is setting up or, while one is being dialled and
     * [gattConnection] is still null, any GATT object it has not moved on
     * from. Call under [connectionLock], in the same step as reading what
     * the callback completes or takes, so a disconnect and a new dial cannot
     * come between the check and the effect.
     */
    private fun ownsGatt(gatt: BluetoothGatt): Boolean {
        val current = gattConnection
        return if (current != null) gatt === current else gatt !in retiredGatts
    }

    /** What [take] returns, read under [connectionLock], or null if [gatt] is not the client's. */
    private fun <T> takeIfOwned(gatt: BluetoothGatt, take: () -> T): T? =
        synchronized(connectionLock) { if (ownsGatt(gatt)) take() else null }

    private val gattCallback = object : BluetoothGattCallback() {

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            Log.d(TAG, "Connection state changed: status=$status, newState=$newState")

            // One step under connectionLock: whether gatt is still the
            // client's and, only if it is, the dial's deferred and, on a
            // disconnect, the end of its own connection, with the write that
            // connection left on the stack. A late callback from a GATT object
            // the client has moved on from, while the next connection is
            // dialled or once it is up, must not complete or fail anything of
            // that connection's or tear it down. The connection is ended only
            // if this is its GATT object, and what is released below is the
            // one it ended, so not even a check gone stale could end, cancel
            // or wake another connection's. The disconnect is queued behind
            // the fragments in the same step, as no fragment of the
            // connection can be queued after it (#63).
            var disconnectQueued = false
            val owned = takeIfOwned(gatt) {
                val ended = if (
                    newState == BluetoothProfile.STATE_DISCONNECTED && connection?.gatt === gatt
                ) {
                    swapConnection(null)?.also { (previous, _) ->
                        disconnectQueued = inboundFragments.trySend(Inbound.Disconnected(previous)).isSuccess
                    }
                } else {
                    null
                }
                connectionDeferred to ended
            }
            if (owned == null) {
                Log.w(TAG, "Ignoring a state change from a stale GATT connection")
                try {
                    gatt.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Error closing a stale GATT connection", e)
                }
                return
            }
            stateChangeHook?.invoke(newState)
            val (dial, ended) = owned

            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.i(TAG, "Connected to GATT server")
                    dial?.complete(Unit)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.i(TAG, "Disconnected from GATT server")
                    dial?.completeExceptionally(
                        BleClientException("Connection failed with status: $status")
                    )
                    // Before the teardown below, which waits on stateMutex: a
                    // request holds that mutex while its write waits for an ack
                    // the dropped link will never send, or while it waits for
                    // a reply that will never come. Ended above, so no write
                    // is admitted to the connection; released here, outside
                    // connectionLock, which the resumed writer may need at
                    // once: its request workers are cancelled and its write
                    // failed. Its request's waiter is woken by the inbound
                    // consumer once the reply queued ahead of the disconnect,
                    // if any, has reached it, or at the drain deadline (#63).
                    // The teardown then finds the connection already ended.
                    releaseConnection(ended, "disconnected from GATT server", wakeWaiter = !disconnectQueued)
                    if (disconnectQueued && ended != null) {
                        val previous = ended.first
                        scope.launch {
                            delay(DRAIN_DEADLINE_MS)
                            takePendingResponse(previous)?.let {
                                Log.w(TAG, "Fragments not drained by the deadline; failing the waiting request")
                                it.cancel()
                            }
                        }
                    }
                    scope.launch {
                        stateMutex.withLock {
                            // Unless a disconnect and a new connection got the
                            // lock first: this callback is not that one's.
                            val live = gattConnection
                            if (live == null || live === gatt) {
                                disconnectInternal()
                                _connectionState.value = ClientConnectionState.Disconnected
                            }
                        }
                    }
                }
            }
        }

        // The dial's steps below are completed only by the client's own GATT
        // object, checked in the same step as reading the deferred: see
        // onConnectionStateChange.

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            Log.d(TAG, "Services discovered: status=$status")

            val discovered = takeIfOwned(gatt) { servicesDiscoveredDeferred }
            if (status == BluetoothGatt.GATT_SUCCESS) {
                discovered?.complete(Unit)
            } else {
                discovered?.completeExceptionally(
                    BleClientException("Service discovery failed with status: $status")
                )
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            Log.d(TAG, "MTU changed: mtu=$mtu, status=$status")

            val negotiated = takeIfOwned(gatt) { mtuDeferred }
            if (status == BluetoothGatt.GATT_SUCCESS) {
                negotiated?.complete(mtu)
            } else {
                negotiated?.complete(DEFAULT_MTU)
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            Log.d(TAG, "Descriptor write: uuid=${descriptor.uuid}, status=$status")

            if (descriptor.uuid == GattServer.CCCD_UUID) {
                val enabled = takeIfOwned(gatt) { notificationEnabledDeferred }
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    enabled?.complete(Unit)
                } else {
                    enabled?.completeExceptionally(
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
            handleCharacteristicWrite(gatt, status)
        }

        private fun handleCharacteristicWrite(gatt: BluetoothGatt, status: Int) {
            Log.d(TAG, "Characteristic write: status=$status")
            // Taken before it runs; see Connection.pendingWrite. Only by the
            // connection's own GATT object: a stale one's ack would complete
            // the new connection's write before the stack has done it. Run
            // outside connectionLock, which the resumed writer's next
            // fragment needs.
            val completion = synchronized(connectionLock) {
                connection?.takeIf { it.gatt === gatt }?.pendingWrite?.getAndSet(null)
            }
            if (completion == null) {
                Log.w(TAG, "Write acknowledged with no write waiting: status=$status")
                return
            }
            completion(status)
        }

        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            @Suppress("DEPRECATION")
            handleCharacteristicChanged(gatt, characteristic.value)
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            handleCharacteristicChanged(gatt, value)
        }

        private fun handleCharacteristicChanged(gatt: BluetoothGatt, value: ByteArray) {
            if (value.isEmpty()) return

            // Hand off without blocking the stack's callback thread, and only
            // from the client's own GATT object, queued in the same step as
            // the check: a late notification from a connection the client
            // has moved on from would land in the next one's reassembly.
            // Tagged with the connection read in that same step, so the
            // consumer can still tell it from the next connection's once
            // this one has ended. Before a connection has a session the
            // desktop has nothing to send, so there is nothing to keep.
            val queued = takeIfOwned(gatt) {
                connection?.takeIf { it.gatt === gatt }?.let { owner ->
                    inboundFragments.trySend(Inbound.Fragment(owner, value))
                }
            }
            if (queued == null) {
                Log.w(TAG, "Ignoring a notification from no current connection")
                return
            }
            // The channel is unbounded, so this only fails once destroy()
            // closed it, which is not a fragment worth reporting.
            if (queued.isFailure) {
                Log.d(TAG, "Dropping a fragment that arrived after teardown")
            }
        }
    }

    /**
     * Routes a whole message by the state of [source], the connection it
     * arrived on. Read from the current connection instead, a message of one
     * that ended would be taken by the next one: its handshake would read it
     * as a reply, or its session would decrypt it.
     *
     * Once [source] has ended, the message is decrypted by its own session
     * and only a reply is kept, and only for a request that went out on
     * [source]: the desktop may have answered just before it disconnected
     * (#63). A handshake message or a request from the desktop is dropped,
     * and nothing is written.
     */
    private fun handleCompleteMessage(source: Connection, message: ByteArray) {
        Log.d(TAG, "Complete message received: ${message.size} bytes")

        val ended = source !== connection
        val session = source.session

        // Check if we're still in handshake phase
        if (!session.isHandshakeComplete()) {
            if (ended) {
                Log.w(TAG, "Dropping a handshake message from a connection that has ended")
                return
            }
            // Route to this connection's own handshake channel. Unbounded, so
            // this never fails while the channel is open.
            source.handshakeResponses.trySend(message)
        } else {
            // Decrypted here, on the single consumer, so the receive nonce
            // advances in arrival order whichever way the message is going.
            // A message that fails authentication leaves the nonce where it
            // was, so dropping it costs nothing but the message.
            val plaintext = try {
                session.decrypt(message)
            } catch (e: Exception) {
                Log.w(TAG, "Discarding a message that failed to decrypt", e)
                return
            }

            val inbound = asInboundRequest(plaintext)
            if (inbound != null) {
                if (ended) {
                    Log.w(TAG, "Dropping a request from a connection that has ended")
                    return
                }
                dispatchInboundRequest(session, inbound, plaintext)
                return
            }

            // Route to the request that is waiting, if one still is. Taking
            // the deferred rather than completing it in place means a
            // duplicated or late reply cannot satisfy a request that a later
            // one already superseded. An ended connection's reply goes only
            // to a request that went out on it.
            val waiter = if (ended) takePendingResponse(source) else takePendingResponse()
            if (waiter == null) {
                Log.w(TAG, "Discarding a response no request is waiting for")
            } else {
                waiter.complete(plaintext)
            }
        }
    }

    /**
     * The message as a JSON-RPC request the desktop sent, or null when it is
     * anything else — a reply to [sendRequest], or bytes that are not JSON,
     * which the waiting request is better placed to report.
     */
    private fun asInboundRequest(plaintext: ByteArray): JSONObject? {
        val json = try {
            JSONObject(String(plaintext, Charsets.UTF_8))
        } catch (e: JSONException) {
            return null
        }
        return if (json.getStringOrNull("method") != null) json else null
    }

    /**
     * Answers a request the desktop sent over this phone-initiated session.
     *
     * Only `local.attestDevice` is served: it is what the desktop requires
     * before it trusts the session, and the handler answers it exactly as it
     * does on the sessions this phone accepts, bound to *this* session's keys.
     * Everything else is refused — this phone dialled out to ask the desktop
     * for something, not to be driven by it.
     *
     * Launched so the reply can go out while [sendRequest] waits; [writeMutex]
     * keeps the two from interleaving on the wire.
     */
    private fun dispatchInboundRequest(session: NoiseInitiatorSession, request: JSONObject, raw: ByteArray) {
        val owner = connection?.takeIf { it.session === session } ?: return
        val requests = owner.requests
        val id = request.optLong("id", -1)
        // The served answer comes from RequestHandler, which echoes it too.
        val generation = readGeneration(String(raw, Charsets.UTF_8))
        val method = request.getStringOrNull("method")
        val handler = inboundRequests
        val peerPublicKeyHex = session.getRemoteStaticKey()?.joinToString("") { "%02x".format(it) }
        Log.i(TAG, "Desktop sent $method over the phone-initiated session")

        // Under this connection's job: a disconnect cancels the worker, even
        // while the handler waits for the user to approve.
        scope.launch(requests) {
            // Nothing is served or answered until the user confirms the SAS
            // (#137): the desktop asks the moment it reads message 3, so this
            // waits. A rejected session answers nothing; its disconnect
            // cancels this worker.
            if (!owner.sasConfirmed.await()) return@launch
            val response = try {
                when {
                    method != MethodNames.LOCAL_ATTEST_DEVICE -> ProtocolResponse.error(
                        id,
                        ErrorCodes.METHOD_NOT_FOUND,
                        "$method is not served on a phone-initiated session",
                        generation = generation
                    ).toJson()
                    handler == null -> ProtocolResponse.error(
                        id,
                        ErrorCodes.METHOD_NOT_FOUND,
                        "This phone cannot attest on this session",
                        generation = generation
                    ).toJson()
                    else -> handler.handle(raw, SessionBindingProvider { session.sessionBinding() }, peerPublicKeyHex)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Answering $method failed", e)
                ProtocolResponse.error(id, ErrorCodes.INTERNAL_ERROR, "Request failed", generation = generation).toJson()
            }

            try {
                sendEncrypted(session, response)
            } catch (e: Exception) {
                Log.w(TAG, "Could not send the answer to $method", e)
            }
        }
    }

    /**
     * Encrypts and sends [plaintext], holding [writeMutex] across both.
     *
     * Refused if [session] is no longer the connection's: a worker that
     * outlived its connection must not write that session's ciphertext onto
     * the one that replaced it. The message is bound to the [Connection] it
     * was checked against, and each fragment is admitted only while that is
     * still the client's (see [sendCharacteristicWrite]), so a connection
     * replaced mid-message gets none of the rest.
     *
     * @throws BleClientException if [session] has ended.
     */
    private suspend fun sendEncrypted(session: NoiseInitiatorSession, plaintext: ByteArray) {
        writeMutex.withLock {
            val current = connection
            if (current == null || current.session !== session) {
                throw BleClientException("The session this message belongs to has ended")
            }
            writeStepHook?.invoke(WriteStep.SESSION_CHECKED)
            val encrypted = session.encrypt(plaintext)
            Log.d(TAG, "Encrypted message: ${encrypted.size} bytes")
            sendFragmentedMessage(current, encrypted)
        }
    }

    /**
     * Installs a fresh deferred for the request about to be sent on [owner],
     * cancelling any deferred it displaces so its owner is failed rather than
     * stranded.
     */
    private fun installPendingResponse(owner: Connection): CompletableDeferred<ByteArray> {
        val deferred = CompletableDeferred<ByteArray>()
        val displaced = synchronized(pendingResponseLock) {
            pendingResponseConnection = owner
            pendingResponse.also { pendingResponse = deferred }
        }
        displaced?.cancel()
        return deferred
    }

    /** Removes and returns the waiting deferred, or null if there is none. */
    private fun takePendingResponse(): CompletableDeferred<ByteArray>? =
        synchronized(pendingResponseLock) {
            pendingResponseConnection = null
            pendingResponse.also { pendingResponse = null }
        }

    /**
     * Removes and returns the waiting deferred only if its request went out
     * on [owner], so ending one connection never wakes a request a later one
     * installed.
     */
    private fun takePendingResponse(owner: Connection): CompletableDeferred<ByteArray>? =
        synchronized(pendingResponseLock) {
            if (pendingResponseConnection === owner) takePendingResponse() else null
        }

    /**
     * Cancels [deferred] and clears the field only if it is still the one
     * installed, so a failing request cannot discard its successor's waiter.
     */
    private fun discardPendingResponse(deferred: CompletableDeferred<ByteArray>) {
        synchronized(pendingResponseLock) {
            if (pendingResponse === deferred) {
                pendingResponse = null
                pendingResponseConnection = null
            }
        }
        deferred.cancel()
    }

    @SuppressLint("MissingPermission")
    private fun disconnectInternal() {
        // First, so no write is admitted to this connection from here on. It
        // cancels the workers answering the desktop's requests on it, and
        // fails the write it left waiting on the stack.
        replaceConnection(null)

        // Cancel pending operations
        takePendingResponse()?.cancel()

        // Clean up GATT connection. Retired in one step with clearing it, so
        // its late callbacks are told from the next dial's: see ownsGatt.
        val gatt = synchronized(connectionLock) {
            gattConnection.also { retired ->
                if (retired != null) retiredGatts += retired
                gattConnection = null
            }
        }
        gatt?.let {
            try {
                it.disconnect()
                it.close()
            } catch (e: Exception) {
                Log.e(TAG, "Error closing GATT connection", e)
            }
        }
        connectedDevice = null

        // Clear characteristics
        controlPointCharacteristic = null
        responseCharacteristic = null
        statusCharacteristic = null

        // No reassembler to reset: the half message this connection left is
        // in its own buffer, which ended with it in replaceConnection above.

        // Reset MTU
        negotiatedMtu = DEFAULT_MTU

        Log.d(TAG, "Disconnected and cleaned up")
    }

    /**
     * One established connection, as the writes that belong to it see it:
     * the session whose ciphertext goes out on it, the GATT object and
     * control point it goes out on, the job its request workers run under,
     * and the completion of the write it has outstanding. Compared by
     * identity; see [connection].
     */
    private class Connection(
        val gatt: BluetoothGatt,
        val controlPoint: BluetoothGattCharacteristic,
        val session: NoiseInitiatorSession,
        val requests: Job
    ) {
        /**
         * The completion of the one write the stack has outstanding on this
         * connection. It lives here, not on the client, so a callback for
         * one GATT object can take only its own connection's write, never
         * the next connection's.
         *
         * Ownership moves only through atomic swaps. The ack *takes* the
         * callback out before invoking it, because invoking it resumes the
         * writer, and a resumed writer can release `writeMutex` and let the
         * next writer install its own callback on another thread before this
         * one returns. Clearing the slot after the call would then discard
         * that second writer's callback, and its ack would find nothing to
         * resume.
         */
        val pendingWrite = AtomicReference<((Int) -> Unit)?>(null)

        /**
         * Reassembles the fragments this connection received. Only the
         * inbound consumer touches it, and it ends with the connection, so a
         * disconnect never resets it from another thread.
         */
        val reassembler = FragmentReassembler()

        /**
         * The complete messages this connection's handshake reads. Its own,
         * so a message queued for a connection that ended is never read by
         * the next connection's handshake. Unbounded, so the consumer hands
         * a message over without suspending and in arrival order.
         */
        val handshakeResponses = Channel<ByteArray>(Channel.UNLIMITED)

        /**
         * The user's answer to this session's SAS. The desktop's requests
         * wait on it; a no, or a connection that fails first, completes it
         * false.
         */
        val sasConfirmed = CompletableDeferred<Boolean>()

        /** Whether the user confirmed this session's SAS; nothing is sent before. */
        @Volatile
        var trusted = false
    }

    /** What the stack delivered on a [Connection], in the order it did. */
    private sealed class Inbound(val connection: Connection) {
        /** A notified fragment. */
        class Fragment(connection: Connection, val bytes: ByteArray) : Inbound(connection)

        /** The stack's disconnect, queued behind the fragments that came before it. */
        class Disconnected(connection: Connection) : Inbound(connection)
    }

    /** The points of an encrypted write [writeStepHook] is called at. */
    internal enum class WriteStep {
        /** In [sendEncrypted], under writeMutex, once the session has been checked. */
        SESSION_CHECKED,

        /** In [sendCharacteristicWrite], under connectionLock, once the fragment is admitted. */
        WRITE_ADMITTED
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
 * Answers a JSON-RPC request the desktop sends over a session [BleClient]
 * opened — in practice `local.attestDevice`, which the desktop requires before
 * it trusts a phone-initiated session.
 *
 * Implemented by delegating to `RequestHandler.handleRawRequest(data, binding,
 * peerPublicKeyHex)`, so the answer is the same handler's, bound to this
 * session rather than to whichever session the phone is serving.
 */
interface PhoneInitiatedRequestHandler {
    /**
     * @param request the decrypted JSON-RPC request
     * @param binding the channel binding of the session it arrived on
     * @param peerPublicKeyHex the desktop's authenticated static key, lowercase hex
     * @return the JSON-RPC response to encrypt and send back
     */
    suspend fun handle(request: ByteArray, binding: SessionBindingProvider, peerPublicKeyHex: String?): ByteArray
}

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
     *
     * The receive nonce advances only once the ciphertext authenticates, as the
     * Noise spec requires: stray or forged bytes are rejected without
     * desynchronising every message after them.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        val key = recvKey ?: throw NoiseException("Session not established")

        val nonce = java.nio.ByteBuffer.allocate(12)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putInt(0)
            .putLong(recvNonce)
            .array()

        val cipher = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = javax.crypto.spec.SecretKeySpec(key, "ChaCha20")
        val ivSpec = javax.crypto.spec.IvParameterSpec(nonce)
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec)

        val plaintext = cipher.doFinal(ciphertext)
        recvNonce++
        return plaintext
    }

    fun isHandshakeComplete(): Boolean = handshakeComplete

    fun getRemoteStaticKey(): ByteArray? = remoteStaticKey

    fun getLocalStaticPublicKey(): ByteArray = localStaticPublicKey

    /**
     * The prologue this session ran its handshake under — 32 bytes once the
     * identity ack bound a known device's fingerprint, empty on a first pairing.
     *
     * An initiator needs its own view of this to derive the device-attestation
     * channel binding (go-xkms#129 §5), which commits to the prologue so a first
     * pairing and a reconnect can never produce the same value. Returns a copy:
     * the prologue is part of a completed handshake's transcript.
     */
    fun getPrologue(): ByteArray = prologue.copyOf()

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
