package com.automatethethings.xkey.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import android.util.Log
import com.automatethethings.xkey.ble.fido.FidoBle
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Manages BLE advertising for xKey service discovery.
 *
 * This class handles starting and stopping BLE advertisements that allow
 * xKey desktop clients to discover and connect to this device.
 *
 * Thread safety: Uses atomic operations for state management.
 */
class Advertiser(
    private val bluetoothAdapter: BluetoothAdapter?
) {
    companion object {
        private const val TAG = "XKeyAdvertiser"

        // Device name advertised (limited to 8 chars for BLE advertisement)
        private const val ADVERTISED_NAME = "xKey"
    }

    // Advertiser state
    private val _advertisingState = MutableStateFlow<AdvertisingState>(AdvertisingState.Stopped)
    val advertisingState: StateFlow<AdvertisingState> = _advertisingState.asStateFlow()

    // BLE advertiser
    private var advertiser: BluetoothLeAdvertiser? = null

    // Atomic flag for advertising state
    private val isAdvertising = AtomicBoolean(false)

    /**
     * The start the stack has not yet answered, kept so a too-large refusal
     * can be retried once without the device name.
     */
    @Volatile
    private var pendingStart: PendingStart? = null

    /**
     * The start token: [startAdvertising] takes one, [stopAdvertising]
     * advances it, so nothing the stack answers for a stopped start counts.
     */
    private val generation = LifecycleGeneration()

    /**
     * The current start attempt, whose callback the stack answers; null when
     * no start is pending or active. A retry is a new attempt on the same token.
     */
    @Volatile
    private var attempt: StartAttempt? = null

    private data class PendingStart(
        val settings: AdvertiseSettings,
        val advertiseData: AdvertiseData,
        val nameDropped: Boolean = false
    )

    /**
     * Starts BLE advertising for the xKey service.
     *
     * @return true if advertising started successfully
     */
    @SuppressLint("MissingPermission")
    fun startAdvertising(): Boolean {
        if (isAdvertising.get()) {
            Log.w(TAG, "Already advertising")
            return true
        }

        val adapter = bluetoothAdapter
        if (adapter == null || !adapter.isEnabled) {
            Log.e(TAG, "Bluetooth is not available or not enabled")
            _advertisingState.value = AdvertisingState.Error(
                AdvertiseError.BLUETOOTH_UNAVAILABLE,
                "Bluetooth is not available or not enabled"
            )
            return false
        }

        advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.e(TAG, "BLE advertising is not supported on this device")
            _advertisingState.value = AdvertisingState.Error(
                AdvertiseError.NOT_SUPPORTED,
                "BLE advertising is not supported"
            )
            return false
        }

        val settings = buildAdvertiseSettings()
        val advertiseData = buildAdvertiseData()
        val scanResponse = buildScanResponseData(includeDeviceName = true)

        val started = beginAttempt() ?: return false
        var handed = false
        ifCurrent(started) {
            pendingStart = PendingStart(settings, advertiseData)
            handed = requestStart(started, settings, advertiseData, scanResponse)
        }
        return handed
    }

    /** Opens a start attempt under a fresh start token; null once ended. */
    private fun beginAttempt(): StartAttempt? {
        val token = generation.begin() ?: return null
        return nextAttempt(token)
    }

    /**
     * Makes a new attempt, with its own callback, the current one for
     * [token]; null when a stop has run since [token] was taken.
     */
    private fun nextAttempt(token: Long): StartAttempt? {
        val next = StartAttempt(token)
        return if (generation.publish(token) { attempt = next }) next else null
    }

    /**
     * The one check by which a stack callback or a retry changes state or
     * calls the stack: [block] runs only while no stop ran since [from]'s
     * token was taken and [from] is still the current attempt, under the
     * token's lock so a stop waits for it. False when [from] is stale.
     */
    private fun ifCurrent(from: StartAttempt, block: () -> Unit): Boolean {
        var ran = false
        generation.publish(from.token) {
            if (attempt === from) {
                block()
                ran = true
            }
        }
        return ran
    }

    @SuppressLint("MissingPermission")
    private fun requestStart(
        callback: StartAttempt,
        settings: AdvertiseSettings,
        advertiseData: AdvertiseData,
        scanResponse: AdvertiseData
    ): Boolean {
        try {
            advertiser?.startAdvertising(settings, advertiseData, scanResponse, callback)
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start advertising", e)
            pendingStart = null
            attempt = null
            _advertisingState.value = AdvertisingState.Error(
                AdvertiseError.INTERNAL_ERROR,
                "Failed to start advertising: ${e.message}"
            )
            return false
        }
    }

    private fun retryWithoutDeviceName(from: StartAttempt): Boolean {
        var handed = false
        ifCurrent(from) {
            val pending = pendingStart ?: return@ifCurrent
            if (pending.nameDropped || advertiser == null) return@ifCurrent
            // The stack refuses one callback object started twice: the retry
            // is a new attempt, on the same token.
            val retry = nextAttempt(from.token) ?: return@ifCurrent
            pendingStart = pending.copy(nameDropped = true)
            Log.w(TAG, "Advertise data too large; retrying without the device name")
            handed = requestStart(
                retry,
                pending.settings,
                pending.advertiseData,
                buildScanResponseData(includeDeviceName = false)
            )
        }
        return handed
    }

    @SuppressLint("MissingPermission")
    fun stopAdvertising() {
        // First, so no answer to a start begun before this stop counts, and
        // a callback already inside the token's lock finishes before it.
        generation.advance()
        val stopping = attempt
        attempt = null
        pendingStart = null
        val wasAdvertising = isAdvertising.getAndSet(false)
        if (stopping == null && !wasAdvertising) {
            Log.d(TAG, "Not currently advertising")
            return
        }

        // A pending start is stopped too: the stack may already have it up.
        try {
            stopping?.let { advertiser?.stopAdvertising(it) }
            Log.i(TAG, "Advertising stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping advertising", e)
        }

        _advertisingState.value = AdvertisingState.Stopped
    }

    /**
     * Builds the advertise settings.
     */
    private fun buildAdvertiseSettings(): AdvertiseSettings {
        return AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setConnectable(true)
            .setTimeout(0) // Advertise indefinitely
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .build()
    }

    /**
     * Builds the primary advertise data.
     */
    private fun buildAdvertiseData(): AdvertiseData {
        val serviceUuid = GattServer.XKEY_SERVICE_UUID
        Log.i(TAG, "Building advertise data with service UUID: $serviceUuid")
        Log.i(TAG, "Service UUID string: ${serviceUuid.toString()}")

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false) // Device name in scan response
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(serviceUuid))
            // The FIDO service UUID; flags, the 128-bit and 16-bit lists fit the 31-byte PDU.
            .addServiceUuid(ParcelUuid(FidoBle.SERVICE_UUID))
            .build()

        Log.i(TAG, "Advertise data built, service UUIDs: ${data.serviceUuids}")
        return data
    }

    /**
     * Builds the scan response data: the TX power level, and the device name
     * unless a start was refused as too large.
     */
    private fun buildScanResponseData(includeDeviceName: Boolean): AdvertiseData {
        return AdvertiseData.Builder()
            .setIncludeDeviceName(includeDeviceName)
            .setIncludeTxPowerLevel(true)
            .build()
    }

    /**
     * One start attempt's callback, carrying its start token. Its answers
     * change state, retry or publish only through [ifCurrent]; a stale
     * success takes down its own advertisement, a stale failure does nothing.
     */
    private inner class StartAttempt(val token: Long) : AdvertiseCallback() {
        @SuppressLint("MissingPermission")
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            val published = ifCurrent(this) {
                pendingStart = null
                isAdvertising.set(true)
                _advertisingState.value = AdvertisingState.Advertising(
                    connectable = settingsInEffect.isConnectable,
                    txPowerLevel = settingsInEffect.txPowerLevel,
                    mode = settingsInEffect.mode
                )
            }
            if (!published) {
                Log.w(TAG, "Advertising started for a stopped start; stopping it")
                try {
                    advertiser?.stopAdvertising(this)
                } catch (e: Exception) {
                    Log.e(TAG, "Error stopping a stale advertisement", e)
                }
                return
            }
            Log.i(TAG, "Advertising started successfully: mode=${settingsInEffect.mode}, " +
                    "txPower=${settingsInEffect.txPowerLevel}, connectable=${settingsInEffect.isConnectable}, " +
                    "timeout=${settingsInEffect.timeout}")
            Log.i(TAG, "xKey service UUID being advertised: ${GattServer.XKEY_SERVICE_UUID}")
        }

        override fun onStartFailure(errorCode: Int) {
            ifCurrent(this) {
                isAdvertising.set(false)
                if (errorCode == AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE &&
                    retryWithoutDeviceName(this)
                ) {
                    return@ifCurrent
                }
                pendingStart = null
                attempt = null
                val (error, message) = mapAdvertiseError(errorCode)
                _advertisingState.value = AdvertisingState.Error(error, message)
                Log.e(TAG, "Advertising failed: $message (code=$errorCode)")
            }
        }
    }

    /**
     * Maps BLE advertise error codes to our error types.
     */
    private fun mapAdvertiseError(errorCode: Int): Pair<AdvertiseError, String> {
        return when (errorCode) {
            AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE -> {
                AdvertiseError.DATA_TOO_LARGE to "Advertise data is too large"
            }
            AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> {
                AdvertiseError.TOO_MANY_ADVERTISERS to "Too many advertisers"
            }
            AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED -> {
                AdvertiseError.ALREADY_STARTED to "Advertising already started"
            }
            AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR -> {
                AdvertiseError.INTERNAL_ERROR to "Internal error"
            }
            AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> {
                AdvertiseError.NOT_SUPPORTED to "Feature unsupported"
            }
            else -> {
                AdvertiseError.INTERNAL_ERROR to "Unknown error (code=$errorCode)"
            }
        }
    }

    /**
     * Returns whether advertising is currently active.
     */
    fun isAdvertising(): Boolean = isAdvertising.get()
}

/**
 * Represents the state of BLE advertising.
 */
sealed class AdvertisingState {
    /**
     * Advertising is stopped.
     */
    data object Stopped : AdvertisingState()

    /**
     * Advertising is active.
     */
    data class Advertising(
        val connectable: Boolean,
        val txPowerLevel: Int,
        val mode: Int
    ) : AdvertisingState()

    /**
     * An error occurred.
     */
    data class Error(
        val error: AdvertiseError,
        val message: String
    ) : AdvertisingState()
}

/**
 * Advertising error types.
 */
enum class AdvertiseError {
    /** Bluetooth is not available or not enabled */
    BLUETOOTH_UNAVAILABLE,

    /** BLE advertising is not supported on this device */
    NOT_SUPPORTED,

    /** Advertise data is too large */
    DATA_TOO_LARGE,

    /** Too many advertisers */
    TOO_MANY_ADVERTISERS,

    /** Advertising is already started */
    ALREADY_STARTED,

    /** Internal error */
    INTERNAL_ERROR
}
