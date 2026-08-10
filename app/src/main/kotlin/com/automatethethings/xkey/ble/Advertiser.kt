package com.automatethethings.xkey.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import android.util.Log
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
        val scanResponse = buildScanResponseData()

        try {
            advertiser?.startAdvertising(settings, advertiseData, scanResponse, advertiseCallback)
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start advertising", e)
            _advertisingState.value = AdvertisingState.Error(
                AdvertiseError.INTERNAL_ERROR,
                "Failed to start advertising: ${e.message}"
            )
            return false
        }
    }

    /**
     * Stops BLE advertising.
     */
    @SuppressLint("MissingPermission")
    fun stopAdvertising() {
        if (!isAdvertising.compareAndSet(true, false)) {
            Log.d(TAG, "Not currently advertising")
            return
        }

        try {
            advertiser?.stopAdvertising(advertiseCallback)
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
            .build()

        Log.i(TAG, "Advertise data built, service UUIDs: ${data.serviceUuids}")
        return data
    }

    /**
     * Builds the scan response data containing additional information.
     */
    private fun buildScanResponseData(): AdvertiseData {
        return AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .setIncludeTxPowerLevel(true)
            .build()
    }

    /**
     * Advertise callback implementation.
     */
    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            isAdvertising.set(true)
            _advertisingState.value = AdvertisingState.Advertising(
                connectable = settingsInEffect.isConnectable,
                txPowerLevel = settingsInEffect.txPowerLevel,
                mode = settingsInEffect.mode
            )
            Log.i(TAG, "Advertising started successfully: mode=${settingsInEffect.mode}, " +
                    "txPower=${settingsInEffect.txPowerLevel}, connectable=${settingsInEffect.isConnectable}, " +
                    "timeout=${settingsInEffect.timeout}")
            Log.i(TAG, "xKey service UUID being advertised: ${GattServer.XKEY_SERVICE_UUID}")
        }

        override fun onStartFailure(errorCode: Int) {
            isAdvertising.set(false)
            val (error, message) = mapAdvertiseError(errorCode)
            _advertisingState.value = AdvertisingState.Error(error, message)
            Log.e(TAG, "Advertising failed: $message (code=$errorCode)")
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
