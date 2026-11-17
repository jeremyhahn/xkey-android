/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ble.fido

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.biometric.BiometricManager
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.BiometricLockoutException
import com.automatethethings.xkey.crypto.UserCancelledException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The FIDO GATT service (0xFFFD): the phone as a standard CTAP2 BLE
 * authenticator, next to and independent of the xkey service.
 *
 * It runs its own [BluetoothGattServer], so nothing in the xkey service's
 * table, callbacks or queues changes. fidoControlPoint takes writes only over
 * an encrypted, authenticated (MITM-protected) link, so a client must bond
 * first; fidoStatus notifies the replies. Each connected client gets one
 * [FidoBleSession]; notifications to a client go out one at a time, the next
 * after the stack reports the last sent.
 */
@SuppressLint("MissingPermission")
class FidoGattServer(
    private val context: Context,
    private val handler: FidoMessageHandler
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val clients = ConcurrentHashMap<String, Client>()

    @Volatile
    private var server: BluetoothGattServer? = null

    @Volatile
    private var statusCharacteristic: BluetoothGattCharacteristic? = null

    fun isRunning(): Boolean = server != null

    /**
     * Opens the server and adds the FIDO service. Blocks until the stack
     * reports the service added, so call it off the main thread.
     */
    fun start(): Boolean {
        if (server != null) return true
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: return false
        val added = CountDownLatch(1)
        var addStatus = BluetoothGatt.GATT_FAILURE
        val callback = Callback { status -> addStatus = status; added.countDown() }
        val opened = try {
            manager.openGattServer(context, callback)
        } catch (e: SecurityException) {
            Log.w(TAG, "No Bluetooth permission for the FIDO service", e)
            null
        } ?: return false
        val service = buildService()
        statusCharacteristic = service.getCharacteristic(FidoBle.STATUS_UUID)
        server = opened
        if (!opened.addService(service) ||
            !added.await(SERVICE_ADD_TIMEOUT_SECONDS, TimeUnit.SECONDS) ||
            addStatus != BluetoothGatt.GATT_SUCCESS
        ) {
            Log.w(TAG, "FIDO service was not added, status=$addStatus")
            stop()
            return false
        }
        Log.i(TAG, "FIDO GATT service started")
        return true
    }

    /** Closes every client session and the server. */
    fun stop() {
        clients.values.forEach { it.close() }
        clients.clear()
        server?.let { s ->
            runCatching { s.clearServices() }
            runCatching { s.close() }
        }
        server = null
        statusCharacteristic = null
    }

    /** [stop], and no session can be started again. */
    fun destroy() {
        stop()
        scope.cancel()
    }

    private fun buildService(): BluetoothGattService {
        val service = BluetoothGattService(FidoBle.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                FidoBle.CONTROL_POINT_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED_MITM
            )
        )
        val status = BluetoothGattCharacteristic(
            FidoBle.STATUS_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            0
        )
        status.addDescriptor(
            BluetoothGattDescriptor(
                FidoBle.CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED_MITM or
                    BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED_MITM
            )
        )
        service.addCharacteristic(status)
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                FidoBle.CONTROL_POINT_LENGTH_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED_MITM
            )
        )
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                FidoBle.SERVICE_REVISION_BITFIELD_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED_MITM or
                    BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED_MITM
            )
        )
        return service
    }

    private fun client(device: BluetoothDevice): Client =
        clients.getOrPut(device.address) { Client(device) }

    /** One connected FIDO client: its session, ATT MTU and notification queue. */
    private inner class Client(private val device: BluetoothDevice) {
        @Volatile
        var mtu = DEFAULT_ATT_MTU

        @Volatile
        var subscribed = false

        private val queue = ArrayDeque<ByteArray>()
        private var inFlight = false

        /**
         * fidoControlPointLength for this client, the one size for both
         * directions: what one ATT write or notification carries at its
         * negotiated MTU (23 until it negotiates), at most 512.
         */
        val controlPointLength: Int
            get() = (mtu - ATT_NOTIFY_OVERHEAD).coerceIn(MIN_FRAME_SIZE, FidoBle.CONTROL_POINT_LENGTH)

        val session = FidoBleSession(
            handler = handler,
            scope = scope,
            send = ::enqueue,
            maxFrameSize = { controlPointLength }
        )

        fun onWrite(frame: ByteArray) = synchronized(session) { session.onControlPointWrite(frame) }

        fun close() {
            synchronized(session) { session.close() }
            synchronized(queue) {
                queue.clear()
                inFlight = false
            }
        }

        /** Set once the queue overflowed; nothing more is queued on this connection. */
        private var overflowed = false

        /**
         * The one notification queue for this client, bounded at
         * [MAX_QUEUED_FRAMES]. A client that keeps writing (PING needs no
         * approval) while delivery stalls fills it; then the queued frames are
         * dropped, one ERROR (ERR_OTHER) frame is queued, and the session is
         * closed, so the client must reconnect.
         */
        private fun enqueue(frame: ByteArray) {
            val overflowNow = synchronized(queue) {
                if (!subscribed || overflowed) return
                val full = queue.size >= MAX_QUEUED_FRAMES
                if (full) {
                    overflowed = true
                    queue.clear()
                    queue.addLast(FidoBle.errorFrame(FidoBle.ERR_OTHER))
                } else {
                    queue.addLast(frame)
                }
                if (!inFlight) sendNext()
                full
            }
            if (overflowNow) {
                Log.w(TAG, "FIDO notification queue full; closing the session")
                synchronized(session) { session.close() }
            }
        }

        fun onSent() = synchronized(queue) {
            inFlight = false
            sendNext()
        }

        /** Caller holds the queue lock. */
        private fun sendNext() {
            val frame = queue.removeFirstOrNull() ?: return
            val s = server
            val characteristic = statusCharacteristic
            if (s == null || characteristic == null || !notify(s, characteristic, frame)) {
                queue.clear()
                return
            }
            inFlight = true
        }

        private fun notify(s: BluetoothGattServer, characteristic: BluetoothGattCharacteristic, frame: ByteArray) =
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    s.notifyCharacteristicChanged(device, characteristic, false, frame) == BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION")
                    characteristic.value = frame
                    @Suppress("DEPRECATION")
                    s.notifyCharacteristicChanged(device, characteristic, false)
                }
            } catch (e: Exception) {
                Log.w(TAG, "FIDO notification refused by the stack", e)
                false
            }
    }

    private inner class Callback(private val onServiceAdded: (Int) -> Unit) : BluetoothGattServerCallback() {

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (service.uuid == FidoBle.SERVICE_UUID) onServiceAdded(status)
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_DISCONNECTED) clients.remove(device.address)?.close()
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            client(device).mtu = mtu
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            clients[device.address]?.onSent()
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            val value = when (characteristic.uuid) {
                FidoBle.CONTROL_POINT_LENGTH_UUID -> client(device).controlPointLength.let {
                    byteArrayOf((it shr 8).toByte(), it.toByte())
                }
                FidoBle.SERVICE_REVISION_BITFIELD_UUID -> byteArrayOf(FidoBle.SERVICE_REVISION_FIDO2)
                else -> null
            }
            when {
                value == null -> respond(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, null)
                offset > value.size -> respond(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, null)
                else -> respond(device, requestId, BluetoothGatt.GATT_SUCCESS, value.copyOfRange(offset, value.size), offset)
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            val data = value ?: ByteArray(0)
            val status = when {
                preparedWrite || offset != 0 -> BluetoothGatt.GATT_INVALID_OFFSET
                characteristic.uuid == FidoBle.CONTROL_POINT_UUID ->
                    if (data.size > client(device).controlPointLength) {
                        BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH
                    } else {
                        BluetoothGatt.GATT_SUCCESS
                    }
                // Only FIDO2 is offered, so FIDO2 is the only revision a client may select.
                characteristic.uuid == FidoBle.SERVICE_REVISION_BITFIELD_UUID ->
                    if (data.size == 1 && data[0] == FidoBle.SERVICE_REVISION_FIDO2) {
                        BluetoothGatt.GATT_SUCCESS
                    } else {
                        BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
                    }
                else -> BluetoothGatt.GATT_WRITE_NOT_PERMITTED
            }
            if (responseNeeded) respond(device, requestId, status, null)
            if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == FidoBle.CONTROL_POINT_UUID) {
                client(device).onWrite(data)
            }
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor
        ) {
            if (descriptor.uuid != FidoBle.CCCD_UUID) {
                respond(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, null)
                return
            }
            val value = if (clients[device.address]?.subscribed == true) {
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            } else {
                BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
            }
            respond(device, requestId, BluetoothGatt.GATT_SUCCESS, value)
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            val ok = descriptor.uuid == FidoBle.CCCD_UUID && !preparedWrite && offset == 0 && value?.size == 2
            if (ok) client(device).subscribed = (value!![0].toInt() and 0x01) != 0
            if (responseNeeded) {
                respond(device, requestId, if (ok) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_WRITE_NOT_PERMITTED, null)
            }
        }

        private fun respond(device: BluetoothDevice, requestId: Int, status: Int, value: ByteArray?, offset: Int = 0) {
            runCatching { server?.sendResponse(device, requestId, status, offset, value) }
        }
    }

    private companion object {
        const val TAG = "FidoGattServer"
        const val DEFAULT_ATT_MTU = 23
        const val ATT_NOTIFY_OVERHEAD = 3
        const val MIN_FRAME_SIZE = 20

        /**
         * Frames queued for one client: the largest reply (1024 bytes) at the
         * smallest frame size is 54 frames, so this holds it with its
         * keepalives and some PING echoes to spare.
         */
        const val MAX_QUEUED_FRAMES = 96
        const val SERVICE_ADD_TIMEOUT_SECONDS = 5L
    }
}

/**
 * The lock screen a BLE prompt must reach: the phone is usually locked in a
 * pocket when a laptop asks it for a passkey.
 */
interface FidoLockScreen {
    val locked: Boolean

    /**
     * Posts the notification that opens [prompt], the launcher request's own
     * intent, under its notification [key]; [onTimeout] runs if it expires
     * unanswered.
     */
    fun post(operationType: String, rpId: String, key: String, prompt: Intent, onTimeout: () -> Unit)

    fun cancel(key: String)
}

/** The keyguard and the lock-screen notification every other xkey approval uses. */
class AndroidFidoLockScreen(private val context: Context) : FidoLockScreen {
    private val keyguard by lazy { context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager }
    private val notifications by lazy { BiometricNotificationHelper(context) }

    override val locked: Boolean
        get() = keyguard?.isKeyguardLocked == true

    override fun post(operationType: String, rpId: String, key: String, prompt: Intent, onTimeout: () -> Unit) =
        notifications.showBiometricRequiredNotification(
            operationType = operationType,
            rpName = rpId,
            requestId = key,
            onTimeout = onTimeout,
            promptIntent = prompt
        )

    override fun cancel(key: String) = notifications.cancelNotification(key)
}

/**
 * The phone's approval prompt for a BLE ceremony, through the same launcher
 * as every other xkey approval. TransparentBiometricActivity allows a strong
 * biometric only, so that is all [available] (getInfo's `uv`) checks: a phone
 * with only a PIN or password does not advertise verification it cannot do.
 *
 * Both prompts take the path the JSON-RPC approvals take on a locked phone:
 * shown over the lock screen, with a notification that opens the launched
 * request's own intent (so answering it completes this request), taken down
 * once the request ends.
 */
class BiometricFidoUserPrompt(
    private val context: Context,
    private val lockScreen: FidoLockScreen = AndroidFidoLockScreen(context),
    private val launcher: () -> BiometricActivityLauncher?
) : FidoUserPrompt {

    override val available: Boolean
        get() = launcher() != null && BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS

    override suspend fun verify(rpId: String, registering: Boolean): UserCheck {
        val l = launcher() ?: return UserCheck.UNAVAILABLE
        return try {
            onLockScreen(if (registering) "makeCredential" else "getAssertion", rpId) { locked, onLaunch ->
                l.requestAuthentication(
                    title = if (registering) "Create a passkey" else "Sign in with a passkey",
                    subtitle = rpId,
                    description = "Requested by a Bluetooth security key client",
                    showOnLockScreen = locked,
                    onLaunch = onLaunch
                )
            }
            UserCheck.VERIFIED
        } catch (e: UserCancelledException) {
            UserCheck.DECLINED
        } catch (e: BiometricLockoutException) {
            UserCheck.DECLINED
        } catch (e: BiometricException) {
            if (e.errorCode in UNAVAILABLE_CODES) UserCheck.UNAVAILABLE else UserCheck.DECLINED
        } catch (e: IllegalStateException) {
            // The launcher is not registered: no prompt can be shown.
            UserCheck.UNAVAILABLE
        }
    }

    /**
     * The credential provider's key-bound prompt: CryptoSigningActivity signs
     * [signedData] with SHA256withECDSA inside Keystore once the prompt
     * unlocks that one signature.
     */
    override suspend fun signWithKey(keyId: String, signedData: ByteArray, rpId: String): ByteArray {
        val l = launcher() ?: throw IllegalStateException("No prompt launcher")
        return onLockScreen("getAssertion", rpId) { locked, onLaunch ->
            l.requestCryptoSignature(
                credentialId = keyId,
                dataHash = signedData,
                title = "Sign in with a passkey",
                subtitle = rpId,
                showOnLockScreen = locked,
                onLaunch = onLaunch
            )
        }
    }

    /**
     * The one lock-screen path for both prompts, as RequestHandler's own
     * notifications: over the lock screen when the phone is locked; on
     * launch, a notification that opens that request's intent and, should it
     * expire with the prompt never up, settles the request; every
     * notification this prompt posted is taken down when it ends, however it
     * ends.
     */
    private suspend fun <T> onLockScreen(
        operationType: String,
        rpId: String,
        prompt: suspend (locked: Boolean, onLaunch: (String, Intent) -> Unit) -> T
    ): T {
        val posted = ConcurrentLinkedQueue<String>()
        val onLaunch: (String, Intent) -> Unit = { key, intent ->
            if (lockScreen.locked) {
                posted.add(key)
                lockScreen.post(operationType, rpId, key, intent) { launcher()?.expireUnshown(key) }
            }
        }
        try {
            return prompt(lockScreen.locked, onLaunch)
        } finally {
            while (true) lockScreen.cancel(posted.poll() ?: break)
        }
    }

    private companion object {
        val UNAVAILABLE_CODES = setOf(
            androidx.biometric.BiometricPrompt.ERROR_HW_UNAVAILABLE,
            androidx.biometric.BiometricPrompt.ERROR_HW_NOT_PRESENT,
            androidx.biometric.BiometricPrompt.ERROR_NO_BIOMETRICS,
            androidx.biometric.BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL
        )
    }
}
