/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ble

import android.content.Context
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import org.json.JSONObject
import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn

/**
 * In-process loopback for the BLE responder stack.
 *
 * An emulator has no Bluetooth radio and no second device, so [GattServer]
 * cannot be reached the way a desktop reaches it. Everything *below* the radio
 * can still be driven for real, and that is what this harness does:
 *
 * ```
 *  NoiseInitiatorSession  ->  Fragmenter/FragmentReassembler  ->  NoiseSession
 *      (BleClient.kt,             (the real 7-byte BLE            (GattServer's
 *       the desktop side)          fragment protocol)              responder)
 *                                                                     |
 *                                                       GattServer.interceptOrRoute
 *                                                                     |
 *                                            BidirectionalMessageRouter -> RequestHandler
 * ```
 *
 * The seam is [GattServer.interceptOrRoute] — private, reached by reflection.
 * It is the exact function `handleApplicationMessage` calls with the decrypted
 * plaintext, and its return value is exactly what that function encrypts and
 * puts on the wire. Feeding it real Noise plaintext and encrypting its reply
 * therefore exercises the production request path byte for byte; only
 * `BluetoothGattServer.notifyCharacteristicChanged` is absent.
 *
 * What this harness deliberately does NOT cover, because the only outlet for
 * those paths is `sendResponse`, which returns early without a real
 * `BluetoothGattServer`:
 *  - `handleIdentityExchange` (its ack is written to the radio),
 *  - `handleHandshakeMessage` (msg2 is written to the radio),
 *  - MTU negotiation, CCCD subscription, and connection state transitions.
 *
 * The handshake is therefore replayed here against the same [NoiseSession] the
 * server would have built, and the authenticated identity is installed exactly
 * as `handleHandshakeMessage` installs it — see [connect].
 */
class BleLoopbackHarness(
    private val context: Context,
    val pairedDeviceRepository: PairedDeviceRepository = PairedDeviceRepository(context),
    private val pairingCallback: PairingConfirmationCallback? = null,
    /** Payload budget per fragment; 237 is MTU 247 minus ATT and header overhead. */
    private val fragmentPayloadSize: Int = Fragmenter.DEFAULT_PAYLOAD_SIZE
) {

    /** The real handler the server dispatches to. */
    val requestHandler: RequestHandler = RequestHandler(
        context = context,
        keystoreManager = KeystoreManager(context),
        biometricLauncher = null,
        sessionAuthManager = SessionAuthManager(),
        pairedDeviceRepository = pairedDeviceRepository
    ).apply {
        // No UI is attached, so gate nothing on biometrics — the same posture
        // the TCP conformance suite uses.
        updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    /** The system under test. */
    val server: GattServer = GattServer(
        context = context,
        requestHandler = requestHandler,
        messageRouter = BidirectionalMessageRouter(requestHandler),
        pairingCallback = pairingCallback,
        pairedDeviceRepository = pairedDeviceRepository
    )

    /** The desktop side: the app's own initiator implementation. */
    private lateinit var initiator: NoiseInitiatorSession

    /** The phone side: the responder [GattServer] would have created. */
    private lateinit var responder: NoiseSession

    /** One reassembler per direction, long-lived like the server's. */
    private val towardsPhone = FragmentReassembler()
    private val towardsDesktop = FragmentReassembler()

    private val nextId = AtomicLong(1)

    /** Hex of the initiator's static public key; valid after [connect]. */
    lateinit var publicKeyHex: String
        private set

    /** The peer identity the server trusts, as taken from the Noise transcript. */
    val authenticatedPeerKeyHex: String?
        get() = readField(server, "authenticatedPeerKeyHex") as String?

    /** Whether the server considers this session paired. */
    val isPairingConfirmed: Boolean
        get() = readField(server, "pairingConfirmed") as Boolean

    /**
     * Runs the identity exchange and the Noise XX handshake in memory, then
     * installs the resulting session into the server the way
     * `handleHandshakeMessage` does.
     *
     * @param knownDeviceFingerprint When non-null, simulates the "known device"
     *   identity ack: both sides bind the handshake to
     *   `SHA256(initiator_pub || fingerprint || "xkey-v1")`. The responder
     *   prologue is computed by the server's own private helper so a divergence
     *   between the two implementations shows up as a failed handshake.
     * @param initiatorFingerprintOverride Lets a test give the initiator a
     *   different fingerprint than the responder, to prove the binding is real.
     */
    suspend fun connect(
        knownDeviceFingerprint: ByteArray? = null,
        initiatorFingerprintOverride: ByteArray? = null
    ) {
        val staticKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        initiator = NoiseInitiatorSession(staticKey)
        publicKeyHex = initiator.getLocalStaticPublicKey().toHex()

        responder = NoiseSession()
        responder.loadStaticKey(context)

        if (knownDeviceFingerprint != null) {
            val initiatorFingerprint = initiatorFingerprintOverride ?: knownDeviceFingerprint
            initiator.processIdentityAck(byteArrayOf(0x01) + initiatorFingerprint)

            val prologue = computePrologue(
                initiator.getLocalStaticPublicKey(),
                knownDeviceFingerprint
            )
            responder.setPrologue(prologue)
            responder.reset()
        }

        val msg1 = deliverToPhone(initiator.createHandshakeMessage1())
        val msg2 = responder.processHandshakeMessage(msg1)
            ?: throw IllegalStateException("responder produced no handshake message 2")
        initiator.processHandshakeMessage2(deliverToDesktop(msg2))

        val msg3 = deliverToPhone(initiator.createHandshakeMessage3())
        val trailing = responder.processHandshakeMessage(msg3)
        check(trailing == null) { "responder replied to handshake message 3" }
        initiator.finalizeHandshake()

        check(responder.isHandshakeComplete()) { "responder handshake did not complete" }
        check(initiator.isHandshakeComplete()) { "initiator handshake did not complete" }

        // Mirrors GattServer.handleHandshakeMessage: the session becomes the
        // server's, and the identity it trusts comes from the transcript.
        writeField(server, "noiseSession", responder)
        writeField(
            server,
            "authenticatedPeerKeyHex",
            responder.getRemoteStaticKey()?.toHex()
        )
    }

    /** The static key the responder authenticated for this peer. */
    fun responderViewOfPeerKey(): ByteArray? = responder.getRemoteStaticKey()

    /**
     * Sends `pairing.confirm` under this peer's own authenticated key, the way
     * the desktop does immediately after the handshake.
     */
    suspend fun confirmPairing(deviceName: String = "BleLoopbackTest"): JSONObject =
        call(
            "pairing.confirm",
            JSONObject().put("deviceName", deviceName).put("publicKeyHex", publicKeyHex)
        )

    /**
     * Sends a JSON-RPC request through the encrypted, fragmented loopback and
     * returns the `result` object.
     *
     * @throws BleProtocolError if the phone answers with an error.
     */
    suspend fun call(method: String, params: JSONObject? = null): JSONObject {
        val json = rpc(method, params)
            ?: throw IOException("$method produced no response")
        json.optJSONObject("error")?.let {
            throw BleProtocolError(method, it.optInt("code"), it.optString("message"))
        }
        return json.optJSONObject("result") ?: JSONObject()
    }

    /** Like [call] but returns the error instead of throwing; null on success. */
    suspend fun callExpectingError(method: String, params: JSONObject? = null): BleProtocolError? =
        try {
            call(method, params)
            null
        } catch (e: BleProtocolError) {
            e
        }

    /** Sends a request and returns the raw response envelope, or null if the server sent nothing. */
    suspend fun rpc(method: String, params: JSONObject? = null): JSONObject? {
        val request = JSONObject()
            .put("id", nextId.getAndIncrement())
            .put("method", method)
        if (params != null) request.put("params", params)

        val response = exchange(request.toString().toByteArray(Charsets.UTF_8)) ?: return null
        return JSONObject(String(response, Charsets.UTF_8))
    }

    /**
     * Encrypts [plaintext], fragments it, hands it to the server's request path
     * and brings the reply back the same way. Returns null when the server
     * chose to send nothing.
     */
    suspend fun exchange(plaintext: ByteArray): ByteArray? {
        val delivered = deliverToPhone(initiator.encrypt(plaintext))
        val decrypted = responder.decrypt(delivered)

        val response = interceptOrRoute(decrypted) ?: return null

        return initiator.decrypt(deliverToDesktop(responder.encrypt(response)))
    }

    /** Releases the server's coroutine scope. */
    fun close() {
        server.destroy()
    }

    // -----------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------

    private fun deliverToPhone(message: ByteArray): ByteArray =
        transfer(message, towardsPhone)

    private fun deliverToDesktop(message: ByteArray): ByteArray =
        transfer(message, towardsDesktop)

    /** Fragments [message] at the configured MTU and reassembles it, as BLE does. */
    private fun transfer(message: ByteArray, reassembler: FragmentReassembler): ByteArray {
        val fragments = Fragmenter(fragmentPayloadSize).fragment(message)
        check(fragments.isNotEmpty()) { "fragmenter produced nothing for ${message.size} bytes" }

        var complete: ByteArray? = null
        for (fragment in fragments) {
            check(fragment.size <= FragmentReassembler.HEADER_SIZE + fragmentPayloadSize) {
                "fragment exceeds the MTU budget"
            }
            reassembler.addFragment(fragment)?.let { complete = it }
        }
        return complete ?: throw IllegalStateException("message never reassembled")
    }

    // -----------------------------------------------------------------
    // Reflection into GattServer
    // -----------------------------------------------------------------

    /** Calls the private `interceptOrRoute`, the server's request seam. */
    private suspend fun interceptOrRoute(plaintext: ByteArray): ByteArray? =
        callSuspend(server, interceptOrRouteMethod, plaintext) as ByteArray?

    /** Calls the private prologue helper so both sides use the server's formula. */
    private fun computePrologue(publicKey: ByteArray, fingerprint: ByteArray): ByteArray =
        try {
            prologueMethod.invoke(server, publicKey, fingerprint) as ByteArray
        } catch (e: InvocationTargetException) {
            throw e.cause ?: e
        }

    private companion object {
        val interceptOrRouteMethod: Method = declaredMethod(
            "interceptOrRoute", ByteArray::class.java, Continuation::class.java
        )

        val prologueMethod: Method = declaredMethod(
            "computePrologueFromIdentity", ByteArray::class.java, ByteArray::class.java
        )

        fun declaredMethod(name: String, vararg types: Class<*>): Method = try {
            GattServer::class.java.getDeclaredMethod(name, *types).apply { isAccessible = true }
        } catch (e: NoSuchMethodException) {
            throw AssertionError(
                "GattServer.$name is the seam these BLE tests drive; if it was " +
                    "renamed or resharped, update BleLoopbackHarness",
                e
            )
        }

        fun readField(target: Any, name: String): Any? = fieldOf(target, name).get(target)

        fun writeField(target: Any, name: String, value: Any?) = fieldOf(target, name).set(target, value)

        fun fieldOf(target: Any, name: String) = try {
            target.javaClass.getDeclaredField(name).apply { isAccessible = true }
        } catch (e: NoSuchFieldException) {
            throw AssertionError("${target.javaClass.simpleName}.$name no longer exists", e)
        }

        /**
         * Invokes a private `suspend` method reflectively. A suspend function
         * compiles to a method with a trailing [Continuation]; passing the
         * unintercepted continuation and returning whatever `invoke` produces is
         * how the compiler itself calls one.
         */
        suspend fun callSuspend(target: Any, method: Method, vararg args: Any?): Any? =
            suspendCoroutineUninterceptedOrReturn { continuation ->
                try {
                    method.invoke(target, *(args.toList() + continuation).toTypedArray())
                } catch (e: InvocationTargetException) {
                    throw e.cause ?: e
                }
            }

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    }
}

/** An error response returned by the phone, carrying the protocol error code. */
class BleProtocolError(
    method: String,
    val code: Int,
    val protocolMessage: String
) : IOException("$method failed: [$code] $protocolMessage")
