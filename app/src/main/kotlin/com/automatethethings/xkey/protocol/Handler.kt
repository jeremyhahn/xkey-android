package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ca.DeviceIdentity
import com.automatethethings.xkey.ca.DeviceIdentityException
import org.bouncycastle.asn1.x500.X500Name
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.credential.UserVerificationCompliance
import com.automatethethings.xkey.credential.UserVerificationRequiredException
import com.automatethethings.xkey.credential.UvRequirement
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.BiometricUnavailableException
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.BiometricLockoutException
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.DecryptionException
import com.automatethethings.xkey.crypto.DeviceAttestationKey
import com.automatethethings.xkey.crypto.ECDHException
import com.automatethethings.xkey.crypto.EncryptionException
import com.automatethethings.xkey.crypto.HMACException
import com.automatethethings.xkey.crypto.KeyGenerationException
import com.automatethethings.xkey.crypto.KeyInvalidatedException
import com.automatethethings.xkey.crypto.KeyNotFoundException
import com.automatethethings.xkey.crypto.KeyInfoUnavailableException
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.KeystoreUserVerificationKey
import com.automatethethings.xkey.crypto.SigningException
import com.automatethethings.xkey.crypto.StrongBoxUnavailableException
import com.automatethethings.xkey.crypto.UnsupportedAlgorithmException
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.crypto.UserVerificationKey
import com.automatethethings.xkey.crypto.UserVerificationPrompt
import com.automatethethings.xkey.crypto.XKeyCryptoException
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.settings.UserVerificationPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import org.json.JSONObject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.lang.ref.WeakReference
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import java.util.Base64
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.pin.PinHasher
import com.automatethethings.xkey.pin.PinType
import com.automatethethings.xkey.pin.PinException
import com.automatethethings.xkey.pin.PinLockedException
import com.automatethethings.xkey.pin.PinRequiredException
import com.automatethethings.xkey.password.PasswordStoreLockedException
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.settings.PinSettingsRepository

/**
 * Interface for sending messages to the connected laptop.
 */
interface MessageSender {
    /**
     * Sends an encrypted message to the laptop.
     * Fire-and-forget - does not wait for response.
     */
    suspend fun sendMessage(message: ByteArray)
}

/**
 * Handles incoming xKey protocol requests.
 *
 * This class dispatches incoming requests to the appropriate handlers and
 * coordinates with the KeystoreManager for cryptographic operations. It supports
 * configurable biometric authentication through [BiometricSettingsData] and
 * [SessionAuthManager].
 *
 * Thread safety: This class is thread-safe. All handlers are suspending
 * functions that can be called from any coroutine context. Settings and session
 * state are managed with volatile fields for visibility guarantees.
 *
 * Usage:
 * ```kotlin
 * val handler = RequestHandler(
 *     context = applicationContext,
 *     keystoreManager = keystoreManager,
 *     biometricLauncher = biometricLauncher,
 *     sessionAuthManager = sessionAuthManager
 * )
 *
 * // Update settings when they change
 * handler.updateSettings(newSettings)
 *
 * // Set session ID when BLE connection is established
 * handler.setSessionId(deviceAddress)
 *
 * // Handle requests
 * val response = handler.handleRequest(request)
 * ```
 *
 * @param context Application context for device capability checks.
 * @param keystoreManager Manager for cryptographic key operations.
 * @param biometricLauncher Optional launcher for biometric authentication from services.
 * @param sessionAuthManager Optional manager for session-based authentication state.
 * @param userVerificationKey The key `local.verifyUser` signs with; null for
 *   the Keystore one. Tests supply a software key.
 * @param userVerificationPrompt The biometric prompt that unlocks that key for
 *   one signature; null for the activity or [BiometricHelper] prompt.
 */
class RequestHandler(
    private val context: Context,
    private val keystoreManager: KeystoreManager,
    private val biometricLauncher: BiometricActivityLauncher?,
    private val sessionAuthManager: SessionAuthManager?,
    private val pairedDeviceRepository: PairedDeviceRepository? = null,
    private val pinManager: PinManager? = null,
    private val pivKeyManager: PivKeyManager? = null,
    userVerificationKey: UserVerificationKey? = null,
    private val userVerificationPrompt: UserVerificationPrompt? = null
) {
    companion object {
        private const val TAG = "RequestHandler"

        // Protocol version
        private const val PROTOCOL_VERSION = "1.0.0"

        // Method names
        private const val METHOD_GENERATE_KEY = "generateKey"
        private const val METHOD_SIGN = "sign"
        private const val METHOD_DELETE_KEY = "deleteKey"
        private const val METHOD_LOAD_KEY = "loadKey"
        private const val METHOD_GET_INFO = "getInfo"
        private const val METHOD_PING = "ping"
        private const val METHOD_LIST_KEYS = "listKeys"

        // Default session duration for PER_SESSION mode (5 minutes)
        private const val DEFAULT_SESSION_DURATION_SECONDS = 300

        /** Android Key Attestation extension OID. */
        private const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /** Map of attestation security level integer values to names. */
        private val securityLevelNames = mapOf(
            0 to "software",
            1 to "tee",
            2 to "strongbox"
        )

        /**
         * The context a transport installs around one request that arrived on a
         * connection it *serves*: that connection's channel binding and
         * authenticated peer, for as long as the request runs.
         *
         * One handler serves BLE, TCP and USB at once, so nothing about the
         * session a request arrived on may be read from handler-wide state: a
         * second transport's handshake would overwrite it, and a verifyUser or
         * attestDevice answer would then commit to the other desktop's channel.
         * Unlike a [handleRawRequest] caller session, a served
         * connection is the one the installed message sender reaches.
         *
         * @param binding the binding of the connection the request arrived on
         * @param peerPublicKeyHex that connection's authenticated peer static key
         */
        fun servedConnection(binding: SessionBindingProvider, peerPublicKeyHex: String?): CoroutineContext =
            CallerSession(binding, peerPublicKeyHex, served = true)
    }

    // Unified key storage DAO
    private val keyDao: KeyDao = XKeyDatabase.getInstance(context).keyDao()

    // Per-key sharing policy DAO
    private val keySharingPolicyDao: KeySharingPolicyDao = XKeyDatabase.getInstance(context).keySharingPolicyDao()

    // Weak reference to activity for biometric prompts
    private var activityRef: WeakReference<FragmentActivity>? = null

    // BiometricHelper instance (created when activity is set)
    private var biometricHelper: BiometricHelper? = null

    // BiometricNotificationHelper for lock screen notifications
    private val biometricNotificationHelper = BiometricNotificationHelper(context)

    // KeyguardManager to check if screen is locked
    private val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    /**
     * Current biometric settings controlling authentication behavior.
     *
     * Updated via [updateSettings] when user preferences change.
     */
    @Volatile
    private var currentSettings: BiometricSettingsData = BiometricSettingsData()

    /**
     * Current BLE session identifier (typically device address).
     *
     * Updated via [setSessionId] when BLE connection state changes.
     */
    @Volatile
    private var currentSessionId: String? = null

    /**
     * Public key hex of the currently connected device.
     *
     * Updated via [setConnectedDevicePublicKeyHex] after pairing confirmation.
     * Used for PAIRED_DEVICES_SKIP attestation biometric policy.
     */
    @Volatile
    private var connectedDevicePublicKeyHex: String? = null

    /**
     * This device's persistent attested identity (go-xkms#129).
     *
     * Built from nothing but the Keystore, so it is created here rather than
     * threaded through every construction site — the same reasoning as
     * [deviceIdentity]. Lazy because minting the key is a hardware operation
     * that must not run until an attestation is actually asked for.
     */
    private val deviceAttestationKey by lazy { DeviceAttestationKey() }

    /**
     * The key `local.verifyUser` signs with, never the DAK. Lazy
     * for the same reason as [deviceAttestationKey].
     */
    private val uvk: UserVerificationKey by lazy {
        userVerificationKey ?: KeystoreUserVerificationKey(context)
    }

    /**
     * Message sender for sending notifications to the connected laptop.
     *
     * Updated via [setMessageSender] when BLE connection state changes.
     */
    @Volatile
    private var messageSender: MessageSender? = null

    // Handler dispatch map for O(1) lookup
    /**
     * This device's standing as an enrollee. Built from [context] rather than
     * injected: it owns only Keystore aliases and its own preferences file, so
     * threading it through every construction site would buy nothing.
     */
    private val deviceIdentity by lazy { DeviceIdentity(context) }

    private val handlers: Map<String, suspend (Request) -> Response> = mapOf(
        // Original methods
        METHOD_GENERATE_KEY to ::handleGenerateKey,
        METHOD_SIGN to ::handleSign,
        METHOD_DELETE_KEY to ::handleDeleteKey,
        METHOD_LOAD_KEY to ::handleLoadKey,
        METHOD_GET_INFO to ::handleGetInfo,
        METHOD_PING to ::handlePing,
        METHOD_LIST_KEYS to ::handleListKeys,
        // Extended local.* methods
        MethodNames.LOCAL_GENERATE_KEY to ::handleLocalGenerateKey,
        MethodNames.LOCAL_SIGN to ::handleLocalSign,
        MethodNames.LOCAL_DECRYPT to ::handleLocalDecrypt,
        MethodNames.LOCAL_SYMMETRIC_ENCRYPT to ::handleLocalSymmetricEncrypt,
        MethodNames.LOCAL_SYMMETRIC_DECRYPT to ::handleLocalSymmetricDecrypt,
        MethodNames.LOCAL_HMAC to ::handleLocalHMAC,
        MethodNames.LOCAL_ECDH to ::handleLocalECDH,
        MethodNames.LOCAL_GET_PUBLIC_KEY to ::handleLocalGetPublicKey,
        MethodNames.LOCAL_LIST_KEYS to ::handleLocalListKeys,
        MethodNames.LOCAL_GET_KEY_INFO to ::handleLocalGetKeyInfo,
        MethodNames.LOCAL_DELETE_KEY to ::handleLocalDeleteKey,
        MethodNames.LOCAL_SET_KEY_POLICY to ::handleLocalSetKeyPolicy,
        MethodNames.LOCAL_ATTEST_KEY to ::handleLocalAttestKey,
        MethodNames.LOCAL_ATTEST_DEVICE to ::handleLocalAttestDevice,
        MethodNames.LOCAL_VERIFY_USER to ::handleLocalVerifyUser,
        // Device enrollment, this phone as the enrollee.
        MethodNames.LOCAL_GET_DEVICE_ENROLLMENT_REQUEST to ::handleLocalGetDeviceEnrollmentRequest,
        MethodNames.LOCAL_STORE_DEVICE_CREDENTIAL to ::handleLocalStoreDeviceCredential,
        // The TCG family is TPM2-only and this platform has no TPM. Each is
        // answered plainly rather than left to fall through as METHOD_NOT_FOUND,
        // which would read as a version mismatch the caller should retry past.
        MethodNames.LOCAL_GET_TCG_CSR_IDEVID to ::refuseTpmOnlyMethod,
        MethodNames.LOCAL_ACTIVATE_CREDENTIAL to ::refuseTpmOnlyMethod,
        MethodNames.LOCAL_GET_ATTESTATION_QUOTE to ::refuseTpmOnlyMethod,
        MethodNames.LOCAL_GET_IAK_PUBLIC_KEY to ::refuseTpmOnlyMethod,
        MethodNames.LOCAL_GET_CAPABILITIES to ::handleLocalGetCapabilities,
        MethodNames.LOCAL_LIST_FIDO2_CREDENTIALS to ::handleLocalListFido2Credentials,
        MethodNames.LOCAL_SIGN_FIDO2_ASSERTION to ::handleLocalSignFido2Assertion,
        // OATH
        MethodNames.LOCAL_OATH_LIST to ::handleOathList,
        MethodNames.LOCAL_OATH_GENERATE to ::handleOathGenerate,
        MethodNames.LOCAL_OATH_ADD to ::handleOathAdd,
        MethodNames.LOCAL_OATH_REMOVE to ::handleOathRemove,
        // Co-signing
        MethodNames.COSIGN_REQUEST to ::handleCosignRequest,
        MethodNames.COSIGN_RESPONSE to ::handleCosignResponse,
        // PIN management
        MethodNames.LOCAL_PIN_STATUS to ::handlePinStatus,
        MethodNames.LOCAL_PIN_VERIFY to ::handlePinVerify,
        MethodNames.LOCAL_PIN_SET to ::handlePinSet,
        MethodNames.LOCAL_PIN_CHANGE to ::handlePinChange,
        MethodNames.LOCAL_PIN_RESET_LOCKOUT to ::handlePinResetLockout,
        // PIV
        MethodNames.LOCAL_PIV_LIST_SLOTS to ::handlePivListSlots,
        MethodNames.LOCAL_PIV_GENERATE_KEY to ::handlePivGenerateKey,
        MethodNames.LOCAL_PIV_IMPORT_CERT to ::handlePivImportCert,
        MethodNames.LOCAL_PIV_SIGN to ::handlePivSign,
        MethodNames.LOCAL_PIV_GET_CERT to ::handlePivGetCert,
        // Sync (laptop <-> phone)
        MethodNames.LOCAL_SYNC_TRUST_STORE to ::handleSyncTrustStore,
        MethodNames.LOCAL_SYNC_OATH to ::handleSyncOATH,
        MethodNames.LOCAL_SYNC_PASSWORDS to ::handleSyncPasswords,
        MethodNames.LOCAL_SYNC_STATUS to ::handleSyncStatus,
        // Backup
        MethodNames.LOCAL_CREATE_BACKUP to ::handleCreateBackup,
        MethodNames.LOCAL_RESTORE_BACKUP to ::handleRestoreBackup,
        // Key sharing
        MethodNames.LOCAL_SHARE_PUBLIC_KEY to ::handleSharePublicKey,
        MethodNames.LOCAL_SHARE_SYMMETRIC to ::handleShareSymmetric,
        MethodNames.LOCAL_IMPORT_SHARED_KEY to ::handleImportSharedKey
    )

    /**
     * Updates the biometric settings used for authentication decisions.
     *
     * This should be called whenever the user changes their biometric preferences
     * in the settings UI. The new settings take effect immediately for subsequent
     * operations.
     *
     * @param settings The new biometric settings to apply.
     */
    fun updateSettings(settings: BiometricSettingsData) {
        currentSettings = settings
        Log.d(TAG, "Settings updated: uvPolicy=${settings.uvPolicy}, authMode=${settings.authMode}")
    }

    /**
     * Sets the current BLE session identifier.
     *
     * This should be called when a BLE connection is established (with the device
     * address) or disconnected (with null). The session ID is used by
     * [SessionAuthManager] for PER_SESSION authentication mode.
     *
     * @param sessionId The BLE device address, or null if disconnected.
     */
    fun setSessionId(sessionId: String?) {
        currentSessionId = sessionId
        if (sessionId == null) {
            sessionAuthManager?.clearSession()
            connectedDevicePublicKeyHex = null
        }
        Log.d(TAG, "Session ID updated: $sessionId")
    }

    /**
     * Sets the public key hex of the currently connected device.
     *
     * This should be called after successful pairing confirmation so that the
     * PAIRED_DEVICES_SKIP attestation policy can check if the device is known.
     *
     * @param publicKeyHex The hex-encoded Noise static public key, or null on disconnect.
     */
    fun setConnectedDevicePublicKeyHex(publicKeyHex: String?) {
        connectedDevicePublicKeyHex = publicKeyHex
        Log.d(TAG, "Connected device public key updated: ${publicKeyHex?.take(16) ?: "null"}")
    }

    /**
     * Returns the currently connected device's Noise public key, or null if not connected.
     */
    fun getConnectedDevicePublicKeyHex(): String? = connectedDevicePublicKeyHex

    /**
     * Sets the message sender for sending notifications to the connected laptop.
     *
     * This should be called when a BLE connection is established (with sender)
     * or disconnected (with null).
     *
     * @param sender The message sender, or null on disconnect.
     */
    fun setMessageSender(sender: MessageSender?) {
        messageSender = sender
        Log.d(TAG, "Message sender updated: ${if (sender != null) "set" else "cleared"}")
    }

    /**
     * Sets the activity for biometric prompts.
     *
     * Must be called when the activity is available, before any sign requests
     * that require crypto-bound biometric authentication.
     */
    fun setActivity(activity: FragmentActivity?) {
        activityRef = if (activity != null) WeakReference(activity) else null
        biometricHelper = if (activity != null) BiometricHelper(activity) else null
    }

    /**
     * Handles a raw request that arrived on a session this phone *opened* — the
     * phone-initiated direction, where the desktop sends `local.attestDevice`
     * right after the handshake and refuses the session without a verified answer.
     *
     * The same dispatch as [handleRawRequest]; only the session differs. For
     * the duration of this call [binding] and [peerPublicKeyHex] describe the
     * session the request arrived on, as [servedConnection] does for a session
     * this phone serves. Nothing global changes, so a concurrent responder
     * session keeps its own.
     *
     * @param binding the channel binding of the session [data] arrived on
     * @param peerPublicKeyHex that session's authenticated peer static key
     */
    suspend fun handleRawRequest(
        data: ByteArray,
        binding: SessionBindingProvider,
        peerPublicKeyHex: String?,
    ): ByteArray = withContext(CallerSession(binding, peerPublicKeyHex, served = false)) {
        handleRawRequest(data)
    }

    /**
     * The session a request arrived on, carried in the coroutine context so it
     * reaches the handler without a second, forked dispatch path: a session
     * this phone opened ([handleRawRequest] with a binding) or one it serves
     * ([servedConnection]).
     *
     * @property served whether this phone serves the session, which is then
     *   the one the installed message sender reaches
     */
    private class CallerSession(
        val binding: SessionBindingProvider,
        val peerPublicKeyHex: String?,
        val served: Boolean,
    ) : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<CallerSession>
    }

    /**
     * Handles a raw request (JSON bytes).
     *
     * @param data Raw JSON request data
     * @return Raw JSON response data
     */
    suspend fun handleRawRequest(data: ByteArray): ByteArray {
        val json = String(data, Charsets.UTF_8)
        return try {
            val request = Request.fromJson(json)
            val response = handleRequest(request)
            response.toJson()
        } catch (e: ProtocolException) {
            // A request that does not parse still echoes its generation when
            // the text carries one where it can be read.
            Log.e(TAG, "Protocol error: ${e.message}")
            Response.error(
                0, e.errorCode, e.message ?: "Protocol error", generation = readGeneration(json)
            ).toJson()
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error", e)
            Response.error(
                0, ErrorCodes.INTERNAL_ERROR, "Internal error: ${e.message}", generation = readGeneration(json)
            ).toJson()
        }
    }

    /**
     * Creates an error response as JSON bytes.
     */
    fun createErrorResponse(id: Long, code: Int, message: String): ByteArray {
        return Response.error(id, code, message).toJson()
    }

    /**
     * Handles a parsed request.
     *
     * Every answer carries the request's `generation` (go-xkms#128), copied
     * here rather than by each handler, so no method can drop it.
     *
     * @param request The parsed request
     * @return Response to the request
     */
    suspend fun handleRequest(request: Request): Response =
        dispatch(request).copy(generation = request.generation)

    private suspend fun dispatch(request: Request): Response {
        Log.d(TAG, "Handling request: id=${request.id}, method=${request.method}")

        val handler = handlers[request.method]
        if (handler == null) {
            Log.w(TAG, "Unknown method: ${request.method}")
            return Response.error(
                request.id,
                ErrorCodes.METHOD_NOT_FOUND,
                "Unknown method: ${request.method}"
            )
        }

        return try {
            handler(request)
        } catch (e: ProtocolException) {
            Log.e(TAG, "Handler error: ${e.message}")
            Response.error(request.id, e.errorCode, e.message ?: "Handler error")
        } catch (e: KeyNotFoundException) {
            Log.e(TAG, "Key not found: ${e.message}")
            Response.error(request.id, ErrorCodes.KEY_NOT_FOUND, e.message ?: "Key not found")
        } catch (e: KeyGenerationException) {
            Log.e(TAG, "Key generation failed: ${e.message}")
            Response.error(request.id, ErrorCodes.KEY_GENERATION_FAILED, e.message ?: "Key generation failed")
        } catch (e: SigningException) {
            Log.e(TAG, "Signing failed: ${e.message}")
            Response.error(request.id, ErrorCodes.SIGNING_FAILED, e.message ?: "Signing failed")
        } catch (e: UserCancelledException) {
            Log.d(TAG, "User cancelled: ${e.message}")
            Response.error(request.id, ErrorCodes.USER_CANCELLED, e.message ?: "User cancelled")
        } catch (e: BiometricLockoutException) {
            Log.e(TAG, "Biometric lockout: ${e.message}")
            Response.error(request.id, ErrorCodes.BIOMETRIC_LOCKOUT, e.message ?: "Biometric lockout")
        } catch (e: BiometricRequiredException) {
            Log.e(TAG, "Biometric required: ${e.message}")
            Response.error(request.id, ErrorCodes.BIOMETRIC_FAILED, e.message ?: "Biometric authentication required")
        } catch (e: BiometricException) {
            Log.e(TAG, "Biometric error: ${e.message}")
            Response.error(request.id, ErrorCodes.BIOMETRIC_FAILED, e.message ?: "Biometric authentication failed")
        } catch (e: BiometricUnavailableException) {
            // Its own type, not a BiometricException, so it fell through to the
            // generic handler: a phone with nothing enrolled answered
            // INTERNAL_ERROR and the desktop could not tell "enrol a biometric"
            // from "the phone is broken". This is the commonest real failure.
            Log.e(TAG, "Biometric unavailable: ${e.message}")
            Response.error(
                request.id,
                ErrorCodes.BIOMETRIC_FAILED,
                e.message ?: "Biometric authentication unavailable"
            )
        } catch (e: StrongBoxUnavailableException) {
            Log.e(TAG, "StrongBox unavailable: ${e.message}")
            Response.error(request.id, ErrorCodes.STRONGBOX_UNAVAILABLE, e.message ?: "StrongBox unavailable")
        } catch (e: DecryptionException) {
            Log.e(TAG, "Decryption failed: ${e.message}")
            Response.error(request.id, ErrorCodes.DECRYPTION_FAILED, e.message ?: "Decryption failed")
        } catch (e: EncryptionException) {
            Log.e(TAG, "Encryption failed: ${e.message}")
            Response.error(request.id, ErrorCodes.ENCRYPTION_FAILED, e.message ?: "Encryption failed")
        } catch (e: HMACException) {
            Log.e(TAG, "HMAC failed: ${e.message}")
            Response.error(request.id, ErrorCodes.HMAC_FAILED, e.message ?: "HMAC computation failed")
        } catch (e: ECDHException) {
            Log.e(TAG, "ECDH failed: ${e.message}")
            Response.error(request.id, ErrorCodes.ECDH_FAILED, e.message ?: "ECDH key agreement failed")
        } catch (e: UnsupportedAlgorithmException) {
            Log.e(TAG, "Unsupported algorithm: ${e.message}")
            Response.error(request.id, ErrorCodes.INVALID_ALGORITHM, e.message ?: "Unsupported algorithm")
        } catch (e: UserVerificationRequiredException) {
            // local.signFido2Assertion refused a ceremony the peer required
            // user verification for. Explicit mapping (#135): the code and
            // why it was chosen are documented at UserVerificationWireError.
            Log.e(TAG, "User verification required: ${e.message}")
            UserVerificationWireError.response(request.id, e)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected handler error", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "Internal error: ${e.message}")
        }
    }

    /**
     * Handles the generateKey method.
     *
     * Key generation uses the current biometric settings to determine authentication
     * duration:
     * - UV DISABLED: Key does not require authentication (authDurationSeconds = -1)
     * - PER_OPERATION: Require authentication for every use (authDurationSeconds = 0)
     * - TIME_WINDOW: Use configured time window duration
     * - PER_SESSION: Use default session duration (5 minutes)
     */
    private suspend fun handleGenerateKey(request: Request): Response = withContext(Dispatchers.Main) {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val generateParams = GenerateKeyParams.fromJson(params)

        // This legacy path always produces EC P-256/SHA-256, so anything else is
        // refused rather than silently answered with an ES256 key. Peers needing
        // another algorithm use `local.generateKey`, which honours the request.
        if (generateParams.algorithm != CoseAlgorithms.ES256) {
            throw ProtocolException(
                "Algorithm ${generateParams.algorithm} is not available on this method; " +
                    "use local.generateKey",
                errorCode = ErrorCodes.INVALID_ALGORITHM
            )
        }

        // As in local.generateKey: the reservation holds the id from this check
        // until the creation ends, and the creation rechecks after the approval.
        val reservation = "credential:${generateParams.credentialId}"
        if (keystoreManager.keyExists(generateParams.credentialId) || !keyIds.tryReserve(reservation)) {
            throw credentialExists()
        }
        try {
            // Determine authentication duration based on settings
            val authDurationSeconds = calculateAuthDuration(currentSettings)
            approveRegistration(generateParams)
            keyIds.withKeyLock(reservation) {
                if (keystoreManager.keyExists(generateParams.credentialId)) {
                    throw credentialExists()
                }
                createCredential(request, generateParams, authDurationSeconds)
            }
        } finally {
            keyIds.release(reservation)
        }
    }

    private fun credentialExists() =
        ProtocolException("Credential already exists", errorCode = ErrorCodes.INVALID_PARAMS)

    /** Asks the owner to approve a `generateKey` registration when verification applies. */
    private suspend fun approveRegistration(generateParams: GenerateKeyParams) {
        // If user verification required (not DISABLED), prompt for biometric BEFORE generating the key
        // This ensures user explicitly approves credential creation
        if (generateParams.requireUserVerification && currentSettings.uvPolicy != UserVerificationPolicy.DISABLED) {
            // Try BiometricActivityLauncher first (for service context)
            if (biometricLauncher != null) {
                // On a locked phone the notification opens this same prompt;
                // the request takes down only its own notification.
                val notice = OwnNotifications(operationType = "register", rpName = null)
                try {
                    biometricLauncher.requestAuthentication(
                        title = "xKey Registration",
                        subtitle = "Verify your identity to create a new passkey",
                        showOnLockScreen = keyguardManager.isKeyguardLocked,
                        onLaunch = notice.onLaunch
                    )
                } finally {
                    notice.close()
                }
            } else {
                // Fall back to BiometricHelper (for activity context)
                val helper = biometricHelper
                    ?: throw ProtocolException(
                        "No activity available for biometric prompt",
                        errorCode = ErrorCodes.INTERNAL_ERROR
                    )

                helper.authenticateWithoutCrypto(
                    title = "xKey Registration",
                    subtitle = "Verify your identity to create a new passkey"
                )
            }
        }
    }

    /** Creates an approved `generateKey` credential; the caller holds its id's lock. */
    private suspend fun createCredential(
        request: Request,
        generateParams: GenerateKeyParams,
        authDurationSeconds: Int
    ): Response {
        // Generate the key with appropriate authentication duration
        val cosePublicKey = keystoreManager.generateKeyWithAuthDuration(
            credentialId = generateParams.credentialId,
            authDurationSeconds = authDurationSeconds,
            requireStrongBox = false // Don't require, just prefer
        )

        val publicKeyBase64 = Base64.getEncoder().encodeToString(cosePublicKey)
        // The credential just generated, read by its exact alias; a KeyInfo
        // read that fails is an error, never a software-backed key.
        val level = generatedKeyLevel(
            generateParams.credentialId,
            read = { keystoreManager.credentialSecurityLevel(generateParams.credentialId) },
            discard = { keystoreManager.deleteKey(generateParams.credentialId) }
        )

        // The leaf of the Keystore chain is the key attestation certificate; the
        // issuing chain is served by local.attestKey. Devices without hardware
        // attestation return nothing, and the field stays absent.
        val attestationBase64 = runCatching {
            keystoreManager.getAttestationChain(generateParams.credentialId)
                ?.firstOrNull()
                ?.encoded
                ?.let { Base64.getEncoder().encodeToString(it) }
        }.getOrNull()

        val result = GenerateKeyResult.withLevel(
            publicKey = publicKeyBase64,
            attestation = attestationBase64,
            level = level
        )

        Log.i(TAG, "Generated key for credential: ${generateParams.credentialId}, " +
                "securityLevel=${level.wire}, authDuration=$authDurationSeconds")
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles the sign method.
     *
     * Signing uses configurable biometric authentication based on current settings:
     * 1. Check if biometric is needed via SessionAuthManager
     * 2. If needed and BiometricActivityLauncher available, use activity-based authentication
     * 3. Record authentication on success for session/time-window tracking
     * 4. Try signing without biometric first if not needed
     * 5. Fall back to crypto-bound BiometricHelper flow for PER_OPERATION keys
     */
    private suspend fun handleSign(request: Request): Response = withContext(Dispatchers.Main) {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val signParams = SignParams.fromJson(params)

        // Check if key exists
        if (!keystoreManager.keyExists(signParams.credentialId)) {
            throw ProtocolException(
                "Credential not found",
                errorCode = ErrorCodes.KEY_NOT_FOUND
            )
        }

        // Decode data hash
        val dataHash = signParams.getDataHashBytes()

        // Determine if biometric authentication is required
        val biometricRequired = if (signParams.userVerificationRequired) {
            sessionAuthManager?.isBiometricRequired(currentSettings, currentSessionId) ?: true
        } else {
            false
        }

        val signature: ByteArray
        val userVerified: Boolean

        if (!biometricRequired) {
            // Try signing without biometric (session/time-window still valid, or UV disabled)
            try {
                signature = keystoreManager.signWithoutBiometric(
                    credentialId = signParams.credentialId,
                    dataHash = dataHash
                )
                userVerified = currentSettings.uvPolicy == UserVerificationPolicy.REQUIRED
                Log.d(TAG, "Signed without biometric prompt (cached auth or UV disabled)")
            } catch (e: BiometricRequiredException) {
                // Key requires biometric but SessionAuthManager said we don't need it
                // This can happen if key was created with different settings
                // Fall through to biometric authentication
                Log.d(TAG, "Key requires biometric despite session auth - falling back to prompt")
                return@withContext signWithBiometric(request, signParams, dataHash)
            } catch (e: SigningException) {
                // Signing failed - likely auth timeout or key invalidation
                // Fall through to biometric authentication to retry
                Log.d(TAG, "Signing failed (${e.message}) - falling back to biometric prompt")
                return@withContext signWithBiometric(request, signParams, dataHash)
            }
        } else {
            // Biometric authentication is required
            return@withContext signWithBiometric(request, signParams, dataHash)
        }

        val signatureBase64 = Base64.getEncoder().encodeToString(signature)

        val result = SignResult(
            signature = signatureBase64,
            userVerified = userVerified
        )

        Log.i(TAG, "Signed data for credential: ${signParams.credentialId}, userVerified=$userVerified")
        Response.success(request.id, result.toJson())
    }

    /**
     * Performs signing with biometric authentication.
     *
     * This method handles the biometric authentication flow:
     * 1. If screen is locked, show a high-priority notification to wake the user
     * 2. For PER_OPERATION mode, use crypto-bound signing via BiometricActivityLauncher
     * 3. For TIME_WINDOW/PER_SESSION modes:
     *    - First try signWithoutBiometric (might work if within auth window)
     *    - If fails, use crypto-bound signing (single biometric prompt)
     * 4. Fall back to crypto-bound BiometricHelper flow if available (for activity context)
     *
     * IMPORTANT: We don't call requestAuthentication() for TIME_WINDOW/PER_SESSION modes
     * because a generic system biometric prompt does NOT unlock Android Keystore keys.
     * Only crypto-bound biometric (BiometricPrompt with CryptoObject) can unlock keys.
     */
    private suspend fun signWithBiometric(
        request: Request,
        signParams: SignParams,
        dataHash: ByteArray
    ): Response {
        // On a locked phone the notification opens the launcher's own prompt
        // (OwnNotifications), so its result completes this request.
        val notice = OwnNotifications(operationType = "sign", rpName = null)

        try {
            // Check if we're in PER_OPERATION mode (requires crypto-bound biometric every time)
            val isPEROperationMode = currentSettings.authMode == BiometricAuthMode.PER_OPERATION &&
                    currentSettings.uvPolicy == UserVerificationPolicy.REQUIRED

            // Try BiometricActivityLauncher first (for service context without activity)
            if (biometricLauncher != null) {
                if (isPEROperationMode) {
                    // PER_OPERATION mode: Use crypto-bound signing directly
                    // This performs biometric auth and signing in a single activity
                    Log.d(TAG, "Using crypto-bound signing for PER_OPERATION mode")
                    val signature = biometricLauncher.requestCryptoSignature(
                        credentialId = signParams.credentialId,
                        dataHash = dataHash,
                        title = "xKey Authentication",
                        subtitle = "Verify your identity to sign",
                        showOnLockScreen = keyguardManager.isKeyguardLocked,
                        onLaunch = notice.onLaunch
                    )

                    // Record successful authentication for session tracking
                    sessionAuthManager?.recordAuthentication(currentSessionId)

                    val signatureBase64 = Base64.getEncoder().encodeToString(signature)
                    val result = SignResult(
                        signature = signatureBase64,
                        userVerified = true
                    )

                    Log.i(TAG, "Signed data for credential: ${signParams.credentialId} (via crypto-bound launcher)")
                    return Response.success(request.id, result.toJson())
                } else {
                    // TIME_WINDOW/PER_SESSION modes: Try signWithoutBiometric first (optimistic)
                    // If the key has an auth duration and we're within the window, this will work
                    // without prompting for biometric again.
                    //
                    // IMPORTANT: TIME_WINDOW keys (authDuration > 0) do NOT support CryptoObject-bound
                    // biometric auth. They require a GENERIC biometric prompt to authenticate the user,
                    // and then signWithoutBiometric() will work within the auth duration window.
                    // Only PER_OPERATION keys (authDuration = 0) support CryptoObject-bound signing.
                    try {
                        Log.d(TAG, "Trying signWithoutBiometric (optimistic for TIME_WINDOW/PER_SESSION)")
                        val signature = keystoreManager.signWithoutBiometric(
                            credentialId = signParams.credentialId,
                            dataHash = dataHash
                        )

                        val signatureBase64 = Base64.getEncoder().encodeToString(signature)
                        val result = SignResult(
                            signature = signatureBase64,
                            userVerified = true
                        )

                        Log.i(TAG, "Signed data for credential: ${signParams.credentialId} (within auth window, no biometric needed)")
                        return Response.success(request.id, result.toJson())
                    } catch (e: BiometricRequiredException) {
                        Log.d(TAG, "Key requires biometric, showing generic prompt for TIME_WINDOW key")
                    } catch (e: SigningException) {
                        Log.d(TAG, "Signing failed (${e.message}), showing generic prompt for TIME_WINDOW key")
                    }

                    // Auth window expired - show generic biometric prompt to re-authenticate,
                    // then sign within the new auth window
                    Log.d(TAG, "Requesting generic biometric authentication for TIME_WINDOW/PER_SESSION key")
                    biometricLauncher.requestAuthentication(
                        title = "xKey Authentication",
                        subtitle = "Verify your identity to sign",
                        showOnLockScreen = keyguardManager.isKeyguardLocked,
                        onLaunch = notice.onLaunch
                    )

                    // Record successful authentication for session tracking
                    sessionAuthManager?.recordAuthentication(currentSessionId)

                    // Now sign within the fresh auth window
                    Log.d(TAG, "Biometric succeeded, signing within auth window")
                    val signature = keystoreManager.signWithoutBiometric(
                        credentialId = signParams.credentialId,
                        dataHash = dataHash
                    )

                    val signatureBase64 = Base64.getEncoder().encodeToString(signature)
                    val result = SignResult(
                        signature = signatureBase64,
                        userVerified = true
                    )

                    Log.i(TAG, "Signed data for credential: ${signParams.credentialId} (via generic biometric + sign)")
                    return Response.success(request.id, result.toJson())
                }
            }

            // Fall back to crypto-bound BiometricHelper flow (requires activity)
            val helper = biometricHelper
                ?: throw ProtocolException(
                    "No activity available for biometric prompt",
                    errorCode = ErrorCodes.INTERNAL_ERROR
                )

            // The activity's own prompt answers no launcher request; it takes
            // its queue turn, and the notification only wakes the phone for it.
            val signature = keystoreManager.sign(
                credentialId = signParams.credentialId,
                dataHash = dataHash,
                biometricHelper = helper,
                title = "xKey Authentication",
                subtitle = "Verify your identity to sign",
                onTurn = notice::wake
            )

            // Record successful authentication for session tracking
            sessionAuthManager?.recordAuthentication(currentSessionId)

            val signatureBase64 = Base64.getEncoder().encodeToString(signature)
            val result = SignResult(
                signature = signatureBase64,
                userVerified = true
            )

            Log.i(TAG, "Signed data for credential: ${signParams.credentialId} (via crypto-bound helper)")
            return Response.success(request.id, result.toJson())
        } finally {
            // This request's notifications, and no other request's.
            notice.close()
        }
    }

    /**
     * Shows a biometric notification if the screen is locked.
     *
     * This is called before biometric prompts to ensure the user sees a
     * full-screen notification when the phone is locked, allowing them to
     * unlock and approve the request. Also sends a notification to the laptop
     * so it can display a waiting indicator.
     *
     * @param operationType The type of operation requiring biometric (e.g., "sign", "decrypt")
     * @param rpName The relying party name for context, or null if unavailable
     * @param key The notification's key ([NotificationKeys]), naming its
     *   request across the whole app
     * @param onTimeout Callback invoked if the notification times out without user action
     * @param notifyLaptop Whether the installed [messageSender]'s laptop is the
     *   one waiting on this prompt, and so should hear that it is pending
     * @param promptIntent The launcher prompt the notification opens, so that
     *   its result completes the launcher's request [key] names; null for a
     *   prompt no launcher request waits on
     */
    private fun showBiometricNotificationIfLocked(
        operationType: String,
        rpName: String?,
        key: String,
        onTimeout: () -> Unit = {},
        notifyLaptop: Boolean = true,
        promptIntent: android.content.Intent? = null
    ) {
        if (keyguardManager.isKeyguardLocked) {
            Log.d(TAG, "Screen is locked, showing biometric notification")
            biometricNotificationHelper.showBiometricRequiredNotification(
                operationType = operationType,
                rpName = rpName,
                requestId = key,
                onTimeout = onTimeout,
                promptIntent = promptIntent
            )
            // Also notify the laptop that biometric is pending
            if (notifyLaptop) {
                sendBiometricPendingNotification(operationType, rpName)
            }
        }
    }

    /**
     * The lock-screen notifications one operation posts, and only those.
     *
     * Notification tags are app-wide, and requests from every connection take
     * turns on one screen, so the notification up may be any request's. Each
     * is posted under its own request's key ([NotificationKeys]), and [close]
     * takes down the ones this operation posted, by the keys it posted them
     * under: an operation withdrawn or timed out while it waited for its turn
     * posted nothing, and takes nothing down.
     */
    private inner class OwnNotifications(
        private val operationType: String,
        private val rpName: String?,
        private val notifyLaptop: Boolean = true
    ) {
        private val posted = java.util.concurrent.ConcurrentLinkedQueue<String>()

        /**
         * The `onLaunch` of a [BiometricActivityLauncher] prompt. On a locked
         * phone the notification opens the launched request's own prompt, so
         * approving or cancelling from the lock screen completes that request;
         * should it expire unanswered with the prompt never up (Android
         * blocked its start), the request settles and hands the screen on.
         * Every launcher prompt goes through this: a notification of its own
         * would open a prompt whose result nobody waits on.
         */
        val onLaunch: (String, android.content.Intent) -> Unit = { key, prompt ->
            post(key, prompt) { biometricLauncher?.expireUnshown(key) }
        }

        /**
         * Wakes a locked phone for a prompt no launcher request waits on,
         * under its queue [key] ([PromptOwnership.turn]): only on its turn.
         */
        fun wake(key: String) = post(key, prompt = null) {}

        private fun post(key: String, prompt: android.content.Intent?, onTimeout: () -> Unit) {
            posted.add(key)
            showBiometricNotificationIfLocked(
                operationType = operationType,
                rpName = rpName,
                key = key,
                onTimeout = onTimeout,
                notifyLaptop = notifyLaptop,
                promptIntent = prompt
            )
        }

        /** Takes down every notification this operation posted, and no other. */
        fun close() {
            while (true) biometricNotificationHelper.cancelNotification(posted.poll() ?: return)
        }
    }

    /**
     * Sends a biometric pending notification to the connected laptop.
     *
     * This is a fire-and-forget notification that informs the laptop that
     * the phone is about to show a biometric prompt while the screen is locked.
     * The laptop can use this to display a waiting indicator to the user.
     *
     * @param operation The operation type requiring biometric ("sign", "decrypt", "attestKey", etc.)
     * @param rpName The relying party name for context, or null if unavailable
     * @param timeoutSecs How long the phone will wait for biometric approval (default 30 seconds)
     */
    private fun sendBiometricPendingNotification(
        operation: String,
        rpName: String?,
        timeoutSecs: Int = 30
    ) {
        val sender = messageSender ?: return

        val params = LocalBiometricPendingParams(
            operation = operation,
            rpName = rpName,
            timeoutSecs = timeoutSecs
        )

        val request = Request(
            id = System.currentTimeMillis(),
            method = MethodNames.LOCAL_BIOMETRIC_PENDING,
            params = params.toJson()
        )

        // Fire and forget - launch in a coroutine and don't wait
        CoroutineScope(Dispatchers.IO).launch {
            try {
                sender.sendMessage(request.toJson())
                Log.d(TAG, "Sent biometric pending notification: operation=$operation")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to send biometric pending notification", e)
                // Don't throw - this is fire-and-forget
            }
        }
    }

    /**
     * Calculates the authentication duration based on biometric settings.
     *
     * @param settings The current biometric settings.
     * @return Authentication duration in seconds:
     *         - -1: No authentication required (UV disabled)
     *         - 0: Require authentication for every use (PER_OPERATION)
     *         - >0: Authentication valid for N seconds
     */
    private fun calculateAuthDuration(settings: BiometricSettingsData): Int {
        return when (settings.uvPolicy) {
            UserVerificationPolicy.DISABLED -> -1
            UserVerificationPolicy.REQUIRED -> {
                when (settings.authMode) {
                    BiometricAuthMode.PER_OPERATION -> 0
                    BiometricAuthMode.TIME_WINDOW -> settings.timeWindowSeconds
                    BiometricAuthMode.PER_SESSION -> DEFAULT_SESSION_DURATION_SECONDS
                }
            }
        }
    }

    /**
     * Checks if device attestation is current for this operation based on
     * the requesting device's settings -- the caller session's peer when there
     * is one, see [attestingPeerPublicKeyHex].
     *
     * @param forKeyUse True if checking for key use, false for key attestation.
     * @return True if attestation is current or not required, false if attestation is required but expired.
     */
    private suspend fun isDeviceAttestationCurrent(forKeyUse: Boolean): Boolean {
        val publicKeyHex = attestingPeerPublicKeyHex() ?: return true  // Unknown device, allow
        val device = pairedDeviceRepository?.getDevice(publicKeyHex) ?: return true  // Not in repo, allow

        val requiresAttestation = if (forKeyUse) {
            device.requireAttestationForKeyUse
        } else {
            device.requireAttestationForKeyAttestation
        }

        if (!requiresAttestation) return true  // Not required

        val lastAttest = device.lastAttestationTime ?: return false  // Never attested
        val graceMs = device.attestationGracePeriodMinutes * 60 * 1000L
        return System.currentTimeMillis() - lastAttest <= graceMs
    }

    /**
     * Handles the deleteKey method.
     */
    private suspend fun handleDeleteKey(request: Request): Response {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val deleteParams = DeleteKeyParams.fromJson(params)

        // Check if key exists
        if (!keystoreManager.keyExists(deleteParams.credentialId)) {
            throw ProtocolException(
                "Credential not found",
                errorCode = ErrorCodes.KEY_NOT_FOUND
            )
        }

        // Delete the key
        val deleted = keystoreManager.deleteKey(deleteParams.credentialId)
        if (!deleted) {
            throw ProtocolException(
                "Failed to delete credential",
                errorCode = ErrorCodes.INTERNAL_ERROR
            )
        }

        Log.i(TAG, "Deleted credential: ${deleteParams.credentialId}")
        return Response.success(request.id, JSONObject().put("deleted", true))
    }

    /**
     * Handles the loadKey method.
     */
    private suspend fun handleLoadKey(request: Request): Response {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val loadParams = LoadKeyParams.fromJson(params)

        val exists = keystoreManager.keyExists(loadParams.credentialId)

        val result = if (exists) {
            val cosePublicKey = keystoreManager.getCOSEPublicKey(loadParams.credentialId)
            if (cosePublicKey != null) {
                LoadKeyResult(
                    exists = true,
                    publicKey = Base64.getEncoder().encodeToString(cosePublicKey),
                    algorithm = CoseAlgorithms.ES256
                )
            } else {
                LoadKeyResult(exists = false)
            }
        } else {
            LoadKeyResult(exists = false)
        }

        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles the getInfo method.
     */
    private suspend fun handleGetInfo(request: Request): Response {
        val deviceName = Build.MODEL
        val hasStrongBox = hasStrongBox()
        val hasBiometrics = hasBiometrics()
        val credentialCount = keystoreManager.listCredentials().size

        val result = GetInfoResult(
            version = PROTOCOL_VERSION,
            deviceName = deviceName,
            hasStrongBox = hasStrongBox,
            hasBiometrics = hasBiometrics,
            credentialCount = credentialCount
        )

        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles the ping method.
     */
    private suspend fun handlePing(request: Request): Response {
        return Response.success(request.id, JSONObject().put("pong", true))
    }

    /**
     * Handles the listKeys method.
     */
    private suspend fun handleListKeys(request: Request): Response {
        val credentials = keystoreManager.listCredentials()

        val result = JSONObject()
        val credentialsArray = org.json.JSONArray()
        for (credentialId in credentials) {
            credentialsArray.put(credentialId)
        }
        result.put("credentials", credentialsArray)
        result.put("count", credentials.size)

        return Response.success(request.id, result)
    }

    // ============================================================
    // Extended local.* method handlers
    // ============================================================

    /** Key ids claimed by a creation or locked by a request, across every connection. */
    private val keyIds = KeyIdReservations.process

    /**
     * Handles local.generateKey - generate a key with specified algorithm.
     *
     * Supports asymmetric (EC, RSA) and symmetric (AES, HMAC) key generation.
     * For asymmetric keys, the DER-encoded public key is returned. For FIDO2
     * keys, the COSE-encoded public key is also returned. Key metadata is
     * persisted in the unified key store for management and policy tracking.
     *
     * Uses [Dispatchers.Main] because biometric prompts require the main thread.
     */
    private suspend fun handleLocalGenerateKey(request: Request): Response = withContext(Dispatchers.Main) {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val genParams = LocalGenerateKeyParams.fromJson(params)
        val algorithmName = CoseAlgorithms.getAlgorithmName(genParams.algorithm)

        // Approval prompts take turns, so another creation of this id can pass
        // this check while this one waits; the reservation refuses it until
        // this creation ends.
        val reservation = "key:${genParams.keyId}"
        if (keystoreManager.generalKeyExists(genParams.keyId) || !keyIds.tryReserve(reservation)) {
            throw ProtocolException("Key already exists: ${genParams.keyId}", errorCode = ErrorCodes.KEY_EXISTS)
        }
        try {
            val authDurationSeconds = calculateAuthDuration(currentSettings)
            approveLocalKeyGeneration(genParams)
            // The approval waited: recheck under the id's lock, since every
            // generator replaces an existing alias, destroying that key.
            keyIds.withKeyLock(reservation) {
                if (keystoreManager.generalKeyExists(genParams.keyId)) {
                    throw ProtocolException(
                        "Key already exists: ${genParams.keyId}",
                        errorCode = ErrorCodes.KEY_EXISTS
                    )
                }
                createLocalKey(request, genParams, algorithmName, authDurationSeconds)
            }
        } finally {
            keyIds.release(reservation)
        }
    }

    /** Asks the owner to approve a `local.generateKey` when verification applies. */
    private suspend fun approveLocalKeyGeneration(genParams: LocalGenerateKeyParams) {
        // Biometric verification before key generation
        if (genParams.requireUserVerification && currentSettings.uvPolicy != UserVerificationPolicy.DISABLED) {
            if (biometricLauncher != null) {
                // On a locked phone the notification opens this same prompt;
                // the request takes down only its own notification.
                val notice = OwnNotifications(operationType = "generateKey", rpName = null)
                try {
                    biometricLauncher.requestAuthentication(
                        title = "Key Generation",
                        subtitle = "Verify your identity to create a new key",
                        showOnLockScreen = keyguardManager.isKeyguardLocked,
                        onLaunch = notice.onLaunch
                    )
                } finally {
                    notice.close()
                }
            } else {
                val helper = biometricHelper
                    ?: throw ProtocolException(
                        "No activity available for biometric prompt",
                        errorCode = ErrorCodes.INTERNAL_ERROR
                    )
                helper.authenticateWithoutCrypto(
                    title = "Key Generation",
                    subtitle = "Verify your identity to create a new key"
                )
            }
        }
    }

    /** Creates an approved `local.generateKey` key; the caller holds its id's lock. */
    private suspend fun createLocalKey(
        request: Request,
        genParams: LocalGenerateKeyParams,
        algorithmName: String,
        authDurationSeconds: Int
    ): Response {
        // Software-backed (exportable) keys take a separate path: the raw
        // material lives in SoftwareKeyStore (app-encrypted) so it can be
        // exported/shared, instead of the non-exportable hardware Keystore.
        if (genParams.exportable) {
            return generateSoftwareKey(request, genParams, algorithmName, authDurationSeconds)
        }

        // Generate key based on algorithm type
        val publicKeyDer: ByteArray
        val keySizeBits: Int
        val isSymmetric = algorithmName.startsWith("AES") || algorithmName.startsWith("HMAC")

        if (isSymmetric) {
            // Symmetric or HMAC key
            if (algorithmName.startsWith("AES")) {
                val bits = if (algorithmName.contains("128")) 128 else 256
                keystoreManager.generateSymmetricKey(genParams.keyId, bits, authDurationSeconds)
                keySizeBits = bits
            } else {
                keystoreManager.generateHMACKey(genParams.keyId, algorithmName)
                keySizeBits = if (algorithmName.contains("512")) 512 else 256
            }
            publicKeyDer = ByteArray(0) // No public key for symmetric/HMAC
            // The exact alias just generated (xkey_key_<id>), never a
            // credential that shares the id.
            val level = generatedKeyLevel(
                genParams.keyId,
                read = { keystoreManager.generalKeySecurityLevel(genParams.keyId) },
                discard = { keystoreManager.deleteGeneralKey(genParams.keyId) }
            )

            // Store in unified key store
            keyDao.insert(
                KeyEntity(
                    keyId = genParams.keyId,
                    keyType = genParams.keyType,
                    algorithm = algorithmName,
                    label = genParams.label,
                    keySizeBits = keySizeBits,
                    strongBoxBacked = level == KeySecurityLevel.STRONGBOX,
                    biometricRequired = genParams.requireUserVerification,
                    authDurationSeconds = authDurationSeconds,
                    shareable = genParams.shareable,
                    // KeyEntity requires shareable and sharingPolicy to agree; a key
                    // created shareable needs a policy that admits a peer or sharing
                    // would be refused despite the caller asking for it.
                    sharingPolicy = if (genParams.shareable) {
                        SharingPolicyType.ALL_PEERS
                    } else {
                        SharingPolicyType.PRIVATE
                    },
                    source = "remote_ble"
                )
            )

            val result = LocalGenerateKeyResult.withLevel(
                keyId = genParams.keyId,
                publicKey = "",
                publicKeyCose = null,
                algorithm = algorithmName,
                keySizeBits = keySizeBits,
                level = level
            )
            return Response.success(request.id, result.toJson())
        }

        // Asymmetric key generation
        publicKeyDer = keystoreManager.generateKeyForAlgorithm(
            keyId = genParams.keyId,
            algorithm = algorithmName,
            authDurationSeconds = authDurationSeconds,
            preferStrongBox = genParams.preferStrongBox
        )
        keySizeBits = CoseAlgorithms.getKeySizeBits(genParams.algorithm)
        val level = generatedKeyLevel(
            genParams.keyId,
            read = { keystoreManager.generalKeySecurityLevel(genParams.keyId) },
            discard = { keystoreManager.deleteGeneralKey(genParams.keyId) }
        )
        val isStrongBoxBacked = level == KeySecurityLevel.STRONGBOX

        // Get COSE-encoded public key for FIDO2 keys
        val publicKeyCose = if (genParams.keyType == KeyTypes.FIDO2 && algorithmName.startsWith("ES")) {
            keystoreManager.getCOSEPublicKey(genParams.keyId)
        } else {
            null
        }

        // Store in unified key store
        keyDao.insert(
            KeyEntity(
                keyId = genParams.keyId,
                keyType = genParams.keyType,
                algorithm = algorithmName,
                label = genParams.label,
                publicKeyDer = publicKeyDer,
                publicKeyCose = publicKeyCose,
                keySizeBits = keySizeBits,
                strongBoxBacked = isStrongBoxBacked,
                biometricRequired = genParams.requireUserVerification,
                authDurationSeconds = authDurationSeconds,
                shareable = genParams.shareable,
                // KeyEntity requires shareable and sharingPolicy to agree; a key
                // created shareable needs a policy that admits a peer or sharing
                // would be refused despite the caller asking for it.
                sharingPolicy = if (genParams.shareable) {
                    SharingPolicyType.ALL_PEERS
                } else {
                    SharingPolicyType.PRIVATE
                },
                source = "remote_ble",
                rpId = genParams.rpId,
                rpName = genParams.rpName,
                userId = genParams.userId,
                userName = genParams.userName,
                userDisplayName = genParams.userDisplayName,
                isDiscoverable = genParams.isDiscoverable
            )
        )

        val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyDer)
        val publicKeyCoseBase64 = publicKeyCose?.let { Base64.getEncoder().encodeToString(it) }

        val result = LocalGenerateKeyResult.withLevel(
            keyId = genParams.keyId,
            publicKey = publicKeyBase64,
            publicKeyCose = publicKeyCoseBase64,
            algorithm = algorithmName,
            keySizeBits = keySizeBits,
            level = level
        )

        Log.i(TAG, "Generated key: ${genParams.keyId}, algo=$algorithmName, type=${genParams.keyType}")

        // Log FIDO2 registration for passkey operations
        if (genParams.keyType == KeyTypes.FIDO2) {
            AuditLogger.logFido2Registration(
                keyId = genParams.keyId,
                keyLabel = genParams.rpName ?: genParams.label ?: genParams.keyId,
                rpId = genParams.rpId ?: "unknown",
                userName = genParams.userName
            )
        }

        return Response.success(request.id, result.toJson())
    }

    /**
     * The security level of the key generateKey or local.generateKey just
     * made, read by [read] from its exact alias. A missing key or a KeyInfo
     * read that fails is an error, never a software-backed key: the key is
     * discarded so nothing is reported or persisted with a level it may not
     * have, and the caller can retry under the same id.
     */
    private fun generatedKeyLevel(
        keyId: String,
        read: () -> KeySecurityLevel?,
        discard: () -> Unit
    ): KeySecurityLevel {
        val failure = try {
            read()?.let { return it }
            null
        } catch (e: KeyInfoUnavailableException) {
            e
        }
        runCatching { discard() }
        Log.e(TAG, "Cannot read the security level of generated key $keyId", failure)
        throw ProtocolException(
            "Cannot read the security level of generated key $keyId",
            errorCode = ErrorCodes.INTERNAL_ERROR
        )
    }

    /**
     * Generates a software-backed (exportable) key. The raw key material is
     * stored in [com.automatethethings.xkey.crypto.SoftwareKeyStore]
     * (app-encrypted) so it can be exported or shared per policy, and mirrored
     * into the unified key store for display/management.
     *
     * Only symmetric algorithms (AES, HMAC) are supported. Asymmetric keys must
     * be hardware-backed (non-exportable) on a security key, so an exportable
     * asymmetric request is rejected rather than silently downgraded.
     */
    private suspend fun generateSoftwareKey(
        request: Request,
        genParams: LocalGenerateKeyParams,
        algorithmName: String,
        authDurationSeconds: Int
    ): Response {
        val isSymmetric = algorithmName.startsWith("AES") || algorithmName.startsWith("HMAC")
        if (!isSymmetric) {
            throw ProtocolException(
                "Exportable asymmetric keys are not supported; asymmetric keys must be " +
                    "hardware-backed. Use a hardware key, or an exportable symmetric (AES/HMAC) key.",
                errorCode = ErrorCodes.INVALID_PARAMS
            )
        }

        val keySizeBits = when {
            algorithmName.startsWith("AES") -> if (algorithmName.contains("128")) 128 else 256
            algorithmName.contains("512") -> 512
            else -> 256
        }
        val material = ByteArray(keySizeBits / 8).also { java.security.SecureRandom().nextBytes(it) }

        com.automatethethings.xkey.crypto.SoftwareKeyStore(context).put(
            com.automatethethings.xkey.crypto.SoftwareKey(
                keyId = genParams.keyId,
                algorithm = algorithmName,
                keyType = "symmetric",
                keySize = keySizeBits,
                exportable = true,
                shareable = genParams.shareable,
                material = material
            )
        )

        keyDao.insert(
            KeyEntity(
                keyId = genParams.keyId,
                keyType = genParams.keyType,
                algorithm = algorithmName,
                label = genParams.label,
                keySizeBits = keySizeBits,
                strongBoxBacked = false,
                biometricRequired = genParams.requireUserVerification,
                authDurationSeconds = authDurationSeconds,
                exportable = true,
                shareable = genParams.shareable,
                // KeyEntity requires shareable and sharingPolicy to agree; a key
                // created shareable needs a policy that admits a peer or sharing
                // would be refused despite the caller asking for it.
                // KeyEntity requires these two to agree: a key created
                // shareable must carry a policy that actually admits a peer,
                // or sharing would be refused despite the caller asking for
                // it. Not shareable stays PRIVATE.
                sharingPolicy = if (genParams.shareable) {
                    SharingPolicyType.ALL_PEERS
                } else {
                    SharingPolicyType.PRIVATE
                },
                source = "local"
            )
        )

        Log.i(TAG, "Generated software key: ${genParams.keyId}, algo=$algorithmName, exportable=true")

        val result = LocalGenerateKeyResult(
            keyId = genParams.keyId,
            publicKey = "",
            publicKeyCose = null,
            algorithm = algorithmName,
            keySizeBits = keySizeBits,
            strongBoxBacked = false,
            softwareBacked = true
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.sign - sign data with specified algorithm.
     *
     * Uses [Dispatchers.Main] because biometric prompts require the main thread
     * when user verification is requested and session authentication has expired.
     */
    private suspend fun handleLocalSign(request: Request): Response = withContext(Dispatchers.Main) {
        // Check device attestation requirement
        if (!isDeviceAttestationCurrent(forKeyUse = true)) {
            throw ProtocolException(
                "Device attestation required before key use",
                errorCode = ErrorCodes.DEVICE_ATTESTATION_REQUIRED
            )
        }

        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val signParams = LocalSignParams.fromJson(params)

        if (!keystoreManager.generalKeyExists(signParams.keyId)) {
            throw ProtocolException("Key not found: ${signParams.keyId}", errorCode = ErrorCodes.KEY_NOT_FOUND)
        }

        val data = signParams.getDataBytes()

        // Check if biometric is needed
        val biometricRequired = if (signParams.userVerificationRequired) {
            sessionAuthManager?.isBiometricRequired(currentSettings, currentSessionId) ?: true
        } else {
            false
        }

        if (biometricRequired && biometricLauncher != null) {
            val notice = OwnNotifications(operationType = "sign", rpName = null)
            try {
                biometricLauncher.requestAuthentication(
                    title = "Signing Request",
                    subtitle = "Verify your identity to sign data",
                    showOnLockScreen = keyguardManager.isKeyguardLocked,
                    onLaunch = notice.onLaunch
                )
                sessionAuthManager?.recordAuthentication(currentSessionId)
            } finally {
                notice.close()
            }
        }

        // `algorithm` is an optional override; default to the key's own
        // algorithm from the key store.
        val signAlgorithm = signParams.algorithm.ifEmpty {
            keyDao.getByKeyId(signParams.keyId)?.algorithm
                ?: throw ProtocolException(
                    "Missing 'algorithm' and key has no recorded algorithm",
                    errorCode = ErrorCodes.INVALID_PARAMS
                )
        }

        val startTime = System.currentTimeMillis()
        val signature = keystoreManager.signWithAlgorithm(signParams.keyId, data, signAlgorithm)
        val durationMs = System.currentTimeMillis() - startTime

        // Record usage
        keyDao.recordUsage(signParams.keyId)

        // Log signing request
        val callerPeer = currentPeerPublicKeyHex()
        val deviceInfo = callerPeer?.let { pairedDeviceRepository?.getDevice(it) }
        AuditLogger.logSigningRequest(
            keyId = signParams.keyId,
            keyLabel = signParams.keyId,
            keyType = "signing",
            algorithm = signAlgorithm,
            deviceId = callerPeer,
            deviceName = deviceInfo?.deviceName,
            success = true,
            durationMs = durationMs
        )

        val result = LocalSignResult(
            signature = Base64.getEncoder().encodeToString(signature),
            algorithm = signAlgorithm,
            userVerified = biometricRequired || currentSettings.uvPolicy == UserVerificationPolicy.REQUIRED
        )

        Log.i(TAG, "Signed data with key: ${signParams.keyId}, algo=$signAlgorithm")
        Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.decrypt - RSA decryption.
     */
    private suspend fun handleLocalDecrypt(request: Request): Response {
        // Check device attestation requirement
        if (!isDeviceAttestationCurrent(forKeyUse = true)) {
            throw ProtocolException(
                "Device attestation required before key use",
                errorCode = ErrorCodes.DEVICE_ATTESTATION_REQUIRED
            )
        }

        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val decryptParams = LocalDecryptParams.fromJson(params)
        val startTime = System.currentTimeMillis()
        val plaintext = keystoreManager.rsaDecrypt(decryptParams.keyId, decryptParams.getCiphertextBytes())
        val durationMs = System.currentTimeMillis() - startTime

        keyDao.recordUsage(decryptParams.keyId)

        // Log decryption request
        val callerPeer = currentPeerPublicKeyHex()
        val deviceInfo = callerPeer?.let { pairedDeviceRepository?.getDevice(it) }
        AuditLogger.logDecryptionRequest(
            keyId = decryptParams.keyId,
            keyLabel = decryptParams.keyId,
            keyType = "rsa",
            algorithm = "RSA-OAEP",
            deviceId = callerPeer,
            deviceName = deviceInfo?.deviceName,
            success = true,
            durationMs = durationMs
        )

        val result = LocalDecryptResult(
            plaintext = Base64.getEncoder().encodeToString(plaintext)
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.symmetricEncrypt - AES-GCM encryption.
     */
    private suspend fun handleLocalSymmetricEncrypt(request: Request): Response {
        // Check device attestation requirement
        if (!isDeviceAttestationCurrent(forKeyUse = true)) {
            throw ProtocolException(
                "Device attestation required before key use",
                errorCode = ErrorCodes.DEVICE_ATTESTATION_REQUIRED
            )
        }

        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val symParams = LocalSymmetricParams.fromJson(params)

        // Software-backed keys are operated on outside the Keystore.
        com.automatethethings.xkey.crypto.SoftwareKeyStore(context).get(symParams.keyId)?.let { sw ->
            val ct = com.automatethethings.xkey.crypto.SoftwareKeyOps.aesGcmEncrypt(
                sw.material, symParams.getDataBytes(), symParams.getAadBytes()
            )
            keyDao.recordUsage(symParams.keyId)
            return Response.success(
                request.id,
                LocalSymmetricResult(data = Base64.getEncoder().encodeToString(ct), payloadField = LocalSymmetricResult.FIELD_CIPHERTEXT).toJson()
            )
        }

        val startTime = System.currentTimeMillis()
        val ciphertext = keystoreManager.symmetricEncrypt(
            symParams.keyId, symParams.getDataBytes(), symParams.getAadBytes()
        )
        val durationMs = System.currentTimeMillis() - startTime

        keyDao.recordUsage(symParams.keyId)

        // Log encryption request
        val callerPeer = currentPeerPublicKeyHex()
        val deviceInfo = callerPeer?.let { pairedDeviceRepository?.getDevice(it) }
        AuditLogger.logEncryptionRequest(
            keyId = symParams.keyId,
            keyLabel = symParams.keyId,
            keyType = "symmetric",
            algorithm = "AES-GCM",
            deviceId = callerPeer,
            deviceName = deviceInfo?.deviceName,
            success = true,
            durationMs = durationMs
        )

        val result = LocalSymmetricResult(
            data = Base64.getEncoder().encodeToString(ciphertext),
            payloadField = LocalSymmetricResult.FIELD_CIPHERTEXT
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.symmetricDecrypt - AES-GCM decryption.
     */
    private suspend fun handleLocalSymmetricDecrypt(request: Request): Response {
        // Check device attestation requirement
        if (!isDeviceAttestationCurrent(forKeyUse = true)) {
            throw ProtocolException(
                "Device attestation required before key use",
                errorCode = ErrorCodes.DEVICE_ATTESTATION_REQUIRED
            )
        }

        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val symParams = LocalSymmetricParams.fromJson(params)

        // Software-backed keys are operated on outside the Keystore.
        com.automatethethings.xkey.crypto.SoftwareKeyStore(context).get(symParams.keyId)?.let { sw ->
            val pt = com.automatethethings.xkey.crypto.SoftwareKeyOps.aesGcmDecrypt(
                sw.material, symParams.getDataBytes(), symParams.getAadBytes()
            )
            keyDao.recordUsage(symParams.keyId)
            return Response.success(
                request.id,
                LocalSymmetricResult(data = Base64.getEncoder().encodeToString(pt), payloadField = LocalSymmetricResult.FIELD_PLAINTEXT).toJson()
            )
        }

        val startTime = System.currentTimeMillis()
        val plaintext = keystoreManager.symmetricDecrypt(
            symParams.keyId, symParams.getDataBytes(), symParams.getAadBytes()
        )
        val durationMs = System.currentTimeMillis() - startTime

        keyDao.recordUsage(symParams.keyId)

        // Log decryption request
        val callerPeer = currentPeerPublicKeyHex()
        val deviceInfo = callerPeer?.let { pairedDeviceRepository?.getDevice(it) }
        AuditLogger.logDecryptionRequest(
            keyId = symParams.keyId,
            keyLabel = symParams.keyId,
            keyType = "symmetric",
            algorithm = "AES-GCM",
            deviceId = callerPeer,
            deviceName = deviceInfo?.deviceName,
            success = true,
            durationMs = durationMs
        )

        val result = LocalSymmetricResult(
            data = Base64.getEncoder().encodeToString(plaintext),
            payloadField = LocalSymmetricResult.FIELD_PLAINTEXT
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.hmac - HMAC computation.
     */
    private suspend fun handleLocalHMAC(request: Request): Response {
        // Check device attestation requirement
        if (!isDeviceAttestationCurrent(forKeyUse = true)) {
            throw ProtocolException(
                "Device attestation required before key use",
                errorCode = ErrorCodes.DEVICE_ATTESTATION_REQUIRED
            )
        }

        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val hmacParams = LocalHMACParams.fromJson(params)

        // Software-backed keys are operated on outside the Keystore.
        com.automatethethings.xkey.crypto.SoftwareKeyStore(context).get(hmacParams.keyId)?.let { sw ->
            val swMac = com.automatethethings.xkey.crypto.SoftwareKeyOps.hmac(
                sw.material, hmacParams.getDataBytes(), sw.algorithm
            )
            keyDao.recordUsage(hmacParams.keyId)
            return Response.success(
                request.id,
                LocalHMACResult(mac = Base64.getEncoder().encodeToString(swMac)).toJson()
            )
        }

        val mac = keystoreManager.computeHMAC(hmacParams.keyId, hmacParams.getDataBytes())

        keyDao.recordUsage(hmacParams.keyId)

        val result = LocalHMACResult(
            mac = Base64.getEncoder().encodeToString(mac)
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.ecdh - ECDH key agreement.
     */
    private suspend fun handleLocalECDH(request: Request): Response {
        // Check device attestation requirement
        if (!isDeviceAttestationCurrent(forKeyUse = true)) {
            throw ProtocolException(
                "Device attestation required before key use",
                errorCode = ErrorCodes.DEVICE_ATTESTATION_REQUIRED
            )
        }

        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val ecdhParams = LocalECDHParams.fromJson(params)
        val sharedSecret = keystoreManager.performECDH(
            ecdhParams.keyId, ecdhParams.getPeerPublicKeyBytes()
        )

        keyDao.recordUsage(ecdhParams.keyId)

        val result = LocalECDHResult(
            sharedSecret = Base64.getEncoder().encodeToString(sharedSecret)
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.getPublicKey - export public key in specified format.
     */
    private suspend fun handleLocalGetPublicKey(request: Request): Response {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val pubKeyParams = LocalGetPublicKeyParams.fromJson(params)
        val keyEntity = keyDao.getByKeyId(pubKeyParams.keyId)
            ?: throw ProtocolException("Key not found: ${pubKeyParams.keyId}", errorCode = ErrorCodes.KEY_NOT_FOUND)

        val publicKey: String = when (pubKeyParams.format) {
            ExportFormats.DER -> {
                val der = keystoreManager.getPublicKeyDER(pubKeyParams.keyId)
                    ?: throw ProtocolException("Cannot export public key", errorCode = ErrorCodes.EXPORT_FAILED)
                Base64.getEncoder().encodeToString(der)
            }
            ExportFormats.PEM -> {
                keystoreManager.getPublicKeyPEM(pubKeyParams.keyId)
                    ?: throw ProtocolException("Cannot export public key", errorCode = ErrorCodes.EXPORT_FAILED)
            }
            ExportFormats.SSH -> {
                keystoreManager.getPublicKeySSH(pubKeyParams.keyId)
                    ?: throw ProtocolException("Cannot export public key", errorCode = ErrorCodes.EXPORT_FAILED)
            }
            ExportFormats.COSE -> {
                val cose = keystoreManager.getCOSEPublicKey(pubKeyParams.keyId)
                    ?: throw ProtocolException("Cannot export COSE key", errorCode = ErrorCodes.EXPORT_FAILED)
                Base64.getEncoder().encodeToString(cose)
            }
            else -> throw ProtocolException(
                "Unsupported format: ${pubKeyParams.format}",
                errorCode = ErrorCodes.UNSUPPORTED_FORMAT
            )
        }

        val result = LocalGetPublicKeyResult(
            publicKey = publicKey,
            format = pubKeyParams.format,
            algorithm = keyEntity.algorithm
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.listKeys - list keys with optional filtering by type and source.
     */
    private suspend fun handleLocalListKeys(request: Request): Response {
        val listParams = LocalListKeysParams.fromJson(request.params)

        val entities: List<KeyEntity> = when {
            listParams.keyType != null && listParams.source != null -> {
                keyDao.getByType(listParams.keyType).filter { it.source == listParams.source }
            }
            listParams.keyType != null -> keyDao.getByType(listParams.keyType)
            listParams.source != null -> keyDao.getBySource(listParams.source)
            else -> keyDao.getAll()
        }

        val keys = entities.map { entity ->
            KeyInfo(
                keyId = entity.keyId,
                keyType = entity.keyType,
                algorithm = entity.algorithm,
                label = entity.label,
                keySizeBits = entity.keySizeBits,
                strongBoxBacked = entity.strongBoxBacked,
                shareable = entity.shareable,
                source = entity.source,
                useCount = entity.useCount,
                createdAt = entity.createdAt,
                lastUsedAt = entity.lastUsedAt,
                rpId = entity.rpId,
                rpName = entity.rpName,
                userName = entity.userName,
                userDisplayName = entity.userDisplayName,
                isDiscoverable = entity.isDiscoverable,
                signCount = entity.signCount
            )
        }

        val result = LocalListKeysResult(keys = keys, count = keys.size)
        return Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.getKeyInfo - get detailed key information.
     */
    private suspend fun handleLocalGetKeyInfo(request: Request): Response {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val infoParams = LocalGetKeyInfoParams.fromJson(params)
        val entity = keyDao.getByKeyId(infoParams.keyId)
            ?: throw ProtocolException("Key not found: ${infoParams.keyId}", errorCode = ErrorCodes.KEY_NOT_FOUND)

        val info = KeyInfo(
            keyId = entity.keyId,
            keyType = entity.keyType,
            algorithm = entity.algorithm,
            label = entity.label,
            keySizeBits = entity.keySizeBits,
            strongBoxBacked = entity.strongBoxBacked,
            shareable = entity.shareable,
            source = entity.source,
            useCount = entity.useCount,
            createdAt = entity.createdAt,
            lastUsedAt = entity.lastUsedAt,
            rpId = entity.rpId,
            rpName = entity.rpName,
            userName = entity.userName,
            userDisplayName = entity.userDisplayName,
            isDiscoverable = entity.isDiscoverable,
            signCount = entity.signCount
        )
        return Response.success(request.id, info.toJson())
    }

    /**
     * Handles local.deleteKey - delete a key from both Android Keystore and unified store.
     */
    private suspend fun handleLocalDeleteKey(request: Request): Response {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        // go-xkms LocalDeleteKeyParams sends `keyId`; the legacy base
        // `deleteKey` shape used `credentialId`. Accept both.
        val keyId = params.optString("keyId").ifEmpty { params.optString("credentialId") }
            .ifEmpty { throw ProtocolException("Missing 'keyId' parameter", errorCode = ErrorCodes.INVALID_PARAMS) }

        // Delete from Android Keystore and the software key store (only one
        // of the two will actually hold the key).
        keystoreManager.deleteGeneralKey(keyId)
        com.automatethethings.xkey.crypto.SoftwareKeyStore(context).delete(keyId)

        // Delete from unified key store
        keyDao.deleteByKeyId(keyId)

        Log.i(TAG, "Deleted key: $keyId")
        return Response.success(request.id, JSONObject().put("deleted", true))
    }

    /**
     * Handles local.setKeyPolicy - update key sharing policy.
     *
     * Widening a key to every peer (`shareable: true` on a key whose policy
     * is not already [SharingPolicyType.ALL_PEERS]) lets any paired peer pass
     * the sharing check, so it needs a confirmed peer and the owner's
     * approval on the phone. Without a launcher, or when the prompt is
     * cancelled or fails, the request answers BIOMETRIC_FAILED and the stored
     * policy is unchanged. Narrowing needs neither. Every stored change is
     * audited.
     *
     * The write is a compare-and-set against the policy revision the
     * decision was taken on (every policy write moves it forward, so a
     * policy changed away and back is a new revision), so a change that
     * lands while the prompt is up, or between the read and the write, is
     * never overwritten: a widening whose starting
     * policy moved is refused (OPERATION_DENIED) rather than applied without
     * an approval for it, and a narrowing re-reads and retries. A key already
     * at the requested policy is not written. The audit records only a write
     * that changed the row, with the policy it replaced.
     */
    private suspend fun handleLocalSetKeyPolicy(request: Request): Response {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val policyParams = LocalSetKeyPolicyParams.fromJson(params)

        val entity = keyDao.getByKeyId(policyParams.keyId)
            ?: throw ProtocolException("Key not found: ${policyParams.keyId}", errorCode = ErrorCodes.KEY_NOT_FOUND)

        val newPolicy = when (policyParams.shareable) {
            null -> null
            true -> SharingPolicyType.ALL_PEERS
            false -> SharingPolicyType.PRIVATE
        }

        // The compare-and-set, like updateSharingPolicy, keeps `shareable` and
        // `sharing_policy` in step, which KeyEntity requires. It is bound to
        // the row read above (its immutable id), so a key deleted and
        // re-created under the same key id is never written, and to the
        // policy revision [from] was read at, so a policy that changed and
        // changed back since is not written either. It returns true only
        // when it changed the row, and audits exactly that change. The write
        // and the audit are one non-cancellable step: a request cancelled
        // after the commit and before its result arrives still audits it.
        suspend fun setPolicyFrom(from: KeyEntity, policy: SharingPolicyType): Boolean {
            val expected = from.sharingPolicy
            return withContext(NonCancellable) {
                if (keyDao.compareAndSetSharingPolicy(entity.id, entity.keyId, from.policyRevision, expected, policy) == 0) {
                    return@withContext false
                }
                AuditLogger.logKeySharingChanged(
                    keyId = entity.keyId,
                    keyLabel = entity.label,
                    keyType = entity.keyType,
                    oldPolicy = expected.name,
                    newPolicy = policy.name
                )
                true
            }
        }

        // The read row as it is now. A different row under the same key id
        // is another key: the request, and any approval for it, named the
        // one read above.
        suspend fun storedRow(): KeyEntity {
            val current = keyDao.getByKeyId(entity.keyId)
                ?: throw ProtocolException("Key not found: ${entity.keyId}", errorCode = ErrorCodes.KEY_NOT_FOUND)
            if (current.id != entity.id) {
                throw ProtocolException(
                    "Key ${entity.keyId} was replaced while the request was in flight; retry",
                    errorCode = ErrorCodes.OPERATION_DENIED
                )
            }
            return current
        }

        if (newPolicy == SharingPolicyType.ALL_PEERS && entity.sharingPolicy != SharingPolicyType.ALL_PEERS) {
            requireConfirmedPeer("Sharing a key with all peers")
            val keyName = entity.label.ifBlank { entity.keyId }
            val launcher = biometricLauncher ?: throw ProtocolException(
                "Sharing a key with all peers needs the owner's approval, and no biometric prompt is available",
                errorCode = ErrorCodes.BIOMETRIC_FAILED
            )
            withContext(Dispatchers.Main) {
                // A request withdrawn or timed out while it waited for its
                // turn posted no notification, and takes none down: the
                // notification up belongs to the request on screen.
                val notice = OwnNotifications(operationType = "share", rpName = keyName)
                try {
                    // One launcher-owned request: on a locked phone the
                    // notification opens this same prompt.
                    launcher.requestAuthentication(
                        title = "Share key with all devices",
                        subtitle = "Allow every paired device to use \"$keyName\"",
                        showOnLockScreen = keyguardManager.isKeyguardLocked,
                        onLaunch = notice.onLaunch
                    )
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    throw ProtocolException(
                        "Owner did not approve sharing the key with all peers: ${e.message}",
                        errorCode = ErrorCodes.BIOMETRIC_FAILED
                    )
                } finally {
                    notice.close()
                }
            }
            // The owner approved widening from the policy revision read
            // above. If any policy write landed while the prompt was up, even
            // one that changed the policy back, the approval does not cover
            // the new state: write nothing unless the key is already open.
            if (!setPolicyFrom(entity, SharingPolicyType.ALL_PEERS) &&
                storedRow().sharingPolicy != SharingPolicyType.ALL_PEERS
            ) {
                throw ProtocolException(
                    "Sharing policy of ${entity.keyId} changed while waiting for approval; retry",
                    errorCode = ErrorCodes.OPERATION_DENIED
                )
            }
        } else if (newPolicy == SharingPolicyType.PRIVATE) {
            // Narrowing needs no approval from any starting policy, so a
            // change that lands first is re-read and narrowed in turn.
            var current = entity
            var attempts = 0
            val maxAttempts = 3
            while (current.sharingPolicy != SharingPolicyType.PRIVATE &&
                !setPolicyFrom(current, SharingPolicyType.PRIVATE)
            ) {
                if (++attempts >= maxAttempts) {
                    throw ProtocolException(
                        "Sharing policy of ${entity.keyId} kept changing; retry",
                        errorCode = ErrorCodes.OPERATION_DENIED
                    )
                }
                current = storedRow()
            }
        }

        Log.i(TAG, "Updated policy for key: ${policyParams.keyId}, shareable=${policyParams.shareable}")
        return Response.success(request.id, JSONObject().put("updated", true))
    }

    /**
     * Handles local.attestKey - get attestation certificate chain.
     *
     * Uses [Dispatchers.Main] because biometric prompts require the main thread
     * when attestation biometric verification is enabled.
     */
    private suspend fun handleLocalAttestKey(request: Request): Response = withContext(Dispatchers.Main) {
        // Check device attestation requirement
        if (!isDeviceAttestationCurrent(forKeyUse = false)) {
            throw ProtocolException(
                "Device attestation required before key attestation",
                errorCode = ErrorCodes.DEVICE_ATTESTATION_REQUIRED
            )
        }

        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val attestParams = LocalAttestKeyParams.fromJson(params)

        requireUserPresenceForAttestation(
            request = request,
            operationType = "attestKey",
            title = "Key Attestation",
            subtitle = "Verify your identity to prove key ownership"
        )

        val key = keyDao.getByKeyId(attestParams.keyId)
        val keyLabel = key?.label ?: attestParams.keyId
        val keyType = key?.keyType ?: "unknown"

        val startTime = System.currentTimeMillis()
        // Every attempt from here on records exactly one KEY_ATTESTED entry,
        // whether the keystore returns no chain, throws (API 28+ reports
        // failures as AttestationException), or the chain cannot be read.
        var recorded = false
        fun recordAttestation(success: Boolean, securityLevel: String? = null, errorMessage: String? = null) {
            recorded = true
            AuditLogger.logKeyAttested(
                keyId = attestParams.keyId,
                keyLabel = keyLabel,
                keyType = keyType,
                securityLevel = securityLevel,
                success = success,
                errorMessage = errorMessage,
                durationMs = System.currentTimeMillis() - startTime
            )
        }

        val certsBase64: List<String>
        val securityLevel: String
        try {
            val certChain = keystoreManager.getKeyAttestationWithChallenge(
                attestParams.keyId, attestParams.getNonceBytes()
            )
            if (certChain == null) {
                val message = "Attestation not available for key: ${attestParams.keyId}"
                recordAttestation(success = false, errorMessage = message)
                throw ProtocolException(message, errorCode = ErrorCodes.ATTESTATION_FAILED)
            }

            certsBase64 = certChain.map { cert ->
                Base64.getEncoder().encodeToString(cert.encoded)
            }

            val leafCert = certChain[0] as java.security.cert.X509Certificate
            securityLevel = parseAttestationSecurityLevel(leafCert)
        } catch (e: Exception) {
            if (!recorded) recordAttestation(success = false, errorMessage = e.message ?: e.javaClass.simpleName)
            throw e
        }

        recordAttestation(success = true, securityLevel = securityLevel)

        val result = LocalAttestKeyResult(
            certificateChain = certsBase64,
            securityLevel = securityLevel,
            nonce = attestParams.nonce // Echo back the nonce
        )
        Response.success(request.id, result.toJson())
    }

    /**
     * Handles local.getCapabilities - report device cryptographic capabilities.
     *
     * Returns a summary of supported algorithms, key types, hardware features,
     * and operational capabilities of the Android device.
     */
    private suspend fun handleLocalGetCapabilities(request: Request): Response {
        val result = LocalGetCapabilitiesResult(
            algorithms = listOf(
                "ES256", "ES384", "ES512",
                "RS256", "RS384", "RS512",
                "AES128", "AES256",
                "HMAC-SHA256", "HMAC-SHA512"
            ),
            keyTypes = listOf("fido2", "tls", "signing", "encryption", "secret", "hmac", "ca", "attestation"),
            hasStrongBox = keystoreManager.isStrongBoxAvailable(),
            hasBiometrics = hasBiometrics(),
            supportsAttestation = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N,
            supportsECDH = true,
            supportsSymmetric = true,
            supportsHMAC = true,
            maxKeys = 256, // Android Keystore practical limit
            version = PROTOCOL_VERSION,
            deviceName = Build.MODEL,
            currentKeyCount = keyDao.getAll().size
        )
        return Response.success(request.id, result.toJson())
    }

    /**
     * Applies the attestation biometric policy, prompting when it demands it.
     *
     * Shared by every operation that asserts something about this device --
     * key attestation, device attestation and enrollment -- because they answer
     * to one policy and drifting copies would let one of them quietly stop
     * asking. Each prompt still carries its own wording, since the user is
     * being asked to authorise different things.
     *
     * Must be called on the main thread: the biometric prompt requires it.
     */
    private suspend fun requireUserPresenceForAttestation(
        request: Request,
        operationType: String,
        title: String,
        subtitle: String
    ) {
        // Resolved before the policy is read, so a caller session with no
        // authenticated peer is refused under every policy, not only the one
        // that consults it.
        val publicKeyHex = attestingPeerPublicKeyHex()
        val requireBiometric = when (currentSettings.attestationBiometricPolicy) {
            AttestationBiometricPolicy.ALWAYS -> true
            AttestationBiometricPolicy.NEVER -> false
            AttestationBiometricPolicy.PAIRED_DEVICES_SKIP -> {
                if (publicKeyHex != null && pairedDeviceRepository != null) {
                    !pairedDeviceRepository.isDeviceKnown(publicKeyHex)
                } else {
                    // An unknown peer, or no repository to ask: prompt rather
                    // than assume the connection is one the user already blessed.
                    true
                }
            }
        }

        if (!requireBiometric || currentSettings.uvPolicy == UserVerificationPolicy.DISABLED) {
            return
        }

        val isLocked = keyguardManager.isKeyguardLocked
        // The installed sender reaches the desktop this phone is serving,
        // which is not the one waiting on a phone-initiated request.
        val notifyLaptop = currentCoroutineContext()[CallerSession]?.served != false

        val notice = OwnNotifications(operationType, rpName = null, notifyLaptop = notifyLaptop)
        try {
            if (biometricLauncher != null) {
                biometricLauncher.requestAuthentication(
                    title = title,
                    subtitle = subtitle,
                    showOnLockScreen = isLocked,
                    onLaunch = notice.onLaunch
                )
            } else {
                // The activity's own prompt answers no launcher request; it
                // takes its queue turn, and the notification only wakes the
                // phone for it.
                val helper = biometricHelper
                    ?: throw ProtocolException(
                        "No activity available for biometric prompt",
                        errorCode = ErrorCodes.INTERNAL_ERROR
                    )
                helper.authenticateWithoutCrypto(title = title, subtitle = subtitle, onTurn = notice::wake)
            }
        } finally {
            notice.close()
        }
    }

    /**
     * Handles local.getDeviceEnrollmentRequest -- this phone asks an external
     * CA (xkey desktop or an xkms server) to certify a device identity key.
     *
     * The reply pairs a PKCS#10 CSR with the Keystore attestation chain over
     * the CA's nonce. Together they say: here is a key I want certified, and
     * here is TEE-signed proof it lives in hardware on a verified-boot device
     * running this exact application.
     *
     * Runs on [Dispatchers.Main] for the same reason the attestation handlers
     * do -- the biometric prompt requires it.
     */
    private suspend fun handleLocalGetDeviceEnrollmentRequest(request: Request): Response =
        withContext(Dispatchers.Main) {
            val params = request.params
                ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

            val enrollParams = LocalGetDeviceEnrollmentRequestParams.fromJson(params)
            val challenge = enrollParams.getNonceBytes()
            if (challenge.isEmpty()) {
                throw ProtocolException(
                    "A device enrollment nonce is required; without one the attestation proves nothing",
                    errorCode = ErrorCodes.INVALID_PARAMS
                )
            }

            // Enrollment binds this device's identity to a CA, so it is gated on
            // the user the same way key attestation is. A silent enrollment is
            // one the owner never agreed to.
            requireUserPresenceForAttestation(
                request = request,
                operationType = "deviceEnrollment",
                title = "Device Enrollment",
                subtitle = "Verify your identity to enroll this device"
            )

            val enrollment = try {
                withContext(Dispatchers.IO) {
                    deviceIdentity.createEnrollmentRequest(
                        challenge = challenge,
                        subject = enrollParams.subject?.let { X500Name(it) }
                            ?: X500Name("CN=${android.os.Build.MODEL ?: "Android device"}, O=xKey")
                    )
                }
            } catch (e: DeviceIdentityException) {
                throw ProtocolException(
                    e.message ?: "This device cannot produce hardware attestation",
                    errorCode = ErrorCodes.ATTESTATION_FAILED
                )
            }

            Response.success(
                request.id,
                LocalGetDeviceEnrollmentRequestResult(
                    csr = enrollment.csr,
                    attestationChain = enrollment.attestationChain.map {
                        java.util.Base64.getEncoder().encodeToString(it)
                    },
                    securityLevel = enrollment.securityLevel,
                    platformModel = android.os.Build.MODEL
                ).toJson()
            )
        }

    /**
     * Handles local.storeDeviceCredential -- the CA answers with the issued
     * certificate and this device adopts it.
     */
    private suspend fun handleLocalStoreDeviceCredential(request: Request): Response =
        withContext(Dispatchers.IO) {
            val params = request.params
                ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

            val storeParams = LocalStoreDeviceCredentialParams.fromJson(params)
            val factory = java.security.cert.CertificateFactory.getInstance("X.509")

            val certificate = try {
                factory.generateCertificate(storeParams.getCertificateBytes().inputStream())
                    as java.security.cert.X509Certificate
            } catch (e: Exception) {
                throw ProtocolException(
                    "The issued credential is not a valid X.509 certificate: ${e.message}",
                    errorCode = ErrorCodes.INVALID_PARAMS
                )
            }

            val chain = storeParams.chain.map { encoded ->
                try {
                    factory.generateCertificate(
                        java.util.Base64.getDecoder().decode(encoded).inputStream()
                    ) as java.security.cert.X509Certificate
                } catch (e: Exception) {
                    throw ProtocolException(
                        "The issuer chain contains an invalid certificate: ${e.message}",
                        errorCode = ErrorCodes.INVALID_PARAMS
                    )
                }
            }

            val stored = try {
                deviceIdentity.storeCredential(certificate, chain)
            } catch (e: DeviceIdentityException) {
                throw ProtocolException(
                    e.message ?: "The credential was refused",
                    errorCode = ErrorCodes.INVALID_PARAMS
                )
            }

            AuditLogger.logDeviceEnrolled(
                caSubject = certificate.issuerX500Principal.name,
                fingerprint = stored.fingerprint,
                notAfter = stored.notAfter
            )

            Response.success(
                request.id,
                LocalStoreDeviceCredentialResult(
                    stored = true,
                    fingerprint = stored.fingerprint,
                    notAfter = stored.notAfter
                ).toJson()
            )
        }

    /**
     * Answers the TCG/TPM2 enrollment family, which this platform cannot serve.
     *
     * Android has no endorsement key and no TPM, so TPM2_ActivateCredential and
     * a PCR quote are not merely unimplemented here -- they are unimplementable.
     * Saying so precisely matters: the caller needs to switch mechanism, not
     * retry, and a *successful-looking* answer would be worse than useless,
     * because credential activation is the step that proves the requester holds
     * the hardware it claims.
     */
    private suspend fun refuseTpmOnlyMethod(request: Request): Response =
        Response.error(
            request.id,
            ErrorCodes.NOT_APPLICABLE,
            "${request.method} requires a TPM2 endorsement key, which Android does not have. " +
                "Use local.getDeviceEnrollmentRequest, which proves hardware backing, " +
                "verified-boot state and application identity with Keystore attestation."
        )

    /**
     * Handles `local.attestDevice` — the prover half of device attestation
     * protocol version 2 (go-xkms#129).
     *
     * Answers with three separable things, all of which the desktop requires:
     *
     * 1. the persistent [DeviceAttestationKey]'s chain, which proves *once* that
     *    the key lives in hardware on a verified-boot device;
     * 2. a live ECDSA signature over the [AttestTranscript] for this exchange,
     *    which proves the device is here *now*;
     * 3. the RootOfTrust fields read out of the leaf, for display.
     *
     * Version 1 folded (1) and (2) together by minting a key whose attestation
     * challenge was the pairing nonce. Keystore seals that challenge at key
     * generation, so identity and freshness could not both be had; splitting them
     * is what makes a stable device fingerprint possible at all.
     *
     * Uses [Dispatchers.Main] because biometric prompts require the main thread.
     */
    private suspend fun handleLocalAttestDevice(request: Request): Response = withContext(Dispatchers.Main) {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val attestParams = LocalAttestDeviceParams.fromJson(params)
        val nonce = attestParams.getNonceBytes()

        // Derived from THIS device's own session. The request carries no channel
        // binding to copy, by design -- a session we cannot bind to is a refusal,
        // not an unbound signature.
        val channelBinding = deriveChannelBinding()

        requireUserPresenceForAttestation(
            request = request,
            operationType = "attestDevice",
            title = "Device Attestation",
            subtitle = "Verify your identity to prove device integrity"
        )

        val certChain = try {
            deviceAttestationKey.chain()
        } catch (e: XKeyCryptoException) {
            throw ProtocolException(
                e.message ?: "Device attestation not supported",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }
        val leafCert = certChain.first()
        val fingerprint = AttestedKeyFingerprint.of(leafCert.encoded)

        val signature = try {
            deviceAttestationKey.sign(
                AttestTranscript.build(
                    purpose = attestParams.purpose,
                    nonce = nonce,
                    channelBinding = channelBinding,
                    deviceFingerprint = fingerprint
                )
            )
        } catch (e: XKeyCryptoException) {
            throw ProtocolException(
                e.message ?: "Device attestation signature failed",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }

        val (securityLevel, rootOfTrust) = parseAttestationExtension(leafCert)

        bindFingerprintAtPairing(attestParams.purpose, fingerprint)

        val result = LocalAttestDeviceResult(
            protocolVersion = AttestTranscript.PROTOCOL_VERSION,
            format = "android-keystore",
            certificateChain = certChain.map { Base64.getEncoder().encodeToString(it.encoded) },
            securityLevel = securityLevel,
            nonce = attestParams.nonce,
            purpose = attestParams.purpose,
            signature = Base64.getEncoder().encodeToString(signature),
            signatureAlgorithm = DeviceAttestationKey.WIRE_SIGNATURE_ALGORITHM,
            bootState = rootOfTrust.bootState,
            deviceLocked = rootOfTrust.deviceLocked,
            verifiedBootKey = Base64.getEncoder().encodeToString(rootOfTrust.verifiedBootKey),
            verifiedBootHash = Base64.getEncoder().encodeToString(rootOfTrust.verifiedBootHash)
        )

        Log.i(TAG, "Device attestation completed: purpose=${attestParams.purpose}, " +
            "securityLevel=$securityLevel, bootState=${rootOfTrust.bootState}, " +
            "deviceLocked=${rootOfTrust.deviceLocked}")

        // The phone stores no record of the LAPTOP here: this handler is the
        // phone attesting itself, and the laptop keeps the result. What it does
        // store is its OWN fingerprint, above, so it can echo it on reconnect.
        Response.success(request.id, result.toJson())
    }

    /**
     * Handles `local.verifyUser` — on-demand user verification for a paired
     * desktop, as the desktop's pairing wire contract defines it.
     *
     * Signs `"xkey-attest-transcript-v1" || 0x0b || "verify-user" || nonce ||
     * channelBinding || SHA-256(UVK SPKI)` with the [UserVerificationKey], which
     * Keystore unlocks only for a Class 3 biometric bound to that one signature.
     * The answer carries the UVK chain, so the desktop can check the key's
     * authorization list, and the signature, so it can check the user was
     * present for this nonce on this session.
     *
     * Always prompts: the attestation and UV policies do not apply, since the
     * prompt *is* the answer. Cancel, lockout and a missing biometric are
     * errors, never a result. A pairing record is neither read nor written; the
     * transport has already refused an unconfirmed session.
     *
     * Uses [Dispatchers.Main] because biometric prompts require the main thread.
     */
    private suspend fun handleLocalVerifyUser(request: Request): Response = withContext(Dispatchers.Main) {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val verifyParams = LocalVerifyUserParams.fromJson(params)
        val nonce = verifyParams.getNonceBytes()

        // As for attestation: derived from this device's own session, and a
        // session we cannot bind to is a refusal.
        val channelBinding = deriveChannelBinding()

        val (certChain, signature) = try {
            signVerifyUser(request, nonce, channelBinding)
        } catch (e: KeyInvalidatedException) {
            // A new biometric enrollment invalidated the UVK. Replace it and
            // ask once more; a second invalidation is not retried.
            Log.w(TAG, "User verification key invalidated; regenerating once")
            uvk.regenerate()
            try {
                signVerifyUser(request, nonce, channelBinding)
            } catch (again: KeyInvalidatedException) {
                throw SigningException("user verification key was invalidated again", again)
            }
        }

        val result = LocalVerifyUserResult(
            protocolVersion = AttestTranscript.PROTOCOL_VERSION,
            certificateChain = certChain.map { Base64.getEncoder().encodeToString(it.encoded) },
            signature = Base64.getEncoder().encodeToString(signature),
            signatureAlgorithm = KeystoreUserVerificationKey.WIRE_SIGNATURE_ALGORITHM
        )

        Log.i(TAG, "User verification completed: ${certChain.size} certificates in the chain")
        Response.success(request.id, result.toJson())
    }

    /**
     * Builds the verify-user transcript over the UVK's current fingerprint and
     * has the user approve its signature. Returns the chain the transcript
     * commits to alongside the signature, so the two cannot disagree.
     */
    private suspend fun signVerifyUser(
        request: Request,
        nonce: ByteArray,
        channelBinding: ByteArray
    ): Pair<List<java.security.cert.X509Certificate>, ByteArray> {
        val certChain = uvk.chain()
        val transcript = AttestTranscript.build(
            purpose = AttestTranscript.PURPOSE_VERIFY_USER,
            nonce = nonce,
            channelBinding = channelBinding,
            deviceFingerprint = AttestedKeyFingerprint.of(certChain.first().encoded)
        )

        val isLocked = keyguardManager.isKeyguardLocked
        val notice = OwnNotifications(
            operationType = "verifyUser",
            rpName = null,
            notifyLaptop = currentCoroutineContext()[CallerSession]?.served != false
        )
        return try {
            val title = context.getString(R.string.verify_user_prompt_title)
            val subtitle = context.getString(R.string.verify_user_prompt_subtitle)
            val signature = userVerificationPrompt?.let { prompt ->
                // Its own queue turn: nothing shows, and no notification
                // wakes the phone, while another approval holds the screen.
                val key = NotificationKeys.wakeOnly("verifyUser")
                PromptOwnership.process.turn(key) {
                    notice.wake(key)
                    prompt.sign(transcript, title, subtitle, isLocked)
                } ?: throw BiometricException(
                    BiometricPrompt.ERROR_TIMEOUT,
                    "Another approval prompt held the screen past this request's deadline"
                )
            } ?: promptWithUserVerificationKey(transcript, title, subtitle, isLocked, notice)
            certChain to signature
        } finally {
            notice.close()
        }
    }

    /**
     * The prompt used when no [UserVerificationPrompt] is injected: a Class 3 `BiometricPrompt`
     * whose `CryptoObject` wraps the UVK [java.security.Signature].
     *
     * The signature is initialised here first even on the activity path, so an
     * invalidated key surfaces as [KeyInvalidatedException] before any prompt.
     */
    private suspend fun promptWithUserVerificationKey(
        message: ByteArray,
        title: String,
        subtitle: String,
        showOnLockScreen: Boolean,
        notice: OwnNotifications
    ): ByteArray {
        val signature = uvk.initSignature()
        if (biometricLauncher != null) {
            // The launcher's request takes its queue turn; its notification
            // opens that request's own prompt.
            return biometricLauncher.requestCryptoSignature(
                credentialId = "user-verification",
                dataHash = message,
                title = title,
                subtitle = subtitle,
                showOnLockScreen = showOnLockScreen,
                keyAlias = KeystoreUserVerificationKey.ALIAS,
                onLaunch = notice.onLaunch
            )
        }
        val helper = biometricHelper
            ?: throw ProtocolException(
                "No activity available for biometric prompt",
                errorCode = ErrorCodes.INTERNAL_ERROR
            )
        helper.authenticate(
            cryptoObject = BiometricPrompt.CryptoObject(signature),
            title = title,
            subtitle = subtitle,
            description = null,
            onTurn = notice::wake
        )
        return try {
            signature.update(message)
            signature.sign()
        } catch (e: Exception) {
            throw SigningException("user verification key could not sign the transcript", e)
        }
    }

    /**
     * The 32-byte channel binding for the session this request arrived on,
     * derived entirely from local state — the request carries no such field.
     * A divergence from the desktop's own derivation surfaces because the
     * desktop's signature check fails closed on it. The value itself is never
     * logged: a channel binding identifies the session.
     *
     * @throws ProtocolException when the request carries no session binding.
     *   Signing without one would produce a transcript that commits to no
     *   channel, and the desktop -- which rebuilds the transcript from its own
     *   session -- can only reject it. Refusing here says why, rather than
     *   returning a signature that looks well-formed and fails verification for
     *   reasons neither side can see.
     */
    private suspend fun deriveChannelBinding(): ByteArray {
        // The session the request arrived on, and only that. There is no
        // handler-wide fallback: with BLE, TCP and USB sharing this handler, any
        // other session is another desktop's channel.
        val binding = currentCoroutineContext()[CallerSession]?.binding?.binding()
            ?: throw ProtocolException(
                "Device attestation requires an established Noise session to bind to",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )

        return AttestTranscript.channelBinding(
            initiatorStaticPublicKey = binding.initiatorStaticPublicKey,
            responderStaticPublicKey = binding.responderStaticPublicKey,
            prologue = binding.prologue
        )
    }

    /**
     * Records this device's own fingerprint against the peer being paired, so the
     * identity ack can echo it on every later reconnect.
     *
     * Only on `purpose == "pair"`. On a reconnect the desktop is checking that
     * the attested key is still the one it recorded; overwriting the stored value
     * then would be a silent rebind to whatever key answered, which is exactly
     * the fail-closed case `ErrDeviceIdentityChanged` exists to catch. A rotated
     * key is meant to cost a re-pair.
     */
    private suspend fun bindFingerprintAtPairing(purpose: String, fingerprint: ByteArray) {
        if (purpose != AttestTranscript.PURPOSE_PAIR) return
        val peerKeyHex = attestingPeerPublicKeyHex() ?: return
        val repo = pairedDeviceRepository ?: return
        if (!repo.isDeviceKnown(peerKeyHex)) return

        val hex = fingerprint.joinToString("") { "%02x".format(it) }
        repo.updateDeviceFingerprint(peerKeyHex, hex)
        Log.i(TAG, "Bound attested-key fingerprint for peer ${peerKeyHex.take(16)}: ${hex.take(16)}...")
    }

    /**
     * The authenticated peer whose per-device policy governs this request --
     * the attestation prompt, attestation freshness, the pairing fingerprint
     * binding. That is the peer of the connection the request arrived on, and
     * the served peer only for a request that names no connection at all.
     *
     * A caller session is never backfilled from the global peer. That one
     * belongs to whichever desktop this phone last served, so its trust would
     * decide a prompt -- or bind a fingerprint -- for a different machine.
     *
     * @return the peer's static key hex, or null when the request's connection
     *   authenticated no peer, or names no connection and none is served
     * @throws ProtocolException when a phone-initiated session carries no peer key
     */
    private suspend fun attestingPeerPublicKeyHex(): String? {
        val caller = currentCoroutineContext()[CallerSession] ?: return connectedDevicePublicKeyHex
        val peer = caller.peerPublicKeyHex
        if (peer.isNullOrEmpty()) {
            // A served connection that authenticated no peer is an unknown
            // peer, prompted for as before; a session this phone opened must
            // name the desktop it opened it to.
            if (caller.served) return null
            throw ProtocolException(
                "Request arrived on a session with no authenticated peer key",
                errorCode = ErrorCodes.ATTESTATION_FAILED
            )
        }
        return peer
    }

    /**
     * RootOfTrust fields from Android Key Attestation extension.
     */
    private data class RootOfTrust(
        val bootState: Int,
        val deviceLocked: Boolean,
        val verifiedBootKey: ByteArray,
        val verifiedBootHash: ByteArray
    )

    /**
     * Parses the attestation extension and extracts security level and RootOfTrust.
     */
    private fun parseAttestationExtension(cert: java.security.cert.X509Certificate): Pair<String, RootOfTrust> {
        val extensionBytes = cert.getExtensionValue(ATTESTATION_EXTENSION_OID)
            ?: return Pair(
                if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee",
                RootOfTrust(0, true, ByteArray(0), ByteArray(0))
            )

        try {
            // Unwrap outer OCTET STRING
            val outerStream = java.io.DataInputStream(extensionBytes.inputStream())
            val outerTag = outerStream.readUnsignedByte()
            if (outerTag != 0x04) {
                return defaultAttestationResult()
            }
            val outerLength = readDerLength(outerStream)
            val innerBytes = ByteArray(outerLength)
            outerStream.readFully(innerBytes)

            // Parse main SEQUENCE
            val innerStream = java.io.DataInputStream(innerBytes.inputStream())
            val seqTag = innerStream.readUnsignedByte()
            if (seqTag != 0x30) {
                return defaultAttestationResult()
            }
            readDerLength(innerStream)

            // [0] attestationVersion - skip
            skipDerElement(innerStream)

            // [1] attestationSecurityLevel
            val secLevelTag = innerStream.readUnsignedByte()
            val secLevelLength = readDerLength(innerStream)
            val secLevelValue = if ((secLevelTag == 0x0A || secLevelTag == 0x02) && secLevelLength >= 1) {
                readDerIntegerValue(innerStream, secLevelLength)
            } else {
                1 // Default to TEE
            }
            val securityLevel = securityLevelNames[secLevelValue] ?: "tee"

            // [2] keyMasterVersion - skip
            skipDerElement(innerStream)

            // [3] keyMasterSecurityLevel - skip
            skipDerElement(innerStream)

            // [4] attestationChallenge - skip
            skipDerElement(innerStream)

            // [5] uniqueId - skip
            skipDerElement(innerStream)

            // [6] softwareEnforced - skip
            skipDerElement(innerStream)

            // [7] teeEnforced (SEQUENCE) - contains RootOfTrust at tag 704
            val teeTag = innerStream.readUnsignedByte()
            if (teeTag != 0x30) {
                return Pair(securityLevel, RootOfTrust(0, true, ByteArray(0), ByteArray(0)))
            }
            val teeLength = readDerLength(innerStream)
            val teeBytes = ByteArray(teeLength)
            innerStream.readFully(teeBytes)

            // Parse teeEnforced looking for RootOfTrust (tag 704 = context-specific [704])
            val rootOfTrust = parseRootOfTrust(teeBytes)

            return Pair(securityLevel, rootOfTrust)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse attestation extension", e)
            return defaultAttestationResult()
        }
    }

    private fun defaultAttestationResult(): Pair<String, RootOfTrust> {
        return Pair(
            if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee",
            RootOfTrust(0, true, ByteArray(0), ByteArray(0))
        )
    }

    /**
     * Parse RootOfTrust from teeEnforced SEQUENCE.
     * RootOfTrust is at context-specific tag [704] (0xA0 + 704 in high-tag form).
     */
    private fun parseRootOfTrust(teeBytes: ByteArray): RootOfTrust {
        val stream = java.io.DataInputStream(teeBytes.inputStream())
        try {
            while (stream.available() > 0) {
                val tag = stream.readUnsignedByte()
                val length = readDerLength(stream)

                // Look for a context-specific CONSTRUCTED tag (0xA0-0xBF).
                // The class bits are 0xC0 and the constructed bit is 0x20, so the
                // mask must be 0xE0. Masking with 0xC0 clears the constructed bit
                // and can only ever yield 0x00/0x40/0x80/0xC0 — never 0xA0 — so
                // this branch never ran and every device reported the hardcoded
                // defaults, including deviceLocked = true for an unlocked one.
                if ((tag and 0xE0) == 0xA0) {
                    // Context-specific tag - check if this is RootOfTrust
                    val content = ByteArray(length)
                    stream.readFully(content)

                    // Check for tag 704 (in high-tag-number form)
                    if (tag == 0xA0 || tag == 0xA2) {
                        // Try to parse as RootOfTrust SEQUENCE
                        val result = tryParseRootOfTrust(content)
                        if (result != null) {
                            return result
                        }
                    }
                } else {
                    // Skip this element
                    if (length > 0) {
                        stream.skipBytes(length)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error parsing RootOfTrust", e)
        }
        return RootOfTrust(0, true, ByteArray(0), ByteArray(0))
    }

    private fun tryParseRootOfTrust(content: ByteArray): RootOfTrust? {
        try {
            val stream = java.io.DataInputStream(content.inputStream())
            val seqTag = stream.readUnsignedByte()
            if (seqTag != 0x30) return null

            val seqLength = readDerLength(stream)
            if (seqLength < 4) return null

            // [0] verifiedBootKey (OCTET STRING)
            val bootKeyTag = stream.readUnsignedByte()
            if (bootKeyTag != 0x04) return null
            val bootKeyLength = readDerLength(stream)
            val verifiedBootKey = ByteArray(bootKeyLength)
            stream.readFully(verifiedBootKey)

            // [1] deviceLocked (BOOLEAN)
            val lockedTag = stream.readUnsignedByte()
            if (lockedTag != 0x01) return null
            val lockedLength = readDerLength(stream)
            val deviceLocked = if (lockedLength > 0) stream.readUnsignedByte() != 0 else true

            // [2] verifiedBootState (ENUMERATED)
            val bootStateTag = stream.readUnsignedByte()
            if (bootStateTag != 0x0A) return null
            val bootStateLength = readDerLength(stream)
            val bootState = if (bootStateLength > 0) readDerIntegerValue(stream, bootStateLength) else 0

            // [3] verifiedBootHash (OCTET STRING) - optional in older versions
            val verifiedBootHash = if (stream.available() > 2) {
                val hashTag = stream.readUnsignedByte()
                if (hashTag == 0x04) {
                    val hashLength = readDerLength(stream)
                    val hash = ByteArray(hashLength)
                    stream.readFully(hash)
                    hash
                } else {
                    ByteArray(0)
                }
            } else {
                ByteArray(0)
            }

            return RootOfTrust(bootState, deviceLocked, verifiedBootKey, verifiedBootHash)
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Handles local.listFido2Credentials - list shareable FIDO2 credentials for an rpId.
     *
     * Uses per-key sharing policies to determine which credentials are available:
     * - PRIVATE: Key is never shared
     * - ALL_PEERS: Key is shared with all trusted peers
     * - SELECTED_PEERS: Key is shared only with specific peers listed in key_sharing_policies
     *
     * Requires the connected device's public key to check SELECTED_PEERS policies.
     */
    private suspend fun handleLocalListFido2Credentials(request: Request): Response {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val listParams = LocalListFido2CredentialsParams.fromJson(params)

        // Get connected device's public key for per-key policy checks
        val peerPublicKeyHex = currentPeerPublicKeyHex()

        // Query all FIDO2 credentials for this rpId
        val allEntities = keyDao.getFido2ByRpId(listParams.rpId)

        // Filter based on per-key sharing policies
        val shareableEntities = allEntities.filter { entity ->
            canShareKeyWithPeer(entity, peerPublicKeyHex)
        }

        val credentials = shareableEntities.map { entity ->
            Fido2CredentialInfo(
                credentialId = entity.keyId,
                rpId = entity.rpId ?: listParams.rpId,
                rpName = entity.rpName,
                userId = entity.userId,
                userName = entity.userName,
                userDisplayName = entity.userDisplayName,
                isDiscoverable = entity.isDiscoverable,
                createdAt = entity.createdAt
            )
        }

        val result = LocalListFido2CredentialsResult(credentials = credentials)
        Log.i(TAG, "Listed ${credentials.size} FIDO2 credentials for rpId=${listParams.rpId}")
        return Response.success(request.id, result.toJson())
    }

    /**
     * Checks if a key can be shared with the given peer based on its sharing policy.
     *
     * @param entity The key entity to check.
     * @param peerPublicKeyHex The peer's public key (hex-encoded), or null if unknown.
     * @return True if the key can be shared with this peer.
     */
    private suspend fun canShareKeyWithPeer(entity: KeyEntity, peerPublicKeyHex: String?): Boolean {
        val allowed = sharePermission.canShare(entity, peerPublicKeyHex)
        if (!allowed && entity.sharingPolicy == SharingPolicyType.SELECTED_PEERS) {
            Log.w(TAG, "SELECTED_PEERS refused: no peer, no grant, or grant revocation pending")
        }
        return allowed
    }

    /** The one share decision ([SharePermission]), shared with every outbound share path. */
    private val sharePermission by lazy { SharePermission(keySharingPolicyDao, pairedDeviceRepository) }

    /**
     * Handles local.signFido2Assertion - sign a FIDO2 assertion with a shared credential.
     *
     * Produces a standard WebAuthn assertion:
     * - Authenticator data: rpIdHash (32) + flags (1) + signCount (4)
     * - Signature: over (authenticatorData || clientDataHash)
     *
     * Uses per-key sharing policies to control access:
     * - PRIVATE: Credential cannot be used by any peer
     * - ALL_PEERS: Credential can be used by all trusted peers
     * - SELECTED_PEERS: Credential can only be used by specific peers
     *
     * Uses [Dispatchers.Main] because biometric prompts require the main thread.
     */
    private suspend fun handleLocalSignFido2Assertion(request: Request): Response = withContext(Dispatchers.Main) {
        val params = request.params
            ?: throw ProtocolException("Missing parameters", errorCode = ErrorCodes.INVALID_PARAMS)

        val assertionParams = LocalSignFido2AssertionParams.fromJson(params)

        // Look up credential
        val entity = keyDao.getByKeyId(assertionParams.credentialId)
            ?: throw ProtocolException(
                "Credential not found: ${assertionParams.credentialId}",
                errorCode = ErrorCodes.KEY_NOT_FOUND
            )

        // Verify it's a FIDO2 credential with matching rpId
        if (entity.keyType != KeyTypes.FIDO2) {
            throw ProtocolException("Not a FIDO2 credential", errorCode = ErrorCodes.INVALID_PARAMS)
        }
        if (entity.rpId != null && entity.rpId != assertionParams.rpId) {
            throw ProtocolException("rpId mismatch", errorCode = ErrorCodes.INVALID_PARAMS)
        }

        // Check per-key sharing policy
        val peerPublicKeyHex = currentPeerPublicKeyHex()
        if (!canShareKeyWithPeer(entity, peerPublicKeyHex)) {
            throw ProtocolException("Credential is not shareable with this peer", errorCode = ErrorCodes.OPERATION_DENIED)
        }

        // Biometric authentication if required
        val biometricRequired = if (assertionParams.userVerificationRequired) {
            sessionAuthManager?.isBiometricRequired(currentSettings, currentSessionId) ?: true
        } else {
            false
        }

        // Tracks whether verification ACTUALLY happened, which is what the UV bit
        // must report. The request asking for it is not evidence that it occurred.
        var userVerified = false

        if (biometricRequired && biometricLauncher != null) {
            val notice = OwnNotifications(operationType = "sign", rpName = entity.rpName)
            try {
                biometricLauncher.requestAuthentication(
                    title = "xKey Authentication",
                    subtitle = "Verify your identity to use this passkey",
                    showOnLockScreen = keyguardManager.isKeyguardLocked,
                    onLaunch = notice.onLaunch
                )
                sessionAuthManager?.recordAuthentication(currentSessionId)
                userVerified = true
            } finally {
                notice.close()
            }
        }

        // The UV bit is signed inside authenticator data, so a response that
        // overstates it cannot be corrected afterwards. Refuse the ceremony
        // outright when the peer required verification that did not happen,
        // unless the owner has turned strict user verification off.
        UserVerificationCompliance.enforce(
            requirement = if (assertionParams.userVerificationRequired) {
                UvRequirement.REQUIRED
            } else {
                UvRequirement.DISCOURAGED
            },
            verificationPerformed = userVerified,
            strict = currentSettings.strictUserVerification,
            ceremony = "Passkey assertion for ${assertionParams.rpId}"
        )

        // Other assertions with this passkey may have signed while this one
        // waited for its approval. Reload the credential under its lock and
        // hold the lock across the counter increment, the signature and the
        // counter write, so each assertion signs a distinct, increasing count.
        val (newSignCount, authData, signature) = keyIds.withKeyLock("key:${assertionParams.credentialId}") {
            val current = keyDao.getByKeyId(assertionParams.credentialId)
                ?: throw ProtocolException(
                    "Credential not found: ${assertionParams.credentialId}",
                    errorCode = ErrorCodes.KEY_NOT_FOUND
                )
            if (current.keyType != KeyTypes.FIDO2 ||
                (current.rpId != null && current.rpId != assertionParams.rpId)
            ) {
                throw ProtocolException("Credential changed during approval", errorCode = ErrorCodes.INVALID_PARAMS)
            }
            if (!canShareKeyWithPeer(current, peerPublicKeyHex)) {
                throw ProtocolException(
                    "Credential is not shareable with this peer",
                    errorCode = ErrorCodes.OPERATION_DENIED
                )
            }

            // Increment sign count
            val newSignCount = current.signCount + 1

            // Build authenticator data
            // rpIdHash (32 bytes) || flags (1 byte) || signCount (4 bytes, big-endian)
            val rpIdHash = java.security.MessageDigest.getInstance("SHA-256")
                .digest(assertionParams.rpId.toByteArray(Charsets.UTF_8))

            val flags: Byte = UserVerificationCompliance.flags(
                userPresent = true,
                userVerified = userVerified,
                attestedCredentialData = false
            )

            val authData = ByteArray(37)
            System.arraycopy(rpIdHash, 0, authData, 0, 32)
            authData[32] = flags
            // signCount as 4-byte big-endian
            authData[33] = ((newSignCount shr 24) and 0xFF).toByte()
            authData[34] = ((newSignCount shr 16) and 0xFF).toByte()
            authData[35] = ((newSignCount shr 8) and 0xFF).toByte()
            authData[36] = (newSignCount and 0xFF).toByte()

            // Sign: authenticatorData || clientDataHash
            val clientDataHash = assertionParams.getClientDataHashBytes()
            val signedData = ByteArray(authData.size + clientDataHash.size)
            System.arraycopy(authData, 0, signedData, 0, authData.size)
            System.arraycopy(clientDataHash, 0, signedData, authData.size, clientDataHash.size)

            // Hash the signed data for ECDSA (sign expects a hash)
            val dataHash = java.security.MessageDigest.getInstance("SHA-256").digest(signedData)

            // Sign using the credential key
            val signature = keystoreManager.signWithoutBiometric(
                credentialId = assertionParams.credentialId,
                dataHash = dataHash
            )

            // Update sign count in database
            keyDao.updateSignCount(assertionParams.credentialId, newSignCount)
            Triple(newSignCount, authData, signature)
        }

        val result = LocalSignFido2AssertionResult(
            authenticatorData = Base64.getEncoder().encodeToString(authData),
            signature = Base64.getEncoder().encodeToString(signature),
            userHandle = entity.userId,
            signCount = newSignCount
        )

        Log.i(TAG, "Signed FIDO2 assertion for credential: ${assertionParams.credentialId}, " +
                "rpId=${assertionParams.rpId}, signCount=$newSignCount")

        // Log FIDO2 authentication
        AuditLogger.logFido2Authentication(
            keyId = assertionParams.credentialId,
            keyLabel = entity.rpName ?: entity.label ?: assertionParams.credentialId,
            rpId = assertionParams.rpId
        )

        Response.success(request.id, result.toJson())
    }

    /**
     * Parses the attestation security level from an Android Key Attestation
     * certificate extension (OID 1.3.6.1.4.1.11129.2.1.17).
     *
     * The extension contains an ASN.1 SEQUENCE where index 1 holds the
     * attestationSecurityLevel as an INTEGER: 0=software, 1=tee, 2=strongbox.
     *
     * Falls back to a heuristic based on StrongBox availability if the
     * extension is absent or cannot be parsed.
     *
     * @param cert The leaf certificate containing the attestation extension.
     * @return Security level string: "software", "tee", or "strongbox".
     */
    private fun parseAttestationSecurityLevel(cert: java.security.cert.X509Certificate): String {
        val extensionBytes = cert.getExtensionValue(ATTESTATION_EXTENSION_OID)
            ?: return if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee"

        return try {
            // The extension value is an OCTET STRING wrapping the actual DER data.
            // Unwrap the outer OCTET STRING: tag(0x04) + length + content.
            val outerStream = java.io.DataInputStream(extensionBytes.inputStream())
            val outerTag = outerStream.readUnsignedByte()
            if (outerTag != 0x04) {
                return if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee"
            }
            val outerLength = readDerLength(outerStream)
            val innerBytes = ByteArray(outerLength)
            outerStream.readFully(innerBytes)

            // The inner data is a SEQUENCE: tag(0x30) + length + elements.
            val innerStream = java.io.DataInputStream(innerBytes.inputStream())
            val seqTag = innerStream.readUnsignedByte()
            if (seqTag != 0x30) {
                return if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee"
            }
            readDerLength(innerStream) // consume sequence length

            // Element 0: attestationVersion (INTEGER)
            skipDerElement(innerStream)

            // Element 1: attestationSecurityLevel (ENUMERATED, tag 0x0A)
            val secLevelTag = innerStream.readUnsignedByte()
            val secLevelLength = readDerLength(innerStream)
            if ((secLevelTag != 0x0A && secLevelTag != 0x02) || secLevelLength < 1) {
                return if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee"
            }
            val secLevelValue = readDerIntegerValue(innerStream, secLevelLength)

            securityLevelNames[secLevelValue]
                ?: if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee"
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse attestation security level", e)
            if (keystoreManager.isStrongBoxAvailable()) "strongbox" else "tee"
        }
    }

    /**
     * Read a DER length field (supports short and long forms).
     */
    private fun readDerLength(stream: java.io.DataInputStream): Int {
        val first = stream.readUnsignedByte()
        if (first < 0x80) return first
        val numOctets = first and 0x7F
        var length = 0
        for (i in 0 until numOctets) {
            length = (length shl 8) or stream.readUnsignedByte()
        }
        return length
    }

    /**
     * Skip a single DER TLV element.
     */
    private fun skipDerElement(stream: java.io.DataInputStream) {
        stream.readUnsignedByte() // tag
        val length = readDerLength(stream)
        if (length > 0) {
            stream.skipBytes(length)
        }
    }

    /**
     * Read a DER integer value from the given number of content bytes.
     */
    private fun readDerIntegerValue(stream: java.io.DataInputStream, length: Int): Int {
        var value = 0
        for (i in 0 until length) {
            value = (value shl 8) or stream.readUnsignedByte()
        }
        return value
    }

    /**
     * Checks if StrongBox is available.
     */
    private fun hasStrongBox(): Boolean {
        return keystoreManager.isStrongBoxAvailable()
    }

    /**
     * Checks if biometrics are available and enrolled.
     */
    private fun hasBiometrics(): Boolean {
        val biometricManager = BiometricManager.from(context)
        return biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    }

    // -------------------------------------------------------------------------
    // OATH Handlers
    // -------------------------------------------------------------------------

    /**
     * Lists all local OATH credentials (without secrets).
     */
    private suspend fun handleOathList(request: Request): Response {
        return try {
            val db = XKeyDatabase.getInstance(context)
            val credentials = db.oathCredentialDao().getAll()
            val arr = org.json.JSONArray()
            for (cred in credentials) {
                arr.put(JSONObject().apply {
                    put("name", cred.oathId)
                    put("issuer", cred.issuer ?: JSONObject.NULL)
                    put("account_name", cred.accountName)
                    put("secret", "") // never expose secrets in a listing
                    put("type", cred.oathType.lowercase())
                    put("algorithm", cred.algorithm)
                    put("digits", cred.digits)
                    put("period", cred.periodSeconds)
                    put("counter", cred.counter)
                })
            }
            val result = JSONObject().apply { put("credentials", arr) }
            Response.success(request.id, result)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to list OATH credentials", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "Failed to list OATH credentials: ${e.message}")
        }
    }

    /**
     * Generates and returns the current OTP code for a credential.
     */
    private suspend fun handleOathGenerate(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")

        val credentialId = params.optString("credential_id", "")
        if (credentialId.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing credential_id")
        }

        return try {
            val db = XKeyDatabase.getInstance(context)
            val oathRepository = com.automatethethings.xkey.oath.OathRepository(
                db.oathCredentialDao(),
                com.automatethethings.xkey.oath.OathSecretManager()
            )
            val code = try {
                oathRepository.generateCode(credentialId)
            } catch (_: NoSuchElementException) {
                return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Credential not found: $credentialId")
            }

            val cred = db.oathCredentialDao().getByOathId(credentialId)
            // expires_in: seconds until the current TOTP window ends (0 for HOTP).
            val expiresIn = if (cred?.oathType == "TOTP") {
                val period = cred.periodSeconds.toLong()
                (period - (System.currentTimeMillis() / 1000 % period)).toInt()
            } else 0

            AuditLogger.logOathCodeGenerated(credentialId, cred?.issuer, cred?.accountName ?: "")

            val result = JSONObject().apply {
                put("code", code)
                put("expires_in", expiresIn)
            }
            Response.success(request.id, result)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate OATH code", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "Failed to generate code: ${e.message}")
        }
    }

    /**
     * Adds (imports) an OATH credential pushed from the desktop (local.oathAdd).
     */
    private suspend fun handleOathAdd(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")

        val credential = params.optJSONObject("credential")
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing credential")

        val name = credential.optString("name", "")
        val accountName = credential.optString("account_name", "")
        val secret = credential.optString("secret", "")
        if (name.isEmpty() || accountName.isEmpty() || secret.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing required credential fields")
        }

        return try {
            val db = XKeyDatabase.getInstance(context)
            val oathRepository = com.automatethethings.xkey.oath.OathRepository(
                db.oathCredentialDao(),
                com.automatethethings.xkey.oath.OathSecretManager()
            )

            val type = credential.optString("type", "totp").lowercase()
            val issuer = credential.optString("issuer", null)
            // The issuer and account arrive as separate fields: the structured
            // import keeps a ':' inside either where it is (#152), as
            // SyncEngine.mergeOath does. The id it returns is the one the
            // credential is stored under: the `name` local.oathList reports
            // and the credential_id oathGenerate/oathRemove accept.
            val credentialId = oathRepository.importStructured(
                type = type,
                issuer = issuer,
                accountName = accountName,
                secret = secret,
                algorithm = credential.optString("algorithm", "SHA1"),
                digits = credential.optInt("digits", 6),
                period = credential.optInt("period", 30),
                counter = credential.optLong("counter", 0)
            )

            AuditLogger.logOathCredentialCreated(name, issuer, accountName, type.uppercase())

            val result = JSONObject().apply {
                put("success", true)
                put("credential_id", credentialId)
            }
            Response.success(request.id, result)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to add OATH credential", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "Failed to add: ${e.message}")
        }
    }

    /**
     * Removes an OATH credential (local.oathRemove).
     */
    private suspend fun handleOathRemove(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")

        val credentialId = params.optString("credential_id", "")
        if (credentialId.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing credential_id")
        }

        return try {
            val db = XKeyDatabase.getInstance(context)
            val cred = db.oathCredentialDao().getByOathId(credentialId)
            if (cred == null) {
                // Nothing has that id: say so rather than claim a deletion.
                return Response.success(request.id, JSONObject().apply { put("deleted", false) })
            }
            db.oathCredentialDao().deleteByOathId(credentialId)

            AuditLogger.logOathCredentialDeleted(credentialId, cred.issuer, cred.accountName)

            val result = JSONObject().apply { put("deleted", true) }
            Response.success(request.id, result)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove OATH credential", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "Failed to remove: ${e.message}")
        }
    }

    // -------------------------------------------------------------------------
    // Sync Handlers (laptop <-> phone bidirectional sync)
    // -------------------------------------------------------------------------

    /**
     * Syncs trust-store certificates: imports the desktop's certs (skipping
     * those already present by fingerprint) and returns the phone's certs so the
     * desktop can merge them back.
     */
    private suspend fun handleSyncTrustStore(request: Request): Response {
        return try {
            val params = request.params ?: JSONObject()
            val engine = com.automatethethings.xkey.sync.SyncEngine(context)
            val counts = engine.mergeCertificates(params.optJSONArray("certificates") ?: org.json.JSONArray())
            val remote = engine.gatherCertificates()
            engine.markSynced()
            Response.success(request.id, JSONObject().apply {
                put("added", counts.added)
                put("skipped", counts.skipped)
                put("remote", remote)
            })
        } catch (e: Exception) {
            Log.e(TAG, "syncTrustStore failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "syncTrustStore failed: ${e.message}")
        }
    }

    /**
     * Syncs OATH credentials: imports/updates the desktop's credentials and
     * returns the phone's credentials (with decrypted Base32 secrets, for
     * replication over the Noise channel) so the desktop can merge them back.
     */
    private suspend fun handleSyncOATH(request: Request): Response {
        return try {
            val params = request.params ?: JSONObject()
            val engine = com.automatethethings.xkey.sync.SyncEngine(context)
            val counts = engine.mergeOath(params.optJSONArray("credentials") ?: org.json.JSONArray())
            val remote = engine.gatherOath()
            engine.markSynced()
            Response.success(request.id, JSONObject().apply {
                put("added", counts.added)
                put("updated", counts.updated)
                put("skipped", counts.skipped)
                put("remote", remote)
            })
        } catch (e: Exception) {
            Log.e(TAG, "syncOATH failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "syncOATH failed: ${e.message}")
        }
    }

    /**
     * Syncs passwords: imports/updates the desktop's passwords into the
     * encrypted password store and returns the phone's passwords so the desktop
     * can merge them back.
     */
    private suspend fun handleSyncPasswords(request: Request): Response {
        return try {
            val params = request.params ?: JSONObject()
            val engine = com.automatethethings.xkey.sync.SyncEngine(context)
            val counts = engine.mergePasswords(params.optJSONArray("passwords") ?: org.json.JSONArray())
            val remote = engine.gatherPasswords()
            engine.markSynced()
            Response.success(request.id, JSONObject().apply {
                put("added", counts.added)
                put("updated", counts.updated)
                put("skipped", counts.skipped)
                put("remote", remote)
            })
        } catch (e: PasswordStoreLockedException) {
            // Merge runs first and is refused before it writes, so a locked
            // vault leaves the store untouched and exports nothing.
            Response.error(request.id, ErrorCodes.PASSWORD_STORE_LOCKED, e.message ?: "password store is locked")
        } catch (e: Exception) {
            Log.e(TAG, "syncPasswords failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "syncPasswords failed: ${e.message}")
        }
    }

    /**
     * Reports sync status: this device's id, the last sync time, and a checksum
     * per store so the desktop can detect changes.
     */
    private suspend fun handleSyncStatus(request: Request): Response {
        return try {
            val engine = com.automatethethings.xkey.sync.SyncEngine(context)
            Response.success(request.id, JSONObject().apply {
                put("last_sync", engine.lastSyncRfc3339())
                put("device_id", engine.deviceId())
                put("store_checksums", engine.storeChecksums())
            })
        } catch (e: Exception) {
            Log.e(TAG, "syncStatus failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "syncStatus failed: ${e.message}")
        }
    }

    // -------------------------------------------------------------------------
    // Backup Handlers (opaque encrypted blobs stored on the phone)
    // -------------------------------------------------------------------------

    /**
     * Stores an opaque encrypted backup blob pushed from the desktop and returns
     * a generated backup id. The phone never inspects the blob.
     */
    private suspend fun handleCreateBackup(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val dataB64 = params.optString("backup_data", "")
        if (dataB64.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing backup_data")
        }
        return try {
            val bytes = decodeBase64Strict("backup_data", dataB64)
            val label = params.optString("label", "")
            val id = com.automatethethings.xkey.backup.BackupStore(context).store("", bytes)
            val peer = backupAuditPeer()
            AuditLogger.logBackupCreated(
                backupId = id,
                sizeBytes = bytes.size,
                deviceId = peer?.publicKeyHex,
                deviceName = peer?.deviceName
            )
            Response.success(request.id, JSONObject().apply {
                put("success", true)
                put("backup_id", id)
                if (label.isNotEmpty()) put("message", "stored backup '$label'")
            })
        } catch (e: ProtocolException) {
            Response.error(request.id, e.errorCode, e.message ?: "Invalid backup_data")
        } catch (e: Exception) {
            Log.e(TAG, "createBackup failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "createBackup failed: ${e.message}")
        }
    }

    /** The peer a backup audit entry names: its static key and paired name. */
    private class BackupAuditPeer(val publicKeyHex: String, val deviceName: String?)

    /**
     * Resolves the desktop a backup request came from, once per request.
     *
     * The peer is the one authenticated on the connection the request arrived
     * on ([attestingPeerPublicKeyHex]), never the handler-wide last-connected
     * key, which any other BLE/USB/TCP connection overwrites. The one snapshot
     * feeds both the entry's device id and its paired-device name. A session
     * that names no peer logs no device rather than failing the backup.
     */
    private suspend fun backupAuditPeer(): BackupAuditPeer? {
        val key = try {
            attestingPeerPublicKeyHex()
        } catch (_: ProtocolException) {
            null
        } ?: return null
        return BackupAuditPeer(key, pairedDeviceRepository?.getDevice(key)?.deviceName)
    }

    /**
     * Returns a previously stored backup blob by id (or the most recent one if
     * no id is given).
     */
    private suspend fun handleRestoreBackup(request: Request): Response {
        return try {
            val params = request.params ?: JSONObject()
            val store = com.automatethethings.xkey.backup.BackupStore(context)
            val id = params.optString("backup_id", "").ifBlank { store.latestId() ?: "" }
            if (id.isEmpty()) {
                return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "No backup available")
            }
            val bytes = store.load(id)
                ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Backup not found: $id")
            val createdAt = com.automatethethings.xkey.crypto.SyncCodec.toRfc3339(store.createdAtMillis(id))
            val peer = backupAuditPeer()
            AuditLogger.logBackupRestored(
                backupId = id,
                sizeBytes = bytes.size,
                deviceId = peer?.publicKeyHex,
                deviceName = peer?.deviceName
            )
            Response.success(request.id, JSONObject().apply {
                put("backup_data", java.util.Base64.getEncoder().encodeToString(bytes))
                put("backup_id", id)
                put("created_at", createdAt)
            })
        } catch (e: Exception) {
            Log.e(TAG, "restoreBackup failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "restoreBackup failed: ${e.message}")
        }
    }

    // -------------------------------------------------------------------------
    // Key-Sharing Handlers
    //
    // Policy model, enforced for every key that leaves or enters the device:
    //
    //  1. The session must carry a confirmed peer identity (the Noise static
    //     public key recorded at pairing). Sharing with an anonymous peer is
    //     never authorized.
    //  2. The key's recorded sharing policy must admit that peer
    //     ([canShareKeyWithPeer], which asks [SharePermission], the decision
    //     every outbound share also takes): PRIVATE never, ALL_PEERS always,
    //     SELECTED_PEERS only when key_sharing_policies lists the peer and
    //     the peer's grant revocation is not pending.
    //  3. A HARDWARE-backed key can only ever share its public half (Android
    //     Keystore private/symmetric material is non-exportable).
    //  4. A SOFTWARE-backed key may additionally share its private/symmetric
    //     material, and only when both the unified key store and the software
    //     key store mark it exportable AND shareable.
    //
    // Material inbound from a peer is stored non-exportable and non-shareable:
    // receiving a key is not consent to hand it back out. Material crosses the
    // already Noise-encrypted pairing channel as-is (no extra wrapping layer),
    // matching the go-xkms software backend's KeyMaterial semantics.
    // -------------------------------------------------------------------------

    /**
     * Returns the confirmed peer identity of the connection this request
     * arrived on, from [currentPeerPublicKeyHex]: the peer every sharing
     * decision and every audit record of a transfer names.
     *
     * @throws ProtocolException with [ErrorCodes.OPERATION_DENIED] when the
     * request's connection has no confirmed peer, since no sharing decision
     * can be made about an anonymous peer.
     */
    private suspend fun requireConfirmedPeer(operation: String): String {
        return currentPeerPublicKeyHex() ?: throw ProtocolException(
            "$operation requires a confirmed peer identity",
            errorCode = ErrorCodes.OPERATION_DENIED
        )
    }

    /**
     * The confirmed peer of the connection this request arrived on.
     *
     * One handler serves BLE, TCP and USB at once, and a transport's teardown
     * clears the handler-wide peer, so a request decides on its own
     * [CallerSession]'s peer. The handler-wide peer answers only for a
     * request that names no connection at all. A caller session is never
     * backfilled from it, as in [attestingPeerPublicKeyHex].
     *
     * @return the peer's static key hex, or null when the request's connection
     *   authenticated no peer, or names no connection and none is confirmed
     */
    private suspend fun currentPeerPublicKeyHex(): String? {
        val caller = currentCoroutineContext()[CallerSession] ?: return connectedDevicePublicKeyHex
        return caller.peerPublicKeyHex?.takeIf { it.isNotEmpty() }
    }

    /**
     * Loads the key metadata for [keyId] and authorizes sharing it with [peerPublicKeyHex].
     *
     * A key with no row in the unified key store has no recorded sharing
     * policy, so it is treated as unshareable rather than defaulting to open.
     *
     * @return The key metadata when sharing is authorized, null when it is refused.
     */
    private suspend fun authorizeShare(keyId: String, peerPublicKeyHex: String): KeyEntity? {
        val entity = keyDao.getByKeyId(keyId) ?: return null
        return if (canShareKeyWithPeer(entity, peerPublicKeyHex)) entity else null
    }

    /**
     * Imports a public key shared by the desktop, stored as a contact entry.
     */
    private suspend fun handleSharePublicKey(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val pem = params.optString("public_key_pem", "")
        if (pem.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing public_key_pem")
        }
        val peerPublicKeyHex = requireConfirmedPeer("sharePublicKey")
        return try {
            val der = com.automatethethings.xkey.crypto.SyncCodec.pemToDer(pem)
                ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Invalid public_key_pem")
            val fingerprint = com.automatethethings.xkey.crypto.SyncCodec.sha256Hex(der)
            val keyId = params.optString("key_id", "")
            val label = params.optString("label", "").ifBlank { keyId.ifBlank { "shared-key" } }
            val dao = XKeyDatabase.getInstance(context).contactDao()
            if (dao.getByFingerprint(fingerprint) == null) {
                dao.insert(
                    com.automatethethings.xkey.storage.entity.ContactEntity(
                        name = label,
                        publicKeyDer = der,
                        publicKeyFingerprint = fingerprint,
                        algorithm = params.optString("algorithm", "").ifBlank { "unknown" },
                        source = "shared",
                        notes = params.optString("backend", "").ifBlank { null }
                    )
                )
                AuditLogger.logContactImported(
                    name = label,
                    fingerprint = fingerprint,
                    source = "shared",
                    deviceId = peerPublicKeyHex,
                    deviceName = pairedDeviceRepository?.getDevice(peerPublicKeyHex)?.deviceName
                )
            }
            Response.success(request.id, JSONObject().apply {
                put("accepted", true)
                put("import_id", keyId.ifBlank { fingerprint })
            })
        } catch (e: Exception) {
            Log.e(TAG, "sharePublicKey failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "sharePublicKey failed: ${e.message}")
        }
    }

    /**
     * Imports a symmetric key shared by the desktop into the software key store
     * (encrypted at rest).
     *
     * The imported key is stored non-exportable and non-shareable: accepting a
     * peer's key material is not authorization to hand it back out, to that
     * peer or any other. The user grants sharing later through the key's
     * sharing policy. An existing key of the same id is never overwritten, so a
     * peer cannot replace locally generated material.
     */
    private suspend fun handleShareSymmetric(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val wrappedB64 = params.optString("wrapped_key", "")
        if (wrappedB64.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing wrapped_key")
        }
        val peerPublicKeyHex = requireConfirmedPeer("shareSymmetric")
        return try {
            val material = decodeBase64Strict("wrapped_key", wrappedB64)
            val keyId = params.optString("label", "").ifBlank {
                params.optString("key_id", "").ifBlank { "shared-sym-${System.currentTimeMillis()}" }
            }
            val store = com.automatethethings.xkey.crypto.SoftwareKeyStore(context)
            if (store.contains(keyId) || keyDao.getByKeyId(keyId) != null) {
                return Response.error(request.id, ErrorCodes.KEY_EXISTS, "Key already exists: $keyId")
            }
            val algorithm = params.optString("algorithm", "").ifBlank { "AES" }
            store.put(
                com.automatethethings.xkey.crypto.SoftwareKey(
                    keyId = keyId,
                    algorithm = algorithm,
                    keyType = "symmetric",
                    keySize = params.optInt("key_size", material.size * 8),
                    exportable = false,
                    shareable = false,
                    material = material
                )
            )
            AuditLogger.logKeyCreated(
                keyId = keyId,
                keyLabel = keyId,
                keyType = "symmetric",
                algorithm = algorithm,
                source = "shared",
                deviceId = peerPublicKeyHex,
                deviceName = pairedDeviceRepository?.getDevice(peerPublicKeyHex)?.deviceName
            )
            Response.success(request.id, JSONObject().apply {
                put("accepted", true)
                put("import_id", keyId)
            })
        } catch (e: Exception) {
            Log.e(TAG, "shareSymmetric failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "shareSymmetric failed: ${e.message}")
        }
    }

    /**
     * Exports one of the phone's keys for the desktop.
     *
     * Nothing leaves the device unless the connected peer is confirmed and the
     * key's sharing policy admits it. Beyond that, software keys may return raw
     * material (only when both stores mark them exportable + shareable), while
     * hardware/Keystore keys return their public key alone.
     */
    private suspend fun handleImportSharedKey(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val keyId = params.optString("key_id", "")
        if (keyId.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing key_id")
        }
        val peerPublicKeyHex = requireConfirmedPeer("importSharedKey")
        return try {
            val software = com.automatethethings.xkey.crypto.SoftwareKeyStore(context).get(keyId)
            val publicKeyPem = if (software == null) keystoreManager.getPublicKeyPEM(keyId) else null
            if (software == null && publicKeyPem == null) {
                return Response.error(request.id, ErrorCodes.KEY_NOT_FOUND, "Key not found: $keyId")
            }

            val peerName = pairedDeviceRepository?.getDevice(peerPublicKeyHex)?.deviceName
            val entity = authorizeShare(keyId, peerPublicKeyHex)
            if (entity == null) {
                val message = "Key is not shareable with this peer: $keyId"
                AuditLogger.logKeyExported(
                    keyId = keyId,
                    keyLabel = keyId,
                    keyType = software?.keyType ?: "public",
                    format = if (software != null) "raw" else "public",
                    deviceId = peerPublicKeyHex,
                    deviceName = peerName,
                    success = false,
                    errorMessage = message
                )
                return Response.error(request.id, ErrorCodes.OPERATION_DENIED, message)
            }

            val result = JSONObject()
            val format: String
            if (software != null) {
                // Software-backed key: may export raw material per policy.
                result.put("algorithm", software.algorithm)
                result.put("key_type", software.keyType)
                val exportMaterial = entity.exportable && entity.shareable &&
                    software.exportable && software.shareable
                format = if (exportMaterial) "raw" else "metadata"
                if (exportMaterial) {
                    result.put("wrapped_key", android.util.Base64.encodeToString(software.material, android.util.Base64.NO_WRAP))
                    result.put("key_size", software.keySize)
                    result.put("exportable", true)
                } else {
                    result.put("exportable", false)
                }
            } else {
                // Hardware/Keystore key: public key only — the private half is
                // non-exportable by design.
                result.put("public_key_pem", publicKeyPem)
                result.put("key_type", "public")
                result.put("exportable", false)
                result.put("algorithm", entity.algorithm)
                format = "public"
            }
            AuditLogger.logKeyExported(
                keyId = keyId,
                keyLabel = entity.label,
                keyType = software?.keyType ?: entity.keyType,
                format = format,
                deviceId = peerPublicKeyHex,
                deviceName = peerName
            )
            Response.success(request.id, result)
        } catch (e: Exception) {
            Log.e(TAG, "importSharedKey failed", e)
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "importSharedKey failed: ${e.message}")
        }
    }

    // -------------------------------------------------------------------------
    // Co-Signing Handlers
    // -------------------------------------------------------------------------

    /**
     * Handles an incoming co-sign request from a paired device.
     *
     * The request contains a content hash that the local device should sign
     * if the user approves. The signed response is returned to the initiator.
     *
     * @param request The co-sign request containing hash, algorithm, and initiator info.
     * @return Response with the signature or an error if user denies.
     */
    private suspend fun handleCosignRequest(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")

        val contentHash = params.optString("hash", "")
        val hashAlgorithm = params.optString("hashAlgorithm", "SHA-256")
        val initiatorFingerprint = params.optString("from", "")
        val keyId = params.optString("keyId", "")

        if (contentHash.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing content hash")
        }

        // Find signing key - use specified key or first available signing key
        val db = XKeyDatabase.getInstance(context)
        val signingKey: KeyEntity? = if (keyId.isNotEmpty()) {
            db.keyDao().getByKeyId(keyId)
        } else {
            db.keyDao().getAll().firstOrNull { it.keyType == "signing" || it.keyType == "fido2" }
        }

        if (signingKey == null) {
            return Response.error(request.id, ErrorCodes.KEY_NOT_FOUND, "No signing key available")
        }

        // Sign the content hash
        return try {
            val hashBytes = hexToBytes(contentHash)
            val signatureBytes = keystoreManager.signWithAlgorithm(
                signingKey.keyId, hashBytes, signingKey.algorithm
            )
            val publicKeyDer = keystoreManager.getPublicKeyDER(signingKey.keyId)
                ?: return Response.error(request.id, ErrorCodes.KEY_NOT_FOUND, "Could not retrieve public key")
            val fingerprint = computeFingerprint(publicKeyDer)

            AuditLogger.logCoSignReceived(
                contentHash = contentHash,
                signerFingerprint = fingerprint
            )

            val result = JSONObject().apply {
                put("signature", Base64.getEncoder().encodeToString(signatureBytes))
                put("keyFingerprint", fingerprint)
                put("algorithm", signingKey.algorithm)
                put("signerName", signingKey.label.ifEmpty { signingKey.keyId })
            }
            Response.success(request.id, result)
        } catch (e: Exception) {
            Log.e(TAG, "Co-sign failed", e)
            Response.error(request.id, ErrorCodes.SIGNING_FAILED, "Co-sign failed: ${e.message}")
        }
    }

    /**
     * Handles an incoming co-sign response from a witness device.
     *
     * This simply acknowledges receipt of the co-signature. The actual
     * signature aggregation happens in the CoSignActivity on the initiator side.
     *
     * @param request The co-sign response containing the witness's signature.
     * @return Acknowledgment response.
     */
    private suspend fun handleCosignResponse(request: Request): Response {
        val params = request.params
            ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")

        val signature = params.optString("signature", "")
        val keyFingerprint = params.optString("keyFingerprint", "")

        if (signature.isEmpty() || keyFingerprint.isEmpty()) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing signature or fingerprint")
        }

        Log.d(TAG, "Received co-sign response from key: $keyFingerprint")

        val result = JSONObject().apply {
            put("status", "received")
        }
        return Response.success(request.id, result)
    }

    // -------------------------------------------------------------------------
    // PIN Management Handlers
    // -------------------------------------------------------------------------

    private suspend fun handlePinStatus(request: Request): Response {
        val pm = pinManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIN support is not available on this transport")
        val result = JSONObject().apply {
            put("soPinSet", pm.soPINSet())
            put("userPinSet", pm.userPINSet())
            put("initialized", pm.isInitialized())
            val soLockout = pm.getLockoutStatus(PinType.SO_PIN)
            val userLockout = pm.getLockoutStatus(PinType.USER_PIN)
            put("soLocked", soLockout.isLocked)
            put("userLocked", userLockout.isLocked)
        }
        return Response.success(request.id, result)
    }

    private suspend fun handlePinVerify(request: Request): Response {
        val pm = pinManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIN support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val pin = params.optString("pin", "")
        val pinType = params.optString("pinType", "USER_PIN")
        if (pinType != "SO_PIN" && pinType != "USER_PIN") {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Invalid pinType: $pinType")
        }
        if (pin.isEmpty()) return Response.error(request.id, ErrorCodes.PIN_REQUIRED, "PIN is required")
        return try {
            val verified = if (pinType == "SO_PIN") pm.verifySOPIN(pin) else pm.verifyUserPIN(pin)
            if (verified) {
                Response.success(request.id, JSONObject().apply { put("verified", true) })
            } else {
                Response.error(request.id, ErrorCodes.PIN_INCORRECT, "PIN verification failed")
            }
        } catch (e: PinLockedException) {
            pinLockedError(request, e)
        } catch (e: PinException) {
            // PinManager.verifyUserPIN/verifySOPIN report a wrong PIN by throwing
            // rather than by returning false.
            pinError(request, e, "PIN verification failed")
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "PIN verification error")
        }
    }

    private suspend fun handlePinSet(request: Request): Response {
        val pm = pinManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIN support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val pinType = params.optString("pinType", "")
        val currentPin = params.optString("currentPin", "").ifEmpty { null }
        val newPin = params.optString("newPin", "")
        if (newPin.isEmpty()) return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "New PIN is required")
        newPinLengthError(request, newPin)?.let { return it }
        return try {
            when (pinType) {
                "SO_PIN" -> pm.setSOPIN(currentPin, newPin)
                "USER_PIN" -> {
                    val soPin = params.optString("soPin", "")
                    if (soPin.isEmpty()) return Response.error(request.id, ErrorCodes.PIN_REQUIRED, "SO PIN required to set User PIN")
                    pm.setUserPIN(soPin, newPin)
                }
                else -> return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Invalid pinType: $pinType")
            }
            Response.success(request.id, JSONObject().apply { put("success", true) })
        } catch (e: PinLockedException) {
            pinLockedError(request, e)
        } catch (e: PinException) {
            pinError(request, e, "PIN set failed")
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "PIN set error")
        }
    }

    private suspend fun handlePinChange(request: Request): Response {
        val pm = pinManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIN support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val pinType = params.optString("pinType", "")
        val currentPin = params.optString("currentPin", "")
        val newPin = params.optString("newPin", "")
        if (newPin.isEmpty()) return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "New PIN required")
        if (currentPin.isEmpty()) return Response.error(request.id, ErrorCodes.PIN_REQUIRED, "Current PIN required")
        newPinLengthError(request, newPin)?.let { return it }
        return try {
            when (pinType) {
                "SO_PIN" -> pm.changeSOPIN(currentPin, newPin)
                "USER_PIN" -> pm.changeUserPIN(currentPin, newPin)
                else -> return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Invalid pinType: $pinType")
            }
            Response.success(request.id, JSONObject().apply { put("success", true) })
        } catch (e: PinLockedException) {
            pinLockedError(request, e)
        } catch (e: PinException) {
            pinError(request, e, "PIN change failed")
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "PIN change error")
        }
    }

    private suspend fun handlePinResetLockout(request: Request): Response {
        val pm = pinManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIN support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val soPin = params.optString("soPin", "")
        if (soPin.isEmpty()) return Response.error(request.id, ErrorCodes.PIN_REQUIRED, "SO PIN required")
        return try {
            pm.resetLockout(soPin)
            Response.success(request.id, JSONObject().apply { put("success", true) })
        } catch (e: PinLockedException) {
            pinLockedError(request, e)
        } catch (e: PinException) {
            pinError(request, e, "Reset failed")
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "Reset error")
        }
    }

    /**
     * PIN_LOCKED for [e], with the `lockoutUntil` and `failedAttempts` the
     * desktop shows; every local.pin* handler answers a lockout this way.
     */
    private fun pinLockedError(request: Request, e: PinLockedException): Response =
        Response.error(request.id, ErrorCodes.PIN_LOCKED, "PIN is locked", JSONObject().apply {
            put("lockoutUntil", e.lockoutStatus.lockoutUntil)
            put("failedAttempts", e.lockoutStatus.failedAttempts)
        })

    /**
     * The error code for a [PinException] from the [PinManager]: PIN_REQUIRED
     * when the PIN is not set or a needed current PIN was not supplied, and
     * PIN_INCORRECT for a wrong PIN (and any other PIN refusal).
     */
    private fun pinError(request: Request, e: PinException, fallback: String): Response {
        val code = if (e is PinRequiredException) ErrorCodes.PIN_REQUIRED else ErrorCodes.PIN_INCORRECT
        return Response.error(request.id, code, e.message ?: fallback)
    }

    /**
     * INVALID_PARAMS when [newPin] is outside the allowed
     * [PinHasher.MIN_PIN_LENGTH]..[PinHasher.MAX_PIN_LENGTH] UTF-8 bytes,
     * checked before the [PinManager] is asked to store it; null when it fits.
     */
    private fun newPinLengthError(request: Request, newPin: String): Response? =
        try {
            PinHasher.validatePinLength(newPin)
            null
        } catch (e: IllegalArgumentException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "Invalid PIN length")
        }

    // -------------------------------------------------------------------------
    // PIV Handlers
    // -------------------------------------------------------------------------

    /**
     * Reads the PIV slot id from a request. go-xkms names this field `slot`
     * (`protocol_piv.go`); older Android callers send `slotId`.
     */
    private fun JSONObject.pivSlotId(): String =
        optString("slot").ifEmpty { optString("slotId") }

    /**
     * Reads a PIV algorithm, accepting go-xkms spellings ("ECDSA-P256",
     * "RSA-2048") alongside the [PivAlgorithm] enum names.
     */
    private fun pivAlgorithmOf(name: String): PivAlgorithm? {
        if (name.isBlank()) return null
        runCatching { return PivAlgorithm.valueOf(name) }
        return when (name.uppercase().replace("_", "-")) {
            "ECDSA-P256", "EC-P256", "P256" -> PivAlgorithm.ES256
            "ECDSA-P384", "EC-P384", "P384" -> PivAlgorithm.ES384
            "RSA-2048", "RSA2048" -> PivAlgorithm.RS2048
            else -> null
        }
    }

    private suspend fun handlePivListSlots(request: Request): Response {
        val pkm = pivKeyManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIV support is not available on this transport")
        return try {
            val slots = pkm.listSlots()
            val result = JSONObject()
            val slotsArray = org.json.JSONArray()
            for (info in slots) {
                slotsArray.put(JSONObject().apply {
                    // go-xkms reads `slot`/`has_key`/`has_certificate`/
                    // `cert_subject`; the camelCase names are the legacy
                    // Android spelling and stay for older peers.
                    put("slot", info.slot.hexId)
                    put("slotId", info.slot.hexId)
                    put("label", info.slot.label)
                    put("description", info.slot.description)
                    put("hasKey", info.hasKey)
                    put("has_key", info.hasKey)
                    put("hasCertificate", info.hasCertificate)
                    put("has_certificate", info.hasCertificate)
                    info.algorithm?.let { put("algorithm", it.displayName) }
                    info.publicKeyDer?.let {
                        val encoded = Base64.getEncoder().encodeToString(it)
                        put("publicKey", encoded)
                        put("public_key_der", encoded)
                    }
                    info.createdAt?.let { put("createdAt", it) }
                    info.lastUsedAt?.let { put("lastUsedAt", it) }
                    put("useCount", info.useCount)
                })
            }
            result.put("slots", slotsArray)
            Response.success(request.id, result)
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "List slots failed")
        }
    }

    private suspend fun handlePivGenerateKey(request: Request): Response {
        val pkm = pivKeyManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIV support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val slotId = params.pivSlotId()
        val algorithmName = params.optString("algorithm", "ES256")
        val slot = PivSlot.fromHexId(slotId) ?: return Response.error(request.id, ErrorCodes.PIV_INVALID_SLOT, "Invalid slot: $slotId")
        val algorithm = pivAlgorithmOf(algorithmName)
            ?: return Response.error(request.id, ErrorCodes.INVALID_ALGORITHM, "Invalid algorithm: $algorithmName")
        return try {
            val info = pkm.generateKey(slot, algorithm)
            val result = JSONObject().apply {
                put("slot", info.slot.hexId)
                put("slotId", info.slot.hexId)
                put("algorithm", info.algorithm?.displayName)
                put("hasKey", info.hasKey)
                put("has_key", info.hasKey)
                info.publicKeyDer?.let {
                    val encoded = Base64.getEncoder().encodeToString(it)
                    put("publicKey", encoded)
                    put("public_key_der", encoded)
                }
            }
            Response.success(request.id, result)
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.KEY_GENERATION_FAILED, e.message ?: "PIV key generation failed")
        }
    }

    private suspend fun handlePivImportCert(request: Request): Response {
        val pkm = pivKeyManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIV support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val slotId = params.pivSlotId()
        val certBase64 = params.optString("certificate_der").ifEmpty { params.optString("certificate") }
        val slot = PivSlot.fromHexId(slotId) ?: return Response.error(request.id, ErrorCodes.PIV_INVALID_SLOT, "Invalid slot: $slotId")
        if (certBase64.isEmpty()) return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Certificate is required")
        val certDer = try {
            Base64.getDecoder().decode(certBase64)
        } catch (_: IllegalArgumentException) {
            return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Certificate is not valid base64")
        }
        return try {
            pkm.importCertificate(slot, certDer)
            Response.success(request.id, JSONObject().apply { put("success", true) })
        } catch (e: com.automatethethings.xkey.piv.PivCertificateRejectedException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "Certificate refused")
        } catch (e: com.automatethethings.xkey.piv.PivSlotEmptyException) {
            Response.error(request.id, ErrorCodes.PIV_SLOT_NOT_FOUND, e.message ?: "No key in slot $slotId")
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "Certificate import failed")
        }
    }

    private suspend fun handlePivSign(request: Request): Response {
        val pkm = pivKeyManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIV support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val slotId = params.pivSlotId()
        val dataBase64 = params.optString("data", "")
        val algorithmName = params.optString("algorithm", "ES256")
        val slot = PivSlot.fromHexId(slotId) ?: return Response.error(request.id, ErrorCodes.PIV_INVALID_SLOT, "Invalid slot: $slotId")
        if (dataBase64.isEmpty()) return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Data is required")
        val algorithm = pivAlgorithmOf(algorithmName)
            ?: return Response.error(request.id, ErrorCodes.INVALID_ALGORITHM, "Invalid algorithm: $algorithmName")
        return try {
            val data = Base64.getDecoder().decode(dataBase64)
            val signature = pkm.sign(slot, data, algorithm)
            Response.success(request.id, JSONObject().apply {
                put("signature", Base64.getEncoder().encodeToString(signature))
            })
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.PIV_SIGN_FAILED, e.message ?: "PIV signing failed")
        }
    }

    private suspend fun handlePivGetCert(request: Request): Response {
        val pkm = pivKeyManager ?: return Response.error(request.id, ErrorCodes.FEATURE_UNAVAILABLE, "PIV support is not available on this transport")
        val params = request.params ?: return Response.error(request.id, ErrorCodes.INVALID_PARAMS, "Missing params")
        val slotId = params.pivSlotId()
        val slot = PivSlot.fromHexId(slotId) ?: return Response.error(request.id, ErrorCodes.PIV_INVALID_SLOT, "Invalid slot: $slotId")
        return try {
            val certDer = pkm.getCertificate(slot)
            if (certDer != null) {
                Response.success(request.id, JSONObject().apply {
                    val encoded = Base64.getEncoder().encodeToString(certDer)
                    put("certificate", encoded)
                    put("certificate_der", encoded)
                })
            } else {
                Response.error(request.id, ErrorCodes.PIV_SLOT_NOT_FOUND, "No certificate in slot $slotId")
            }
        } catch (e: Exception) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "Get certificate failed")
        }
    }

    /**
     * Decodes [hex] into bytes, rejecting anything that is not valid hex.
     *
     * `Character.digit` returns -1 for a non-hex character rather than failing,
     * so without these checks a malformed digest decoded to garbage and was
     * signed as though it were the caller's hash.
     */
    /**
     * Decodes a base64 field from the wire, refusing anything malformed.
     *
     * `android.util.Base64` SKIPS characters outside the alphabet, so a corrupt
     * payload decodes to something shorter and is accepted; the corruption then
     * surfaces at restore or import time with nothing to point at. Every other
     * protocol field uses the strict JDK decoder, and so must these.
     */
    private fun decodeBase64Strict(field: String, value: String): ByteArray =
        try {
            java.util.Base64.getDecoder().decode(value)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException(
                "Field '$field' is not valid base64",
                errorCode = ErrorCodes.INVALID_PARAMS
            )
        }

    private fun hexToBytes(hex: String): ByteArray {
        if (hex.length % 2 != 0) {
            throw ProtocolException(
                "Hex string has an odd length: ${hex.length}",
                errorCode = ErrorCodes.INVALID_PARAMS
            )
        }
        val data = ByteArray(hex.length / 2)
        for (i in hex.indices step 2) {
            val high = Character.digit(hex[i], 16)
            val low = Character.digit(hex[i + 1], 16)
            if (high < 0 || low < 0) {
                throw ProtocolException(
                    "Hex string contains a non-hex character at index $i",
                    errorCode = ErrorCodes.INVALID_PARAMS
                )
            }
            data[i / 2] = ((high shl 4) + low).toByte()
        }
        return data
    }

    private fun computeFingerprint(publicKeyDer: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        return digest.digest(publicKeyDer).joinToString("") { "%02x".format(it) }
    }
}
