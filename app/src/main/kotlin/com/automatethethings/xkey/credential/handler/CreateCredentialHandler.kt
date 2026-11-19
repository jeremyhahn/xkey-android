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
package com.automatethethings.xkey.credential.handler

import android.content.Context
import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.ProviderCreateCredentialRequest
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.CredentialCreationException
import com.automatethethings.xkey.credential.UserVerificationCompliance
import com.automatethethings.xkey.credential.UvRequirement
import com.automatethethings.xkey.credential.InvalidRequestException
import com.automatethethings.xkey.credential.RelyingPartyOrigin
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import org.json.JSONException
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Handles credential creation (registration) requests from CredentialManager.
 *
 * This handler processes WebAuthn makeCredential requests, generating new
 * passkey credentials using Android Keystore and storing metadata in Room.
 *
 * Two-phase flow:
 * 1. Begin phase: Returns CreateEntry options for user to select account
 * 2. Final phase: Actually creates the credential after user selection
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CreateCredentialHandler(
    private val context: Context
) {
    private val keystoreManager = KeystoreManager(context)
    private val settingsRepository = BiometricSettingsRepository(context)
    private val database = XKeyDatabase.getInstance(context)
    private val credentialDao = database.credentialMetadataDao()
    private val keyDao = database.keyDao()

    /**
     * Reports whether the device can actually verify the user, by strong
     * biometric or by device credential (PIN/pattern/password). Keystore
     * rejects auth-bound key generation when neither is enrolled.
     */
    private fun canAuthenticateUser(): Boolean {
        val manager = androidx.biometric.BiometricManager.from(context)
        val authenticators = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return manager.canAuthenticate(authenticators) ==
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Handle the begin phase of credential creation.
     *
     * Parses the request and returns CreateEntry options for the system UI
     * to display to the user.
     *
     * @param request The begin create credential request.
     * @return Response containing create entries for user selection.
     */
    suspend fun handleBeginCreateCredential(
        request: BeginCreateCredentialRequest
    ): BeginCreateCredentialResponse {
        Log.i(TAG, "handleBeginCreateCredential: request type=${request::class.simpleName}")

        val publicKeyRequest = request as? BeginCreatePublicKeyCredentialRequest
            ?: throw InvalidRequestException("Only public key credentials are supported")

        val requestJson = JSONObject(publicKeyRequest.requestJson)
        val rpJson = requestJson.getJSONObject("rp")
        val rpName = rpJson.optString("name", rpJson.getString("id"))
        val userJson = requestJson.getJSONObject("user")
        val userName = userJson.optString("name", "")
        val userDisplayName = userJson.optString("displayName", userName)

        Log.i(TAG, "handleBeginCreateCredential: rp=$rpName, user=$userName, displayName=$userDisplayName")

        val createEntry = CreateEntry.Builder(
            accountName = userDisplayName.ifEmpty { userName },
            pendingIntent = CredentialPendingIntentHelper.createCreatePendingIntent(
                context,
                publicKeyRequest.requestJson
            )
        )
            .setDescription("Create passkey for $rpName")
            .build()

        Log.i(TAG, "handleBeginCreateCredential: returning CreateEntry for $rpName")

        return BeginCreateCredentialResponse.Builder()
            .addCreateEntry(createEntry)
            .build()
    }

    /**
     * Handle the final phase of credential creation.
     *
     * Creates the actual passkey credential after user selection and
     * biometric authentication.
     *
     * @param request The provider create credential request.
     * @return JSON response containing the attestation object.
     */
    suspend fun handleCreateCredential(
        request: ProviderCreateCredentialRequest,
        userVerified: Boolean
    ): String {
        Log.i(TAG, "=== handleCreateCredential FINAL PHASE ===")

        val callingRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
            ?: throw InvalidRequestException("Not a public key credential request")

        val requestJson = try {
            JSONObject(callingRequest.requestJson)
        } catch (e: Exception) {
            throw InvalidRequestException("Failed to parse request JSON", e)
        }

        // Extract request parameters. A request missing any mandatory member is
        // a malformed request, so it reports as one rather than escaping as a
        // raw JSONException that no caller of this handler expects.
        val rpId: String
        val rpName: String
        val userId: String
        val userName: String
        val userDisplayName: String
        val pubKeyCredParams: org.json.JSONArray
        try {
            val rpJson = requestJson.getJSONObject("rp")
            rpId = rpJson.getString("id")
            rpName = rpJson.optString("name", rpId)

            val userJson = requestJson.getJSONObject("user")
            userId = userJson.getString("id")
            userName = userJson.optString("name", "")
            userDisplayName = userJson.optString("displayName", userName)

            pubKeyCredParams = requestJson.getJSONArray("pubKeyCredParams")
        } catch (e: JSONException) {
            throw InvalidRequestException("Request is missing a required member", e)
        }
        Log.i(TAG, "handleCreateCredential: rpId=$rpId, rpName=$rpName")

        // Before the origin work below, so an unsupported algorithm reports as
        // an unsupported algorithm rather than as an origin failure.
        validateAlgorithmSupport(pubKeyCredParams)

        // Construct clientDataJSON if the browser didn't provide clientDataHash
        val clientDataHash = callingRequest.clientDataHash
        var clientDataJsonBase64: String? = null
        Log.d(TAG, "clientDataHash provided: ${clientDataHash != null}")

        if (clientDataHash == null) {
            // This provider is signing the client data itself, so the origin it
            // binds must be one Android verified for the caller. Deriving an
            // origin from the requested rpId would let any app mint a passkey
            // for a site it does not control.
            Log.w(TAG, "clientDataHash is null, constructing clientDataJSON")
            val challenge = try {
                requestJson.getString("challenge")
            } catch (e: JSONException) {
                throw InvalidRequestException("Request is missing a challenge", e)
            }
            val callingPackage = request.callingAppInfo.packageName
            val verifiedOrigin = try {
                request.callingAppInfo.getOrigin(BROWSER_PRIVILEGED_ALLOWLIST)
            } catch (e: Exception) {
                Log.e(TAG, "Origin verification failed for $callingPackage", e)
                throw CredentialCreationException(
                    "Could not verify the calling app's origin ($callingPackage)",
                    e
                )
            }
            val origin = verifiedOrigin ?: throw CredentialCreationException(
                "Calling app $callingPackage provided no client data hash and has no " +
                    "verified web origin; refusing to create a passkey"
            )
            Log.d(TAG, "Using origin: $origin")

            // The origin goes into clientDataJSON and the rpId is hashed into
            // authenticator data. Signing a response where they are unrelated
            // would let an app mint a passkey for a site it does not control.
            if (!RelyingPartyOrigin.isRpIdValidForOrigin(rpId, origin)) {
                throw CredentialCreationException(
                    "Relying party $rpId is not valid for the caller's origin $origin"
                )
            }

            val clientDataJson = JSONObject().apply {
                put("type", "webauthn.create")
                put("challenge", challenge)
                put("origin", origin)
                put("crossOrigin", false)
            }
            val clientDataJsonBytes = clientDataJson.toString().toByteArray(Charsets.UTF_8)
            clientDataJsonBase64 = Base64.encodeToString(
                clientDataJsonBytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
        }

        val authenticatorSelection = requestJson.optJSONObject("authenticatorSelection")
        val residentKey = authenticatorSelection?.optString("residentKey", "preferred") ?: "preferred"
        val userVerification = authenticatorSelection?.optString("userVerification", "preferred") ?: "preferred"
        val uvRequirement = UvRequirement.fromJson(userVerification)

        // Fail here rather than mint a credential the relying party asked to
        // be user-verified but which was not.
        val uvCompliant = UserVerificationCompliance.enforce(
            requirement = uvRequirement,
            verificationPerformed = userVerified,
            strict = settingsRepository.getSettings().strictUserVerification,
            ceremony = "Passkey registration for $rpId"
        )
        if (!uvCompliant) {
            Log.w(
                TAG,
                "Relying party required user verification and none was performed. " +
                    "Proceeding with UV=0 because strict user verification is disabled; " +
                    "a conformant relying party will reject this response."
            )
        }
        val isDiscoverable = residentKey == "required" || residentKey == "preferred"

        // Check for excluded credentials
        val excludeCredentials = requestJson.optJSONArray("excludeCredentials")
        if (excludeCredentials != null) {
            for (i in 0 until excludeCredentials.length()) {
                val excluded = excludeCredentials.getJSONObject(i)
                val excludedId = excluded.getString("id")
                // Scoped to this relying party. A credential id is only
                // meaningful within the RP that issued it, so an unscoped
                // lookup would let one RP block registration at another.
                if (credentialDao.getByCredentialId(excludedId)?.rpId == rpId) {
                    throw CredentialCreationException("Credential already exists for this user")
                }
            }
        }

        // Generate credential ID
        val credentialId = generateCredentialId()
        val credentialIdBase64 = Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        // Determine auth duration based on userVerification
        val requestedAuthDuration = when (uvRequirement) {
            UvRequirement.REQUIRED -> 0 // Require auth for every use
            UvRequirement.PREFERRED -> 5 // Short grace period
            UvRequirement.DISCOURAGED -> -1 // No auth required
        }

        // Keystore refuses to create an auth-bound key when the device has no
        // usable authenticator enrolled, which would fail the whole ceremony.
        // CredentialSelectorActivity already skips the prompt in that case, so
        // bind the key to match: no authenticator, no auth-bound key.
        val authDurationSeconds = if (requestedAuthDuration >= 0 && !canAuthenticateUser()) {
            Log.w(
                TAG,
                "No biometric or device credential enrolled; creating a key that is " +
                    "not auth-bound (requested userVerification=$userVerification)"
            )
            -1
        } else {
            requestedAuthDuration
        }

        // Generate key in Android Keystore
        Log.i(TAG, "Generating key: credentialId=$credentialIdBase64, authDuration=$authDurationSeconds")
        val publicKeyCose = try {
            keystoreManager.generateKeyWithAuthDuration(
                credentialId = credentialIdBase64,
                authDurationSeconds = authDurationSeconds,
                requireStrongBox = false
            )
        } catch (e: Exception) {
            Log.e(TAG, "Key generation failed", e)
            throw CredentialCreationException("Failed to generate key", e)
        }
        Log.i(TAG, "Key generated: COSE publicKey size=${publicKeyCose.size}")

        // Store credential metadata
        val credentialMetadata = CredentialMetadataEntity(
            credentialId = credentialIdBase64,
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = userName,
            userDisplayName = userDisplayName,
            publicKeyCose = publicKeyCose,
            signCount = 0,
            isDiscoverable = isDiscoverable
        )

        try {
            credentialDao.insert(credentialMetadata)
        } catch (e: Exception) {
            // Clean up the key if metadata storage fails
            keystoreManager.deleteKey(credentialIdBase64)
            throw CredentialCreationException("Failed to store credential metadata", e)
        }

        // Also store in unified key store for bidirectional key sharing
        try {
            keyDao.insert(KeyEntity(
                keyId = credentialIdBase64,
                keyType = "fido2",
                algorithm = "ES256",
                label = rpName,
                publicKeyCose = publicKeyCose,
                keySizeBits = 256,
                strongBoxBacked = keystoreManager.isStrongBoxAvailable(),
                // What the key IS, not what the ceremony asked for. Recording the
                // request would claim an auth-bound key on a device with nothing
                // enrolled, and the assertion path reads this flag to decide the
                // UV bit — it would then sign UV=1 for an unverified ceremony.
                biometricRequired = authDurationSeconds >= 0,
                authDurationSeconds = authDurationSeconds,
                exportable = false,
                shareable = false,
                source = "local",
                createdAt = System.currentTimeMillis(),
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = userDisplayName,
                isDiscoverable = isDiscoverable,
                signCount = 0
            ))
        } catch (e: Exception) {
            // Non-fatal - credential_metadata is the primary store for CredentialProvider
            Log.w(TAG, "Failed to sync to unified key store: ${e.message}")
        }

        // Log successful registration
        AuditLogger.logFido2Registration(
            keyId = credentialIdBase64,
            keyLabel = rpName,
            rpId = rpId,
            userName = userName
        )

        // Get DER-encoded (SPKI) public key for WebAuthn Level 3 response
        val publicKeyDer = keystoreManager.getPublicKey(credentialIdBase64)?.encoded
            ?: throw CredentialCreationException("Failed to retrieve public key after generation")
        Log.i(TAG, "DER publicKey size=${publicKeyDer.size} (COSE=${publicKeyCose.size})")

        // Build attestation response
        Log.i(TAG, "Building attestation response: credIdSize=${credentialId.size}, rpId=$rpId, clientDataJson=${clientDataJsonBase64 != null}")
        val responseJson = buildAttestationResponse(
            credentialId = credentialId,
            rpId = rpId,
            publicKeyCose = publicKeyCose,
            publicKeyDer = publicKeyDer,
            clientDataJsonBase64 = clientDataJsonBase64,
            userVerified = userVerified
        )
        Log.i(TAG, "=== handleCreateCredential SUCCESS: response length=${responseJson.length} ===")
        return responseJson
    }

    /**
     * Generate a random credential ID.
     */
    private fun generateCredentialId(): ByteArray {
        val credentialId = ByteArray(CREDENTIAL_ID_LENGTH)
        SecureRandom().nextBytes(credentialId)
        return credentialId
    }

    /**
     * Validate that ES256 algorithm is supported in the request.
     */
    private fun validateAlgorithmSupport(pubKeyCredParams: org.json.JSONArray) {
        var es256Supported = false
        for (i in 0 until pubKeyCredParams.length()) {
            val param = pubKeyCredParams.getJSONObject(i)
            val alg = param.getInt("alg")
            if (alg == COSE_ALG_ES256) {
                es256Supported = true
                break
            }
        }
        if (!es256Supported) {
            throw InvalidRequestException("ES256 algorithm not supported in request")
        }
    }

    /**
     * Build the attestation response JSON.
     */
    private fun buildAttestationResponse(
        credentialId: ByteArray,
        rpId: String,
        publicKeyCose: ByteArray,
        publicKeyDer: ByteArray,
        clientDataJsonBase64: String? = null,
        userVerified: Boolean
    ): String {
        // Build authenticator data. The UV bit must report whether the user
        // was really verified — a relying party trusts it.
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val flags: Byte = UserVerificationCompliance.flags(
            userPresent = true,
            userVerified = userVerified,
            attestedCredentialData = true
        )
        val signCount = ByteArray(4) // Initial count of 0

        // Attested credential data
        val aaguid = PASSKEY_AAGUID
        val credIdLength = byteArrayOf(
            ((credentialId.size shr 8) and 0xFF).toByte(),
            (credentialId.size and 0xFF).toByte()
        )

        val authData = rpIdHash + flags + signCount + aaguid + credIdLength + credentialId + publicKeyCose

        // Build attestation object (self-attestation / none attestation)
        val attestationObject = buildAttestationObject(authData)

        // Build response JSON
        val response = JSONObject().apply {
            put("id", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
            put("rawId", Base64.encodeToString(credentialId, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("response", JSONObject().apply {
                if (clientDataJsonBase64 != null) {
                    put("clientDataJSON", clientDataJsonBase64)
                }
                put("attestationObject", Base64.encodeToString(attestationObject, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
                put("authenticatorData", Base64.encodeToString(authData, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
                put("publicKeyAlgorithm", COSE_ALG_ES256)
                put("publicKey", Base64.encodeToString(publicKeyDer, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
                put("transports", org.json.JSONArray().apply {
                    put("internal")
                })
            })
            put("clientExtensionResults", JSONObject())
        }

        return response.toString()
    }

    /**
     * Build CBOR-encoded attestation object with "none" attestation.
     */
    private fun buildAttestationObject(authData: ByteArray): ByteArray {
        // Simple CBOR map: {"fmt": "none", "attStmt": {}, "authData": authData}
        val buffer = java.io.ByteArrayOutputStream()

        // Map with 3 items
        buffer.write(0xA3)

        // "fmt": "none"
        buffer.write(0x63) // text string length 3
        buffer.write("fmt".toByteArray())
        buffer.write(0x64) // text string length 4
        buffer.write("none".toByteArray())

        // "attStmt": {}
        buffer.write(0x67) // text string length 7
        buffer.write("attStmt".toByteArray())
        buffer.write(0xA0) // empty map

        // "authData": bytes
        buffer.write(0x68) // text string length 8
        buffer.write("authData".toByteArray())
        // Encode byte string length
        if (authData.size <= 23) {
            buffer.write(0x40 or authData.size)
        } else if (authData.size <= 255) {
            buffer.write(0x58)
            buffer.write(authData.size)
        } else {
            buffer.write(0x59)
            buffer.write(authData.size shr 8)
            buffer.write(authData.size and 0xFF)
        }
        buffer.write(authData)

        return buffer.toByteArray()
    }

    companion object {
        private const val TAG = "CreateCredentialHandler"
        private const val CREDENTIAL_ID_LENGTH = 32
        private const val COSE_ALG_ES256 = -7

        // Privileged browser allowlist for origin resolution
        private val BROWSER_PRIVILEGED_ALLOWLIST = BrowserAllowlist.PRIVILEGED_BROWSERS

        // Authenticator data flags
        private const val FLAGS_UP: Byte = 0x01 // User Present
        private const val FLAGS_UV: Byte = 0x04 // User Verified
        private const val FLAGS_AT: Byte = 0x40 // Attested Credential Data

        // AAGUID for this authenticator (all zeros for self-attestation)
        private val PASSKEY_AAGUID = ByteArray(16)
    }
}
