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
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.CredentialAssertionException
import com.automatethethings.xkey.credential.UserVerificationCompliance
import com.automatethethings.xkey.credential.UvRequirement
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.credential.InvalidRequestException
import com.automatethethings.xkey.credential.PasskeySignCounter
import com.automatethethings.xkey.credential.RelyingPartyOrigin
import com.automatethethings.xkey.credential.NoCredentialsFoundException
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import kotlinx.coroutines.CancellationException
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Handles credential assertion (authentication) requests from CredentialManager.
 *
 * This handler processes WebAuthn getAssertion requests, signing challenges
 * with existing passkey credentials stored in Android Keystore.
 *
 * Two-phase flow:
 * 1. Begin phase: Returns matching CredentialEntry options for user to select
 * 2. Final phase: Signs the challenge with the selected credential
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class GetCredentialHandler(
    private val context: Context,
    private val biometricHelper: BiometricHelper? = null
) {
    private val keystoreManager = KeystoreManager(context)
    private val database = XKeyDatabase.getInstance(context)
    private val credentialDao = database.credentialMetadataDao()
    private val keyDao = database.keyDao()
    private val signCounter = PasskeySignCounter(credentialDao, keyDao)
    private val settingsRepository = BiometricSettingsRepository(context)

    /**
     * Handle the begin phase of credential assertion.
     *
     * Queries stored credentials matching the request and returns
     * CredentialEntry options for the system UI to display.
     *
     * @param request The begin get credential request.
     * @return Response containing credential entries for user selection.
     */
    suspend fun handleBeginGetCredential(
        request: BeginGetCredentialRequest
    ): BeginGetCredentialResponse {
        Log.d(TAG, "handleBeginGetCredential: ${request.beginGetCredentialOptions.size} options")
        val credentialEntries = mutableListOf<CredentialEntry>()

        for (option in request.beginGetCredentialOptions) {
            Log.d(TAG, "  option type: ${option.javaClass.name}")
            if (option is BeginGetPublicKeyCredentialOption) {
                val entries = processPublicKeyOption(option)
                Log.d(TAG, "  matched ${entries.size} credentials")
                credentialEntries.addAll(entries)
            }
        }

        Log.d(TAG, "Returning ${credentialEntries.size} credential entries")
        return BeginGetCredentialResponse.Builder()
            .setCredentialEntries(credentialEntries)
            .build()
    }

    /**
     * Process a public key credential option and return matching entries.
     */
    private suspend fun processPublicKeyOption(
        option: BeginGetPublicKeyCredentialOption
    ): List<CredentialEntry> {
        val requestJson = JSONObject(option.requestJson)
        val rpId = requestJson.getString("rpId")
        val allowCredentials = requestJson.optJSONArray("allowCredentials")

        val matchingCredentials = if (allowCredentials != null && allowCredentials.length() > 0) {
            // Filter by allowed credentials
            findAllowedCredentials(rpId, allowCredentials)
        } else {
            // Discoverable credential request - return all credentials for rpId
            credentialDao.getDiscoverableByRpId(rpId)
        }

        return matchingCredentials.map { credential ->
            PublicKeyCredentialEntry.Builder(
                context,
                username = credential.userName.ifEmpty { credential.userDisplayName },
                pendingIntent = CredentialPendingIntentHelper.createGetPendingIntent(
                    context,
                    credential.credentialId,
                    option.requestJson
                ),
                beginGetPublicKeyCredentialOption = option
            )
                .setDisplayName(credential.userDisplayName)
                .setLastUsedTime(java.time.Instant.ofEpochMilli(credential.lastUsedAt))
                .build()
        }
    }

    /**
     * Find credentials matching the allowCredentials list.
     */
    private suspend fun findAllowedCredentials(
        rpId: String,
        allowCredentials: JSONArray
    ): List<CredentialMetadataEntity> {
        val allowedIds = mutableSetOf<String>()
        for (i in 0 until allowCredentials.length()) {
            val cred = allowCredentials.getJSONObject(i)
            allowedIds.add(cred.getString("id"))
        }

        val rpCredentials = credentialDao.getByRpId(rpId)
        return rpCredentials.filter { it.credentialId in allowedIds }
    }

    /**
     * Handle the final phase of credential assertion.
     *
     * Signs the challenge with the selected credential after biometric
     * authentication.
     *
     * @param request The provider get credential request.
     * @param credentialId The selected credential ID.
     * @return JSON response containing the assertion.
     */
    suspend fun handleGetCredential(
        request: ProviderGetCredentialRequest,
        credentialId: String
    ): String {
        Log.d(TAG, "handleGetCredential: credentialId=$credentialId")

        val credential = credentialDao.getByCredentialId(credentialId)
            ?: throw NoCredentialsFoundException(credentialId)
        Log.d(TAG, "Found credential: rpId=${credential.rpId}, signCount=${credential.signCount}")

        // Log available credential options for debugging
        Log.d(TAG, "credentialOptions count: ${request.credentialOptions.size}")
        for ((i, opt) in request.credentialOptions.withIndex()) {
            Log.d(TAG, "  option[$i]: ${opt.javaClass.name}, type=${opt.type}")
        }

        // Get the public key credential option from the request
        val credentialOption = request.credentialOptions.firstOrNull { it is GetPublicKeyCredentialOption }
            as? GetPublicKeyCredentialOption
            ?: throw InvalidRequestException("No public key credential option found in ${request.credentialOptions.size} options")

        val requestJson = try {
            JSONObject(credentialOption.requestJson)
        } catch (e: Exception) {
            throw InvalidRequestException("Failed to parse request JSON", e)
        }
        Log.d(TAG, "requestJson: $requestJson")

        // A request missing rpId is malformed; report it as such rather than
        // letting a raw JSONException escape to a caller that expects a
        // CredentialProviderException.
        val rpId = try {
            requestJson.getString("rpId")
        } catch (e: JSONException) {
            throw InvalidRequestException("Request is missing rpId", e)
        }
        if (rpId != credential.rpId) {
            throw InvalidRequestException("RP ID mismatch: request=$rpId, stored=${credential.rpId}")
        }

        // Get clientDataHash - provided by browser through Credential Manager framework
        var clientDataHash = credentialOption.clientDataHash
        var clientDataJsonBase64: String? = null
        Log.d(TAG, "clientDataHash provided: ${clientDataHash != null}")

        if (clientDataHash == null) {
            // Browser didn't provide clientDataHash - construct clientDataJSON
            // ourselves. Because this provider is signing the client data, the
            // origin it binds must be one Android verified for the caller.
            // Deriving an origin from the requested rpId would let any app
            // obtain an assertion for a site it does not control.
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
                throw CredentialAssertionException(
                    "Could not verify the calling app's origin ($callingPackage)",
                    e
                )
            }
            val origin = verifiedOrigin ?: throw CredentialAssertionException(
                "Calling app $callingPackage provided no client data hash and has no " +
                    "verified web origin; refusing to sign an assertion"
            )
            Log.d(TAG, "Using origin: $origin")

            // The origin goes into clientDataJSON and the rpId is hashed into
            // authenticator data. Signing a response where they are unrelated
            // would let an app obtain an assertion for a site it does not control.
            if (!RelyingPartyOrigin.isRpIdValidForOrigin(rpId, origin)) {
                throw CredentialAssertionException(
                    "Relying party $rpId is not valid for the caller's origin $origin"
                )
            }

            val clientDataJson = JSONObject().apply {
                put("type", "webauthn.get")
                put("challenge", challenge)
                put("origin", origin)
                put("crossOrigin", false)
            }
            val clientDataJsonBytes = clientDataJson.toString().toByteArray(Charsets.UTF_8)
            clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJsonBytes)
            clientDataJsonBase64 = Base64.encodeToString(
                clientDataJsonBytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
        }

        // Decide user verification BEFORE building authenticator data: the UV
        // bit is inside authData, which is what gets signed, so it cannot be
        // corrected afterwards.
        val uvRequirement = UvRequirement.fromJson(requestJson.optString("userVerification"))

        // An auth-bound key forces CryptoObject-backed verification during
        // signing, so verification is guaranteed for those keys.
        val keyRequiresAuth = try {
            keyDao.getByKeyId(credentialId)?.biometricRequired ?: false
        } catch (e: Exception) {
            Log.w(TAG, "Could not read key policy, assuming not auth-bound: ${e.message}")
            false
        }
        val canVerify = biometricHelper?.isBiometricAvailable() == true

        val willVerify = keyRequiresAuth || when (uvRequirement) {
            UvRequirement.REQUIRED -> canVerify
            UvRequirement.PREFERRED -> canVerify
            UvRequirement.DISCOURAGED -> false
        }

        val uvCompliant = UserVerificationCompliance.enforce(
            requirement = uvRequirement,
            verificationPerformed = willVerify,
            strict = settingsRepository.getSettings().strictUserVerification,
            ceremony = "Passkey authentication for $rpId"
        )
        if (!uvCompliant) {
            Log.w(
                TAG,
                "Relying party required user verification and none was performed. " +
                    "Proceeding with UV=0 because strict user verification is disabled; " +
                    "a conformant relying party will reject this response."
            )
        }

        // We are asserting UV=1, so verification must actually occur: sign
        // through the biometric-bound path, never the silent one. Refusals and
        // the explicit verification come before the counter advances, so a
        // refused ceremony never consumes a value.
        val verifyingHelper = if (willVerify) {
            val helper = biometricHelper
                ?: throw CredentialAssertionException(
                    "User verification is required but no biometric prompt is available"
                )
            if (!keyRequiresAuth) {
                // Keystore only demands a prompt for an auth-bound key, so for
                // any other key sign() would take its silent path and we would
                // assert UV=1 without anyone being verified. Verify explicitly.
                try {
                    helper.authenticateWithoutCrypto(
                        title = "Sign In",
                        subtitle = "Authenticate to $rpId"
                    )
                } catch (bioEx: Exception) {
                    Log.e(TAG, "Verification failed", bioEx)
                    throw CredentialAssertionException("Biometric signing failed", bioEx)
                }
            }
            helper
        } else {
            null
        }

        // The phone backend serves this passkey too, so the counter comes from
        // the one both paths share. It advances before signing: a failed
        // signature leaves a gap, never a reused value. A counter that cannot
        // be persisted refuses the assertion before anything is signed.
        val signCount = try {
            signCounter.next(credentialId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Could not persist the signature counter", e)
            throw CredentialAssertionException("Could not persist the signature counter", e)
        }

        val authData = buildAuthenticatorData(
            rpId = rpId,
            signCount = signCount,
            userVerified = willVerify
        )
        Log.d(TAG, "authData size: ${authData.size}, userVerified=$willVerify")

        // Sign: authData || clientDataHash
        // SHA256withECDSA hashes internally, so pass raw concatenation
        val dataToSign = authData + clientDataHash

        val signature = if (verifyingHelper != null) {
            try {
                Log.d(TAG, "Signing with verification, credentialId=$credentialId")
                keystoreManager.sign(
                    credentialId, dataToSign, verifyingHelper,
                    title = "Sign In",
                    subtitle = "Authenticate to $rpId"
                )
            } catch (bioEx: Exception) {
                Log.e(TAG, "Verified signing failed", bioEx)
                throw CredentialAssertionException("Biometric signing failed", bioEx)
            }
        } else {
            try {
                Log.d(TAG, "Signing without verification, credentialId=$credentialId")
                keystoreManager.signWithoutBiometric(credentialId, dataToSign)
            } catch (e: BiometricRequiredException) {
                // The key turned out to be auth-bound after all. Rather than
                // sign with UV=0 baked into authData while actually verifying,
                // fail: the response would misreport the ceremony.
                Log.e(TAG, "Key unexpectedly requires authentication", e)
                throw CredentialAssertionException(
                    "Key requires user verification but the ceremony was prepared without it", e
                )
            } catch (e: Exception) {
                Log.e(TAG, "Signing failed", e)
                throw CredentialAssertionException("Failed to sign assertion", e)
            }
        }
        Log.d(TAG, "Signature generated, size=${signature.size}")

        // Record usage in unified key store
        try {
            keyDao.recordUsage(credentialId)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to sync to unified key store: ${e.message}")
        }

        // Log successful authentication
        AuditLogger.logFido2Authentication(
            keyId = credentialId,
            keyLabel = credential.rpName ?: credential.userDisplayName,
            rpId = rpId
        )

        // Build response
        val response = buildAssertionResponse(
            credentialId = credentialId,
            authData = authData,
            signature = signature,
            userHandle = credential.userId,
            clientDataJsonBase64 = clientDataJsonBase64
        )
        Log.d(TAG, "Assertion response built: ${response.take(200)}...")
        return response
    }

    /**
     * Build authenticator data for assertion.
     */
    private fun buildAuthenticatorData(
        rpId: String,
        signCount: Long,
        userVerified: Boolean
    ): ByteArray {
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        // The UV bit must report whether the user was really verified.
        val flags: Byte = UserVerificationCompliance.flags(
            userPresent = true,
            userVerified = userVerified
        )

        val signCountBytes = byteArrayOf(
            ((signCount shr 24) and 0xFF).toByte(),
            ((signCount shr 16) and 0xFF).toByte(),
            ((signCount shr 8) and 0xFF).toByte(),
            (signCount and 0xFF).toByte()
        )

        return rpIdHash + flags + signCountBytes
    }

    /**
     * Build the assertion response JSON.
     */
    private fun buildAssertionResponse(
        credentialId: String,
        authData: ByteArray,
        signature: ByteArray,
        userHandle: String,
        clientDataJsonBase64: String? = null
    ): String {
        val response = JSONObject().apply {
            put("id", credentialId)
            put("rawId", credentialId)
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("response", JSONObject().apply {
                put("authenticatorData", Base64.encodeToString(authData, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
                put("signature", Base64.encodeToString(signature, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
                put("userHandle", userHandle)
                if (clientDataJsonBase64 != null) {
                    put("clientDataJSON", clientDataJsonBase64)
                }
            })
            put("clientExtensionResults", JSONObject())
        }

        return response.toString()
    }

    companion object {
        private const val TAG = "GetCredentialHandler"

        // Authenticator data flags
        private const val FLAGS_UP: Byte = 0x01 // User Present
        private const val FLAGS_UV: Byte = 0x04 // User Verified

        // Privileged browser allowlist for origin resolution
        private val BROWSER_PRIVILEGED_ALLOWLIST = BrowserAllowlist.PRIVILEGED_BROWSERS
    }
}
