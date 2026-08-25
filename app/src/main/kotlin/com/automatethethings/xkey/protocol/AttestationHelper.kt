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
package com.automatethethings.xkey.protocol

import android.content.Context
import android.util.Base64
import android.util.Log
import com.automatethethings.xkey.ble.BleClient
import com.automatethethings.xkey.util.getStringOrNull
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Handles requesting attestation from the paired laptop/desktop.
 *
 * When the user clicks "Re-attest" on a paired device, this class:
 * 1. Generates a challenge nonce
 * 2. Sends `remote.attestDevice` to the laptop
 * 3. Receives and verifies the laptop's attestation
 * 4. Returns the verification result for storage
 *
 * This is the phone requesting the LAPTOP to prove its identity,
 * NOT the phone attesting itself.
 */
class AttestationHelper(private val context: Context) {

    companion object {
        private const val TAG = "AttestationHelper"
        private const val METHOD_REMOTE_ATTEST_DEVICE = "remote.attestDevice"
        private const val JSONRPC_VERSION = "2.0"
        private const val NONCE_SIZE = 32
        private const val BASE64_FLAGS = Base64.NO_WRAP
    }

    private val secureRandom = SecureRandom()

    /**
     * Requests the laptop to attest itself to the phone.
     *
     * @param client The connected BLE client
     * @return AttestationResult with verification status and device info
     */
    suspend fun requestLaptopAttestation(client: BleClient): AttestationResult {
        try {
            // Generate challenge nonce
            val nonce = ByteArray(NONCE_SIZE)
            secureRandom.nextBytes(nonce)
            Log.d(TAG, "Generated challenge nonce: ${nonce.size} bytes")

            // Build remote.attestDevice request
            val params = JSONObject().apply {
                put("nonce", Base64.encodeToString(nonce, BASE64_FLAGS))
            }

            val request = JSONObject().apply {
                put("jsonrpc", JSONRPC_VERSION)
                put("id", System.currentTimeMillis())
                put("method", METHOD_REMOTE_ATTEST_DEVICE)
                put("params", params)
            }

            Log.d(TAG, "Sending remote.attestDevice request to laptop")
            val responseBytes = client.sendRequest(request.toString().toByteArray(Charsets.UTF_8))
            val response = JSONObject(String(responseBytes, Charsets.UTF_8))

            // Check for error
            if (response.has("error")) {
                val error = response.getJSONObject("error")
                val message = error.optString("message", "Unknown error")
                Log.e(TAG, "Laptop attestation request failed: $message")
                return AttestationResult.Failure(message)
            }

            // Parse result
            val result = response.getJSONObject("result")

            // Verify nonce echo
            val returnedNonce = Base64.decode(result.getString("nonce"), BASE64_FLAGS)
            if (!returnedNonce.contentEquals(nonce)) {
                Log.e(TAG, "Nonce mismatch - possible replay attack")
                return AttestationResult.Failure("Nonce mismatch - attestation rejected")
            }

            val format = result.getString("format")
            val securityLevel = result.getString("securityLevel")
            val bootHashHex = result.getStringOrNull("bootHashHex")
            val bootStateVerified = result.optBoolean("bootStateVerified", false)

            // Parse certificate chain and compute device fingerprint
            val certChainArray = result.optJSONArray("certificateChain")
            var deviceFingerprint: String? = null

            if (certChainArray != null && certChainArray.length() > 0) {
                // The device identity is the per-device ATTESTED KEY (#93), not
                // the attestation ROOT — the old SHA-256-of-the-last-cert value,
                // which was a Google Hardware Attestation Root shared by every
                // handset under it (a vendor identity, not a device one). Hash
                // the leaf (index 0) SubjectPublicKeyInfo, matching go-xkms
                // sha256(cert.RawSubjectPublicKeyInfo). See docs/12 and #93.
                val leafCertB64 = certChainArray.getString(0)
                val leafCertBytes = Base64.decode(leafCertB64, BASE64_FLAGS)
                deviceFingerprint = AttestedKeyFingerprint.hexOf(leafCertBytes)

                Log.d(TAG, "Attested-key fingerprint: ${deviceFingerprint.take(16)}...")
            }

            Log.i(TAG, "Laptop attestation verified: format=$format, securityLevel=$securityLevel")

            return AttestationResult.Success(
                format = format,
                securityLevel = securityLevel,
                bootHashHex = bootHashHex,
                bootStateVerified = bootStateVerified,
                deviceFingerprint = deviceFingerprint
            )

        } catch (e: Exception) {
            Log.e(TAG, "Laptop attestation request failed", e)
            return AttestationResult.Failure(e.message ?: "Unknown error")
        }
    }

    /**
     * Result of requesting laptop attestation.
     */
    sealed class AttestationResult {
        /**
         * Laptop attestation was successful.
         */
        data class Success(
            val format: String,           // "tpm2", "software", etc.
            val securityLevel: String,    // "hardware", "software"
            val bootHashHex: String?,     // Platform boot hash
            val bootStateVerified: Boolean,
            val deviceFingerprint: String?
        ) : AttestationResult()

        /**
         * Laptop attestation failed.
         */
        data class Failure(val reason: String) : AttestationResult()
    }
}
