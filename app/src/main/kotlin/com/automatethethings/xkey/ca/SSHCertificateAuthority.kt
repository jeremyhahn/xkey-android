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
package com.automatethethings.xkey.ca

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.crypto.SSHCertificateEncoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * Result of SSH certificate issuance.
 */
data class IssuedSSHCertificate(
    val certificate: String,
    val certificateType: String,
    val serialNumber: Long,
    val keyId: String,
    val validPrincipals: List<String>,
    val validAfter: Long,
    val validBefore: Long,
    val fingerprint: String
)

/**
 * SSH Certificate Authority that uses AndroidCA's hardware-backed keys to sign
 * OpenSSH certificates.
 *
 * Supports issuing both user and host certificates. All signing operations use
 * Android Keystore (StrongBox/TEE) — private keys never leave hardware.
 */
class SSHCertificateAuthority(private val context: Context) {

    companion object {
        private const val TAG = "SSHCertificateAuthority"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        private const val DEFAULT_USER_VALIDITY_DAYS = 365
        private const val DEFAULT_HOST_VALIDITY_DAYS = 730

        val DEFAULT_USER_EXTENSIONS: Map<String, String> = mapOf(
            "permit-X11-forwarding" to "",
            "permit-agent-forwarding" to "",
            "permit-port-forwarding" to "",
            "permit-pty" to "",
            "permit-user-rc" to ""
        )
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    /**
     * Issue an SSH user certificate.
     *
     * @param publicKey The user's public key to certify
     * @param keyId Key identifier string (e.g., "user@example.com")
     * @param principals List of valid usernames
     * @param validityDays Certificate validity in days
     * @param extensions Map of extensions (default: standard user extensions)
     * @param criticalOptions Map of critical options (default: empty)
     * @param signingAlias Android Keystore alias for the CA signing key
     * @return IssuedSSHCertificate with the full certificate string
     */
    suspend fun issueUserCertificate(
        publicKey: PublicKey,
        keyId: String,
        principals: List<String>,
        validityDays: Int = DEFAULT_USER_VALIDITY_DAYS,
        extensions: Map<String, String> = DEFAULT_USER_EXTENSIONS,
        criticalOptions: Map<String, String> = emptyMap(),
        signingAlias: String = AndroidCA.INTERMEDIATE_CA_ALIAS
    ): IssuedSSHCertificate = withContext(Dispatchers.Default) {
        Log.i(TAG, "Issuing SSH user certificate for: $keyId")

        issueCertificate(
            publicKey = publicKey,
            certType = SSHCertificateEncoder.SSH_CERT_TYPE_USER,
            keyId = keyId,
            principals = principals,
            validityDays = validityDays,
            extensions = extensions,
            criticalOptions = criticalOptions,
            signingAlias = signingAlias,
            certificateTypeLabel = "user"
        )
    }

    /**
     * Issue an SSH host certificate.
     *
     * @param publicKey The host's public key to certify
     * @param keyId Key identifier string (e.g., "server.example.com")
     * @param hostnames List of valid hostnames
     * @param validityDays Certificate validity in days
     * @param signingAlias Android Keystore alias for the CA signing key
     * @return IssuedSSHCertificate with the full certificate string
     */
    suspend fun issueHostCertificate(
        publicKey: PublicKey,
        keyId: String,
        hostnames: List<String>,
        validityDays: Int = DEFAULT_HOST_VALIDITY_DAYS,
        signingAlias: String = AndroidCA.INTERMEDIATE_CA_ALIAS
    ): IssuedSSHCertificate = withContext(Dispatchers.Default) {
        Log.i(TAG, "Issuing SSH host certificate for: $keyId")

        issueCertificate(
            publicKey = publicKey,
            certType = SSHCertificateEncoder.SSH_CERT_TYPE_HOST,
            keyId = keyId,
            principals = hostnames,
            validityDays = validityDays,
            extensions = emptyMap(),
            criticalOptions = emptyMap(),
            signingAlias = signingAlias,
            certificateTypeLabel = "host"
        )
    }

    private fun issueCertificate(
        publicKey: PublicKey,
        certType: Int,
        keyId: String,
        principals: List<String>,
        validityDays: Int,
        extensions: Map<String, String>,
        criticalOptions: Map<String, String>,
        signingAlias: String,
        certificateTypeLabel: String
    ): IssuedSSHCertificate {
        val signingKey = keyStore.getKey(signingAlias, null) as PrivateKey
        val signingCert = keyStore.getCertificate(signingAlias)
            ?: throw IllegalStateException("CA certificate not found for alias: $signingAlias")
        val caPublicKey = signingCert.publicKey

        val serial = System.currentTimeMillis() / 1000
        val now = System.currentTimeMillis() / 1000
        val validAfter = now
        val validBefore = now + (validityDays.toLong() * 86400)

        val body = SSHCertificateEncoder.buildCertificateBody(
            subjectPublicKey = publicKey,
            serial = serial,
            certType = certType,
            keyId = keyId,
            validPrincipals = principals,
            validAfter = validAfter,
            validBefore = validBefore,
            criticalOptions = criticalOptions,
            extensions = extensions,
            caPublicKey = caPublicKey
        )

        val certificate = SSHCertificateEncoder.buildSignedCertificate(
            body = body,
            sign = { data ->
                val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
                sig.initSign(signingKey)
                sig.update(data)
                sig.sign()
            },
            caPublicKey = caPublicKey
        )

        val digest = MessageDigest.getInstance("SHA-256")
        val certBytes = android.util.Base64.decode(
            certificate.substringAfter(' '),
            android.util.Base64.NO_WRAP
        )
        val fingerprint = digest.digest(certBytes)
            .joinToString("") { "%02x".format(it) }

        Log.i(TAG, "SSH $certificateTypeLabel certificate issued: serial=$serial, keyId=$keyId")

        return IssuedSSHCertificate(
            certificate = certificate,
            certificateType = certificateTypeLabel,
            serialNumber = serial,
            keyId = keyId,
            validPrincipals = principals,
            validAfter = validAfter,
            validBefore = validBefore,
            fingerprint = fingerprint
        )
    }
}
