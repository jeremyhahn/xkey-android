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
package com.automatethethings.xkey.truststore

import android.util.Log
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Result of IDevID certificate verification.
 */
sealed class IDevIDVerificationResult {
    /**
     * Certificate is valid and trusted.
     */
    data class Trusted(
        val trustLevel: String,          // "android-ca", "external-ca", etc.
        val subjectDN: String,
        val notAfter: Long,
        val fingerprint: String
    ) : IDevIDVerificationResult()

    /**
     * Certificate is self-signed (NEVER trusted).
     */
    data object SelfSigned : IDevIDVerificationResult()

    /**
     * Certificate chain is invalid or doesn't lead to a trusted root.
     */
    data class Untrusted(val reason: String) : IDevIDVerificationResult()

    /**
     * No IDevID certificate was provided.
     */
    data object NoCertificate : IDevIDVerificationResult()

    /**
     * Verification failed due to an error.
     */
    data class Error(val message: String) : IDevIDVerificationResult()
}

/**
 * Verifies IDevID certificates from paired laptops.
 *
 * IMPORTANT: Self-signed certificates are NEVER accepted.
 */
class IDevIDVerifier(
    private val trustStoreRepository: TrustStoreRepository
) {
    companion object {
        private const val TAG = "IDevIDVerifier"
    }

    /**
     * Verify an IDevID certificate chain from a paired laptop.
     *
     * @param certificateChain The DER-encoded certificate chain (leaf first)
     * @return IDevIDVerificationResult indicating the trust status
     */
    suspend fun verify(certificateChain: List<ByteArray>): IDevIDVerificationResult {
        if (certificateChain.isEmpty()) {
            return IDevIDVerificationResult.NoCertificate
        }

        try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val certs = certificateChain.map { der ->
                certFactory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            }

            val leafCert = certs.first()

            // Check for self-signed (NEVER accept)
            if (leafCert.subjectX500Principal == leafCert.issuerX500Principal) {
                Log.w(TAG, "Rejecting self-signed IDevID certificate")
                return IDevIDVerificationResult.SelfSigned
            }

            // Verify chain against trust store
            val verificationResult = trustStoreRepository.verifyIDevIDChain(certificateChain)

            return when (verificationResult) {
                is VerificationResult.Valid -> {
                    val fingerprint = computeFingerprint(leafCert)
                    IDevIDVerificationResult.Trusted(
                        trustLevel = verificationResult.trustLevel,
                        subjectDN = leafCert.subjectX500Principal.name,
                        notAfter = leafCert.notAfter.time,
                        fingerprint = fingerprint
                    )
                }
                is VerificationResult.Invalid -> {
                    IDevIDVerificationResult.Untrusted(verificationResult.error)
                }
                VerificationResult.SelfSigned -> {
                    IDevIDVerificationResult.SelfSigned
                }
                VerificationResult.NoTrustAnchors -> {
                    IDevIDVerificationResult.Untrusted("No trusted CA certificates configured")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "IDevID verification failed", e)
            return IDevIDVerificationResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Check if a device has a verified IDevID and it's still valid.
     *
     * @param certificateDER The stored IDevID certificate (DER)
     * @param verifiedAt When the certificate was last verified
     * @param trustLevel The stored trust level
     * @return true if the IDevID is still considered valid
     */
    fun isIDevIDStillValid(
        certificateDER: ByteArray?,
        verifiedAt: Long?,
        trustLevel: String?
    ): Boolean {
        if (certificateDER == null || verifiedAt == null || trustLevel == null) {
            return false
        }

        try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(
                ByteArrayInputStream(certificateDER)
            ) as X509Certificate

            // Check expiry
            val now = System.currentTimeMillis()
            if (now > cert.notAfter.time) {
                return false
            }

            // Self-signed is never valid
            if (cert.subjectX500Principal == cert.issuerX500Principal) {
                return false
            }

            return true
        } catch (e: Exception) {
            return false
        }
    }

    private fun computeFingerprint(cert: X509Certificate): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(cert.encoded)
        return hash.joinToString("") { "%02x".format(it) }
    }
}
