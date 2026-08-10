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

/**
 * Subject Alternative Names for X.509 certificates.
 */
data class SubjectAlternativeNames(
    val dnsNames: List<String> = emptyList(),
    val ipAddresses: List<String> = emptyList(),
    val emailAddresses: List<String> = emptyList()
)

/**
 * Sealed class hierarchy defining X.509 extension profiles per certificate type.
 *
 * Each profile specifies the Key Usage bits, Extended Key Usage OIDs, and
 * Subject Alternative Names appropriate for its certificate type.
 */
sealed class CertificateProfile {
    abstract val validityDays: Int
    abstract val keyUsageBits: Int
    abstract val extendedKeyUsageOIDs: List<String>?
    abstract val san: SubjectAlternativeNames?
    abstract val profileName: String

    companion object {
        fun fromName(name: String): CertificateProfile = when (name.lowercase()) {
            "idevid" -> IDevID()
            "tls-server" -> TLSServer()
            "tls-client" -> TLSClient()
            "code-signing" -> CodeSigning()
            "email" -> Email()
            "ocsp-responder" -> OCSPResponder()
            "timestamping" -> Timestamping()
            "subordinate-ca" -> SubordinateCA()
            else -> throw IllegalArgumentException("Unknown certificate profile: $name")
        }
    }

    /**
     * IDevID (Initial Device Identifier) certificate profile.
     *
     * Key Usage: digitalSignature
     * Extended Key Usage: none
     * SAN: none
     */
    data class IDevID(
        override val validityDays: Int = 365
    ) : CertificateProfile() {
        override val profileName: String = "idevid"
        override val keyUsageBits: Int = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
        override val extendedKeyUsageOIDs: List<String>? = null
        override val san: SubjectAlternativeNames? = null
    }

    /**
     * TLS Server certificate profile.
     *
     * Key Usage: digitalSignature | keyEncipherment
     * Extended Key Usage: id-kp-serverAuth (1.3.6.1.5.5.7.3.1)
     * SAN: DNS names and/or IP addresses
     */
    data class TLSServer(
        override val validityDays: Int = 365,
        val dnsNames: List<String> = emptyList(),
        val ipAddresses: List<String> = emptyList()
    ) : CertificateProfile() {
        override val profileName: String = "tls-server"
        override val keyUsageBits: Int =
            org.bouncycastle.asn1.x509.KeyUsage.digitalSignature or
                org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment
        override val extendedKeyUsageOIDs: List<String> = listOf("1.3.6.1.5.5.7.3.1")
        override val san: SubjectAlternativeNames?
            get() = if (dnsNames.isEmpty() && ipAddresses.isEmpty()) null
            else SubjectAlternativeNames(dnsNames = dnsNames, ipAddresses = ipAddresses)
    }

    /**
     * TLS Client certificate profile.
     *
     * Key Usage: digitalSignature
     * Extended Key Usage: id-kp-clientAuth (1.3.6.1.5.5.7.3.2)
     * SAN: email addresses (optional)
     */
    data class TLSClient(
        override val validityDays: Int = 365,
        val emailAddresses: List<String> = emptyList()
    ) : CertificateProfile() {
        override val profileName: String = "tls-client"
        override val keyUsageBits: Int = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
        override val extendedKeyUsageOIDs: List<String> = listOf("1.3.6.1.5.5.7.3.2")
        override val san: SubjectAlternativeNames?
            get() = if (emailAddresses.isEmpty()) null
            else SubjectAlternativeNames(emailAddresses = emailAddresses)
    }

    /**
     * Code Signing certificate profile.
     *
     * Key Usage: digitalSignature
     * Extended Key Usage: id-kp-codeSigning (1.3.6.1.5.5.7.3.3)
     * SAN: none
     */
    data class CodeSigning(
        override val validityDays: Int = 365
    ) : CertificateProfile() {
        override val profileName: String = "code-signing"
        override val keyUsageBits: Int = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
        override val extendedKeyUsageOIDs: List<String> = listOf("1.3.6.1.5.5.7.3.3")
        override val san: SubjectAlternativeNames? = null
    }

    /**
     * Email (S/MIME) certificate profile.
     *
     * Key Usage: digitalSignature | nonRepudiation | keyEncipherment
     * Extended Key Usage: id-kp-emailProtection (1.3.6.1.5.5.7.3.4)
     * SAN: email addresses
     */
    data class Email(
        override val validityDays: Int = 365,
        val emailAddresses: List<String> = emptyList()
    ) : CertificateProfile() {
        override val profileName: String = "email"
        override val keyUsageBits: Int =
            org.bouncycastle.asn1.x509.KeyUsage.digitalSignature or
                org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation or
                org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment
        override val extendedKeyUsageOIDs: List<String> = listOf("1.3.6.1.5.5.7.3.4")
        override val san: SubjectAlternativeNames?
            get() = if (emailAddresses.isEmpty()) null
            else SubjectAlternativeNames(emailAddresses = emailAddresses)
    }

    /**
     * OCSP Responder certificate profile.
     *
     * Key Usage: digitalSignature
     * Extended Key Usage: id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
     * SAN: none
     */
    data class OCSPResponder(
        override val validityDays: Int = 90
    ) : CertificateProfile() {
        override val profileName: String = "ocsp-responder"
        override val keyUsageBits: Int = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
        override val extendedKeyUsageOIDs: List<String> = listOf("1.3.6.1.5.5.7.3.9")
        override val san: SubjectAlternativeNames? = null
    }

    /**
     * Timestamping certificate profile.
     *
     * Key Usage: digitalSignature | nonRepudiation
     * Extended Key Usage: id-kp-timeStamping (1.3.6.1.5.5.7.3.8)
     * SAN: none
     */
    data class Timestamping(
        override val validityDays: Int = 365
    ) : CertificateProfile() {
        override val profileName: String = "timestamping"
        override val keyUsageBits: Int =
            org.bouncycastle.asn1.x509.KeyUsage.digitalSignature or
                org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation
        override val extendedKeyUsageOIDs: List<String> = listOf("1.3.6.1.5.5.7.3.8")
        override val san: SubjectAlternativeNames? = null
    }

    /**
     * Subordinate CA certificate profile.
     *
     * Key Usage: digitalSignature | keyCertSign | cRLSign
     * Extended Key Usage: none (CA certificates don't need EKU)
     * SAN: none
     */
    data class SubordinateCA(
        override val validityDays: Int = 1825,
        val pathLenConstraint: Int = 0
    ) : CertificateProfile() {
        override val profileName: String = "subordinate-ca"
        override val keyUsageBits: Int =
            org.bouncycastle.asn1.x509.KeyUsage.digitalSignature or
                org.bouncycastle.asn1.x509.KeyUsage.keyCertSign or
                org.bouncycastle.asn1.x509.KeyUsage.cRLSign
        override val extendedKeyUsageOIDs: List<String>? = null
        override val san: SubjectAlternativeNames? = null
    }
}
