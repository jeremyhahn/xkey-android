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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.CRLNumber
import org.bouncycastle.asn1.x509.CRLReason as BCCRLReason
import org.bouncycastle.cert.X509v2CRLBuilder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import com.automatethethings.xkey.audit.AuditLogger
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import java.util.Date

/**
 * Result of certificate issuance.
 */
data class IssuedCertificate(
    val certificate: ByteArray,      // Issued certificate (DER)
    val chain: List<ByteArray>,      // Full chain including issued cert
    val serialNumber: String,
    val subjectDN: String,
    val notAfter: Long,
    val fingerprint: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IssuedCertificate) return false
        return certificate.contentEquals(other.certificate) && serialNumber == other.serialNumber
    }
    override fun hashCode(): Int = certificate.contentHashCode()
}

/**
 * CA initialization result.
 */
sealed class CAInitResult {
    data class Success(val rootCertDER: ByteArray, val intermediateCertDER: ByteArray) : CAInitResult()
    data class AlreadyInitialized(val rootCertDER: ByteArray, val intermediateCertDER: ByteArray) : CAInitResult()
    data class Error(val message: String) : CAInitResult()
}

/**
 * CA subject configuration for X.509 certificate generation.
 */
data class CASubject(
    val cn: String = "",
    val org: String = "",
    val ou: String = "",
    val locality: String = "",
    val province: String = "",
    val country: String = ""
) {
    fun toX500Name(defaultCN: String): X500Name {
        val builder = X500NameBuilder(BCStyle.INSTANCE)
        if (country.isNotBlank()) builder.addRDN(BCStyle.C, country)
        if (province.isNotBlank()) builder.addRDN(BCStyle.ST, province)
        if (locality.isNotBlank()) builder.addRDN(BCStyle.L, locality)
        if (org.isNotBlank()) builder.addRDN(BCStyle.O, org)
        if (ou.isNotBlank()) builder.addRDN(BCStyle.OU, ou)
        builder.addRDN(BCStyle.CN, cn.ifBlank { defaultCN })
        return builder.build()
    }
}

/**
 * Certificate information for UI display.
 */
data class CACertificateInfo(
    val subjectDN: String,
    val issuerDN: String,
    val notBefore: Date,
    val notAfter: Date,
    val fingerprint: String,
    val isExpired: Boolean
)

/**
 * Android-based Certificate Authority for issuing IDevID certificates.
 *
 * Uses Android Keystore with StrongBox/TEE backing for secure key storage.
 * Issues certificates for paired devices after attestation verification.
 * Uses BouncyCastle for proper X.509 certificate generation with configurable subjects.
 *
 * Certificate hierarchy:
 * - Root CA (10 year validity, StrongBox-backed)
 *   - Intermediate CA (5 year validity, StrongBox-backed)
 *     - IDevID certificates (1 year validity)
 */
class AndroidCA internal constructor(
    private val context: Context,
    /**
     * Opens the KeyStore holding the CA keys. Production always uses the
     * Android Keystore (the public constructor); JVM tests pass an in-memory
     * store so issuance can run without StrongBox/TEE.
     */
    private val openKeyStore: () -> KeyStore
) {
    constructor(context: Context) : this(context, ::openAndroidKeyStore)

    companion object {
        private const val TAG = "AndroidCA"

        private fun openAndroidKeyStore(): KeyStore =
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        const val ROOT_CA_ALIAS = "xkey_root_ca"
        const val INTERMEDIATE_CA_ALIAS = "xkey_intermediate_ca"

        private const val ROOT_CA_VALIDITY_YEARS = 10
        private const val INTERMEDIATE_CA_VALIDITY_YEARS = 5
        private const val IDEVID_VALIDITY_DAYS = 365

        private const val KEY_SIZE = 256
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        private const val PREFS_NAME = "xkey_ca"
        private const val PREF_ROOT_CERT_DER = "root_ca_cert_der"
        private const val PREF_INTERMEDIATE_CERT_DER = "intermediate_ca_cert_der"
        private const val PREF_ROOT_CA_SUBJECT = "root_ca_subject"
        private const val PREF_ROOT_CA_NOT_AFTER = "root_ca_not_after"
        private const val PREF_INTERMEDIATE_CA_SUBJECT = "intermediate_ca_subject"
        private const val PREF_INTERMEDIATE_CA_NOT_AFTER = "intermediate_ca_not_after"
    }

    /**
     * RFC 5280 CRLReason constants.
     */
    object CRLReason {
        const val UNSPECIFIED = 0
        const val KEY_COMPROMISE = 1
        const val CA_COMPROMISE = 2
        const val AFFILIATION_CHANGED = 3
        const val SUPERSEDED = 4
        const val CESSATION_OF_OPERATION = 5
        const val CERTIFICATE_HOLD = 6
        const val PRIVILEGE_WITHDRAWN = 9
        const val AA_COMPROMISE = 10
    }

    /** Optional CertificateDao for auto-persisting issued certs. */
    var certificateDao: CertificateDao? = null

    private val keyStore: KeyStore by lazy { openKeyStore() }

    /**
     * Check if the Root CA has been generated.
     */
    fun isRootCAGenerated(): Boolean {
        return keyStore.containsAlias(ROOT_CA_ALIAS) && hasStoredCert(PREF_ROOT_CERT_DER)
    }

    /**
     * Check if the Intermediate CA has been generated.
     */
    fun isIntermediateCAGenerated(): Boolean {
        return keyStore.containsAlias(INTERMEDIATE_CA_ALIAS) && hasStoredCert(PREF_INTERMEDIATE_CERT_DER)
    }

    /**
     * Check if the CA has been fully initialized (both root and intermediate).
     */
    fun isInitialized(): Boolean {
        return isRootCAGenerated() && isIntermediateCAGenerated()
    }

    /**
     * Generate the Root CA key and self-signed certificate.
     *
     * @param subject CA subject configuration
     * @return CAInitResult indicating success or failure
     */
    suspend fun generateRootCA(subject: CASubject): CAInitResult = withContext(Dispatchers.Default) {
        try {
            if (isRootCAGenerated()) {
                val rootCert = getStoredCertificate(PREF_ROOT_CERT_DER)
                    ?: return@withContext CAInitResult.Error("Root CA key exists but certificate not found")
                return@withContext CAInitResult.AlreadyInitialized(
                    rootCertDER = rootCert.encoded,
                    intermediateCertDER = if (isIntermediateCAGenerated())
                        getStoredCertificate(PREF_INTERMEDIATE_CERT_DER)!!.encoded
                    else ByteArray(0)
                )
            }

            Log.i(TAG, "Generating Root CA with StrongBox/TEE backing")

            generateCAKey(ROOT_CA_ALIAS, isStrongBox = true)

            val rootSubject = subject.toX500Name("xKey Root CA")
            val rootCert = generateRootCACertificate(rootSubject)
            storeCertificate(PREF_ROOT_CERT_DER, rootCert)
            storeRootCertificateMetadata(rootCert)
            persistCACertificateToRoom(rootCert, "ca-root")

            Log.i(TAG, "Root CA generated: ${rootCert.subjectX500Principal}")
            CAInitResult.Success(
                rootCertDER = rootCert.encoded,
                intermediateCertDER = ByteArray(0)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Root CA generation failed", e)
            // Clean up partial state
            try { if (keyStore.containsAlias(ROOT_CA_ALIAS)) keyStore.deleteEntry(ROOT_CA_ALIAS) } catch (_: Exception) {}
            CAInitResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Generate the Intermediate CA key and certificate signed by the Root CA.
     *
     * @param subject CA subject configuration
     * @return CAInitResult indicating success or failure
     */
    suspend fun generateIntermediateCA(subject: CASubject): CAInitResult = withContext(Dispatchers.Default) {
        try {
            if (!isRootCAGenerated()) {
                return@withContext CAInitResult.Error("Root CA must be generated first")
            }

            if (isIntermediateCAGenerated()) {
                val rootCert = getStoredCertificate(PREF_ROOT_CERT_DER)!!
                val intermediateCert = getStoredCertificate(PREF_INTERMEDIATE_CERT_DER)!!
                return@withContext CAInitResult.AlreadyInitialized(
                    rootCertDER = rootCert.encoded,
                    intermediateCertDER = intermediateCert.encoded
                )
            }

            Log.i(TAG, "Generating Intermediate CA with StrongBox/TEE backing")

            generateCAKey(INTERMEDIATE_CA_ALIAS, isStrongBox = true)

            val rootCert = getStoredCertificate(PREF_ROOT_CERT_DER)!!
            val rootKey = keyStore.getKey(ROOT_CA_ALIAS, null) as PrivateKey
            val intermediateSubject = subject.toX500Name("xKey Intermediate CA")
            val intermediateCert = generateIntermediateCertificate(rootCert, rootKey, intermediateSubject)
            storeCertificate(PREF_INTERMEDIATE_CERT_DER, intermediateCert)
            storeIntermediateCertificateMetadata(intermediateCert)
            persistCACertificateToRoom(intermediateCert, "ca-intermediate")

            Log.i(TAG, "Intermediate CA generated: ${intermediateCert.subjectX500Principal}")
            CAInitResult.Success(
                rootCertDER = rootCert.encoded,
                intermediateCertDER = intermediateCert.encoded
            )
        } catch (e: Exception) {
            Log.e(TAG, "Intermediate CA generation failed", e)
            try { if (keyStore.containsAlias(INTERMEDIATE_CA_ALIAS)) keyStore.deleteEntry(INTERMEDIATE_CA_ALIAS) } catch (_: Exception) {}
            CAInitResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Initialize the CA by generating both root and intermediate CA.
     * Kept for backward compatibility.
     */
    suspend fun initialize(subject: CASubject = CASubject()): CAInitResult = withContext(Dispatchers.Default) {
        val rootResult = generateRootCA(subject)
        if (rootResult is CAInitResult.Error) return@withContext rootResult

        val intermediateResult = generateIntermediateCA(subject)
        if (intermediateResult is CAInitResult.Error) return@withContext intermediateResult

        intermediateResult
    }

    /**
     * Issue an IDevID certificate for a paired device.
     *
     * @param csrDER The Certificate Signing Request in DER format (PKCS#10)
     * @param deviceId Unique identifier for the device
     * @param signingAlias Which CA key to sign with (ROOT_CA_ALIAS or INTERMEDIATE_CA_ALIAS)
     * @return IssuedCertificate containing the certificate and chain
     */
    suspend fun issueIDevIDCertificate(
        csrDER: ByteArray,
        deviceId: String,
        signingAlias: String = INTERMEDIATE_CA_ALIAS
    ): IssuedCertificate {
        val subjectDN = X500NameBuilder(BCStyle.INSTANCE).apply {
            addRDN(BCStyle.CN, deviceId)
            addRDN(BCStyle.OU, "IDevID")
            addRDN(BCStyle.O, "xKey")
        }.build()

        return issueCertificate(
            csrDER = csrDER,
            profile = CertificateProfile.IDevID(),
            subjectDN = subjectDN,
            signingAlias = signingAlias
        )
    }

    /**
     * Issue a certificate based on a [CertificateProfile].
     *
     * Validates the CSR, applies profile-specific X.509 extensions (Key Usage,
     * Extended Key Usage, Subject Alternative Names), and signs with the
     * hardware-backed CA key.
     *
     * @param csrDER The Certificate Signing Request in DER format (PKCS#10)
     * @param profile The certificate profile defining extensions and validity
     * @param subjectDN Subject distinguished name; if null, the CSR subject is used
     * @param signingAlias Which CA key to sign with (ROOT_CA_ALIAS or INTERMEDIATE_CA_ALIAS)
     * @return IssuedCertificate containing the certificate and chain
     */
    suspend fun issueCertificate(
        csrDER: ByteArray,
        profile: CertificateProfile,
        subjectDN: X500Name? = null,
        signingAlias: String = INTERMEDIATE_CA_ALIAS
    ): IssuedCertificate = withContext(Dispatchers.Default) {
        if (!isInitialized()) {
            throw IllegalStateException("CA not initialized")
        }

        val csr = JcaPKCS10CertificationRequest(csrDER)
        val verifierProvider = JcaContentVerifierProviderBuilder().build(csr.publicKey)
        if (!csr.isSignatureValid(verifierProvider)) {
            throw IllegalArgumentException("CSR signature verification failed")
        }

        issueForPublicKey(
            publicKey = csr.publicKey,
            subject = subjectDN ?: csr.subject,
            profile = profile,
            signingAlias = signingAlias
        )
    }

    /**
     * Issue a certificate over a public key whose private half is held elsewhere.
     *
     * In the TCG single-pass enrollment ceremony ("TPM 2.0 Keys for Device
     * Identity and Attestation", Section 6.2.2) the keys to certify arrive as TPM
     * public areas and their private halves never leave the enrollee's TPM. There
     * is no PKCS#10 and no self-signature to check here: possession is proved by
     * the TCG-CSR's own signature, which the caller verifies before reaching this.
     *
     * [issueCertificate] is the same issuance with a PKCS#10 in front of it.
     *
     * @param publicKey The key to certify.
     * @param subject Subject distinguished name for the certificate.
     * @param profile The certificate profile defining extensions and validity.
     * @param signingAlias Which CA key to sign with (ROOT_CA_ALIAS or INTERMEDIATE_CA_ALIAS)
     * @return IssuedCertificate containing the certificate and chain
     */
    suspend fun issueForPublicKey(
        publicKey: PublicKey,
        subject: X500Name,
        profile: CertificateProfile,
        signingAlias: String = INTERMEDIATE_CA_ALIAS
    ): IssuedCertificate = withContext(Dispatchers.Default) {
        if (!isInitialized()) {
            throw IllegalStateException("CA not initialized")
        }

        Log.i(TAG, "Issuing ${profile::class.simpleName} certificate")

        val signingCert = getStoredCertificate(
            if (signingAlias == ROOT_CA_ALIAS) PREF_ROOT_CERT_DER else PREF_INTERMEDIATE_CERT_DER
        ) ?: throw IllegalStateException("Signing CA certificate not found")
        // Before anything is built or stored: a refused issuer stores nothing.
        val validity = validityFor(
            now = Date(),
            validityDays = profile.validityDays,
            issuerNotBefore = signingCert.notBefore,
            issuerNotAfter = signingCert.notAfter
        )
        val signingKey = keyStore.getKey(signingAlias, null) as PrivateKey

        val serialNumber = BigInteger(64, SecureRandom())

        val certBuilder = JcaX509v3CertificateBuilder(
            issuerNameOf(signingCert),
            serialNumber,
            validity.notBefore,
            validity.notAfter,
            subject,
            publicKey
        )

        applyProfileExtensions(certBuilder, profile, publicKey, signingCert)

        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(signingKey)
        val certHolder = certBuilder.build(signer)
        val issuedCert = JcaX509CertificateConverter().getCertificate(certHolder)

        val chain = buildCertificateChain(issuedCert, signingAlias)

        val digest = MessageDigest.getInstance("SHA-256")
        val fingerprint = digest.digest(issuedCert.encoded)
            .joinToString("") { "%02x".format(it) }

        Log.i(TAG, "${profile::class.simpleName} certificate issued: serial=$serialNumber")

        val result = IssuedCertificate(
            certificate = issuedCert.encoded,
            chain = chain,
            serialNumber = serialNumber.toString(16),
            subjectDN = issuedCert.subjectX500Principal.name,
            // Read back from the certificate: X.509 validity has one-second
            // resolution, so the Date used to build it carries milliseconds the
            // certificate does not, and reporting those overstates the expiry.
            notAfter = issuedCert.notAfter.time,
            fingerprint = fingerprint
        )

        // Auto-persist to Room if CertificateDao is available
        certificateDao?.let { dao ->
            try {
                val pemCert = derToPEM(issuedCert.encoded)
                val entity = CertificateEntity(
                    serialNumber = serialNumber.toString(16),
                    subjectDN = issuedCert.subjectX500Principal.name,
                    issuerDN = issuedCert.issuerX500Principal.name,
                    notBefore = issuedCert.notBefore.time,
                    notAfter = issuedCert.notAfter.time,
                    profile = profile.profileName,
                    fingerprint = fingerprint,
                    certificatePEM = pemCert,
                    chainPEM = chain.joinToString("\n") { derToPEM(it) },
                    isCA = profile is CertificateProfile.SubordinateCA,
                    createdAt = System.currentTimeMillis()
                )
                dao.insert(entity)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to auto-persist certificate to Room", e)
            }
        }

        // Audit log
        AuditLogger.logCertificateIssued(
            serialNumber = serialNumber.toString(16),
            subjectDN = issuedCert.subjectX500Principal.name,
            profile = profile.profileName
        )

        result
    }

    /**
     * Get the root CA certificate.
     */
    fun getRootCertificate(): X509Certificate {
        return getStoredCertificate(PREF_ROOT_CERT_DER)
            ?: throw IllegalStateException("Root CA certificate not found. Call initialize() first.")
    }

    /**
     * Get the intermediate CA certificate.
     */
    fun getIntermediateCertificate(): X509Certificate {
        return getStoredCertificate(PREF_INTERMEDIATE_CERT_DER)
            ?: throw IllegalStateException("Intermediate CA certificate not found. Call initialize() first.")
    }

    /**
     * Get certificate info for UI display.
     */
    fun getRootCACertificateInfo(): CACertificateInfo? {
        val cert = getStoredCertificate(PREF_ROOT_CERT_DER) ?: return null
        return certToCertInfo(cert)
    }

    /**
     * Get intermediate certificate info for UI display.
     */
    fun getIntermediateCACertificateInfo(): CACertificateInfo? {
        val cert = getStoredCertificate(PREF_INTERMEDIATE_CERT_DER) ?: return null
        return certToCertInfo(cert)
    }

    /**
     * Get the CA bundle (root + intermediate) in DER format.
     */
    fun getCABundle(): List<ByteArray> {
        if (!isInitialized()) return emptyList()
        return listOf(
            getIntermediateCertificate().encoded,
            getRootCertificate().encoded
        )
    }

    /**
     * Delete all CA keys and certificates.
     */
    suspend fun reset() = withContext(Dispatchers.Default) {
        try {
            if (keyStore.containsAlias(ROOT_CA_ALIAS)) {
                keyStore.deleteEntry(ROOT_CA_ALIAS)
            }
            if (keyStore.containsAlias(INTERMEDIATE_CA_ALIAS)) {
                keyStore.deleteEntry(INTERMEDIATE_CA_ALIAS)
            }
            clearStoredCertificates()
            Log.i(TAG, "CA reset complete")
        } catch (e: Exception) {
            Log.e(TAG, "CA reset failed", e)
        }
    }

    /**
     * Create a Certificate Signing Request (PKCS#10).
     *
     * @param subjectDN Subject distinguished name for the CSR.
     * @param keyAlias Android Keystore alias of the key to use.
     * @return DER-encoded PKCS#10 CSR bytes.
     */
    fun createCSR(subjectDN: X500Name, keyAlias: String): ByteArray {
        val keyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        val publicKey = keyEntry.certificate.publicKey
        val privateKey = keyEntry.privateKey

        val csrBuilder = JcaPKCS10CertificationRequestBuilder(subjectDN, publicKey)
        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(privateKey)
        val csr = csrBuilder.build(signer)
        return csr.encoded
    }

    /**
     * Sign a CSR with the specified certificate profile.
     *
     * Parses the CSR, validates its signature, and issues a certificate
     * using the specified profile.
     *
     * @param csrBytes DER-encoded PKCS#10 CSR.
     * @param profileName Certificate profile name (e.g., "tls-server").
     * @param subjectDN Optional subject DN override; uses CSR subject if null.
     * @return IssuedCertificate containing the certificate and chain.
     */
    suspend fun signCSR(
        csrBytes: ByteArray,
        profileName: String,
        subjectDN: X500Name? = null
    ): IssuedCertificate {
        val profile = CertificateProfile.fromName(profileName)
        val result = issueCertificate(
            csrDER = csrBytes,
            profile = profile,
            subjectDN = subjectDN
        )

        AuditLogger.logCSRSigned(
            serialNumber = result.serialNumber,
            subjectDN = result.subjectDN,
            profile = profileName
        )

        return result
    }

    /**
     * Convenience method to issue a certificate with a named profile.
     *
     * @param csrDER DER-encoded PKCS#10 CSR.
     * @param profileName Certificate profile name.
     * @param subjectDN Optional subject DN override.
     * @return IssuedCertificate containing the certificate and chain.
     */
    suspend fun issueCertificateWithProfile(
        csrDER: ByteArray,
        profileName: String,
        subjectDN: X500Name? = null
    ): IssuedCertificate {
        val profile = CertificateProfile.fromName(profileName)
        return issueCertificate(csrDER = csrDER, profile = profile, subjectDN = subjectDN)
    }

    /**
     * Revoke a certificate by serial number.
     *
     * @param serialNumber Hex-encoded certificate serial number.
     * @param reason RFC 5280 CRLReason code (default: UNSPECIFIED).
     */
    suspend fun revoke(serialNumber: String, reason: Int = CRLReason.UNSPECIFIED) {
        val dao = certificateDao ?: throw IllegalStateException("CertificateDao not configured")
        val cert = dao.getBySerial(serialNumber)
            ?: throw IllegalArgumentException("Certificate not found: $serialNumber")
        dao.revoke(serialNumber, System.currentTimeMillis(), reason)

        AuditLogger.logCertificateRevoked(
            serialNumber = serialNumber,
            subjectDN = cert.subjectDN,
            reason = reason
        )

        Log.i(TAG, "Certificate revoked: serial=$serialNumber, reason=$reason")
    }

    /**
     * Check if a certificate is revoked.
     *
     * @param serialNumber Hex-encoded certificate serial number.
     * @return True if the certificate is revoked, null if not found.
     */
    suspend fun isRevoked(serialNumber: String): Boolean? {
        return certificateDao?.isRevoked(serialNumber)
    }

    /**
     * Generate a CRL (Certificate Revocation List) signed by the intermediate CA.
     *
     * @return DER-encoded X.509 CRL bytes.
     */
    suspend fun generateCRL(): ByteArray = withContext(Dispatchers.Default) {
        if (!isInitialized()) {
            throw IllegalStateException("CA not initialized")
        }

        val dao = certificateDao ?: throw IllegalStateException("CertificateDao not configured")
        val revokedCerts = dao.getRevoked()

        val intermediateCert = getIntermediateCertificate()
        val signingKey = keyStore.getKey(INTERMEDIATE_CA_ALIAS, null) as PrivateKey

        val now = Date()
        val calendar = Calendar.getInstance()
        calendar.time = now
        calendar.add(Calendar.DAY_OF_YEAR, 7)  // CRL valid for 7 days
        val nextUpdate = calendar.time

        val crlBuilder = X509v2CRLBuilder(
            issuerNameOf(intermediateCert),
            now
        )
        crlBuilder.setNextUpdate(nextUpdate)

        // Add revoked certificate entries
        for (cert in revokedCerts) {
            val serial = BigInteger(cert.serialNumber, 16)
            val revokedAt = Date(cert.revokedAt ?: System.currentTimeMillis())
            val reason = cert.revokedReason ?: CRLReason.UNSPECIFIED
            crlBuilder.addCRLEntry(serial, revokedAt, reason)
        }

        // Add CRL extensions
        val extUtils = JcaX509ExtensionUtils()
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
            extUtils.createAuthorityKeyIdentifier(intermediateCert))
        crlBuilder.addExtension(Extension.cRLNumber, false,
            CRLNumber(BigInteger.valueOf(System.currentTimeMillis())))

        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(signingKey)
        val crlHolder = crlBuilder.build(signer)

        AuditLogger.logCRLGenerated(revokedCerts.size)
        Log.i(TAG, "CRL generated with ${revokedCerts.size} revoked entries")

        crlHolder.encoded
    }

    // Private helpers

    /**
     * Persists a CA certificate (root or intermediate) to the Room certificates table.
     *
     * @param cert The X509Certificate to persist.
     * @param profile Certificate profile name ("ca-root" or "ca-intermediate").
     */
    private suspend fun persistCACertificateToRoom(cert: X509Certificate, profile: String) {
        val dao = certificateDao ?: return
        try {
            val fingerprint = MessageDigest.getInstance("SHA-256")
                .digest(cert.encoded)
                .joinToString("") { "%02x".format(it) }

            // Avoid duplicate insertion
            if (dao.getBySerial(cert.serialNumber.toString(16)) != null) return

            val entity = CertificateEntity(
                serialNumber = cert.serialNumber.toString(16),
                subjectDN = cert.subjectX500Principal.name,
                issuerDN = cert.issuerX500Principal.name,
                notBefore = cert.notBefore.time,
                notAfter = cert.notAfter.time,
                profile = profile,
                fingerprint = fingerprint,
                certificatePEM = derToPEM(cert.encoded),
                isCA = true,
                createdAt = System.currentTimeMillis()
            )
            dao.insert(entity)
            Log.i(TAG, "CA certificate persisted to Room: profile=$profile, serial=${cert.serialNumber.toString(16)}")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to persist CA certificate to Room", e)
        }
    }

    /**
     * Convert DER-encoded certificate to PEM format.
     */
    private fun derToPEM(der: ByteArray): String {
        val base64 = Base64.encodeToString(der, Base64.NO_WRAP)
        val sb = StringBuilder()
        sb.appendLine("-----BEGIN CERTIFICATE-----")
        var offset = 0
        while (offset < base64.length) {
            val end = minOf(offset + 64, base64.length)
            sb.appendLine(base64.substring(offset, end))
            offset = end
        }
        sb.append("-----END CERTIFICATE-----")
        return sb.toString()
    }

    /**
     * Apply X.509 extensions based on the certificate profile.
     *
     * Always adds: BasicConstraints(false), SubjectKeyIdentifier, AuthorityKeyIdentifier.
     * Conditionally adds: KeyUsage, ExtendedKeyUsage, SubjectAlternativeName.
     */
    private fun applyProfileExtensions(
        certBuilder: JcaX509v3CertificateBuilder,
        profile: CertificateProfile,
        subjectPublicKey: PublicKey,
        signingCert: X509Certificate
    ) {
        val extUtils = JcaX509ExtensionUtils()

        if (profile is CertificateProfile.SubordinateCA) {
            certBuilder.addExtension(Extension.basicConstraints, true,
                BasicConstraints(profile.pathLenConstraint))
        } else {
            certBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        }
        certBuilder.addExtension(Extension.keyUsage, true, KeyUsage(profile.keyUsageBits))
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
            extUtils.createSubjectKeyIdentifier(subjectPublicKey))
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
            extUtils.createAuthorityKeyIdentifier(signingCert))

        profile.extendedKeyUsageOIDs?.let { oids ->
            val purposes = oids.map { KeyPurposeId.getInstance(ASN1ObjectIdentifier(it)) }
            certBuilder.addExtension(
                Extension.extendedKeyUsage, false,
                ExtendedKeyUsage(purposes.toTypedArray())
            )
        }

        profile.san?.let { san ->
            val names = mutableListOf<GeneralName>()
            san.dnsNames.forEach { names.add(GeneralName(GeneralName.dNSName, it)) }
            san.ipAddresses.forEach { ip ->
                names.add(GeneralName(GeneralName.iPAddress, ip))
            }
            san.emailAddresses.forEach { names.add(GeneralName(GeneralName.rfc822Name, it)) }

            if (names.isNotEmpty()) {
                certBuilder.addExtension(
                    Extension.subjectAlternativeName, false,
                    GeneralNames(names.toTypedArray())
                )
            }
        }
    }

    /**
     * Build the full certificate chain for an issued certificate.
     *
     * @return List of DER-encoded certificates: [issued, intermediate (if applicable), root]
     */
    private fun buildCertificateChain(
        issuedCert: X509Certificate,
        signingAlias: String
    ): List<ByteArray> {
        val rootCert = getStoredCertificate(PREF_ROOT_CERT_DER)!!
        val intermediateCert = getStoredCertificate(PREF_INTERMEDIATE_CERT_DER)

        val chain = mutableListOf(issuedCert.encoded)
        if (signingAlias == INTERMEDIATE_CA_ALIAS && intermediateCert != null) {
            chain.add(intermediateCert.encoded)
        }
        chain.add(rootCert.encoded)
        return chain
    }

    /**
     * Generates the CA key for [alias], preferring StrongBox when [isStrongBox]
     * is set and falling back to the TEE where StrongBox is absent.
     *
     * The fallback has to wrap the generation itself. `setIsStrongBoxBacked` only
     * records the preference and never throws; the "no such security level" error
     * comes out of `generateKeyPair`. Guarding the builder call instead meant the
     * fallback could never fire, so CA setup failed outright on every device
     * without StrongBox — which is most of them.
     */
    /**
     * The issuer name to put in a certificate signed by [issuer], taken from its
     * encoded subject.
     *
     * RFC 5280 requires a certificate's issuer field to match the issuing
     * certificate's subject field exactly, and path builders compare the DER
     * bytes. Rebuilding the name from `X500Principal.getName()` does not preserve
     * them: that string is RFC 2253, which lists attributes in reverse encoding
     * order, so re-parsing it produced an issuer whose DER was the reverse of the
     * root's subject and which strict validators would not chain.
     */
    private fun issuerNameOf(issuer: X509Certificate): X500Name =
        X500Name.getInstance(issuer.subjectX500Principal.encoded)

    private fun generateCAKey(alias: String, isStrongBox: Boolean) {
        if (isStrongBox) {
            try {
                generateCAKeyPair(alias, strongBox = true)
                return
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox unavailable for $alias, falling back to TEE", e)
                // A failed attempt can leave a half-created entry behind, and the
                // retry would then collide with it.
                runCatching { keyStore.deleteEntry(alias) }
            }
        }
        generateCAKeyPair(alias, strongBox = false)
    }

    private fun generateCAKeyPair(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setKeySize(KEY_SIZE)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    private fun generateRootCACertificate(subject: X500Name): X509Certificate {
        val keyEntry = keyStore.getEntry(ROOT_CA_ALIAS, null) as KeyStore.PrivateKeyEntry
        val publicKey = keyEntry.certificate.publicKey
        val privateKey = keyEntry.privateKey

        val serialNumber = BigInteger(64, SecureRandom())
        val notBefore = Date()
        val calendar = Calendar.getInstance()
        calendar.time = notBefore
        calendar.add(Calendar.YEAR, ROOT_CA_VALIDITY_YEARS)
        val notAfter = calendar.time

        val extUtils = JcaX509ExtensionUtils()
        val certBuilder = JcaX509v3CertificateBuilder(
            subject,        // issuer (self-signed)
            serialNumber,
            notBefore,
            notAfter,
            subject,        // subject
            publicKey
        ).apply {
            addExtension(Extension.basicConstraints, true, BasicConstraints(1))
            addExtension(Extension.keyUsage, true,
                KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
            addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(publicKey))
            addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(publicKey))
        }

        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(privateKey)
        val certHolder = certBuilder.build(signer)
        return JcaX509CertificateConverter().getCertificate(certHolder)
    }

    /** Internal, not private, so JVM tests can sign an intermediate under a given root. */
    internal fun generateIntermediateCertificate(
        rootCert: X509Certificate,
        rootKey: PrivateKey,
        subject: X500Name
    ): X509Certificate {
        val keyEntry = keyStore.getEntry(INTERMEDIATE_CA_ALIAS, null) as KeyStore.PrivateKeyEntry
        val intermediatePublicKey = keyEntry.certificate.publicKey

        val serialNumber = BigInteger(64, SecureRandom())
        val now = Date()
        val calendar = Calendar.getInstance()
        calendar.time = now
        calendar.add(Calendar.YEAR, INTERMEDIATE_CA_VALIDITY_YEARS)
        val validity = validityUntil(
            now = now,
            requestedNotAfter = calendar.time,
            issuerNotBefore = rootCert.notBefore,
            issuerNotAfter = rootCert.notAfter
        )

        val extUtils = JcaX509ExtensionUtils()
        val certBuilder = JcaX509v3CertificateBuilder(
            issuerNameOf(rootCert),
            serialNumber,
            validity.notBefore,
            validity.notAfter,
            subject,
            intermediatePublicKey
        ).apply {
            addExtension(Extension.basicConstraints, true, BasicConstraints(0))
            addExtension(Extension.keyUsage, true,
                KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
            addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(intermediatePublicKey))
            addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(rootCert))
        }

        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(rootKey)
        val certHolder = certBuilder.build(signer)
        return JcaX509CertificateConverter().getCertificate(certHolder)
    }

    private fun storeCertificate(prefKey: String, cert: X509Certificate) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val base64 = Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
        prefs.edit().putString(prefKey, base64).apply()
    }

    private fun getStoredCertificate(prefKey: String): X509Certificate? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val base64 = prefs.getString(prefKey, null) ?: return null
        return try {
            val der = Base64.decode(base64, Base64.NO_WRAP)
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load stored certificate: $prefKey", e)
            null
        }
    }

    private fun hasStoredCert(prefKey: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(prefKey, null) != null
    }

    private fun storeRootCertificateMetadata(cert: X509Certificate) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(PREF_ROOT_CA_SUBJECT, cert.subjectX500Principal.name)
            .putLong(PREF_ROOT_CA_NOT_AFTER, cert.notAfter.time)
            .apply()
    }

    private fun storeIntermediateCertificateMetadata(cert: X509Certificate) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(PREF_INTERMEDIATE_CA_SUBJECT, cert.subjectX500Principal.name)
            .putLong(PREF_INTERMEDIATE_CA_NOT_AFTER, cert.notAfter.time)
            .apply()
    }

    private fun clearStoredCertificates() {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
    }

    private fun certToCertInfo(cert: X509Certificate): CACertificateInfo {
        val digest = MessageDigest.getInstance("SHA-256")
        val fingerprint = digest.digest(cert.encoded)
            .joinToString(":") { "%02X".format(it) }
        return CACertificateInfo(
            subjectDN = cert.subjectX500Principal.name,
            issuerDN = cert.issuerX500Principal.name,
            notBefore = cert.notBefore,
            notAfter = cert.notAfter,
            fingerprint = fingerprint,
            isExpired = cert.notAfter.before(Date())
        )
    }
}
