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
package com.automatethethings.xkey.ca

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * This device's identity as an *enrollee*: the key an external CA -- xkey
 * desktop or an xkms server -- certifies so it can recognise this phone later.
 *
 * This is the mirror image of [AndroidCA], which is this device acting as the
 * CA for someone else. The two are independent: a phone can be an enterprise CA
 * for a laptop and simultaneously hold a credential issued by an xkms server.
 *
 * ## Why the key is regenerated for every enrollment
 *
 * Android binds the attestation challenge at key *generation*; a key cannot be
 * asked to attest a nonce it was not born with. So a long-lived identity key
 * could only ever present the challenge from its original enrollment, which a
 * CA has no way to distinguish from a replay.
 *
 * Minting a fresh key per enrollment is not a workaround, it is the correct
 * behaviour: re-enrollment is supposed to prove the device is *still* sound --
 * still verified-boot, still bootloader-locked, still running this app -- and
 * only a fresh attestation says anything about the present. The certificate the
 * CA issues is the durable identity; the key underneath it rotates with it,
 * which is exactly what IEEE 802.1AR expects of an LDevID.
 *
 * ## Why enrollment stages behind a generation pointer
 *
 * A request that is never answered -- the CA refuses, the link drops -- must not
 * cost this device the credential it already holds. So each enrollment mints its
 * key under its own alias, `xkey_device_identity_<n>`, and a preference records
 * which generation is live. The pointer moves only once the CA's certificate has
 * been checked against that key; until then the previous generation keeps
 * serving.
 *
 * The pointer exists because a Keystore private key cannot be moved: it is
 * non-exportable by construction, and `setKeyEntry` refuses to file one under a
 * second alias ("can only replace keys with same alias"). Numbering the aliases
 * and moving a pointer achieves the same staging without the key ever leaving
 * hardware.
 */
class DeviceIdentity(private val context: Context) {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private val prefs by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /** True when this device holds a credential issued by an external CA. */
    fun isEnrolled(): Boolean {
        val alias = activeAlias() ?: return false
        return keyStore.containsAlias(alias) && prefs.contains(PREF_CERT_DER)
    }

    /** Keystore alias of the key the live credential certifies, if enrolled. */
    fun activeAlias(): String? {
        val generation = prefs.getInt(PREF_ACTIVE_GENERATION, NO_GENERATION)
        return if (generation == NO_GENERATION) null else aliasFor(generation)
    }

    /** The credential this device currently presents, or null when unenrolled. */
    fun credential(): X509Certificate? = readCertificate(PREF_CERT_DER)

    /**
     * The issuer chain stored alongside the credential, root last.
     *
     * Empty when the CA supplied no chain, which is legitimate for a CA whose
     * root the verifier already trusts out of band.
     */
    fun credentialChain(): List<X509Certificate> {
        val stored = prefs.getString(PREF_CHAIN_DER, null) ?: return emptyList()
        if (stored.isEmpty()) return emptyList()
        val factory = CertificateFactory.getInstance("X.509")
        return stored.split(CHAIN_SEPARATOR).mapNotNull { encoded ->
            runCatching {
                factory.generateCertificate(Base64.getDecoder().decode(encoded).inputStream())
                    as X509Certificate
            }.getOrNull()
        }
    }

    /**
     * Whether the credential has lapsed, and so whether the device must
     * re-attest before it can be trusted again.
     *
     * The expiry is the CA's, taken from the certificate rather than from any
     * local setting: how often this device must prove itself is the relying
     * party's decision, not the device's.
     */
    fun isCredentialExpired(now: Long = System.currentTimeMillis()): Boolean {
        val cert = credential() ?: return true
        return cert.notAfter.time <= now
    }

    /**
     * Generates a fresh identity key attesting [challenge] and returns the
     * enrollment request to hand the CA.
     *
     * @param challenge the CA's nonce, embedded in the attestation extension by
     *   the TEE, which is what makes the evidence non-replayable.
     * @param subject the subject the device asks for; the CA may override it.
     * @throws DeviceIdentityException when this device cannot produce hardware
     *   attestation at all, so the caller reports that rather than returning
     *   evidence that proves nothing.
     */
    fun createEnrollmentRequest(
        challenge: ByteArray,
        subject: X500Name = defaultSubject()
    ): DeviceEnrollmentRequest {
        require(challenge.isNotEmpty()) { "attestation challenge must not be empty" }

        val pending = aliasFor(nextGeneration())
        if (keyStore.containsAlias(pending)) {
            keyStore.deleteEntry(pending)
        }

        val chain = generateAttestedKey(pending, challenge)
        if (chain.size < 2) {
            // A single self-signed certificate means the platform produced no
            // attestation: there is no Google-rooted path, so nothing here
            // proves hardware backing and the CA must not be handed it.
            keyStore.deleteEntry(pending)
            throw DeviceIdentityException(
                "This device produced no attestation chain, so hardware backing cannot be proven"
            )
        }
        prefs.edit().putString(PREF_PENDING_ALIAS, pending).apply()

        val entry = keyStore.getEntry(pending, null) as KeyStore.PrivateKeyEntry
        val csr = JcaPKCS10CertificationRequestBuilder(subject, entry.certificate.publicKey)
            .build(JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(entry.privateKey))

        return DeviceEnrollmentRequest(
            csr = csr.encoded,
            attestationChain = chain.map { it.encoded },
            securityLevel = securityLevelOf(chain.first() as X509Certificate)
        )
    }

    /**
     * Accepts a credential the CA issued for the pending request and promotes
     * the pending key to this device's identity.
     *
     * The certificate is checked against the pending key before anything is
     * stored. A credential whose public key is not ours is either a mix-up or
     * an attempt to bind this device to a key it does not hold, and storing it
     * would leave the device presenting a certificate it cannot use.
     *
     * @throws DeviceIdentityException when no request is pending, or the
     *   certificate does not match it.
     */
    fun storeCredential(
        certificate: X509Certificate,
        chain: List<X509Certificate> = emptyList()
    ): StoredCredential {
        val pendingAlias = prefs.getString(PREF_PENDING_ALIAS, null)
            ?: throw DeviceIdentityException(
                "No enrollment is pending; request one before storing a credential"
            )
        val pending = keyStore.getEntry(pendingAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw DeviceIdentityException(
                "No enrollment is pending; request one before storing a credential"
            )

        if (certificate.publicKey != pending.certificate.publicKey) {
            throw DeviceIdentityException(
                "The issued certificate does not certify the pending enrollment key"
            )
        }

        // Retire the generation this one replaces. Done after the match is
        // confirmed, so a credential that does not fit costs nothing.
        val previous = activeAlias()
        if (previous != null && previous != pendingAlias && keyStore.containsAlias(previous)) {
            keyStore.deleteEntry(previous)
        }

        val fingerprint = fingerprintOf(certificate)
        prefs.edit()
            .putInt(PREF_ACTIVE_GENERATION, generationOf(pendingAlias))
            .remove(PREF_PENDING_ALIAS)
            .putString(PREF_CERT_DER, Base64.getEncoder().encodeToString(certificate.encoded))
            .putString(
                PREF_CHAIN_DER,
                chain.joinToString(CHAIN_SEPARATOR) {
                    Base64.getEncoder().encodeToString(it.encoded)
                }
            )
            .putString(PREF_FINGERPRINT, fingerprint)
            .putLong(PREF_NOT_AFTER, certificate.notAfter.time)
            .putString(PREF_ISSUER, certificate.issuerX500Principal.name)
            .apply()

        Log.i(TAG, "Device credential stored: issuer=${certificate.issuerX500Principal}")
        return StoredCredential(fingerprint, certificate.notAfter.time)
    }

    /** Discards the credential and every identity key, leaving no enrollment. */
    fun reset() {
        keyStore.aliases().toList()
            .filter { it.startsWith(ALIAS_PREFIX) }
            .forEach { keyStore.deleteEntry(it) }
        prefs.edit().clear().apply()
        Log.i(TAG, "Device identity reset")
    }

    private fun aliasFor(generation: Int): String = "$ALIAS_PREFIX$generation"

    private fun generationOf(alias: String): Int =
        alias.removePrefix(ALIAS_PREFIX).toInt()

    /**
     * The generation a new enrollment takes.
     *
     * One past the highest alias present, not one past the active generation:
     * an abandoned pending key keeps its number until [reset], so a retry never
     * lands on an alias that already exists.
     */
    private fun nextGeneration(): Int {
        val highest = keyStore.aliases().toList()
            .filter { it.startsWith(ALIAS_PREFIX) }
            .mapNotNull { it.removePrefix(ALIAS_PREFIX).toIntOrNull() }
            .maxOrNull() ?: NO_GENERATION
        return highest + 1
    }

    /**
     * Generates the attested key, preferring StrongBox and falling back to the
     * TEE.
     *
     * The fallback wraps `generateKeyPair()`, not the builder call: requesting
     * StrongBox always succeeds at build time and only fails when the key is
     * actually generated, so a guard around the builder catches nothing.
     */
    private fun generateAttestedKey(alias: String, challenge: ByteArray): List<Certificate> {
        val spec = {
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generate(alias, spec().setIsStrongBoxBacked(true).build())
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox unavailable for the device identity key, falling back to TEE", e)
                if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
            }
        }
        return generate(alias, spec().build())
    }

    private fun generate(alias: String, spec: KeyGenParameterSpec): List<Certificate> {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )
        generator.initialize(spec)
        generator.generateKeyPair()
        return keyStore.getCertificateChain(alias)?.toList() ?: emptyList()
    }

    private fun readCertificate(key: String): X509Certificate? {
        val encoded = prefs.getString(key, null) ?: return null
        return runCatching {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(Base64.getDecoder().decode(encoded).inputStream())
                as X509Certificate
        }.getOrNull()
    }

    private fun defaultSubject(): X500Name =
        X500Name("CN=${Build.MODEL ?: "Android device"}, O=xKey")

    /**
     * Reads the attestation security level from the leaf.
     *
     * Advisory only, and reported as such on the wire: the authoritative answer
     * is in the attestation extension the CA parses itself. A device that lies
     * here gains nothing, because the CA does not take its word for it.
     */
    private fun securityLevelOf(leaf: X509Certificate): String {
        val ext = leaf.getExtensionValue(KEY_DESCRIPTION_OID) ?: return LEVEL_SOFTWARE
        // attestationSecurityLevel is the second field of the KeyDescription
        // SEQUENCE, an ENUMERATED: 0 software, 1 TEE, 2 StrongBox.
        val level = readAttestationSecurityLevel(ext) ?: return LEVEL_SOFTWARE
        return when (level) {
            1 -> LEVEL_TEE
            2 -> LEVEL_STRONGBOX
            else -> LEVEL_SOFTWARE
        }
    }

    private fun readAttestationSecurityLevel(extensionValue: ByteArray): Int? = runCatching {
        // The extension value is an OCTET STRING wrapping the KeyDescription.
        var i = 0
        if (extensionValue[i++].toInt() and 0xFF != 0x04) return null
        i += lengthOctets(extensionValue, i).second
        // KeyDescription ::= SEQUENCE { attestationVersion INTEGER,
        //                               attestationSecurityLevel ENUMERATED, ... }
        if (extensionValue[i++].toInt() and 0xFF != 0x30) return null
        i += lengthOctets(extensionValue, i).second
        if (extensionValue[i++].toInt() and 0xFF != 0x02) return null
        val (versionLen, versionHeader) = lengthOctets(extensionValue, i)
        i += versionHeader + versionLen
        if (extensionValue[i++].toInt() and 0xFF != 0x0A) return null
        val (levelLen, levelHeader) = lengthOctets(extensionValue, i)
        i += levelHeader
        if (levelLen < 1) return null
        extensionValue[i].toInt() and 0xFF
    }.getOrNull()

    /** Returns the DER length at [offset] and how many octets encoded it. */
    private fun lengthOctets(bytes: ByteArray, offset: Int): Pair<Int, Int> {
        val first = bytes[offset].toInt() and 0xFF
        if (first and 0x80 == 0) return first to 1
        val count = first and 0x7F
        var value = 0
        for (n in 1..count) {
            value = (value shl 8) or (bytes[offset + n].toInt() and 0xFF)
        }
        return value to (count + 1)
    }

    private fun fingerprintOf(certificate: X509Certificate): String =
        MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG = "DeviceIdentity"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val EC_CURVE = "secp256r1"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /** Android key attestation extension, RFC-style OID assigned by Google. */
        private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

        const val LEVEL_SOFTWARE = "software"
        const val LEVEL_TEE = "trusted_environment"
        const val LEVEL_STRONGBOX = "strongbox"

        /**
         * Prefix of every device identity key. Each enrollment appends its
         * generation number, and a preference says which generation is live.
         *
         * The writers here replace these keys outside SharePermissionLedger,
         * so DesktopShareGate.isIdentityKey keeps them out of outbound shares.
         */
        const val ALIAS_PREFIX = "xkey_device_identity_"

        /** Sentinel for "this device has never completed an enrollment". */
        const val NO_GENERATION = -1

        private const val PREFS_NAME = "xkey_device_identity"
        private const val PREF_CERT_DER = "credential_der"
        private const val PREF_CHAIN_DER = "credential_chain_der"
        private const val PREF_FINGERPRINT = "credential_fingerprint"
        private const val PREF_NOT_AFTER = "credential_not_after"
        private const val PREF_ISSUER = "credential_issuer"
        private const val PREF_ACTIVE_GENERATION = "active_generation"
        private const val PREF_PENDING_ALIAS = "pending_alias"

        private const val CHAIN_SEPARATOR = "|"
    }
}

/** The enrollment package this device hands a CA. */
data class DeviceEnrollmentRequest(
    val csr: ByteArray,
    val attestationChain: List<ByteArray>,
    val securityLevel: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DeviceEnrollmentRequest
        if (!csr.contentEquals(other.csr)) return false
        if (attestationChain.size != other.attestationChain.size) return false
        attestationChain.forEachIndexed { i, bytes ->
            if (!bytes.contentEquals(other.attestationChain[i])) return false
        }
        return securityLevel == other.securityLevel
    }

    override fun hashCode(): Int {
        var result = csr.contentHashCode()
        attestationChain.forEach { result = 31 * result + it.contentHashCode() }
        return 31 * result + securityLevel.hashCode()
    }
}

/** What was persisted when a credential was accepted. */
data class StoredCredential(
    val fingerprint: String,
    val notAfter: Long
)

/** This device cannot enroll, or the credential offered does not fit. */
class DeviceIdentityException(message: String) : Exception(message)
