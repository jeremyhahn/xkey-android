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

package com.automatethethings.xkey.crypto

/**
 * The ML-DSA parameter sets of FIPS 204.
 *
 * @property wireName the name on the wire, in the key list and in the dialogs.
 * @property coseAlgorithm the COSE algorithm id.
 * @property oid the SubjectPublicKeyInfo algorithm OID (no parameters).
 * @property publicKeyBytes the raw public key size.
 * @property signatureBytes the signature size.
 */
enum class MlDsaParameterSet(
    val wireName: String,
    val coseAlgorithm: Int,
    val oid: String,
    val publicKeyBytes: Int,
    val signatureBytes: Int
) {
    ML_DSA_44("ML-DSA-44", -48, "2.16.840.1.101.3.4.3.17", 1312, 2420),
    ML_DSA_65("ML-DSA-65", -49, "2.16.840.1.101.3.4.3.18", 1952, 3309),
    ML_DSA_87("ML-DSA-87", -50, "2.16.840.1.101.3.4.3.19", 2592, 4627);

    companion object {
        /**
         * The set [name] names: "ML-DSA-65", "MLDSA65" and "ml_dsa_65" all
         * name ML-DSA-65. Any other name is null.
         */
        fun fromWireName(name: String): MlDsaParameterSet? {
            val folded = name.uppercase().replace("_", "").replace("-", "")
            return entries.firstOrNull { it.wireName.replace("-", "") == folded }
        }

        /** The set whose SPKI OID is [oid], or null. */
        fun fromOid(oid: String): MlDsaParameterSet? = entries.firstOrNull { it.oid == oid }
    }
}

/** Where an ML-DSA private key lives. */
enum class PqcBacking(val wire: String) {
    /** In the Android Keystore, made by [PqcHardware.backend]. */
    HARDWARE("hardware"),

    /** In app storage, sealed by a non-exportable Keystore AES-GCM key ([PqcSoftwareKeyStore]). */
    SOFTWARE("software");

    companion object {
        /** The backing [wire] names, or null for any other name. */
        fun fromWire(wire: String): PqcBacking? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * The Android Keystore's ML-DSA keys, for the devices that make them. The
 * key is generated under [generate]'s alias in AndroidKeyStore and signs
 * through `Signature.getInstance(jcaSignatureAlgorithm(set))`.
 */
interface PqcHardwareBackend {
    /** The parameter sets this device makes in hardware. */
    fun supportedParameterSets(): Set<MlDsaParameterSet>

    /**
     * Generates a non-exportable [set] key under [alias] and returns its
     * SubjectPublicKeyInfo DER.
     */
    fun generate(
        alias: String,
        set: MlDsaParameterSet,
        authDurationSeconds: Int,
        preferStrongBox: Boolean
    ): ByteArray

    /** The JCA signature algorithm a [set] Keystore key signs with. */
    fun jcaSignatureAlgorithm(set: MlDsaParameterSet): String
}

/**
 * The registered hardware backend. Null means no hardware ML-DSA: no dialog
 * offers it and `keyBacking: "hardware"` is refused.
 */
object PqcHardware {
    @Volatile
    var backend: PqcHardwareBackend? = null

    /** The sets the device makes in hardware; empty with no backend. */
    fun supported(): Set<MlDsaParameterSet> = backend?.supportedParameterSets() ?: emptySet()
}
