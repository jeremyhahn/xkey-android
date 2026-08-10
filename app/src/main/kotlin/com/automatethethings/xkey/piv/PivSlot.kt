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
package com.automatethethings.xkey.piv

/**
 * Represents the standard PIV (Personal Identity Verification) smart card key slots
 * as defined by NIST SP 800-73-4.
 *
 * Each slot has a specific purpose in the PIV specification:
 * - **Primary slots** (9A, 9C, 9D, 9E, F9): Core PIV functions including authentication,
 *   digital signatures, key management, card authentication, and attestation.
 * - **Retired slots** (82-95): Key history slots for maintaining access to previously
 *   encrypted data after key rotation.
 *
 * @property hexId The two-character hex identifier for the slot as defined in the PIV spec.
 * @property label Human-readable short label for display purposes.
 * @property description Brief description of the slot's intended use case.
 */
enum class PivSlot(val hexId: String, val label: String, val description: String) {
    /** General-purpose authentication (SSH, VPN, login). */
    AUTHENTICATION("9A", "PIV Authentication", "General authentication, SSH, VPN"),

    /** Non-repudiation signing (code signing, document signing). */
    DIGITAL_SIGNATURE("9C", "Digital Signature", "Code signing, document signing"),

    /** Encryption and key exchange operations. */
    KEY_MANAGEMENT("9D", "Key Management", "Encryption, key exchange"),

    /** Contactless card authentication (physical access). */
    CARD_AUTHENTICATION("9E", "Card Authentication", "Physical access, contactless"),

    /** Device attestation certificate. */
    ATTESTATION("F9", "Attestation", "Device attestation certificate"),

    /** Retired key history slot 1. */
    RETIRED_1("82", "Retired 1", "Key history slot"),
    /** Retired key history slot 2. */
    RETIRED_2("83", "Retired 2", "Key history slot"),
    /** Retired key history slot 3. */
    RETIRED_3("84", "Retired 3", "Key history slot"),
    /** Retired key history slot 4. */
    RETIRED_4("85", "Retired 4", "Key history slot"),
    /** Retired key history slot 5. */
    RETIRED_5("86", "Retired 5", "Key history slot"),
    /** Retired key history slot 6. */
    RETIRED_6("87", "Retired 6", "Key history slot"),
    /** Retired key history slot 7. */
    RETIRED_7("88", "Retired 7", "Key history slot"),
    /** Retired key history slot 8. */
    RETIRED_8("89", "Retired 8", "Key history slot"),
    /** Retired key history slot 9. */
    RETIRED_9("8A", "Retired 9", "Key history slot"),
    /** Retired key history slot 10. */
    RETIRED_10("8B", "Retired 10", "Key history slot"),
    /** Retired key history slot 11. */
    RETIRED_11("8C", "Retired 11", "Key history slot"),
    /** Retired key history slot 12. */
    RETIRED_12("8D", "Retired 12", "Key history slot"),
    /** Retired key history slot 13. */
    RETIRED_13("8E", "Retired 13", "Key history slot"),
    /** Retired key history slot 14. */
    RETIRED_14("8F", "Retired 14", "Key history slot"),
    /** Retired key history slot 15. */
    RETIRED_15("90", "Retired 15", "Key history slot"),
    /** Retired key history slot 16. */
    RETIRED_16("91", "Retired 16", "Key history slot"),
    /** Retired key history slot 17. */
    RETIRED_17("92", "Retired 17", "Key history slot"),
    /** Retired key history slot 18. */
    RETIRED_18("93", "Retired 18", "Key history slot"),
    /** Retired key history slot 19. */
    RETIRED_19("94", "Retired 19", "Key history slot"),
    /** Retired key history slot 20. */
    RETIRED_20("95", "Retired 20", "Key history slot");

    /** Android Keystore alias for keys stored in this slot. */
    val keystoreAlias: String get() = "xkey_piv_$hexId"

    /** Whether this is one of the five primary PIV slots (not a retired key history slot). */
    val isPrimarySlot: Boolean get() = this in listOf(
        AUTHENTICATION, DIGITAL_SIGNATURE, KEY_MANAGEMENT, CARD_AUTHENTICATION, ATTESTATION
    )

    companion object {
        /**
         * Look up a [PivSlot] by its hex identifier.
         *
         * @param hexId The two-character hex slot identifier (case-insensitive).
         * @return The matching [PivSlot], or null if no slot matches.
         */
        fun fromHexId(hexId: String): PivSlot? =
            entries.find { it.hexId.equals(hexId, ignoreCase = true) }
    }
}

/**
 * Cryptographic algorithms supported for PIV key generation.
 *
 * Maps PIV algorithm identifiers to Android Keystore parameters for
 * key generation and signing operations.
 *
 * @property displayName Human-readable algorithm name for UI display.
 * @property keyAlgorithm The JCA key algorithm name (e.g., "EC", "RSA").
 * @property keySizeBits The key size in bits.
 */
enum class PivAlgorithm(val displayName: String, val keyAlgorithm: String, val keySizeBits: Int) {
    /** ECDSA with NIST P-256 curve. */
    ES256("ECDSA P-256", "EC", 256),

    /** ECDSA with NIST P-384 curve. */
    ES384("ECDSA P-384", "EC", 384),

    /** RSA with 2048-bit key. */
    RS2048("RSA 2048", "RSA", 2048);
}
