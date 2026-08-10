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
package com.automatethethings.xkey.credential

/**
 * The relying party's user-verification requirement for a ceremony, as defined
 * by the WebAuthn `UserVerificationRequirement` enumeration
 * (W3C WebAuthn Level 3, section 5.8.6).
 */
enum class UvRequirement {
    /** The RP requires user verification; the ceremony fails without it. */
    REQUIRED,

    /** The RP prefers verification but accepts a ceremony without it. */
    PREFERRED,

    /** The RP does not want verification performed. */
    DISCOURAGED;

    companion object {
        /**
         * Parses the `userVerification` member of an RP request. WebAuthn
         * defines "preferred" as the default when the member is absent or
         * holds an unknown value.
         */
        fun fromJson(value: String?): UvRequirement = when (value?.lowercase()) {
            "required" -> REQUIRED
            "discouraged" -> DISCOURAGED
            else -> PREFERRED
        }
    }
}

/**
 * Thrown when a ceremony cannot satisfy the relying party's user-verification
 * requirement. The ceremony must fail rather than complete unverified.
 */
class UserVerificationRequiredException(message: String) : Exception(message)

/**
 * Enforces WebAuthn user-verification semantics.
 *
 * Two rules matter, and only the first is negotiable:
 *
 * 1. **Refusal.** When the RP sets `userVerification: "required"` and this
 *    device cannot verify the user, the ceremony must fail
 *    (WebAuthn Level 3, section 6.3.2 step 8 / section 6.3.3 step 7; CTAP2
 *    returns `CTAP2_ERR_UNSUPPORTED_OPTION` in the same situation). Disabling
 *    [BiometricSettingsData.strictUserVerification] relaxes only this rule.
 *
 * 2. **Honest reporting.** The `UV` bit in authenticator data must be set if
 *    and only if user verification actually took place
 *    (WebAuthn Level 3, section 6.1). This is never relaxed: the flag is the
 *    single signal a relying party has to decide whether a human was verified,
 *    and asserting it falsely would let any RP be misled into trusting an
 *    unverified ceremony.
 */
object UserVerificationCompliance {

    /**
     * Validates a ceremony against [requirement].
     *
     * @param requirement what the relying party asked for.
     * @param verificationPerformed whether the user was actually verified.
     * @param strict whether to enforce rule 1 above (the compliant default).
     * @param ceremony a short label used in the error message.
     * @return true when the ceremony satisfies the requirement; false when it
     *         proceeds unverified only because [strict] was disabled, which the
     *         caller should log. A conformant relying party will reject such a
     *         response on its own terms, since `UV` still reports 0.
     * @throws UserVerificationRequiredException when the RP required
     *         verification, none was performed, and [strict] is set.
     */
    fun enforce(
        requirement: UvRequirement,
        verificationPerformed: Boolean,
        strict: Boolean,
        ceremony: String
    ): Boolean {
        if (requirement != UvRequirement.REQUIRED || verificationPerformed) return true

        if (strict) {
            throw UserVerificationRequiredException(
                "$ceremony requires user verification, but this device could not verify " +
                    "the user. Enrol a biometric or device credential, or disable strict " +
                    "user verification in xKey settings to allow unverified ceremonies."
            )
        }
        return false
    }

    /**
     * Returns the authenticator-data flag byte for a ceremony.
     *
     * @param userPresent user presence was established (bit 0, `UP`).
     * @param userVerified user verification was performed (bit 2, `UV`).
     * @param attestedCredentialData attested credential data follows
     *        (bit 6, `AT`) — set for registration, clear for assertion.
     */
    fun flags(
        userPresent: Boolean = true,
        userVerified: Boolean,
        attestedCredentialData: Boolean = false
    ): Byte {
        var flags = 0
        if (userPresent) flags = flags or FLAG_UP
        if (userVerified) flags = flags or FLAG_UV
        if (attestedCredentialData) flags = flags or FLAG_AT
        return flags.toByte()
    }

    /** Bit 0: User Present. */
    const val FLAG_UP = 0x01

    /** Bit 2: User Verified. */
    const val FLAG_UV = 0x04

    /** Bit 6: Attested credential data included. */
    const val FLAG_AT = 0x40
}
