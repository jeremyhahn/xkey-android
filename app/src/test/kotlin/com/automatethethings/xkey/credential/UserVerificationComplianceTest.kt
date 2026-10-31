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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Tests for WebAuthn user-verification semantics.
 *
 * Two properties matter: a ceremony that cannot meet a `required` UV request
 * must fail by default, and the `UV` bit must never claim verification that
 * did not happen.
 */
class UserVerificationComplianceTest {

    // --- requirement parsing (WebAuthn L3 section 5.8.6) ---

    @Test
    fun parsesTheThreeDefinedRequirements() {
        assertEquals(UvRequirement.REQUIRED, UvRequirement.fromJson("required"))
        assertEquals(UvRequirement.PREFERRED, UvRequirement.fromJson("preferred"))
        assertEquals(UvRequirement.DISCOURAGED, UvRequirement.fromJson("discouraged"))
    }

    @Test
    fun parsingIsCaseInsensitive() {
        assertEquals(UvRequirement.REQUIRED, UvRequirement.fromJson("REQUIRED"))
        assertEquals(UvRequirement.DISCOURAGED, UvRequirement.fromJson("Discouraged"))
    }

    @Test
    fun absentOrUnknownRequirementDefaultsToPreferred() {
        // WebAuthn defines "preferred" as the default for this member.
        assertEquals(UvRequirement.PREFERRED, UvRequirement.fromJson(null))
        assertEquals(UvRequirement.PREFERRED, UvRequirement.fromJson(""))
        assertEquals(UvRequirement.PREFERRED, UvRequirement.fromJson("nonsense"))
    }

    // --- rule 1: refusal, strict (compliant default) ---

    @Test
    fun strictModeRejectsRequiredUvWithoutVerification() {
        val error = assertThrows(UserVerificationRequiredException::class.java) {
            UserVerificationCompliance.enforce(
                requirement = UvRequirement.REQUIRED,
                verificationPerformed = false,
                strict = true,
                ceremony = "test ceremony"
            )
        }
        // The message must tell the user how to resolve it.
        assertEquals(true, error.message!!.contains("requires user verification"))
    }

    @Test
    fun strictModeAllowsRequiredUvWhenVerificationHappened() {
        UserVerificationCompliance.enforce(
            requirement = UvRequirement.REQUIRED,
            verificationPerformed = true,
            strict = true,
            ceremony = "test ceremony"
        )
    }

    @Test
    fun preferredAndDiscouragedNeverRefuse() {
        for (requirement in listOf(UvRequirement.PREFERRED, UvRequirement.DISCOURAGED)) {
            for (performed in listOf(true, false)) {
                UserVerificationCompliance.enforce(
                    requirement = requirement,
                    verificationPerformed = performed,
                    strict = true,
                    ceremony = "test ceremony"
                )
            }
        }
    }

    // --- rule 1 relaxed: the explicit opt-out ---

    @Test
    fun nonStrictModeAllowsRequiredUvWithoutVerification() {
        // Permitted only because the user opted out; the UV bit still reports
        // the truth, which is asserted separately below.
        UserVerificationCompliance.enforce(
            requirement = UvRequirement.REQUIRED,
            verificationPerformed = false,
            strict = false,
            ceremony = "test ceremony"
        )
    }

    // --- rule 2: honest reporting (WebAuthn L3 section 6.1) ---

    // The exact flag bytes pin every bit: UV only when verified, UP
    // independently of UV, AT for registration only.

    @Test
    fun registrationFlagsMatchTheSpecEncoding() {
        // UP | UV | AT == 0x45, the byte a conformant registration emits when
        // the user was verified.
        assertEquals(
            0x45,
            UserVerificationCompliance.flags(
                userPresent = true,
                userVerified = true,
                attestedCredentialData = true
            ).toInt() and 0xFF
        )
        // Unverified registration: UP | AT == 0x41.
        assertEquals(
            0x41,
            UserVerificationCompliance.flags(
                userPresent = true,
                userVerified = false,
                attestedCredentialData = true
            ).toInt() and 0xFF
        )
    }

    @Test
    fun assertionFlagsMatchTheSpecEncoding() {
        // UP | UV == 0x05 verified, UP == 0x01 unverified.
        assertEquals(
            0x05,
            UserVerificationCompliance.flags(userVerified = true).toInt() and 0xFF
        )
        assertEquals(
            0x01,
            UserVerificationCompliance.flags(userVerified = false).toInt() and 0xFF
        )
    }
}
