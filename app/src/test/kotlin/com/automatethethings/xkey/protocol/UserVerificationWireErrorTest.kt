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

import com.automatethethings.xkey.credential.UserVerificationCompliance
import com.automatethethings.xkey.credential.UserVerificationRequiredException
import com.automatethethings.xkey.credential.UvRequirement
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Pins the wire error a FIDO2 request answers with when the peer required
 * user verification that did not happen (#135).
 *
 * The exception comes from the real [UserVerificationCompliance.enforce], so
 * the test breaks if either the refusal or its wire mapping changes.
 */
class UserVerificationWireErrorTest {

    private val fido2Methods = listOf(
        MethodNames.LOCAL_LIST_FIDO2_CREDENTIALS,
        MethodNames.LOCAL_SIGN_FIDO2_ASSERTION
    )

    private fun refusal(): UserVerificationRequiredException =
        assertThrows(UserVerificationRequiredException::class.java) {
            UserVerificationCompliance.enforce(
                requirement = UvRequirement.REQUIRED,
                verificationPerformed = false,
                strict = true,
                ceremony = "Passkey assertion for example.com"
            )
        }

    @Test
    fun `missing user verification answers BIOMETRIC_FAILED on both FIDO2 methods`() {
        fido2Methods.forEachIndexed { index, method ->
            val request = Request(id = 40L + index, method = method)
            val error = refusal()

            val response = UserVerificationWireError.response(request.id, error)

            assertEquals(method, request.id, response.id)
            assertNull(method, response.result)
            assertEquals(method, ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
            assertEquals(method, -32003, response.error?.code)
            assertEquals(method, error.message, response.error?.message)
        }
    }

    @Test
    fun `mapping constant is BIOMETRIC_FAILED`() {
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, UserVerificationWireError.CODE)
    }
}
