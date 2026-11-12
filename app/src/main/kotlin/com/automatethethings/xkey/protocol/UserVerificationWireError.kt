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

import com.automatethethings.xkey.credential.UserVerificationRequiredException

/**
 * The wire answer to a [UserVerificationRequiredException]: the peer required
 * user verification, none took place, and strict user verification is on
 * (see `UserVerificationCompliance.enforce`).
 *
 * The code is [ErrorCodes.BIOMETRIC_FAILED] (-32003). SPEC.md names no code
 * for this case, and no new one is added. -32003 is what dispatch already
 * sends for `BiometricRequiredException` and `BiometricUnavailableException`,
 * the other "verification was required and did not happen" cases, so a peer
 * tells its user the same thing: verify, or enrol a biometric, on the phone.
 * Before this mapping the exception fell through to [ErrorCodes.INTERNAL_ERROR],
 * which reads as a fault in the phone. [ErrorCodes.OPERATION_DENIED] would
 * mean a policy refusal the user cannot fix by verifying, so it fits less.
 */
internal object UserVerificationWireError {

    /** The single code a missing user verification answers with on the wire. */
    const val CODE = ErrorCodes.BIOMETRIC_FAILED

    /** Builds the error response for [requestId] from [error]. */
    fun response(requestId: Long, error: UserVerificationRequiredException): Response =
        Response.error(requestId, CODE, error.message ?: "User verification required")
}
