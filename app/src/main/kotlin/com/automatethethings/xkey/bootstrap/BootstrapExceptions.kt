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
package com.automatethethings.xkey.bootstrap

import com.automatethethings.xkey.settings.BootstrapMethod

/**
 * Base exception for all bootstrap operations.
 *
 * This sealed class hierarchy provides type-safe exception handling for
 * CA bundle bootstrap operations across different methods (DANE, Noise, SPKI, Direct).
 *
 * @param message Descriptive error message.
 * @param cause The underlying exception that caused this failure, if any.
 */
sealed class BootstrapException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * Exception thrown when DANE/TLSA bootstrap fails.
 *
 * DANE (DNS-based Authentication of Named Entities) requires DNSSEC-validated
 * TLSA records to verify the CA bundle. This exception covers DNS lookup failures,
 * missing TLSA records, and DANE verification mismatches.
 *
 * @param reason Description of why DANE bootstrap failed.
 * @param cause The underlying exception, if any.
 */
class DANEException(
    val reason: String,
    cause: Throwable? = null
) : BootstrapException("DANE bootstrap failed: $reason", cause)

/**
 * Exception thrown when Noise protocol bootstrap fails.
 *
 * The Noise_NK protocol uses a pre-shared server public key for encrypted
 * CA bundle retrieval. This exception covers connection failures, handshake
 * errors, and decryption failures.
 *
 * @param reason Description of why Noise bootstrap failed.
 * @param cause The underlying exception, if any.
 */
class NoiseBootstrapException(
    val reason: String,
    cause: Throwable? = null
) : BootstrapException("Noise bootstrap failed: $reason", cause)

/**
 * Exception thrown when SPKI pin verification fails.
 *
 * SPKI (Subject Public Key Info) pinning verifies the server certificate
 * against a pre-configured SHA-256 hash of its public key. This exception
 * is thrown when the computed pin does not match the expected value.
 *
 * @param expectedPin The expected SPKI pin (hex-encoded SHA-256).
 * @param actualPin The actual SPKI pin computed from the server certificate.
 */
class SPKIException(
    val expectedPin: String,
    val actualPin: String? = null
) : BootstrapException(
    if (actualPin != null) {
        "SPKI pin mismatch: expected $expectedPin, got $actualPin"
    } else {
        "SPKI verification failed: expected pin $expectedPin"
    }
)

/**
 * Exception thrown when direct HTTPS bootstrap fails.
 *
 * Direct bootstrap uses standard HTTPS with the system trust store.
 * This exception covers network errors, HTTP errors, and response parsing failures.
 *
 * @param reason Description of why direct bootstrap failed.
 * @param httpStatusCode The HTTP status code, if the failure was due to an HTTP error.
 * @param cause The underlying exception, if any.
 */
class DirectException(
    val reason: String,
    val httpStatusCode: Int? = null,
    cause: Throwable? = null
) : BootstrapException(
    if (httpStatusCode != null) {
        "Direct bootstrap failed (HTTP $httpStatusCode): $reason"
    } else {
        "Direct bootstrap failed: $reason"
    },
    cause
)

/**
 * Exception thrown when all bootstrap methods fail.
 *
 * The auto-bootstrap mechanism tries multiple methods in priority order.
 * When all configured methods fail, this exception is thrown containing
 * the individual errors from each attempt.
 *
 * @param attempts List of method-specific errors from each failed attempt.
 */
class BootstrapFailedException(
    val attempts: List<MethodAttemptError>
) : BootstrapException(buildAggregateMessage(attempts)) {
    companion object {
        private fun buildAggregateMessage(attempts: List<MethodAttemptError>): String {
            if (attempts.isEmpty()) {
                return "Bootstrap failed: no methods configured"
            }
            val details = attempts.joinToString(", ") { "${it.method}: ${it.error.message}" }
            return "Bootstrap failed: all methods failed [$details]"
        }
    }
}

/**
 * Records a single bootstrap method attempt failure.
 *
 * @property method The bootstrap method that was attempted.
 * @property error The exception that caused the failure.
 */
data class MethodAttemptError(
    val method: BootstrapMethod,
    val error: Throwable
)

/**
 * Exception thrown when bootstrap configuration is invalid.
 *
 * @param reason Description of the configuration error.
 */
class BootstrapConfigException(
    val reason: String
) : BootstrapException("Invalid bootstrap configuration: $reason")

/**
 * Exception thrown when no bootstrap methods are configured.
 *
 * At least one bootstrap method must be enabled for CA bundle retrieval.
 */
class NoMethodsConfiguredException : BootstrapException(
    "No bootstrap methods configured: enable at least one of DANE, Noise, SPKI, or Direct"
)

/**
 * Exception thrown when certificate parsing fails.
 *
 * @param reason Description of why certificate parsing failed.
 * @param cause The underlying exception, if any.
 */
class CertificateParseException(
    val reason: String,
    cause: Throwable? = null
) : BootstrapException("Certificate parsing failed: $reason", cause)
