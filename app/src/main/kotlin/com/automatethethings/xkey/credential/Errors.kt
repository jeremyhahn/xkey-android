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
package com.automatethethings.xkey.credential

/**
 * Base exception for all CredentialProvider operations.
 */
sealed class CredentialProviderException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * Exception thrown when the request data is invalid or malformed.
 */
class InvalidRequestException(
    val reason: String,
    cause: Throwable? = null
) : CredentialProviderException("Invalid request: $reason", cause)

/**
 * Exception thrown when no matching credentials are found.
 */
class NoCredentialsFoundException(
    val rpId: String
) : CredentialProviderException("No credentials found for relying party: $rpId")

/**
 * Exception thrown when credential creation fails.
 */
class CredentialCreationException(
    val reason: String,
    cause: Throwable? = null
) : CredentialProviderException("Credential creation failed: $reason", cause)

/**
 * Exception thrown when credential assertion fails.
 */
class CredentialAssertionException(
    val reason: String,
    cause: Throwable? = null
) : CredentialProviderException("Credential assertion failed: $reason", cause)

/**
 * Exception thrown when user verification fails.
 */
class UserVerificationException(
    val reason: String,
    cause: Throwable? = null
) : CredentialProviderException("User verification failed: $reason", cause)

/**
 * Exception thrown when the user cancels the operation.
 */
class UserCancelledCredentialException : CredentialProviderException(
    "User cancelled the credential operation"
)

/**
 * Exception thrown when the credential provider is not enabled.
 */
class ProviderNotEnabledException : CredentialProviderException(
    "Credential provider is not enabled"
)
