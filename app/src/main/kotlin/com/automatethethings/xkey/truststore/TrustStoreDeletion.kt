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
package com.automatethethings.xkey.truststore

/**
 * Removes one certificate from the trust store, then its database row.
 *
 * The row is deleted only once the certificate is neither on disk nor in the
 * trust store's metadata, so a certificate that stays trusted stays listed.
 *
 * @param deleteRow deletes the certificate's database row
 * @return true when the certificate is no longer trusted, false when the
 *   trust store could not remove it (its row is kept)
 */
public suspend fun removeTrustedCertificate(
    repository: TrustStoreRepository,
    fingerprint: String,
    deleteRow: suspend () -> Unit
): Boolean {
    if (!repository.deleteCertificate(fingerprint) && isStillStored(repository, fingerprint)) {
        return false
    }
    deleteRow()
    return true
}

/**
 * Clears the trust store, then deletes the database rows of the certificates
 * it removed; those it could not remove keep their rows.
 *
 * @param deleteRow deletes the database row of one fingerprint
 * @return the trust store's [ClearResult]; check [ClearResult.complete]
 */
public suspend fun clearTrustStore(
    repository: TrustStoreRepository,
    deleteRow: suspend (String) -> Unit
): ClearResult {
    val result = repository.clearAll()
    result.removed.forEach { deleteRow(it) }
    return result
}

private suspend fun isStillStored(repository: TrustStoreRepository, fingerprint: String): Boolean =
    repository.hasCertificate(fingerprint) || repository.getCertificate(fingerprint) != null
