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
 * Removes one certificate from the trust store and its database row.
 *
 * @param deleteRow deletes the certificate's database row
 * @return true when the certificate is no longer trusted
 */
public suspend fun removeTrustedCertificate(
    repository: TrustStoreRepository,
    fingerprint: String,
    deleteRow: suspend () -> Unit
): Boolean {
    deleteRow()
    repository.deleteCertificate(fingerprint)
    return true
}

/**
 * Clears the trust store and the database rows of its certificates.
 *
 * @param deleteRow deletes the database row of one fingerprint
 */
public suspend fun clearTrustStore(
    repository: TrustStoreRepository,
    deleteRow: suspend (String) -> Unit
): ClearResult {
    repository.getAllCertificates().forEach { deleteRow(it.fingerprint) }
    return repository.clearAll()
}
