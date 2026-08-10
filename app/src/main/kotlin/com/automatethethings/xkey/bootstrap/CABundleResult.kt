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
 * Result of a successful CA bundle fetch operation.
 *
 * Contains the PEM-encoded certificate bundle, individual DER-encoded certificates,
 * and metadata about the fetch operation. This data class is designed to be compatible
 * with go-xkms's bootstrap response format.
 *
 * @property bundlePEM The raw PEM-encoded certificate chain bytes.
 * @property certificates List of individual DER-encoded certificate bytes.
 * @property method The bootstrap method that successfully retrieved the bundle.
 * @property fetchedAt Unix timestamp (milliseconds) when the bundle was fetched.
 */
data class CABundleResult(
    val bundlePEM: ByteArray,
    val certificates: List<ByteArray>,
    val method: BootstrapMethod,
    val fetchedAt: Long = System.currentTimeMillis()
) {
    /**
     * Returns the number of certificates in the bundle.
     */
    val certificateCount: Int
        get() = certificates.size

    /**
     * Returns true if the bundle contains at least one certificate.
     */
    val isNotEmpty: Boolean
        get() = certificates.isNotEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CABundleResult) return false

        if (!bundlePEM.contentEquals(other.bundlePEM)) return false
        if (certificates.size != other.certificates.size) return false
        for (i in certificates.indices) {
            if (!certificates[i].contentEquals(other.certificates[i])) return false
        }
        if (method != other.method) return false
        if (fetchedAt != other.fetchedAt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = bundlePEM.contentHashCode()
        result = 31 * result + certificates.fold(0) { acc, cert -> 31 * acc + cert.contentHashCode() }
        result = 31 * result + method.hashCode()
        result = 31 * result + fetchedAt.hashCode()
        return result
    }

    override fun toString(): String {
        return "CABundleResult(method=$method, certificates=${certificates.size}, " +
                "bundleSize=${bundlePEM.size}, fetchedAt=$fetchedAt)"
    }
}
