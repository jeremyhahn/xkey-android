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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The PIV algorithm names a peer may send: the enum names, the desktop's
 * spellings and the older dashed spellings all name the same algorithms.
 */
class PivAlgorithmWireNameTest {

    @Test
    fun `enum names map to themselves`() {
        for (algorithm in PivAlgorithm.entries) {
            assertEquals(algorithm, PivAlgorithm.fromWireName(algorithm.name))
        }
    }

    @Test
    fun `desktop spellings map to the phone's algorithms`() {
        val expected = mapOf(
            "ECCP256" to PivAlgorithm.ES256,
            "ECCP384" to PivAlgorithm.ES384,
            "RSA2048" to PivAlgorithm.RS2048,
            "RSA3072" to PivAlgorithm.RS3072,
            "RSA4096" to PivAlgorithm.RS4096,
            "RSA-2048" to PivAlgorithm.RS2048,
            "RSA-3072" to PivAlgorithm.RS3072,
            "RSA-4096" to PivAlgorithm.RS4096,
            "ECDSA-P256" to PivAlgorithm.ES256,
            "ECDSA-P384" to PivAlgorithm.ES384,
            "eccp256" to PivAlgorithm.ES256,
            "rsa_4096" to PivAlgorithm.RS4096,
            "ML-DSA-44" to PivAlgorithm.ML_DSA_44,
            "ML-DSA-65" to PivAlgorithm.ML_DSA_65,
            "MLDSA65" to PivAlgorithm.ML_DSA_65,
            "ml_dsa_87" to PivAlgorithm.ML_DSA_87
        )
        for ((name, algorithm) in expected) {
            assertEquals(name, algorithm, PivAlgorithm.fromWireName(name))
        }
    }

    @Test
    fun `unknown or blank names are not an algorithm`() {
        assertNull(PivAlgorithm.fromWireName(""))
        assertNull(PivAlgorithm.fromWireName("RSA1024"))
        assertNull(PivAlgorithm.fromWireName("RSA-8192"))
        assertNull(PivAlgorithm.fromWireName("ECCP521"))
        assertNull(PivAlgorithm.fromWireName("SLH-DSA-SHA2-128S"))
        assertNull(PivAlgorithm.fromWireName("ML-DSA-99"))
    }
}
