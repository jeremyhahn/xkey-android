/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.crypto

import com.automatethethings.xkey.protocol.CoseAlgorithms
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The ML-DSA parameter sets, their wire spellings and COSE ids (FIPS 204). */
class PqcKeysTest {

    private val saved = PqcHardware.backend

    @After
    fun restore() {
        PqcHardware.backend = saved
    }

    @Test
    fun `each set carries its FIPS 204 sizes, OID and COSE id`() {
        val expected = listOf(
            listOf("ML-DSA-44", -48, "2.16.840.1.101.3.4.3.17", 1312, 2420),
            listOf("ML-DSA-65", -49, "2.16.840.1.101.3.4.3.18", 1952, 3309),
            listOf("ML-DSA-87", -50, "2.16.840.1.101.3.4.3.19", 2592, 4627)
        )
        assertEquals(expected.size, MlDsaParameterSet.entries.size)
        for ((set, row) in MlDsaParameterSet.entries.zip(expected)) {
            assertEquals(row, listOf(set.wireName, set.coseAlgorithm, set.oid, set.publicKeyBytes, set.signatureBytes))
        }
    }

    @Test
    fun `fromWireName accepts the dashed, joined and underscored spellings in any case`() {
        for (set in MlDsaParameterSet.entries) {
            val digits = set.wireName.removePrefix("ML-DSA-")
            for (name in listOf(set.wireName, "MLDSA$digits", "ml_dsa_$digits", "ml-dsa-$digits", set.name)) {
                assertEquals(name, set, MlDsaParameterSet.fromWireName(name))
            }
        }
    }

    @Test
    fun `fromWireName refuses other names`() {
        for (name in listOf("", "ML-DSA", "ML-DSA-99", "ML-KEM-768", "ES256", "SLH-DSA-SHA2-128S", "Ed25519")) {
            assertNull(name, MlDsaParameterSet.fromWireName(name))
        }
    }

    @Test
    fun `COSE names and ids round trip`() {
        for (set in MlDsaParameterSet.entries) {
            assertEquals(set.coseAlgorithm, CoseAlgorithms.fromName(set.wireName))
            assertEquals(set.coseAlgorithm, CoseAlgorithms.fromName("MLDSA" + set.wireName.takeLast(2)))
            assertEquals(set.wireName, CoseAlgorithms.getAlgorithmName(set.coseAlgorithm))
            assertEquals(set.publicKeyBytes * 8, CoseAlgorithms.getKeySizeBits(set.coseAlgorithm))
            assertTrue(CoseAlgorithms.isMlDsa(set.coseAlgorithm))
        }
        assertFalse(CoseAlgorithms.isMlDsa(CoseAlgorithms.ES256))
    }

    @Test
    fun `backings carry their wire names`() {
        assertEquals("hardware", PqcBacking.HARDWARE.wire)
        assertEquals("software", PqcBacking.SOFTWARE.wire)
    }

    @Test
    fun `no backend means no hardware set`() {
        PqcHardware.backend = null
        assertEquals(emptySet<MlDsaParameterSet>(), PqcHardware.supported())
    }

    @Test
    fun `supported reports what the backend makes`() {
        PqcHardware.backend = object : PqcHardwareBackend {
            override fun supportedParameterSets() = setOf(MlDsaParameterSet.ML_DSA_65)
            override fun generate(
                alias: String,
                set: MlDsaParameterSet,
                authDurationSeconds: Int,
                preferStrongBox: Boolean
            ): ByteArray = throw UnsupportedOperationException()
            override fun jcaSignatureAlgorithm(set: MlDsaParameterSet) = set.wireName
        }
        assertEquals(setOf(MlDsaParameterSet.ML_DSA_65), PqcHardware.supported())
    }
}
