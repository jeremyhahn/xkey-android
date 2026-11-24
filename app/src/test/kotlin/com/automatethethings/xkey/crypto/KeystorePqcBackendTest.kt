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

import android.security.keystore.KeyProperties
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * [KeystorePqcBackend] with an injected SDK level and probe: nothing is
 * probed below API 37, a set is reported only when its probe key read back
 * TEE or StrongBox, and nothing blocks while the probe runs.
 */
class KeystorePqcBackendTest {

    /** [KeystorePqcBackend.awaitProbe] from a plain test thread. */
    private fun KeystorePqcBackend.awaitProbeBlocking(timeoutMs: Long): Set<MlDsaParameterSet> =
        runBlocking { awaitProbe(timeoutMs) }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @After
    fun tearDown() {
        scope.cancel()
    }

    @Test
    fun `below API 37 nothing is supported and no probe runs`() {
        for (sdk in 28 until KeystorePqcBackend.MIN_SDK) {
            val calls = AtomicInteger()
            val backend = KeystorePqcBackend(sdkInt = sdk, probe = { _, _ ->
                calls.incrementAndGet()
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            })
            backend.startProbe(scope)
            assertEquals("API $sdk", emptySet<MlDsaParameterSet>(), backend.awaitProbeBlocking(5_000))
            assertEquals("API $sdk", emptySet<MlDsaParameterSet>(), backend.supportedParameterSets())
            assertEquals("API $sdk runs no probe", 0, calls.get())
        }
    }

    @Test
    fun `only sets whose probe key is in the TEE or StrongBox are reported`() {
        val levels = mapOf(
            MlDsaParameterSet.ML_DSA_44 to KeyProperties.SECURITY_LEVEL_SOFTWARE,
            MlDsaParameterSet.ML_DSA_65 to KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            MlDsaParameterSet.ML_DSA_87 to KeyProperties.SECURITY_LEVEL_STRONGBOX
        )
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { set, _ -> levels[set] })
        backend.startProbe(scope)

        val expected = setOf(MlDsaParameterSet.ML_DSA_65, MlDsaParameterSet.ML_DSA_87)
        assertEquals(expected, backend.awaitProbeBlocking(5_000))
        assertEquals(expected, backend.supportedParameterSets())
    }

    @Test
    fun `a set the TEE refuses but StrongBox makes is kept`() {
        val asked = mutableListOf<Pair<MlDsaParameterSet, Boolean>>()
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { set, strongBox ->
            synchronized(asked) { asked += set to strongBox }
            when {
                strongBox -> KeyProperties.SECURITY_LEVEL_STRONGBOX
                set == MlDsaParameterSet.ML_DSA_44 -> throw IllegalStateException("no TEE ML-DSA-44")
                else -> null
            }
        })
        backend.startProbe(scope)

        assertEquals(MlDsaParameterSet.entries.toSet(), backend.awaitProbeBlocking(5_000))
        assertTrue(asked.containsAll(MlDsaParameterSet.entries.map { it to true }))
    }

    @Test
    fun `a set both backends refuse or make in software is dropped`() {
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { set, strongBox ->
            when (set) {
                MlDsaParameterSet.ML_DSA_44 -> if (strongBox) throw IllegalStateException("no StrongBox") else null
                MlDsaParameterSet.ML_DSA_65 -> KeyProperties.SECURITY_LEVEL_SOFTWARE
                MlDsaParameterSet.ML_DSA_87 ->
                    if (strongBox) KeyProperties.SECURITY_LEVEL_SOFTWARE else throw IllegalStateException("no TEE")
            }
        })
        backend.startProbe(scope)
        assertEquals(emptySet<MlDsaParameterSet>(), backend.awaitProbeBlocking(5_000))
    }

    @Test
    fun `a probe that throws, returns null or an unknown level reports nothing`() {
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { set, _ ->
            when (set) {
                MlDsaParameterSet.ML_DSA_44 -> throw IllegalStateException("no ML-DSA-44")
                MlDsaParameterSet.ML_DSA_65 -> null
                MlDsaParameterSet.ML_DSA_87 -> KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
            }
        })
        backend.startProbe(scope)
        assertEquals(emptySet<MlDsaParameterSet>(), backend.awaitProbeBlocking(5_000))
    }

    @Test
    fun `one failing set does not hide the others`() {
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { set, _ ->
            if (set == MlDsaParameterSet.ML_DSA_65) throw RuntimeException("probe failed")
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        })
        backend.startProbe(scope)
        assertEquals(
            setOf(MlDsaParameterSet.ML_DSA_44, MlDsaParameterSet.ML_DSA_87),
            backend.awaitProbeBlocking(5_000)
        )
    }

    @Test
    fun `supported sets are empty and do not block before the probe ends`() {
        val release = CountDownLatch(1)
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { _, _ ->
            release.await(10, TimeUnit.SECONDS)
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        })
        assertEquals("before the probe starts", emptySet<MlDsaParameterSet>(), backend.supportedParameterSets())
        backend.startProbe(scope)

        val started = System.nanoTime()
        assertEquals("while the probe runs", emptySet<MlDsaParameterSet>(), backend.supportedParameterSets())
        assertTrue("never blocks", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 1_000)

        release.countDown()
        assertEquals(MlDsaParameterSet.entries.toSet(), backend.awaitProbeBlocking(5_000))
        assertEquals(MlDsaParameterSet.entries.toSet(), backend.supportedParameterSets())
    }

    @Test
    fun `the probe runs once however often it is started`() {
        val calls = AtomicInteger()
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { _, _ ->
            calls.incrementAndGet()
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        })
        backend.startProbe(scope)
        backend.startProbe(scope)
        backend.awaitProbeBlocking(5_000)
        backend.startProbe(scope)
        backend.awaitProbeBlocking(5_000)
        assertEquals(MlDsaParameterSet.entries.size, calls.get())
    }

    @Test
    fun `generate refuses a set the probe did not report`() {
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { set, _ ->
            if (set == MlDsaParameterSet.ML_DSA_65) KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT else null
        })
        assertThrows("before the probe", UnsupportedAlgorithmException::class.java) {
            backend.generate("xkey_key_t", MlDsaParameterSet.ML_DSA_65, -1, false)
        }
        backend.startProbe(scope)
        backend.awaitProbeBlocking(5_000)
        assertThrows(UnsupportedAlgorithmException::class.java) {
            backend.generate("xkey_key_t", MlDsaParameterSet.ML_DSA_44, -1, false)
        }
        assertThrows(UnsupportedAlgorithmException::class.java) {
            backend.generate("xkey_key_t", MlDsaParameterSet.ML_DSA_87, 30, true)
        }
    }

    @Test
    fun `generate refuses everything below API 37`() {
        val backend = KeystorePqcBackend(sdkInt = 36, probe = { _, _ -> KeyProperties.SECURITY_LEVEL_STRONGBOX })
        backend.startProbe(scope)
        backend.awaitProbeBlocking(5_000)
        for (set in MlDsaParameterSet.entries) {
            assertThrows(set.wireName, UnsupportedAlgorithmException::class.java) {
                backend.generate("xkey_key_t", set, -1, false)
            }
        }
    }

    @Test
    fun `the JCA signature name is the platform's ML-DSA name for every set`() {
        val backend = KeystorePqcBackend(sdkInt = 37, probe = { _, _ -> null })
        for (set in MlDsaParameterSet.entries) {
            assertEquals(KeyProperties.KEY_ALGORITHM_ML_DSA, backend.jcaSignatureAlgorithm(set))
            assertEquals("ML-DSA", backend.jcaSignatureAlgorithm(set))
        }
    }

    @Test
    fun `probe aliases are distinct per set and never a general key alias`() {
        val aliases = MlDsaParameterSet.entries.map { KeystorePqcBackend.probeAlias(it) }
        assertEquals(aliases.size, aliases.toSet().size)
        for (alias in aliases) {
            assertTrue(alias, alias.startsWith("xkey_pqc_probe_"))
        }
    }

    @Test
    fun `the SPKI check takes the set's OID and size and refuses any other`() {
        for (set in MlDsaParameterSet.entries) {
            val spki = bcSpki(set)
            KeystorePqcBackend.checkSpki(set, spki)
            for (other in MlDsaParameterSet.entries - set) {
                assertThrows("${set.wireName} as ${other.wireName}", KeyGenerationException::class.java) {
                    KeystorePqcBackend.checkSpki(other, spki)
                }
            }
        }
        assertThrows(KeyGenerationException::class.java) {
            KeystorePqcBackend.checkSpki(MlDsaParameterSet.ML_DSA_65, byteArrayOf(0x30, 0x00))
        }
    }

/** A fake Keystore for the generation seam: the aliases it holds and every location asked. */
    private inner class FakeKeystore(private val level: (MlDsaParameterSet, Boolean) -> Int?) {
        val aliases: MutableSet<String> = java.util.Collections.synchronizedSet(mutableSetOf())
        val asked: MutableList<Pair<MlDsaParameterSet, Boolean>> =
            java.util.Collections.synchronizedList(mutableListOf())
        var failStrongBox = false

        fun generate(alias: String, set: MlDsaParameterSet, auth: Int, strongBox: Boolean): PqcGeneratedKey {
            asked += set to strongBox
            if (strongBox && failStrongBox) throw IllegalStateException("StrongBox refused")
            aliases += alias
            return PqcGeneratedKey(bcSpki(set), level(set, strongBox))
        }

        fun delete(alias: String) {
            aliases -= alias
        }
    }

    private fun backendWith(
        fake: FakeKeystore,
        probe: (MlDsaParameterSet, Boolean) -> Int?
    ): KeystorePqcBackend {
        val backend = KeystorePqcBackend(
            sdkInt = 37,
            probe = probe,
            generateKey = fake::generate,
            deleteKey = fake::delete
        )
        backend.startProbe(scope)
        backend.awaitProbeBlocking(5_000)
        return backend
    }

    @Test
    fun `a set only StrongBox makes in hardware is generated in StrongBox without preferStrongBox`() {
        val fake = FakeKeystore { _, strongBox ->
            if (strongBox) KeyProperties.SECURITY_LEVEL_STRONGBOX else KeyProperties.SECURITY_LEVEL_SOFTWARE
        }
        val backend = backendWith(fake) { _, strongBox ->
            if (strongBox) KeyProperties.SECURITY_LEVEL_STRONGBOX else null
        }

        val spki = backend.generate("xkey_key_sb", MlDsaParameterSet.ML_DSA_65, -1, preferStrongBox = false)

        KeystorePqcBackend.checkSpki(MlDsaParameterSet.ML_DSA_65, spki)
        assertEquals(listOf(MlDsaParameterSet.ML_DSA_65 to true), fake.asked.toList())
        assertTrue("xkey_key_sb" in fake.aliases)
    }

    @Test
    fun `a generated key at software level is refused and its alias deleted`() {
        val fake = FakeKeystore { _, _ -> KeyProperties.SECURITY_LEVEL_SOFTWARE }
        val backend = backendWith(fake) { _, strongBox ->
            if (strongBox) null else KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }

        assertThrows(KeyGenerationException::class.java) {
            backend.generate("xkey_key_sw", MlDsaParameterSet.ML_DSA_44, -1, preferStrongBox = false)
        }
        assertFalse("xkey_key_sw" in fake.aliases)
        assertEquals(listOf(MlDsaParameterSet.ML_DSA_44 to false), fake.asked.toList())
    }

    @Test
    fun `a StrongBox failure falls back to the TEE only when the TEE probed hardware`() {
        val teeToo = FakeKeystore { _, strongBox ->
            if (strongBox) KeyProperties.SECURITY_LEVEL_STRONGBOX else KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }.apply { failStrongBox = true }
        val both = backendWith(teeToo) { _, strongBox ->
            if (strongBox) KeyProperties.SECURITY_LEVEL_STRONGBOX else KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }
        both.generate("xkey_key_fb", MlDsaParameterSet.ML_DSA_87, -1, preferStrongBox = true)
        assertEquals(
            listOf(MlDsaParameterSet.ML_DSA_87 to true, MlDsaParameterSet.ML_DSA_87 to false),
            teeToo.asked.toList()
        )
        assertTrue("xkey_key_fb" in teeToo.aliases)

        val strongBoxOnly = FakeKeystore { _, strongBox ->
            if (strongBox) KeyProperties.SECURITY_LEVEL_STRONGBOX else KeyProperties.SECURITY_LEVEL_SOFTWARE
        }.apply { failStrongBox = true }
        val sbBackend = backendWith(strongBoxOnly) { _, strongBox ->
            if (strongBox) KeyProperties.SECURITY_LEVEL_STRONGBOX else null
        }
        assertThrows(KeyGenerationException::class.java) {
            sbBackend.generate("xkey_key_nf", MlDsaParameterSet.ML_DSA_87, -1, preferStrongBox = true)
        }
        assertEquals(listOf(MlDsaParameterSet.ML_DSA_87 to true), strongBoxOnly.asked.toList())
        assertFalse("xkey_key_nf" in strongBoxOnly.aliases)
    }

    @Test
    fun `no software-level key is ever kept whatever the set or location`() {
        val fake = FakeKeystore { _, _ -> KeyProperties.SECURITY_LEVEL_SOFTWARE }
        val backend = backendWith(fake) { _, strongBox ->
            if (strongBox) KeyProperties.SECURITY_LEVEL_STRONGBOX else KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }
        for (set in MlDsaParameterSet.entries) {
            for (prefer in listOf(false, true)) {
                assertThrows("$set prefer=$prefer", KeyGenerationException::class.java) {
                    backend.generate("xkey_key_${set.name}", set, -1, prefer)
                }
            }
        }
        assertEquals(emptySet<String>(), fake.aliases.toSet())
    }

    private fun bcSpki(set: MlDsaParameterSet): ByteArray {
        val params = when (set) {
            MlDsaParameterSet.ML_DSA_44 -> MLDSAParameters.ml_dsa_44
            MlDsaParameterSet.ML_DSA_65 -> MLDSAParameters.ml_dsa_65
            MlDsaParameterSet.ML_DSA_87 -> MLDSAParameters.ml_dsa_87
        }
        val generator = MLDSAKeyPairGenerator()
        generator.init(MLDSAKeyGenerationParameters(SecureRandom(), params))
        val pair = generator.generateKeyPair()
        return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.public).encoded
    }
}
