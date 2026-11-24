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

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.annotation.VisibleForTesting
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.spec.NamedParameterSpec
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * ML-DSA keys in the Android Keystore (API 37+, `KeyProperties.KEY_ALGORITHM_ML_DSA`).
 *
 * Which sets a device makes in hardware is learned once, in the background:
 * [startProbe] generates a throwaway key per set under [probeAlias], reads
 * its [KeyInfo] level and deletes it. Only a set whose probe key came back
 * in the TEE or StrongBox is reported. Until the probe ends, and always
 * below API 37, [supportedParameterSets] is empty, so no dialog offers
 * hardware and `keyBacking: "hardware"` is refused.
 *
 * @param sdkInt the device API level; injected by tests.
 * @param probe generates, reads back and deletes a probe key of a set and
 *   returns its `KeyProperties.SECURITY_LEVEL_*`, or null or a throw when the
 *   set cannot be made; injected by tests.
 * @param ioDispatcher where the probe runs, never the main thread.
 */
class KeystorePqcBackend(
    private val sdkInt: Int = Build.VERSION.SDK_INT,
    private val probe: (MlDsaParameterSet) -> Int? = ::probeOnce,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : PqcHardwareBackend {

    private val supported = AtomicReference<Set<MlDsaParameterSet>>(emptySet())
    private val started = AtomicBoolean(false)
    private val probed = CompletableDeferred<Set<MlDsaParameterSet>>()

    /** The sets the probe found in the TEE or StrongBox; empty until it ends. Never blocks. */
    override fun supportedParameterSets(): Set<MlDsaParameterSet> =
        if (sdkInt < MIN_SDK) emptySet() else supported.get()

    /**
     * Starts the probe on [ioDispatcher] in [scope]. Runs once per backend;
     * later calls do nothing. Below API 37 no probe runs.
     */
    fun startProbe(scope: CoroutineScope) {
        if (!started.compareAndSet(false, true)) return
        if (sdkInt < MIN_SDK) {
            probed.complete(emptySet())
            return
        }
        scope.launch(ioDispatcher) {
            try {
                val found = MlDsaParameterSet.entries.filterTo(LinkedHashSet()) { set ->
                    probeLevel(set)?.let { it in HARDWARE_LEVELS } == true
                }
                supported.set(found.toSet())
            } finally {
                probed.complete(supported.get())
            }
        }
    }

    /** Waits up to [timeoutMs] for the probe; the sets found so far on timeout. Tests only. */
    @VisibleForTesting
    fun awaitProbe(timeoutMs: Long): Set<MlDsaParameterSet> = runBlocking {
        withTimeoutOrNull(timeoutMs) { probed.await() } ?: supportedParameterSets()
    }

    /**
     * Generates a non-exportable [set] signing key under [alias], replacing
     * any entry there, and returns its SubjectPublicKeyInfo DER.
     *
     * [authDurationSeconds] follows the EC keys: negative needs no user
     * authentication, zero authenticates every use, positive keeps one
     * authentication valid that many seconds. [preferStrongBox] asks
     * StrongBox first and falls back to the TEE when StrongBox refuses.
     * Blocks on the Keystore: never call it on the main thread.
     *
     * @throws UnsupportedAlgorithmException if the probe did not report [set].
     * @throws KeyGenerationException if the Keystore fails or returns a key
     *   that is not a [set] SubjectPublicKeyInfo.
     */
    override fun generate(
        alias: String,
        set: MlDsaParameterSet,
        authDurationSeconds: Int,
        preferStrongBox: Boolean
    ): ByteArray {
        if (set !in supportedParameterSets()) throw UnsupportedAlgorithmException(set.wireName)
        if (Build.VERSION.SDK_INT < MIN_SDK) throw UnsupportedAlgorithmException(set.wireName)

        val keyStore = androidKeyStore()
        val spki = try {
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
            generateKeyPair(alias, set, authDurationSeconds, preferStrongBox).public.encoded
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate ${set.wireName} key", e)
        }
        try {
            checkSpki(set, spki)
        } catch (e: KeyGenerationException) {
            runCatching { keyStore.deleteEntry(alias) }
            throw e
        }
        return spki
    }

    /** `"ML-DSA"`: the platform's `KeyProperties.KEY_ALGORITHM_ML_DSA`, for every set. */
    override fun jcaSignatureAlgorithm(set: MlDsaParameterSet): String = ML_DSA

    /** The probe's level for [set]; null when it throws, so a failing set is unsupported. */
    private fun probeLevel(set: MlDsaParameterSet): Int? = try {
        probe(set)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        null
    } catch (e: LinkageError) {
        null
    }

    companion object {
        /** The API level that added `KeyProperties.KEY_ALGORITHM_ML_DSA` (android-37.0). */
        const val MIN_SDK = 37

        /** Equal to `KeyProperties.KEY_ALGORITHM_ML_DSA`, inlined to need no API guard. */
        private const val ML_DSA = "ML-DSA"

        private const val PROBE_ALIAS_PREFIX = "xkey_pqc_probe_"

        private val HARDWARE_LEVELS = setOf(
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            KeyProperties.SECURITY_LEVEL_STRONGBOX
        )

        /** The Keystore alias of [set]'s throwaway probe key. */
        fun probeAlias(set: MlDsaParameterSet): String = PROBE_ALIAS_PREFIX + set.name.lowercase()

        /**
         * Checks that [der] is a SubjectPublicKeyInfo with [set]'s OID and a
         * public key of [set]'s size.
         *
         * @throws KeyGenerationException if it is not.
         */
        fun checkSpki(set: MlDsaParameterSet, der: ByteArray) {
            val info = try {
                SubjectPublicKeyInfo.getInstance(der)
            } catch (e: Exception) {
                throw KeyGenerationException("${set.wireName} public key is not a SubjectPublicKeyInfo", e)
            }
            val oid = info.algorithm.algorithm.id
            if (oid != set.oid) {
                throw KeyGenerationException("${set.wireName} public key has OID $oid, not ${set.oid}")
            }
            val key = info.publicKeyData
            if (key.padBits != 0 || key.bytes.size != set.publicKeyBytes) {
                throw KeyGenerationException(
                    "${set.wireName} public key is ${key.bytes.size} bytes, not ${set.publicKeyBytes}"
                )
            }
        }
    }
}

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

/**
 * The default probe: generates [set] in the TEE under its probe alias with
 * no user authentication, checks the public key, reads the private key's
 * [KeyInfo] level and deletes the key whatever happened.
 */
private fun probeOnce(set: MlDsaParameterSet): Int? {
    if (Build.VERSION.SDK_INT < KeystorePqcBackend.MIN_SDK) return null
    val alias = KeystorePqcBackend.probeAlias(set)
    val keyStore = androidKeyStore()
    try {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        val pair = generateWith(alias, set, authDurationSeconds = -1, strongBox = false)
        KeystorePqcBackend.checkSpki(set, pair.public.encoded)
        val info = KeyFactory.getInstance(pair.private.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(pair.private, KeyInfo::class.java)
        return info.securityLevel
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

/**
 * StrongBox first when [preferStrongBox], then the TEE: as the EC keys do,
 * any StrongBox refusal (`StrongBoxUnavailableException`, or a StrongBox
 * that does not make ML-DSA) falls back to the TEE.
 */
@RequiresApi(KeystorePqcBackend.MIN_SDK)
private fun generateKeyPair(
    alias: String,
    set: MlDsaParameterSet,
    authDurationSeconds: Int,
    preferStrongBox: Boolean
): KeyPair {
    if (preferStrongBox) {
        try {
            return generateWith(alias, set, authDurationSeconds, strongBox = true)
        } catch (e: Exception) {
            // The TEE below.
        }
    }
    return generateWith(alias, set, authDurationSeconds, strongBox = false)
}

/**
 * Generates [set] under [alias]: a PURPOSE_SIGN spec naming the set with
 * `NamedParameterSpec("ML-DSA-<n>")`, asked of `KeyPairGenerator` as
 * `"ML-DSA"`, then by the set's own algorithm name where the platform has
 * one, if the generic name is refused.
 */
@RequiresApi(KeystorePqcBackend.MIN_SDK)
private fun generateWith(
    alias: String,
    set: MlDsaParameterSet,
    authDurationSeconds: Int,
    strongBox: Boolean
): KeyPair {
    var refused: GeneralSecurityException? = null
    for (algorithm in generatorAlgorithms(set)) {
        try {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(NamedParameterSpec(set.wireName))
            applyAuthDuration(builder, authDurationSeconds)
            if (strongBox) builder.setIsStrongBoxBacked(true)
            val generator = KeyPairGenerator.getInstance(algorithm, ANDROID_KEYSTORE)
            generator.initialize(builder.build())
            return generator.generateKeyPair()
        } catch (e: GeneralSecurityException) {
            // NoSuchAlgorithmException or InvalidAlgorithmParameterException: try the next name.
            refused = e
        }
    }
    throw refused ?: NoSuchAlgorithmException(set.wireName)
}

@RequiresApi(KeystorePqcBackend.MIN_SDK)
private fun generatorAlgorithms(set: MlDsaParameterSet): List<String> = when (set) {
    MlDsaParameterSet.ML_DSA_44 -> listOf(KeyProperties.KEY_ALGORITHM_ML_DSA)
    MlDsaParameterSet.ML_DSA_65 ->
        listOf(KeyProperties.KEY_ALGORITHM_ML_DSA, KeyProperties.KEY_ALGORITHM_ML_DSA_65)
    MlDsaParameterSet.ML_DSA_87 ->
        listOf(KeyProperties.KEY_ALGORITHM_ML_DSA, KeyProperties.KEY_ALGORITHM_ML_DSA_87)
}

/** The EC keys' user-authentication rule (`KeystoreManager.applyAuthDuration`), API 30+ form. */
@RequiresApi(KeystorePqcBackend.MIN_SDK)
private fun applyAuthDuration(builder: KeyGenParameterSpec.Builder, authDurationSeconds: Int) {
    if (authDurationSeconds < 0) {
        builder.setUserAuthenticationRequired(false)
        return
    }
    builder.setUserAuthenticationRequired(true)
    builder.setUserAuthenticationParameters(authDurationSeconds, KeyProperties.AUTH_BIOMETRIC_STRONG)
}
