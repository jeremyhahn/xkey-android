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

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.biometric.BiometricManager
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.AttestedKeyFingerprint
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * This device's **User Verification Key** — the key a `local.verifyUser`
 * answer is signed with (the desktop's `local.verifyUser` contract).
 *
 * The [DeviceAttestationKey] says *which handset* is answering and never
 * prompts, so an unattended reconnect stays possible. The UVK says *a person
 * with an enrolled Class 3 biometric approved this answer*: Keystore refuses
 * every signature until that biometric is presented, bound to the one
 * [Signature] it unlocks. Keeping the two apart means neither property can be
 * borrowed from the other — the DAK never prompts, and the UVK never signs an
 * attest or reattest transcript.
 *
 * The UVK's attestation chain is sealed at generation under the fixed
 * [AttestTranscript.USER_VERIFICATION_CHALLENGE] and proves the key's
 * authorization list (user authentication required, biometric-strong) to the
 * desktop; freshness comes from the signed transcript, as with the DAK.
 *
 * A new biometric enrollment permanently invalidates the key. That surfaces as
 * a [KeyInvalidatedException] from [initSignature]; the caller [regenerate]s
 * and asks once more.
 */
interface UserVerificationKey {

    /** Whether the key has been minted on this install. */
    fun exists(): Boolean

    /** The UVK's attestation chain, leaf first, minting the key on first call. */
    fun chain(): List<X509Certificate>

    /** `SHA-256(UVK SPKI)`, the last field of the verify-user transcript. */
    fun fingerprint(): ByteArray = AttestedKeyFingerprint.of(chain().first().encoded)

    /** Discards the key and mints a new one, returning its chain. */
    fun regenerate(): List<X509Certificate>

    /**
     * A `SHA256withECDSA` [Signature] initialised with the UVK, ready to wrap in
     * a `BiometricPrompt.CryptoObject`. It cannot sign until the prompt succeeds.
     *
     * @throws KeyInvalidatedException if a biometric enrollment invalidated the key.
     * @throws SigningException if the key cannot be loaded or initialised.
     */
    fun initSignature(): Signature
}

/**
 * Asks the user to approve one verify-user answer and returns the UVK's ASN.1
 * DER ECDSA signature over [message].
 *
 * Implementations raise the typed biometric exceptions — [UserCancelledException],
 * [BiometricLockoutException], [BiometricUnavailableException] — and
 * [KeyInvalidatedException] when the UVK has to be replaced; none of them is
 * ever turned into a result.
 */
fun interface UserVerificationPrompt {
    suspend fun sign(
        message: ByteArray,
        title: String,
        subtitle: String,
        showOnLockScreen: Boolean
    ): ByteArray
}

/**
 * The [UserVerificationKey] held in AndroidKeyStore, StrongBox when available.
 *
 * @param alias the Keystore alias; always [ALIAS] in the app. Device tests mint
 *   the same key under their own alias, so they never touch the user's.
 */
class KeystoreUserVerificationKey(
    private val context: Context,
    private val alias: String = ALIAS
) : UserVerificationKey {

    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun exists(): Boolean = keyStore.containsAlias(alias)

    /**
     * @throws BiometricUnavailableException if the key has to be minted and no
     *   Class 3 biometric is enrolled; Keystore cannot create a key bound to one.
     * @throws KeyGenerationException if the platform cannot mint an attested key.
     */
    override fun chain(): List<X509Certificate> {
        if (!keyStore.containsAlias(alias)) {
            return generate()
        }
        val existing = keyStore.getCertificateChain(alias)
            ?.filterIsInstance<X509Certificate>()
            .orEmpty()
        if (existing.isEmpty()) {
            Log.w(TAG, "User verification key alias held no certificate chain; regenerating")
            keyStore.deleteEntry(alias)
            return generate()
        }
        return existing
    }

    override fun regenerate(): List<X509Certificate> {
        if (keyStore.containsAlias(alias)) {
            Log.w(TAG, "Replacing the user verification key")
            keyStore.deleteEntry(alias)
        }
        return generate()
    }

    override fun initSignature(): Signature {
        chain()
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw SigningException("user verification key is not present")
        return try {
            Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(privateKey) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException("user verification key was invalidated by a biometric enrollment", e)
        } catch (e: Exception) {
            throw SigningException("user verification key could not be initialised", e)
        }
    }

    /** Mints the key, preferring StrongBox and falling back to the TEE. */
    private fun generate(): List<X509Certificate> {
        requireStrongBiometric()

        val spec = {
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .setAttestationChallenge(AttestTranscript.USER_VERIFICATION_CHALLENGE)
                .apply {
                    // Below API 30 the default validity (-1) already means a
                    // Class 3 biometric for every use.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    }
                }
        }

        try {
            return attestedChain(spec().setIsStrongBoxBacked(true).build())
        } catch (e: Exception) {
            Log.w(TAG, "StrongBox unavailable for the user verification key, falling back to TEE", e)
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
        return try {
            attestedChain(spec().build())
        } catch (e: KeyGenerationException) {
            throw e
        } catch (e: Exception) {
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
            throw KeyGenerationException("user verification key could not be generated", e)
        }
    }

    private fun attestedChain(spec: KeyGenParameterSpec): List<X509Certificate> {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )
        generator.initialize(spec)
        generator.generateKeyPair()

        val chain = keyStore.getCertificateChain(alias)
            ?.filterIsInstance<X509Certificate>()
            .orEmpty()
        if (chain.size < 2) {
            keyStore.deleteEntry(alias)
            throw KeyGenerationException(
                "this device produced no attestation chain for its user verification key"
            )
        }
        Log.i(TAG, "Minted the user verification key: ${chain.size} certificates in the chain")
        return chain
    }

    private fun requireStrongBiometric() {
        val status = BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        when (status) {
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                throw BiometricUnavailableException("no Class 3 biometric is enrolled")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                throw BiometricUnavailableException("no Class 3 biometric is available")
        }
    }

    companion object {
        private const val TAG = "UserVerificationKey"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val EC_CURVE = "secp256r1"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /**
         * The one alias. Deliberately outside the `xkey_credential_` namespace,
         * so credential sync and cleanup never see it.
         */
        const val ALIAS = "xkey_user_verification_key"

        /** The `signatureAlgorithm` reported on the wire. */
        const val WIRE_SIGNATURE_ALGORITHM = "ES256"
    }
}
