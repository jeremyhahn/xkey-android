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
import android.security.keystore.KeyProperties
import android.util.Log
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.AttestedKeyFingerprint
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * This device's **Device Attestation Key** — the persistent, hardware-backed key
 * that *is* its identity to a paired xkey desktop (go-xkms#129).
 *
 * ## Why the key persists, where the enrollment key does not
 *
 * [com.automatethethings.xkey.ca.DeviceIdentity] mints a fresh key for every
 * enrollment, and that is right for an LDevID: a CA is asking whether the device
 * is sound *now*, and only a fresh attestation says anything about the present.
 *
 * The DAK answers a different question — "are you the same handset I paired
 * with?" — and a key that rotates cannot answer it at all. Keystore seals the
 * attestation challenge at key **generation** and offers no way to re-attest an
 * existing key, so a challenge drawn per pairing would force a new key per
 * pairing and the fingerprint would move every time. That measured impossibility
 * is why the owner replaced the embedded-challenge model on 2026-08-24.
 *
 * So this key is generated once, under the fixed
 * [AttestTranscript.GENESIS_CHALLENGE], and kept. Its attestation chain proves
 * *once* that the key lives in hardware on a verified-boot device; freshness
 * comes separately, from [sign] over a live transcript, on every exchange.
 *
 * ## Identity
 *
 * `SHA-256(leaf SubjectPublicKeyInfo)` — see [AttestedKeyFingerprint]. The SPKI
 * is hashed rather than the leaf DER because an honest re-attestation reissues
 * the leaf with a fresh serial and validity window while leaving the key alone:
 * an SPKI hash moves only on a genuine [rotate].
 *
 * ## Rotation
 *
 * [rotate] is a deliberate act and a **hard break**: the new key has a new
 * fingerprint, so every desktop holding the old one refuses to reconnect rather
 * than silently rebinding to whatever key answers. Recovering means re-pairing
 * (`xkey device pair --force`), which is the intended cost — a device identity
 * that could be replaced quietly would not be an identity. A factory reset or an
 * app reinstall clears the Keystore and has the same effect.
 *
 * Thread safety: stateless beyond the Keystore handle; concurrent [sign] calls
 * each build their own [Signature].
 */
class DeviceAttestationKey {

    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** Whether this install has already minted its Device Attestation Key. */
    fun exists(): Boolean = keyStore.containsAlias(ALIAS)

    /**
     * The DAK's attestation chain, minting the key on first call.
     *
     * The chain is leaf-first: `chain[0]` certifies the DAK itself and is the
     * certificate the desktop verifies to a trusted Android hardware root.
     *
     * @throws AttestationException if the platform produces no attestation chain.
     *   A lone self-signed certificate means there is no Google-rooted path, so
     *   nothing about hardware backing has been proven and the desktop must not
     *   be handed it as though it had been. Refusing here keeps the failure at
     *   the device that cannot attest, rather than shipping evidence that proves
     *   nothing.
     */
    fun chain(): List<X509Certificate> {
        if (!keyStore.containsAlias(ALIAS)) {
            return generate()
        }
        val existing = keyStore.getCertificateChain(ALIAS)
            ?.filterIsInstance<X509Certificate>()
            .orEmpty()
        if (existing.isEmpty()) {
            // An alias with no chain is a half-created entry from an interrupted
            // generation; there is nothing to preserve, so replace it.
            Log.w(TAG, "Device attestation key alias held no certificate chain; regenerating")
            keyStore.deleteEntry(ALIAS)
            return generate()
        }
        return existing
    }

    /**
     * The 32 raw bytes of this device's fingerprint, `SHA-256(DAK SPKI)`.
     *
     * This is the value the phone stores at pairing and echoes in the identity
     * ack on reconnect, and the value committed to inside every signed
     * transcript.
     */
    fun fingerprint(): ByteArray = AttestedKeyFingerprint.of(chain().first().encoded)

    /** Lowercase hex of [fingerprint], the form persisted with a paired device. */
    fun fingerprintHex(): String = AttestedKeyFingerprint.hexOf(chain().first().encoded)

    /**
     * Signs [message] with the DAK, returning an ASN.1 DER ECDSA signature —
     * what `ecdsa.VerifyASN1` reads on the go-xkms side.
     *
     * The key carries no user-authentication requirement, so this never prompts.
     * Whether the *operation* needs the user present is a policy decision made by
     * the caller (`AttestationBiometricPolicy`), not a property of the key: an
     * auth-bound DAK would make an unattended reconnect impossible.
     *
     * Mints the key first if this install has none — the same on-demand contract
     * as [chain], so the two cannot disagree about whether an identity exists.
     * Reading the alias directly instead would fail on a fresh install, and on
     * any reinstall, since that clears the Keystore.
     *
     * @throws SigningException if the key cannot be loaded or the platform
     *   refuses to sign.
     * @throws AttestationException if the key has to be minted and this device
     *   cannot produce an attestation chain.
     */
    fun sign(message: ByteArray): ByteArray {
        chain()
        val entry = keyStore.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw SigningException("device attestation key is not present")
        return try {
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initSign(entry.privateKey)
                update(message)
                sign()
            }
        } catch (e: Exception) {
            throw SigningException("device attestation key could not sign the transcript", e)
        }
    }

    /**
     * Discards the current DAK and mints a new one, returning its chain.
     *
     * Every existing pairing is invalidated: the fingerprint the desktops hold no
     * longer matches, and they fail closed. Call this only on an explicit user
     * action, never as recovery from a transient error.
     */
    fun rotate(): List<X509Certificate> {
        if (keyStore.containsAlias(ALIAS)) {
            Log.w(TAG, "Rotating the device attestation key; every existing pairing is invalidated")
            keyStore.deleteEntry(ALIAS)
        }
        return generate()
    }

    /**
     * Mints the key, preferring StrongBox and falling back to the TEE.
     *
     * The fallback wraps `generateKeyPair()` rather than the builder call:
     * requesting StrongBox always succeeds at build time and only fails when the
     * key is actually generated, so a guard around the builder catches nothing.
     */
    private fun generate(): List<X509Certificate> {
        val spec = {
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(AttestTranscript.GENESIS_CHALLENGE)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return attestedChain(spec().setIsStrongBoxBacked(true).build())
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox unavailable for the device attestation key, falling back to TEE", e)
                if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
            }
        }
        return attestedChain(spec().build())
    }

    private fun attestedChain(spec: KeyGenParameterSpec): List<X509Certificate> {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )
        generator.initialize(spec)
        generator.generateKeyPair()

        val chain = keyStore.getCertificateChain(ALIAS)
            ?.filterIsInstance<X509Certificate>()
            .orEmpty()
        if (chain.size < 2) {
            keyStore.deleteEntry(ALIAS)
            throw AttestationException(
                "this device produced no attestation chain for its device attestation key, " +
                    "so hardware backing cannot be proven"
            )
        }
        Log.i(TAG, "Minted the device attestation key: ${chain.size} certificates in the chain")
        return chain
    }

    companion object {
        private const val TAG = "DeviceAttestationKey"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val EC_CURVE = "secp256r1"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /**
         * The one alias. Unlike the enrollment key there is no generation
         * counter: nothing stages behind this key, and rotation is meant to be a
         * visible break rather than a swap that keeps the old identity alive.
         */
        const val ALIAS = "xkey_device_attestation_key"

        /** The `signatureAlgorithm` this prover reports on the wire. */
        const val WIRE_SIGNATURE_ALGORITHM = "ES256"
    }
}
