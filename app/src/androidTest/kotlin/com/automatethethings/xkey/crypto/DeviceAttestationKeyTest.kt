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

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.AttestedKeyFingerprint
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import java.security.Signature

/**
 * The Device Attestation Key itself, against real Keystore hardware.
 *
 * This is the identity half of go-xkms#129: the properties asserted here —
 * a key that persists, a fingerprint that does not move, and a rotation that
 * breaks the binding on purpose — are what the desktop's stable
 * `DeviceFingerprint` rests on.
 */
@RunWith(AndroidJUnit4::class)
class DeviceAttestationKeyTest {

    private val dak = DeviceAttestationKey()

    /**
     * Identity persists. This is the property version 1 could not have: with the
     * pairing nonce as the attestation challenge, every exchange minted a new key
     * and the fingerprint moved with it.
     */
    @Test
    fun theKeyAndItsFingerprintPersistAcrossCalls() {
        val first = dak.fingerprintHex()
        val second = dak.fingerprintHex()
        val third = DeviceAttestationKey().fingerprintHex()

        assertEquals("the same instance must report a stable identity", first, second)
        assertEquals("a fresh instance must find the same key", first, third)
        assertTrue("the key must exist once it has been used", dak.exists())
    }

    /** The fingerprint is exactly what the desktop derives from the wire chain. */
    @Test
    fun theFingerprintIsSha256OfTheLeafSpki() {
        val leaf = dak.chain().first()

        assertArrayEquals(AttestedKeyFingerprint.of(leaf.encoded), dak.fingerprint())
        assertEquals(32, dak.fingerprint().size)
        assertEquals(AttestedKeyFingerprint.hexOf(leaf.encoded), dak.fingerprintHex())
    }

    /**
     * The chain must reach past the leaf, or nothing about hardware backing has
     * been proven: a lone self-signed certificate has no Google-rooted path for
     * the desktop to verify.
     */
    @Test
    fun theChainCarriesAnIssuerAndTheGenesisChallenge() {
        val chain = dak.chain()

        assertTrue("an attestation chain must carry more than the leaf", chain.size >= 2)

        val extension = chain.first().getExtensionValue(KEY_DESCRIPTION_OID)
        if (extension != null) {
            assertTrue(
                "the leaf must attest the genesis challenge",
                containsSubsequence(extension, AttestTranscript.GENESIS_CHALLENGE)
            )
        }
    }

    /** The key signs, and the signature verifies under the leaf it published. */
    @Test
    fun theKeySignsVerifiablyUnderItsOwnLeaf() {
        val message = ByteArray(64).also { SecureRandom().nextBytes(it) }

        val signature = dak.sign(message)

        assertTrue(verify(message, signature))
        assertFalse(
            "a signature must not verify over different bytes",
            verify(message.copyOf().also { it[0] = (it[0] + 1).toByte() }, signature)
        )
    }

    /**
     * Rotation is meant to be a visible break, not a swap.
     *
     * After it the fingerprint is different, which is exactly what makes every
     * desktop holding the old one fail closed rather than rebind to whatever key
     * now answers. Recovery is a re-pair, and that cost is the point.
     */
    @Test
    fun rotationChangesTheIdentityAndInvalidatesTheOldOne() {
        val before = dak.fingerprintHex()
        val message = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val signedBefore = dak.sign(message)
        assertTrue("precondition: the pre-rotation signature verifies", verify(message, signedBefore))

        dak.rotate()

        val after = dak.fingerprintHex()
        assertNotEquals("rotation must move the device fingerprint", before, after)
        assertFalse(
            "a signature by the retired key must no longer verify under the new one",
            verify(message, signedBefore)
        )
        assertTrue("the new key must sign", verify(message, dak.sign(message)))
    }

    /** Verifies [signature] over [message] under the DAK's current leaf. */
    private fun verify(message: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(dak.chain().first().publicKey)
            update(message)
            runCatching { verify(signature) }.getOrDefault(false)
        }

    /** True when [needle] appears anywhere inside [haystack]. */
    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (start in 0..(haystack.size - needle.size)) {
            for (offset in needle.indices) {
                if (haystack[start + offset] != needle[offset]) continue@outer
            }
            return true
        }
        return false
    }

    private companion object {
        /** Android Key Attestation extension OID. */
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
    }
}
