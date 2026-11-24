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

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.AttestedKeyFingerprint
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The life of the Device Attestation Key in the Keystore: when it is minted,
 * what replaces it, what its leaf attests, and how [DeviceAttestationKey.sign]
 * fails. [DeviceAttestationKeyTest] covers the steady state of a key that
 * already exists; every case here starts from a known Keystore entry under
 * [DeviceAttestationKey.ALIAS] and deletes it afterwards.
 */
@RunWith(AndroidJUnit4::class)
class DeviceAttestationKeyLifecycleTest {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    @Before
    fun startWithoutAKey() {
        deleteAlias()
    }

    @After
    fun deleteTheKey() {
        deleteAlias()
    }

    // -----------------------------------------------------------------
    // Minting
    // -----------------------------------------------------------------

    @Test
    fun chainMintsTheKeyOnFirstUseAndReturnsTheSameChainAfter() {
        val dak = DeviceAttestationKey()
        assertFalse("precondition: no key under the alias", dak.exists())

        val first = dak.chain()
        assertTrue("the first chain() mints the key", dak.exists())
        assertTrue("a minted key carries an attestation chain", first.size >= 2)

        val second = dak.chain()
        assertEquals("the chain is read back, not minted again", encodedOf(first), encodedOf(second))
        assertArrayEquals(
            "the fingerprint is that of the chain first returned",
            AttestedKeyFingerprint.of(first.first().encoded),
            dak.fingerprint()
        )
    }

    @Test
    fun signOnAnInstallWithNoKeyMintsItAndVerifiesUnderItsLeaf() {
        val dak = DeviceAttestationKey()
        val message = randomBytes(48)

        val signature = dak.sign(message)

        assertTrue("sign() mints the key on demand, as chain() does", dak.exists())
        assertTrue(
            "the signature verifies under the leaf of the key it minted",
            verify(DeviceAttestationKey().chain().first(), message, signature)
        )
    }

    // -----------------------------------------------------------------
    // Rotation
    // -----------------------------------------------------------------

    @Test
    fun rotateMintsANewLeafKeyAndReturnsTheChainItStores() {
        val dak = DeviceAttestationKey()
        val before = dak.chain().first()
        val fingerprintBefore = dak.fingerprint()

        val rotated = dak.rotate()

        assertTrue("a rotated key carries an attestation chain", rotated.size >= 2)
        assertFalse(
            "rotation mints a new key pair, not a reissued leaf",
            before.publicKey.encoded.contentEquals(rotated.first().publicKey.encoded)
        )
        assertEquals("chain() returns what rotate() stored", encodedOf(rotated), encodedOf(dak.chain()))
        assertArrayEquals(AttestedKeyFingerprint.of(rotated.first().encoded), dak.fingerprint())
        assertFalse(fingerprintBefore.contentEquals(dak.fingerprint()))
    }

    @Test
    fun rotateWithNoKeyMintsOne() {
        val dak = DeviceAttestationKey()

        val chain = dak.rotate()

        assertTrue(dak.exists())
        assertTrue(chain.size >= 2)
        assertEquals(encodedOf(chain), encodedOf(dak.chain()))
    }

    // -----------------------------------------------------------------
    // What the leaf attests
    // -----------------------------------------------------------------

    /**
     * The attestation extension is required, and its `attestationChallenge`
     * field is exactly the genesis challenge — not merely bytes that contain it.
     */
    @Test
    fun theLeafAttestsExactlyTheGenesisChallenge() {
        val leaf = DeviceAttestationKey().chain().first()

        val extension = leaf.getExtensionValue(KEY_DESCRIPTION_OID)
        assertNotNull("the leaf must carry the key attestation extension", extension)

        assertArrayEquals(AttestTranscript.GENESIS_CHALLENGE, attestationChallengeOf(extension!!))
    }

    @Test
    fun theLeafKeyIsAP256EcKey() {
        val leaf = DeviceAttestationKey().chain().first()
        assertEquals("EC", leaf.publicKey.algorithm)
        assertEquals(
            "a P-256 key in SubjectPublicKeyInfo is 91 bytes",
            P256_SPKI_SIZE,
            leaf.publicKey.encoded.size
        )
    }

    // -----------------------------------------------------------------
    // An unusable entry under the alias
    // -----------------------------------------------------------------

    /**
     * A secret key under the alias has no certificate chain: `chain()` treats
     * it as a half-created entry and replaces it with an attested key pair.
     */
    @Test
    fun anEntryWithNoChainIsReplacedRatherThanReturned() {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    DeviceAttestationKey.ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
            generateKey()
        }
        assertTrue("precondition: the alias is taken", keyStore.containsAlias(DeviceAttestationKey.ALIAS))

        val dak = DeviceAttestationKey()
        val chain = dak.chain()

        assertTrue("the replacement carries an attestation chain", chain.size >= 2)
        assertTrue(
            "the alias now holds a signing key pair",
            keyStore.getEntry(DeviceAttestationKey.ALIAS, null) is KeyStore.PrivateKeyEntry
        )
        val message = randomBytes(32)
        assertTrue(verify(chain.first(), message, dak.sign(message)))
    }

    /**
     * A key pair generated without an attestation challenge carries one
     * self-signed certificate. A mint refuses exactly that chain, since it has
     * no hardware-rooted path; `chain()` must not hand it out because it was
     * found already stored.
     */
    @Test
    fun aStoredKeyWithASelfSignedChainIsReplacedRatherThanReturned() {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(
                KeyGenParameterSpec.Builder(DeviceAttestationKey.ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            generateKeyPair()
        }
        val planted = keyStore.getCertificateChain(DeviceAttestationKey.ALIAS)
        assertEquals("precondition: an unattested key has a lone certificate", 1, planted.size)

        val dak = DeviceAttestationKey()
        val chain = dak.chain()

        assertTrue("a stored lone certificate is not an attestation chain", chain.size >= 2)
        assertFalse(
            "the unattested key is replaced, not kept",
            (planted[0] as X509Certificate).publicKey.encoded.contentEquals(chain.first().publicKey.encoded)
        )
        val message = randomBytes(32)
        assertTrue("sign() uses the replacement", verify(chain.first(), message, dak.sign(message)))
    }

    // -----------------------------------------------------------------
    // Signing failures
    // -----------------------------------------------------------------

    /**
     * A key the Keystore will not sign with surfaces as [SigningException],
     * not as a raw platform exception the caller does not expect.
     */
    @Test
    fun aKeyTheKeystoreRefusesToSignWithThrowsSigningException() {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(
                KeyGenParameterSpec.Builder(DeviceAttestationKey.ALIAS, KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(AttestTranscript.GENESIS_CHALLENGE)
                    .build()
            )
            generateKeyPair()
        }

        try {
            DeviceAttestationKey().sign(randomBytes(32))
            fail("a verify-only key must not sign")
        } catch (expected: SigningException) {
            // expected
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun deleteAlias() {
        if (keyStore.containsAlias(DeviceAttestationKey.ALIAS)) {
            keyStore.deleteEntry(DeviceAttestationKey.ALIAS)
        }
    }

    private fun encodedOf(chain: List<X509Certificate>): List<String> =
        chain.map { it.encoded.joinToString("") { b -> "%02x".format(b) } }

    private fun randomBytes(size: Int): ByteArray = ByteArray(size).also { SecureRandom().nextBytes(it) }

    private fun verify(leaf: X509Certificate, message: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(leaf.publicKey)
            update(message)
            runCatching { verify(signature) }.getOrDefault(false)
        }

    /**
     * The `attestationChallenge` of a KeyDescription:
     * `SEQUENCE { attestationVersion, attestationSecurityLevel, keymasterVersion,
     * keymasterSecurityLevel, attestationChallenge OCTET STRING, ... }`, inside
     * the OCTET STRING [X509Certificate.getExtensionValue] wraps it in.
     */
    private fun attestationChallengeOf(extensionValue: ByteArray): ByteArray {
        val outer = Der(extensionValue)
        assertEquals("extension value is an OCTET STRING", OCTET_STRING, outer.tag())
        val description = Der(outer.content())
        assertEquals("KeyDescription is a SEQUENCE", SEQUENCE, description.tag())
        val fields = Der(description.content())
        repeat(4) { fields.skip() }
        assertEquals("attestationChallenge is an OCTET STRING", OCTET_STRING, fields.tag())
        return fields.content()
    }

    /** A minimal DER reader: one TLV at a time from [bytes]. */
    private class Der(private val bytes: ByteArray) {
        private var pos = 0

        fun tag(): Int = bytes[pos].toInt() and 0xff

        fun content(): ByteArray {
            val (start, length) = header()
            pos = start + length
            return bytes.copyOfRange(start, start + length)
        }

        fun skip() {
            val (start, length) = header()
            pos = start + length
        }

        /** The content offset and length of the TLV at [pos]. */
        private fun header(): Pair<Int, Int> {
            var at = pos + 1
            val first = bytes[at++].toInt() and 0xff
            if (first < 0x80) return at to first
            var length = 0
            repeat(first and 0x7f) { length = (length shl 8) or (bytes[at++].toInt() and 0xff) }
            return at to length
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** Android Key Attestation extension OID. */
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

        const val OCTET_STRING = 0x04
        const val SEQUENCE = 0x30

        /** SubjectPublicKeyInfo DER of an uncompressed P-256 public key. */
        const val P256_SPKI_SIZE = 91
    }
}
