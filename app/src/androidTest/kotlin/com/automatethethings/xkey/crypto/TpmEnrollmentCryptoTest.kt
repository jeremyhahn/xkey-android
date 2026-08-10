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
import androidx.test.filters.SmallTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * Runs the enrollment cryptography on Android's own JCA providers.
 *
 * The JVM unit suite proves the algorithms against TCG and go-tpm vectors, but
 * it proves them on OpenJDK. Android resolves `AES/CFB/NoPadding`,
 * `RSA/ECB/OAEPPadding` with a label, and the TPM's own hash and signature names
 * through Conscrypt and its bundled BouncyCastle instead, and a mode or a
 * default that differs there would break enrollment on a real phone while every
 * unit test stayed green. That gap is what this suite closes.
 *
 * Nothing here touches the Keystore or any app state, so there is nothing to
 * clean up.
 */
@RunWith(AndroidJUnit4::class)
@SmallTest
class TpmEnrollmentCryptoTest {

    // The same vector the JVM suite checks, computed with go-tpm's KDFa and the
    // composition its CreateCredential uses.
    private val katSeed = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val katName = hex("000bb9f4a1c5d0e2f30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c")
    private val katCredential = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
    private val katIdObject =
        "0020ae319bf95801ca416090fbbc5e14f28c793b0fed40df130383bdaf995e0a418a" +
            "a8432d9767ec47e085ab0c8f1c2e38c78f500ccb38751550da358dd6321c7ae1ef7b"

    @Test
    fun kdfaMatchesTheTcgVectorOnAndroidProviders() {
        val actual = TpmMakeCredential.kdfa(
            hashAlg = TpmAlg.SHA256,
            key = hex("aff14e568afc0ea51eea748c8915df067c7700"),
            label = "IDENTITY",
            contextU = hex("ce4edfb881540700e300"),
            contextV = hex("68ddb4a0e59d74cd34dfe631d91e1ea3fbc95865440adedff7e9d011890fba"),
            bits = 116
        )
        assertEquals("019ed5e0956338ddda4413ecee5cf2", hex(actual))
    }

    @Test
    fun credentialBlobMatchesTheReferenceCompositionOnAndroidProviders() {
        // If Android resolved AES/CFB to a segment size other than the full
        // block, this is the assertion that would catch it.
        assertEquals(katIdObject, hex(TpmMakeCredential.idObject(katName, katCredential, katSeed)))
    }

    @Test
    fun aHolderOfTheEndorsementKeyRecoversTheSecret() {
        val ek = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val name = MessageDigest.getInstance("SHA-256").digest("iak".toByteArray())

        val credential = TpmMakeCredential.make(ek.public as RSAPublicKey, name)
        val recovered = activate(ek.private as RSAPrivateKey, name, credential.credentialBlob, credential.encryptedSecret)

        assertArrayEquals(credential.secret, recovered)
        assertEquals(32, credential.secret.size)
    }

    @Test
    fun theIdentityLabelIsRequiredToUnwrapTheSeed() {
        val ek = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val seed = ByteArray(32) { (it * 5).toByte() }
        val wrapped = TpmMakeCredential.encryptSeed(ek.public as RSAPublicKey, seed)

        assertArrayEquals(seed, unwrap(ek.private as RSAPrivateKey, wrapped, "IDENTITY\u0000"))
        try {
            unwrap(ek.private as RSAPrivateKey, wrapped, "DUPLICATE\u0000")
            fail("a ciphertext labelled IDENTITY must not unwrap under another label")
        } catch (e: Exception) {
            assertTrue(e is javax.crypto.BadPaddingException)
        }
    }

    @Test
    fun aPublicAreaYieldsTheKeyItEncodesAndAStableName() {
        val keys = ecKeyPair()
        val area = eccPublicArea(keys.public as ECPublicKey)
        val parsed = TpmPublicArea.parse(area)

        assertEquals(TpmAlg.ECC, parsed.type)
        assertTrue(parsed.isRestricted)
        assertEquals(keys.public, parsed.publicKey)

        // Name is the algorithm id followed by the digest of the public area.
        val expected = ByteArrayOutputStream().apply {
            write(0x00); write(0x0B)
            write(MessageDigest.getInstance("SHA-256").digest(area))
        }.toByteArray()
        assertArrayEquals(expected, parsed.name())
    }

    @Test
    fun aQuoteVerifiesUnderTheAttestationKeyOnAndroidProviders() {
        val keys = ecKeyPair()
        val iak = TpmPublicArea.parse(eccPublicArea(keys.public as ECPublicKey))
        val nonce = ByteArray(32) { (it + 9).toByte() }
        val quoted = quoteAttest(iak.name(), nonce)
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(keys.private)
            update(quoted)
        }.sign()

        val attest = TpmQuoteVerifier.verify(iak, quoted, signature, nonce)
        assertArrayEquals(nonce, attest.extraData)

        try {
            TpmQuoteVerifier.verify(iak, quoted, signature, ByteArray(32))
            fail("a quote bound to another nonce must be refused")
        } catch (e: TpmQuoteException) {
            assertTrue(e.message!!.contains("not bound to the nonce"))
        }
    }

    // ---------------------------------------------------------------
    // Fixtures. Deliberately hand-rolled so they cannot agree with the
    // parser by sharing its code.
    // ---------------------------------------------------------------

    private fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun eccPublicArea(key: ECPublicKey): ByteArray = ByteArrayOutputStream().apply {
        u16(TpmAlg.ECC)
        u16(TpmAlg.SHA256)
        u32(
            TpmObjectAttributes.FIXED_TPM or TpmObjectAttributes.FIXED_PARENT or
                TpmObjectAttributes.SENSITIVE_DATA_ORIGIN or TpmObjectAttributes.USER_WITH_AUTH or
                TpmObjectAttributes.RESTRICTED or TpmObjectAttributes.SIGN_ENCRYPT
        )
        b2(ByteArray(0))          // authPolicy
        u16(TpmAlg.NULL)          // symmetric
        u16(TpmAlg.ECDSA)
        u16(TpmAlg.SHA256)
        u16(0x0003)               // NIST P-256
        u16(TpmAlg.NULL)          // kdf
        b2(fixed(key.w.affineX))
        b2(fixed(key.w.affineY))
    }.toByteArray()

    private fun quoteAttest(signerName: ByteArray, nonce: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            u32(TpmAttest.TPM_GENERATED)
            u16(TpmAttest.ST_ATTEST_QUOTE)
            b2(signerName)
            b2(nonce)
            write(ByteArray(8))       // clock
            u32(0)                    // resetCount
            u32(0)                    // restartCount
            write(byteArrayOf(1))     // safe
            write(ByteArray(8))       // firmwareVersion
            u32(1)                    // one selection
            u16(TpmAlg.SHA256)
            write(byteArrayOf(3))
            write(byteArrayOf(0xFF.toByte(), 0, 0))
            b2(ByteArray(32) { it.toByte() })
        }.toByteArray()

    private fun unwrap(ek: RSAPrivateKey, ciphertext: ByteArray, label: String): ByteArray {
        val spec = OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
            PSource.PSpecified(label.toByteArray(Charsets.US_ASCII))
        )
        return Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
            init(Cipher.DECRYPT_MODE, ek, spec)
        }.doFinal(ciphertext)
    }

    /** A software TPM2_ActivateCredential: the inverse of what is under test. */
    private fun activate(
        ek: RSAPrivateKey,
        name: ByteArray,
        credentialBlob: ByteArray,
        encryptedSecret: ByteArray
    ): ByteArray {
        val seed = unwrap(ek, encryptedSecret, "IDENTITY\u0000")
        val hmacSize = ((credentialBlob[0].toInt() and 0xFF) shl 8) or (credentialBlob[1].toInt() and 0xFF)
        val outer = credentialBlob.copyOfRange(2, 2 + hmacSize)
        val encIdentity = credentialBlob.copyOfRange(2 + hmacSize, credentialBlob.size)

        val hmacKey = TpmMakeCredential.kdfa(TpmAlg.SHA256, seed, "INTEGRITY", null, null, 256)
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(hmacKey, "HmacSHA256")) }
        mac.update(encIdentity)
        mac.update(name)
        assertTrue("credential integrity check failed", MessageDigest.isEqual(mac.doFinal(), outer))

        val symKey = TpmMakeCredential.kdfa(TpmAlg.SHA256, seed, "STORAGE", name, null, 128)
        val plain = Cipher.getInstance("AES/CFB/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(symKey, "AES"), IvParameterSpec(ByteArray(16)))
        }.doFinal(encIdentity)
        val size = ((plain[0].toInt() and 0xFF) shl 8) or (plain[1].toInt() and 0xFF)
        return plain.copyOfRange(2, 2 + size)
    }

    private fun ByteArrayOutputStream.u16(value: Int) {
        write((value ushr 8) and 0xFF); write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.u32(value: Int) {
        write((value ushr 24) and 0xFF); write((value ushr 16) and 0xFF)
        write((value ushr 8) and 0xFF); write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.b2(value: ByteArray) {
        u16(value.size); write(value)
    }

    private fun fixed(value: BigInteger, size: Int = 32): ByteArray {
        val raw = value.toByteArray().let { if (it[0].toInt() == 0) it.copyOfRange(1, it.size) else it }
        return if (raw.size == size) raw else ByteArray(size - raw.size) + raw
    }

    private fun hex(text: String): ByteArray = ByteArray(text.length / 2) {
        ((Character.digit(text[it * 2], 16) shl 4) or Character.digit(text[it * 2 + 1], 16)).toByte()
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
