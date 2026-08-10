/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Proves the software TPM2_MakeCredential against reference vectors and against
 * the only thing that ultimately matters: that a holder of the endorsement key
 * can recover the secret from what this produces.
 *
 * The KDFa cases come from the TCG-validated vector set published at
 * github.com/chrisfenner/tpm-test-vectors, which go-tpm embeds and tests
 * against. The credential case was computed with go-tpm's own KDFa and the same
 * composition its `CreateCredential` uses, so the two implementations are
 * checked against each other and not merely against themselves.
 */
class TpmMakeCredentialTest {

    // ---------------------------------------------------------------
    // KDFa, against the TCG reference vectors
    // ---------------------------------------------------------------

    private class KdfaVector(
        val name: String,
        val hashAlg: Int,
        val key: String,
        val label: String,
        val contextU: String,
        val contextV: String,
        val bits: Int,
        val expected: String
    )

    private val kdfaVectors = listOf(
        KdfaVector(
            "27_SHA256_116", TpmAlg.SHA256,
            "aff14e568afc0ea51eea748c8915df067c7700", "IDENTITY",
            "ce4edfb881540700e300",
            "68ddb4a0e59d74cd34dfe631d91e1ea3fbc95865440adedff7e9d011890fba",
            116, "019ed5e0956338ddda4413ecee5cf2"
        ),
        KdfaVector(
            "28_SHA256_17", TpmAlg.SHA256,
            "ff5625623188b99180b53e96108e3e01d19c18db598631d56c", "STORAGE",
            "ef12916d91f3ed8355f100ef7d3553ff69eb63edd59a0048eeda77",
            "800bce408c34f800",
            17, "0051bb"
        ),
        KdfaVector(
            "29_SHA256_175", TpmAlg.SHA256,
            "ff29ff21930d6a35ae4a", "STORAGE",
            "00f0fe886c43cb9c67a79b2d8a70585c2a7fbf8d3fc4e101f1c7",
            "2d",
            175, "438e1b194c52951d00d003410a51a95a936e036eb28f"
        ),
        KdfaVector(
            "31_SHA256_261", TpmAlg.SHA256,
            "2eff", "CFB",
            "ff2427af98c60f2bbc5480e24c64459dbe66a754f3",
            "69b182c92e3f79304513027c388100",
            261, "18bef37aae51edc4c229e179e7b401b98fc88eabd608262b41730d2d7c54927549"
        ),
        KdfaVector(
            "00_SHA1_140", TpmAlg.SHA1,
            "ff", "CFB",
            "86ed23c15d086e70a8eae700680e75d20cff",
            "51122c5879b277ff",
            140, "0d0be71c885d10eb61f2219000885c2d7658"
        ),
        KdfaVector(
            "02_SHA1_297", TpmAlg.SHA1,
            "4599ec1b3c30340e8b4f2b5869", "STORAGE",
            "ff",
            "5a2b980322a96c6db49b15ff16ff",
            297, "00f47f8fdd0bdaf9f22ec614a8ccc370fb822fa3dd80758fddc0140a45443e4be4cbc41fe74d"
        ),
        KdfaVector(
            "54_SHA384_107", TpmAlg.SHA384,
            "407c690e26a916d42b396e0650d0d1fa32b26182fbe8696af8795f7046febb0f10070a5c", "CFB",
            "a6ea7f4af368d953580a0c2a00",
            "fbbd51b1e120ea187847",
            107, "0435309894c071e659e1351e6ece"
        ),
        KdfaVector(
            "55_SHA384_168", TpmAlg.SHA384,
            "ff873218c658337b133d95677b350db6fad5f0fcee50ed948dbfa7bcf1eb7cf3da7b65e30d1004be0a29db0b94cb",
            "INTEGRITY",
            "f4ba2ca34d644c764621b3fa4ec217018d38d18b759bbae330484a8ac2d5e8fb626b063555b85fa100",
            "005a66eb842dc34064ac55b3cfd1234692de",
            168, "41dcda37d9eb927530e3802cc23a2b2346ffddaeea"
        )
    )

    @Test
    fun `kdfa matches the TCG reference vectors`() {
        kdfaVectors.forEach { vector ->
            val actual = TpmMakeCredential.kdfa(
                hashAlg = vector.hashAlg,
                key = hexToBytes(vector.key),
                label = vector.label,
                contextU = hexToBytes(vector.contextU),
                contextV = hexToBytes(vector.contextV),
                bits = vector.bits
            )
            assertEquals(
                "KDFa vector ${vector.name}",
                vector.expected,
                bytesToHex(actual)
            )
        }
    }

    @Test
    fun `kdfa masks the leading bits when the length is not a whole byte`() {
        // 17 bits is two full bytes plus one, so the first byte keeps only its
        // single low bit. The vector's leading 0x00 is that mask at work.
        val vector = kdfaVectors.first { it.bits == 17 }
        val actual = TpmMakeCredential.kdfa(
            vector.hashAlg, hexToBytes(vector.key), vector.label,
            hexToBytes(vector.contextU), hexToBytes(vector.contextV), vector.bits
        )
        assertEquals(3, actual.size)
        assertEquals(0, actual[0].toInt() and 0xFE)
    }

    @Test
    fun `kdfa spans several HMAC iterations when more bits are asked for`() {
        // 261 bits needs two SHA-256 blocks, so a single-iteration KDF would
        // come up short or wrong here.
        val vector = kdfaVectors.first { it.bits == 261 }
        val actual = TpmMakeCredential.kdfa(
            vector.hashAlg, hexToBytes(vector.key), vector.label,
            hexToBytes(vector.contextU), hexToBytes(vector.contextV), vector.bits
        )
        assertEquals(33, actual.size)
        assertEquals(vector.expected, bytesToHex(actual))
    }

    @Test
    fun `kdfa refuses an empty key rather than padding it`() {
        try {
            TpmMakeCredential.kdfa(TpmAlg.SHA256, ByteArray(0), "STORAGE", null, null, 128)
            fail("expected an empty key to be refused")
        } catch (e: TpmStructureException) {
            assertTrue(e.message!!.contains("empty"))
        }
    }

    // ---------------------------------------------------------------
    // The credential blob, against a go-tpm computed vector
    // ---------------------------------------------------------------

    private val katSeed = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val katName = hexToBytes(
        "000bb9f4a1c5d0e2f30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c"
    )
    private val katCredential = hexToBytes(
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    )
    private val katIdObject =
        "0020ae319bf95801ca416090fbbc5e14f28c793b0fed40df130383bdaf995e0a418a" +
            "a8432d9767ec47e085ab0c8f1c2e38c78f500ccb38751550da358dd6321c7ae1ef7b"

    @Test
    fun `id object matches the go-tpm reference composition`() {
        val actual = TpmMakeCredential.idObject(katName, katCredential, katSeed)
        assertEquals(katIdObject, bytesToHex(actual))
    }

    @Test
    fun `id object begins with the outer HMAC marshalled as a TPM2B`() {
        val idObject = TpmMakeCredential.idObject(katName, katCredential, katSeed)
        val declaredSize = ((idObject[0].toInt() and 0xFF) shl 8) or (idObject[1].toInt() and 0xFF)
        assertEquals("the outer HMAC is a SHA-256 digest", 32, declaredSize)
        // Two size bytes, the HMAC, then the encrypted credential, itself a
        // TPM2B of a 32-byte secret.
        assertEquals(2 + 32 + 2 + 32, idObject.size)
    }

    @Test
    fun `binding to a different name changes the credential blob`() {
        val other = katName.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        val a = TpmMakeCredential.idObject(katName, katCredential, katSeed)
        val b = TpmMakeCredential.idObject(other, katCredential, katSeed)
        assertNotEquals(bytesToHex(a), bytesToHex(b))
    }

    // ---------------------------------------------------------------
    // The whole challenge, verified the way a TPM would
    // ---------------------------------------------------------------

    @Test
    fun `a holder of the endorsement key recovers the secret`() {
        val ek = TpmTestStructures.generateRsaKeyPair()
        val name = MessageDigest.getInstance("SHA-256").digest("iak".toByteArray())
        val credential = TpmMakeCredential.make(ek.public as RSAPublicKey, name)

        val recovered = softwareActivateCredential(
            ek.private as RSAPrivateKey,
            name,
            credential.credentialBlob,
            credential.encryptedSecret
        )
        assertArrayEquals(credential.secret, recovered)
    }

    @Test
    fun `activation fails when the credential is bound to another name`() {
        val ek = TpmTestStructures.generateRsaKeyPair()
        val name = MessageDigest.getInstance("SHA-256").digest("iak".toByteArray())
        val impostor = MessageDigest.getInstance("SHA-256").digest("other".toByteArray())
        val credential = TpmMakeCredential.make(ek.public as RSAPublicKey, name)

        try {
            softwareActivateCredential(
                ek.private as RSAPrivateKey,
                impostor,
                credential.credentialBlob,
                credential.encryptedSecret
            )
            fail("a credential bound to another name must not activate")
        } catch (e: IllegalStateException) {
            assertTrue(e.message!!.contains("integrity"))
        }
    }

    @Test
    fun `a different endorsement key cannot recover the seed`() {
        val ek = TpmTestStructures.generateRsaKeyPair()
        val other = TpmTestStructures.generateRsaKeyPair()
        val name = MessageDigest.getInstance("SHA-256").digest("iak".toByteArray())
        val credential = TpmMakeCredential.make(ek.public as RSAPublicKey, name)

        var recovered: ByteArray? = null
        try {
            recovered = softwareActivateCredential(
                other.private as RSAPrivateKey,
                name,
                credential.credentialBlob,
                credential.encryptedSecret
            )
        } catch (e: Exception) {
            // Either the OAEP unwrap fails outright or the integrity HMAC does.
            assertTrue(e is IllegalStateException || e is javax.crypto.BadPaddingException)
        }
        assertFalse("the wrong EK must not recover the secret", credential.secret.contentEquals(recovered))
    }

    @Test
    fun `each challenge carries a fresh secret`() {
        val ek = TpmTestStructures.generateRsaKeyPair()
        val name = MessageDigest.getInstance("SHA-256").digest("iak".toByteArray())
        val first = TpmMakeCredential.make(ek.public as RSAPublicKey, name)
        val second = TpmMakeCredential.make(ek.public as RSAPublicKey, name)
        assertNotEquals(bytesToHex(first.secret), bytesToHex(second.secret))
        assertNotEquals(bytesToHex(first.credentialBlob), bytesToHex(second.credentialBlob))
        assertEquals(32, first.secret.size)
    }

    @Test
    fun `the encrypted seed is labelled and unwraps to the seed`() {
        val ek = TpmTestStructures.generateRsaKeyPair()
        val seed = ByteArray(32) { (it * 7).toByte() }
        val encrypted = TpmMakeCredential.encryptSeed(ek.public as RSAPublicKey, seed)

        assertArrayEquals(seed, unwrapSeed(ek.private as RSAPrivateKey, encrypted, "IDENTITY\u0000"))

        // The label is part of the OAEP input; a decryption that assumes a
        // different one must fail, which is what keeps this ciphertext usable
        // only for credential activation.
        try {
            unwrapSeed(ek.private as RSAPrivateKey, encrypted, "DUPLICATE\u0000")
            fail("the identity label must be required to unwrap the seed")
        } catch (e: Exception) {
            assertTrue(e is javax.crypto.BadPaddingException)
        }
    }

    @Test
    fun `an empty object name is refused`() {
        val ek = TpmTestStructures.generateRsaKeyPair()
        try {
            TpmMakeCredential.make(ek.public as RSAPublicKey, ByteArray(0))
            fail("a credential must be bound to a name")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("name"))
        }
    }

    // ---------------------------------------------------------------
    // A software TPM2_ActivateCredential, the inverse of what is under test
    // ---------------------------------------------------------------

    private fun unwrapSeed(ek: RSAPrivateKey, ciphertext: ByteArray, label: String): ByteArray {
        val spec = OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
            PSource.PSpecified(label.toByteArray(Charsets.US_ASCII))
        )
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.DECRYPT_MODE, ek, spec)
        return cipher.doFinal(ciphertext)
    }

    /**
     * What the desktop's TPM does with the challenge: unwrap the seed, re-derive
     * the integrity and storage keys from it and the object's own Name, check the
     * outer HMAC, then decrypt the credential.
     */
    private fun softwareActivateCredential(
        ek: RSAPrivateKey,
        name: ByteArray,
        credentialBlob: ByteArray,
        encryptedSecret: ByteArray
    ): ByteArray {
        val seed = unwrapSeed(ek, encryptedSecret, "IDENTITY\u0000")

        val hmacSize = ((credentialBlob[0].toInt() and 0xFF) shl 8) or (credentialBlob[1].toInt() and 0xFF)
        val outerHmac = credentialBlob.copyOfRange(2, 2 + hmacSize)
        val encIdentity = credentialBlob.copyOfRange(2 + hmacSize, credentialBlob.size)

        val hmacKey = TpmMakeCredential.kdfa(TpmAlg.SHA256, seed, "INTEGRITY", null, null, 256)
        val mac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(hmacKey, "HmacSHA256"))
        }
        mac.update(encIdentity)
        mac.update(name)
        check(MessageDigest.isEqual(mac.doFinal(), outerHmac)) { "credential integrity check failed" }

        val symKey = TpmMakeCredential.kdfa(TpmAlg.SHA256, seed, "STORAGE", name, null, 128)
        val cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(symKey, "AES"),
            IvParameterSpec(ByteArray(16))
        )
        val credential2B = cipher.doFinal(encIdentity)
        val size = ((credential2B[0].toInt() and 0xFF) shl 8) or (credential2B[1].toInt() and 0xFF)
        return credential2B.copyOfRange(2, 2 + size)
    }
}
