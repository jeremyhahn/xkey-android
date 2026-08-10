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

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * The output of a software TPM2_MakeCredential.
 *
 * @property credentialBlob The TPMS_ID_OBJECT contents, which the desktop hands
 *   to TPM2_ActivateCredential as the `credentialBlob` argument. Carries no
 *   TPM2B size prefix: the wire and go-tpm both use the bare buffer.
 * @property encryptedSecret The seed encrypted to the endorsement key.
 * @property secret The plaintext credential. The CA keeps this and requires the
 *   device to return exactly these bytes.
 */
class TpmCredential(
    val credentialBlob: ByteArray,
    val encryptedSecret: ByteArray,
    val secret: ByteArray
)

/**
 * TPM2_MakeCredential performed entirely in software.
 *
 * A Certificate Authority has to be able to issue a credential challenge without
 * owning a TPM, and the TPM 2.0 Library Specification is written so that it can:
 * Part 3, Section 12.6.3 ("TPM2_MakeCredential Detailed Actions") together with
 * Part 1, Section 24 ("Credential Protection") define the whole construction in
 * terms of a public-key encryption, the KDFa key derivation, a symmetric cipher
 * and an HMAC. Nothing in it needs a private key or a TPM.
 *
 * The construction, given the endorsement key's public area and the Name of the
 * object being credentialed:
 *
 *  1. `seed`            — random, the size of a digest under the EK's name algorithm
 *  2. `encryptedSecret` — RSA-OAEP(seed) to the EK, with the label `"IDENTITY\0"`
 *  3. `symKey`          — KDFa(nameAlg, seed, "STORAGE", name, null, keyBits)
 *  4. `encIdentity`     — AES-CFB under symKey, zero IV, over the credential
 *                         marshalled as a TPM2B_DIGEST
 *  5. `HMACkey`         — KDFa(nameAlg, seed, "INTEGRITY", null, null, digestBits)
 *  6. `outerHMAC`       — HMAC(HMACkey, encIdentity || name)
 *  7. `credentialBlob`  — TPM2B_DIGEST(outerHMAC) || encIdentity
 *
 * Only a TPM that holds the private endorsement key can recover the seed, and
 * only one that also holds the named object will hand the credential back, so a
 * matching `decryptedSecret` proves both keys live in the same TPM. Without this
 * step a stolen EK certificate is enough to enrol.
 */
object TpmMakeCredential {

    /** Labels are C strings: the terminating NUL is part of the input. */
    private const val LABEL_IDENTITY = "IDENTITY"
    private const val LABEL_STORAGE = "STORAGE"
    private const val LABEL_INTEGRITY = "INTEGRITY"

    /**
     * The name algorithm of the standard TCG endorsement key templates
     * (TCG EK Credential Profile, Table 2 for RSA).
     */
    const val EK_NAME_ALG = TpmAlg.SHA256

    /** The symmetric key size of the standard EK templates, in bits. */
    const val EK_SYMMETRIC_KEY_BITS = 128

    /**
     * Creates a credential challenge for [objectName] encrypted to [ekPublicKey].
     *
     * @param ekPublicKey The endorsement key, taken from the EK certificate.
     * @param objectName The TPM Name of the credentialed object — for device
     *   enrollment, the Name of the IAK.
     * @param secretSize Size of the credential to generate, in bytes.
     * @param nameAlg The EK's name algorithm; also the OAEP and KDFa hash.
     * @param symmetricKeyBits The EK's symmetric key size.
     */
    fun make(
        ekPublicKey: RSAPublicKey,
        objectName: ByteArray,
        secretSize: Int = 32,
        nameAlg: Int = EK_NAME_ALG,
        symmetricKeyBits: Int = EK_SYMMETRIC_KEY_BITS,
        random: SecureRandom = SecureRandom()
    ): TpmCredential {
        require(objectName.isNotEmpty()) { "object name is required" }
        require(secretSize > 0) { "secret size must be positive" }

        val digestName = TpmAlg.digestName(nameAlg)
            ?: throw TpmStructureException("unsupported name algorithm 0x%04x".format(nameAlg))
        val seed = ByteArray(MessageDigest.getInstance(digestName).digestLength)
        random.nextBytes(seed)
        val secret = ByteArray(secretSize)
        random.nextBytes(secret)

        return makeWithSeed(ekPublicKey, objectName, secret, seed, nameAlg, symmetricKeyBits)
    }

    /**
     * The derandomized half of [make], separated so tests can drive it with
     * known values and compare against reference vectors.
     */
    fun makeWithSeed(
        ekPublicKey: RSAPublicKey,
        objectName: ByteArray,
        secret: ByteArray,
        seed: ByteArray,
        nameAlg: Int = EK_NAME_ALG,
        symmetricKeyBits: Int = EK_SYMMETRIC_KEY_BITS
    ): TpmCredential {
        val encryptedSecret = encryptSeed(ekPublicKey, seed, nameAlg)
        val credentialBlob = idObject(objectName, secret, seed, nameAlg, symmetricKeyBits)
        return TpmCredential(credentialBlob, encryptedSecret, secret.copyOf())
    }

    /**
     * RSA-OAEP encrypts [seed] to the endorsement key under the label
     * `"IDENTITY\0"`, which is what makes the result usable only by a TPM in an
     * activation and not, say, as a general decryption oracle.
     */
    fun encryptSeed(ekPublicKey: RSAPublicKey, seed: ByteArray, nameAlg: Int = EK_NAME_ALG): ByteArray {
        val digestName = TpmAlg.digestName(nameAlg)
            ?: throw TpmStructureException("unsupported name algorithm 0x%04x".format(nameAlg))
        val label = (LABEL_IDENTITY + "\u0000").toByteArray(Charsets.US_ASCII)
        val spec = OAEPParameterSpec(
            digestName,
            "MGF1",
            MGF1ParameterSpec(digestName),
            PSource.PSpecified(label)
        )
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.ENCRYPT_MODE, ekPublicKey, spec)
        return cipher.doFinal(seed)
    }

    /**
     * Builds the TPMS_ID_OBJECT that carries [secret] to the object named
     * [objectName], protected by [seed].
     */
    fun idObject(
        objectName: ByteArray,
        secret: ByteArray,
        seed: ByteArray,
        nameAlg: Int = EK_NAME_ALG,
        symmetricKeyBits: Int = EK_SYMMETRIC_KEY_BITS
    ): ByteArray {
        val digestName = TpmAlg.digestName(nameAlg)
            ?: throw TpmStructureException("unsupported name algorithm 0x%04x".format(nameAlg))
        val digestBits = MessageDigest.getInstance(digestName).digestLength * 8

        val credential2B = marshal2B(secret)
        val symKey = kdfa(nameAlg, seed, LABEL_STORAGE, objectName, null, symmetricKeyBits)
        val encIdentity = aesCfbEncrypt(symKey, credential2B)

        val hmacKey = kdfa(nameAlg, seed, LABEL_INTEGRITY, null, null, digestBits)
        val outerHmac = hmac(nameAlg, hmacKey, encIdentity, objectName)

        val out = ByteArrayOutputStream(2 + outerHmac.size + encIdentity.size)
        out.write(marshal2B(outerHmac))
        out.write(encIdentity)
        return out.toByteArray()
    }

    /**
     * KDFa, the SP800-108 counter-mode KDF in the TPM's own encoding
     * (Part 1, Section 11.4.10.2).
     *
     * Each iteration HMACs `counter || label || 0x00 || contextU || contextV ||
     * bits`, all integers big-endian, and the concatenated output is truncated
     * to [bits]. When [bits] is not a whole number of bytes the leftmost bits of
     * the first byte are masked off, as the specification requires.
     */
    fun kdfa(
        hashAlg: Int,
        key: ByteArray,
        label: String,
        contextU: ByteArray?,
        contextV: ByteArray?,
        bits: Int
    ): ByteArray {
        require(bits > 0) { "bits must be positive" }
        val mac = macFor(hashAlg, key)
        val byteCount = (bits + 7) / 8
        val out = ByteArrayOutputStream(byteCount)
        var counter = 1
        while (out.size() < byteCount) {
            mac.reset()
            mac.update(int32(counter))
            mac.update(label.toByteArray(Charsets.US_ASCII))
            mac.update(byteArrayOf(0))
            contextU?.let { mac.update(it) }
            contextV?.let { mac.update(it) }
            mac.update(int32(bits))
            out.write(mac.doFinal())
            counter++
        }
        val result = out.toByteArray().copyOf(byteCount)
        val maskBits = bits % 8
        if (maskBits != 0) {
            result[0] = (result[0].toInt() and ((1 shl maskBits) - 1)).toByte()
        }
        return result
    }

    /**
     * AES-CFB with a zero IV and full-block feedback, which is what the TPM's
     * symmetric protection uses. The key size follows the derived key.
     */
    private fun aesCfbEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(ByteArray(16))
        )
        return cipher.doFinal(plaintext)
    }

    private fun hmac(hashAlg: Int, key: ByteArray, vararg data: ByteArray): ByteArray {
        val mac = macFor(hashAlg, key)
        data.forEach { mac.update(it) }
        return mac.doFinal()
    }

    private fun macFor(hashAlg: Int, key: ByteArray): Mac {
        val name = when (hashAlg) {
            TpmAlg.SHA1 -> "HmacSHA1"
            TpmAlg.SHA256 -> "HmacSHA256"
            TpmAlg.SHA384 -> "HmacSHA384"
            TpmAlg.SHA512 -> "HmacSHA512"
            else -> throw TpmStructureException("unsupported hash algorithm 0x%04x".format(hashAlg))
        }
        if (key.isEmpty()) {
            // Padding an empty key would silently derive different bytes than
            // the specification does, so refuse it rather than guess.
            throw TpmStructureException("HMAC key must not be empty")
        }
        return Mac.getInstance(name).apply { init(SecretKeySpec(key, name)) }
    }

    /** Marshals [value] as a TPM2B: a big-endian uint16 size then the bytes. */
    private fun marshal2B(value: ByteArray): ByteArray {
        val out = ByteArray(2 + value.size)
        out[0] = ((value.size ushr 8) and 0xFF).toByte()
        out[1] = (value.size and 0xFF).toByte()
        value.copyInto(out, 2)
        return out
    }

    private fun int32(value: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array()
}
