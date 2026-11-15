/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.automatethethings.xkey.remote.SharePermissionLedger
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Wraps hardware-backed ECIES encryption for the .xkeyenc file format.
 *
 * Encryption workflow:
 * 1. Generates an ephemeral EC key in Android Keystore with [KeyProperties.PURPOSE_AGREE_KEY]
 * 2. Performs ECDH in hardware with the recipient's public key
 * 3. Derives an AES-256 key via HKDF-SHA256
 * 4. Encrypts the plaintext with AES-256-GCM streaming
 * 5. Deletes the ephemeral key from the Keystore
 *
 * File format (.xkeyenc):
 * ```
 * [version:1 byte][ephemeral_pubkey_len:2 bytes big-endian][ephemeral_pubkey][salt:32 bytes][iv:12 bytes][ciphertext][tag:16 bytes]
 * ```
 *
 * @param keystoreManager The [KeystoreManager] instance used for ECDH and key operations.
 * @param generateEphemeralKey Generates the ephemeral agreement key at the given
 *   Keystore alias; the Android Keystore unless a test supplies another.
 */
class FileEncryptor(
    private val keystoreManager: KeystoreManager,
    private val generateEphemeralKey: (alias: String) -> Unit = ::generateKeystoreAgreementKey
) {

    companion object {
        /** Key ID prefix of the ephemeral agreement key (Keystore alias `xkey_key_ephemeral_<UUID>`). */
        const val EPHEMERAL_KEY_PREFIX = "ephemeral_"

        private const val VERSION: Byte = 0x01
        private const val SALT_SIZE = 32
        private const val IV_SIZE = 12
        private const val GCM_TAG_BITS = 128
        private const val AES_KEY_SIZE = 32
        private const val BUFFER_SIZE = 8192
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val HKDF_INFO = "xkey-file-encryption-v1"
    }

    /**
     * Encrypt a plaintext stream for a recipient identified by their DER-encoded public key.
     *
     * An ephemeral EC key is generated in Android Keystore, used for ECDH key agreement
     * with the recipient, and deleted after encryption completes (even on failure).
     *
     * @param recipientPublicKeyDer DER-encoded (X.509 SubjectPublicKeyInfo) recipient public key.
     * @param plaintext Input stream of plaintext data to encrypt.
     * @param output Output stream where the .xkeyenc formatted ciphertext is written.
     * @throws EncryptionException if any step of the encryption process fails.
     */
    suspend fun encryptForRecipient(
        recipientPublicKeyDer: ByteArray,
        plaintext: InputStream,
        output: OutputStream
    ) {
        val ephemeralKeyId = "$EPHEMERAL_KEY_PREFIX${UUID.randomUUID()}"
        try {
            // Generate ephemeral EC key in Keystore with PURPOSE_AGREE_KEY
            generateEphemeralKey("xkey_key_$ephemeralKeyId")

            // Get ephemeral public key DER
            val ephemeralPubKeyDer = keystoreManager.getPublicKeyDER(ephemeralKeyId)
                ?: throw EncryptionException("Failed to get ephemeral public key", null)

            // Perform ECDH in hardware
            val sharedSecret = keystoreManager.performECDH(ephemeralKeyId, recipientPublicKeyDer)

            // Generate random salt
            val salt = ByteArray(SALT_SIZE)
            SecureRandom().nextBytes(salt)

            // HKDF to derive AES key
            val aesKey = hkdfDerive(sharedSecret, salt, AES_KEY_SIZE)

            // Generate random IV
            val iv = ByteArray(IV_SIZE)
            SecureRandom().nextBytes(iv)

            // Write header
            output.write(VERSION.toInt())
            val pubKeyLen = ephemeralPubKeyDer.size
            output.write((pubKeyLen shr 8) and 0xFF)
            output.write(pubKeyLen and 0xFF)
            output.write(ephemeralPubKeyDer)
            output.write(salt)
            output.write(iv)

            // AES-256-GCM encrypt (streaming)
            val secretKey = SecretKeySpec(aesKey, "AES")
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))

            CipherOutputStream(output, cipher).use { cos ->
                val buffer = ByteArray(BUFFER_SIZE)
                var bytesRead: Int
                while (plaintext.read(buffer).also { bytesRead = it } != -1) {
                    cos.write(buffer, 0, bytesRead)
                }
            }
        } finally {
            // Always delete ephemeral key, as a revoke of its ID: a share of
            // it, however it got a row, is refused from here on.
            SharePermissionLedger.revoking(ephemeralKeyId) { keystoreManager.deleteKey(ephemeralKeyId) }
        }
    }

    /**
     * Decrypt a .xkeyenc formatted stream using a local key stored in the Keystore.
     *
     * The local key must be an EC key capable of ECDH key agreement. The method reads
     * the file header to extract the ephemeral public key, salt, and IV, then performs
     * ECDH to derive the decryption key.
     *
     * @param localKeyId Key identifier for the local EC private key in the Keystore.
     * @param input Input stream of .xkeyenc formatted ciphertext.
     * @param output Output stream where decrypted plaintext is written.
     * @throws DecryptionException if the file version is unsupported, the file is truncated,
     *         or any step of the decryption process fails.
     */
    suspend fun decryptWithKey(
        localKeyId: String,
        input: InputStream,
        output: OutputStream
    ) {
        // Read version
        val version = input.read()
        if (version != VERSION.toInt()) {
            throw DecryptionException("Unsupported file version: $version", null)
        }

        // Read ephemeral public key length (2 bytes big-endian)
        val lenHigh = input.read()
        val lenLow = input.read()
        if (lenHigh == -1 || lenLow == -1) {
            throw DecryptionException("Unexpected end of encrypted file", null)
        }
        val ephPubKeyLen = (lenHigh shl 8) or lenLow

        // Read ephemeral public key
        val ephemeralPubKeyDer = ByteArray(ephPubKeyLen)
        readFully(input, ephemeralPubKeyDer)

        // Read salt
        val salt = ByteArray(SALT_SIZE)
        readFully(input, salt)

        // Read IV
        val iv = ByteArray(IV_SIZE)
        readFully(input, iv)

        // Perform ECDH with local key
        val sharedSecret = keystoreManager.performECDH(localKeyId, ephemeralPubKeyDer)

        // HKDF derive AES key
        val aesKey = hkdfDerive(sharedSecret, salt, AES_KEY_SIZE)

        // AES-256-GCM decrypt (streaming)
        val secretKey = SecretKeySpec(aesKey, "AES")
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))

        CipherInputStream(input, cipher).use { cis ->
            val buffer = ByteArray(BUFFER_SIZE)
            var bytesRead: Int
            while (cis.read(buffer).also { bytesRead = it } != -1) {
                output.write(buffer, 0, bytesRead)
            }
        }
    }


    /**
     * Derive a key using HKDF-SHA256.
     *
     * @param ikm Input keying material (the ECDH shared secret).
     * @param salt Random salt bytes.
     * @param length Desired output key length in bytes.
     * @return Derived key bytes.
     */
    private fun hkdfDerive(ikm: ByteArray, salt: ByteArray, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, HKDF_INFO.toByteArray(Charsets.UTF_8)))
        val output = ByteArray(length)
        hkdf.generateBytes(output, 0, length)
        return output
    }

    /**
     * Read exactly [buffer].size bytes from the input stream.
     *
     * @param input Source input stream.
     * @param buffer Destination buffer to fill completely.
     * @throws DecryptionException if the stream ends before the buffer is filled.
     */
    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val bytesRead = input.read(buffer, offset, buffer.size - offset)
            if (bytesRead == -1) throw DecryptionException("Unexpected end of encrypted file", null)
            offset += bytesRead
        }
    }
}

/**
 * Generate an ephemeral EC key in Android Keystore with [KeyProperties.PURPOSE_AGREE_KEY].
 *
 * The key is created on the secp256r1 (P-256) curve without user authentication
 * requirements, as it is used only for a single ECDH operation and then deleted.
 *
 * @param alias Keystore alias of the ephemeral key.
 */
private fun generateKeystoreAgreementKey(alias: String) {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    if (keyStore.containsAlias(alias)) {
        keyStore.deleteEntry(alias)
    }

    val specBuilder = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_AGREE_KEY
    )
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setUserAuthenticationRequired(false)

    val keyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
    )
    keyPairGenerator.initialize(specBuilder.build())
    keyPairGenerator.generateKeyPair()
}
