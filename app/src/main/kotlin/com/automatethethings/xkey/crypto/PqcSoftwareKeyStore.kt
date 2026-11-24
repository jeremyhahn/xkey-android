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
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.MLDSASigner
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory

/** A software ML-DSA record that is missing, damaged or not the key asked for. */
class PqcKeyRecordException(message: String) : GeneralSecurityException(message)

/**
 * ML-DSA keys held in software (Bouncy Castle), one file per Keystore-style
 * alias under `filesDir/pqc_keys`.
 *
 * The PKCS#8 private key is sealed with a non-exportable Keystore
 * AES-256-GCM key ([KeystoreAeadCipher], alias [WRAP_KEY_ALIAS]) before it
 * reaches the disk. The sealed plaintext binds the key to its alias and
 * parameter set, so a record copied under another alias, or holding another
 * record's sealed blob, is refused. Every plaintext copy this class makes is
 * zeroed after use; no key byte is logged.
 *
 * Signatures are pure ML-DSA (FIPS 204, empty context) over the message.
 */
class PqcSoftwareKeyStore(
    private val context: Context,
    cipher: KeystoreAeadCipher? = null
) {
    // Built on first use: KeystoreAeadCipher opens AndroidKeyStore when constructed.
    private val cipher: KeystoreAeadCipher by lazy { cipher ?: KeystoreAeadCipher(WRAP_KEY_ALIAS) }
    private val random = SecureRandom()

    /** The file a key under [alias] lives in. */
    internal fun fileFor(alias: String): File =
        File(File(context.filesDir, DIR), SyncCodec.sha256Hex(alias.toByteArray(Charsets.UTF_8)) + ".key")

    /**
     * Makes a [set] key under [alias], replacing any key there, and returns
     * its SubjectPublicKeyInfo DER.
     */
    @Synchronized
    fun generate(alias: String, set: MlDsaParameterSet): ByteArray {
        val generator = MLDSAKeyPairGenerator()
        generator.init(MLDSAKeyGenerationParameters(random, bcParameters(set)))
        val pair = generator.generateKeyPair()
        val spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.public).encoded
        val pkcs8 = PrivateKeyInfoFactory.createPrivateKeyInfo(pair.private).encoded
        val plaintext = sealedPlaintext(alias, set, pkcs8)
        pkcs8.fill(0)
        val sealed = try {
            cipher.encrypt(plaintext)
        } finally {
            plaintext.fill(0)
        }
        write(fileFor(alias), Record(alias, set, spki, sealed).encode())
        return spki
    }

    /** Whether a readable record for [alias] exists. */
    @Synchronized
    fun contains(alias: String): Boolean = record(alias) != null

    /** The SubjectPublicKeyInfo DER of the key under [alias], or null. */
    @Synchronized
    fun publicKeyDer(alias: String): ByteArray? = record(alias)?.spki?.copyOf()

    /** The parameter set of the key under [alias], or null. */
    @Synchronized
    fun parameterSet(alias: String): MlDsaParameterSet? = record(alias)?.set

    /**
     * Signs [data] with the key under [alias].
     *
     * @throws PqcKeyRecordException when there is no such key, or its record
     *   was sealed for another alias or set.
     */
    @Synchronized
    fun sign(alias: String, data: ByteArray): ByteArray {
        val record = record(alias) ?: throw PqcKeyRecordException("No ML-DSA key under this alias")
        val plaintext = cipher.decrypt(record.sealed)
        var pkcs8: ByteArray? = null
        try {
            val buffer = ByteBuffer.wrap(plaintext)
            val sealedAlias = readField(buffer)
            val sealedSet = readField(buffer)
            if (sealedAlias != alias || sealedSet != record.set.wireName) {
                throw PqcKeyRecordException("ML-DSA record was sealed for another key")
            }
            pkcs8 = ByteArray(buffer.remaining()).also { buffer.get(it) }
            val key = PrivateKeyFactory.createKey(pkcs8) as? MLDSAPrivateKeyParameters
                ?: throw PqcKeyRecordException("ML-DSA record holds another key type")
            if (key.parameters.name != bcParameters(record.set).name) {
                throw PqcKeyRecordException("ML-DSA record holds another parameter set")
            }
            val signer = MLDSASigner()
            signer.init(true, ParametersWithRandom(key, random))
            signer.update(data, 0, data.size)
            return signer.generateSignature()
        } catch (e: IOException) {
            throw PqcKeyRecordException("ML-DSA record is damaged")
        } catch (e: RuntimeException) {
            throw PqcKeyRecordException("ML-DSA record is damaged")
        } finally {
            plaintext.fill(0)
            pkcs8?.fill(0)
        }
    }

    /** Deletes the key under [alias]; true when there was one. */
    @Synchronized
    fun delete(alias: String): Boolean {
        val file = fileFor(alias)
        return file.exists() && file.delete()
    }

    /** The record under [alias], or null when it is missing, damaged or another alias's. */
    private fun record(alias: String): Record? {
        val file = fileFor(alias)
        if (!file.exists()) return null
        val record = try {
            Record.decode(file.readBytes())
        } catch (e: IOException) {
            return null
        }
        return record.takeIf { it.alias == alias }
    }

    private fun write(file: File, bytes: ByteArray) {
        val dir = file.parentFile ?: throw IOException("No key directory")
        if (!dir.exists() && !dir.mkdirs()) throw IOException("Cannot create key directory")
        val temp = File(dir, file.name + ".tmp")
        temp.writeBytes(bytes)
        if (!temp.renameTo(file)) {
            temp.delete()
            throw IOException("Cannot store ML-DSA key")
        }
    }

    /**
     * The on-disk record: the alias, set and public key in the clear, and the
     * sealed `alias || set || PKCS#8`.
     */
    @Suppress("ArrayInDataClass")
    internal data class Record(
        val alias: String,
        val set: MlDsaParameterSet,
        val spki: ByteArray,
        val sealed: ByteArray
    ) {
        fun encode(): ByteArray {
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use { out ->
                out.write(MAGIC)
                out.writeUTF(alias)
                out.writeUTF(set.wireName)
                out.writeInt(spki.size)
                out.write(spki)
                out.writeInt(sealed.size)
                out.write(sealed)
            }
            return bytes.toByteArray()
        }

        companion object {
            /** @throws IOException when [bytes] is not a record. */
            fun decode(bytes: ByteArray): Record = DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
                if (!magic.contentEquals(MAGIC)) throw IOException("Not an ML-DSA record")
                val alias = input.readUTF()
                val set = MlDsaParameterSet.fromWireName(input.readUTF())
                    ?: throw IOException("Unknown ML-DSA parameter set")
                val spki = readSized(input)
                val sealed = readSized(input)
                if (input.read() != -1) throw IOException("Trailing bytes in ML-DSA record")
                Record(alias, set, spki, sealed)
            }

            private fun readSized(input: DataInputStream): ByteArray {
                val size = input.readInt()
                if (size < 0 || size > MAX_FIELD) throw IOException("Bad ML-DSA record field")
                return ByteArray(size).also { input.readFully(it) }
            }
        }
    }

    companion object {
        /** The Keystore AES-GCM key that seals every software ML-DSA private key. */
        const val WRAP_KEY_ALIAS = "xkey_pqc_wrap"
        private const val DIR = "pqc_keys"
        private const val MAX_FIELD = 64 * 1024
        private val MAGIC = byteArrayOf('X'.code.toByte(), 'P'.code.toByte(), 'Q'.code.toByte(), '1'.code.toByte())

        internal fun bcParameters(set: MlDsaParameterSet): MLDSAParameters = when (set) {
            MlDsaParameterSet.ML_DSA_44 -> MLDSAParameters.ml_dsa_44
            MlDsaParameterSet.ML_DSA_65 -> MLDSAParameters.ml_dsa_65
            MlDsaParameterSet.ML_DSA_87 -> MLDSAParameters.ml_dsa_87
        }

        /** `len || alias || len || set || pkcs8`, in one array the caller zeroes. */
        private fun sealedPlaintext(alias: String, set: MlDsaParameterSet, pkcs8: ByteArray): ByteArray {
            val aliasBytes = alias.toByteArray(Charsets.UTF_8)
            val setBytes = set.wireName.toByteArray(Charsets.UTF_8)
            val buffer = ByteBuffer.allocate(4 + aliasBytes.size + 4 + setBytes.size + pkcs8.size)
            buffer.putInt(aliasBytes.size).put(aliasBytes)
            buffer.putInt(setBytes.size).put(setBytes)
            buffer.put(pkcs8)
            return buffer.array()
        }

        private fun readField(buffer: ByteBuffer): String {
            val size = buffer.int
            if (size < 0 || size > buffer.remaining()) throw PqcKeyRecordException("ML-DSA record is damaged")
            val bytes = ByteArray(size).also { buffer.get(it) }
            return String(bytes, Charsets.UTF_8)
        }
    }
}
