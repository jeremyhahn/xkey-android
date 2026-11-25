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
import android.os.SystemClock
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.KeyStoreException
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
 * AES-256-GCM key of its own ([PqcWrapKeyring]) before it reaches the disk.
 * Deleting or replacing a key removes that Keystore key first, so a copy of
 * the old record put back, with any generation file, never opens again. The sealed plaintext binds the key to its alias and
 * parameter set, so a record copied under another alias, or holding another
 * record's sealed blob, is refused. The sealed plaintext also carries the
 * key's user-authentication policy, which [sign] enforces for every caller.
 * Every plaintext copy this class makes is zeroed after use; no key byte is
 * logged.
 *
 * Signatures are pure ML-DSA (FIPS 204, empty context) over the message.
 */
class PqcSoftwareKeyStore internal constructor(
    private val context: Context,
    private val keyring: PqcWrapKeyring
) {
    /** The app's store: per-key Keystore wrap keys, or one injected [cipher] in tests. */
    constructor(context: Context, cipher: KeystoreAeadCipher? = null) :
        this(context, if (cipher != null) SingleCipherKeyring(cipher) else KeystoreWrapKeyring())

    private val random = SecureRandom()

    /** The file a key under [alias] lives in. */
    internal fun fileFor(alias: String): File =
        File(File(context.filesDir, DIR), SyncCodec.sha256Hex(alias.toByteArray(Charsets.UTF_8)) + ".key")

    /**
     * Makes a [set] key under [alias], replacing any key there, and returns
     * its SubjectPublicKeyInfo DER.
     */
    @Synchronized
    fun generate(
        alias: String,
        set: MlDsaParameterSet,
        authDurationSeconds: Int = NO_USER_AUTHENTICATION
    ): ByteArray {
        // The replaced key's wrap key goes first, so its record cannot be put back.
        if (fileFor(alias).exists()) delete(alias)
        val generator = MLDSAKeyPairGenerator()
        generator.init(MLDSAKeyGenerationParameters(random, bcParameters(set)))
        val pair = generator.generateKeyPair()
        val spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.public).encoded
        val pkcs8 = PrivateKeyInfoFactory.createPrivateKeyInfo(pair.private).encoded
        // A damaged or missing generation file must not block a new key; the new key's generation replaces it.
        val generation = (runCatching { storedGeneration(alias) }.getOrNull() ?: 0L) + 1
        val plaintext = sealedPlaintext(
            alias, set, spki, generation, authDurationSeconds.coerceAtLeast(NO_USER_AUTHENTICATION), pkcs8
        )
        pkcs8.fill(0)
        val wrapId = keyring.newId()
        val sealed = try {
            keyring.seal(wrapId, plaintext)
        } finally {
            plaintext.fill(0)
        }
        try {
            write(fileFor(alias), Record(alias, set, spki, wrapId, sealed).encode())
            write(generationFileFor(alias), ByteBuffer.allocate(8).putLong(generation).array())
        } catch (e: IOException) {
            // A key whose record or generation was not stored is revoked, so no half-written key opens later.
            runCatching { keyring.destroy(wrapId) }
            runCatching { removeFile(fileFor(alias)) }
            throw e
        }
        return spki
    }

    /** The file holding the generation a record under [alias] must reach to open; delete keeps it. */
    internal fun generationFileFor(alias: String): File =
        File(File(context.filesDir, DIR), SyncCodec.sha256Hex(alias.toByteArray(Charsets.UTF_8)) + ".gen")

    /**
     * The generation a record under [alias] must reach to open.
     *
     * @throws PqcKeyRecordException when none is stored: a missing file is never read as 0.
     */
    private fun storedGeneration(alias: String): Long {
        val file = generationFileFor(alias)
        if (!file.exists()) throw PqcKeyRecordException("ML-DSA generation is missing")
        val bytes = try {
            file.readBytes()
        } catch (e: IOException) {
            throw PqcKeyRecordException("ML-DSA generation is unreadable")
        }
        if (bytes.size != 8) throw PqcKeyRecordException("ML-DSA generation is damaged")
        return ByteBuffer.wrap(bytes).long
    }

    /** Whether a readable record for [alias] exists. */
    @Synchronized
    fun contains(alias: String): Boolean = record(alias) != null

    /** The SubjectPublicKeyInfo DER of the key under [alias], or null when there is none or it does not open. */
    @Synchronized
    fun publicKeyDer(alias: String): ByteArray? {
        val record = record(alias) ?: return null
        return try {
            openRecord(alias, record) { _, _ -> record.spki.copyOf() }
        } catch (e: GeneralSecurityException) {
            null
        }
    }

    /** The parameter set of the key under [alias], or null. */
    @Synchronized
    fun parameterSet(alias: String): MlDsaParameterSet? = record(alias)?.set

    /**
     * The user-authentication policy sealed with the key under [alias]:
     * [NO_USER_AUTHENTICATION], 0 (every use) or a window in seconds; null
     * when there is no such key.
     *
     * @throws PqcKeyRecordException when the record does not open for [alias].
     */
    @Synchronized
    fun authDurationSeconds(alias: String): Int? {
        val record = record(alias) ?: return null
        return openRecord(alias, record) { authDurationSeconds, _ -> authDurationSeconds }
    }

    /**
     * Signs [data] with the key under [alias], only when the key's sealed
     * user-authentication policy is met: a key made with a policy signs only
     * when [userAuthenticatedAt] (a [userAuthenticationTime] the caller took
     * when the user authenticated) is recent enough. This is the one check
     * for every software ML-DSA signature, whoever the caller is.
     *
     * @throws BiometricRequiredException when the key needs a user
     *   authentication and [userAuthenticatedAt] is null, too old or ahead
     *   of the clock.
     * @throws PqcKeyRecordException when there is no such key, its record is
     *   not a [set] key, or it was sealed for another alias or set.
     */
    @Synchronized
    fun sign(alias: String, set: MlDsaParameterSet, data: ByteArray, userAuthenticatedAt: Long? = null): ByteArray {
        val record = record(alias) ?: throw PqcKeyRecordException("No ML-DSA key under this alias")
        // Checked under the store's lock: a concurrent generate cannot swap the record after this.
        if (record.set != set) throw PqcKeyRecordException("ML-DSA key under this alias is not ${set.wireName}")
        return openRecord(alias, record) { authDurationSeconds, key ->
            requireUserAuthentication(authDurationSeconds, userAuthenticatedAt)
            val signer = MLDSASigner()
            signer.init(true, ParametersWithRandom(key, random))
            signer.update(data, 0, data.size)
            signer.generateSignature()
        }
    }

    /**
     * Opens [record] for [alias] and passes its sealed policy and private key
     * to [use]: the one place a sealed key is opened. Refuses a record whose
     * wrap key was removed, a record with no stored generation, one sealed
     * for another alias or set, one whose clear public key is not the sealed
     * one or not its private key's, and one older than the alias's stored
     * generation. Every plaintext is zeroed before it returns.
     *
     * @throws PqcKeyRecordException when the record does not open or is refused.
     */
    private fun <T> openRecord(
        alias: String,
        record: Record,
        use: (authDurationSeconds: Int, key: MLDSAPrivateKeyParameters) -> T
    ): T {
        val plaintext = try {
            keyring.open(record.wrapId, record.sealed)
        } catch (e: GeneralSecurityException) {
            if (e is PqcKeyRecordException) throw e
            throw PqcKeyRecordException("ML-DSA record does not open")
        }
        var pkcs8: ByteArray? = null
        try {
            val buffer = ByteBuffer.wrap(plaintext)
            if (readField(buffer) != alias || readField(buffer) != record.set.wireName) {
                throw PqcKeyRecordException("ML-DSA record was sealed for another key")
            }
            val sealedSpki = readSizedField(buffer)
            if (!sealedSpki.contentEquals(record.spki)) {
                throw PqcKeyRecordException("ML-DSA record's public key is not the sealed one")
            }
            if (buffer.long < storedGeneration(alias)) {
                throw PqcKeyRecordException("ML-DSA record is older than the key under this alias")
            }
            val authDurationSeconds = buffer.int
            pkcs8 = ByteArray(buffer.remaining()).also { buffer.get(it) }
            val key = PrivateKeyFactory.createKey(pkcs8) as? MLDSAPrivateKeyParameters
                ?: throw PqcKeyRecordException("ML-DSA record holds another key type")
            if (key.parameters.name != bcParameters(record.set).name) {
                throw PqcKeyRecordException("ML-DSA record holds another parameter set")
            }
            val derivedSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key.publicKeyParameters).encoded
            if (!derivedSpki.contentEquals(record.spki)) {
                throw PqcKeyRecordException("ML-DSA record's public key is not its private key's")
            }
            return use(authDurationSeconds, key)
        } catch (e: IOException) {
            throw PqcKeyRecordException("ML-DSA record is damaged")
        } catch (e: RuntimeException) {
            throw PqcKeyRecordException("ML-DSA record is damaged")
        } finally {
            plaintext.fill(0)
            pkcs8?.fill(0)
        }
    }

    /**
     * Deletes the key under [alias]; true when there was one, false when
     * there was none. The record's own Keystore wrap key is removed, so no
     * copy of the record put back opens, and the alias's generation moves
     * past the deleted record.
     *
     * @throws IOException when a record exists and cannot be removed or its
     *   wrap key cannot be revoked: the key is still usable, so a caller must
     *   keep its slot row or metadata. Also when the generation cannot be
     *   advanced after the key was revoked: the key no longer signs, and the
     *   delete is not reported done.
     */
    @Synchronized
    fun delete(alias: String): Boolean {
        val file = fileFor(alias)
        if (!file.exists()) return false
        val bytes = file.readBytes()
        val record = runCatching { Record.decode(bytes) }.getOrNull()?.takeIf { it.alias == alias }
        if (!removeFile(file) && file.exists()) throw IOException("Cannot delete ML-DSA key")
        if (record != null) {
            try {
                keyring.destroy(record.wrapId)
            } catch (e: Exception) {
                // The wrap key is still there, so the record goes back and the key stays usable.
                runCatching { write(file, bytes) }
                throw IOException("Cannot revoke ML-DSA key", e)
            }
        }
        // Advanced past the removed record; a failure is reported, never ignored.
        val generation = (runCatching { storedGeneration(alias) }.getOrNull() ?: 0L) + 1
        write(generationFileFor(alias), ByteBuffer.allocate(8).putLong(generation).array())
        return true
    }

    /** Removes a record file; a test swaps in one that fails. */
    internal var removeFile: (File) -> Boolean = { it.delete() }

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
        // Another store may make the directory between the two checks: only a
        // directory that still is not there is a failure.
        if (!dir.mkdirs() && !dir.isDirectory) throw IOException("Cannot create key directory")
        val temp = File(dir, file.name + ".tmp")
        temp.writeBytes(bytes)
        if (!temp.renameTo(file)) {
            temp.delete()
            throw IOException("Cannot store ML-DSA key")
        }
    }

    /**
     * The on-disk record: the alias, set, public key and wrap key id in the clear, and the
     * sealed `alias || set || public key || generation || user-authentication
     * policy || PKCS#8`, so the clear fields are checked against the sealed ones.
     */
    @Suppress("ArrayInDataClass")
    internal data class Record(
        val alias: String,
        val set: MlDsaParameterSet,
        val spki: ByteArray,
        val wrapId: String,
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
                out.writeUTF(wrapId)
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
                val wrapId = input.readUTF()
                if (!PqcWrapKeyring.isWrapId(wrapId)) throw IOException("Bad ML-DSA wrap key id")
                val sealed = readSized(input)
                if (input.read() != -1) throw IOException("Trailing bytes in ML-DSA record")
                Record(alias, set, spki, wrapId, sealed)
            }

            private fun readSized(input: DataInputStream): ByteArray {
                val size = input.readInt()
                if (size < 0 || size > MAX_FIELD) throw IOException("Bad ML-DSA record field")
                return ByteArray(size).also { input.readFully(it) }
            }
        }
    }

    companion object {
        /** The shared Keystore AES-GCM key earlier builds sealed with; kept internal, no record uses it. */
        const val WRAP_KEY_ALIAS = KeystoreAeadCipher.PQC_WRAP_ALIAS

        /**
         * The app's one store, once [registerShared] has built it; null
         * before. Every app caller (KeystoreManager, the PIV screen, a PIV
         * key manager built without a store) uses it, so one instance
         * serializes every record.
         */
        @Volatile
        var shared: PqcSoftwareKeyStore? = null
            private set

        /**
         * The app's [shared] store, building it on [context]'s application
         * context if none is registered yet. Cheap: the wrap key opens on
         * first use. `XKeyApplication.onCreate` calls it, so callers built
         * without a Context find the store from process start.
         */
        @Synchronized
        fun registerShared(context: Context): PqcSoftwareKeyStore =
            shared ?: PqcSoftwareKeyStore(context.applicationContext ?: context).also { shared = it }

        /** Forgets the [shared] store, as a fresh process has none. Tests only. */
        @Synchronized
        internal fun clearSharedForTest() {
            shared = null
        }

        /** The policy of a key that signs with no user authentication. */
        const val NO_USER_AUTHENTICATION = -1

        /**
         * How old the authentication passed for a per-use key (policy 0) may
         * be: the prompt of the request that signs, not an earlier one.
         */
        internal const val PER_USE_WINDOW_MS = 30_000L

        /** The clock [userAuthenticationTime] and [sign] read; a test sets its own. */
        @Volatile
        internal var clock: () -> Long = { SystemClock.elapsedRealtime() }

        /** Now, as [sign] reads a caller's user authentication time. */
        fun userAuthenticationTime(): Long = clock()

        private const val DIR = "pqc_keys"
        private const val MAX_FIELD = 64 * 1024
        // Version 3 seals each key under its own Keystore wrap key, named in the record;
        // earlier records (never released) do not open and are not migrated.
        private val MAGIC = byteArrayOf('X'.code.toByte(), 'P'.code.toByte(), 'Q'.code.toByte(), '3'.code.toByte())

        /** Throws unless [userAuthenticatedAt] meets [authDurationSeconds]. */
        private fun requireUserAuthentication(authDurationSeconds: Int, userAuthenticatedAt: Long?) {
            if (authDurationSeconds < 0) return
            val at = userAuthenticatedAt ?: throw BiometricRequiredException()
            val windowMs = if (authDurationSeconds == 0) PER_USE_WINDOW_MS else authDurationSeconds * 1000L
            val age = clock() - at
            if (age < 0 || age > windowMs) throw BiometricRequiredException()
        }


        internal fun bcParameters(set: MlDsaParameterSet): MLDSAParameters = when (set) {
            MlDsaParameterSet.ML_DSA_44 -> MLDSAParameters.ml_dsa_44
            MlDsaParameterSet.ML_DSA_65 -> MLDSAParameters.ml_dsa_65
            MlDsaParameterSet.ML_DSA_87 -> MLDSAParameters.ml_dsa_87
        }

        /**
         * `len || alias || len || set || len || spki || generation || policy || pkcs8`,
         * in one array the caller zeroes.
         */
        private fun sealedPlaintext(
            alias: String,
            set: MlDsaParameterSet,
            spki: ByteArray,
            generation: Long,
            authDurationSeconds: Int,
            pkcs8: ByteArray
        ): ByteArray {
            val aliasBytes = alias.toByteArray(Charsets.UTF_8)
            val setBytes = set.wireName.toByteArray(Charsets.UTF_8)
            val buffer = ByteBuffer.allocate(
                4 + aliasBytes.size + 4 + setBytes.size + 4 + spki.size + 8 + 4 + pkcs8.size
            )
            buffer.putInt(aliasBytes.size).put(aliasBytes)
            buffer.putInt(setBytes.size).put(setBytes)
            buffer.putInt(spki.size).put(spki)
            buffer.putLong(generation)
            buffer.putInt(authDurationSeconds)
            buffer.put(pkcs8)
            return buffer.array()
        }

        private fun readField(buffer: ByteBuffer): String = String(readSizedField(buffer), Charsets.UTF_8)

        private fun readSizedField(buffer: ByteBuffer): ByteArray {
            val size = buffer.int
            if (size < 0 || size > buffer.remaining()) throw PqcKeyRecordException("ML-DSA record is damaged")
            return ByteArray(size).also { buffer.get(it) }
        }
    }
}

/**
 * The wrap keys software ML-DSA records are sealed under, one per record:
 * removing a record's wrap key revokes every copy of that record.
 */
internal interface PqcWrapKeyring {
    /** A fresh id for a new wrap key; [seal] makes the key on first use. */
    fun newId(): String

    /** Seals [plaintext] under wrap key [id]. */
    fun seal(id: String, plaintext: ByteArray): ByteArray

    /** @throws GeneralSecurityException when wrap key [id] was removed or [sealed] does not open under it. */
    fun open(id: String, sealed: ByteArray): ByteArray

    /** Removes wrap key [id]; @throws GeneralSecurityException when it is still there. */
    fun destroy(id: String)

    companion object {
        private val random = SecureRandom()

        /** 16 random bytes as lowercase hex. */
        fun randomId(): String = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }

        /** Whether [id] has the form [randomId] makes. */
        fun isWrapId(id: String): Boolean = id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' }
    }
}

/** One AndroidKeyStore AES-256-GCM key per record, under [KeystoreAeadCipher.PQC_WRAP_ALIAS_PREFIX] and its id. */
internal class KeystoreWrapKeyring : PqcWrapKeyring {
    private val keyStore: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    override fun newId(): String = PqcWrapKeyring.randomId()

    override fun seal(id: String, plaintext: ByteArray): ByteArray {
        val wrapAlias = KeystoreAeadCipher.PQC_WRAP_ALIAS_PREFIX + id
        return KeystoreAeadCipher(wrapAlias).encrypt(plaintext)
    }

    override fun open(id: String, sealed: ByteArray): ByteArray {
        val wrapAlias = KeystoreAeadCipher.PQC_WRAP_ALIAS_PREFIX + id
        // Checked first: the cipher would make a fresh key under a removed alias.
        if (!keyStore.containsAlias(wrapAlias)) throw PqcKeyRecordException("ML-DSA key was deleted")
        val cipher = KeystoreAeadCipher(wrapAlias)
        return cipher.decrypt(sealed)
    }

    override fun destroy(id: String) {
        val wrapAlias = KeystoreAeadCipher.PQC_WRAP_ALIAS_PREFIX + id
        keyStore.deleteEntry(wrapAlias)
        if (keyStore.containsAlias(wrapAlias)) throw KeyStoreException("ML-DSA wrap key was not removed")
    }
}

/** Seals every record with one injected [cipher]; removed ids stay refused for this instance's life. Tests only. */
internal class SingleCipherKeyring(private val cipher: KeystoreAeadCipher) : PqcWrapKeyring {
    private val removed = mutableSetOf<String>()

    override fun newId(): String = PqcWrapKeyring.randomId()

    override fun seal(id: String, plaintext: ByteArray): ByteArray = cipher.encrypt(plaintext)

    override fun open(id: String, sealed: ByteArray): ByteArray {
        if (synchronized(removed) { id in removed }) throw PqcKeyRecordException("ML-DSA key was deleted")
        return cipher.decrypt(sealed)
    }

    override fun destroy(id: String) {
        synchronized(removed) { removed += id }
    }
}
