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
package com.automatethethings.xkey.password

import com.automatethethings.xkey.pin.PinLockout
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.settings.VaultUnlockAttempts
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.signal.argon2.Argon2
import org.signal.argon2.MemoryCost
import org.signal.argon2.Type
import org.signal.argon2.Version
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/** Base type for the password vault's typed refusals. */
sealed class PasswordVaultException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The credential body is malformed. */
class VaultCredentialInvalidException(message: String) : PasswordVaultException(message)

/** An unlock or lock arrived before any factor was enrolled. */
class VaultNotInitializedException : PasswordVaultException("password vault is not initialized")

/**
 * The credential unwrapped no enrolled factor. Deliberately carries no detail:
 * which part was wrong is exactly what a guesser wants to learn.
 */
class VaultCredentialRejectedException : PasswordVaultException("password vault credential rejected")

/** The vault is initialized and locked. */
class PasswordStoreLockedException : PasswordVaultException("password store is locked")

/**
 * Too many failed unlocks: the vault refuses every credential, without
 * checking it, until the lockout ends. Carries no detail, as a PIN lockout
 * over USB need not tell a guesser when to resume.
 */
class VaultUnlockLockedOutException : PasswordVaultException("password vault unlock is locked out")

/**
 * The enrolled factors exist but cannot be read. Never taken for "no factor
 * enrolled": that would open a locked store, so every gate fails closed and
 * the RPC answers INTERNAL_ERROR.
 */
class PasswordVaultFactorsUnreadableException(cause: Throwable) :
    PasswordVaultException("password vault factors cannot be read", cause)

/** The PIN lockout thresholds the vault is held to. */
class VaultUnlockLimits(val maxAttempts: Int, val lockoutDurationSeconds: Int)

/**
 * Persistence for the vault's failed-unlock counter, and the thresholds that
 * counter is held to. The counter outlives a [PasswordVault] instance, so a
 * USB reconnect or an app restart does not reset it.
 */
interface VaultUnlockAttemptStore {

    /** The thresholds: the PIN's own. */
    suspend fun limits(): VaultUnlockLimits

    /** The persisted counter. */
    suspend fun read(): VaultUnlockAttempts

    /** Replaces the persisted counter. */
    suspend fun write(attempts: VaultUnlockAttempts)
}

/**
 * [VaultUnlockAttemptStore] backed by the PIN settings DataStore: the counter
 * is persisted beside the PIN counters, and the thresholds are the PIN's
 * configured `maxPinAttempts` and `lockoutDurationSeconds`.
 */
class PinSettingsVaultUnlockAttemptStore(
    private val repository: PinSettingsRepository
) : VaultUnlockAttemptStore {

    override suspend fun limits(): VaultUnlockLimits {
        val settings = repository.getSettings()
        return VaultUnlockLimits(settings.maxPinAttempts, settings.lockoutDurationSeconds)
    }

    override suspend fun read(): VaultUnlockAttempts = repository.getVaultUnlockAttempts()

    override suspend fun write(attempts: VaultUnlockAttempts) = repository.updateVaultUnlockAttempts(attempts)
}

/**
 * One enrolled vault factor as the phone persists it.
 *
 * Only passphrase factors exist on the phone today: [verifier] is the
 * Argon2id hash of the passphrase under [salt], never the passphrase itself.
 */
class PasswordVaultFactorRecord(
    val id: String,
    val factor: String,
    val label: String?,
    val createdAt: Long,
    val salt: ByteArray,
    val verifier: ByteArray
)

/** Persistence for enrolled vault factors. */
interface PasswordVaultFactorStore {

    /**
     * Every enrolled factor, oldest first: empty only when none is enrolled.
     *
     * @throws PasswordVaultFactorsUnreadableException if the factors cannot be read.
     */
    suspend fun list(): List<PasswordVaultFactorRecord>

    /** Appends an enrolled factor. */
    suspend fun add(record: PasswordVaultFactorRecord)
}

/**
 * [PasswordVaultFactorStore] backed by one JSON file, `factors.json`, in [dir]
 * (app-private storage, like the PIN verifiers in `PinSettings`). Writes go to a
 * temporary file first and are renamed into place, so a crash mid-write leaves
 * the previous list intact.
 */
class FilePasswordVaultFactorStore(private val dir: File) : PasswordVaultFactorStore {

    private val file: File get() = File(dir, "factors.json")

    override suspend fun list(): List<PasswordVaultFactorRecord> = withContext(Dispatchers.IO) {
        // Only a file that is not there means "no factor yet". File.exists()
        // also answers false when the lookup itself fails, which would read a
        // locked vault as uninitialized.
        val bytes = try {
            Files.readAllBytes(file.toPath())
        } catch (e: java.nio.file.NoSuchFileException) {
            return@withContext emptyList()
        } catch (e: IOException) {
            throw PasswordVaultFactorsUnreadableException(e)
        }
        val array = JSONArray(String(bytes, Charsets.UTF_8))
        (0 until array.length()).map { index ->
            val obj = array.getJSONObject(index)
            PasswordVaultFactorRecord(
                id = obj.getString("id"),
                factor = obj.getString("factor"),
                label = if (obj.has("label") && !obj.isNull("label")) obj.getString("label") else null,
                createdAt = obj.getLong("created_at"),
                salt = Base64.getDecoder().decode(obj.getString("salt")),
                verifier = Base64.getDecoder().decode(obj.getString("verifier"))
            )
        }
    }

    override suspend fun add(record: PasswordVaultFactorRecord) {
        val records = list() + record
        withContext(Dispatchers.IO) {
            dir.mkdirs()
            val array = JSONArray()
            records.forEach { r ->
                array.put(
                    JSONObject().apply {
                        put("id", r.id)
                        put("factor", r.factor)
                        if (r.label != null) put("label", r.label)
                        put("created_at", r.createdAt)
                        put("salt", Base64.getEncoder().encodeToString(r.salt))
                        put("verifier", Base64.getEncoder().encodeToString(r.verifier))
                    }
                )
            }
            val tmp = File(dir, "factors.json.tmp")
            tmp.writeText(array.toString())
            if (!tmp.renameTo(file)) {
                tmp.delete()
                throw java.io.IOException("failed to persist password vault factors")
            }
        }
    }
}

/** Derives a passphrase verifier. A seam so JVM tests need no native Argon2. */
fun interface PassphraseHasher {
    fun hash(passphrase: String, salt: ByteArray): ByteArray
}

/**
 * Argon2id with the parameters [com.automatethethings.xkey.pin.PinHasher]
 * uses (64 MiB, 3 iterations, 4 lanes, 32-byte output), without the PIN
 * length rule, which does not apply to a passphrase.
 */
object Argon2PassphraseHasher : PassphraseHasher {
    override fun hash(passphrase: String, salt: ByteArray): ByteArray {
        val argon2 = Argon2.Builder(Version.V13)
            .type(Type.Argon2id)
            .memoryCost(MemoryCost.KiB(65536))
            .parallelism(4)
            .iterations(3)
            .hashLength(32)
            .build()
        return argon2.hash(passphrase.toByteArray(Charsets.UTF_8), salt).hash
    }
}

/**
 * Names the [PasswordVault] of the session a request arrived on, for code
 * that reaches the password store below the transport, such as sync.
 *
 * A session that owns a vault (USB) adds this to the coroutine context of
 * every request it routes. The element is per request: the request handler is
 * shared by every transport, so session state on it would leak an unlocked USB
 * vault to a BLE peer.
 */
class SessionPasswordVault(val vault: PasswordVault) : AbstractCoroutineContextElement(SessionPasswordVault) {
    companion object Key : CoroutineContext.Key<SessionPasswordVault>
}

/**
 * The password store's lock check for every path without a vault of its own.
 *
 * Under a [SessionPasswordVault] the store is locked exactly when that vault
 * is. Without one (BLE, TCP, a phone-initiated sync) no credential can have
 * unlocked anything, so the store is locked once any factor is enrolled. With
 * no factor enrolled the store is open, as before the vault existed. Nothing
 * is hashed, so a locked refusal costs no Argon2id.
 *
 * @throws PasswordStoreLockedException if the store is locked.
 * @throws PasswordVaultFactorsUnreadableException if the enrolled factors
 *   cannot be read: whether the store is locked is unknown, so it stays shut.
 */
suspend fun requirePasswordStoreUnlocked(factors: PasswordVaultFactorStore) {
    val vault = currentCoroutineContext()[SessionPasswordVault]?.vault
    val locked = vault?.isLocked() ?: factors.list().isNotEmpty()
    if (locked) throw PasswordStoreLockedException()
}

/**
 * The phone's per-user password vault: the lock in front of the password store.
 *
 * Stored passwords are encrypted with a Keystore key (see [PasswordRepository]);
 * that key never leaves the TEE and is not derived from any factor. What the
 * vault adds is the gate: once a factor is enrolled the store is locked until
 * a credential for an enrolled factor unlocks it. Before any enrollment the
 * vault is uninitialized, unlock and lock answer [VaultNotInitializedException],
 * and the store stays usable as it was before the vault existed.
 *
 * The unlocked state lives in memory only, per instance: a new USB session
 * starts locked.
 *
 * Factors: only the passphrase factor can be enrolled on the phone
 * ([enrollPassphrase]). A passkey or key factor credential is parsed and
 * checked for shape, but no such factor can be enrolled here yet, so it
 * unwraps nothing and is rejected.
 *
 * Unlock attempts are limited by the PIN's lockout rule ([PinLockout]) with
 * the PIN's thresholds, through [attempts]: once the consecutive failures
 * reach the limit, unlocks are refused for the lockout duration without
 * hashing anything. The counter is persisted and only a successful unlock
 * clears it.
 *
 * @param clock Epoch milliseconds, the PIN lockout's time base.
 */
class PasswordVault(
    private val factors: PasswordVaultFactorStore,
    private val attempts: VaultUnlockAttemptStore,
    private val hasher: PassphraseHasher = Argon2PassphraseHasher,
    private val random: SecureRandom = SecureRandom(),
    private val clock: () -> Long = System::currentTimeMillis
) {
    companion object {
        private const val SALT_LENGTH = 16

        /**
         * The factor store's directory under the app's `filesDir`. The service
         * that builds the USB session's vault names the same directory
         * (`XKeyGattService.PASSWORD_VAULT_DIR`); the two must stay equal.
         */
        const val FACTOR_DIR = "password_vault"

        /**
         * Serializes the counter's read-modify-write across every vault
         * instance, as `PinManager`'s PIN state mutex does for the PINs.
         */
        private val attemptsMutex = Mutex()
    }

    private val mutex = Mutex()

    @Volatile
    private var unlocked = false

    /** Whether any factor is enrolled. */
    suspend fun isInitialized(): Boolean = factors.list().isNotEmpty()

    /** Whether a credential has unlocked the vault in this session. */
    fun isUnlocked(): Boolean = unlocked

    /** Whether the store is gated: initialized and not unlocked. */
    suspend fun isLocked(): Boolean = !unlocked && isInitialized()

    /**
     * Unlocks the vault with [credential].
     *
     * @throws VaultUnlockLockedOutException if too many unlocks have failed and
     *   the lockout has not ended. The credential is not checked.
     * @throws VaultNotInitializedException if no factor is enrolled.
     * @throws VaultCredentialRejectedException if the credential matches no
     *   enrolled factor. The vault stays locked and the failure is counted.
     */
    suspend fun unlock(credential: PasswordVaultCredential) = mutex.withLock {
        attemptsMutex.withLock {
            val counter = attempts.read()
            if (PinLockout.isLocked(counter.lockedUntil, clock())) throw VaultUnlockLockedOutException()
            val enrolled = factors.list()
            if (enrolled.isEmpty()) throw VaultNotInitializedException()
            val matched = when (credential) {
                is PasswordVaultCredential.Passphrase -> enrolled
                    .filter { it.factor == PasswordVaultCredential.FACTOR_PASSPHRASE }
                    .any { MessageDigest.isEqual(hasher.hash(credential.passphrase, it.salt), it.verifier) }
                // No passkey or key factor can be enrolled on the phone yet.
                is PasswordVaultCredential.Passkey -> false
                is PasswordVaultCredential.Key -> false
            }
            if (!matched) {
                val limits = attempts.limits()
                val failed = counter.failedAttempts + 1
                attempts.write(
                    VaultUnlockAttempts(
                        failedAttempts = failed,
                        lockedUntil = PinLockout.lockedUntil(
                            failed, limits.maxAttempts, limits.lockoutDurationSeconds, clock()
                        )
                    )
                )
                throw VaultCredentialRejectedException()
            }
            if (counter != VaultUnlockAttempts()) attempts.write(VaultUnlockAttempts())
            unlocked = true
        }
    }

    /**
     * Locks the vault.
     *
     * The vault is locked on every exit, the failures below included: access
     * is withdrawn before the fallible factor read, so a lock that throws
     * never leaves the store open.
     *
     * @throws VaultNotInitializedException if no factor is enrolled: a vault
     *   that nothing can unlock must not be lockable.
     * @throws PasswordVaultFactorsUnreadableException if the factors cannot be
     *   read. The vault is locked regardless.
     */
    suspend fun lock() = mutex.withLock {
        unlocked = false
        if (!isInitialized()) throw VaultNotInitializedException()
    }

    /**
     * Enrolls a passphrase factor and returns its record.
     *
     * Not reachable over any transport yet: the vault enroll verb is go-xkms'
     * to send (issue #15's remaining scope).
     */
    suspend fun enrollPassphrase(
        passphrase: String,
        label: String? = null,
        now: Long = System.currentTimeMillis()
    ): PasswordVaultFactorRecord = mutex.withLock {
        if (passphrase.isEmpty()) throw VaultCredentialInvalidException("passphrase is required")
        val salt = ByteArray(SALT_LENGTH).also { random.nextBytes(it) }
        val record = PasswordVaultFactorRecord(
            id = UUID.randomUUID().toString(),
            factor = PasswordVaultCredential.FACTOR_PASSPHRASE,
            label = label,
            createdAt = now,
            salt = salt,
            verifier = hasher.hash(passphrase, salt)
        )
        factors.add(record)
        record
    }
}
