package com.automatethethings.xkey.ble

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.cancellation.CancellationException

/**
 * Noise_XX_25519_ChaChaPoly_SHA256 session for BLE encryption.
 *
 * This implementation is compatible with the Go flynn/noise library.
 * It uses raw 32-byte X25519 keys (not X.509 encoded).
 *
 * The XX handshake pattern:
 * -> e
 * <- e, ee, s, es
 * -> s, se
 *
 * Thread safety: This class is NOT thread-safe. Synchronize externally.
 *
 * ## Key material on the heap (#6)
 *
 * So that key material does not outlive its use in process memory (a heap dump
 * or a later allocation can otherwise expose it), the secret arrays
 * this class owns are overwritten with zeros (`fill(0)`) before their reference
 * is dropped or replaced:
 *
 *  - the static private key, when [loadStaticKey] or a regeneration replaces it;
 *  - the ephemeral private key, the chaining key, the handshake encryption key
 *    and the handshake hash, when the next handshake state replaces them, when
 *    [reset] drops them, and (all but the hash) as soon as the handshake splits
 *    into transport keys;
 *  - the send and receive transport keys, on [reset] and on replacement;
 *  - the intermediates: every DH output once mixed in, the HKDF pseudorandom
 *    key, the PKCS#8 wrapping of a private scalar, the clamped scalar copy, and
 *    a PKCS#8-encoded private key read from storage once its raw key is cut out.
 *
 * Public keys (ours, the peer's, both ephemerals) and the prologue are not
 * secret and are not zeroized; getters hand out copies.
 *
 * This is **best effort**. A generational collector may already have copied an
 * array before it is zeroed, and several copies are out of reach: the
 * `SecretKeySpec`, `PKCS8EncodedKeySpec`, `PrivateKey`, `Mac` and `Cipher`
 * objects the JCA builds keep their own clones; the Base64 `String` the static
 * key is stored as is immutable; and the X25519 implementations ([X25519]: the
 * platform provider, or Bouncy Castle's constant-time fallback where the
 * platform has none) keep their own working state, out of this class's reach.
 * The static
 * private key also lives for as long as the session object does: nothing
 * releases it before the collector does.
 *
 * Zeroization here is hygiene, not a compliance claim: no mandate is met on
 * its basis alone.
 */
class NoiseSession {
    companion object {
        private const val TAG = "NoiseSession"

        // Noise protocol name for hashing
        private const val PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256"

        // Key sizes
        private const val KEY_SIZE = 32
        private const val NONCE_SIZE = 8  // ChaCha20-Poly1305 uses 8-byte counter
        private const val TAG_SIZE = 16

        // Noise reserves the counter value 2^64-1 (-1 as a signed Long):
        // no message is encrypted or decrypted with it (#236)
        private const val RESERVED_NONCE = -1L

        // SharedPreferences keys
        private const val PREFS_NAME = "xkey_noise_keys"
        private const val KEY_STATIC_PRIVATE = "static_private_key"
        private const val KEY_STATIC_PUBLIC = "static_public_key"

        /** Opens the encrypted store the static key pair lives in. */
        private fun openEncryptedKeyStore(context: Context): SharedPreferences {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            return EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }

        /** The production [keyStoreOpener]. */
        internal val ENCRYPTED_KEY_STORE: (Context) -> SharedPreferences = { openEncryptedKeyStore(it) }

        /**
         * Opens the store the static key pair lives in. Test seam: off-device
         * there is no Android Keystore, so a unit test puts an in-memory store
         * here (or one whose open throws); production code must not set it.
         */
        @Volatile
        internal var keyStoreOpener: (Context) -> SharedPreferences = ENCRYPTED_KEY_STORE

        /**
         * Data class for returning the stored static key pair.
         */
        data class StaticKeyPair(
            val privateKey: ByteArray,
            val publicKey: ByteArray
        )

        /**
         * Loads the static key pair from encrypted storage.
         * This is useful for BleClient which needs the same key for initiator mode.
         *
         * Null means only that no key is stored (neither half present). A store
         * that cannot be opened, holds only one half, or holds a key that does
         * not decode to the right size is a corrupt store and throws.
         *
         * @param context Android context
         * @return The stored key pair, or null if no keys are stored
         * @throws NoiseException when the store cannot be read or holds a corrupt key
         */
        suspend fun getStoredStaticKeyPair(context: Context): StaticKeyPair? {
            val prefs = try {
                keyStoreOpener(context)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Failed to open the static key store", e)
                throw NoiseException("Static key store cannot be opened", e)
            }

            val privateKeyBase64 = prefs.getString(KEY_STATIC_PRIVATE, null)
            val publicKeyBase64 = prefs.getString(KEY_STATIC_PUBLIC, null)

            if (privateKeyBase64 == null && publicKeyBase64 == null) return null
            if (privateKeyBase64 == null || publicKeyBase64 == null) {
                throw NoiseException("Stored static key pair is incomplete")
            }

            // The decoder's message quotes a character of the stored secret:
            // neither it nor the exception is carried.
            var decodedPrivKey = try {
                Base64.getDecoder().decode(privateKeyBase64)
            } catch (e: IllegalArgumentException) {
                null
            } ?: throw NoiseException("Stored static private key does not decode")
            var decodedPubKey = try {
                Base64.getDecoder().decode(publicKeyBase64)
            } catch (e: IllegalArgumentException) {
                null
            }
            if (decodedPubKey == null) {
                decodedPrivKey.fill(0)
                throw NoiseException("Stored static public key does not decode")
            }

            // Handle PKCS#8 encoded private key (48 bytes)
            if (decodedPrivKey.size == 48 &&
                decodedPrivKey[0] == 0x30.toByte() && decodedPrivKey[1] == 0x2e.toByte()) {
                val encoded = decodedPrivKey
                decodedPrivKey = encoded.copyOfRange(16, 48)
                encoded.fill(0)
            }

            // Handle X.509 encoded public key (44 bytes)
            if (decodedPubKey.size == 44 &&
                decodedPubKey[0] == 0x30.toByte() && decodedPubKey[1] == 0x2a.toByte()) {
                decodedPubKey = decodedPubKey.copyOfRange(12, 44)
            }

            if (decodedPrivKey.size != KEY_SIZE || decodedPubKey.size != KEY_SIZE) {
                val sizes = "privkey: ${decodedPrivKey.size}, pubkey: ${decodedPubKey.size}"
                decodedPrivKey.fill(0)
                throw NoiseException("Stored static key has the wrong size ($sizes)")
            }

            return StaticKeyPair(decodedPrivKey, decodedPubKey)
        }
    }

    // Static keypair (raw 32-byte keys)
    private var staticPrivateKey: ByteArray? = null
    private var staticPublicKey: ByteArray? = null

    // Ephemeral keypair (per session)
    private var ephemeralPrivateKey: ByteArray? = null
    private var ephemeralPublicKey: ByteArray? = null

    // Remote keys
    private var remoteEphemeralKey: ByteArray? = null
    private var remoteStaticKey: ByteArray? = null

    // Symmetric state during handshake
    private var chainingKey: ByteArray = ByteArray(KEY_SIZE)
    private var handshakeHash: ByteArray = ByteArray(KEY_SIZE)
    private var encryptionKey: ByteArray? = null
    private var handshakeNonce: Long = 0  // Nonce for handshake encryption, resets after mixKey

    // Session keys after handshake
    private var sendKey: ByteArray? = null
    private var recvKey: ByteArray? = null
    // Transport counters: recvNonce advances only on a frame that decrypts,
    // and neither is ever used at RESERVED_NONCE (#236)
    private var sendNonce: Long = 0
    private var recvNonce: Long = 0

    // Handshake state
    private var handshakeState = HandshakeState.AWAITING_INIT
    private var handshakeComplete = false

    // Random number generator
    private val secureRandom = SecureRandom()

    // Prologue for trusted device binding (must match on both sides)
    private var prologue: ByteArray = ByteArray(0)

    /**
     * Sets the prologue for trusted device binding.
     *
     * The prologue is mixed into the handshake hash and must match exactly
     * on both sides for the handshake to succeed. Use this to bind the
     * handshake to external channel context (e.g., expected device fingerprints).
     *
     * Must be called BEFORE [loadStaticKey] or before the next handshake.
     *
     * @param data The prologue data (empty by default)
     */
    fun setPrologue(data: ByteArray) {
        prologue = data
        Log.d(TAG, "Prologue set: ${data.size} bytes")
    }

    /**
     * The prologue this session ran its handshake under — empty when none was
     * set.
     *
     * Needed by the device-attestation channel binding (go-xkms#129 §5), which
     * commits to the prologue so that a first pairing and a reconnect can never
     * derive the same binding. Returns a copy: the prologue is part of a
     * completed handshake's transcript and a caller must not be able to edit it
     * out from under the session.
     */
    fun getPrologue(): ByteArray = prologue.copyOf()

    /**
     * Loads the static key from encrypted storage.
     *
     * The static key is the device identity every paired desktop pins. When no
     * key is stored yet (neither half present) one is generated and saved.
     * Anything else that goes wrong (the store cannot be opened, one half is
     * missing, a stored key cannot be decoded, the new key cannot be saved)
     * throws [NoiseException]: the session fails closed rather than answer
     * under an unsaved identity that no paired desktop knows and the next
     * connection would replace.
     *
     * @throws NoiseException when the static key cannot be loaded or saved.
     */
    suspend fun loadStaticKey(context: Context) {
        try {
            val prefs = keyStoreOpener(context)

            val privateKeyBase64 = prefs.getString(KEY_STATIC_PRIVATE, null)
            val publicKeyBase64 = prefs.getString(KEY_STATIC_PUBLIC, null)

            if (privateKeyBase64 != null && publicKeyBase64 != null) {
                val decodedPrivKey = Base64.getDecoder().decode(privateKeyBase64)
                val decodedPubKey = Base64.getDecoder().decode(publicKeyBase64)

                // Check if the private key is PKCS#8 encoded (48 bytes) vs raw (32 bytes)
                // PKCS#8 header for X25519: 302e020100300506032b656e04220420 (16 bytes)
                val rawPrivKey = if (decodedPrivKey.size == 48 &&
                    decodedPrivKey[0] == 0x30.toByte() && decodedPrivKey[1] == 0x2e.toByte()) {
                    Log.w(TAG, "Converting PKCS#8 encoded private key to raw format")
                    // Extract raw 32-byte key from PKCS#8 encoding (skip 16-byte header)
                    decodedPrivKey.copyOfRange(16, 48).also { decodedPrivKey.fill(0) }
                } else {
                    decodedPrivKey
                }

                // Check if the public key is X.509 encoded (44 bytes) vs raw (32 bytes)
                // X.509 header for X25519: 302a300506032b656e032100 (12 bytes)
                val rawPubKey = if (decodedPubKey.size == 44 &&
                    decodedPubKey[0] == 0x30.toByte() && decodedPubKey[1] == 0x2a.toByte()) {
                    Log.w(TAG, "Converting X.509 encoded public key to raw format")
                    // Extract raw 32-byte key from X.509 encoding (skip 12-byte header)
                    decodedPubKey.copyOfRange(12, 44)
                } else {
                    decodedPubKey
                }

                if (rawPrivKey.size != KEY_SIZE || rawPubKey.size != KEY_SIZE) {
                    rawPrivKey.fill(0)
                    throw NoiseException(
                        "Stored static key has the wrong size (privkey: ${rawPrivKey.size}, pubkey: ${rawPubKey.size})"
                    )
                }

                if (staticPrivateKey !== rawPrivKey) staticPrivateKey?.fill(0)
                staticPrivateKey = rawPrivKey
                staticPublicKey = rawPubKey

                Log.d(TAG, "Loaded static key from storage")

                // If we had to convert from encoded format, re-save in raw format
                if (decodedPrivKey.size != KEY_SIZE || decodedPubKey.size != KEY_SIZE) {
                    Log.i(TAG, "Re-saving keys in raw format for future compatibility")
                    saveStaticKey(context)
                }
            } else if (privateKeyBase64 == null && publicKeyBase64 == null) {
                generateStaticKey()
                saveStaticKey(context)
                Log.d(TAG, "Generated new static key")
            } else {
                throw NoiseException("Stored static key pair is incomplete")
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load static key; refusing the session", e)
            // Nothing half-loaded stays behind
            staticPrivateKey?.fill(0)
            staticPrivateKey = null
            staticPublicKey = null
            throw e as? NoiseException ?: NoiseException("Failed to load static key: ${e.message}", e)
        }
    }

    /**
     * Saves the static key to encrypted storage. Throws when it cannot: a key
     * that is not saved is not the device identity.
     */
    private suspend fun saveStaticKey(context: Context) {
        val privKey = staticPrivateKey ?: return
        val pubKey = staticPublicKey ?: return

        val prefs = keyStoreOpener(context)
        val saved = prefs.edit()
            .putString(KEY_STATIC_PRIVATE, Base64.getEncoder().encodeToString(privKey))
            .putString(KEY_STATIC_PUBLIC, Base64.getEncoder().encodeToString(pubKey))
            .commit()
        if (!saved) throw NoiseException("Failed to save static key")

        Log.d(TAG, "Saved static key to storage")
    }

    private fun generateStaticKey() {
        val privateKey = newClampedScalar()
        staticPrivateKey?.fill(0)
        staticPrivateKey = privateKey
        staticPublicKey = X25519.scalarMultBase(privateKey)
    }

    private fun generateEphemeralKey() {
        val privateKey = newClampedScalar()
        ephemeralPrivateKey?.fill(0)
        ephemeralPrivateKey = privateKey
        ephemeralPublicKey = X25519.scalarMultBase(privateKey)
    }

    /**
     * A fresh random X25519 private scalar, clamped per RFC 7748.
     */
    private fun newClampedScalar(): ByteArray {
        val scalar = ByteArray(KEY_SIZE).also { secureRandom.nextBytes(it) }
        scalar[0] = (scalar[0].toInt() and 248).toByte()
        scalar[31] = (scalar[31].toInt() and 127).toByte()
        scalar[31] = (scalar[31].toInt() or 64).toByte()
        return scalar
    }

    /**
     * Initializes the handshake symmetric state.
     */
    private fun initializeHandshakeState() {
        // h = SHA256(protocol_name) padded/truncated to 32 bytes
        val protocolBytes = PROTOCOL_NAME.toByteArray()
        val initialHash = if (protocolBytes.size <= KEY_SIZE) {
            ByteArray(KEY_SIZE).also { System.arraycopy(protocolBytes, 0, it, 0, protocolBytes.size) }
        } else {
            sha256(protocolBytes)
        }
        handshakeHash.fill(0)
        handshakeHash = initialHash

        // ck = h
        chainingKey.fill(0)
        chainingKey = handshakeHash.copyOf()

        // MixHash(prologue) - Noise spec requires this even for empty prologue!
        // h = SHA256(h || prologue)
        // With empty prologue, this is h = SHA256(h)
        mixHash(prologue)

        // Generate ephemeral key
        generateEphemeralKey()

        // Reset encryption key and nonce
        encryptionKey?.fill(0)
        encryptionKey = ByteArray(KEY_SIZE)
        handshakeNonce = 0

    }

    /**
     * Processes a handshake message from the remote party.
     *
     * @param message The incoming handshake message (raw Noise protocol format)
     * @return Response message to send, or null if handshake complete
     */
    suspend fun processHandshakeMessage(message: ByteArray): ByteArray? {
        Log.d(TAG, "Processing handshake message: ${message.size} bytes, state=$handshakeState")

        return when (handshakeState) {
            HandshakeState.AWAITING_INIT -> processHandshakeInit(message)
            HandshakeState.AWAITING_FINAL -> processHandshakeFinal(message)
            HandshakeState.COMPLETE -> throw NoiseException("Handshake already complete")
        }
    }

    /**
     * Processes the first handshake message (-> e).
     * Responds with (<- e, ee, s, es).
     */
    private fun processHandshakeInit(message: ByteArray): ByteArray {
        Log.i(TAG, "Processing handshake init, message size: ${message.size}")

        // Message is just the remote ephemeral public key (32 bytes)
        if (message.size != KEY_SIZE) {
            throw NoiseException("Invalid init message size: ${message.size}, expected $KEY_SIZE")
        }
        // No identity, no answer: loadStaticKey failed or was never called
        if (staticPrivateKey == null || staticPublicKey == null) {
            throw NoiseException("No static key loaded")
        }

        // The handshake state (and the ephemeral key) exists only from msg1
        // on, so a reset or an idle session holds no handshake secret
        initializeHandshakeState()

        // Extract remote ephemeral public key (e)
        remoteEphemeralKey = message.copyOf()

        // MixHash(remote_e) - from reading msg1
        mixHash(remoteEphemeralKey!!)

        // Per Noise spec, after processing message tokens, we must also "decrypt" the payload.
        // For msg1, the payload is empty and hasK=false, so DecryptAndHash just does MixHash(empty).
        // This is critical for hash state synchronization with flynn/noise library!
        mixHash(ByteArray(0))

        // e - our ephemeral public key (32 bytes)
        // Per Noise XX spec, MixHash(local_e) MUST happen BEFORE MixKey(ee)
        mixHash(ephemeralPublicKey!!)

        // ee - DH(e, re)
        mixDh(ephemeralPrivateKey!!, remoteEphemeralKey!!)

        // s - our static public key (encrypted)
        val encryptedS = encryptAndHash(staticPublicKey!!)
        Log.d(TAG, "NOISE STATE: encrypted_s (${encryptedS.size} bytes)")

        // es - DH(s, re)
        mixDh(staticPrivateKey!!, remoteEphemeralKey!!)

        handshakeState = HandshakeState.AWAITING_FINAL

        // Build response: <- e (32) + encrypted_s (48) + encrypted_empty_payload (16) = 96 bytes
        // Note: MixHash(local_e) was already called above before MixKey(ee)
        // Per Noise spec, even empty payloads must be encrypted, producing a 16-byte AEAD tag
        val emptyPayloadCiphertext = encryptAndHash(ByteArray(0))
        Log.d(TAG, "NOISE STATE: encrypted empty payload (${emptyPayloadCiphertext.size} bytes)")

        val result = ByteArray(KEY_SIZE + encryptedS.size + emptyPayloadCiphertext.size)
        System.arraycopy(ephemeralPublicKey!!, 0, result, 0, KEY_SIZE)
        System.arraycopy(encryptedS, 0, result, KEY_SIZE, encryptedS.size)
        System.arraycopy(emptyPayloadCiphertext, 0, result, KEY_SIZE + encryptedS.size, emptyPayloadCiphertext.size)

        Log.i(TAG, "Handshake response size: ${result.size} bytes (expected 96)")
        return result
    }

    /**
     * Processes the final handshake message (-> s, se).
     */
    private fun processHandshakeFinal(message: ByteArray): ByteArray? {
        Log.d(TAG, "Processing handshake final, message size: ${message.size}")

        try {
            // Message contains: encrypted static key (32 + 16 bytes) + encrypted payload
            // (at least its 16-byte AEAD tag). flynn/noise always encrypts the payload,
            // so a shorter msg3 is malformed: refuse it, never complete without it.
            val expectedMinSize = KEY_SIZE + TAG_SIZE + TAG_SIZE // 32 + 16 + 16 = 64
            if (message.size < expectedMinSize) {
                throw NoiseException("Invalid final message size: ${message.size}, expected at least $expectedMinSize")
            }

            // Decrypt remote static key
            val encryptedRS = message.copyOfRange(0, KEY_SIZE + TAG_SIZE)
            remoteStaticKey = decryptAndHash(encryptedRS)

            // se - DH(e, rs)
            mixDh(ephemeralPrivateKey!!, remoteStaticKey!!)

            // Decrypt the payload (flynn/noise always sends one, empty or not)
            val encryptedPayload = message.copyOfRange(KEY_SIZE + TAG_SIZE, message.size)
            val payload = decryptAndHash(encryptedPayload)
            Log.d(TAG, "Decrypted msg3 payload: ${payload.size} bytes")

            // Split into transport keys
            Log.d(TAG, "Splitting symmetric state...")
            splitSymmetricState()
            Log.d(TAG, "Split complete")
            afterSplitForTest?.invoke()

            // The ephemeral private key has no use after the last DH
            ephemeralPrivateKey?.fill(0)
            ephemeralPrivateKey = null

            handshakeState = HandshakeState.COMPLETE
            handshakeComplete = true

            Log.i(TAG, "Handshake complete - ready for application messages")
            return null // No response needed
        } catch (e: Exception) {
            Log.e(TAG, "processHandshakeFinal FAILED: ${e.message}", e)
            throw e
        }
    }

    /**
     * SHA-256 hash.
     */
    private fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    private fun mixHash(data: ByteArray) {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(handshakeHash)
        digest.update(data)
        val previous = handshakeHash
        handshakeHash = digest.digest()
        previous.fill(0)
    }

    private fun mixKey(inputKeyMaterial: ByteArray) {
        val (ck, k) = hkdf2(chainingKey, inputKeyMaterial)
        chainingKey.fill(0)
        chainingKey = ck
        encryptionKey?.fill(0)
        encryptionKey = k
        handshakeNonce = 0  // Reset nonce when key changes
    }

    /**
     * MixKey(DH(privateKey, publicKey)). The DH output is overwritten once it
     * has been mixed in, or once mixing it in has failed. [X25519.dh] refuses
     * an all-zero output, so a small-order peer key never reaches [mixKey].
     */
    private fun mixDh(privateKey: ByteArray, publicKey: ByteArray) {
        val secret = X25519.dh(privateKey, publicKey)
        try {
            mixKey(secret)
        } finally {
            secret.fill(0)
        }
    }

    private fun hkdf2(salt: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        // Extract
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        try {
            // Expand - output 1
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(byteArrayOf(0x01))
            val t1 = mac.doFinal()

            // Expand - output 2
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t1)
            mac.update(byteArrayOf(0x02))
            val t2 = mac.doFinal()

            return Pair(t1, t2)
        } finally {
            prk.fill(0)
        }
    }

    /**
     * Encrypts plaintext using ChaCha20-Poly1305 and mixes ciphertext into hash.
     */
    private fun encryptAndHash(plaintext: ByteArray): ByteArray {
        if (handshakeNonce == RESERVED_NONCE) throw NoiseException("Handshake nonce exhausted")

        // Noise uses 12-byte nonce: 4 bytes of zeros + 8-byte little-endian counter
        // Per Noise spec: "96-bit nonce is formed by encoding 32 bits of zeros
        // followed by little-endian encoding of n"
        val nonce = ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0)               // bytes 0-3: 32 bits of zeros
            .putLong(handshakeNonce) // bytes 4-11: counter in little-endian
            .array()

        Log.d(TAG, "encryptAndHash: plaintext=${plaintext.size}, key=${encryptionKey?.size}, hash=${handshakeHash.size}, nonce=$handshakeNonce")

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(encryptionKey!!, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        cipher.updateAAD(handshakeHash)
        val ciphertext = cipher.doFinal(plaintext)

        Log.d(TAG, "encryptAndHash: ciphertext=${ciphertext.size} (expected ${plaintext.size + TAG_SIZE})")

        mixHash(ciphertext)
        handshakeNonce++  // Increment nonce for next operation with same key

        return ciphertext
    }

    /**
     * Decrypts ciphertext using ChaCha20-Poly1305 and mixes it into hash.
     */
    private fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        if (handshakeNonce == RESERVED_NONCE) throw NoiseException("Handshake nonce exhausted")

        // Noise uses 12-byte nonce: 4 bytes of zeros + 8-byte little-endian counter
        // Per Noise spec: "96-bit nonce is formed by encoding 32 bits of zeros
        // followed by little-endian encoding of n"
        val nonce = ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0)               // bytes 0-3: 32 bits of zeros
            .putLong(handshakeNonce) // bytes 4-11: counter in little-endian
            .array()

        Log.d(TAG, "decryptAndHash: ciphertext=${ciphertext.size}, nonce=$handshakeNonce")

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(encryptionKey!!, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        cipher.updateAAD(handshakeHash)

        val plaintext = cipher.doFinal(ciphertext)

        mixHash(ciphertext)
        handshakeNonce++  // Increment nonce for next operation with same key
        return plaintext
    }

    private fun splitSymmetricState() {
        val (k1, k2) = hkdf2(chainingKey, ByteArray(0))

        // Responder: k1 for receiving, k2 for sending
        recvKey?.fill(0)
        recvKey = k1
        sendKey?.fill(0)
        sendKey = k2
        sendNonce = 0
        recvNonce = 0

        // Split ends the symmetric state: the chaining key and the handshake
        // key are never used again. The handshake hash stays until [reset]:
        // it is the transcript value, not a key.
        chainingKey.fill(0)
        encryptionKey?.fill(0)
        encryptionKey = null
    }

    /**
     * Encrypts plaintext for transport.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val key = sendKey ?: throw NoiseException("Session not established")
        if (sendNonce == RESERVED_NONCE) throw NoiseException("Send nonce exhausted")

        // Noise spec: "96-bit nonce is formed by encoding 32 bits of zeros
        // followed by little-endian encoding of n"
        val nonce = ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0)             // bytes 0-3: 32 bits of zeros
            .putLong(sendNonce++)  // bytes 4-11: counter in little-endian
            .array()

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(key, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

        return cipher.doFinal(plaintext)
    }

    /**
     * Decrypts ciphertext from transport.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        val key = recvKey ?: throw NoiseException("Session not established")
        if (recvNonce == RESERVED_NONCE) throw NoiseException("Receive nonce exhausted")

        // Noise spec: "96-bit nonce is formed by encoding 32 bits of zeros
        // followed by little-endian encoding of n"
        val nonce = ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0)             // bytes 0-3: 32 bits of zeros
            .putLong(recvNonce)    // bytes 4-11: counter in little-endian
            .array()

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(key, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

        // Noise DecryptWithAd: a frame that fails authentication throws
        // here and leaves recvNonce unchanged, so the next genuine frame
        // still decrypts (#236)
        val plaintext = cipher.doFinal(ciphertext)
        recvNonce++
        return plaintext
    }

    /**
     * Returns whether the handshake is complete.
     */
    fun isHandshakeComplete(): Boolean = handshakeComplete

    /**
     * Returns the remote static public key after handshake, as a copy the
     * caller owns: a later [reset] cannot touch it.
     */
    fun getRemoteStaticKey(): ByteArray? = remoteStaticKey?.copyOf()

    /**
     * Returns our static public key, as a copy the caller owns.
     */
    fun getStaticPublicKey(): ByteArray? = staticPublicKey?.copyOf()

    /**
     * Test seam (#236): sets the transport counters, so that a test can put a
     * session at the reserved counter value without sending 2^64 messages;
     * production code must not call this.
     */
    internal fun setTransportNoncesForTest(send: Long, recv: Long) {
        sendNonce = send
        recvNonce = recv
    }

    /**
     * Test seam (#6): the secret arrays this session holds right now, by field
     * name. These are the live arrays, not copies, so that a test can watch
     * them being overwritten; production code must not call this.
     */
    internal fun secretArraysForTest(): Map<String, ByteArray> = buildMap {
        staticPrivateKey?.let { put("staticPrivateKey", it) }
        ephemeralPrivateKey?.let { put("ephemeralPrivateKey", it) }
        put("chainingKey", chainingKey)
        put("handshakeHash", handshakeHash)
        encryptionKey?.let { put("encryptionKey", it) }
        sendKey?.let { put("sendKey", it) }
        recvKey?.let { put("recvKey", it) }
    }

    /**
     * Test seam (#59): the next transport send nonce, so a test can prove a
     * refused send consumed none. Production code must not call this.
     */
    internal fun sendNonceForTest(): Long = sendNonce

    /**
     * Test seam (#59): runs inside msg3 processing, after the transport keys
     * are split and before the handshake is marked complete, so a test can
     * land a revocation in that window. Production code must not set this.
     */
    @Volatile
    internal var afterSplitForTest: (() -> Unit)? = null

    /**
     * Resets the session state for a new handshake.
     *
     * Call this when reconnecting to the same or different device.
     * The prologue is preserved unless explicitly changed via [setPrologue].
     * Every transient secret of the old session is overwritten with zeros
     * before it is dropped; the static key pair is kept. No new handshake
     * secret is made here: the next msg1 initializes the handshake state.
     */
    fun reset() {
        ephemeralPrivateKey?.fill(0)
        ephemeralPrivateKey = null
        ephemeralPublicKey = null
        remoteEphemeralKey = null
        remoteStaticKey = null
        chainingKey.fill(0)
        chainingKey = ByteArray(KEY_SIZE)
        handshakeHash.fill(0)
        handshakeHash = ByteArray(KEY_SIZE)
        encryptionKey?.fill(0)
        encryptionKey = null
        handshakeNonce = 0
        sendKey?.fill(0)
        sendKey = null
        recvKey?.fill(0)
        recvKey = null
        sendNonce = 0
        recvNonce = 0
        handshakeState = HandshakeState.AWAITING_INIT
        handshakeComplete = false
        // No fresh ephemeral key here: the next msg1 initializes the handshake
        // state, under whatever prologue is set by then.
        Log.d(TAG, "Session reset for new handshake")
    }

    /**
     * Handshake state machine states.
     */
    private enum class HandshakeState {
        AWAITING_INIT,
        AWAITING_FINAL,
        COMPLETE
    }
}

/**
 * Exception thrown for Noise protocol errors.
 */
class NoiseException(message: String, cause: Throwable? = null) : Exception(message, cause)
