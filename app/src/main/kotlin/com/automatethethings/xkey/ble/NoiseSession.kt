package com.automatethethings.xkey.ble

import android.content.Context
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

        // SharedPreferences keys
        private const val PREFS_NAME = "xkey_noise_keys"
        private const val KEY_STATIC_PRIVATE = "static_private_key"
        private const val KEY_STATIC_PUBLIC = "static_public_key"

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
         * @param context Android context
         * @return The stored key pair, or null if no keys are stored
         */
        suspend fun getStoredStaticKeyPair(context: Context): StaticKeyPair? {
            return try {
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()

                val prefs = EncryptedSharedPreferences.create(
                    context,
                    PREFS_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )

                val privateKeyBase64 = prefs.getString(KEY_STATIC_PRIVATE, null)
                val publicKeyBase64 = prefs.getString(KEY_STATIC_PUBLIC, null)

                if (privateKeyBase64 != null && publicKeyBase64 != null) {
                    var decodedPrivKey = Base64.getDecoder().decode(privateKeyBase64)
                    var decodedPubKey = Base64.getDecoder().decode(publicKeyBase64)

                    // Handle PKCS#8 encoded private key (48 bytes)
                    if (decodedPrivKey.size == 48 &&
                        decodedPrivKey[0] == 0x30.toByte() && decodedPrivKey[1] == 0x2e.toByte()) {
                        decodedPrivKey = decodedPrivKey.copyOfRange(16, 48)
                    }

                    // Handle X.509 encoded public key (44 bytes)
                    if (decodedPubKey.size == 44 &&
                        decodedPubKey[0] == 0x30.toByte() && decodedPubKey[1] == 0x2a.toByte()) {
                        decodedPubKey = decodedPubKey.copyOfRange(12, 44)
                    }

                    StaticKeyPair(decodedPrivKey, decodedPubKey)
                } else {
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load static key pair", e)
                null
            }
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
     */
    suspend fun loadStaticKey(context: Context) {
        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val prefs = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            val privateKeyBase64 = prefs.getString(KEY_STATIC_PRIVATE, null)
            val publicKeyBase64 = prefs.getString(KEY_STATIC_PUBLIC, null)

            if (privateKeyBase64 != null && publicKeyBase64 != null) {
                val decodedPrivKey = Base64.getDecoder().decode(privateKeyBase64)
                val decodedPubKey = Base64.getDecoder().decode(publicKeyBase64)

                // Check if the private key is PKCS#8 encoded (48 bytes) vs raw (32 bytes)
                // PKCS#8 header for X25519: 302e020100300506032b656e04220420 (16 bytes)
                staticPrivateKey = if (decodedPrivKey.size == 48 &&
                    decodedPrivKey[0] == 0x30.toByte() && decodedPrivKey[1] == 0x2e.toByte()) {
                    Log.w(TAG, "Converting PKCS#8 encoded private key to raw format")
                    // Extract raw 32-byte key from PKCS#8 encoding (skip 16-byte header)
                    decodedPrivKey.copyOfRange(16, 48)
                } else {
                    decodedPrivKey
                }

                // Check if the public key is X.509 encoded (44 bytes) vs raw (32 bytes)
                // X.509 header for X25519: 302a300506032b656e032100 (12 bytes)
                staticPublicKey = if (decodedPubKey.size == 44 &&
                    decodedPubKey[0] == 0x30.toByte() && decodedPubKey[1] == 0x2a.toByte()) {
                    Log.w(TAG, "Converting X.509 encoded public key to raw format")
                    // Extract raw 32-byte key from X.509 encoding (skip 12-byte header)
                    decodedPubKey.copyOfRange(12, 44)
                } else {
                    decodedPubKey
                }

                Log.d(TAG, "Loaded static key from storage (privkey: ${staticPrivateKey!!.size}, pubkey: ${staticPublicKey!!.size})")

                // If we had to convert from encoded format, re-save in raw format
                if (decodedPrivKey.size != 32 || decodedPubKey.size != 32) {
                    Log.i(TAG, "Re-saving keys in raw format for future compatibility")
                    saveStaticKey(context)
                }
            } else {
                generateStaticKey()
                saveStaticKey(context)
                Log.d(TAG, "Generated new static key")
            }

            initializeHandshakeState()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to load static key, generating new one", e)
            generateStaticKey()
            initializeHandshakeState()
        }
    }

    /**
     * Saves the static key to encrypted storage.
     */
    private suspend fun saveStaticKey(context: Context) {
        val privKey = staticPrivateKey ?: return
        val pubKey = staticPublicKey ?: return

        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val prefs = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            prefs.edit()
                .putString(KEY_STATIC_PRIVATE, Base64.getEncoder().encodeToString(privKey))
                .putString(KEY_STATIC_PUBLIC, Base64.getEncoder().encodeToString(pubKey))
                .apply()

            Log.d(TAG, "Saved static key to storage")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save static key", e)
        }
    }

    /**
     * Generates a new X25519 static keypair using raw 32-byte format.
     */
    private fun generateStaticKey() {
        staticPrivateKey = ByteArray(KEY_SIZE).also { secureRandom.nextBytes(it) }
        // Clamp the private key per X25519 spec
        staticPrivateKey!![0] = (staticPrivateKey!![0].toInt() and 248).toByte()
        staticPrivateKey!![31] = (staticPrivateKey!![31].toInt() and 127).toByte()
        staticPrivateKey!![31] = (staticPrivateKey!![31].toInt() or 64).toByte()
        staticPublicKey = x25519ScalarMultBase(staticPrivateKey!!)
    }

    /**
     * Generates a new ephemeral X25519 keypair.
     */
    private fun generateEphemeralKey() {
        ephemeralPrivateKey = ByteArray(KEY_SIZE).also { secureRandom.nextBytes(it) }
        // Clamp the private key per X25519 spec
        ephemeralPrivateKey!![0] = (ephemeralPrivateKey!![0].toInt() and 248).toByte()
        ephemeralPrivateKey!![31] = (ephemeralPrivateKey!![31].toInt() and 127).toByte()
        ephemeralPrivateKey!![31] = (ephemeralPrivateKey!![31].toInt() or 64).toByte()
        ephemeralPublicKey = x25519ScalarMultBase(ephemeralPrivateKey!!)
    }

    /**
     * Initializes the handshake symmetric state.
     */
    private fun initializeHandshakeState() {
        // h = SHA256(protocol_name) padded/truncated to 32 bytes
        val protocolBytes = PROTOCOL_NAME.toByteArray()
        if (protocolBytes.size <= KEY_SIZE) {
            handshakeHash = ByteArray(KEY_SIZE)
            System.arraycopy(protocolBytes, 0, handshakeHash, 0, protocolBytes.size)
        } else {
            handshakeHash = sha256(protocolBytes)
        }

        // ck = h
        chainingKey = handshakeHash.copyOf()

        // MixHash(prologue) - Noise spec requires this even for empty prologue!
        // h = SHA256(h || prologue)
        // With empty prologue, this is h = SHA256(h)
        mixHash(prologue)

        // Generate ephemeral key
        generateEphemeralKey()

        // Reset encryption key and nonce
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
        val eeSecret = x25519(ephemeralPrivateKey!!, remoteEphemeralKey!!)
        mixKey(eeSecret)

        // s - our static public key (encrypted)
        val encryptedS = encryptAndHash(staticPublicKey!!)
        Log.d(TAG, "NOISE STATE: encrypted_s (${encryptedS.size} bytes)")

        // es - DH(s, re)
        val esSecret = x25519(staticPrivateKey!!, remoteEphemeralKey!!)
        Log.i(TAG, "es DH secret: ${esSecret.size} bytes")
        mixKey(esSecret)

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
            // Message contains: encrypted static key (32 + 16 bytes) + encrypted empty payload (16 bytes) = 64 bytes
            // Per Noise spec, even empty payloads are encrypted with a 16-byte AEAD tag
            val expectedMinSize = KEY_SIZE + TAG_SIZE + TAG_SIZE // 32 + 16 + 16 = 64
            if (message.size < expectedMinSize) {
                // Backwards compatibility: accept 48-byte messages without empty payload
                // This handles implementations that don't encrypt empty payloads
                Log.w(TAG, "msg3 is only ${message.size} bytes, expected $expectedMinSize - proceeding with legacy format")
            }

            // Decrypt remote static key
            Log.d(TAG, "Decrypting remote static key...")
            val encryptedRS = message.copyOfRange(0, KEY_SIZE + TAG_SIZE)
            Log.d(TAG, "encryptedRS size: ${encryptedRS.size}")
            remoteStaticKey = decryptAndHash(encryptedRS)

            // se - DH(e, rs)
            Log.d(TAG, "Computing se DH...")
            val seSecret = x25519(ephemeralPrivateKey!!, remoteStaticKey!!)
            mixKey(seSecret)
            Log.d(TAG, "Computed se DH and mixKey complete")

            // Decrypt empty payload if present (flynn/noise includes this)
            if (message.size >= expectedMinSize) {
                Log.d(TAG, "Decrypting empty payload...")
                val encryptedEmptyPayload = message.copyOfRange(KEY_SIZE + TAG_SIZE, message.size)
                Log.d(TAG, "encryptedEmptyPayload size: ${encryptedEmptyPayload.size}")
                val emptyPayload = decryptAndHash(encryptedEmptyPayload)
                Log.d(TAG, "Decrypted empty payload: ${emptyPayload.size} bytes")
            }

            // Split into transport keys
            Log.d(TAG, "Splitting symmetric state...")
            splitSymmetricState()
            Log.d(TAG, "Split complete")

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
     * X25519 scalar multiplication with base point.
     * Computes public key from private key scalar.
     *
     * This uses the X25519 base point (u=9) and computes publicKey = scalar * basePoint.
     * We use the pure implementation here because Java's KeyAgreement may not accept
     * the base point as a valid public key for DH operations.
     */
    private fun x25519ScalarMultBase(scalar: ByteArray): ByteArray {
        // X25519 base point u-coordinate (u = 9 in little-endian)
        val basePoint = ByteArray(32)
        basePoint[0] = 9

        // Use pure implementation for scalar-mult-base since Java's KeyAgreement
        // may reject the base point as a public key
        return x25519ScalarMultPure(scalar, basePoint)
    }

    /**
     * X25519 scalar multiplication.
     * Computes result = scalar * point (Montgomery ladder).
     */
    private fun x25519ScalarMult(scalar: ByteArray, point: ByteArray): ByteArray {
        return try {
            // Try Java crypto API first
            val privKeySpec = java.security.spec.PKCS8EncodedKeySpec(wrapX25519PrivateKey(scalar))
            val pubKeySpec = java.security.spec.X509EncodedKeySpec(wrapX25519PublicKey(point))

            val keyFactory = java.security.KeyFactory.getInstance("X25519")
            val privKey = keyFactory.generatePrivate(privKeySpec)
            val pubKey = keyFactory.generatePublic(pubKeySpec)

            val keyAgreement = javax.crypto.KeyAgreement.getInstance("X25519")
            keyAgreement.init(privKey)
            keyAgreement.doPhase(pubKey, true)
            keyAgreement.generateSecret()
        } catch (e: Exception) {
            Log.e(TAG, "X25519 scalar mult via Java failed, using pure impl", e)
            x25519ScalarMultPure(scalar, point)
        }
    }

    /**
     * Pure Kotlin X25519 scalar multiplication (fallback).
     * Implements the Montgomery ladder from RFC 7748 using BigInteger.
     */
    private fun x25519ScalarMultPure(k: ByteArray, u: ByteArray): ByteArray {
        // Field arithmetic in GF(2^255 - 19)
        val p = java.math.BigInteger.ONE.shiftLeft(255).subtract(java.math.BigInteger.valueOf(19))

        // Decode scalar (clamp it)
        val kClamped = k.copyOf()
        kClamped[0] = (kClamped[0].toInt() and 248).toByte()
        kClamped[31] = (kClamped[31].toInt() and 127).toByte()
        kClamped[31] = (kClamped[31].toInt() or 64).toByte()

        // Decode u-coordinate (little-endian)
        val uInt = decodeLittleEndian(u).mod(p)

        // Montgomery ladder
        var x1 = uInt
        var x2 = java.math.BigInteger.ONE
        var z2 = java.math.BigInteger.ZERO
        var x3 = uInt
        var z3 = java.math.BigInteger.ONE

        var swap = java.math.BigInteger.ZERO

        for (t in 254 downTo 0) {
            val kT = kClamped[t / 8].toInt().ushr(t % 8).and(1)
            val kTBig = java.math.BigInteger.valueOf(kT.toLong())

            swap = swap.xor(kTBig)
            val (cx2, cx3) = cswap(swap, x2, x3)
            val (cz2, cz3) = cswap(swap, z2, z3)
            x2 = cx2; x3 = cx3; z2 = cz2; z3 = cz3
            swap = kTBig

            val a = x2.add(z2).mod(p)
            val aa = a.multiply(a).mod(p)
            val b = x2.subtract(z2).mod(p)
            val bb = b.multiply(b).mod(p)
            val e = aa.subtract(bb).mod(p)
            val c = x3.add(z3).mod(p)
            val d = x3.subtract(z3).mod(p)
            val da = d.multiply(a).mod(p)
            val cb = c.multiply(b).mod(p)
            x3 = da.add(cb).mod(p).pow(2).mod(p)
            z3 = x1.multiply(da.subtract(cb).mod(p).pow(2)).mod(p)
            x2 = aa.multiply(bb).mod(p)
            val a24 = java.math.BigInteger.valueOf(121665)
            z2 = e.multiply(aa.add(a24.multiply(e))).mod(p)
        }

        val (fx2, _) = cswap(swap, x2, x3)
        val (fz2, _) = cswap(swap, z2, z3)
        x2 = fx2; z2 = fz2

        // Compute result = x2 * z2^(p-2) mod p
        val result = x2.multiply(z2.modPow(p.subtract(java.math.BigInteger.valueOf(2)), p)).mod(p)

        return encodeLittleEndian(result)
    }

    private fun decodeLittleEndian(b: ByteArray): java.math.BigInteger {
        val reversed = b.reversedArray()
        return java.math.BigInteger(1, reversed)
    }

    private fun encodeLittleEndian(n: java.math.BigInteger): ByteArray {
        var bytes = n.toByteArray()
        // Remove leading zero if present
        if (bytes.size > 32 && bytes[0] == 0.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        // Pad to 32 bytes
        val result = ByteArray(32)
        val offset = 32 - bytes.size
        System.arraycopy(bytes, 0, result, offset, bytes.size)
        // Reverse for little-endian
        return result.reversedArray()
    }

    private fun cswap(swap: java.math.BigInteger, a: java.math.BigInteger, b: java.math.BigInteger): Pair<java.math.BigInteger, java.math.BigInteger> {
        return if (swap == java.math.BigInteger.ONE) Pair(b, a) else Pair(a, b)
    }

    /**
     * X25519 Diffie-Hellman.
     * Computes shared secret = privateKey * publicKey
     */
    /**
     * X25519 Diffie-Hellman.
     * Computes shared secret = privateKey * publicKey
     */
    private fun x25519(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        // Use the unified scalar multiplication function
        return x25519ScalarMult(privateKey, publicKey)
    }

    /**
     * Wraps raw X25519 private key in PKCS#8 format.
     */
    private fun wrapX25519PrivateKey(raw: ByteArray): ByteArray {
        // PKCS#8 header for X25519 private key
        val header = byteArrayOf(
            0x30, 0x2e, // SEQUENCE, length 46
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x05, // SEQUENCE, length 5
            0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
            0x04, 0x22, // OCTET STRING, length 34
            0x04, 0x20  // OCTET STRING, length 32
        )
        return header + raw
    }

    /**
     * Wraps raw X25519 public key in X.509 format.
     */
    private fun wrapX25519PublicKey(raw: ByteArray): ByteArray {
        // X.509 header for X25519 public key
        val header = byteArrayOf(
            0x30, 0x2a, // SEQUENCE, length 42
            0x30, 0x05, // SEQUENCE, length 5
            0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
            0x03, 0x21, 0x00 // BIT STRING, length 33, no unused bits
        )
        return header + raw
    }

    /**
     * Extracts raw 32-byte public key from Java PublicKey.
     */
    private fun extractRawPublicKey(publicKey: java.security.PublicKey): ByteArray {
        val encoded = publicKey.encoded
        // X.509 encoded X25519 key is 44 bytes, raw key is last 32
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    /**
     * SHA-256 hash.
     */
    private fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    /**
     * MixHash: h = SHA256(h || data)
     */
    private fun mixHash(data: ByteArray) {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(handshakeHash)
        digest.update(data)
        handshakeHash = digest.digest()
    }

    /**
     * MixKey: Derives new chaining key and encryption key.
     * Also resets the handshake nonce to 0 per Noise spec.
     */
    private fun mixKey(inputKeyMaterial: ByteArray) {
        val (ck, k) = hkdf2(chainingKey, inputKeyMaterial)
        chainingKey = ck
        encryptionKey = k
        handshakeNonce = 0  // Reset nonce when key changes
    }

    /**
     * HKDF-SHA256 with 2 outputs.
     */
    private fun hkdf2(salt: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        // Extract
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

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
    }

    /**
     * Encrypts plaintext using ChaCha20-Poly1305 and mixes ciphertext into hash.
     */
    private fun encryptAndHash(plaintext: ByteArray): ByteArray {
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

    /**
     * Splits the symmetric state into send and receive keys.
     */
    private fun splitSymmetricState() {
        val (k1, k2) = hkdf2(chainingKey, ByteArray(0))

        // Responder: k1 for receiving, k2 for sending
        recvKey = k1
        sendKey = k2
        sendNonce = 0
        recvNonce = 0
    }

    /**
     * Encrypts plaintext for transport.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val key = sendKey ?: throw NoiseException("Session not established")

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

        // Noise spec: "96-bit nonce is formed by encoding 32 bits of zeros
        // followed by little-endian encoding of n"
        val nonce = ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0)             // bytes 0-3: 32 bits of zeros
            .putLong(recvNonce++)  // bytes 4-11: counter in little-endian
            .array()

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(key, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

        return cipher.doFinal(ciphertext)
    }

    /**
     * Returns whether the handshake is complete.
     */
    fun isHandshakeComplete(): Boolean = handshakeComplete

    /**
     * Returns the remote static public key after handshake.
     */
    fun getRemoteStaticKey(): ByteArray? = remoteStaticKey

    /**
     * Returns our static public key.
     */
    fun getStaticPublicKey(): ByteArray? = staticPublicKey

    /**
     * Resets the session state for a new handshake.
     *
     * Call this when reconnecting to the same or different device.
     * The prologue is preserved unless explicitly changed via [setPrologue].
     */
    fun reset() {
        ephemeralPrivateKey = null
        ephemeralPublicKey = null
        remoteEphemeralKey = null
        remoteStaticKey = null
        chainingKey = ByteArray(KEY_SIZE)
        handshakeHash = ByteArray(KEY_SIZE)
        encryptionKey = null
        handshakeNonce = 0
        sendKey = null
        recvKey = null
        sendNonce = 0
        recvNonce = 0
        handshakeState = HandshakeState.AWAITING_INIT
        handshakeComplete = false
        initializeHandshakeState()
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
