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
package com.automatethethings.xkey.bootstrap

import android.util.Log
import com.automatethethings.xkey.settings.BootstrapMethod
import com.automatethethings.xkey.settings.BootstrapSettingsData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Client for fetching CA certificate bundles using secure bootstrap mechanisms.
 *
 * This client implements the same trust mechanisms as go-xkms's SDK bootstrap
 * service, supporting multiple verification methods in priority order:
 *
 * 1. **DANE**: DNS-based Authentication of Named Entities using TLSA records
 * 2. **Noise**: Noise_NK protocol with pre-shared server public key
 * 3. **SPKI**: SPKI-pinned TLS verification
 * 4. **Direct**: Standard HTTPS with system trust store
 *
 * Example usage:
 * ```kotlin
 * val settings = BootstrapSettingsData(
 *     autoBootstrap = true,
 *     noiseEnabled = true,
 *     noiseConfig = NoiseConfig(
 *         serverAddress = "kms.example.com:8445",
 *         serverStaticKey = "0102030405..." // 64 hex chars
 *     )
 * )
 * val client = BootstrapClient(settings)
 * val result = client.fetchCABundle()
 * println("Fetched ${result.certificates.size} certificates via ${result.method}")
 * ```
 *
 * @property settings The bootstrap configuration.
 * @property httpClient Optional custom OkHttpClient instance.
 */
class BootstrapClient(
    private val settings: BootstrapSettingsData,
    private val httpClient: OkHttpClient = defaultHttpClient(settings.timeoutSeconds)
) {
    companion object {
        private const val TAG = "BootstrapClient"
        private const val BOOTSTRAP_PATH = "/v1/ca/bootstrap"
        private const val PEM_CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
        private const val PEM_CERT_END = "-----END CERTIFICATE-----"
        private const val MAX_RESPONSE_SIZE = 1 * 1024 * 1024 // 1 MB
        private const val READ_CHUNK_SIZE = 8192
        private const val FRAME_HEADER_SIZE = 2
        private const val MAX_FRAME_SIZE = 65535
        private const val KEY_SIZE = 32
        private const val TAG_SIZE = 16

        /**
         * Upper bound on certificates accepted from a bootstrap bundle. A trust
         * bundle is a handful of anchors; anything larger is a hostile endpoint
         * trying to make the client parse certificates indefinitely.
         */
        internal const val MAX_BUNDLE_CERTIFICATES = 64

        private fun defaultHttpClient(timeoutSeconds: Int): OkHttpClient {
            return OkHttpClient.Builder()
                .connectTimeout(timeoutSeconds.toLong(), TimeUnit.SECONDS)
                .readTimeout(timeoutSeconds.toLong(), TimeUnit.SECONDS)
                .writeTimeout(timeoutSeconds.toLong(), TimeUnit.SECONDS)
                .build()
        }

        /**
         * Parses every PEM certificate block in [pemData]. Bundles declaring
         * more than [maxCertificates] blocks are rejected before any parsing
         * work is done; individual blocks that fail to decode are skipped, and
         * callers treat an empty result as a failure.
         */
        internal fun parsePemBundle(
            pemData: ByteArray,
            maxCertificates: Int = MAX_BUNDLE_CERTIFICATES
        ): List<X509Certificate> {
            val pemString = String(pemData, Charsets.UTF_8)
            val blocks = countPemBlocks(pemString)
            if (blocks > maxCertificates) {
                throw CertificateParseException(
                    "bundle contains $blocks certificates, limit is $maxCertificates"
                )
            }

            val certFactory = CertificateFactory.getInstance("X.509")
            val certificates = mutableListOf<X509Certificate>()
            var startIndex = 0
            while (true) {
                val beginIndex = pemString.indexOf(PEM_CERT_BEGIN, startIndex)
                if (beginIndex == -1) break

                val endIndex = pemString.indexOf(PEM_CERT_END, beginIndex)
                if (endIndex == -1) break

                val certPem = pemString.substring(beginIndex, endIndex + PEM_CERT_END.length)
                try {
                    certificates.add(
                        certFactory.generateCertificate(
                            ByteArrayInputStream(certPem.toByteArray(Charsets.UTF_8))
                        ) as X509Certificate
                    )
                } catch (_: Exception) {
                    // Undecodable block; the caller fails if nothing parses.
                }

                startIndex = endIndex + PEM_CERT_END.length
            }

            return certificates
        }

        private fun countPemBlocks(pem: String): Int {
            var count = 0
            var index = pem.indexOf(PEM_CERT_BEGIN)
            while (index >= 0) {
                count++
                index = pem.indexOf(PEM_CERT_BEGIN, index + PEM_CERT_BEGIN.length)
            }
            return count
        }
    }

    /**
     * Fetch CA bundle using auto-bootstrap mechanism.
     *
     * Tries each enabled bootstrap method in priority order (DANE, Noise, SPKI, Direct)
     * and returns the first successful result. If all methods fail, throws
     * [BootstrapFailedException] containing errors from all attempts.
     *
     * @return The CA bundle result from the first successful method.
     * @throws NoMethodsConfiguredException If no methods are enabled.
     * @throws BootstrapFailedException If all methods fail.
     */
    suspend fun fetchCABundle(): CABundleResult = withContext(Dispatchers.IO) {
        val enabledMethods = settings.getEnabledMethods()
        if (enabledMethods.isEmpty()) {
            throw NoMethodsConfiguredException()
        }

        val attempts = mutableListOf<MethodAttemptError>()

        for (method in enabledMethods) {
            try {
                Log.i(TAG, "Attempting bootstrap method: $method")
                val result = fetchWithMethod(method)
                Log.i(TAG, "Bootstrap succeeded with method: $method")
                return@withContext result
            } catch (e: Exception) {
                Log.w(TAG, "Bootstrap method $method failed: ${e.message}")
                attempts.add(MethodAttemptError(method, e))
            }
        }

        throw BootstrapFailedException(attempts)
    }

    /**
     * Fetch CA bundle using a specific bootstrap method.
     *
     * @param method The bootstrap method to use.
     * @return The CA bundle result.
     * @throws BootstrapException If the fetch fails.
     */
    suspend fun fetchWithMethod(method: BootstrapMethod): CABundleResult = withContext(Dispatchers.IO) {
        val timeoutMillis = settings.timeoutSeconds * 1000L

        withTimeout(timeoutMillis) {
            when (method) {
                BootstrapMethod.DANE -> fetchWithDANE()
                BootstrapMethod.NOISE -> fetchWithNoise()
                BootstrapMethod.SPKI -> fetchWithSPKI()
                BootstrapMethod.DIRECT -> fetchWithDirect()
            }
        }
    }

    /**
     * Fetch CA bundle using DANE/TLSA verification (RFC 6698/7671).
     *
     * Resolves TLSA records for `_<port>._tcp.<host>` against the configured
     * DNS server (optionally over DNS-over-TLS, optionally requiring the
     * DNSSEC AD flag) and fetches the bundle over TLS whose sole certificate
     * verification is DANE validation of the presented chain — the same
     * custom-verifier pattern and policy as go-xkms/go-truststrap
     * (`NewVerifiedTLSConfigFromRecords`): DANE-EE (usage 3) matches the leaf
     * with no name check; DANE-TA (usage 2) requires the anchor in the chain,
     * PKIX validation, and a hostname check.
     */
    private suspend fun fetchWithDANE(): CABundleResult = withContext(Dispatchers.IO) {
        val config = settings.daneConfig
        if (config.serverUrl.isBlank()) {
            throw DANEException("DANE server URL not configured")
        }

        val url = normalizeUrl(config.serverUrl) + BOOTSTRAP_PATH
        val parsedUrl = try {
            java.net.URL(if ("://" in url) url else "https://$url")
        } catch (e: Exception) {
            throw DANEException("Invalid DANE server URL: ${config.serverUrl}", e)
        }
        val host = parsedUrl.host
        val port = if (parsedUrl.port > 0) parsedUrl.port else 443

        val records = try {
            DnsTlsaResolver(
                dnsServer = config.dnsServer,
                dnsOverTls = config.dnsOverTls,
                requireDnssec = config.requireDnssec
            ).lookupTlsa(host, port)
        } catch (e: Exception) {
            throw DANEException("TLSA lookup failed for $host:$port", e)
        }
        Log.i(TAG, "DANE: resolved ${records.size} TLSA record(s) for _$port._tcp.$host")

        val daneClient = createDaneHttpClient(records, host)

        val request = Request.Builder()
            .url(url)
            .get()
            .build()

        val response = try {
            daneClient.newCall(request).execute()
        } catch (e: Exception) {
            throw DANEException("Network error fetching from $url", e)
        }

        response.use { resp ->
            if (!resp.isSuccessful) {
                throw DANEException("HTTP ${resp.code} from $url")
            }

            val body = readBoundedBody(resp) { DANEException("$it from $url") }

            val certificates = parsePEMCertificates(body)
            if (certificates.isEmpty()) {
                throw DANEException("No valid certificates in response")
            }

            CABundleResult(
                bundlePEM = body,
                certificates = certificates.map { it.encoded },
                method = BootstrapMethod.DANE
            )
        }
    }

    /**
     * Fetch CA bundle using Noise_NK protocol.
     *
     * Uses the Noise protocol with a pre-shared server public key for encrypted
     * CA bundle retrieval. The handshake pattern is Noise_NK:
     *   -> e (initiator sends ephemeral)
     *   <- e, ee (responder sends ephemeral, performs DH)
     */
    private suspend fun fetchWithNoise(): CABundleResult = withContext(Dispatchers.IO) {
        val config = settings.noiseConfig
        if (config.serverAddress.isBlank()) {
            throw NoiseBootstrapException("Noise server address not configured")
        }
        if (config.serverStaticKey.isBlank()) {
            throw NoiseBootstrapException("Noise server static key not configured")
        }

        val serverKey = try {
            hexToBytes(config.serverStaticKey)
        } catch (e: Exception) {
            throw NoiseBootstrapException("Invalid server static key: ${e.message}", e)
        }

        if (serverKey.size != KEY_SIZE) {
            throw NoiseBootstrapException(
                "Server static key must be $KEY_SIZE bytes, got ${serverKey.size}"
            )
        }

        // Parse host:port
        val parts = config.serverAddress.split(":")
        if (parts.size != 2) {
            throw NoiseBootstrapException("Invalid server address format: ${config.serverAddress}")
        }
        val host = parts[0]
        val port = parts[1].toIntOrNull()
            ?: throw NoiseBootstrapException("Invalid port: ${parts[1]}")

        // Create socket and perform Noise_NK handshake
        val socket = try {
            Socket(host, port).apply {
                soTimeout = settings.timeoutSeconds * 1000
            }
        } catch (e: Exception) {
            throw NoiseBootstrapException("Failed to connect to $host:$port", e)
        }

        try {
            val session = NoiseNKSession(serverKey)
            val dataIn = DataInputStream(socket.getInputStream())
            val dataOut = DataOutputStream(socket.getOutputStream())

            // NK Handshake: initiator sends (e)
            val msg1 = session.createHandshakeMessage1()
            writeFrame(dataOut, msg1)

            // Read server response (e, ee)
            val msg2 = readFrame(dataIn)
            session.processHandshakeMessage2(msg2)

            // Send CA bundle request
            val request = JSONObject().apply {
                put("method", "get_ca_bundle")
            }
            val encryptedRequest = session.encrypt(request.toString().toByteArray())
            writeFrame(dataOut, encryptedRequest)

            // Read response
            val encryptedResponse = readFrame(dataIn)
            val responseBytes = session.decrypt(encryptedResponse)
            val response = JSONObject(String(responseBytes))

            if (response.has("error") && response.getString("error").isNotEmpty()) {
                throw NoiseBootstrapException("Server error: ${response.getString("error")}")
            }

            val bundlePEM = response.optString("bundle_pem", "")
            val certsArray = response.optJSONArray("certificates")

            val derCerts = mutableListOf<ByteArray>()
            if (certsArray != null) {
                if (certsArray.length() > MAX_BUNDLE_CERTIFICATES) {
                    throw NoiseBootstrapException(
                        "Bundle contains ${certsArray.length()} certificates, " +
                            "limit is $MAX_BUNDLE_CERTIFICATES"
                    )
                }
                for (i in 0 until certsArray.length()) {
                    val certB64 = certsArray.getString(i)
                    try {
                        derCerts.add(Base64.getDecoder().decode(certB64))
                    } catch (e: Exception) {
                        Log.w(TAG, "Skipping malformed certificate at index $i")
                    }
                }
            }

            CABundleResult(
                bundlePEM = bundlePEM.toByteArray(),
                certificates = derCerts,
                method = BootstrapMethod.NOISE
            )
        } finally {
            socket.close()
        }
    }

    /**
     * Fetch CA bundle using SPKI-pinned TLS.
     *
     * Verifies the server certificate against a SHA-256 hash of its
     * Subject Public Key Info (SPKI).
     */
    private suspend fun fetchWithSPKI(): CABundleResult = withContext(Dispatchers.IO) {
        val config = settings.spkiConfig
        if (config.serverUrl.isBlank()) {
            throw SPKIException("", "SPKI server URL not configured")
        }
        if (config.spkiPinSha256.isBlank()) {
            throw SPKIException("", "SPKI pin not configured")
        }

        val expectedPin = config.spkiPinSha256.lowercase()
        if (expectedPin.length != 64) {
            throw BootstrapConfigException("SPKI pin must be 64 hex characters (SHA-256)")
        }

        val pinnedClient = createSPKIPinnedHttpClient(expectedPin)
        val url = normalizeUrl(config.serverUrl) + BOOTSTRAP_PATH

        val request = Request.Builder()
            .url(url)
            .get()
            .build()

        val response = try {
            pinnedClient.newCall(request).execute()
        } catch (e: SPKIException) {
            throw e
        } catch (e: Exception) {
            throw DirectException("SPKI fetch failed from $url", cause = e)
        }

        response.use { resp ->
            if (!resp.isSuccessful) {
                throw DirectException("HTTP error", resp.code)
            }

            val body = readBoundedBody(resp) { DirectException("$it from $url") }

            val certificates = parsePEMCertificates(body)
            if (certificates.isEmpty()) {
                throw CertificateParseException("No valid certificates in response")
            }

            CABundleResult(
                bundlePEM = body,
                certificates = certificates.map { it.encoded },
                method = BootstrapMethod.SPKI
            )
        }
    }

    /**
     * Fetch CA bundle using direct HTTPS with system trust store.
     *
     * This is the fallback method that uses standard HTTPS verification.
     */
    private suspend fun fetchWithDirect(): CABundleResult = withContext(Dispatchers.IO) {
        val config = settings.directConfig
        if (config.serverUrl.isBlank()) {
            throw DirectException("Direct server URL not configured")
        }

        val url = normalizeUrl(config.serverUrl) + BOOTSTRAP_PATH

        val request = Request.Builder()
            .url(url)
            .get()
            .build()

        val response = try {
            httpClient.newCall(request).execute()
        } catch (e: Exception) {
            throw DirectException("Network error fetching from $url", cause = e)
        }

        response.use { resp ->
            if (!resp.isSuccessful) {
                throw DirectException("Server returned error", resp.code)
            }

            val body = readBoundedBody(resp) { DirectException("$it from $url") }

            val certificates = parsePEMCertificates(body)
            if (certificates.isEmpty()) {
                throw CertificateParseException("No valid certificates in response")
            }

            CABundleResult(
                bundlePEM = body,
                certificates = certificates.map { it.encoded },
                method = BootstrapMethod.DIRECT
            )
        }
    }

    /**
     * Reads the response body, refusing to buffer more than [MAX_RESPONSE_SIZE]
     * bytes so a hostile bootstrap endpoint cannot exhaust memory. The limit is
     * applied to the decoded stream, which also bounds a compressed reply.
     * [onError] supplies the method-specific failure to raise.
     */
    private fun readBoundedBody(
        response: Response,
        onError: (String) -> BootstrapException
    ): ByteArray {
        val stream = response.body?.byteStream() ?: throw onError("Empty response body")
        val buffer = ByteArrayOutputStream()
        val chunk = ByteArray(READ_CHUNK_SIZE)
        stream.use { input ->
            while (true) {
                val read = input.read(chunk)
                if (read < 0) break
                if (buffer.size() + read > MAX_RESPONSE_SIZE) {
                    throw onError("Response too large: exceeds $MAX_RESPONSE_SIZE bytes")
                }
                buffer.write(chunk, 0, read)
            }
        }
        if (buffer.size() == 0) throw onError("Empty response body")
        return buffer.toByteArray()
    }

    /**
     * Parse PEM-encoded certificates from raw bytes, bounded by
     * [MAX_BUNDLE_CERTIFICATES].
     */
    private fun parsePEMCertificates(pemData: ByteArray): List<X509Certificate> {
        val certificates = parsePemBundle(pemData)
        val blocks = countPemBlocks(String(pemData, Charsets.UTF_8))
        if (certificates.size < blocks) {
            Log.w(TAG, "Skipped ${blocks - certificates.size} malformed certificate(s) in bundle")
        }
        return certificates
    }

    /**
     * Create an OkHttpClient whose sole certificate verification is DANE/TLSA
     * validation of the presented chain. WebPKI hostname verification is
     * disabled because [DaneVerifier] applies the RFC 7671 name-check rules
     * itself (none for DANE-EE, PKIX + hostname for DANE-TA) — the same
     * custom-verifier pattern go-truststrap uses.
     */
    private fun createDaneHttpClient(records: List<TlsaRecord>, hostname: String): OkHttpClient {
        val daneTrustManager = DaneVerifier.trustManager(records, hostname)
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(daneTrustManager), SecureRandom())
        return httpClient.newBuilder()
            .sslSocketFactory(sslContext.socketFactory, daneTrustManager)
            .hostnameVerifier { _, _ -> true }
            .build()
    }

    /**
     * Create an OkHttpClient that verifies SPKI pin.
     */
    private fun createSPKIPinnedHttpClient(expectedPin: String): OkHttpClient {
        val spkiTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) {
                    throw SPKIException(expectedPin)
                }

                for (cert in chain) {
                    val actualPin = computeSPKIPin(cert)
                    if (actualPin == expectedPin) {
                        return // Pin matched
                    }
                }

                val actualPin = if (chain.isNotEmpty()) computeSPKIPin(chain[0]) else null
                throw SPKIException(expectedPin, actualPin)
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(spkiTrustManager), SecureRandom())

        return httpClient.newBuilder()
            .sslSocketFactory(sslContext.socketFactory, spkiTrustManager)
            .build()
    }

    /**
     * Compute SHA-256 hash of certificate's SubjectPublicKeyInfo.
     */
    private fun computeSPKIPin(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(spki)
        return bytesToHex(hash)
    }

    /**
     * Normalize URL by removing trailing slash.
     */
    private fun normalizeUrl(url: String): String = url.trimEnd('/')

    /**
     * Write a length-prefixed frame to the output stream.
     */
    private fun writeFrame(out: DataOutputStream, data: ByteArray) {
        if (data.size > MAX_FRAME_SIZE) {
            throw NoiseBootstrapException("Frame too large: ${data.size} > $MAX_FRAME_SIZE")
        }
        out.writeShort(data.size)
        out.write(data)
        out.flush()
    }

    /**
     * Read a length-prefixed frame from the input stream.
     */
    private fun readFrame(input: DataInputStream): ByteArray {
        val length = input.readUnsignedShort()
        if (length > MAX_FRAME_SIZE) {
            throw NoiseBootstrapException("Frame too large: $length > $MAX_FRAME_SIZE")
        }
        val data = ByteArray(length)
        input.readFully(data)
        return data
    }

    /**
     * Convert hex string to byte array.
     */
    private fun hexToBytes(hex: String): ByteArray {
        val cleanHex = hex.replace(" ", "").lowercase()
        if (cleanHex.length % 2 != 0) {
            throw IllegalArgumentException("Hex string must have even length")
        }
        return ByteArray(cleanHex.length / 2) { i ->
            val index = i * 2
            cleanHex.substring(index, index + 2).toInt(16).toByte()
        }
    }

    /**
     * Convert byte array to hex string.
     */
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Noise_NK session for initiator (client) side.
     *
     * Implements the NK handshake pattern where the initiator knows
     * the responder's static public key beforehand:
     *   -> e (initiator sends ephemeral)
     *   <- e, ee (responder sends ephemeral, performs DH)
     */
    private inner class NoiseNKSession(private val serverStaticKey: ByteArray) {
        private val PROTOCOL_NAME = "Noise_NK_25519_ChaChaPoly_SHA256"

        private val secureRandom = SecureRandom()

        // Ephemeral keypair
        private var ephemeralPrivateKey: ByteArray = ByteArray(KEY_SIZE)
        private var ephemeralPublicKey: ByteArray = ByteArray(KEY_SIZE)

        // Symmetric state
        private var chainingKey: ByteArray = ByteArray(KEY_SIZE)
        private var handshakeHash: ByteArray = ByteArray(KEY_SIZE)
        private var encryptionKey: ByteArray? = null
        private var handshakeNonce: Long = 0

        // Transport keys
        private var sendKey: ByteArray? = null
        private var recvKey: ByteArray? = null
        private var sendNonce: Long = 0
        private var recvNonce: Long = 0

        init {
            initializeSymmetricState()
            generateEphemeralKey()
        }

        private fun initializeSymmetricState() {
            // h = SHA256(protocol_name) padded to 32 bytes
            val protocolBytes = PROTOCOL_NAME.toByteArray()
            if (protocolBytes.size <= KEY_SIZE) {
                handshakeHash = ByteArray(KEY_SIZE)
                System.arraycopy(protocolBytes, 0, handshakeHash, 0, protocolBytes.size)
            } else {
                handshakeHash = sha256(protocolBytes)
            }
            chainingKey = handshakeHash.copyOf()

            // MixHash(prologue) - empty prologue
            mixHash(ByteArray(0))

            // MixHash(server's static public key) - NK pattern pre-message
            mixHash(serverStaticKey)

            encryptionKey = ByteArray(KEY_SIZE)
            handshakeNonce = 0
        }

        private fun generateEphemeralKey() {
            ephemeralPrivateKey = ByteArray(KEY_SIZE).also { secureRandom.nextBytes(it) }
            // Clamp per X25519 spec
            ephemeralPrivateKey[0] = (ephemeralPrivateKey[0].toInt() and 248).toByte()
            ephemeralPrivateKey[31] = (ephemeralPrivateKey[31].toInt() and 127).toByte()
            ephemeralPrivateKey[31] = (ephemeralPrivateKey[31].toInt() or 64).toByte()
            ephemeralPublicKey = x25519ScalarMultBase(ephemeralPrivateKey)
        }

        /**
         * Create first handshake message: -> e, es
         */
        fun createHandshakeMessage1(): ByteArray {
            // Send ephemeral public key
            mixHash(ephemeralPublicKey)

            // es - DH(e, rs)
            val esSecret = x25519(ephemeralPrivateKey, serverStaticKey)
            mixKey(esSecret)

            return ephemeralPublicKey.copyOf()
        }

        /**
         * Process second handshake message: <- e, ee
         */
        fun processHandshakeMessage2(message: ByteArray) {
            if (message.size < KEY_SIZE) {
                throw NoiseBootstrapException("Message too short: ${message.size}")
            }

            // Extract server ephemeral key
            val serverEphemeralKey = message.copyOfRange(0, KEY_SIZE)
            mixHash(serverEphemeralKey)

            // ee - DH(e, re)
            val eeSecret = x25519(ephemeralPrivateKey, serverEphemeralKey)
            mixKey(eeSecret)

            // Decrypt empty payload if present (may have auth tag)
            if (message.size > KEY_SIZE) {
                val encryptedPayload = message.copyOfRange(KEY_SIZE, message.size)
                decryptAndHash(encryptedPayload)
            }

            // Split into transport keys
            splitSymmetricState()
        }

        fun encrypt(plaintext: ByteArray): ByteArray {
            val key = sendKey ?: throw NoiseBootstrapException("Session not established")
            val nonce = createNonce(sendNonce++)
            return chacha20Poly1305Encrypt(key, nonce, plaintext, ByteArray(0))
        }

        fun decrypt(ciphertext: ByteArray): ByteArray {
            val key = recvKey ?: throw NoiseBootstrapException("Session not established")
            val nonce = createNonce(recvNonce++)
            return chacha20Poly1305Decrypt(key, nonce, ciphertext, ByteArray(0))
        }

        private fun mixHash(data: ByteArray) {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(handshakeHash)
            digest.update(data)
            handshakeHash = digest.digest()
        }

        private fun mixKey(inputKeyMaterial: ByteArray) {
            val (ck, k) = hkdf2(chainingKey, inputKeyMaterial)
            chainingKey = ck
            encryptionKey = k
            handshakeNonce = 0
        }

        private fun decryptAndHash(ciphertext: ByteArray): ByteArray {
            val nonce = createNonce(handshakeNonce)
            val key = encryptionKey ?: throw NoiseBootstrapException("No encryption key")
            val plaintext = chacha20Poly1305Decrypt(key, nonce, ciphertext, handshakeHash)
            mixHash(ciphertext)
            handshakeNonce++
            return plaintext
        }

        private fun splitSymmetricState() {
            val (k1, k2) = hkdf2(chainingKey, ByteArray(0))
            // Initiator: k1 for sending, k2 for receiving
            sendKey = k1
            recvKey = k2
            sendNonce = 0
            recvNonce = 0
        }

        private fun sha256(data: ByteArray): ByteArray {
            return MessageDigest.getInstance("SHA-256").digest(data)
        }

        private fun hkdf2(salt: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            val prk = mac.doFinal(ikm)

            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(byteArrayOf(0x01))
            val t1 = mac.doFinal()

            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t1)
            mac.update(byteArrayOf(0x02))
            val t2 = mac.doFinal()

            return Pair(t1, t2)
        }

        private fun createNonce(n: Long): ByteArray {
            return ByteBuffer.allocate(12)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(0)
                .putLong(n)
                .array()
        }

        private fun x25519ScalarMultBase(scalar: ByteArray): ByteArray {
            val basePoint = ByteArray(32)
            basePoint[0] = 9
            return x25519ScalarMultPure(scalar, basePoint)
        }

        private fun x25519(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
            return try {
                val privKeySpec = java.security.spec.PKCS8EncodedKeySpec(wrapX25519PrivateKey(privateKey))
                val pubKeySpec = java.security.spec.X509EncodedKeySpec(wrapX25519PublicKey(publicKey))

                val keyFactory = java.security.KeyFactory.getInstance("X25519")
                val privKey = keyFactory.generatePrivate(privKeySpec)
                val pubKey = keyFactory.generatePublic(pubKeySpec)

                val keyAgreement = javax.crypto.KeyAgreement.getInstance("X25519")
                keyAgreement.init(privKey)
                keyAgreement.doPhase(pubKey, true)
                keyAgreement.generateSecret()
            } catch (e: Exception) {
                x25519ScalarMultPure(privateKey, publicKey)
            }
        }

        private fun x25519ScalarMultPure(k: ByteArray, u: ByteArray): ByteArray {
            val p = java.math.BigInteger.ONE.shiftLeft(255).subtract(java.math.BigInteger.valueOf(19))

            val kClamped = k.copyOf()
            kClamped[0] = (kClamped[0].toInt() and 248).toByte()
            kClamped[31] = (kClamped[31].toInt() and 127).toByte()
            kClamped[31] = (kClamped[31].toInt() or 64).toByte()

            val uInt = decodeLittleEndian(u).mod(p)

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

            val result = fx2.multiply(fz2.modPow(p.subtract(java.math.BigInteger.valueOf(2)), p)).mod(p)
            return encodeLittleEndian(result)
        }

        private fun decodeLittleEndian(b: ByteArray): java.math.BigInteger {
            return java.math.BigInteger(1, b.reversedArray())
        }

        private fun encodeLittleEndian(n: java.math.BigInteger): ByteArray {
            var bytes = n.toByteArray()
            if (bytes.size > 32 && bytes[0] == 0.toByte()) {
                bytes = bytes.copyOfRange(1, bytes.size)
            }
            val result = ByteArray(32)
            val offset = 32 - bytes.size
            System.arraycopy(bytes, 0, result, offset, bytes.size)
            return result.reversedArray()
        }

        private fun cswap(
            swap: java.math.BigInteger,
            a: java.math.BigInteger,
            b: java.math.BigInteger
        ): Pair<java.math.BigInteger, java.math.BigInteger> {
            return if (swap == java.math.BigInteger.ONE) Pair(b, a) else Pair(a, b)
        }

        private fun wrapX25519PrivateKey(raw: ByteArray): ByteArray {
            val header = byteArrayOf(
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
                0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
            )
            return header + raw
        }

        private fun wrapX25519PublicKey(raw: ByteArray): ByteArray {
            val header = byteArrayOf(
                0x30, 0x2a, 0x30, 0x05,
                0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
            )
            return header + raw
        }

        private fun chacha20Poly1305Encrypt(
            key: ByteArray,
            nonce: ByteArray,
            plaintext: ByteArray,
            aad: ByteArray
        ): ByteArray {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            val keySpec = SecretKeySpec(key, "ChaCha20")
            val ivSpec = IvParameterSpec(nonce)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
            cipher.updateAAD(aad)
            return cipher.doFinal(plaintext)
        }

        private fun chacha20Poly1305Decrypt(
            key: ByteArray,
            nonce: ByteArray,
            ciphertext: ByteArray,
            aad: ByteArray
        ): ByteArray {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            val keySpec = SecretKeySpec(key, "ChaCha20")
            val ivSpec = IvParameterSpec(nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            cipher.updateAAD(aad)
            return cipher.doFinal(ciphertext)
        }
    }
}
