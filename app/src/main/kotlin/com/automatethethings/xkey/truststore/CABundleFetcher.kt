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
package com.automatethethings.xkey.truststore

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

/**
 * Result of fetching a CA bundle from a remote server.
 *
 * @property pemBundle The raw PEM-encoded certificate chain bytes
 * @property certificates The parsed X509 certificates from the bundle
 * @property cacheControl The Cache-Control header value from the response, if present
 */
data class CABundleResult(
    val pemBundle: ByteArray,
    val certificates: List<X509Certificate>,
    val cacheControl: String?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CABundleResult) return false
        return pemBundle.contentEquals(other.pemBundle) &&
                certificates == other.certificates &&
                cacheControl == other.cacheControl
    }

    override fun hashCode(): Int {
        var result = pemBundle.contentHashCode()
        result = 31 * result + certificates.hashCode()
        result = 31 * result + (cacheControl?.hashCode() ?: 0)
        return result
    }
}

/**
 * Exception thrown when CA bundle fetching fails.
 *
 * @property message Description of the failure
 * @property cause The underlying exception that caused this failure, if any
 */
class CABundleFetchException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Fetches CA certificate bundles from remote servers.
 *
 * This class provides functionality to retrieve PEM-encoded certificate chains
 * from CA servers compatible with go-xkms and go-trusted-ca endpoints.
 *
 * Compatible endpoints:
 * - go-xkms: GET /acme/ca-bundle or GET /v1/ca/bundle
 * - go-trusted-ca: GET /acme/ca-bundle
 *
 * The endpoints return PEM-encoded certificate chains with
 * Content-Type: application/pem-certificate-chain
 *
 * Limits, the same as `BootstrapClient` applies to `/v1/ca/bootstrap`:
 * - the response body is read up to [MAX_RESPONSE_SIZE] (1 MB), counted on
 *   the decoded stream so a compressed reply is bounded too;
 * - a bundle with more than [MAX_BUNDLE_CERTIFICATES] (64) certificate
 *   blocks is refused before any block is parsed.
 * Either failure raises [CABundleFetchException].
 *
 * Example usage:
 * ```kotlin
 * val fetcher = CABundleFetcher()
 * val result = fetcher.fetchBundle("https://ca.example.com")
 * result.certificates.forEach { cert ->
 *     println("Subject: ${cert.subjectDN}")
 * }
 * ```
 *
 * @property httpClient The OkHttpClient instance used for HTTP requests
 */
class CABundleFetcher(
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .build()
) {
    companion object {
        private const val TAG = "CABundleFetcher"
        private const val EXPECTED_CONTENT_TYPE = "application/pem-certificate-chain"
        private const val ENDPOINT_PATH = "/acme/ca-bundle"
        private const val PEM_CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
        private const val PEM_CERT_END = "-----END CERTIFICATE-----"
        private const val DEFAULT_TIMEOUT_SECONDS = 30L
        private const val READ_CHUNK_SIZE = 8192

        // Same limits as BootstrapClient.MAX_RESPONSE_SIZE and
        // BootstrapClient.MAX_BUNDLE_CERTIFICATES: both endpoints serve a
        // trust bundle and get the same bounds.

        /** Largest decoded response body accepted, in bytes. */
        internal const val MAX_RESPONSE_SIZE = 1 * 1024 * 1024 // 1 MB

        /** Most certificate blocks accepted in one bundle. */
        internal const val MAX_BUNDLE_CERTIFICATES = 64
    }

    /**
     * Fetch CA bundle from the specified URL.
     *
     * This method performs a GET request to the CA bundle endpoint and parses
     * the returned PEM-encoded certificate chain into X509Certificate objects.
     *
     * @param baseUrl The base URL of the CA server (e.g., "https://ca.example.com")
     * @return CABundleResult containing the PEM bundle and parsed certificates
     * @throws CABundleFetchException if the fetch fails, response is invalid,
     *         or no valid certificates are found in the response
     */
    suspend fun fetchBundle(baseUrl: String): CABundleResult = withContext(Dispatchers.IO) {
        val url = normalizeUrl(baseUrl) + ENDPOINT_PATH

        val request = Request.Builder()
            .url(url)
            .get()
            .header("Accept", EXPECTED_CONTENT_TYPE)
            .build()

        val response = try {
            httpClient.newCall(request).execute()
        } catch (e: Exception) {
            throw CABundleFetchException("Network error fetching CA bundle from $url", e)
        }

        response.use { resp ->
            if (!resp.isSuccessful) {
                throw CABundleFetchException(
                    "Failed to fetch CA bundle: HTTP ${resp.code} from $url"
                )
            }

            val contentType = resp.header("Content-Type")
            if (contentType != null && !contentType.startsWith(EXPECTED_CONTENT_TYPE)) {
                Log.w(TAG, "Unexpected Content-Type: $contentType (expected $EXPECTED_CONTENT_TYPE)")
            }

            val pemBundle = readBoundedBody(resp, url)

            val certificates = parsePEMBundle(pemBundle)
            if (certificates.isEmpty()) {
                throw CABundleFetchException("No valid certificates found in response from $url")
            }

            CABundleResult(
                pemBundle = pemBundle,
                certificates = certificates,
                cacheControl = resp.header("Cache-Control")
            )
        }
    }

    /**
     * Parse PEM-encoded certificate bundle into X509Certificate list.
     *
     * This method extracts individual certificates from a PEM bundle and
     * parses them into X509Certificate objects. Malformed certificates
     * are logged and skipped. A bundle declaring more than
     * [MAX_BUNDLE_CERTIFICATES] blocks is refused before any is parsed.
     *
     * @param pemData The raw PEM-encoded certificate chain bytes
     * @return List of parsed X509Certificate objects
     * @throws CABundleFetchException if the bundle has too many certificate blocks
     */
    private fun parsePEMBundle(pemData: ByteArray): List<X509Certificate> {
        val pemString = String(pemData, Charsets.UTF_8)
        val blocks = countPemBlocks(pemString)
        if (blocks > MAX_BUNDLE_CERTIFICATES) {
            throw CABundleFetchException(
                "CA bundle contains $blocks certificates, limit is $MAX_BUNDLE_CERTIFICATES"
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
                val cert = certFactory.generateCertificate(
                    ByteArrayInputStream(certPem.toByteArray(Charsets.UTF_8))
                ) as X509Certificate
                certificates.add(cert)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse certificate: ${e.message}")
            }

            startIndex = endIndex + PEM_CERT_END.length
        }

        return certificates
    }

    /**
     * Reads the response body, refusing to buffer more than [MAX_RESPONSE_SIZE]
     * bytes so a hostile endpoint cannot exhaust memory. The limit is applied
     * to the decoded stream, which also bounds a compressed reply.
     *
     * @throws CABundleFetchException if the body is empty or too large
     */
    private fun readBoundedBody(response: Response, url: String): ByteArray {
        val stream = response.body?.byteStream()
            ?: throw CABundleFetchException("Empty response body from $url")
        val buffer = ByteArrayOutputStream()
        val chunk = ByteArray(READ_CHUNK_SIZE)
        stream.use { input ->
            while (true) {
                val read = input.read(chunk)
                if (read < 0) break
                if (buffer.size() + read > MAX_RESPONSE_SIZE) {
                    throw CABundleFetchException(
                        "CA bundle response too large: exceeds $MAX_RESPONSE_SIZE bytes from $url"
                    )
                }
                buffer.write(chunk, 0, read)
            }
        }
        if (buffer.size() == 0) throw CABundleFetchException("Empty response body from $url")
        return buffer.toByteArray()
    }

    /** Counts the PEM certificate blocks in [pem] without parsing them. */
    private fun countPemBlocks(pem: String): Int {
        var count = 0
        var index = pem.indexOf(PEM_CERT_BEGIN)
        while (index >= 0) {
            count++
            index = pem.indexOf(PEM_CERT_BEGIN, index + PEM_CERT_BEGIN.length)
        }
        return count
    }

    /**
     * Normalize URL by removing trailing slash.
     *
     * @param url The URL to normalize
     * @return The normalized URL without trailing slash
     */
    private fun normalizeUrl(url: String): String {
        return url.trimEnd('/')
    }
}
