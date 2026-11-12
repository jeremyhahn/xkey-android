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

import android.content.Context
import com.automatethethings.xkey.audit.AuditLogger
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Represents a trusted CA certificate stored in the trust store.
 */
public data class TrustedCA(
    val fingerprint: String,
    val subjectDN: String,
    val issuerDN: String,
    val notBefore: Long,
    val notAfter: Long,
    val label: String?,
    val importedAt: Long,
    val source: String,
    val systemInstalled: Boolean = false
)

/**
 * Result of certificate chain verification.
 */
public sealed class VerificationResult {
    public data class Valid(val trustLevel: String) : VerificationResult()
    public data class Invalid(val error: String) : VerificationResult()
    public data object SelfSigned : VerificationResult()
    public data object NoTrustAnchors : VerificationResult()
}

/**
 * Result of importing certificates.
 */
public data class ImportResult(
    val imported: Int,
    val skipped: Int,
    val errors: List<String>
)

/**
 * Result of [TrustStoreRepository.clearAll]: the fingerprints actually
 * removed, those whose file or metadata row could not be removed (still
 * trusted), and whether the store directory could not be listed for files
 * no metadata row names.
 */
public data class ClearResult(
    val removed: List<String>,
    val failed: List<String>,
    val unlisted: Boolean = false
) {
    val complete: Boolean get() = failed.isEmpty() && !unlisted
}

/**
 * Repository for managing trusted CA certificates.
 *
 * Certificates are stored in the app's private directory and used
 * to verify IDevID certificate chains from paired devices.
 *
 * IMPORTANT: Self-signed certificates are NEVER accepted.
 */
public class TrustStoreRepository(
    private val context: Context,
    private val caFetcher: CABundleFetcher = CABundleFetcher(),
    /** Deletes one file; tests inject a deleter that refuses. */
    private val fileDeleter: (File) -> Boolean = { it.delete() },
    /** Writes text to one file; tests inject a writer that fails part-way. */
    private val fileWriter: (File, String) -> Unit = { file, text -> file.writeText(text) }
) {
    private val trustStoreDir: File by lazy {
        context.getDir("trust_store", Context.MODE_PRIVATE)
    }

    private val storeLock: Any by lazy { lockFor(trustStoreDir) }

    /**
     * Run [block], which reads, modifies or writes the trust store, as the
     * only writer of this directory in the process. [block] must not suspend.
     */
    private inline fun <T> withStoreLock(block: () -> T): T = synchronized(storeLock, block)

    private val certFactory: CertificateFactory by lazy {
        CertificateFactory.getInstance("X.509")
    }

    /**
     * Import CA bundle from a URL.
     *
     * @param url The URL to fetch the CA bundle from
     * @param label Optional label for the imported certificates
     * @return ImportResult with counts of imported/skipped certificates
     */
    public suspend fun importFromURL(url: String, label: String? = null): ImportResult =
        withContext(Dispatchers.IO) {
            val bundle = caFetcher.fetchBundle(url)
            val source = "url:${redactedUrl(url)}"
            var imported = 0
            var skipped = 0
            val errors = mutableListOf<String>()

            for (cert in bundle.certificates) {
                if (isSelfSigned(cert)) {
                    errors.add("Skipped self-signed certificate: ${cert.subjectX500Principal}")
                    skipped++
                    continue
                }

                try {
                    if (storeIfAbsent(cert, label, source) != null) {
                        imported++
                    } else {
                        skipped++
                    }
                } catch (e: Exception) {
                    errors.add("Failed to store certificate: ${e.message}")
                }
            }

            ImportResult(imported, skipped, errors)
        }

    /**
     * Import a single DER-encoded certificate.
     *
     * @param certDER The DER-encoded certificate bytes
     * @param label Optional label for the certificate
     * @return The TrustedCA entry if successful, null if rejected
     * @throws IllegalArgumentException if certificate is self-signed
     */
    public suspend fun importCertificate(certDER: ByteArray, label: String? = null): TrustedCA? =
        withContext(Dispatchers.IO) {
            val cert = certFactory.generateCertificate(
                ByteArrayInputStream(certDER)
            ) as X509Certificate

            if (isSelfSigned(cert)) {
                throw IllegalArgumentException("Self-signed certificates are not accepted")
            }

            storeIfAbsent(cert, label, "manual")
        }

    /**
     * Verify an IDevID certificate chain.
     *
     * @param chain List of DER-encoded certificates (leaf first, root last)
     * @return VerificationResult indicating validity
     */
    public suspend fun verifyIDevIDChain(chain: List<ByteArray>): VerificationResult =
        withContext(Dispatchers.IO) {
            if (chain.isEmpty()) {
                return@withContext VerificationResult.Invalid("Empty certificate chain")
            }

            val certs = chain.map { certDER ->
                certFactory.generateCertificate(
                    ByteArrayInputStream(certDER)
                ) as X509Certificate
            }

            val leafCert = certs.first()
            if (isSelfSigned(leafCert)) {
                return@withContext VerificationResult.SelfSigned
            }

            val trustedCAs = getAllCertificates()
            if (trustedCAs.isEmpty()) {
                return@withContext VerificationResult.NoTrustAnchors
            }

            val trustAnchors = trustedCAs.mapNotNull { trustedCA ->
                try {
                    val certFile = getCertificateFile(trustedCA.fingerprint)
                    val cert = certFactory.generateCertificate(
                        certFile.inputStream()
                    ) as X509Certificate
                    TrustAnchor(cert, null)
                } catch (e: Exception) {
                    null
                }
            }.toSet()

            if (trustAnchors.isEmpty()) {
                return@withContext VerificationResult.NoTrustAnchors
            }

            try {
                val pkixParams = PKIXParameters(trustAnchors).apply {
                    isRevocationEnabled = false
                }

                val certPath = certFactory.generateCertPath(certs)
                CertPathValidator.getInstance("PKIX").validate(certPath, pkixParams)

                VerificationResult.Valid(determineTrustLevel(certs))
            } catch (e: Exception) {
                VerificationResult.Invalid(e.message ?: "Certificate chain validation failed")
            }
        }

    /**
     * Get all stored trusted CA certificates.
     */
    public suspend fun getAllCertificates(): List<TrustedCA> = withContext(Dispatchers.IO) {
        readMetadataSync()
    }

    /**
     * Reads the metadata on the calling thread, for the synchronous write paths.
     * They cannot call [getAllCertificates]: blocking on a nested IO dispatch
     * from a thread that is already on the IO dispatcher is a deadlock shape.
     */
    private fun readMetadataSync(): List<TrustedCA> {
        val metadataFile = File(trustStoreDir, "metadata.json")
        if (!metadataFile.exists()) return emptyList()
        return try {
            parseMetadata(metadataFile.readText())
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Get a certificate by fingerprint.
     *
     * @param fingerprint The SHA-256 fingerprint of the certificate
     * @return The TrustedCA if found, null otherwise
     */
    public suspend fun getCertificate(fingerprint: String): TrustedCA? =
        getAllCertificates().find { it.fingerprint == fingerprint }

    /**
     * Get the raw DER-encoded certificate bytes by fingerprint.
     *
     * @param fingerprint The SHA-256 fingerprint of the certificate
     * @return The DER-encoded certificate bytes, null if not found
     */
    public suspend fun getCertificateDER(fingerprint: String): ByteArray? =
        withContext(Dispatchers.IO) {
            val certFile = getCertificateFile(fingerprint)
            if (certFile.exists()) {
                certFile.readBytes()
            } else {
                null
            }
        }

    /**
     * Delete a certificate from the trust store.
     *
     * Records a successful deletion only when the certificate's file and
     * metadata row are both gone; a removal that fails is recorded as a
     * failure and leaves the certificate trusted.
     *
     * @param fingerprint The SHA-256 fingerprint of the certificate to delete
     * @return true if deleted, false if not found or it could not be removed
     */
    public suspend fun deleteCertificate(fingerprint: String): Boolean =
        withContext(Dispatchers.IO) { withStoreLock { deleteCertificateLocked(fingerprint) } }

    private fun deleteCertificateLocked(fingerprint: String): Boolean {
        val certFile = getCertificateFile(fingerprint)
        val all = readMetadataSync()
        val entry = all.firstOrNull { it.fingerprint == fingerprint }
        val fileExisted = certFile.exists()

        // The DER file may already be gone while the metadata row survives.
        // Returning early there would strand the row: it stays listed
        // forever and only clearAll() can remove it.
        if (!fileExisted && entry == null) {
            return false
        }
        val subject = entry?.subjectDN ?: ""

        if (fileExisted && !removeFile(certFile)) {
            auditDelete(subject, fingerprint, FILE_NOT_DELETED)
            return false
        }
        if (entry != null) {
            try {
                saveMetadataSync(all.filter { it.fingerprint != fingerprint })
            } catch (e: IOException) {
                auditDelete(subject, fingerprint, "$METADATA_NOT_UPDATED: ${e.message}")
                return false
            }
        }
        auditDelete(subject, fingerprint)
        return true
    }

    /**
     * Clear all certificates from the trust store.
     *
     * Each certificate in the metadata is removed on its own. A deletion
     * is recorded as successful only when the certificate's file and its
     * metadata row are both gone; one that could not be removed stays
     * listed and trusted, is recorded as a failure, and is returned in
     * [ClearResult.failed].
     */
    public suspend fun clearAll(): ClearResult =
        withContext(Dispatchers.IO) { withStoreLock { clearAllLocked() } }

    private fun clearAllLocked(): ClearResult {
        val entries = readMetadataSync()
        val filesRemoved = entries.filter { removeFile(getCertificateFile(it.fingerprint)) }
        val kept = entries.filter { it !in filesRemoved }

        val metadataFile = File(trustStoreDir, "metadata.json")
        val metadataError: String? = try {
            if (kept.isNotEmpty()) {
                saveMetadataSync(kept)
            } else if (metadataFile.exists() && !removeFile(metadataFile)) {
                saveMetadataSync(emptyList())
            }
            null
        } catch (e: IOException) {
            "$METADATA_NOT_UPDATED: ${e.message}"
        }

        // Files no metadata row names (strays): remove them too, except the
        // ones kept above. A directory that cannot be listed is a failure.
        val keepNames = kept.map { getCertificateFile(it.fingerprint).name }.toSet() + metadataFile.name
        val listing = trustStoreDir.listFiles()
        val (strays, strayLeft) = listing.orEmpty()
            .filter { it.name !in keepNames }
            .partition { removeFile(it) }
        // A removed certificate file is a removed certificate even when its
        // metadata row was lost: audit it, with no subject to name.
        val strayRemoved = strays.filter { it.name.endsWith(".der") }.map { it.name.removeSuffix(".der") }
        val strayFailed = strayLeft.map { it.name.removeSuffix(".der") }

        val removed = if (metadataError == null) filesRemoved else emptyList()
        filesRemoved.forEach {
            if (metadataError == null) {
                auditDelete(it.subjectDN, it.fingerprint)
            } else {
                auditDelete(it.subjectDN, it.fingerprint, metadataError)
            }
        }
        kept.forEach { auditDelete(it.subjectDN, it.fingerprint, FILE_NOT_DELETED) }
        strayRemoved.forEach { auditDelete("", it) }
        strayFailed.forEach { auditDelete("", it, FILE_NOT_DELETED) }

        return ClearResult(
            removed = removed.map { it.fingerprint } + strayRemoved,
            failed = (entries - removed.toSet()).map { it.fingerprint } + strayFailed,
            unlisted = listing == null
        )
    }

    /**
     * Get the total count of stored certificates.
     */
    public suspend fun getCertificateCount(): Int = getAllCertificates().size

    /**
     * Check if a certificate with the given fingerprint exists.
     *
     * @param fingerprint The SHA-256 fingerprint to check
     * @return true if the certificate exists
     */
    public suspend fun hasCertificate(fingerprint: String): Boolean =
        withContext(Dispatchers.IO) {
            getCertificateFile(fingerprint).exists()
        }

    /**
     * Search certificates by subject DN pattern.
     *
     * @param pattern Substring to search for in subject DN (case-insensitive)
     * @return List of matching TrustedCA entries
     */
    public suspend fun searchBySubject(pattern: String): List<TrustedCA> =
        getAllCertificates().filter {
            it.subjectDN.contains(pattern, ignoreCase = true)
        }

    /**
     * Get certificates that are expiring within the specified days.
     *
     * @param days Number of days to check for expiration
     * @return List of certificates expiring within the timeframe
     */
    public suspend fun getExpiringCertificates(days: Int): List<TrustedCA> {
        val threshold = System.currentTimeMillis() + (days.toLong() * 24 * 60 * 60 * 1000)
        return getAllCertificates().filter { it.notAfter <= threshold }
    }

    /**
     * Get expired certificates.
     *
     * @return List of expired certificates
     */
    public suspend fun getExpiredCertificates(): List<TrustedCA> {
        val now = System.currentTimeMillis()
        return getAllCertificates().filter { it.notAfter < now }
    }

    /**
     * Import an internal CA certificate (e.g., AndroidCA root or intermediate).
     *
     * Unlike [importCertificate], this method accepts self-signed certificates
     * (root CAs are self-signed by definition) and tags the source as "internal-ca".
     * Idempotent: returns existing fingerprint if already imported.
     *
     * @param cert The X509Certificate to import
     * @param label Label for the certificate
     * @return The fingerprint of the imported or existing certificate
     */
    public suspend fun importInternalCACertificate(
        cert: X509Certificate,
        label: String
    ): String = withContext(Dispatchers.IO) {
        storeIfAbsent(cert, label, "internal-ca")
        computeFingerprint(cert)
    }

    /**
     * Refresh the system install status for all trust store certificates.
     *
     * Enumerates the Android system + user trusted CA store and compares
     * SHA-256 fingerprints against our trust store entries, updating the
     * [TrustedCA.systemInstalled] field accordingly.
     */
    public suspend fun refreshSystemInstallStatus(): Unit = withContext(Dispatchers.IO) {
        val systemFingerprints = mutableSetOf<String>()
        try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            val aliases = ks.aliases()
            val digest = MessageDigest.getInstance("SHA-256")
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                try {
                    val cert = ks.getCertificate(alias) as? X509Certificate ?: continue
                    val hash = digest.digest(cert.encoded)
                    systemFingerprints.add(hash.joinToString("") { "%02x".format(it) })
                } catch (_: Exception) {
                    // Skip unreadable entries
                }
            }
        } catch (_: Exception) {
            // AndroidCAStore not available on this device
            return@withContext
        }

        withStoreLock {
            val certs = readMetadataSync()
            val updated = certs.map { cert ->
                val isInstalled = systemFingerprints.contains(cert.fingerprint)
                if (cert.systemInstalled != isInstalled) {
                    cert.copy(systemInstalled = isInstalled)
                } else {
                    cert
                }
            }
            if (updated != certs) {
                saveMetadataSync(updated)
            }
        }
    }

    /**
     * Update the system install status for a single certificate.
     *
     * @param fingerprint The SHA-256 fingerprint of the certificate
     * @param installed Whether the cert is installed in the Android system store
     */
    public suspend fun updateSystemInstalled(
        fingerprint: String,
        installed: Boolean
    ): Unit = withContext(Dispatchers.IO) {
        withStoreLock {
            val updated = readMetadataSync().map { cert ->
                if (cert.fingerprint == fingerprint) {
                    cert.copy(systemInstalled = installed)
                } else {
                    cert
                }
            }
            saveMetadataSync(updated)
        }
    }

    private fun isSelfSigned(cert: X509Certificate): Boolean {
        return cert.subjectX500Principal == cert.issuerX500Principal
    }

    private fun computeFingerprint(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(cert.encoded)
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun getCertificateFile(fingerprint: String): File {
        return File(trustStoreDir, "$fingerprint.der")
    }

/**
     * Store [cert] unless its file is already present, deciding and writing
     * under the store lock so two imports of one certificate store it once.
     *
     * @return the stored entry, or null if the certificate was already present
     */
    private fun storeIfAbsent(cert: X509Certificate, label: String?, source: String): TrustedCA? =
        withStoreLock {
            if (getCertificateFile(computeFingerprint(cert)).exists()) {
                null
            } else {
                storeCertificate(cert, label, source)
            }
        }

    private fun storeCertificate(
        cert: X509Certificate,
        label: String?,
        source: String
    ): TrustedCA {
        val fingerprint = computeFingerprint(cert)
        val certFile = getCertificateFile(fingerprint)
        certFile.writeBytes(cert.encoded)

        val trustedCA = TrustedCA(
            fingerprint = fingerprint,
            subjectDN = cert.subjectX500Principal.name,
            issuerDN = cert.issuerX500Principal.name,
            notBefore = cert.notBefore.time,
            notAfter = cert.notAfter.time,
            label = label,
            importedAt = System.currentTimeMillis(),
            source = source,
            systemInstalled = false
        )

        val existing = readMetadataSync()
        val updated = existing.filter { it.fingerprint != fingerprint } + trustedCA
        saveMetadataSync(updated)

        if (AuditLogger.isInitialized()) {
            AuditLogger.logTrustStoreImport(trustedCA.subjectDN, fingerprint, source)
        }

        return trustedCA
    }

    /**
     * Record a trust store deletion: a success when [error] is null, else a
     * failure carrying it. Only when the audit logger is initialized: its
     * drop path calls `Log.w`, which callers that never initialize it (JVM
     * tests, sync) must not reach.
     */
    private fun auditDelete(subject: String, fingerprint: String, error: String? = null) {
        if (AuditLogger.isInitialized()) {
            AuditLogger.logTrustStoreDelete(subject, fingerprint, error == null, error)
        }
    }

    /** Delete [file] through [fileDeleter]; true only if it is gone. */
    private fun removeFile(file: File): Boolean {
        fileDeleter(file)
        return !file.exists()
    }

    private companion object {
        const val FILE_NOT_DELETED = "could not delete the certificate file"
        const val METADATA_NOT_UPDATED = "could not update the trust store metadata"

        /**
         * One lock per trust store directory, shared by every repository
         * instance in the process: SyncEngine and the screens each create
         * their own, and their metadata read/modify/writes must not interleave.
         */
        private val storeLocks = ConcurrentHashMap<String, Any>()

        fun lockFor(dir: File): Any = storeLocks.computeIfAbsent(dir.canonicalPath) { Any() }

        const val UNPARSEABLE_URL = "[unparseable url]"
        const val ILLEGAL_URI_CHARS = " \"<>\\^`{|}"

        /**
         * The import source recorded for [url]: scheme, host, port and path
         * only. Userinfo, the query and the fragment can carry credentials
         * (basic auth, signed-URL tokens), and the source is stored in the
         * metadata and in audit details that the audit log exports, so they
         * are dropped. Characters a URI never allows (quotes, spaces, braces)
         * are percent-encoded before parsing and the path is recorded decoded.
         * A URL that still does not parse as a hierarchical URL with a
         * server-based authority is recorded without its text.
         */
        fun redactedUrl(url: String): String {
            val escaped = buildString {
                url.trim().forEach { c ->
                    if (c < ' ' || c == '\u007f' || c in ILLEGAL_URI_CHARS) {
                        append('%').append("%02X".format(c.code))
                    } else {
                        append(c)
                    }
                }
            }
            val uri = try {
                java.net.URI(escaped)
            } catch (e: java.net.URISyntaxException) {
                return UNPARSEABLE_URL
            }
            val scheme = uri.scheme
            if (uri.isOpaque || scheme == null) return UNPARSEABLE_URL
            val host = uri.host
            if (host == null) {
                // A registry-based authority (e.g. a host with "_") keeps the
                // userinfo in its raw text: record nothing of it.
                if (uri.rawAuthority != null) return UNPARSEABLE_URL
                return "$scheme:${uri.path.orEmpty()}"
            }
            val port = if (uri.port != -1) ":${uri.port}" else ""
            return "$scheme://$host$port${uri.path.orEmpty()}"
        }
    }

    private fun saveMetadataSync(certs: List<TrustedCA>) {
        val array = JSONArray()
        certs.forEach { cert ->
            array.put(
                JSONObject().apply {
                    put("fingerprint", cert.fingerprint)
                    put("subjectDN", cert.subjectDN)
                    put("issuerDN", cert.issuerDN)
                    put("notBefore", cert.notBefore)
                    put("notAfter", cert.notAfter)
                    put("label", cert.label ?: JSONObject.NULL)
                    put("importedAt", cert.importedAt)
                    put("source", cert.source)
                    put("systemInstalled", cert.systemInstalled)
                }
            )
        }
        // Write a temp file and rename it over the metadata, so a write that
        // fails part-way leaves the previous document in place. The temp file
        // is this writer's own: created exclusively under a unique name, it is
        // written, renamed and removed by this call alone. Callers hold the
        // store lock, so no other writer reads or replaces the metadata between.
        val metadataFile = File(trustStoreDir, "metadata.json")
        val tempFile = File.createTempFile("metadata.json.", ".tmp", trustStoreDir)
        try {
            fileWriter(tempFile, array.toString())
            if (!tempFile.renameTo(metadataFile)) {
                throw IOException("cannot replace ${metadataFile.name}")
            }
        } finally {
            tempFile.delete()
        }
    }

    /**
     * Reads the trust-store metadata written by [saveMetadataSync].
     *
     * Uses `org.json` rather than pattern matching. The previous reader split
     * the document on `\{[^}]+\}`, so any value containing a closing brace —
     * a label or a DN — truncated its own object and silently dropped every
     * field after it. Entries that are individually malformed are still skipped
     * rather than failing the whole read, since the DER files remain the
     * authority for what is actually trusted.
     */
    private fun parseMetadata(json: String): List<TrustedCA> {
        val array = try {
            JSONArray(json)
        } catch (e: JSONException) {
            // Not a JSON array: treat the store as having no metadata rather
            // than failing the read. The DER files still say what is trusted.
            return emptyList()
        }

        val result = mutableListOf<TrustedCA>()
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val fingerprint = obj.optString("fingerprint").takeIf { it.isNotEmpty() } ?: continue
            result += TrustedCA(
                fingerprint = fingerprint,
                subjectDN = obj.optString("subjectDN"),
                issuerDN = obj.optString("issuerDN"),
                notBefore = obj.optLong("notBefore"),
                notAfter = obj.optLong("notAfter"),
                label = if (obj.isNull("label")) null else obj.optString("label"),
                importedAt = obj.optLong("importedAt"),
                source = obj.optString("source").takeIf { it.isNotEmpty() } ?: "unknown",
                systemInstalled = obj.optBoolean("systemInstalled")
            )
        }
        return result
    }

    private fun determineTrustLevel(certs: List<X509Certificate>): String {
        val rootSubject = certs.lastOrNull()?.issuerX500Principal?.name ?: ""
        return when {
            rootSubject.contains("StrongBox", ignoreCase = true) -> "hardware-backed"
            rootSubject.contains("TEE", ignoreCase = true) -> "tee-backed"
            rootSubject.contains("Android", ignoreCase = true) -> "android-ca"
            else -> "external-ca"
        }
    }
}
