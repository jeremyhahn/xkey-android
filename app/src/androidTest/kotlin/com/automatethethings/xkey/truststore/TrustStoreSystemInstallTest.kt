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
package com.automatethethings.xkey.truststore

import android.content.Context
import android.content.ContextWrapper
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [TrustStoreRepository.refreshSystemInstallStatus].
 *
 * The refresh enumerates `AndroidCAStore` — the platform's system + user CA
 * store — and flips [TrustedCA.systemInstalled] for anything whose SHA-256
 * fingerprint it recognises. That keystore only exists on a device, so the JVM
 * suite can only reach the early return; everything below the enumeration is
 * covered here.
 *
 * The repository is pointed at a throwaway directory through a [ContextWrapper],
 * so the app's real trust store is neither read nor written and there is nothing
 * to undo beyond deleting that directory.
 */
@RunWith(AndroidJUnit4::class)
class TrustStoreSystemInstallTest {

    private lateinit var storeDir: File
    private lateinit var repository: TrustStoreRepository

    @Before
    fun setUp() {
        val target = ApplicationProvider.getApplicationContext<Context>()
        storeDir = File(target.cacheDir, "trust-store-system-${System.nanoTime()}")
        assertTrue(storeDir.mkdirs())
        val isolated = object : ContextWrapper(target) {
            override fun getDir(name: String, mode: Int): File = storeDir
        }
        repository = TrustStoreRepository(isolated)
    }

    @After
    fun tearDown() {
        storeDir.deleteRecursively()
    }

    /** The first readable certificate in the platform CA store, if there is one. */
    private fun aSystemCertificate(): X509Certificate? {
        val keyStore = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            val cert = runCatching {
                keyStore.getCertificate(aliases.nextElement()) as? X509Certificate
            }.getOrNull()
            if (cert != null) return cert
        }
        return null
    }

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    /**
     * A freshly generated, self-signed certificate.
     *
     * The key is random per call, so the certificate is guaranteed *not* to be
     * in the platform CA store — which is exactly what the negative cases need.
     */
    private fun freshCertificate(cn: String): X509Certificate {
        val keyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val subject = X500Name("CN=$cn")
        val notBefore = Date()
        val notAfter = Date(notBefore.time + 86_400_000L)
        val holder = JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(System.nanoTime()),
            notBefore,
            notAfter,
            subject,
            keyPair.public
        ).build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    @Test
    fun refreshFlagsACertificateThatIsInThePlatformStore() = runBlocking<Unit> {
        val systemCert = aSystemCertificate()
        assumeTrue("no readable certificates in AndroidCAStore", systemCert != null)

        val fingerprint = repository.importInternalCACertificate(systemCert!!, "platform root")
        assertEquals(sha256Hex(systemCert.encoded), fingerprint)
        assertFalse(repository.getCertificate(fingerprint)!!.systemInstalled)

        repository.refreshSystemInstallStatus()

        assertTrue(
            "a certificate taken straight out of AndroidCAStore must be reported as installed",
            repository.getCertificate(fingerprint)!!.systemInstalled
        )
    }

    @Test
    fun refreshLeavesAnUnknownCertificateUnflagged() = runBlocking<Unit> {
        val fingerprint = repository.importInternalCACertificate(
            freshCertificate("xkey-not-in-system-store"),
            "local only"
        )

        repository.refreshSystemInstallStatus()

        assertFalse(repository.getCertificate(fingerprint)!!.systemInstalled)
    }

    @Test
    fun refreshClearsAStaleInstalledFlag() = runBlocking<Unit> {
        val fingerprint = repository.importInternalCACertificate(
            freshCertificate("xkey-stale-flag"),
            "local only"
        )
        repository.updateSystemInstalled(fingerprint, true)
        assertTrue(repository.getCertificate(fingerprint)!!.systemInstalled)

        repository.refreshSystemInstallStatus()

        assertFalse(
            "a certificate that was uninstalled from the system store must lose the flag",
            repository.getCertificate(fingerprint)!!.systemInstalled
        )
    }

    @Test
    fun refreshPreservesTheRestOfTheMetadata() = runBlocking<Unit> {
        val cert = freshCertificate("xkey-metadata-survivor")
        val fingerprint = repository.importInternalCACertificate(cert, "corporate root")
        val before = repository.getCertificate(fingerprint)!!

        repository.refreshSystemInstallStatus()

        val after = repository.getCertificate(fingerprint)!!
        assertEquals(before.label, after.label)
        assertEquals("internal-ca", after.source)
        assertEquals(before.subjectDN, after.subjectDN)
        assertEquals(before.issuerDN, after.issuerDN)
        assertEquals(before.notBefore, after.notBefore)
        assertEquals(before.notAfter, after.notAfter)
        assertEquals(before.importedAt, after.importedAt)
        assertNotNull(repository.getCertificateDER(fingerprint))
    }

    @Test
    fun refreshOnAnEmptyStoreIsHarmless() = runBlocking<Unit> {
        repository.refreshSystemInstallStatus()

        assertEquals(0, repository.getCertificateCount())
        assertTrue(repository.getAllCertificates().isEmpty())
    }

    @Test
    fun refreshIsIdempotent() = runBlocking<Unit> {
        val fingerprint = repository.importInternalCACertificate(
            freshCertificate("xkey-idempotent"),
            "local only"
        )

        repository.refreshSystemInstallStatus()
        val once = repository.getAllCertificates()
        repository.refreshSystemInstallStatus()

        assertEquals(once, repository.getAllCertificates())
        assertEquals(1, repository.getCertificateCount())
        assertEquals(fingerprint, once.single().fingerprint)
    }
}
