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
package com.automatethethings.xkey.ui

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * What `TrustStoreActivity` tells the user when an import refuses a certificate.
 *
 * The store never accepts a self-signed certificate, and the import loop used to
 * count that refusal as *both* an error and a skip. The result `when` then tested
 * "everything was already there" before it tested "nothing worked", so a user
 * importing certificates the store had flatly rejected was told they were
 * already imported — the one message that tells them there is nothing to do.
 *
 * A rejection is now counted apart from a skip and reported ahead of it. The two
 * loops that produced this message — the file picker and the bootstrap dialog —
 * were byte-for-byte copies of each other, so they share one implementation now
 * and this suite exercises it through the file picker.
 *
 * ## Shared state
 *
 * The trust store is shared with every other suite. Nothing here is destructive:
 * counts are recomputed from the repository rather than assumed, and every
 * fingerprint this run may have written is removed in `@After` — including the
 * ones an import was expected to reject, in case it did not.
 */
@RunWith(AndroidJUnit4::class)
class TrustStoreImportOutcomeTest {

    private val runId = System.nanoTime()

    private lateinit var context: Context
    private lateinit var repository: TrustStoreRepository

    private val createdFingerprints = mutableSetOf<String>()
    private val createdAliases = mutableListOf<String>()
    private val scratchFiles = mutableListOf<File>()

    @Before
    fun setUp() {
        Intents.init()
        context = ApplicationProvider.getApplicationContext()
        repository = TrustStoreRepository(context)
    }

    @After
    fun tearDown() {
        runBlocking {
            createdFingerprints.forEach { repository.deleteCertificate(it) }
        }
        createdAliases.forEach { TestCertificates.deleteAlias(it) }
        scratchFiles.forEach { it.delete() }
        Intents.release()
    }

    /**
     * A bundle the store refuses outright says so, rather than claiming the
     * certificates were already present.
     */
    @Test
    fun aFileOfOnlyRejectedCertificates_reportsTheRejection() {
        val first = keystoreCertificate("$ALIAS_PREFIX-only-a-$runId", "xKey Outcome Self A $runId")
        val second = keystoreCertificate("$ALIAS_PREFIX-only-b-$runId", "xKey Outcome Self B $runId")
        createdFingerprints += listOf(fingerprintOf(first), fingerprintOf(second))
        stubOpenDocumentWith(
            scratchFile(
                "rejected-only-$runId.pem",
                (TestCertificates.toPem(first) + TestCertificates.toPem(second)).toByteArray()
            )
        )

        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, fileButton)

        assertShownTextInTree(
            scenario,
            context.getString(R.string.trust_store_import_rejected, 2)
        )
        assertTextNotInTree(scenario, context.getString(R.string.trust_store_import_all_exist))
        assertEquals("A wholly rejected import must not change the store", before, certificateCount())
        scenario.close()
    }

    /**
     * The reported defect: one certificate already in the store and one the store
     * refuses. Nothing is imported, so the old ordering reached the "already
     * imported" arm and the rejection went unmentioned.
     */
    @Test
    fun aFileMixingADuplicateAndARejection_reportsTheRejectionNotTheDuplicate() {
        val duplicate = caSignedCertificate("xKey Outcome Duplicate CA $runId")
        val duplicateFingerprint = fingerprintOf(duplicate)
        createdFingerprints += duplicateFingerprint
        val stored = runBlocking {
            repository.importCertificate(duplicate.encoded, "seed-$runId")
        }
        assertTrue("The seeded certificate should have been accepted", stored != null)

        val refused = keystoreCertificate("$ALIAS_PREFIX-mixed-$runId", "xKey Outcome Self $runId")
        createdFingerprints += fingerprintOf(refused)
        stubOpenDocumentWith(
            scratchFile(
                "duplicate-and-rejected-$runId.pem",
                (TestCertificates.toPem(duplicate) + TestCertificates.toPem(refused)).toByteArray()
            )
        )

        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, fileButton)

        assertShownTextInTree(
            scenario,
            context.getString(R.string.trust_store_import_rejected, 1)
        )
        assertTextNotInTree(scenario, context.getString(R.string.trust_store_import_all_exist))
        assertEquals("Neither half of the bundle should add a row", before, certificateCount())
        scenario.close()
    }

    /**
     * A rejection alongside a genuine import still names both halves: reporting
     * the rejection first must not cost the user the count that succeeded.
     */
    @Test
    fun aFileMixingAnAcceptedCertificateAndARejection_reportsBothHalves() {
        val accepted = caSignedCertificate("xKey Outcome Accepted CA $runId")
        val acceptedFingerprint = fingerprintOf(accepted)
        val refused = keystoreCertificate("$ALIAS_PREFIX-partial-$runId", "xKey Outcome Partial $runId")
        createdFingerprints += listOf(acceptedFingerprint, fingerprintOf(refused))
        stubOpenDocumentWith(
            scratchFile(
                "accepted-and-rejected-$runId.pem",
                (TestCertificates.toPem(accepted) + TestCertificates.toPem(refused)).toByteArray()
            )
        )

        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, fileButton)

        assertShownTextInTree(
            scenario,
            context.getString(R.string.trust_store_import_partial_rejected, 1, 1)
        )
        awaitCondition("Only the CA-signed certificate should be stored") {
            certificateCount() == before + 1
        }
        assertTrue(
            "The accepted half should be in the store",
            runBlocking { repository.hasCertificate(acceptedFingerprint) }
        )
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<TrustStoreActivity> {
        val scenario = ActivityScenario.launch<TrustStoreActivity>(TrustStoreActivity::class.java)
        awaitText(scenario, context.getString(R.string.trust_store_title))
        return scenario
    }

    private fun certificateCount(): Int =
        runBlocking { repository.getAllCertificates() }.size

    private fun stubOpenDocumentWith(file: File) {
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT)).respondWith(
            Instrumentation.ActivityResult(
                Activity.RESULT_OK,
                Intent().setData(Uri.fromFile(file))
            )
        )
    }

    private fun scratchFile(name: String, bytes: ByteArray): File =
        File(context.cacheDir, name).apply {
            writeBytes(bytes)
            scratchFiles += this
        }

    /**
     * Generates a self-signed Keystore certificate and registers its alias.
     *
     * Self-signed is precisely what the trust store refuses, so this is the
     * rejection these tests need.
     */
    private fun keystoreCertificate(alias: String, commonName: String): X509Certificate {
        createdAliases += alias
        return TestCertificates.selfSigned(alias, commonName)
    }

    /**
     * Builds a certificate signed by a throwaway software CA — the only kind the
     * trust store accepts, since it refuses anything whose subject is its issuer.
     */
    private fun caSignedCertificate(commonName: String): X509Certificate {
        val issuerKey = softwareKeyPair()
        val subjectKey = softwareKeyPair()
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Name("CN=UI Outcome Import Issuer"),
            BigInteger.valueOf(System.nanoTime()),
            Date(now - TestCertificates.ONE_DAY_MS),
            Date(now + 365L * TestCertificates.ONE_DAY_MS),
            X500Name("CN=$commonName"),
            subjectKey.public
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun softwareKeyPair() = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private fun fingerprintOf(certificate: X509Certificate): String =
        MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }

    /** The import card's file entry. */
    private val fileButton: String
        get() = context.getString(R.string.trust_store_import_file_title)

    private companion object {
        const val ALIAS_PREFIX = "xkey_uitest_truststoreoutcome"
    }
}
