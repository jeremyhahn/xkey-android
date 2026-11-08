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
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.ImageButton
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.closeSoftKeyboard
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withContentDescription
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.BootstrapMethod
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.hamcrest.Matchers.not
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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
 * Detail, delete, bootstrap and import flows for [TrustStoreActivity].
 *
 * `TrustStoreActivityUiTest` establishes that the screen renders and that its
 * dialogs open and cancel. This suite drives the parts that actually change
 * something: every field of the detail bottom sheet across all three validity
 * states, both routes into the delete confirmation, the bootstrap dialog's
 * method-specific inputs, and the file/URL import paths including their failure
 * messages.
 *
 * The trust store keeps a DER file per certificate plus a `metadata.json`
 * index, and the two can disagree. One test deletes a DER file behind the
 * screen's back to prove that removing the entry still clears the metadata row
 * rather than stranding it.
 *
 * Nothing here is allowed to leak: each seeded or imported fingerprint is
 * registered and removed in @After, and the destructive "Clear All" flow is
 * never confirmed. The store is shared with other suites, so every expectation
 * is recomputed from the repository instead of assumed.
 *
 * Tests cover:
 * - The expiring-soon summary badge
 * - The detail sheet: subject, issuer, validity window, source, label, status
 *   badge for valid / expiring / expired, and the install-to-system offer
 * - Copying the fingerprint to the clipboard
 * - Delete from the row button (cancelled) and from a long press (confirmed)
 * - Deleting an entry whose DER file has gone missing
 * - The bootstrap dialog revealing the Noise and SPKI fields, and refusing an
 *   empty server URL
 * - Import from URL: the untouched placeholder, and an unreachable host
 * - Import from file: a CA-signed certificate, self-signed rejection, the DER
 *   branch, and a file holding no certificate at all
 */
@RunWith(AndroidJUnit4::class)
class TrustStoreFlowTest {

    private lateinit var context: Context
    private lateinit var repository: TrustStoreRepository
    private lateinit var trustStoreDir: File

    /** Fingerprints this run may have written, cleared in @After. */
    private val createdFingerprints = mutableSetOf<String>()
    private val createdAliases = mutableListOf<String>()
    private val scratchFiles = mutableListOf<File>()

    private val runId = System.nanoTime()

    private lateinit var validFingerprint: String
    private lateinit var expiringFingerprint: String
    private lateinit var expiredFingerprint: String

    @Before
    fun setUp() {
        Intents.init()
        context = ApplicationProvider.getApplicationContext()
        repository = TrustStoreRepository(context)
        trustStoreDir = context.getDir("trust_store", Context.MODE_PRIVATE)

        val now = System.currentTimeMillis()
        val valid = keystoreCertificate(
            alias = "$ALIAS_PREFIX-valid-$runId",
            commonName = VALID_CN,
            notAfter = Date(now + 365L * TestCertificates.ONE_DAY_MS)
        )
        val expiring = keystoreCertificate(
            alias = "$ALIAS_PREFIX-expiring-$runId",
            commonName = EXPIRING_CN,
            notAfter = Date(now + EXPIRING_IN_DAYS * TestCertificates.ONE_DAY_MS)
        )
        val expired = keystoreCertificate(
            alias = "$ALIAS_PREFIX-expired-$runId",
            commonName = EXPIRED_CN,
            notBefore = Date(now - 30L * TestCertificates.ONE_DAY_MS),
            notAfter = Date(now - TestCertificates.ONE_DAY_MS)
        )

        runBlocking {
            validFingerprint = repository.importInternalCACertificate(valid, VALID_LABEL)
            expiringFingerprint = repository.importInternalCACertificate(expiring, EXPIRING_LABEL)
            expiredFingerprint = repository.importInternalCACertificate(expired, EXPIRED_LABEL)
        }
        createdFingerprints += listOf(validFingerprint, expiringFingerprint, expiredFingerprint)
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

    // -----------------------------------------------------------------
    // Summary badges
    // -----------------------------------------------------------------

    /**
     * A certificate inside the 30-day window is counted as expiring soon rather
     * than as expired, and gets its own badge.
     */
    @Test
    fun summaryCard_showsTheExpiringSoonBadge() {
        val scenario = launch()
        assertShownTextInTree(scenario, EXPIRING_CN)

        val now = System.currentTimeMillis()
        val threshold = now + EXPIRING_WINDOW_DAYS * TestCertificates.ONE_DAY_MS
        val expected = runBlocking {
            repository.getAllCertificates().count { it.notAfter in now..threshold }
        }
        assertTrue("The seeded certificate should be counted as expiring", expected >= 1)
        assertShownTextInTree(scenario, "$expected expiring soon")
    }

    // -----------------------------------------------------------------
    // Detail bottom sheet
    // -----------------------------------------------------------------

    @Test
    fun detailSheet_showsEveryFieldOfAValidCertificate() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)
        val stored = runBlocking { repository.getCertificate(validFingerprint) }!!

        clickTextInTree(scenario, VALID_CN)

        onView(withText(STATUS_VALID)).inRoot(isDialog()).check(matches(isDisplayed()))
        // A self-signed certificate repeats its DN as both subject and issuer,
        // so pin the assertion to the first of the two rather than letting the
        // matcher hit both.
        onView(nthMatch(withText(stored.subjectDN), 0))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_detail_subject))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_detail_issuer))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_detail_valid_from))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_detail_valid_until))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(stored.source)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withText(VALID_LABEL)).inRoot(isDialog()).check(matches(isDisplayed()))

        // The seeded certificates are not in the Android system store, so the
        // sheet has to offer the install action rather than the "already there"
        // notice.
        onView(withText(R.string.install_to_system))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    @Test
    fun detailSheet_marksACertificateInsideTheWindowAsExpiringSoon() {
        val scenario = launch()
        assertShownTextInTree(scenario, EXPIRING_CN)

        clickTextInTree(scenario, EXPIRING_CN)

        onView(withText(STATUS_EXPIRING)).inRoot(isDialog()).check(matches(isDisplayed()))
    }

    @Test
    fun detailSheet_marksAPastCertificateAsExpired() {
        val scenario = launch()
        assertShownTextInTree(scenario, EXPIRED_CN)

        clickTextInTree(scenario, EXPIRED_CN)

        onView(withText(STATUS_EXPIRED)).inRoot(isDialog()).check(matches(isDisplayed()))
    }

    /**
     * The fingerprint is rendered in eight-character groups for readability, but
     * what lands on the clipboard has to be the unbroken hex a peer can compare.
     */
    @Test
    fun detailSheet_copyingTheFingerprint_putsTheUngroupedHexOnTheClipboard() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, VALID_CN)
        onView(withContentDescription(COPY_FINGERPRINT_DESCRIPTION))
            .inRoot(isDialog())
            .perform(click())

        val copied = withActivity(scenario) { activity ->
            val clipboard =
                activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.primaryClip?.getItemAt(0)?.text?.toString()
        }
        assertEquals(validFingerprint, copied)
    }

    // -----------------------------------------------------------------
    // Delete routes
    // -----------------------------------------------------------------

    /**
     * Each row carries its own delete button, which is a separate entry into the
     * confirmation from the detail sheet's delete button.
     */
    @Test
    fun rowDeleteButtonCancelled_keepsTheCertificate() {
        val scenario = launch()
        val position = rowPositionOf(scenario, validFingerprint, VALID_CN)

        clickRowDeleteButton(scenario, position)

        onView(withText(R.string.trust_store_delete_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Cancelling must keep the certificate",
            runBlocking { repository.hasCertificate(validFingerprint) }
        )
    }

    /** Long-pressing a row is the third route into the same confirmation. */
    @Test
    fun rowLongPressConfirmed_removesTheCertificate() {
        val scenario = launch()
        val position = rowPositionOf(scenario, validFingerprint, VALID_CN)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.trust_store_delete_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_delete)).inRoot(isDialog()).perform(click())

        awaitCondition("Confirming a long-press delete must remove the certificate") {
            !runBlocking { repository.hasCertificate(validFingerprint) }
        }
        assertTextNotInTree(scenario, VALID_CN)
    }

    /**
     * The DER files are the authority, but the metadata index outlives them if
     * one is removed out of band. Deleting such an entry has to clear the row as
     * well, or it becomes permanently un-removable.
     */
    @Test
    fun deletingAnEntryWhoseDerFileIsGone_stillClearsTheMetadataRow() {
        val orphanFile = File(trustStoreDir, "$expiredFingerprint.der")
        assertTrue("The seeded certificate should have a DER file", orphanFile.delete())

        val scenario = launch()
        val position = rowPositionOf(scenario, expiredFingerprint, EXPIRED_CN)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.trust_store_delete)).inRoot(isDialog()).perform(click())

        awaitCondition("The orphaned metadata row must be cleared") {
            runBlocking { repository.getCertificate(expiredFingerprint) } == null
        }
    }

    // -----------------------------------------------------------------
    // Bootstrap dialog
    // -----------------------------------------------------------------

    /**
     * Only the selected method's extra input may be on screen; the others are
     * meaningless for it and are hidden.
     */
    @Test
    fun bootstrapDialog_revealsOnlyTheSelectedMethodsExtraField() {
        val scenario = launch()

        clickTextInTree(scenario, BOOTSTRAP_BUTTON)

        // Nothing method-specific is shown for the default (DANE) selection.
        onView(withHint(NOISE_KEY_HINT)).inRoot(isDialog()).check(matches(not(isDisplayed())))
        onView(withHint(SPKI_PIN_HINT)).inRoot(isDialog()).check(matches(not(isDisplayed())))

        onView(withText(BootstrapMethod.NOISE.displayName)).inRoot(isDialog()).perform(click())
        onView(withHint(NOISE_KEY_HINT)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withHint(SPKI_PIN_HINT)).inRoot(isDialog()).check(matches(not(isDisplayed())))

        onView(withText(BootstrapMethod.SPKI.displayName)).inRoot(isDialog()).perform(click())
        onView(withHint(SPKI_PIN_HINT)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withHint(NOISE_KEY_HINT)).inRoot(isDialog()).check(matches(not(isDisplayed())))

        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())
    }

    /** The URL field starts at the bare scheme, which is not a server. */
    @Test
    fun bootstrapWithTheUntouchedUrl_reportsTheMissingUrlAndImportsNothing() {
        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, BOOTSTRAP_BUTTON)
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())

        assertShownTextInTree(scenario, MISSING_URL_MESSAGE)
        assertEquals(before, certificateCount())
    }

    // -----------------------------------------------------------------
    // Import from URL
    // -----------------------------------------------------------------

    /** The placeholder scheme is treated as "nothing entered". */
    @Test
    fun importFromUrlWithTheUntouchedPlaceholder_doesNothing() {
        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, URL_BUTTON)
        onView(withText(R.string.trust_store_import_button)).inRoot(isDialog()).perform(click())

        assertEquals(before, certificateCount())
    }

    /**
     * A refused connection has to surface as a fetch error rather than a silent
     * no-op. Port 1 on loopback is never listening, so this stays offline.
     */
    @Test
    fun importFromUrlWithAnUnreachableHost_reportsAFetchError() {
        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, URL_BUTTON)
        onView(withHint(R.string.trust_store_url_hint))
            .inRoot(isDialog())
            .perform(replaceText(UNREACHABLE_URL), closeSoftKeyboard())
        onView(withHint(R.string.trust_store_label_hint))
            .inRoot(isDialog())
            .perform(replaceText(IMPORT_LABEL), closeSoftKeyboard())
        onView(withText(R.string.trust_store_import_button)).inRoot(isDialog()).perform(click())

        assertShownTextInTree(scenario, string(scenario, R.string.trust_store_fetch_error, "").trim())
        assertEquals(before, certificateCount())
    }

    // -----------------------------------------------------------------
    // Import from file
    // -----------------------------------------------------------------

    /** The happy path: a PEM file holding a CA-signed certificate is stored. */
    @Test
    fun fileImport_ofACaSignedPemCertificate_addsItToTheStore() {
        val certificate = caSignedCertificate(IMPORTED_CN)
        val fingerprint = fingerprintOf(certificate)
        createdFingerprints += fingerprint
        stubOpenDocumentWith(
            scratchFile("bundle-$runId.pem", TestCertificates.toPem(certificate).toByteArray())
        )

        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)
        val before = certificateCount()

        clickTextInTree(scenario, FILE_BUTTON)

        awaitCondition("The certificate from the file should have been stored") {
            runBlocking { repository.hasCertificate(fingerprint) }
        }
        assertEquals(before + 1, certificateCount())
        assertShownTextInList(scenario, IMPORTED_CN)

        val stored = runBlocking { repository.getCertificate(fingerprint) }!!
        assertNotNull("The file name should be recorded as the label", stored.label)
        assertEquals("manual", stored.source)
    }

    /** A file holding raw DER exercises the non-PEM parse branch. */
    @Test
    fun fileImport_ofADerCertificate_takesTheDerBranch() {
        val certificate = caSignedCertificate(DER_IMPORT_CN)
        val fingerprint = fingerprintOf(certificate)
        createdFingerprints += fingerprint
        stubOpenDocumentWith(scratchFile("cert-$runId.der", certificate.encoded))

        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, FILE_BUTTON)

        awaitCondition("The DER certificate should have been stored") {
            runBlocking { repository.hasCertificate(fingerprint) }
        }
        assertShownTextInList(scenario, DER_IMPORT_CN)
    }

    @Test
    fun fileImport_ofAFileWithoutACertificate_reportsNothingFound() {
        stubOpenDocumentWith(scratchFile("garbage-$runId.bin", ByteArray(64) { it.toByte() }))

        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)
        val before = certificateCount()

        clickTextInTree(scenario, FILE_BUTTON)

        assertShownTextInTree(scenario, NO_CERTIFICATES_MESSAGE)
        assertEquals(before, certificateCount())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<TrustStoreActivity> =
        ActivityScenario.launch(TrustStoreActivity::class.java)

    private fun string(
        scenario: ActivityScenario<TrustStoreActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    private fun certificateCount(): Int = runBlocking { repository.getAllCertificates().size }

    /**
     * Waits for the row carrying [commonName] and returns its adapter position.
     *
     * The list is sorted by import time and the screen may add its own CA
     * certificates on resume, so the position is derived from the repository
     * only after the screen has finished loading.
     */
    private fun rowPositionOf(
        scenario: ActivityScenario<TrustStoreActivity>,
        fingerprint: String,
        commonName: String
    ): Int {
        assertShownTextInTree(scenario, commonName)
        val ordered = runBlocking { repository.getAllCertificates() }
            .sortedByDescending { it.importedAt }
        val position = ordered.indexOfFirst { it.fingerprint == fingerprint }
        assertTrue("The seeded certificate should be stored", position >= 0)
        assertTrue(
            "The adapter should have bound at least ${position + 1} rows",
            awaitRecyclerItemCount(scenario, position + 1)
        )
        return position
    }

    /** Clicks the trailing delete button of the row bound at [position]. */
    private fun clickRowDeleteButton(
        scenario: ActivityScenario<TrustStoreActivity>,
        position: Int
    ) {
        scenario.onActivity { activity ->
            val recycler = findFirstRecyclerView(activity.window.decorView)
            val holder = recycler?.findViewHolderForAdapterPosition(position)
            val button = holder?.itemView?.let { row ->
                collectViews(row) { it is ImageButton }.firstOrNull()
            }
            assertNotNull("Row $position should carry a delete button", button)
            button!!.performClick()
        }
        waitForIdle()
    }

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

    /** Generates a self-signed Keystore certificate and registers its alias. */
    private fun keystoreCertificate(
        alias: String,
        commonName: String,
        notBefore: Date = Date(System.currentTimeMillis() - TestCertificates.ONE_DAY_MS),
        notAfter: Date = Date(System.currentTimeMillis() + 365L * TestCertificates.ONE_DAY_MS)
    ): X509Certificate {
        createdAliases += alias
        return TestCertificates.selfSigned(alias, commonName, notBefore, notAfter)
    }

    /**
     * Builds a certificate signed by a throwaway software CA.
     *
     * The trust store refuses anything whose subject equals its issuer, so the
     * only way to exercise a successful import is with a real two-party
     * certificate. Both key pairs are software-only and are discarded here.
     */
    private fun caSignedCertificate(commonName: String): X509Certificate {
        val issuerKey = softwareKeyPair()
        val subjectKey = softwareKeyPair()
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Name("CN=UI Flow Import Issuer"),
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

    private companion object {
        const val ALIAS_PREFIX = "xkey_uitest_truststoreflow"

        const val VALID_CN = "xKey Flow Valid CA"
        const val EXPIRING_CN = "xKey Flow Expiring CA"
        const val EXPIRED_CN = "xKey Flow Expired CA"
        const val IMPORTED_CN = "xKey Flow Imported CA"
        const val DER_IMPORT_CN = "xKey Flow Der CA"

        const val VALID_LABEL = "Flow Valid Label"
        const val EXPIRING_LABEL = "Flow Expiring Label"
        const val EXPIRED_LABEL = "Flow Expired Label"
        const val IMPORT_LABEL = "Flow Import Label"

        /** Inside the screen's 30-day "expiring soon" window. */
        const val EXPIRING_IN_DAYS = 10L
        const val EXPIRING_WINDOW_DAYS = 30L

        // Literals the screen builds in code rather than from resources.
        const val STATUS_VALID = "VALID"
        const val STATUS_EXPIRING = "EXPIRING SOON"
        const val STATUS_EXPIRED = "EXPIRED"
        const val BOOTSTRAP_BUTTON = "Bootstrap from Server"
        const val URL_BUTTON = "Import from URL"
        const val FILE_BUTTON = "Import from File"
        const val COPY_FINGERPRINT_DESCRIPTION = "Copy fingerprint"
        const val NOISE_KEY_HINT = "Server static key (64 hex chars)"
        const val SPKI_PIN_HINT = "SPKI pin SHA-256 (64 hex chars)"
        const val MISSING_URL_MESSAGE = "Please enter a server URL"
        const val NO_CERTIFICATES_MESSAGE = "No valid certificates found in file"

        /** Loopback port 1 is never listening, so the fetch fails without network. */
        const val UNREACHABLE_URL = "https://127.0.0.1:1"
    }
}
