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
import android.view.MenuItem
import androidx.appcompat.widget.PopupMenu
import androidx.core.content.FileProvider
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
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
 * Import- and menu-branch coverage for [TrustStoreActivity].
 *
 * `TrustStoreFlowTest` drives the happy paths of every import route plus the
 * self-signed rejection. What it never produces is a *partial* result — some
 * certificates stored and some rejected in the same file — or a repeat import
 * where every certificate is already known, or a stream that cannot be opened
 * at all. Each of those is a separate arm of the import coroutine's result
 * `when`, and all three are unreached. Neither suite touches
 * `onOptionsItemSelected` (0% covered: both back-navigation tests press the
 * system back button), the empty-state call to action, or the cancelled file
 * picker.
 *
 * A certificate with no CN in its subject and no label is also seeded here: it
 * is the only way to reach the last arm of the row title's fallback chain and
 * the matching fallback in the delete confirmation, both of which otherwise sit
 * behind data the app never writes itself.
 *
 * The trust store is shared with every other suite, so nothing here is
 * destructive: "Clear All" is never confirmed, counts are always recomputed from
 * the repository rather than assumed, and every fingerprint this run may have
 * written is removed in `@After` — including the ones an import was expected to
 * reject, in case it did not.
 */
@RunWith(AndroidJUnit4::class)
class TrustStoreBranchTest {

    private val runId = System.nanoTime()

    private lateinit var context: Context
    private lateinit var repository: TrustStoreRepository
    private lateinit var trustStoreDir: File

    private val createdFingerprints = mutableSetOf<String>()
    private val createdAliases = mutableListOf<String>()
    private val scratchFiles = mutableListOf<File>()

    @Before
    fun setUp() {
        Intents.init()
        context = ApplicationProvider.getApplicationContext()
        repository = TrustStoreRepository(context)
        trustStoreDir = context.getDir("trust_store", Context.MODE_PRIVATE)
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

    // ---------------------------------------------------------------
    // Import results the happy paths never produce
    // ---------------------------------------------------------------

    /**
     * Importing the same file twice reports that everything was already there,
     * and leaves the store the size it already was.
     */
    @Test
    fun reImportingTheSameBundle_reportsThatEverythingAlreadyExists() {
        val certificate = caSignedCertificate("xKey Branch Duplicate CA $runId")
        val fingerprint = fingerprintOf(certificate)
        createdFingerprints += fingerprint
        val file = scratchFile(
            "duplicate-$runId.pem",
            TestCertificates.toPem(certificate).toByteArray()
        )
        stubOpenDocumentWith(file)

        val scenario = launch()
        clickTextInTree(scenario, FILE_BUTTON)
        awaitCondition("The first import should store the certificate") {
            runBlocking { repository.hasCertificate(fingerprint) }
        }
        val after = certificateCount()

        clickTextInTree(scenario, FILE_BUTTON)

        assertShownTextInTree(scenario, context.getString(R.string.trust_store_import_all_exist))
        assertEquals("A repeat import must not add a row", after, certificateCount())
        scenario.close()
    }

    /**
     * A picked file that no longer exists surfaces the read failure rather than
     * silently doing nothing.
     */
    @Test
    fun anUnreadableFile_reportsTheImportError() {
        stubOpenDocumentWith(File(context.cacheDir, "gone-$runId.pem"))

        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, FILE_BUTTON)

        assertShownTextInTree(scenario, IMPORT_ERROR_PREFIX)
        assertEquals("A failed read must not change the store", before, certificateCount())
        scenario.close()
    }

    /**
     * A malformed PEM block is skipped and the valid one after it is still
     * stored: the parser recovers per block rather than abandoning the file.
     */
    @Test
    fun aMalformedPemBlock_doesNotStopTheRestOfTheFile() {
        val certificate = caSignedCertificate("xKey Branch Recovered CA $runId")
        val fingerprint = fingerprintOf(certificate)
        createdFingerprints += fingerprint
        val bundle = GARBAGE_PEM_BLOCK + TestCertificates.toPem(certificate)
        stubOpenDocumentWith(scratchFile("malformed-$runId.pem", bundle.toByteArray()))

        val scenario = launch()

        clickTextInTree(scenario, FILE_BUTTON)

        awaitCondition("The well-formed block should still be stored") {
            runBlocking { repository.hasCertificate(fingerprint) }
        }
        scenario.close()
    }

    /**
     * A content URI is resolved to its display name, which becomes the stored
     * label — the file:// paths the other suite uses take the fallback instead.
     */
    @Test
    fun aContentUri_takesItsLabelFromTheProvidersDisplayName() {
        val certificate = caSignedCertificate("xKey Branch Content CA $runId")
        val fingerprint = fingerprintOf(certificate)
        createdFingerprints += fingerprint
        val fileName = "content-bundle-$runId.pem"
        val file = scratchFile(fileName, TestCertificates.toPem(certificate).toByteArray())
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT)).respondWith(
            Instrumentation.ActivityResult(
                Activity.RESULT_OK,
                Intent().setData(
                    FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
                )
            )
        )

        val scenario = launch()

        clickTextInTree(scenario, FILE_BUTTON)

        awaitCondition("The certificate behind the content URI should be stored") {
            runBlocking { repository.hasCertificate(fingerprint) }
        }
        assertEquals(
            "The provider's display name should become the label",
            fileName,
            runBlocking { repository.getCertificate(fingerprint) }?.label
        )
        scenario.close()
    }

    /** Backing out of the file picker leaves the screen and the store untouched. */
    @Test
    fun cancellingTheFilePicker_changesNothing() {
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null)
        )

        val scenario = launch()
        val before = certificateCount()

        clickTextInTree(scenario, FILE_BUTTON)
        waitForIdle()

        assertEquals("A cancelled picker must not change the store", before, certificateCount())
        assertTextNotInTree(scenario, IMPORT_ERROR_PREFIX)
        scenario.close()
    }

    /**
     * A URL whose scheme the fetcher cannot build a request from fails through
     * the generic handler rather than the fetch handler.
     */
    @Test
    fun aUrlWithAnUnsupportedScheme_reportsTheImportError() {
        val scenario = launch()

        clickTextInTree(scenario, URL_BUTTON)
        onView(withHint(R.string.trust_store_url_hint))
            .inRoot(isDialog())
            .perform(replaceText("ftp://ca.uitest.invalid"), closeSoftKeyboard())
        onView(withText(R.string.trust_store_import_button)).inRoot(isDialog()).perform(click())

        assertShownTextInTree(scenario, IMPORT_ERROR_PREFIX)
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Fallback chains for data the app never writes itself
    // ---------------------------------------------------------------

    /**
     * A certificate with no CN and no label falls all the way through to its
     * truncated distinguished name, on the row and in the delete confirmation.
     *
     * The label is cleared by rewriting `metadata.json` — the repository's
     * import entry points always record one.
     */
    @Test
    fun aCertificateWithNoCnAndNoLabel_fallsBackToItsTruncatedSubject() {
        val certificate = caSignedCertificate(commonName = null)
        val stored = runBlocking {
            repository.importCertificate(certificate.encoded, "temporary-$runId")
        }
        assertTrue("The seeded certificate should have been accepted", stored != null)
        val fingerprint = stored!!.fingerprint
        createdFingerprints += fingerprint
        clearLabel(fingerprint)
        val expected = certificate.subjectX500Principal.name.take(SUBJECT_TRUNCATION)

        val scenario = launch()

        assertShownTextInList(scenario, expected)
        RowFlowInteractions.longClickText(scenario, expected)
        onView(withText(R.string.trust_store_delete_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(context.getString(R.string.trust_store_delete_message, expected)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Empty state and options menu
    // ---------------------------------------------------------------

    /**
     * The empty state's call to action opens the same import dialog as the
     * header button.
     *
     * The button is only on screen when the store is empty, which this suite
     * refuses to arrange — clicking it in the tree drives the listener without
     * having to empty a store other suites depend on.
     */
    @Test
    fun theEmptyStateCallToAction_opensTheImportDialog() {
        val scenario = launch()

        clickTextInTree(scenario, EMPTY_STATE_BUTTON)

        onView(withText(R.string.trust_store_import_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())
        scenario.close()
    }

    /** The `home` item routes through the back dispatcher and closes the screen. */
    @Test
    fun homeMenuItem_finishesTheActivity() {
        val scenario = launch()

        val handled = selectMenuItem(scenario, android.R.id.home)

        assertTrue("The home item should be handled by the activity", handled)
        assertActivityDestroyed(scenario)
    }

    /** Any other item falls through to the superclass and is left unhandled. */
    @Test
    fun anUnrecognisedMenuItem_isNotHandled() {
        val scenario = launch()

        val handled = selectMenuItem(scenario, UNRECOGNISED_ITEM_ID)

        assertFalse("An unknown menu item must not be claimed", handled)
        assertFalse(
            "An unhandled menu item must not close the screen",
            withActivity(scenario) { it.isFinishing }
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

    /** Passes a synthesised [MenuItem] with [itemId] to the activity's handler. */
    private fun selectMenuItem(
        scenario: ActivityScenario<TrustStoreActivity>,
        itemId: Int
    ): Boolean {
        val handled = withActivity(scenario) { activity ->
            val item: MenuItem = PopupMenu(activity, activity.window.decorView)
                .menu
                .add(0, itemId, 0, "synthetic")
            activity.onOptionsItemSelected(item)
        }
        waitForIdle()
        return handled
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

    /** Generates a self-signed Keystore certificate and registers its alias. */
    private fun keystoreCertificate(alias: String, commonName: String): X509Certificate {
        createdAliases += alias
        return TestCertificates.selfSigned(alias, commonName)
    }

    /**
     * Builds a certificate signed by a throwaway software CA.
     *
     * The trust store refuses anything whose subject equals its issuer, so a
     * real two-party certificate is the only kind that can be imported. Passing
     * a null [commonName] gives the subject no CN at all, which is what the row
     * title's last fallback needs.
     */
    private fun caSignedCertificate(commonName: String?): X509Certificate {
        val issuerKey = softwareKeyPair()
        val subjectKey = softwareKeyPair()
        val now = System.currentTimeMillis()
        val subject = if (commonName == null) {
            X500Name("OU=xKey Branch Unit $runId,O=Automate The Things")
        } else {
            X500Name("CN=$commonName")
        }
        val builder = JcaX509v3CertificateBuilder(
            X500Name("CN=UI Branch Import Issuer"),
            BigInteger.valueOf(System.nanoTime()),
            Date(now - TestCertificates.ONE_DAY_MS),
            Date(now + 365L * TestCertificates.ONE_DAY_MS),
            subject,
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

    /**
     * Nulls the stored label of [fingerprint] in the trust store's index.
     *
     * Every repository entry point records a label, so the only way to render a
     * row that has none is to edit the index the same way the repository does.
     */
    private fun clearLabel(fingerprint: String) {
        val metadata = File(trustStoreDir, METADATA_FILE)
        val entries = JSONArray(metadata.readText())
        for (index in 0 until entries.length()) {
            val entry = entries.getJSONObject(index)
            if (entry.getString("fingerprint") == fingerprint) {
                entry.put("label", JSONObject.NULL)
            }
        }
        metadata.writeText(entries.toString())
    }

    private companion object {

        const val ALIAS_PREFIX = "xkey_uitest_truststorebranch"

        const val METADATA_FILE = "metadata.json"

        // Literals the screen builds in code rather than from resources.
        const val FILE_BUTTON = "Import from File"
        const val URL_BUTTON = "Import from URL"
        const val EMPTY_STATE_BUTTON = "Import your first certificate"

        /** The screen truncates a subject DN at this length for display. */
        const val SUBJECT_TRUNCATION = 40

        /**
         * The stable prefix of `trust_store_import_error`, whose suffix is the
         * platform's exception message and therefore not worth asserting.
         */
        const val IMPORT_ERROR_PREFIX = "Error importing certificates"

        /** A PEM block whose body is not base64, so its parse throws. */
        const val GARBAGE_PEM_BLOCK =
            "-----BEGIN CERTIFICATE-----\nnot base64 at all !!!\n-----END CERTIFICATE-----\n"

        /** An id no resource in this app can collide with. */
        const val UNRECOGNISED_ITEM_ID = 0x7EEE0003
    }
}
