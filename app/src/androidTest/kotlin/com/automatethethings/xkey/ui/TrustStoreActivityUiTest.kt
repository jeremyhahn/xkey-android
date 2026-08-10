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
package com.automatethethings.xkey.ui

import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Date

/**
 * Instrumented UI tests for [TrustStoreActivity].
 *
 * TrustStoreActivity builds its UI programmatically, loads certificates from
 * [TrustStoreRepository] in onResume, and renders either a certificate list card
 * or an empty state. These tests seed two real X.509 certificates (one valid,
 * one already expired) via [TestCertificates] so that list binding, summary
 * badges, the certificate detail bottom sheet and the delete flow can all be
 * exercised against known content. Both are removed in @After.
 *
 * State shared with other suites is never assumed: counts are read back from the
 * repository rather than hard-coded, and the destructive "Clear All" flow is
 * only cancelled, never confirmed.
 *
 * Tests cover:
 * - Toolbar and import-options rendering
 * - List binding for seeded certificates, including the expired variant
 * - Summary count and expired badge derived from live repository state
 * - Empty state vs list-card visibility
 * - Certificate detail bottom sheet contents
 * - Delete: cancel keeps the certificate, confirm removes it
 * - Import-from-URL, bootstrap and clear-all dialogs open and cancel cleanly
 * - Back navigation finishes the activity
 */
@RunWith(AndroidJUnit4::class)
class TrustStoreActivityUiTest {

    private lateinit var repository: TrustStoreRepository
    private lateinit var validFingerprint: String
    private lateinit var expiredFingerprint: String

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = TrustStoreRepository(context)

        val now = System.currentTimeMillis()
        val validCert = TestCertificates.selfSigned(
            alias = VALID_ALIAS,
            commonName = VALID_CN,
            notAfter = Date(now + 365L * TestCertificates.ONE_DAY_MS)
        )
        val expiredCert = TestCertificates.selfSigned(
            alias = EXPIRED_ALIAS,
            commonName = EXPIRED_CN,
            notBefore = Date(now - 30L * TestCertificates.ONE_DAY_MS),
            notAfter = Date(now - TestCertificates.ONE_DAY_MS)
        )

        runBlocking {
            validFingerprint = repository.importInternalCACertificate(validCert, VALID_LABEL)
            expiredFingerprint = repository.importInternalCACertificate(expiredCert, EXPIRED_LABEL)
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            repository.deleteCertificate(validFingerprint)
            repository.deleteCertificate(expiredFingerprint)
        }
        TestCertificates.deleteAlias(VALID_ALIAS)
        TestCertificates.deleteAlias(EXPIRED_ALIAS)
    }

    // -----------------------------------------------------------------
    // Toolbar and import options
    // -----------------------------------------------------------------

    @Test
    fun toolbar_showsTitleAndSubtitle() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)

        assertShownTextInTree(scenario, TITLE)
        assertShownTextInTree(scenario, SUBTITLE)
    }

    @Test
    fun importOptionsCard_offersAllThreeImportPaths() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)

        assertTextInTree(scenario, "Bootstrap from Server")
        assertTextInTree(scenario, "Import from URL")
        assertTextInTree(scenario, "Import from File")
    }

    // -----------------------------------------------------------------
    // List binding
    // -----------------------------------------------------------------

    @Test
    fun certificateList_bindsSeededCertificate() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)

        assertShownTextInTree(scenario, VALID_CN)
    }

    /**
     * The adapter labels a certificate whose notAfter is in the past with the
     * "Expired <date>" row text rather than "Expires <date>".
     */
    @Test
    fun certificateList_marksExpiredCertificateAsExpired() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, EXPIRED_CN)

        val expiredPrefix = withActivity(scenario) {
            it.getString(R.string.trust_store_item_expired, "").trim()
        }
        val expiresPrefix = withActivity(scenario) {
            it.getString(R.string.trust_store_item_expires, "").trim()
        }
        assertShownTextInTree(scenario, expiredPrefix)
        assertShownTextInTree(scenario, expiresPrefix)
    }

    /**
     * The adapter must bind one row per stored certificate. The expected count is
     * read back from the repository so ambient certificates left by the app (for
     * example the internal xKey CA) do not break the assertion.
     */
    @Test
    fun certificateList_itemCountMatchesRepository() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)

        val expected = runBlocking { repository.getAllCertificates().size }
        assertTrue(
            "RecyclerView should bind every stored certificate",
            awaitRecyclerItemCount(scenario, expected)
        )
        assertEquals(expected, recyclerItemCount(scenario))
    }

    // -----------------------------------------------------------------
    // Summary card
    // -----------------------------------------------------------------

    @Test
    fun summaryCard_countMatchesRepository() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)

        val expected = runBlocking { repository.getAllCertificates().size }
        assertExactTextShown(scenario, expected.toString())
    }

    @Test
    fun summaryCard_showsExpiredBadgeWhenACertificateHasExpired() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, EXPIRED_CN)

        val now = System.currentTimeMillis()
        val expectedExpired = runBlocking {
            repository.getAllCertificates().count { it.notAfter < now }
        }
        assertTrue("The seeded expired certificate should be counted", expectedExpired >= 1)
        assertShownTextInTree(scenario, "$expectedExpired expired")
    }

    // -----------------------------------------------------------------
    // Empty state
    // -----------------------------------------------------------------

    /**
     * With certificates present the list card is shown and the empty state is
     * hidden. The two are mutually exclusive, so assert both directions.
     */
    @Test
    fun emptyState_isHiddenWhileCertificatesExist() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)

        val emptyTitle = withActivity(scenario) { it.getString(R.string.trust_store_empty) }
        assertFalse(
            "Empty state must be hidden when the trust store has certificates",
            withActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, emptyTitle) != null
            }
        )
    }

    // -----------------------------------------------------------------
    // Certificate detail bottom sheet
    // -----------------------------------------------------------------

    @Test
    fun certificateRow_opensDetailSheetWithSubjectAndFingerprint() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, VALID_CN)

        onView(withText(R.string.trust_store_detail_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_detail_fingerprint))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    @Test
    fun detailSheet_showsTheCertificateLabel() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, VALID_CN)

        onView(withText(VALID_LABEL))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    // -----------------------------------------------------------------
    // Delete flow
    // -----------------------------------------------------------------

    @Test
    fun deleteCancelled_keepsTheCertificate() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, VALID_CN)
        onView(withText(R.string.trust_store_delete)).inRoot(isDialog()).perform(click())

        onView(withText(R.string.trust_store_delete_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Cancelling the delete dialog must keep the certificate",
            runBlocking { repository.hasCertificate(validFingerprint) }
        )
    }

    @Test
    fun deleteConfirmed_removesTheCertificateFromTheStore() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, VALID_CN)
        onView(withText(R.string.trust_store_delete)).inRoot(isDialog()).perform(click())

        // Wait for the bottom sheet to give way to the confirmation dialog before
        // clicking its positive button, which carries the same "Delete" label.
        onView(withText(R.string.trust_store_delete_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_delete)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Confirming the delete dialog must remove the certificate",
            awaitCondition { !runBlocking { repository.hasCertificate(validFingerprint) } }
        )
    }

    // -----------------------------------------------------------------
    // Import and clear-all dialogs
    // -----------------------------------------------------------------

    @Test
    fun importFromUrl_opensDialogAndCancelLeavesStoreUnchanged() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        val before = runBlocking { repository.getAllCertificates().size }

        clickTextInTree(scenario, "Import from URL")

        onView(withText(R.string.trust_store_import_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.trust_store_import_message))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))

        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        assertEquals(before, runBlocking { repository.getAllCertificates().size })
    }

    @Test
    fun bootstrapFromServer_opensDialogAndCancels() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        val before = runBlocking { repository.getAllCertificates().size }

        clickTextInTree(scenario, "Bootstrap from Server")

        onView(withText("Bootstrap from Server"))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))

        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        assertEquals(before, runBlocking { repository.getAllCertificates().size })
    }

    /**
     * "Clear All" is destructive for every suite that shares this device, so only
     * the cancel path is exercised; it must leave the store untouched.
     */
    @Test
    fun clearAllCancelled_keepsEveryCertificate() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInTree(scenario, VALID_CN)
        val before = runBlocking { repository.getAllCertificates().size }

        clickTextInTree(scenario, "Clear All")

        onView(withText(R.string.trust_store_clear_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        assertEquals(before, runBlocking { repository.getAllCertificates().size })
    }

    // -----------------------------------------------------------------
    // Back navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Polls [condition] because deletion runs on a coroutine. */
    private fun awaitCondition(condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + UI_AWAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(50)
        }
        return false
    }

    private companion object {
        const val TITLE = "Trust Store"
        const val SUBTITLE = "Manage trusted CA certificates"
        const val VALID_ALIAS = "xkey_uitest_truststore_valid"
        const val EXPIRED_ALIAS = "xkey_uitest_truststore_expired"
        const val VALID_CN = "xKey UI Test Valid CA"
        const val EXPIRED_CN = "xKey UI Test Expired CA"
        const val VALID_LABEL = "UI Test Valid Label"
        const val EXPIRED_LABEL = "UI Test Expired Label"
    }
}
