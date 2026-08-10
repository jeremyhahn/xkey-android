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

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.RootMatchers.isPlatformPopup
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ca.CertificateDao
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [CertificateManagementActivity].
 *
 * The screen builds its UI programmatically, observes `certificates` through a
 * Room `Flow`, and renders a filter chip bar over a RecyclerView with an empty
 * state behind it. These tests seed three certificates covering the three
 * interesting states -- valid TLS server, expired code-signing, revoked email --
 * so list binding, chip filtering, the summary badges, the row context menu and
 * the revoke/delete confirmations can all be asserted against known rows. Every
 * seeded row is deleted in @After.
 *
 * Expected counts are always recomputed from the DAO so that certificates left
 * behind by the app or other suites cannot break the assertions.
 *
 * Tests cover:
 * - Toolbar, filter bar and FAB rendering
 * - Adapter binding for each seeded certificate and its status badge
 * - Summary total and expired / revoked badges
 * - Filter chips actually filtering (profile, revoked, expired, back to all)
 * - Row tap navigating to [CertificateDetailActivity] with the serial number
 * - Long-press context menu, including the revoked certificate hiding "Revoke"
 * - Revoke and delete confirmations: cancel is a no-op, confirm mutates the DAO
 * - Issue-certificate dialog opening and cancelling
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class CertificateManagementActivityUiTest {

    private lateinit var dao: CertificateDao

    private val validSerial = "ui-certmgmt-valid-${System.nanoTime()}"
    private val expiredSerial = "ui-certmgmt-expired-${System.nanoTime()}"
    private val revokedSerial = "ui-certmgmt-revoked-${System.nanoTime()}"

    @Before
    fun setUp() {
        Intents.init()
        // Keep row taps from actually launching the detail screen; stubbing the
        // specific component leaves ActivityScenario's own launch untouched.
        intending(hasComponent(CertificateDetailActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, null)
        )

        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).certificateDao()

        val now = System.currentTimeMillis()
        runBlocking {
            // Distinct createdAt values keep the "ORDER BY created_at DESC"
            // ordering deterministic, so adapter positions can be derived
            // from the same DAO query the screen observes.
            dao.insert(
                certificate(
                    serial = validSerial,
                    cn = VALID_CN,
                    profile = "tls-server",
                    notAfter = now + 365L * ONE_DAY_MS,
                    createdAt = now
                )
            )
            dao.insert(
                certificate(
                    serial = expiredSerial,
                    cn = EXPIRED_CN,
                    profile = "code-signing",
                    notBefore = now - 400L * ONE_DAY_MS,
                    notAfter = now - ONE_DAY_MS,
                    createdAt = now - 1_000L
                )
            )
            dao.insert(
                certificate(
                    serial = revokedSerial,
                    cn = REVOKED_CN,
                    profile = "email",
                    notAfter = now + 365L * ONE_DAY_MS,
                    revoked = true,
                    revokedAt = now - ONE_DAY_MS,
                    createdAt = now - 2_000L
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            dao.deleteBySerial(validSerial)
            dao.deleteBySerial(expiredSerial)
            dao.deleteBySerial(revokedSerial)
        }
        Intents.release()
    }

    // -----------------------------------------------------------------
    // Chrome
    // -----------------------------------------------------------------

    @Test
    fun toolbar_showsTitleAndSubtitle() {
        val scenario = launch()

        assertShownTextInTree(scenario, withString(scenario, R.string.certificate_management_title))
        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.certificate_management_subtitle)
        )
    }

    @Test
    fun filterBar_rendersEveryFilterChip() {
        val scenario = launch()

        listOf(
            R.string.cert_filter_all,
            R.string.cert_filter_tls_server,
            R.string.cert_filter_code_signing,
            R.string.cert_filter_email,
            R.string.cert_filter_revoked,
            R.string.cert_filter_expired
        ).forEach { resId ->
            assertTextInTree(scenario, withString(scenario, resId))
        }
    }

    @Test
    fun fab_showsIssueCertificateAction() {
        val scenario = launch()

        assertShownTextInTree(scenario, withString(scenario, R.string.cert_issue_title))
    }

    // -----------------------------------------------------------------
    // List binding
    // -----------------------------------------------------------------

    @Test
    fun certificateList_bindsEverySeededCertificate() {
        val scenario = launch()

        assertShownTextInTree(scenario, VALID_CN)
        assertShownTextInTree(scenario, EXPIRED_CN)
        assertShownTextInTree(scenario, REVOKED_CN)
    }

    /**
     * Status and profile labels also appear on the filter chips, so these
     * assertions are scoped to the list rows.
     */
    @Test
    fun certificateList_showsProfileAndStatusBadges() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        assertTextInList(scenario, withString(scenario, R.string.cert_status_expired))
        assertTextInList(scenario, withString(scenario, R.string.cert_status_revoked))
        assertTextInList(scenario, withString(scenario, R.string.cert_filter_code_signing))
    }

    @Test
    fun certificateList_itemCountMatchesDatabase() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        val expected = runBlocking { dao.getAll().size }
        assertTrue(
            "Unfiltered list should bind every stored certificate",
            awaitExactRecyclerItemCount(scenario, expected)
        )
    }

    // -----------------------------------------------------------------
    // Summary hero card
    // -----------------------------------------------------------------

    @Test
    fun summaryCard_totalMatchesDatabase() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        val expected = runBlocking { dao.getAll().size }
        assertExactTextShown(scenario, expected.toString())
    }

    @Test
    fun summaryCard_showsExpiredAndRevokedBadges() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        val now = System.currentTimeMillis()
        val all = runBlocking { dao.getAll() }
        val expiredCount = all.count { it.notAfter < now && !it.revoked }
        val revokedCount = all.count { it.revoked }

        assertShownTextInTree(
            scenario,
            "$expiredCount ${withString(scenario, R.string.cert_summary_expired)}"
        )
        assertShownTextInTree(
            scenario,
            "$revokedCount ${withString(scenario, R.string.cert_summary_revoked)}"
        )
    }

    // -----------------------------------------------------------------
    // Filtering
    // -----------------------------------------------------------------

    @Test
    fun expiredFilter_showsOnlyExpiredCertificates() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        clickClickableWithExactText(scenario, withString(scenario, R.string.cert_filter_expired))

        val now = System.currentTimeMillis()
        val expected = runBlocking { dao.getAll().count { it.notAfter < now && !it.revoked } }
        assertTrue(
            "Expired filter should bind only the expired certificates",
            awaitExactRecyclerItemCount(scenario, expected)
        )
        assertShownTextInTree(scenario, EXPIRED_CN)
        assertTextNotInTree(scenario, VALID_CN)
    }

    @Test
    fun revokedFilter_showsOnlyRevokedCertificates() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        clickClickableWithExactText(scenario, withString(scenario, R.string.cert_filter_revoked))

        val expected = runBlocking { dao.getAll().count { it.revoked } }
        assertTrue(
            "Revoked filter should bind only the revoked certificates",
            awaitExactRecyclerItemCount(scenario, expected)
        )
        assertShownTextInTree(scenario, REVOKED_CN)
        assertTextNotInTree(scenario, VALID_CN)
    }

    @Test
    fun profileFilter_showsOnlyMatchingProfile() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        clickClickableWithExactText(
            scenario,
            withString(scenario, R.string.cert_filter_code_signing)
        )

        val expected = runBlocking { dao.getAll().count { it.profile == "code-signing" } }
        assertTrue(
            "Code-signing filter should bind only code-signing certificates",
            awaitExactRecyclerItemCount(scenario, expected)
        )
        assertShownTextInTree(scenario, EXPIRED_CN)
        assertTextNotInTree(scenario, REVOKED_CN)
    }

    @Test
    fun allFilter_restoresTheFullListAfterFiltering() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        clickClickableWithExactText(scenario, withString(scenario, R.string.cert_filter_revoked))
        assertTextNotInTree(scenario, VALID_CN)

        clickClickableWithExactText(scenario, withString(scenario, R.string.cert_filter_all))

        val expected = runBlocking { dao.getAll().size }
        assertTrue(
            "Selecting All should restore every certificate",
            awaitExactRecyclerItemCount(scenario, expected)
        )
        assertShownTextInTree(scenario, VALID_CN)
    }

    /**
     * A filter that matches nothing must swap the list for the empty state. The
     * OCSP profile is never seeded here, so the expectation is derived from the
     * DAO rather than assumed.
     */
    @Test
    fun filterWithNoMatches_showsEmptyState() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        val expected = runBlocking { dao.getAll().count { it.profile == "ocsp-responder" } }

        clickClickableWithExactText(scenario, withString(scenario, R.string.cert_filter_ocsp))

        assertTrue(
            "OCSP filter should bind only OCSP certificates",
            awaitExactRecyclerItemCount(scenario, expected)
        )
        if (expected == 0) {
            assertShownTextInTree(scenario, withString(scenario, R.string.cert_empty_title))
        }
    }

    // -----------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------

    @Test
    fun certificateRowTap_opensDetailWithSerialNumber() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, VALID_CN)

        intended(
            allOf(
                hasComponent(CertificateDetailActivity::class.java.name),
                hasExtra(CertificateDetailActivity.EXTRA_SERIAL_NUMBER, validSerial)
            )
        )
    }

    // -----------------------------------------------------------------
    // Context menu
    // -----------------------------------------------------------------

    @Test
    fun longPress_opensContextMenuWithRevokeForAnActiveCertificate() {
        val scenario = launch()
        val position = awaitPositionOf(scenario, validSerial)

        longClickRecyclerItem(scenario, position)

        onView(withText(R.string.cert_revoke_title))
            .inRoot(isPlatformPopup())
            .check(matches(isDisplayed()))
        onView(withText(R.string.cert_delete_title))
            .inRoot(isPlatformPopup())
            .check(matches(isDisplayed()))
    }

    @Test
    fun revokeConfirmationCancelled_leavesCertificateActive() {
        val scenario = launch()
        val position = awaitPositionOf(scenario, validSerial)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.cert_revoke_title)).inRoot(isPlatformPopup()).perform(click())

        onView(withText(R.string.cert_revoke_message))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertFalse(
            "Cancelling revocation must leave the certificate active",
            runBlocking { dao.getBySerial(validSerial)!!.revoked }
        )
    }

    @Test
    fun revokeConfirmed_marksCertificateRevokedInTheDatabase() {
        val scenario = launch()
        val position = awaitPositionOf(scenario, validSerial)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.cert_revoke_title)).inRoot(isPlatformPopup()).perform(click())
        onView(withText(R.string.cert_revoke_confirm)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Confirming revocation must persist revoked = true",
            awaitCondition { runBlocking { dao.getBySerial(validSerial)?.revoked == true } }
        )
    }

    @Test
    fun deleteConfirmationCancelled_keepsTheCertificateRow() {
        val scenario = launch()
        val position = awaitPositionOf(scenario, validSerial)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.cert_delete_title)).inRoot(isPlatformPopup()).perform(click())

        onView(withText(R.string.cert_delete_message))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Cancelling delete must keep the certificate",
            runBlocking { dao.getBySerial(validSerial) != null }
        )
        assertShownTextInTree(scenario, VALID_CN)
    }

    @Test
    fun deleteConfirmed_removesTheCertificateFromDatabaseAndList() {
        val scenario = launch()
        val position = awaitPositionOf(scenario, validSerial)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.cert_delete_title)).inRoot(isPlatformPopup()).perform(click())
        onView(withText(R.string.cert_delete_confirm)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Confirming delete must remove the certificate row",
            awaitCondition { runBlocking { dao.getBySerial(validSerial) == null } }
        )
        assertTextNotInTree(scenario, VALID_CN)
    }

    // -----------------------------------------------------------------
    // Issue dialog
    // -----------------------------------------------------------------

    @Test
    fun issueCertificateDialog_opensWithProfileAndSubjectFields() {
        val scenario = launch()

        clickClickableWithExactText(scenario, withString(scenario, R.string.cert_issue_title))

        onView(withText(R.string.cert_issue_profile))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.cert_issue_subject_cn))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    @Test
    fun issueCertificateDialogCancelled_addsNoCertificate() {
        val scenario = launch()
        assertShownTextInTree(scenario, VALID_CN)
        val before = runBlocking { dao.getAll().size }

        clickClickableWithExactText(scenario, withString(scenario, R.string.cert_issue_title))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertEquals(before, runBlocking { dao.getAll().size })
    }

    // -----------------------------------------------------------------
    // Back navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launch()

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<CertificateManagementActivity> =
        ActivityScenario.launch(CertificateManagementActivity::class.java)

    private fun withString(
        scenario: ActivityScenario<CertificateManagementActivity>,
        resId: Int
    ): String = withActivity(scenario) { it.getString(resId) }

    /**
     * Waits for the adapter to bind [serial] and returns its adapter position.
     * The list is ordered by creation time, so the position is not fixed.
     */
    private fun awaitPositionOf(
        scenario: ActivityScenario<CertificateManagementActivity>,
        serial: String
    ): Int {
        val cn = when (serial) {
            validSerial -> VALID_CN
            expiredSerial -> EXPIRED_CN
            else -> REVOKED_CN
        }
        assertShownTextInTree(scenario, cn)

        val ordered = runBlocking { dao.getAll() }
        val position = ordered.indexOfFirst { it.serialNumber == serial }
        assertTrue("Seeded certificate $serial should be present", position >= 0)
        assertTrue(
            "Adapter should have bound at least ${position + 1} rows",
            awaitRecyclerItemCount(scenario, position + 1)
        )
        return position
    }

    private fun awaitCondition(condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + UI_AWAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(50)
        }
        return false
    }

    private fun certificate(
        serial: String,
        cn: String,
        profile: String,
        notBefore: Long = System.currentTimeMillis() - ONE_DAY_MS,
        notAfter: Long,
        revoked: Boolean = false,
        revokedAt: Long? = null,
        createdAt: Long = System.currentTimeMillis()
    ) = CertificateEntity(
        serialNumber = serial,
        subjectDN = "CN=$cn,O=Automate The Things",
        issuerDN = "CN=xKey Test CA,O=Automate The Things",
        notBefore = notBefore,
        notAfter = notAfter,
        profile = profile,
        fingerprint = "fp-$serial",
        certificatePEM = "",
        revoked = revoked,
        revokedAt = revokedAt,
        revokedReason = if (revoked) 0 else null,
        createdAt = createdAt
    )

    private companion object {
        const val ONE_DAY_MS = 86_400_000L
        const val VALID_CN = "UI CertMgmt Valid"
        const val EXPIRED_CN = "UI CertMgmt Expired"
        const val REVOKED_CN = "UI CertMgmt Revoked"
    }
}
