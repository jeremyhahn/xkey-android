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
import android.content.Intent
import androidx.lifecycle.Lifecycle
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
import com.automatethethings.xkey.ca.CertificateDao
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [CertificateDetailActivity].
 *
 * The screen renders nothing on its own: the collapsing toolbar disables its
 * title and every card is built only after the certificate has been loaded from
 * Room. These tests therefore seed three certificates -- a valid one carrying a
 * real PEM, an already-expired one and a revoked one -- and assert the cards,
 * badges and actions each state produces. All seeded rows are removed in @After.
 *
 * The valid certificate's PEM comes from [TestCertificates] so that the security
 * card can parse a genuine X.509 and report a signature algorithm, which is the
 * only way to reach `buildSecurityCard`'s parsed branch.
 *
 * Tests cover:
 * - Launch behavior: finishes without the extra, and for an unknown serial
 * - Hero: subject common name and status badge
 * - General info, validity and security cards
 * - Expired and revoked rendering, including the revocation card
 * - Actions card contents, and the revoked certificate hiding "Revoke"
 * - Delete and revoke confirmations mutating (or not mutating) the database
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class CertificateDetailActivityUiTest {

    private lateinit var dao: CertificateDao

    private val validSerial = "ui-certdetail-valid-${System.nanoTime()}"
    private val expiredSerial = "ui-certdetail-expired-${System.nanoTime()}"
    private val revokedSerial = "ui-certdetail-revoked-${System.nanoTime()}"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).certificateDao()

        val now = System.currentTimeMillis()
        runBlocking {
            dao.insert(
                CertificateEntity(
                    serialNumber = validSerial,
                    subjectDN = "CN=$VALID_CN,O=Automate The Things",
                    issuerDN = ISSUER_DN,
                    notBefore = now - ONE_DAY_MS,
                    notAfter = now + 365L * ONE_DAY_MS,
                    profile = "tls-server",
                    fingerprint = TEST_FINGERPRINT,
                    certificatePEM = validPem
                )
            )
            dao.insert(
                CertificateEntity(
                    serialNumber = expiredSerial,
                    subjectDN = "CN=$EXPIRED_CN,O=Automate The Things",
                    issuerDN = ISSUER_DN,
                    notBefore = now - 400L * ONE_DAY_MS,
                    notAfter = now - ONE_DAY_MS,
                    profile = "code-signing",
                    fingerprint = "ff".repeat(32),
                    certificatePEM = ""
                )
            )
            dao.insert(
                CertificateEntity(
                    serialNumber = revokedSerial,
                    subjectDN = "CN=$REVOKED_CN,O=Automate The Things",
                    issuerDN = ISSUER_DN,
                    notBefore = now - ONE_DAY_MS,
                    notAfter = now + 365L * ONE_DAY_MS,
                    profile = "email",
                    fingerprint = "ee".repeat(32),
                    certificatePEM = "",
                    revoked = true,
                    revokedAt = now - ONE_DAY_MS,
                    revokedReason = 0
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
    }

    // -----------------------------------------------------------------
    // Launch behavior
    // -----------------------------------------------------------------

    /**
     * When launched without [CertificateDetailActivity.EXTRA_SERIAL_NUMBER], the
     * activity should call finish() immediately in onCreate and reach DESTROYED.
     */
    @Test
    fun activity_finishesWithoutSerialNumber() {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            CertificateDetailActivity::class.java
        )
        val scenario = ActivityScenario.launch<CertificateDetailActivity>(intent)

        assertTrue(
            "Activity should finish when launched without EXTRA_SERIAL_NUMBER",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    /** An unknown serial number resolves to no row, so the screen closes itself. */
    @Test
    fun activity_finishesWhenSerialNumberIsUnknown() {
        val scenario = launch("ui-certdetail-does-not-exist")

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Hero
    // -----------------------------------------------------------------

    @Test
    fun heroSection_showsSubjectCommonNameAndValidStatus() {
        val scenario = launch(validSerial)

        assertShownTextInTree(scenario, VALID_CN)
        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.cert_detail_status_valid)
        )
    }

    @Test
    fun heroSection_showsProfileBadge() {
        val scenario = launch(validSerial)

        assertShownTextInTree(scenario, withString(scenario, R.string.cert_filter_tls_server))
    }

    // -----------------------------------------------------------------
    // Cards
    // -----------------------------------------------------------------

    @Test
    fun generalInfoCard_showsSubjectIssuerAndSerial() {
        val scenario = launch(validSerial)

        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_general_info))
        assertTextInTree(scenario, "CN=$VALID_CN,O=Automate The Things")
        assertTextInTree(scenario, ISSUER_DN)
        assertTextInTree(scenario, validSerial)
    }

    @Test
    fun validityCard_showsValidFromAndValidUntilLabels() {
        val scenario = launch(validSerial)

        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_validity))
        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_not_before))
        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_not_after))
    }

    @Test
    fun securityCard_showsFormattedFingerprint() {
        val scenario = launch(validSerial)

        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_security))
        assertTextInTree(
            scenario,
            TEST_FINGERPRINT.uppercase().chunked(2).joinToString(":")
        )
    }

    /**
     * A parseable PEM lets the security card report the signature algorithm; an
     * empty PEM would silently omit that row.
     */
    @Test
    fun securityCard_showsSignatureAlgorithmForAParseableCertificate() {
        val scenario = launch(validSerial)

        assertTextInTree(
            scenario,
            withString(scenario, R.string.cert_detail_signature_algorithm)
        )
    }

    // -----------------------------------------------------------------
    // Expired and revoked rendering
    // -----------------------------------------------------------------

    @Test
    fun expiredCertificate_showsExpiredStatus() {
        val scenario = launch(expiredSerial)

        assertShownTextInTree(scenario, EXPIRED_CN)
        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.cert_detail_status_expired)
        )
    }

    @Test
    fun revokedCertificate_showsRevocationCard() {
        val scenario = launch(revokedSerial)

        assertShownTextInTree(scenario, REVOKED_CN)
        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_revocation))
        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_revoke_reason))
    }

    /** A valid certificate has nothing to report, so the card is not built. */
    @Test
    fun validCertificate_omitsRevocationCard() {
        val scenario = launch(validSerial)
        assertShownTextInTree(scenario, VALID_CN)

        assertTextNotInTree(scenario, withString(scenario, R.string.cert_detail_revocation))
    }

    // -----------------------------------------------------------------
    // Actions card
    // -----------------------------------------------------------------

    @Test
    fun actionsCard_offersExportAndDelete() {
        val scenario = launch(validSerial)

        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_export))
        assertTextInTree(scenario, withString(scenario, R.string.cert_detail_delete))
    }

    @Test
    fun actionsCard_hidesRevokeForAnAlreadyRevokedCertificate() {
        val scenario = launch(revokedSerial)
        assertShownTextInTree(scenario, REVOKED_CN)

        assertTextNotInTree(scenario, withString(scenario, R.string.cert_detail_revoke))
    }

    @Test
    fun deleteCancelled_keepsTheCertificate() {
        val scenario = launch(validSerial)
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, withString(scenario, R.string.cert_detail_delete))

        onView(withText(R.string.cert_delete_message))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Cancelling delete must keep the certificate row",
            runBlocking { dao.getBySerial(validSerial) != null }
        )
    }

    @Test
    fun deleteConfirmed_removesTheCertificate() {
        val scenario = launch(validSerial)
        assertShownTextInTree(scenario, VALID_CN)

        clickTextInTree(scenario, withString(scenario, R.string.cert_detail_delete))
        onView(withText(R.string.cert_delete_confirm)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Confirming delete must remove the certificate row",
            awaitCondition { runBlocking { dao.getBySerial(validSerial) == null } }
        )
    }

    // -----------------------------------------------------------------
    // Back navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launch(validSerial)
        assertShownTextInTree(scenario, VALID_CN)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(serial: String): ActivityScenario<CertificateDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            CertificateDetailActivity::class.java
        ).apply {
            putExtra(CertificateDetailActivity.EXTRA_SERIAL_NUMBER, serial)
        }
        return ActivityScenario.launch(intent)
    }

    private fun withString(
        scenario: ActivityScenario<CertificateDetailActivity>,
        resId: Int
    ): String = withActivity(scenario) { it.getString(resId) }

    private fun awaitCondition(condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + UI_AWAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(50)
        }
        return false
    }

    companion object {
        private const val ONE_DAY_MS = 86_400_000L
        private const val VALID_CN = "UI CertDetail Valid"
        private const val EXPIRED_CN = "UI CertDetail Expired"
        private const val REVOKED_CN = "UI CertDetail Revoked"
        private const val ISSUER_DN = "CN=xKey Test CA,O=Automate The Things"
        private const val TEST_FINGERPRINT =
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        private const val KEY_ALIAS = "xkey_uitest_certdetail"

        /** PEM of a real certificate, generated once for the whole class. */
        private lateinit var validPem: String

        @BeforeClass
        @JvmStatic
        fun generateCertificate() {
            validPem = TestCertificates.toPem(
                TestCertificates.selfSigned(KEY_ALIAS, VALID_CN)
            )
        }

        @AfterClass
        @JvmStatic
        fun removeCertificate() {
            TestCertificates.deleteAlias(KEY_ALIAS)
        }
    }
}
