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
import android.view.View
import android.widget.EditText
import android.widget.Spinner
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.closeSoftKeyboard
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.UiController
import androidx.test.espresso.ViewAction
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.action.ViewActions.scrollTo
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.RootMatchers.isPlatformPopup
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.CASubject
import com.automatethethings.xkey.ca.CaTestSupport
import com.automatethethings.xkey.ca.CertificateDao
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matcher
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.not
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Certificate issuance and context-menu flows for [CertificateManagementActivity].
 *
 * `CertificateManagementActivityUiTest` opens the issue dialog and cancels it,
 * which leaves `issueCertificate` -- key generation, CSR creation, profile
 * selection, signing and persistence -- completely unreached. This suite runs
 * that flow for real against a CA generated in @BeforeClass, and asserts on the
 * certificate that comes out rather than on the success snackbar: the subject,
 * the issuer chaining back to the intermediate CA, the validity window derived
 * from the dialog, and the subject alternative names parsed out of the SAN
 * field.
 *
 * It also covers the context-menu actions the existing suite skips: exporting
 * the PEM to the clipboard, opening the detail screen, and the revoked
 * certificate hiding the revoke entry.
 *
 * ## Shared state
 *
 * The CA is device-wide, and the app ships uninitialised, so @BeforeClass
 * resets it, generates a hierarchy of its own, and @AfterClass resets it again.
 * Issuance also writes to the shared `certificates` and `keys` tables and to
 * Android Keystore: every row and alias that did not exist before a test is
 * removed after it, and the audit rows issuance produces are deleted once the
 * class finishes.
 *
 * Tests cover:
 * - Issuing for the default TLS-server profile, with DNS and IP SANs
 * - Issuing for a profile chosen from the spinner, with e-mail SANs
 * - Profile selection driving the validity default and the SAN field visibility
 * - The subordinate-CA profile producing a CA certificate
 * - An emptied validity field falling back to the profile default
 * - Context menu: export PEM to the clipboard, view details, and revoke being
 *   absent for an already-revoked certificate
 * - The expiring-soon summary badge
 */
@RunWith(AndroidJUnit4::class)
class CertificateIssuanceFlowTest {

    private lateinit var context: Context
    private lateinit var dao: CertificateDao
    private lateinit var keyDao: KeyDao

    /** Rows that existed before the test, so only new ones are cleaned up. */
    private var serialsBefore: Set<String> = emptySet()
    private var keyIdsBefore: Set<String> = emptySet()

    /** Serials this test seeded directly. */
    private val seededSerials = mutableListOf<String>()

    private val runId = System.nanoTime()

    @Before
    fun setUp() {
        Intents.init()
        // Row taps and the detail menu item both start the detail screen;
        // stubbing the component leaves ActivityScenario's own launch alone.
        intending(hasComponent(CertificateDetailActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, null)
        )

        context = ApplicationProvider.getApplicationContext()

        // The CA lives in the Keystore and is shared across the whole
        // instrumentation run; the AndroidCA suites reset it in @AfterClass.
        // Without this every issuance here would hit the "CA not initialised"
        // dialog, write nothing, and fail as a timeout rather than an error.
        CaTestSupport.ensureInitialized(context)

        dao = XKeyDatabase.getInstance(context).certificateDao()
        keyDao = XKeyDatabase.getInstance(context).keyDao()

        runBlocking {
            serialsBefore = dao.getAll().map { it.serialNumber }.toSet()
            keyIdsBefore = keyDao.getAll().map { it.keyId }.toSet()
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            seededSerials.forEach { dao.deleteBySerial(it) }
            dao.getAll()
                .filter { it.serialNumber !in serialsBefore }
                .forEach { dao.deleteBySerial(it.serialNumber) }
            keyDao.getAll()
                .filter { it.keyId !in keyIdsBefore }
                .forEach {
                    keyDao.deleteByKeyId(it.keyId)
                    TestCertificates.deleteAlias("xkey_key_${it.keyId}")
                }
        }
        Intents.release()
    }

    // -----------------------------------------------------------------
    // Issuance
    // -----------------------------------------------------------------

    /**
     * The default profile, driven entirely through the dialog. Everything
     * asserted here comes out of the issued certificate itself, so a change that
     * silently stopped applying the dialog's input would fail.
     */
    @Test
    fun issueCertificate_forTheDefaultProfile_persistsASignedTlsServerCertificate() {
        val scenario = launch()
        val commonName = "ui-issue-tls-$runId"

        openIssueDialog(scenario)
        typeInto(R.string.cert_issue_subject_cn_hint, commonName)
        typeInto(R.string.cert_issue_organization_hint, ORGANISATION)
        setValidity(TLS_VALIDITY_DAYS.toString())
        typeInto(R.string.cert_issue_sans_hint, "$DNS_SAN\n$IP_SAN")
        closeSoftKeyboard()
        clickPositiveButton()

        val entity = awaitIssuedCertificate(commonName)
        assertEquals("tls-server", entity.profile)

        val certificate = parsePem(entity.certificatePEM)
        val subject = certificate.subjectX500Principal.name
        assertTrue("Subject $subject should carry the entered CN", subject.contains("CN=$commonName"))
        assertTrue("Subject $subject should carry the entered O", subject.contains("O=$ORGANISATION"))
        assertEquals(
            "The certificate must chain to the intermediate CA",
            AndroidCA(context).getIntermediateCertificate().subjectX500Principal,
            certificate.issuerX500Principal
        )

        val days = (certificate.notAfter.time - certificate.notBefore.time) / ONE_DAY_MS
        assertTrue(
            "Validity was $days days, expected about $TLS_VALIDITY_DAYS",
            days >= TLS_VALIDITY_DAYS - 1 && days <= TLS_VALIDITY_DAYS
        )

        val sans = certificate.subjectAlternativeNames ?: emptyList()
        assertTrue(
            "The DNS SAN should have been applied, got $sans",
            sans.any { it[0] == SAN_TYPE_DNS && it[1] == DNS_SAN }
        )
        assertTrue(
            "The IP SAN should have been applied, got $sans",
            sans.any { it[0] == SAN_TYPE_IP && it[1] == IP_SAN }
        )

        // The signing key is recorded alongside the certificate.
        val label = "$commonName (${string(scenario, R.string.cert_filter_tls_server)})"
        assertNotNull(
            "A key row should have been created for the new certificate",
            runBlocking { keyDao.getAll() }.firstOrNull { it.label == label }
        )
        assertShownTextInList(scenario, commonName)
    }

    /** The spinner selection has to reach the issued certificate's profile. */
    @Test
    fun issueCertificate_forTheEmailProfile_appliesTheEmailSan() {
        val scenario = launch()
        val commonName = "ui-issue-email-$runId"

        openIssueDialog(scenario)
        selectProfile(PROFILE_INDEX_EMAIL)
        typeInto(R.string.cert_issue_subject_cn_hint, commonName)
        typeInto(R.string.cert_issue_email_hint, EMAIL_SAN)
        closeSoftKeyboard()
        clickPositiveButton()

        val entity = awaitIssuedCertificate(commonName)
        assertEquals("email", entity.profile)

        val sans = parsePem(entity.certificatePEM).subjectAlternativeNames ?: emptyList()
        assertTrue(
            "The e-mail SAN should have been applied, got $sans",
            sans.any { it[0] == SAN_TYPE_RFC822 && it[1] == EMAIL_SAN }
        )
    }

    /**
     * Each profile carries its own default lifetime, and the SAN field is only
     * meaningful for the three profiles that put names in the certificate.
     */
    @Test
    fun profileSelection_updatesTheValidityDefaultAndHidesUnusedSans() {
        val scenario = launch()

        openIssueDialog(scenario)

        selectProfile(PROFILE_INDEX_OCSP)
        assertValidityReads(OCSP_VALIDITY_DAYS.toString())
        onView(withHint(R.string.cert_issue_sans_hint))
            .inRoot(isDialog())
            .check(matches(not(isDisplayed())))

        selectProfile(PROFILE_INDEX_TLS_CLIENT)
        assertValidityReads(TLS_CLIENT_VALIDITY_DAYS.toString())
        // The client profile swaps the hint over to e-mail addresses.
        onView(withHint(R.string.cert_issue_email_hint))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))

        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())
        assertEquals(
            "Cancelling must not issue anything",
            0,
            runBlocking { dao.getAll() }.count { it.serialNumber !in serialsBefore }
        )
    }

    /** A subordinate CA has to come out flagged as a CA in the store. */
    @Test
    fun issueCertificate_forTheSubordinateCaProfile_marksTheRowAsACa() {
        val scenario = launch()
        val commonName = "ui-issue-subca-$runId"

        openIssueDialog(scenario)
        selectProfile(PROFILE_INDEX_SUBORDINATE_CA)
        typeInto(R.string.cert_issue_subject_cn_hint, commonName)
        closeSoftKeyboard()
        clickPositiveButton()

        val entity = awaitIssuedCertificate(commonName)
        assertEquals("subordinate-ca", entity.profile)
        assertTrue("A subordinate CA must be stored with isCA set", entity.isCA)
        assertTrue(
            "A subordinate CA certificate must carry a CA basic constraint",
            parsePem(entity.certificatePEM).basicConstraints >= 0
        )
        assertShownTextInList(scenario, commonName)
    }

    /** An emptied validity field must not produce a zero-day certificate. */
    @Test
    fun issueCertificate_withAnEmptiedValidity_fallsBackToTheProfileDefault() {
        val scenario = launch()
        val commonName = "ui-issue-default-validity-$runId"

        openIssueDialog(scenario)
        typeInto(R.string.cert_issue_subject_cn_hint, commonName)
        setValidity("")
        closeSoftKeyboard()
        clickPositiveButton()

        val certificate = parsePem(awaitIssuedCertificate(commonName).certificatePEM)
        val days = (certificate.notAfter.time - certificate.notBefore.time) / ONE_DAY_MS
        assertTrue(
            "Validity was $days days, expected the profile default of $DEFAULT_VALIDITY_DAYS",
            days >= DEFAULT_VALIDITY_DAYS - 1 && days <= DEFAULT_VALIDITY_DAYS
        )
    }

    // -----------------------------------------------------------------
    // Context menu
    // -----------------------------------------------------------------

    @Test
    fun contextMenuExport_copiesTheCertificatePemToTheClipboard() {
        val serial = seedCertificate(EXPORT_CN, "tls-server")
        val scenario = launch()
        val position = rowPositionOf(scenario, serial, EXPORT_CN)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.cert_export_action)).inRoot(isPlatformPopup()).perform(click())

        val copied = withActivity(scenario) { activity ->
            val clipboard =
                activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.primaryClip?.getItemAt(0)?.text?.toString()
        }
        assertEquals(pemFor(serial), copied)
    }

    @Test
    fun contextMenuDetails_opensTheDetailScreenForThatCertificate() {
        val serial = seedCertificate(DETAIL_CN, "tls-server")
        val scenario = launch()
        val position = rowPositionOf(scenario, serial, DETAIL_CN)

        longClickRecyclerItem(scenario, position)
        onView(withText(R.string.cert_detail_title)).inRoot(isPlatformPopup()).perform(click())

        intended(
            allOf(
                hasComponent(CertificateDetailActivity::class.java.name),
                hasExtra(CertificateDetailActivity.EXTRA_SERIAL_NUMBER, serial)
            )
        )
    }

    /** Revoking twice is meaningless, so the entry is not offered. */
    @Test
    fun contextMenuForARevokedCertificate_omitsRevoke() {
        val serial = seedCertificate(REVOKED_CN, "email", revoked = true)
        val scenario = launch()
        val position = rowPositionOf(scenario, serial, REVOKED_CN)

        longClickRecyclerItem(scenario, position)

        onView(withText(R.string.cert_delete_title))
            .inRoot(isPlatformPopup())
            .check(matches(isDisplayed()))
        onView(withText(R.string.cert_revoke_title)).inRoot(isPlatformPopup()).check(doesNotExist())
    }

    // -----------------------------------------------------------------
    // Summary badges
    // -----------------------------------------------------------------

    /**
     * A certificate inside the 30-day window gets its own badge, distinct from
     * the expired one.
     */
    @Test
    fun summaryCard_showsTheExpiringBadge() {
        val now = System.currentTimeMillis()
        seedCertificate(EXPIRING_CN, "tls-server", notAfter = now + 10L * ONE_DAY_MS)
        val scenario = launch()
        assertShownTextInList(scenario, EXPIRING_CN)

        val threshold = now + EXPIRING_WINDOW_DAYS * ONE_DAY_MS
        val expected = runBlocking { dao.getAll() }.count {
            !it.revoked && it.notAfter >= now && it.notAfter < threshold
        }
        assertTrue("The seeded certificate should be counted as expiring", expected >= 1)
        assertShownTextInTree(
            scenario,
            "$expected ${string(scenario, R.string.cert_summary_expiring)}"
        )
        assertTextInList(scenario, string(scenario, R.string.cert_status_expiring))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<CertificateManagementActivity> =
        ActivityScenario.launch(CertificateManagementActivity::class.java)

    private fun string(
        scenario: ActivityScenario<CertificateManagementActivity>,
        resId: Int
    ): String = withActivity(scenario) { it.getString(resId) }

    private fun openIssueDialog(scenario: ActivityScenario<CertificateManagementActivity>) {
        clickClickableWithExactText(scenario, string(scenario, R.string.cert_issue_title))
        onView(withText(R.string.cert_issue_profile))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    /**
     * Clicks the dialog's positive button by id: it carries the same label as
     * the dialog title and as the FAB, so a text matcher would be ambiguous.
     */
    private fun clickPositiveButton() {
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())
    }

    /** Fills the uniquely-hinted field [hintRes], scrolling it into view first. */
    private fun typeInto(hintRes: Int, text: String) {
        onView(withHint(hintRes))
            .inRoot(isDialog())
            .perform(scrollTo(), replaceText(text))
    }

    /**
     * The validity field is the only input in the dialog without a hint, so it
     * is addressed positionally. Each [nthMatch] is good for a single traversal,
     * hence the two interactions.
     */
    private fun setValidity(days: String) {
        onView(nthMatch(isAssignableFrom(EditText::class.java), VALIDITY_FIELD_INDEX))
            .inRoot(isDialog())
            .perform(scrollTo())
        onView(nthMatch(isAssignableFrom(EditText::class.java), VALIDITY_FIELD_INDEX))
            .inRoot(isDialog())
            .perform(replaceText(days))
    }

    private fun assertValidityReads(days: String) {
        onView(nthMatch(isAssignableFrom(EditText::class.java), VALIDITY_FIELD_INDEX))
            .inRoot(isDialog())
            .check(matches(withText(days)))
    }

    private fun selectProfile(index: Int) {
        onView(isAssignableFrom(Spinner::class.java))
            .inRoot(isDialog())
            .perform(setSpinnerSelection(index))
    }

    /**
     * Sets a [Spinner]'s selection directly.
     *
     * Opening the dropdown and picking an item would work, but the popup is a
     * separate window whose row text repeats the filter-chip labels already on
     * screen; setting the selection drives the same `onItemSelected` callback
     * without that ambiguity.
     */
    private fun setSpinnerSelection(index: Int): ViewAction = object : ViewAction {

        override fun getConstraints(): Matcher<View> = isAssignableFrom(Spinner::class.java)

        override fun getDescription(): String = "set spinner selection to $index"

        override fun perform(uiController: UiController, view: View) {
            (view as Spinner).setSelection(index)
            uiController.loopMainThreadUntilIdle()
        }
    }

    /**
     * Waits for a certificate whose subject carries [commonName] and that did
     * not exist before the test.
     *
     * Issuance generates a Keystore key, builds a CSR and signs it, which is far
     * slower than the default polling budget on an emulator.
     */
    private fun awaitIssuedCertificate(commonName: String): CertificateEntity {
        awaitCondition(
            timeoutMs = ISSUE_TIMEOUT_MS,
            describe = {
                "A certificate for CN=$commonName should have been issued. " +
                    "Rows not present at setUp: ${describeNewRows()}"
            }
        ) {
            issuedCertificates(commonName).isNotEmpty()
        }
        return issuedCertificates(commonName).first()
    }

    /** Every row this test did not start with, for diagnosing a missed match. */
    private fun describeNewRows(): String =
        runBlocking { dao.getAll() }
            .filter { it.serialNumber !in serialsBefore }
            .joinToString("; ") { "[serial=${it.serialNumber} profile=${it.profile} subject=${it.subjectDN}]" }
            .ifEmpty { "(none)" }

    private fun issuedCertificates(commonName: String): List<CertificateEntity> =
        runBlocking { dao.getAll() }.filter {
            it.serialNumber !in serialsBefore && it.subjectDN.contains("CN=$commonName")
        }

    /**
     * Waits for the row carrying [commonName] and returns its adapter position.
     * The list is ordered by creation time, so the position is not fixed.
     */
    private fun rowPositionOf(
        scenario: ActivityScenario<CertificateManagementActivity>,
        serial: String,
        commonName: String
    ): Int {
        assertShownTextInList(scenario, commonName)
        val position = runBlocking { dao.getAll() }.indexOfFirst { it.serialNumber == serial }
        assertTrue("The seeded certificate should be stored", position >= 0)
        assertTrue(
            "The adapter should have bound at least ${position + 1} rows",
            awaitRecyclerItemCount(scenario, position + 1)
        )
        return position
    }

    /** Inserts a certificate row and registers its serial for cleanup. */
    private fun seedCertificate(
        commonName: String,
        profile: String,
        revoked: Boolean = false,
        notAfter: Long = System.currentTimeMillis() + 365L * ONE_DAY_MS
    ): String {
        val serial = "ui-issueflow-${seededSerials.size}-$runId"
        seededSerials += serial
        runBlocking {
            dao.insert(
                CertificateEntity(
                    serialNumber = serial,
                    subjectDN = "CN=$commonName,O=$ORGANISATION",
                    issuerDN = "CN=xKey UI Flow CA,O=$ORGANISATION",
                    notBefore = System.currentTimeMillis() - ONE_DAY_MS,
                    notAfter = notAfter,
                    profile = profile,
                    fingerprint = "fp-$serial",
                    certificatePEM = pemFor(serial),
                    revoked = revoked,
                    revokedAt = if (revoked) System.currentTimeMillis() else null,
                    revokedReason = if (revoked) 0 else null
                )
            )
        }
        return serial
    }

    /** A recognisable stand-in for real PEM, used by the clipboard assertion. */
    private fun pemFor(serial: String): String =
        "-----BEGIN CERTIFICATE-----\n$serial\n-----END CERTIFICATE-----"

    private fun parsePem(pem: String): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(pem.toByteArray())) as X509Certificate

    // JUnit needs the lifecycle hooks below to be public statics, so the
    // companion cannot be private.
    companion object {
        private const val ONE_DAY_MS = 86_400_000L
        private const val EXPIRING_WINDOW_DAYS = 30L

        private const val ORGANISATION = "Automate The Things"
        private const val DNS_SAN = "flow.example.test"
        private const val IP_SAN = "10.11.12.13"
        private const val EMAIL_SAN = "flow@example.test"

        private const val EXPORT_CN = "UI Flow Export Cert"
        private const val DETAIL_CN = "UI Flow Detail Cert"
        private const val REVOKED_CN = "UI Flow Revoked Cert"
        private const val EXPIRING_CN = "UI Flow Expiring Cert"

        /** Positions in the dialog's profile spinner. */
        private const val PROFILE_INDEX_TLS_CLIENT = 1
        private const val PROFILE_INDEX_EMAIL = 4
        private const val PROFILE_INDEX_OCSP = 5
        private const val PROFILE_INDEX_SUBORDINATE_CA = 7

        /** Per-profile validity defaults the dialog fills in. */
        private const val DEFAULT_VALIDITY_DAYS = 365L
        private const val TLS_CLIENT_VALIDITY_DAYS = 365L
        private const val OCSP_VALIDITY_DAYS = 90L
        private const val TLS_VALIDITY_DAYS = 30L

        /** The validity input is the third EditText in the dialog. */
        private const val VALIDITY_FIELD_INDEX = 2

        /** `GeneralName` tags as reported by `getSubjectAlternativeNames`. */
        private const val SAN_TYPE_RFC822 = 1
        private const val SAN_TYPE_DNS = 2
        private const val SAN_TYPE_IP = 7

        /** Key generation plus CSR signing needs more than the default budget. */
        private const val ISSUE_TIMEOUT_MS = 30_000L

        private val CA_SUBJECT = CASubject(
            cn = "xKey UI Issuance CA",
            org = "Automate The Things",
            country = "US"
        )

        /** Start of the run, used to purge the audit rows issuance writes. */
        private var startedAt = 0L

        /**
         * Builds the CA hierarchy the issue dialog needs.
         *
         * No `CertificateDao` is attached to this handle, so the CA's own
         * certificates never reach the shared `certificates` table; only the
         * activity's own handle persists what it issues.
         */
        @JvmStatic
        @BeforeClass
        fun generateCaHierarchy() {
            runBlocking {
                startedAt = System.currentTimeMillis()
                val ca = AndroidCA(ApplicationProvider.getApplicationContext<Context>())
                ca.reset()
                CaTestSupport.assumeCaGenerated(ca.generateRootCA(CA_SUBJECT), "Root CA generation")
                CaTestSupport.assumeCaGenerated(
                    ca.generateIntermediateCA(CA_SUBJECT),
                    "Intermediate CA generation"
                )
            }
        }

        /**
         * Returns the device to the uninitialised state the app ships with, and
         * removes the audit rows issuance wrote.
         *
         * Those rows carry no key id for certificate events, so they cannot be
         * removed through the DAO; the exact operation types this class produces
         * are deleted by timestamp instead.
         */
        @JvmStatic
        @AfterClass
        fun resetSharedCaState() {
            runBlocking {
                val context = ApplicationProvider.getApplicationContext<Context>()
                AndroidCA(context).reset()
                XKeyDatabase.getInstance(context).openHelper.writableDatabase.delete(
                    "audit_logs",
                    "timestamp >= ? AND operation_type IN " +
                        "('CERTIFICATE_ISSUED', 'CSR_SIGNED', 'KEY_CREATED')",
                    arrayOf(startedAt.toString())
                )
            }
        }
    }
}
