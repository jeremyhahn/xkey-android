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

import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.closeSoftKeyboard
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.action.ViewActions.scrollTo
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
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
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * Rollback behaviour of `CertificateManagementActivity.issueCertificate`.
 *
 * Issuance generates an Android Keystore key and writes a `keys` row *before* it
 * builds the CSR and asks the CA to sign it. Everything after that point can
 * throw, and every throw lands in one catch that reports the failure and returns
 * — so a failed issuance used to leave a Keystore alias and a key row behind
 * with no certificate referencing them and nothing to notice.
 *
 * The failure this suite provokes is an ordinary user mistake: a comma inside
 * the common name. The dialog joins the subject's RDNs with commas, so
 * `X500Name` sees a second RDN with no `=` in it and refuses the whole string —
 * after the key exists, and before the CSR is built.
 *
 * ## Shared state
 *
 * The CA is device-wide and the app ships uninitialised, so @BeforeClass builds
 * a hierarchy of its own and @AfterClass resets it. The `keys` and
 * `certificates` tables and Android Keystore are shared with every other suite,
 * so only rows and aliases that were absent before a test are removed after it.
 */
@RunWith(AndroidJUnit4::class)
class CertificateIssuanceRollbackTest {

    private lateinit var context: Context
    private lateinit var certificateDao: CertificateDao
    private lateinit var keyDao: KeyDao

    private var serialsBefore: Set<String> = emptySet()
    private var keyIdsBefore: Set<String> = emptySet()
    private var aliasesBefore: Set<String> = emptySet()

    private val runId = System.nanoTime()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        certificateDao = XKeyDatabase.getInstance(context).certificateDao()
        keyDao = XKeyDatabase.getInstance(context).keyDao()

        runBlocking {
            serialsBefore = certificateDao.getAll().map { it.serialNumber }.toSet()
            keyIdsBefore = keyDao.getAll().map { it.keyId }.toSet()
        }
        aliasesBefore = generalKeyAliases()
    }

    @After
    fun tearDown() {
        runBlocking {
            certificateDao.getAll()
                .filter { it.serialNumber !in serialsBefore }
                .forEach { certificateDao.deleteBySerial(it.serialNumber) }
            keyDao.getAll()
                .filter { it.keyId !in keyIdsBefore }
                .forEach { keyDao.deleteByKeyId(it.keyId) }
        }
        (generalKeyAliases() - aliasesBefore).forEach { TestCertificates.deleteAlias(it) }
    }

    // -----------------------------------------------------------------
    // A failed issuance
    // -----------------------------------------------------------------

    /**
     * The failure is reported, and neither half of the abandoned key survives it.
     *
     * The error snackbar is asserted first: if the subject ever stopped throwing,
     * the cleanup assertions below would pass for the wrong reason.
     */
    @Test
    fun anIssuanceThatFailsAfterKeyGeneration_leavesNoKeyBehind() {
        val scenario = launch()

        issue(scenario, commonName = "Rollback, Fail $runId")

        assertIssuanceFailed(scenario)
        awaitCondition(
            "The abandoned keys row should have been deleted",
            ROLLBACK_TIMEOUT_MS
        ) { newKeyRows().isEmpty() }
        awaitCondition(
            "The abandoned Keystore alias should have been deleted",
            ROLLBACK_TIMEOUT_MS
        ) { (generalKeyAliases() - aliasesBefore).isEmpty() }
        scenario.close()
    }

    /** A failure that rolls back its key must not have issued anything either. */
    @Test
    fun anIssuanceThatFails_storesNoCertificate() {
        val scenario = launch()

        issue(scenario, commonName = "Rollback, None $runId")

        assertIssuanceFailed(scenario)
        assertEquals(
            "A failed issuance must not write a certificate row",
            0,
            runBlocking { certificateDao.getAll() }.count { it.serialNumber !in serialsBefore }
        )
        scenario.close()
    }

    // -----------------------------------------------------------------
    // A successful issuance
    // -----------------------------------------------------------------

    /**
     * The rollback must fire only on failure: a certificate whose signing key had
     * been deleted out from under it would be unusable.
     */
    @Test
    fun aSuccessfulIssuance_keepsItsSigningKey() {
        val scenario = launch()
        val commonName = "rollback-ok-$runId"

        issue(scenario, commonName)

        // The snackbar is LENGTH_SHORT and issuance is slow enough on an
        // emulator that it can come and go, so the certificate row is what
        // proves the happy path ran.
        awaitCondition(
            "A certificate for CN=$commonName should have been issued",
            ISSUE_TIMEOUT_MS
        ) {
            runBlocking { certificateDao.getAll() }.any {
                it.serialNumber !in serialsBefore && it.subjectDN.contains("CN=$commonName")
            }
        }
        awaitCondition(
            "The signing key should still be recorded after a successful issuance",
            ROLLBACK_TIMEOUT_MS
        ) { newKeyRows().any { row -> row.label.startsWith(commonName) } }
        val keyId = newKeyRows().first { it.label.startsWith(commonName) }.keyId
        assertTrue(
            "The signing key should still be in the Keystore",
            generalKeyAliases().contains("$GENERAL_ALIAS_PREFIX$keyId")
        )
        scenario.close()
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

    /** Opens the issue dialog, fills in [commonName] only, and confirms. */
    private fun issue(
        scenario: ActivityScenario<CertificateManagementActivity>,
        commonName: String
    ) {
        clickClickableWithExactText(scenario, string(scenario, R.string.cert_issue_title))
        onView(withText(R.string.cert_issue_profile))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withHint(R.string.cert_issue_subject_cn_hint))
            .inRoot(isDialog())
            .perform(scrollTo(), replaceText(commonName))
        closeSoftKeyboard()
        // The positive button repeats the dialog title and the FAB label, so a
        // text matcher would be ambiguous.
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())
    }

    /**
     * Asserts that the issuance reported a failure.
     *
     * Generating the key is slow enough on an emulator to outlast the default
     * polling budget, so this waits as long as an issuance itself is given. It
     * runs before every cleanup assertion: without it, a subject that had
     * stopped throwing would let "nothing was left behind" pass for the wrong
     * reason.
     */
    private fun assertIssuanceFailed(
        scenario: ActivityScenario<CertificateManagementActivity>
    ) {
        assertTrue(
            "The issuance should have reported a failure",
            awaitShownTextInTree(scenario, ISSUE_ERROR_PREFIX, ISSUE_TIMEOUT_MS)
        )
    }

    private fun newKeyRows() =
        runBlocking { keyDao.getAll() }.filter { it.keyId !in keyIdsBefore }

    /** Every general-purpose xKey alias currently in Android Keystore. */
    private fun generalKeyAliases(): Set<String> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.aliases().toList().filter { it.startsWith(GENERAL_ALIAS_PREFIX) }.toSet()
    }

    // JUnit needs the lifecycle hooks below to be public statics, so the
    // companion cannot be private.
    companion object {

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** The prefix `KeystoreManager` gives general-purpose key aliases. */
        private const val GENERAL_ALIAS_PREFIX = "xkey_key_"

        /**
         * The stable prefix of `cert_issue_error`, whose suffix is the parser's
         * own message and therefore not worth asserting.
         */
        private const val ISSUE_ERROR_PREFIX = "Failed to issue certificate"

        /** Key generation plus CSR signing needs more than the default budget. */
        private const val ISSUE_TIMEOUT_MS = 30_000L

        /** The rollback runs after the failure, on the IO dispatcher. */
        private const val ROLLBACK_TIMEOUT_MS = 15_000L

        private val CA_SUBJECT = CASubject(
            cn = "xKey Rollback CA",
            org = "Automate The Things",
            country = "US"
        )

        /** Start of the run, used to purge the audit rows issuance writes. */
        private var startedAt = 0L

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
         * Certificate events carry no key id, so they cannot be removed through
         * the DAO; they are deleted by timestamp and operation type instead.
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
                        "('CERTIFICATE_ISSUED', 'CSR_SIGNED', 'KEY_CREATED', 'KEY_DELETED')",
                    arrayOf(startedAt.toString())
                )
            }
        }
    }
}
