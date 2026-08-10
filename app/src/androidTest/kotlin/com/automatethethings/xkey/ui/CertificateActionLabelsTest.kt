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
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
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
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Whether the certificate list's controls and confirmations say the right thing.
 *
 * The context menu's export entry was labelled with `cert_export_copied`, so the
 * *action* read "Certificate PEM copied to clipboard" — a past-tense claim about
 * something that had not happened yet. The delete confirmation ran the other way
 * round and reported success with `cert_delete_confirm`, the word "Delete", which
 * reads as another button rather than as an outcome.
 *
 * A control says what it will do; a confirmation says what happened. Both are
 * asserted here, in both directions, so a future edit cannot quietly swap them
 * back.
 *
 * Every seeded row is removed in @After; nothing else on the screen is touched.
 */
@RunWith(AndroidJUnit4::class)
class CertificateActionLabelsTest {

    private val runId = System.nanoTime()

    private lateinit var context: Context
    private lateinit var dao: CertificateDao

    private val seededSerials = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        dao = XKeyDatabase.getInstance(context).certificateDao()
    }

    @After
    fun tearDown() {
        runBlocking {
            seededSerials.forEach { dao.deleteBySerial(it) }
        }
        seededSerials.clear()
    }

    /** The menu entry names the action, not its eventual confirmation. */
    @Test
    fun contextMenu_labelsTheExportEntryWithTheAction() {
        val serial = seed(EXPORT_CN)
        val scenario = launch()
        openContextMenu(scenario, serial, EXPORT_CN)

        onView(withText(R.string.cert_export_action))
            .inRoot(isPlatformPopup())
            .check(matches(isDisplayed()))
        onView(withText(R.string.cert_export_copied))
            .inRoot(isPlatformPopup())
            .check(doesNotExist())
        scenario.close()
    }

    /** Once the export has run, the confirmation is the past-tense message. */
    @Test
    fun exportingFromTheContextMenu_confirmsWithWhatHappened() {
        val serial = seed(EXPORT_CONFIRM_CN)
        val scenario = launch()
        openContextMenu(scenario, serial, EXPORT_CONFIRM_CN)

        onView(withText(R.string.cert_export_action)).inRoot(isPlatformPopup()).perform(click())

        assertShownTextInTree(scenario, context.getString(R.string.cert_export_copied))
        scenario.close()
    }

    /**
     * Deleting confirms with an outcome rather than echoing the button that was
     * just pressed.
     */
    @Test
    fun deletingACertificate_confirmsThatItWasDeleted() {
        val serial = seed(DELETE_CN)
        val scenario = launch()
        openContextMenu(scenario, serial, DELETE_CN)

        onView(withText(R.string.cert_delete_title)).inRoot(isPlatformPopup()).perform(click())
        onView(withText(R.string.cert_delete_confirm)).inRoot(isDialog()).perform(click())

        assertShownTextInTree(scenario, context.getString(R.string.cert_delete_success))
        awaitCondition("The certificate row should have been deleted") {
            runBlocking { dao.getBySerial(serial) } == null
        }
        scenario.close()
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<CertificateManagementActivity> =
        ActivityScenario.launch(CertificateManagementActivity::class.java)

    /**
     * Long-presses the row carrying [commonName].
     *
     * The list is ordered by creation time and shared with every other suite's
     * rows, so the position is looked up rather than assumed.
     */
    private fun openContextMenu(
        scenario: ActivityScenario<CertificateManagementActivity>,
        serial: String,
        commonName: String
    ) {
        assertShownTextInList(scenario, commonName)
        val position = runBlocking { dao.getAll() }.indexOfFirst { it.serialNumber == serial }
        assertTrue("The seeded certificate should be stored", position >= 0)
        assertTrue(
            "The adapter should have bound at least ${position + 1} rows",
            awaitRecyclerItemCount(scenario, position + 1)
        )
        longClickRecyclerItem(scenario, position)
    }

    private fun seed(commonName: String): String {
        val serial = "ui-actionlabels-${seededSerials.size}-$runId"
        seededSerials += serial
        runBlocking {
            dao.insert(
                CertificateEntity(
                    serialNumber = serial,
                    subjectDN = "CN=$commonName",
                    issuerDN = "CN=xKey Action Labels CA",
                    notBefore = System.currentTimeMillis() - ONE_DAY_MS,
                    notAfter = System.currentTimeMillis() + 365L * ONE_DAY_MS,
                    profile = "tls-server",
                    fingerprint = "fp-$serial",
                    certificatePEM =
                        "-----BEGIN CERTIFICATE-----\n$serial\n-----END CERTIFICATE-----"
                )
            )
        }
        return serial
    }

    // JUnit needs the lifecycle hook below to be a public static, so the
    // companion cannot be private.
    companion object {
        private const val ONE_DAY_MS = 86_400_000L

        private const val EXPORT_CN = "UI Labels Export Cert"
        private const val EXPORT_CONFIRM_CN = "UI Labels Export Confirm Cert"
        private const val DELETE_CN = "UI Labels Delete Cert"

        /** Start of the run, used to purge the audit rows exporting writes. */
        private var startedAt = 0L

        @JvmStatic
        @BeforeClass
        fun recordStart() {
            startedAt = System.currentTimeMillis()
        }

        /**
         * Removes the export events this suite produced.
         *
         * Certificate events carry no key id, so they cannot be removed through
         * the DAO; they are deleted by timestamp and operation type instead.
         */
        @JvmStatic
        @AfterClass
        fun purgeAuditRows() {
            val context = ApplicationProvider.getApplicationContext<Context>()
            XKeyDatabase.getInstance(context).openHelper.writableDatabase.delete(
                "audit_logs",
                "timestamp >= ? AND operation_type = 'CERTIFICATE_EXPORTED'",
                arrayOf(startedAt.toString())
            )
        }
    }
}
