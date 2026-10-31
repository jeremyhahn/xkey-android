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
import android.view.View
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Date

/**
 * Instrumented tests for the row rendering of `TrustedCertificateAdapter`, the
 * private adapter behind [TrustStoreActivity]'s certificate list.
 *
 * `TrustStoreActivityUiTest` seeds two internal-CA certificates, one valid and
 * one expired, which leaves the middle expiry state and four of the five source
 * badges unbound. The adapter derives the source badge from a free-form string
 * that only the import paths produce ("manual", "url:…", "Bootstrap …"), so the
 * fixtures are written through the repository and their stored source is then
 * rewritten in the trust store's own metadata — the one field no import path
 * lets a test choose.
 *
 * Tests cover:
 * - The expiring-soon row: warning-coloured expiry text rather than danger or
 *   the neutral variant
 * - All five source badges: AndroidCA, Manual, URL, Bootstrap and the File
 *   fallback
 * - The row's delete button and its long-press equivalent both raising the
 *   delete confirmation, which is then cancelled
 *
 * The four seeded certificates and their Keystore aliases are removed in @After;
 * nothing is ever confirmed for deletion, so the shared store is left intact.
 */
@RunWith(AndroidJUnit4::class)
class TrustedCertificateAdapterFlowTest {

    private lateinit var context: Context
    private lateinit var repository: TrustStoreRepository
    private val fingerprints = mutableMapOf<String, String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        repository = TrustStoreRepository(context)

        val now = System.currentTimeMillis()
        seed(MANUAL_ALIAS, MANUAL_CN, Date(now + 365L * TestCertificates.ONE_DAY_MS))
        seed(URL_ALIAS, URL_CN, Date(now + 365L * TestCertificates.ONE_DAY_MS))
        seed(BOOTSTRAP_ALIAS, BOOTSTRAP_CN, Date(now + 365L * TestCertificates.ONE_DAY_MS))
        // Inside the 30-day window the adapter treats as "expiring soon".
        seed(FILE_ALIAS, FILE_CN, Date(now + 10L * TestCertificates.ONE_DAY_MS))

        rewriteSources(
            mapOf(
                fingerprints.getValue(MANUAL_CN) to "manual",
                fingerprints.getValue(URL_CN) to "url:https://ca.example.com/bundle.pem",
                fingerprints.getValue(BOOTSTRAP_CN) to "Bootstrap (DANE)",
                fingerprints.getValue(FILE_CN) to "ca-bundle.pem"
            )
        )
    }

    @After
    fun tearDown() {
        runBlocking { fingerprints.values.forEach { repository.deleteCertificate(it) } }
        listOf(MANUAL_ALIAS, URL_ALIAS, BOOTSTRAP_ALIAS, FILE_ALIAS).forEach {
            TestCertificates.deleteAlias(it)
        }
    }

    // ---------------------------------------------------------------
    // Expiry states
    // ---------------------------------------------------------------

    /**
     * Between "valid" and "expired" sits a warning state the basic suite never
     * produces: still trusted, but inside the 30-day window.
     */
    @Test
    fun rowForACertificateExpiringSoon_usesTheWarningColour() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInList(scenario, FILE_CN)

        val expiresPrefix = withActivity(scenario) {
            it.getString(R.string.trust_store_item_expires, "").trim()
        }
        val warning = withActivity(scenario) {
            ContextCompat.getColor(it, R.color.security_warning)
        }
        val expiryView = rowViews(scenario, FILE_CN)
            .filterIsInstance<TextView>()
            .first { it.text.toString().startsWith(expiresPrefix) }

        assertEquals(
            "A certificate expiring within 30 days must be flagged with the warning colour",
            warning,
            expiryView.currentTextColor
        )
    }

    // ---------------------------------------------------------------
    // Source badges
    // ---------------------------------------------------------------

    @Test
    fun sourceBadges_reflectHowEachCertificateWasImported() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInList(scenario, MANUAL_CN)

        assertBadge(scenario, MANUAL_CN, "Manual")
        assertBadge(scenario, URL_CN, "URL")
        assertBadge(scenario, BOOTSTRAP_CN, "Bootstrap")
        assertBadge(scenario, FILE_CN, "File")
    }

    /** Certificates the app generated itself are badged as the internal CA. */
    @Test
    fun internalCaCertificates_keepTheAndroidCaBadge() {
        val internalCn = "xKey Flow Internal CA"
        val fingerprint = runBlocking {
            repository.importInternalCACertificate(
                TestCertificates.selfSigned(
                    alias = INTERNAL_ALIAS,
                    commonName = internalCn,
                    notAfter = Date(
                        System.currentTimeMillis() + 365L * TestCertificates.ONE_DAY_MS
                    )
                ),
                "Flow Internal CA"
            )
        }
        fingerprints[internalCn] = fingerprint

        try {
            val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
            assertShownTextInList(scenario, internalCn)

            assertBadge(
                scenario,
                internalCn,
                withActivity(scenario) { it.getString(R.string.source_internal_ca) }
            )
        } finally {
            TestCertificates.deleteAlias(INTERNAL_ALIAS)
        }
    }

    // ---------------------------------------------------------------
    // Row actions
    // ---------------------------------------------------------------

    @Test
    fun longPressingARow_raisesTheDeleteConfirmation() {
        val scenario = ActivityScenario.launch(TrustStoreActivity::class.java)
        assertShownTextInList(scenario, URL_CN)

        RowFlowInteractions.longClickText(scenario, URL_CN)

        onView(withText(R.string.trust_store_delete_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Cancelling must keep the certificate",
            runBlocking { repository.hasCertificate(fingerprints.getValue(URL_CN)) }
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun seed(alias: String, commonName: String, notAfter: Date) {
        val certificate = TestCertificates.selfSigned(
            alias = alias,
            commonName = commonName,
            notAfter = notAfter
        )
        fingerprints[commonName] = runBlocking {
            repository.importInternalCACertificate(certificate, "$commonName label")
        }
    }

    /**
     * Rewrites the `source` recorded for the given fingerprints.
     *
     * The source is assigned by whichever import path stored the certificate and
     * there is no API to set it, so the store's metadata file is edited directly.
     * Only that one field is touched; the DER files and every other field stay as
     * the repository wrote them, and the activity's own refresh pass preserves
     * the change.
     */
    private fun rewriteSources(sources: Map<String, String>) {
        val metadata = File(context.getDir("trust_store", Context.MODE_PRIVATE), "metadata.json")
        val entries = JSONArray(metadata.readText())
        for (i in 0 until entries.length()) {
            val entry = entries.getJSONObject(i)
            sources[entry.getString("fingerprint")]?.let { entry.put("source", it) }
        }
        metadata.writeText(entries.toString())
    }

    private fun assertBadge(
        scenario: ActivityScenario<TrustStoreActivity>,
        commonName: String,
        badge: String
    ) {
        val texts = rowViews(scenario, commonName)
            .filterIsInstance<TextView>()
            .map { it.text.toString() }
        assertTrue(
            "Expected the '$commonName' row to carry a '$badge' badge, found $texts",
            texts.contains(badge)
        )
    }

    private fun rowViews(
        scenario: ActivityScenario<TrustStoreActivity>,
        commonName: String
    ): List<View> = withActivity(scenario) { rowViews(it.window.decorView, commonName) }

    /**
     * Returns every view on the row titled [commonName].
     *
     * Each row repeats the same badges and the same delete icon, so the card is
     * located by the certificate's CN and read as a unit.
     */
    private fun rowViews(root: View, commonName: String): List<View> {
        val title = collectViews(root) {
            it is TextView && it.text?.toString() == commonName
        }.firstOrNull() ?: throw AssertionError("No bound row for '$commonName'")
        val card = generateSequence(title.parent as? View) { it.parent as? View }
            .first { it.isClickable }
        return collectViews(card) { true }
    }

    private companion object {
        const val MANUAL_ALIAS = "xkey_uitest_trustadapter_manual"
        const val URL_ALIAS = "xkey_uitest_trustadapter_url"
        const val BOOTSTRAP_ALIAS = "xkey_uitest_trustadapter_bootstrap"
        const val FILE_ALIAS = "xkey_uitest_trustadapter_file"
        const val INTERNAL_ALIAS = "xkey_uitest_trustadapter_internal"

        const val MANUAL_CN = "xKey Flow Manual CA"
        const val URL_CN = "xKey Flow URL CA"
        const val BOOTSTRAP_CN = "xKey Flow Bootstrap CA"
        const val FILE_CN = "xKey Flow File CA"
    }
}
