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
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivSlotEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.util.Date

/**
 * Instrumented UI tests for [PivSlotDetailActivity].
 *
 * PivSlotDetailActivity builds its UI programmatically (no XML layout IDs) and
 * requires a valid [PivSlotDetailActivity.EXTRA_SLOT_ID] hex identifier. The
 * gradient toolbar is built synchronously, while the detail cards are added only
 * after the slot row has been read from Room -- and the screen finishes itself
 * if that row is missing.
 *
 * Two slots are seeded: one with a public key and a real certificate, and one
 * bare row with neither. Between them they cover the populated and empty
 * branches of the public-key and certificate cards. Both rows are deleted in
 * @After, and the retired slots used here are chosen so they do not collide with
 * the primary slots other suites depend on.
 *
 * Tests cover:
 * - Launch behavior: finishes without a slot id, with an invalid one, and when
 *   the slot has no stored row
 * - Gradient toolbar: title, subtitle and slot badge
 * - Key information card: slot id, label, algorithm, key size, usage counters
 * - Public key card: fingerprint plus export action, and the "Empty" fallback
 * - Certificate card: subject, issuer and validity for a real certificate
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class PivSlotDetailActivityUiTest {

    private lateinit var dao: PivSlotDao
    private var publicKeyDer: ByteArray = ByteArray(0)
    private var certificateDer: ByteArray = ByteArray(0)

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).pivSlotDao()

        val certificate = TestCertificates.selfSigned(
            alias = KEY_ALIAS,
            commonName = CERT_CN,
            notAfter = Date(System.currentTimeMillis() + 365L * TestCertificates.ONE_DAY_MS)
        )
        publicKeyDer = certificate.publicKey.encoded
        certificateDer = certificate.encoded

        runBlocking {
            dao.upsert(
                PivSlotEntity(
                    slotId = POPULATED_SLOT.hexId,
                    algorithm = ALGORITHM.name,
                    publicKeyDer = publicKeyDer,
                    certificateDer = certificateDer,
                    hasKey = true,
                    useCount = USE_COUNT
                )
            )
            dao.upsert(
                PivSlotEntity(
                    slotId = BARE_SLOT.hexId,
                    algorithm = null,
                    hasKey = false
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            dao.deleteBySlotId(POPULATED_SLOT.hexId)
            dao.deleteBySlotId(BARE_SLOT.hexId)
        }
        TestCertificates.deleteAlias(KEY_ALIAS)
    }

    // -----------------------------------------------------------------
    // Launch Behavior
    // -----------------------------------------------------------------

    /**
     * When launched without [PivSlotDetailActivity.EXTRA_SLOT_ID], the activity
     * should call finish() immediately in onCreate and reach DESTROYED.
     */
    @Test
    fun activity_finishesWithoutSlotId() {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            PivSlotDetailActivity::class.java
        )
        val scenario = ActivityScenario.launch<PivSlotDetailActivity>(intent)

        assertTrue(
            "Activity should finish when launched without EXTRA_SLOT_ID",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    /**
     * When launched with a slot id that does not map to a [PivSlot], the
     * activity should call finish() immediately in onCreate and reach DESTROYED.
     */
    @Test
    fun activity_finishesWithInvalidSlotId() {
        val scenario = launch("ZZ")

        assertTrue(
            "Activity should finish when given an unrecognized slot id",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    /**
     * A valid slot id with no stored row still builds the toolbar, then finishes
     * once the Room lookup comes back empty.
     */
    @Test
    fun activity_finishesWhenTheSlotHasNoStoredRow() {
        runBlocking { dao.deleteBySlotId(BARE_SLOT.hexId) }

        val scenario = launch(BARE_SLOT.hexId)

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Gradient Toolbar
    // -----------------------------------------------------------------

    /**
     * The gradient toolbar title is set during buildUI(), which executes before
     * the slot-detail lookup coroutine. Verify it renders.
     */
    @Test
    fun gradientToolbar_showsTitleSubtitleAndSlotBadge() {
        val scenario = launch(POPULATED_SLOT.hexId)

        onView(withText(R.string.piv_detail_title)).check(matches(isDisplayed()))
        assertShownTextInTree(
            scenario,
            withString(
                scenario,
                R.string.piv_detail_subtitle,
                POPULATED_SLOT.hexId,
                POPULATED_SLOT.label
            )
        )
        assertShownTextInTree(scenario, POPULATED_SLOT.hexId)
    }

    // -----------------------------------------------------------------
    // Key information card
    // -----------------------------------------------------------------

    @Test
    fun keyInformationCard_showsSlotIdLabelAndAlgorithm() {
        val scenario = launch(POPULATED_SLOT.hexId)

        assertTextInTree(scenario, withString(scenario, R.string.piv_section_info))
        assertTextInTree(scenario, withString(scenario, R.string.piv_detail_slot_id))
        assertTextInTree(scenario, POPULATED_SLOT.label)
        assertTextInTree(scenario, ALGORITHM.displayName)
    }

    @Test
    fun keyInformationCard_showsKeySizeAndUseCount() {
        val scenario = launch(POPULATED_SLOT.hexId)

        assertTextInTree(
            scenario,
            withString(scenario, R.string.piv_detail_key_size_value, ALGORITHM.keySizeBits)
        )
        assertTextInTree(
            scenario,
            withString(scenario, R.string.piv_detail_times_used, USE_COUNT)
        )
    }

    /** A slot that has never been used reports "Never" rather than a date. */
    @Test
    fun keyInformationCard_reportsNeverUsedWhenThereIsNoUsageTimestamp() {
        val scenario = launch(POPULATED_SLOT.hexId)

        assertTextInTree(scenario, withString(scenario, R.string.piv_detail_never_used))
    }

    // -----------------------------------------------------------------
    // Public key card
    // -----------------------------------------------------------------

    @Test
    fun publicKeyCard_showsFingerprintAndExportAction() {
        val scenario = launch(POPULATED_SLOT.hexId)

        assertTextInTree(scenario, withString(scenario, R.string.piv_section_public_key))
        assertTextInTree(scenario, sha256Fingerprint(publicKeyDer))
        assertTextInTree(scenario, withString(scenario, R.string.piv_detail_export_pubkey))
    }

    /**
     * A row flagged as holding a key but carrying no public key bytes falls back
     * to the "Empty" placeholder instead of a fingerprint.
     */
    @Test
    fun publicKeyCard_fallsBackToEmptyWithoutPublicKeyBytes() {
        runBlocking {
            dao.upsert(
                PivSlotEntity(
                    slotId = BARE_SLOT.hexId,
                    algorithm = ALGORITHM.name,
                    hasKey = true
                )
            )
        }

        val scenario = launch(BARE_SLOT.hexId)

        assertTextInTree(scenario, withString(scenario, R.string.piv_slot_empty))
    }

    // -----------------------------------------------------------------
    // Certificate card
    // -----------------------------------------------------------------

    @Test
    fun certificateCard_showsSubjectIssuerAndValidity() {
        val scenario = launch(POPULATED_SLOT.hexId)

        assertTextInTree(scenario, withString(scenario, R.string.piv_section_certificate))
        assertTextInTree(scenario, withString(scenario, R.string.piv_cert_subject))
        assertTextInTree(scenario, CERT_CN)
        assertTextInTree(scenario, withString(scenario, R.string.piv_cert_not_after))
        assertTextInTree(scenario, withString(scenario, R.string.piv_cert_issuer))
    }

    // -----------------------------------------------------------------
    // Back Navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launch(POPULATED_SLOT.hexId)
        assertTextInTree(scenario, POPULATED_SLOT.label)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(slotId: String): ActivityScenario<PivSlotDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            PivSlotDetailActivity::class.java
        ).apply {
            putExtra(PivSlotDetailActivity.EXTRA_SLOT_ID, slotId)
        }
        return ActivityScenario.launch(intent)
    }

    private fun withString(
        scenario: ActivityScenario<PivSlotDetailActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    /** Mirrors the screen's colon-separated uppercase SHA-256 rendering. */
    private fun sha256Fingerprint(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(der)
            .joinToString(":") { "%02X".format(it) }

    private companion object {
        /** Retired slots, chosen so the primary slots other suites use stay free. */
        val POPULATED_SLOT = PivSlot.RETIRED_19
        val BARE_SLOT = PivSlot.RETIRED_20
        val ALGORITHM = PivAlgorithm.ES256
        const val CERT_CN = "xKey UI Test PIV Slot"
        const val KEY_ALIAS = "xkey_uitest_pivslotdetail"
        const val USE_COUNT = 7
    }
}
