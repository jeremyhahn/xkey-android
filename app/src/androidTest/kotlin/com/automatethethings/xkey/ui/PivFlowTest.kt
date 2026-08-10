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
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivSlotEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Instrumented tests for the [PivActivity] slot-card branches the basic suite
 * does not reach.
 *
 * `PivActivityUiTest` covers the chrome, the populated/empty card variants and
 * the generate-key dialog. What is left is the certificate row a card grows when
 * its slot holds one: three colour-coded validity states plus the silent
 * fallback when the stored DER cannot be parsed at all. The retired slots are
 * used throughout so the primary slots other suites depend on stay untouched —
 * which also exercises the collapsed retired section, since a card inside it is
 * unreachable until the header is tapped.
 *
 * Tests cover:
 * - Certificate row: subject CN plus the valid / expiring / expired badge
 * - Unparseable certificate DER omitting the row instead of crashing the card
 * - The whole card (not just its button) navigating to the slot detail screen
 * - The hero badge minted for a populated primary slot
 *
 * Every seeded slot row and Keystore alias is removed in @After.
 */
@RunWith(AndroidJUnit4::class)
class PivFlowTest {

    private lateinit var dao: PivSlotDao

    @Before
    fun setUp() {
        Intents.init()
        // Keep card taps from actually launching the detail screen.
        intending(hasComponent(PivSlotDetailActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, null)
        )

        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).pivSlotDao()

        val now = System.currentTimeMillis()
        seedSlot(
            slot = VALID_SLOT,
            certificate = certificate(
                VALID_ALIAS,
                VALID_CN,
                notAfter = Date(now + 365L * TestCertificates.ONE_DAY_MS)
            )
        )
        seedSlot(
            slot = EXPIRING_SLOT,
            certificate = certificate(
                EXPIRING_ALIAS,
                EXPIRING_CN,
                notAfter = Date(now + 10L * TestCertificates.ONE_DAY_MS)
            )
        )
        seedSlot(
            slot = EXPIRED_SLOT,
            certificate = certificate(
                EXPIRED_ALIAS,
                EXPIRED_CN,
                notBefore = Date(now - 30L * TestCertificates.ONE_DAY_MS),
                notAfter = Date(now - TestCertificates.ONE_DAY_MS)
            )
        )
        runBlocking {
            dao.upsert(
                PivSlotEntity(
                    slotId = UNPARSEABLE_SLOT.hexId,
                    algorithm = ALGORITHM.name,
                    certificateDer = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x00),
                    hasKey = true
                )
            )
            dao.upsert(
                PivSlotEntity(
                    slotId = PRIMARY_SLOT.hexId,
                    algorithm = ALGORITHM.name,
                    hasKey = true
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            listOf(VALID_SLOT, EXPIRING_SLOT, EXPIRED_SLOT, UNPARSEABLE_SLOT, PRIMARY_SLOT)
                .forEach { dao.deleteBySlotId(it.hexId) }
        }
        listOf(VALID_ALIAS, EXPIRING_ALIAS, EXPIRED_ALIAS).forEach {
            TestCertificates.deleteAlias(it)
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Certificate row
    // ---------------------------------------------------------------

    @Test
    fun certificateRow_showsTheSubjectAndAValidBadge() {
        val scenario = launchWithRetiredSlotsExpanded()

        val texts = cardTexts(scenario, VALID_SLOT.label)
        assertTrue(
            "The card should name the certificate subject, found $texts",
            texts.any { it == VALID_CN }
        )
        assertTrue(
            "A certificate a year from expiry is valid, found $texts",
            texts.any { it == withString(scenario, R.string.piv_cert_valid) }
        )
    }

    /** Inside the 30-day warning window the badge switches to "Expiring". */
    @Test
    fun certificateRow_warnsAboutAnImminentExpiry() {
        val scenario = launchWithRetiredSlotsExpanded()

        val texts = cardTexts(scenario, EXPIRING_SLOT.label)
        assertTrue(
            "A certificate expiring in ten days must be flagged, found $texts",
            texts.any { it == withString(scenario, R.string.piv_cert_expiring) }
        )
    }

    @Test
    fun certificateRow_marksAnAlreadyExpiredCertificate() {
        val scenario = launchWithRetiredSlotsExpanded()

        val texts = cardTexts(scenario, EXPIRED_SLOT.label)
        assertTrue(
            "A certificate whose notAfter has passed must be flagged, found $texts",
            texts.any { it == withString(scenario, R.string.piv_cert_expired) }
        )
    }

    /**
     * Stored bytes that are not an X.509 certificate must degrade to no
     * certificate row at all; the rest of the card still has to render.
     */
    @Test
    fun certificateRow_isOmittedWhenTheStoredDerCannotBeParsed() {
        val scenario = launchWithRetiredSlotsExpanded()

        val texts = cardTexts(scenario, UNPARSEABLE_SLOT.label)
        val statuses = listOf(
            withString(scenario, R.string.piv_cert_valid),
            withString(scenario, R.string.piv_cert_expiring),
            withString(scenario, R.string.piv_cert_expired)
        )
        assertTrue(
            "No validity badge may be shown for unparseable DER, found $texts",
            texts.none { it in statuses }
        )
        assertTrue(
            "The rest of the card must still render, found $texts",
            texts.any { it == ALGORITHM.name }
        )
    }

    // ---------------------------------------------------------------
    // Navigation and summary
    // ---------------------------------------------------------------

    /** The whole card is a target, not only its "View Details" button. */
    @Test
    fun populatedSlotCard_opensTheDetailScreenWhenTheCardItselfIsTapped() {
        val scenario = ActivityScenario.launch(PivActivity::class.java)
        assertShownTextInTree(scenario, PRIMARY_SLOT.label)

        clickTextInTree(scenario, PRIMARY_SLOT.label)

        intended(
            allOf(
                hasComponent(PivSlotDetailActivity::class.java.name),
                hasExtra(PivSlotDetailActivity.EXTRA_SLOT_ID, PRIMARY_SLOT.hexId)
            )
        )
    }

    /**
     * Each populated primary slot mints a hero badge of "<hex> <first word of
     * the label>"; retired slots never do.
     */
    @Test
    fun heroCard_badgesEveryPopulatedPrimarySlot() {
        val scenario = ActivityScenario.launch(PivActivity::class.java)

        assertExactTextShown(
            scenario,
            "${PRIMARY_SLOT.hexId} ${PRIMARY_SLOT.label.substringBefore(" ")}"
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launchWithRetiredSlotsExpanded(): ActivityScenario<PivActivity> {
        val scenario = ActivityScenario.launch(PivActivity::class.java)
        assertShownTextInTree(scenario, PRIMARY_SLOT.label)
        clickTextInTree(scenario, withString(scenario, R.string.piv_section_retired_toggle, 20))
        return scenario
    }

    /**
     * Returns every label rendered on the card for [slotLabel].
     *
     * Cards are rebuilt on each Room emission and repeat the same badges, so a
     * card is identified by its unique slot label and read as a whole: the label
     * sits in the info column, whose parent is the card's content row.
     */
    private fun cardTexts(
        scenario: ActivityScenario<PivActivity>,
        slotLabel: String
    ): List<String> = withActivity(scenario) { activity ->
        val label = collectViews(activity.window.decorView) {
            it is TextView && it.text?.toString() == slotLabel
        }.firstOrNull() ?: throw AssertionError("No card labelled '$slotLabel'")
        val cardContent = (label.parent as View).parent as View
        collectViews(cardContent) { it is TextView }
            .map { (it as TextView).text?.toString().orEmpty() }
    }

    private fun withString(
        scenario: ActivityScenario<PivActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    private fun certificate(
        alias: String,
        commonName: String,
        notBefore: Date = Date(System.currentTimeMillis() - TestCertificates.ONE_DAY_MS),
        notAfter: Date
    ): X509Certificate = TestCertificates.selfSigned(alias, commonName, notBefore, notAfter)

    private fun seedSlot(slot: PivSlot, certificate: X509Certificate) {
        runBlocking {
            dao.upsert(
                PivSlotEntity(
                    slotId = slot.hexId,
                    algorithm = ALGORITHM.name,
                    publicKeyDer = certificate.publicKey.encoded,
                    certificateDer = certificate.encoded,
                    hasKey = true
                )
            )
        }
    }

    private companion object {
        /**
         * Retired slots with labels that are not a prefix of any other slot's
         * label ("Retired 1" would also match "Retired 19").
         */
        val VALID_SLOT = PivSlot.RETIRED_5
        val EXPIRING_SLOT = PivSlot.RETIRED_6
        val EXPIRED_SLOT = PivSlot.RETIRED_7
        val UNPARSEABLE_SLOT = PivSlot.RETIRED_8

        /** Key Management: no other suite seeds this primary slot. */
        val PRIMARY_SLOT = PivSlot.KEY_MANAGEMENT

        val ALGORITHM = PivAlgorithm.ES256

        const val VALID_ALIAS = "xkey_uitest_pivflow_valid"
        const val EXPIRING_ALIAS = "xkey_uitest_pivflow_expiring"
        const val EXPIRED_ALIAS = "xkey_uitest_pivflow_expired"
        const val VALID_CN = "xKey Flow Valid PIV"
        const val EXPIRING_CN = "xKey Flow Expiring PIV"
        const val EXPIRED_CN = "xKey Flow Expired PIV"
    }
}
