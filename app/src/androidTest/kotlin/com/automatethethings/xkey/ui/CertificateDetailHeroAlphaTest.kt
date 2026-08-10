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
import android.content.Intent
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.ca.CertificateDao
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The collapsing hero's fade in [CertificateDetailActivity].
 *
 * The offset listener divided the app bar's vertical offset by its total scroll
 * range. A certificate whose content is too short to scroll leaves that range at
 * zero, and `0f / 0` is NaN — which the view system happily accepts as an alpha
 * and then draws as nothing, so the subject, the status badge and the profile
 * badge all vanished on exactly the certificates with the least to show.
 *
 * `heroAlpha` is the arithmetic on its own, so the boundary can be asserted
 * directly rather than by trying to arrange an unscrollable app bar; the last
 * test then confirms the running screen never hands the hero a value the view
 * system cannot use.
 */
@RunWith(AndroidJUnit4::class)
class CertificateDetailHeroAlphaTest {

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

    /** Nothing to scroll means fully expanded, not NaN. */
    @Test
    fun heroAlpha_withNothingToScroll_staysFullyOpaque() {
        assertEquals(1f, CertificateDetailActivity.heroAlpha(0, 0), 0f)
        assertEquals(1f, CertificateDetailActivity.heroAlpha(-120, 0), 0f)
    }

    /** A negative range is as meaningless as a zero one and is treated the same. */
    @Test
    fun heroAlpha_withANegativeRange_staysFullyOpaque() {
        assertEquals(1f, CertificateDetailActivity.heroAlpha(-40, -1), 0f)
    }

    /** The fade itself still runs from opaque at the top to clear at the bottom. */
    @Test
    fun heroAlpha_fadesAcrossTheScrollRange() {
        assertEquals(1f, CertificateDetailActivity.heroAlpha(0, 400), TOLERANCE)
        assertEquals(0.5f, CertificateDetailActivity.heroAlpha(-200, 400), TOLERANCE)
        assertEquals(0f, CertificateDetailActivity.heroAlpha(-400, 400), TOLERANCE)
    }

    /**
     * An over-scrolled offset would otherwise drive the alpha negative, which the
     * view system silently clamps — the coercion makes that explicit.
     */
    @Test
    fun heroAlpha_isClampedToTheLegalRange() {
        assertEquals(0f, CertificateDetailActivity.heroAlpha(-800, 400), TOLERANCE)
    }

    /** On the live screen the hero is drawable, whatever the app bar reports. */
    @Test
    fun heroSection_isDrawnWithAUsableAlpha() {
        val serial = seed(SHORT_CN)
        val scenario = launch(serial)
        assertShownTextInTree(scenario, SHORT_CN)

        val alpha = withActivity(scenario) { activity ->
            heroContainer(activity.window.decorView)?.alpha
        }
        assertTrue("The hero section should be in the view tree", alpha != null)
        assertFalse("The hero alpha must never be NaN", alpha!!.isNaN())
        assertTrue("The hero alpha must be within [0, 1], was $alpha", alpha in 0f..1f)
        assertTrue("A freshly opened detail screen shows its hero", alpha > 0f)
        scenario.close()
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * The hero section, found through the emoji badge the app bar tags.
     *
     * The icon sits in its own round container, which in turn sits in the hero
     * the offset listener fades, so the grandparent is the view under test.
     */
    private fun heroContainer(root: View): View? {
        val icon = root.findViewWithTag<TextView>(HERO_ICON_TAG) ?: return null
        val iconContainer = icon.parent as? ViewGroup ?: return null
        return iconContainer.parent as? ViewGroup
    }

    private fun launch(serial: String): ActivityScenario<CertificateDetailActivity> {
        val intent = Intent(context, CertificateDetailActivity::class.java).apply {
            putExtra(CertificateDetailActivity.EXTRA_SERIAL_NUMBER, serial)
        }
        return ActivityScenario.launch(intent)
    }

    /**
     * Seeds the shortest row the screen can render: no chain, no revocation and a
     * PEM that does not parse, so only the two cards built from the row itself
     * are shown and there is as little to scroll as the screen allows.
     */
    private fun seed(commonName: String): String {
        val serial = "ui-heroalpha-${seededSerials.size}-$runId"
        seededSerials += serial
        runBlocking {
            dao.insert(
                CertificateEntity(
                    serialNumber = serial,
                    subjectDN = "CN=$commonName",
                    issuerDN = "CN=xKey Hero Alpha CA",
                    notBefore = System.currentTimeMillis() - ONE_DAY_MS,
                    notAfter = System.currentTimeMillis() + 365L * ONE_DAY_MS,
                    profile = "tls-server",
                    fingerprint = "fp-$serial",
                    certificatePEM = "not a certificate"
                )
            )
        }
        return serial
    }

    private companion object {
        const val ONE_DAY_MS = 86_400_000L
        const val TOLERANCE = 0.0001f

        /** The tag the app bar puts on the hero's emoji badge. */
        const val HERO_ICON_TAG = "hero_icon"

        const val SHORT_CN = "UI Hero Alpha Cert"
    }
}
