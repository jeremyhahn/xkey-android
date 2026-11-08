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

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The collapsing hero's fade in [CertificateDetailActivity], as arithmetic.
 *
 * The offset listener divided the app bar's vertical offset by its total scroll
 * range. A certificate whose content is too short to scroll leaves that range at
 * zero, and `0f / 0` is NaN — which the view system happily accepts as an alpha
 * and then draws as nothing, so the subject, the status badge and the profile
 * badge all vanished on exactly the certificates with the least to show.
 *
 * `heroAlpha` is the arithmetic on its own, so the boundary can be asserted
 * directly rather than by trying to arrange an unscrollable app bar. The
 * instrumented `CertificateDetailHeroAlphaTest` confirms the running screen
 * never hands the hero a value the view system cannot use.
 */
class CertificateDetailHeroAlphaArithmeticTest {

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

    private companion object {
        const val TOLERANCE = 0.0001f
    }
}
