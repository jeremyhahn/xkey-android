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

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Guards the *semantic* separation of [PremiumCardFactory]'s status presets.
 *
 * `createInfoCard` and `createSuccessCard` used to be byte-identical — both the
 * tertiary container over a tertiary stroke — so a screen reporting "verified"
 * looked exactly like one reporting "here is some background information". The
 * success card now uses `security_verified`, the green the rest of the app
 * already paints a valid signature, a trusted certificate and a connected device
 * with.
 *
 * `PremiumCardFactoryTest` checks each preset against the attribute it claims to
 * use; this suite checks that no two of them collapse onto the same paint, which
 * is the property that actually broke.
 */
@RunWith(AndroidJUnit4::class)
class PremiumCardSemanticsTest {

    private lateinit var hostScenario: ActivityScenario<MainActivity>

    /** A fresh host per test: a shared one dies with the first teardown. */
    @Before
    fun launchHostActivity() {
        hostScenario = ActivityScenario.launch(MainActivity::class.java)
    }

    @After
    fun closeHostActivity() {
        if (::hostScenario.isInitialized) hostScenario.close()
    }

    /** No two status presets may render identically. */
    @Test
    fun everyStatusPreset_hasItsOwnFill() {
        withActivity(hostScenario) { activity ->
            val fills = listOf(
                "info" to PremiumCardFactory.createInfoCard(activity),
                "warning" to PremiumCardFactory.createWarningCard(activity),
                "error" to PremiumCardFactory.createErrorCard(activity),
                "success" to PremiumCardFactory.createSuccessCard(activity)
            ).associate { (name, card) -> name to card.cardBackgroundColor.defaultColor }

            assertEquals(
                "Each status preset needs a distinct fill, got $fills",
                fills.size,
                fills.values.toSet().size
            )
        }
    }
}
