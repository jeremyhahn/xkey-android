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
import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.fail

/**
 * Row-level interactions the shared matchers do not cover.
 *
 * `clickTextInTree` walks up to the nearest *clickable* ancestor, which is the
 * wrong target for a list whose rows carry both a click and a long-click
 * listener: the two live on the same view, and a long press is the only way into
 * the context menus on the OATH, passkey and trust-store lists.
 *
 * Like the click helper, this invokes the listener on the main thread instead of
 * injecting motion events, so a row that is bound but scrolled part-way off the
 * screen still responds.
 *
 * Members live on an object so these names cannot clash with helpers other
 * suites add to this package.
 */
internal object RowFlowInteractions {

    /**
     * Long-clicks the view carrying [text], or its nearest long-clickable
     * ancestor.
     *
     * The row must already be bound; scroll it into view first (for example with
     * [assertShownTextInList]) when other suites' data can push it down the list.
     */
    fun <A : Activity> longClickText(scenario: ActivityScenario<A>, text: String) {
        scenario.onActivity { activity ->
            val target = findTextViewContaining(activity.window.decorView, text)
            if (target == null) {
                fail("No view containing '$text' to long-click")
                return@onActivity
            }
            var candidate: View? = target
            while (candidate != null && !candidate.isLongClickable) {
                candidate = candidate.parent as? View
            }
            if (candidate == null) {
                fail("No long-clickable ancestor of the view containing '$text'")
                return@onActivity
            }
            candidate.performLongClick()
        }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }
}
