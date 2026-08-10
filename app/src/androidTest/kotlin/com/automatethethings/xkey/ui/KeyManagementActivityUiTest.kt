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
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [KeyManagementActivity].
 *
 * The Key Vault is built entirely in code: gradient toolbar, hero card with the
 * live key count and FIDO2/Signing/Encryption badges, a horizontally scrolling
 * chip filter bar, a RecyclerView of key cards, and a "Create Key" FAB. Every
 * assertion therefore matches displayed text.
 *
 * Two details drive the seeding strategy:
 * - The activity runs `KeyStoreSyncManager.syncAll()` on start, which prunes any
 *   non-"xkmsd" key row whose Android Keystore alias is missing. Rows seeded
 *   straight into Room must therefore use `source = "xkmsd"` to survive.
 * - Chip labels collide with the key-type text on the cards ("Signing" appears
 *   both places), so chips are addressed with [nthMatch] — the filter bar is
 *   built before the list, so the chip is always the first match.
 *
 * Tests cover:
 * - Gradient toolbar title and subtitle
 * - Hero card: live count and type-breakdown badges
 * - Card binding: label, algorithm and type of a seeded key
 * - Filter chips actually filtering (Signing hides FIDO2 and vice versa, All restores)
 * - FAB opening the Create Key dialog, and cancel creating nothing
 * - Tapping a card opening [KeyDetailActivity] with that key's id
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class KeyManagementActivityUiTest {

    private val runId = System.nanoTime()
    private val signingKeyId = "ui-test-vault-signing-$runId"
    private val fido2KeyId = "ui-test-vault-fido2-$runId"
    private val signingLabel = "UI Test Signing Vault Key $runId"
    private val fido2Label = "UI Test Passkey Vault Key $runId"

    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
        runBlocking {
            keyDao.insert(remoteKey(signingKeyId, signingLabel, "signing", "ES256"))
            keyDao.insert(remoteKey(fido2KeyId, fido2Label, "fido2", "ES256"))
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            keyDao.deleteByKeyId(signingKeyId)
            keyDao.deleteByKeyId(fido2KeyId)
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Gradient Toolbar
    // ---------------------------------------------------------------

    @Test
    fun gradientToolbar_showsTitle() {
        ActivityScenario.launch(KeyManagementActivity::class.java)

        onView(withText(R.string.key_vault_title))
            .check(matches(isDisplayed()))
    }

    @Test
    fun gradientToolbar_showsSubtitle() {
        ActivityScenario.launch(KeyManagementActivity::class.java)

        onView(withText(R.string.key_vault_subtitle))
            .check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Hero Summary Card
    // ---------------------------------------------------------------

    /**
     * The hero card renders the live key count, so it is asserted against the
     * store rather than a hard-coded value that any other suite can break.
     */
    @Test
    fun heroCard_showsLiveKeyCount() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, signingLabel)

        val expectedCount = runBlocking { keyDao.countAll() }.toString()

        onView(withText(expectedCount)).check(matches(isDisplayed()))
    }

    /** The hero card breaks the vault down into FIDO2 / Signing / Encryption. */
    @Test
    fun heroCard_showsTypeBreakdownBadges() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, signingLabel)

        val keys = runBlocking { keyDao.getAll() }
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, "${keys.count { it.keyType == "fido2" }} FIDO2")
        awaitText(
            scenario,
            "${keys.count { it.keyType == "signing" }} " +
                context.getString(R.string.key_filter_signing)
        )
    }

    // ---------------------------------------------------------------
    // Filter Chips
    // ---------------------------------------------------------------

    @Test
    fun filterChips_allAndFido2AreDisplayed() {
        ActivityScenario.launch(KeyManagementActivity::class.java)

        onView(firstDisplayed(R.string.key_filter_all)).check(matches(isDisplayed()))
        onView(firstDisplayed(R.string.key_filter_fido2)).check(matches(isDisplayed()))
    }

    /** Selecting "Signing" must hide keys of every other type. */
    @Test
    fun signingFilter_showsOnlySigningKeys() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, signingLabel)
        awaitText(scenario, fido2Label)

        onView(firstDisplayed(R.string.key_filter_signing)).perform(click())

        awaitText(scenario, signingLabel)
        awaitTextAbsent(scenario, fido2Label)
    }

    /** Selecting "FIDO2" must hide keys of every other type. */
    @Test
    fun fido2Filter_showsOnlyFido2Keys() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, fido2Label)

        onView(firstDisplayed(R.string.key_filter_fido2)).perform(click())

        awaitText(scenario, fido2Label)
        awaitTextAbsent(scenario, signingLabel)
    }

    /** Re-selecting "All" restores the unfiltered list. */
    @Test
    fun allFilter_restoresEveryKeyAfterFiltering() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, signingLabel)

        onView(firstDisplayed(R.string.key_filter_fido2)).perform(click())
        awaitTextAbsent(scenario, signingLabel)

        onView(firstDisplayed(R.string.key_filter_all)).perform(click())

        awaitText(scenario, signingLabel)
        awaitText(scenario, fido2Label)
    }

    // ---------------------------------------------------------------
    // Card binding
    // ---------------------------------------------------------------

    @Test
    fun keyCard_bindsLabelAlgorithmAndType() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, signingLabel)
        awaitText(scenario, "ES256")
        awaitText(scenario, context.getString(R.string.key_filter_signing))
    }

    /** A key with `source = "xkmsd"` is badged as Remote on its card. */
    @Test
    fun remoteKeyCard_showsRemoteBadge() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, signingLabel)
        awaitText(scenario, context.getString(R.string.key_badge_remote))
    }

    @Test
    fun emptyState_isHiddenWhileKeysExist() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, signingLabel)

        scenario.onActivity { activity ->
            val emptyTitle = findTextView(
                activity.window.decorView,
                activity.getString(R.string.key_vault_empty_title)
            )
            assertTrue(
                "The empty-vault state must not be shown while keys exist",
                emptyTitle == null || !emptyTitle.isShown
            )
        }
    }

    // ---------------------------------------------------------------
    // Create Key dialog
    // ---------------------------------------------------------------

    @Test
    fun fab_isDisplayed() {
        ActivityScenario.launch(KeyManagementActivity::class.java)

        onView(firstDisplayed(R.string.key_create_title))
            .check(matches(isDisplayed()))
    }

    @Test
    fun fab_opensCreateKeyDialog() {
        ActivityScenario.launch(KeyManagementActivity::class.java)

        onView(firstDisplayed(R.string.key_create_title)).perform(click())

        onView(withText(R.string.key_create_purpose))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.key_create_algorithm))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    /** Dismissing the Create Key dialog must not add anything to the vault. */
    @Test
    fun createKeyDialog_cancel_createsNothing() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, signingLabel)
        val before = runBlocking { keyDao.countAll() }

        onView(firstDisplayed(R.string.key_create_title)).perform(click())
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        waitForIdle()
        assertEquals("Cancelling must not create a key", before, runBlocking { keyDao.countAll() })
    }

    // ---------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------

    @Test
    fun tappingKeyCard_opensKeyDetailWithThatKeyId() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)
        awaitText(scenario, signingLabel)

        onView(withText(signingLabel)).perform(scrollToView(), click())

        Intents.intended(
            allOf(
                hasComponent(KeyDetailActivity::class.java.name),
                hasExtra(KeyDetailActivity.EXTRA_KEY_ID, signingKeyId)
            )
        )
    }

    // ---------------------------------------------------------------
    // Back Navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(KeyManagementActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Matches the first displayed view carrying [stringRes].
     *
     * Chip labels are duplicated by the key cards' type text, and the FAB label
     * is duplicated by the create dialog, so an unqualified matcher would raise
     * `AmbiguousViewMatcherException`. The filter bar and the FAB are both built
     * before the views that repeat their text, so index 0 is the control.
     */
    private fun firstDisplayed(stringRes: Int) =
        nthMatch(allOf(withText(stringRes), isDisplayed()), 0)

    /**
     * Builds a key row that survives the activity's start-up
     * `KeyStoreSyncManager.syncAll()` — only non-"xkmsd" rows are pruned when
     * their Keystore alias is missing.
     */
    private fun remoteKey(
        keyId: String,
        label: String,
        keyType: String,
        algorithm: String
    ) = KeyEntity(
        keyId = keyId,
        keyType = keyType,
        algorithm = algorithm,
        label = label,
        keySizeBits = 256,
        biometricRequired = false,
        source = "xkmsd",
        remoteBackend = "software"
    )

    /** Guards the seeding assumption the filter assertions depend on. */
    @Test
    fun seededKeys_arePresentInStore() {
        assertNotNull(runBlocking { keyDao.getByKeyId(signingKeyId) })
        assertNotNull(runBlocking { keyDao.getByKeyId(fido2KeyId) })
    }
}
