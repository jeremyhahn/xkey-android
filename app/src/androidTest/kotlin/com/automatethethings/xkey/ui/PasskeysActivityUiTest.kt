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
import androidx.test.espresso.action.ViewActions.longClick
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [PasskeysActivity].
 *
 * The screen is fully programmatic: a gradient toolbar, a hero card holding the
 * live passkey count plus Discoverable/Biometric badges, a
 * [PasskeyAdapter]-backed RecyclerView and an empty state. There are no XML ids,
 * so assertions match displayed strings, and the count is always read back from
 * Room rather than hard-coded — other suites share the device database.
 *
 * Tests cover:
 * - Gradient toolbar title and subtitle
 * - Hero card: live count and the Discoverable/Biometric summary badges
 * - Adapter binding: relying-party name, username and "never used" marker
 * - Empty state hidden once a passkey exists
 * - Tapping a row opens [PasskeyDetailActivity] with the row's key id
 * - Long-press context menu, and the delete confirmation's cancel/confirm paths
 * - The list rebinding after a configuration change (recreate)
 * - Back navigation finishing the activity
 *
 * Seeded rows are deleted in @After so suites that assert an empty vault or a
 * specific count are unaffected.
 */
@RunWith(AndroidJUnit4::class)
class PasskeysActivityUiTest {

    private val runId = System.nanoTime()
    private val testKeyId = "ui-test-passkeys-$runId"
    private val deletableKeyId = "ui-test-passkeys-del-$runId"
    private val testRpName = "UI Test Site $runId"
    private val deletableRpName = "UI Test Doomed Site $runId"

    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
    }

    @After
    fun tearDown() {
        runBlocking {
            keyDao.deleteByKeyId(testKeyId)
            keyDao.deleteByKeyId(deletableKeyId)
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Gradient Toolbar
    // ---------------------------------------------------------------

    @Test
    fun gradientToolbar_showsTitle() {
        ActivityScenario.launch(PasskeysActivity::class.java)

        onView(withText(R.string.passkeys_title))
            .check(matches(isDisplayed()))
    }

    @Test
    fun gradientToolbar_showsSubtitle() {
        ActivityScenario.launch(PasskeysActivity::class.java)

        onView(withText(R.string.passkeys_card_description))
            .check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Hero Summary Card
    // ---------------------------------------------------------------

    /**
     * The hero count renders the live number of fido2 keys, so it is asserted
     * against Room instead of a literal that any other suite could invalidate.
     */
    @Test
    fun heroCard_showsLivePasskeyCount() {
        seedPasskey()
        val expected = runBlocking { keyDao.countByType("fido2") }.toString()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)

        awaitText(scenario, testRpName)
        onView(withText(expected)).check(matches(isDisplayed()))
    }

    /** The hero card summarises how many passkeys are discoverable / biometric. */
    @Test
    fun heroCard_showsDiscoverableAndBiometricBadges() {
        seedPasskey()
        val discoverable = runBlocking { keyDao.getByType("fido2").count { it.isDiscoverable } }
        val biometric = runBlocking { keyDao.getByType("fido2").count { it.biometricRequired } }

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)

        awaitText(scenario, "$discoverable Discoverable")
        awaitText(scenario, "$biometric Biometric")
    }

    // ---------------------------------------------------------------
    // Adapter binding
    // ---------------------------------------------------------------

    @Test
    fun seededPasskey_bindsRelyingPartyAndUserName() {
        seedPasskey()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)

        awaitText(scenario, testRpName)
        awaitText(scenario, TEST_USER_NAME)
    }

    /** A passkey that has never been used renders the "Never" last-used marker. */
    @Test
    fun unusedPasskey_showsNeverUsedMarker() {
        seedPasskey()
        val context = ApplicationProvider.getApplicationContext<Context>()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)

        awaitText(scenario, testRpName)
        awaitText(scenario, context.getString(R.string.passkey_never_used))
    }

    // ---------------------------------------------------------------
    // Empty state
    // ---------------------------------------------------------------

    @Test
    fun emptyState_isHiddenWhilePasskeysExist() {
        seedPasskey()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        awaitText(scenario, testRpName)

        scenario.onActivity { activity ->
            val emptyTitle = findTextView(
                activity.window.decorView,
                activity.getString(R.string.passkeys_empty_title)
            )
            assertNotNull("Empty-state title should exist in the hierarchy", emptyTitle)
            assertTrue(
                "Empty state must not be shown while the list has passkeys",
                !emptyTitle!!.isShown
            )
        }
    }

    // ---------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------

    @Test
    fun tappingPasskey_opensDetailWithThatKeyId() {
        seedPasskey()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        awaitText(scenario, testRpName)

        onView(withText(testRpName)).perform(click())

        Intents.intended(
            allOf(
                hasComponent(PasskeyDetailActivity::class.java.name),
                hasExtra(PasskeyDetailActivity.EXTRA_KEY_ID, testKeyId)
            )
        )
    }

    // ---------------------------------------------------------------
    // Context menu and delete flow
    // ---------------------------------------------------------------

    @Test
    fun longPress_opensContextMenuWithViewDetailsAndDelete() {
        seedPasskey()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        awaitText(scenario, testRpName)

        onView(withText(testRpName)).perform(longClick())

        onView(withText(R.string.passkey_context_view_details))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.passkey_context_delete))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    @Test
    fun contextMenuDelete_cancelled_keepsPasskey() {
        seedPasskey()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        awaitText(scenario, testRpName)

        onView(withText(testRpName)).perform(longClick())
        onView(withText(R.string.passkey_context_delete)).inRoot(isDialog()).perform(click())
        onView(withText(R.string.passkey_delete_title)).inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertNotNull(
            "Cancelling the confirmation must keep the passkey",
            runBlocking { keyDao.getByKeyId(testKeyId) }
        )
    }

    @Test
    fun contextMenuDelete_confirmed_removesPasskey() {
        seedDeletablePasskey()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        awaitText(scenario, deletableRpName)

        onView(withText(deletableRpName)).perform(longClick())
        onView(withText(R.string.passkey_context_delete)).inRoot(isDialog()).perform(click())

        // "Delete" is both the context-menu entry and the confirmation's
        // positive button, so gate on the confirmation title to prove the menu
        // is gone before clicking the button.
        onView(withText(R.string.passkey_delete_title)).inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.key_delete_confirm)).inRoot(isDialog()).perform(click())

        awaitCondition("Confirmed delete should remove the passkey from Room") {
            runBlocking { keyDao.getByKeyId(deletableKeyId) } == null
        }
        awaitTextAbsent(scenario, deletableRpName)
        assertNull(runBlocking { keyDao.getByKeyId(deletableKeyId) })
    }

    // ---------------------------------------------------------------
    // Configuration change
    // ---------------------------------------------------------------

    /** The Room-backed list must rebind after the activity is recreated. */
    @Test
    fun listSurvivesRecreate() {
        seedPasskey()

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        awaitText(scenario, testRpName)

        scenario.recreate()

        awaitText(scenario, testRpName)
    }

    // ---------------------------------------------------------------
    // Back Navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun seedPasskey() {
        runBlocking { keyDao.insert(passkey(testKeyId, testRpName)) }
    }

    private fun seedDeletablePasskey() {
        runBlocking { keyDao.insert(passkey(deletableKeyId, deletableRpName)) }
    }

    private fun passkey(keyId: String, rpName: String) = KeyEntity(
        keyId = keyId,
        keyType = "fido2",
        algorithm = "ES256",
        label = rpName,
        keySizeBits = 256,
        biometricRequired = true,
        rpId = "ui-test.example.com",
        rpName = rpName,
        userName = TEST_USER_NAME,
        isDiscoverable = true,
        source = "local"
    )

    private companion object {
        const val TEST_USER_NAME = "ui-test-passkey-user"
    }
}
