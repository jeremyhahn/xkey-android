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
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [PasskeyDetailActivity].
 *
 * The activity builds its UI programmatically (no XML layout ids) and requires
 * a valid [PasskeyDetailActivity.EXTRA_KEY_ID]; without one it finishes in
 * onCreate, and with an unknown id it finishes once the Room lookup returns.
 * The toolbar renders synchronously, but every card is populated from a
 * coroutine, so content assertions poll via [awaitText].
 *
 * Tests cover:
 * - Launch behaviour: finishes when no key id is supplied
 * - Gradient toolbar: title and subtitle
 * - Section cards: Site / Account / Credential / Security / Usage / Actions
 * - Bound values: relying party, username, algorithm, sign count, never-used
 * - Delete dialog: opens, cancel keeps the passkey, confirm deletes and finishes
 * - Back navigation finishing the activity
 *
 * Both seeded rows are removed in @After.
 */
@RunWith(AndroidJUnit4::class)
class PasskeyDetailActivityUiTest {

    // Unique per test instance so leftover rows never collide.
    private val runId = System.nanoTime()
    private val testKeyId = "ui-test-passkey-detail-$runId"
    private val deletableKeyId = "ui-test-passkey-detail-del-$runId"

    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
        runBlocking { keyDao.insert(passkey(testKeyId, "UI Test Passkey")) }
    }

    @After
    fun tearDown() {
        runBlocking {
            keyDao.deleteByKeyId(testKeyId)
            keyDao.deleteByKeyId(deletableKeyId)
        }
        Intents.release()
    }

    // -----------------------------------------------------------------
    // Launch Behavior
    // -----------------------------------------------------------------

    /**
     * When launched without [PasskeyDetailActivity.EXTRA_KEY_ID], the
     * activity should call finish() immediately in onCreate and reach
     * the DESTROYED state.
     */
    @Test
    fun activity_finishesWithoutKeyId() {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            PasskeyDetailActivity::class.java
        )
        val scenario = ActivityScenario.launch<PasskeyDetailActivity>(intent)

        assertTrue(
            "Activity should finish when launched without EXTRA_KEY_ID",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    // -----------------------------------------------------------------
    // Gradient Toolbar
    // -----------------------------------------------------------------

    @Test
    fun gradientToolbar_showsTitle() {
        val scenario = launchWithSeededKey()

        awaitText(scenario, context().getString(R.string.passkey_detail_title))
    }

    @Test
    fun gradientToolbar_showsSubtitle() {
        val scenario = launchWithSeededKey()

        awaitText(scenario, context().getString(R.string.passkey_card_description))
    }

    // -----------------------------------------------------------------
    // Section Cards
    // -----------------------------------------------------------------

    /** All six section headers are built once the key loads. */
    @Test
    fun allSectionCards_areBuiltForLoadedKey() {
        val scenario = launchWithSeededKey()
        val context = context()

        listOf(
            R.string.passkey_section_site,
            R.string.passkey_section_account,
            R.string.passkey_section_credential,
            R.string.passkey_section_security,
            R.string.passkey_section_usage,
            R.string.passkey_section_actions
        ).forEach { section ->
            awaitText(scenario, context.getString(section))
        }
    }

    // -----------------------------------------------------------------
    // Bound Values
    // -----------------------------------------------------------------

    @Test
    fun siteCard_showsRelyingPartyNameAndId() {
        val scenario = launchWithSeededKey()

        awaitText(scenario, TEST_RP_NAME)
        awaitText(scenario, TEST_RP_ID)
    }

    @Test
    fun accountCard_showsUserNameAndDisplayName() {
        val scenario = launchWithSeededKey()

        awaitText(scenario, TEST_USER_NAME)
        awaitText(scenario, TEST_USER_DISPLAY_NAME)
    }

    @Test
    fun credentialCard_showsAlgorithmAndSignCount() {
        val scenario = launchWithSeededKey()

        awaitText(scenario, TEST_ALGORITHM)
        awaitText(scenario, context().getString(R.string.passkey_sign_count))
    }

    /** A passkey with lastUsedAt == 0 renders the "Never" marker in Usage. */
    @Test
    fun usageCard_showsNeverUsedForFreshPasskey() {
        val scenario = launchWithSeededKey()

        awaitText(scenario, context().getString(R.string.passkey_never_used))
    }

    // -----------------------------------------------------------------
    // Delete Flow
    // -----------------------------------------------------------------

    @Test
    fun deleteAction_opensConfirmationDialog() {
        val scenario = launchWithSeededKey()
        awaitText(scenario, context().getString(R.string.key_action_delete))

        onView(withText(R.string.key_action_delete)).perform(scrollToView(), click())

        onView(withText(R.string.passkey_delete_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    @Test
    fun deleteConfirmation_cancelled_keepsPasskey() {
        val scenario = launchWithSeededKey()
        awaitText(scenario, context().getString(R.string.key_action_delete))

        onView(withText(R.string.key_action_delete)).perform(scrollToView(), click())
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertNotNull(
            "Cancelling the dialog must keep the passkey",
            runBlocking { keyDao.getByKeyId(testKeyId) }
        )
        assertTrue(
            "The detail screen should stay open after cancelling",
            scenario.state != Lifecycle.State.DESTROYED
        )
    }

    @Test
    fun deleteConfirmation_confirmed_deletesPasskeyAndFinishes() {
        runBlocking { keyDao.insert(passkey(deletableKeyId, "UI Test Doomed Passkey")) }
        val scenario = launchWithKey(deletableKeyId)
        awaitText(scenario, context().getString(R.string.key_action_delete))

        onView(withText(R.string.key_action_delete)).perform(scrollToView(), click())
        onView(withText(R.string.key_delete_confirm)).inRoot(isDialog()).perform(click())

        awaitCondition("Confirmed delete should remove the passkey from Room") {
            runBlocking { keyDao.getByKeyId(deletableKeyId) } == null
        }
        assertNull(runBlocking { keyDao.getByKeyId(deletableKeyId) })
        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Back Navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launchWithSeededKey()
        awaitText(scenario, TEST_RP_NAME)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun context(): Context = ApplicationProvider.getApplicationContext()

    private fun launchWithSeededKey(): ActivityScenario<PasskeyDetailActivity> =
        launchWithKey(testKeyId)

    private fun launchWithKey(keyId: String): ActivityScenario<PasskeyDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            PasskeyDetailActivity::class.java
        ).apply {
            putExtra(PasskeyDetailActivity.EXTRA_KEY_ID, keyId)
        }
        return ActivityScenario.launch(intent)
    }

    private fun passkey(keyId: String, label: String) = KeyEntity(
        keyId = keyId,
        keyType = "fido2",
        algorithm = TEST_ALGORITHM,
        label = label,
        keySizeBits = 256,
        biometricRequired = true,
        rpId = TEST_RP_ID,
        rpName = TEST_RP_NAME,
        userName = TEST_USER_NAME,
        userDisplayName = TEST_USER_DISPLAY_NAME,
        isDiscoverable = true,
        source = "local"
    )

    private companion object {
        const val TEST_ALGORITHM = "ES256"
        const val TEST_RP_ID = "ui-test-detail.example.com"
        const val TEST_RP_NAME = "UI Test Detail Site"
        const val TEST_USER_NAME = "ui-test-detail-user"
        const val TEST_USER_DISPLAY_NAME = "UI Test Detail User"
    }
}
