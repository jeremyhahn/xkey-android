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
import org.hamcrest.CoreMatchers.not
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [KeyDetailActivity].
 *
 * KeyDetailActivity builds its UI programmatically (no XML layout ids) and
 * requires a valid [KeyDetailActivity.EXTRA_KEY_ID] intent extra. Without a key
 * id it calls finish() immediately in onCreate; with an unknown id it also
 * finishes, after a coroutine-based DB lookup. It has no static toolbar text --
 * hero title, badges and every info card are populated asynchronously -- so
 * content assertions poll via [awaitText].
 *
 * Two representative rows are seeded into the real Room database: a signing key
 * and a FIDO2 key, because the FIDO2 metadata and Sharing cards are only built
 * for `keyType == "fido2"`. Both rows are removed in @After.
 *
 * Tests cover:
 * - Launch behaviour: finishes without EXTRA_KEY_ID
 * - Hero section: label plus the algorithm and key-type badges
 * - General/Security/Usage/Attestation/Actions cards and their bound values
 * - Card set varies by key type: FIDO2 metadata + Sharing only for passkeys
 * - Delete bottom sheet: cancelling keeps the key
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class KeyDetailActivityUiTest {

    // Unique per test instance so parallel/leftover rows never collide.
    private val runId = System.nanoTime()
    private val testKeyId = "ui-test-key-detail-$runId"
    private val fido2KeyId = "ui-test-key-detail-fido2-$runId"

    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = testKeyId,
                    keyType = "signing",
                    algorithm = TEST_ALGORITHM,
                    label = TEST_LABEL,
                    keySizeBits = 256,
                    source = "local"
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            keyDao.deleteByKeyId(testKeyId)
            keyDao.deleteByKeyId(fido2KeyId)
        }
        Intents.release()
    }

    // -----------------------------------------------------------------
    // Launch Behavior
    // -----------------------------------------------------------------

    /**
     * When launched without [KeyDetailActivity.EXTRA_KEY_ID], the activity
     * calls finish() synchronously in onCreate and reaches DESTROYED.
     */
    @Test
    fun activity_finishesWithoutKeyId() {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            KeyDetailActivity::class.java
        )
        val scenario = ActivityScenario.launch<KeyDetailActivity>(intent)

        assertTrue(
            "Activity should finish when launched without EXTRA_KEY_ID",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    // -----------------------------------------------------------------
    // Hero Section
    // -----------------------------------------------------------------

    @Test
    fun heroSection_showsKeyLabel() {
        val scenario = launchWithKey(testKeyId)

        awaitText(scenario, TEST_LABEL)

        onView(withText(TEST_LABEL))
            .check(matches(isDisplayed()))
    }

    /** The hero renders an algorithm badge and a key-type badge. */
    @Test
    fun heroSection_showsAlgorithmAndTypeBadges() {
        val scenario = launchWithKey(testKeyId)
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, TEST_ALGORITHM)
        awaitText(scenario, context.getString(R.string.key_filter_signing))
    }

    // -----------------------------------------------------------------
    // Info Cards
    // -----------------------------------------------------------------

    @Test
    fun securityCard_isShown() {
        val scenario = launchWithKey(testKeyId)

        awaitText(scenario, "Security")
    }

    @Test
    fun actionsCard_isShown() {
        val scenario = launchWithKey(testKeyId)

        awaitText(scenario, "Actions")
    }

    /** General Information binds the key id, algorithm and key size. */
    @Test
    fun generalInfoCard_bindsIdentityFields() {
        val scenario = launchWithKey(testKeyId)
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, testKeyId)
        awaitText(scenario, context.getString(R.string.key_detail_algorithm))
        awaitText(scenario, "256 bits")
        awaitText(scenario, context.getString(R.string.key_source_local))
    }

    // -----------------------------------------------------------------
    // Card set varies by key type
    // -----------------------------------------------------------------

    /** FIDO2 keys additionally get the FIDO2 metadata and Sharing cards. */
    @Test
    fun fido2Key_showsFido2MetadataAndSharingCards() {
        seedFido2Key()
        val scenario = launchWithKey(fido2KeyId)
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, context.getString(R.string.key_section_fido2))
        awaitText(scenario, context.getString(R.string.sharing_settings_title))
        awaitText(scenario, FIDO2_RP_ID)
    }

    /** A non-FIDO2 key must not render the FIDO2 metadata card. */
    @Test
    fun signingKey_doesNotShowFido2MetadataCard() {
        val scenario = launchWithKey(testKeyId)
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, "General Information")
        awaitTextAbsent(scenario, context.getString(R.string.key_section_fido2), timeoutMs = 1_500L)
    }

    // -----------------------------------------------------------------
    // Delete bottom sheet
    // -----------------------------------------------------------------

    @Test
    fun deleteBottomSheet_cancelled_keepsKey() {
        val scenario = launchWithKey(testKeyId)
        awaitText(scenario, "Delete Key")

        onView(withText(R.string.key_action_delete))
            .inRoot(not(isDialog()))
            .perform(scrollToView(), click())
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertNotNull(
            "Dismissing the bottom sheet must keep the key",
            runBlocking { keyDao.getByKeyId(testKeyId) }
        )
        assertTrue(
            "The detail screen should stay open after cancelling",
            scenario.state != Lifecycle.State.DESTROYED
        )
    }

    // -----------------------------------------------------------------
    // Back Navigation
    // -----------------------------------------------------------------

    /**
     * Pressing back finishes the activity and transitions to DESTROYED.
     */
    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launchWithKey(testKeyId)
        awaitText(scenario, TEST_LABEL)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launchWithKey(keyId: String): ActivityScenario<KeyDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            KeyDetailActivity::class.java
        ).apply {
            putExtra(KeyDetailActivity.EXTRA_KEY_ID, keyId)
        }
        return ActivityScenario.launch(intent)
    }

    private fun seedFido2Key() {
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = fido2KeyId,
                    keyType = "fido2",
                    algorithm = TEST_ALGORITHM,
                    label = "UI Test Detail Passkey",
                    keySizeBits = 256,
                    rpId = FIDO2_RP_ID,
                    rpName = "UI Test Detail RP",
                    userName = "ui-test-detail-user",
                    isDiscoverable = true,
                    source = "local"
                )
            )
        }
    }

    private companion object {
        const val TEST_LABEL = "UI Test Signing Key"
        const val TEST_ALGORITHM = "ES256"
        const val FIDO2_RP_ID = "ui-test-keydetail.example.com"
    }
}
