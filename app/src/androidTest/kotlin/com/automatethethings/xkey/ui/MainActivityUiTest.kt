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
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.matcher.ViewMatchers.isClickable
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.not
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for [MainActivity].
 *
 * The home screen is a single NestedScrollView whose sections are shown and
 * hidden by the bottom navigation bar:
 * - Dashboard: hero section + Device Info (no action cards)
 * - Apps: Authenticator, Passkeys, PIV Smart Card
 * - Store: Key Management, Certificates, Trust Store, Contacts, Passwords
 * - Management: Sync, PIN, Co-Sign, Paired Devices, Audit Log, Settings
 *
 * Tests cover:
 * - Dashboard content and status text at rest
 * - Tab switching: exactly one container visible per tab, hero only on Dashboard
 * - Tab headers built programmatically for each container
 * - Card counts bound from the live Room store (passkeys, authenticator)
 * - Each card navigating to its activity with the right component
 * - The Sync card's not-connected path surfacing a snackbar
 *
 * Cards live far down a scrolling layout, so navigation tests scroll the target
 * into view before tapping. The seeded passkey is deleted in @After.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityUiTest {

    private val testKeyId = "ui-test-main-passkey-${System.nanoTime()}"

    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
    }

    @After
    fun tearDown() {
        runBlocking { keyDao.deleteByKeyId(testKeyId) }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Dashboard
    // ---------------------------------------------------------------

    @Test
    fun heroSection_isDisplayed() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.heroSection))
            .check(matches(isDisplayed()))
    }

    @Test
    fun bleSwitch_isDisplayed() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.switchBle))
            .check(matches(isDisplayed()))
            .check(matches(isClickable()))
    }

    /** With no service bound the switch label reads the "off" string. */
    @Test
    fun bleStatusText_readsOffAtRest() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.textBleStatus))
            .check(matches(withText(R.string.ble_switch_off)))
    }

    @Test
    fun statusText_showsDisconnected() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.textStatusLarge))
            .check(matches(isDisplayed()))
            .check(matches(withText(R.string.status_disconnected)))
    }

    @Test
    fun statusDescription_showsNoDeviceConnected() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.textStatusDescription))
            .check(matches(isDisplayed()))
            .check(matches(withText(R.string.connection_indicator_disconnected)))
    }

    @Test
    fun deviceInformationCard_isDisplayed() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.cardDeviceInformation))
            .check(matches(isDisplayed()))
    }

    @Test
    fun appTagline_isDisplayed() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withText(R.string.app_tagline))
            .check(matches(isDisplayed()))
    }

    @Test
    fun dashboard_doesNotShowActionCards() {
        ActivityScenario.launch(MainActivity::class.java)

        // Dashboard should only show hero + device info, not action cards
        onView(withId(R.id.containerApps))
            .check(matches(not(isDisplayed())))
        onView(withId(R.id.containerStore))
            .check(matches(not(isDisplayed())))
        onView(withId(R.id.containerManagement))
            .check(matches(not(isDisplayed())))
    }

    // ---------------------------------------------------------------
    // Tab switching
    // ---------------------------------------------------------------

    @Test
    fun appsTab_showsOnlyTheAppsContainer() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_applications)).perform(click())

        onView(withId(R.id.containerApps)).check(matches(isDisplayed()))
        onView(withId(R.id.containerStore)).check(matches(not(isDisplayed())))
        onView(withId(R.id.containerManagement)).check(matches(not(isDisplayed())))
        onView(withId(R.id.heroSection)).check(matches(not(isDisplayed())))
        onView(withId(R.id.cardDeviceInformation)).check(matches(not(isDisplayed())))
    }

    @Test
    fun storeTab_showsOnlyTheStoreContainer() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_store)).perform(click())

        onView(withId(R.id.containerStore)).check(matches(isDisplayed()))
        onView(withId(R.id.containerApps)).check(matches(not(isDisplayed())))
        onView(withId(R.id.containerManagement)).check(matches(not(isDisplayed())))
        onView(withId(R.id.heroSection)).check(matches(not(isDisplayed())))
    }

    @Test
    fun managementTab_showsOnlyTheManagementContainer() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_management)).perform(click())

        onView(withId(R.id.containerManagement)).check(matches(isDisplayed()))
        onView(withId(R.id.containerApps)).check(matches(not(isDisplayed())))
        onView(withId(R.id.containerStore)).check(matches(not(isDisplayed())))
        onView(withId(R.id.heroSection)).check(matches(not(isDisplayed())))
    }

    /** Switching away and back restores the dashboard-only content. */
    @Test
    fun returningToDashboard_restoresHeroAndHidesContainers() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_store)).perform(click())
        onView(withId(R.id.containerStore)).check(matches(isDisplayed()))

        onView(withId(R.id.nav_dashboard)).perform(click())

        onView(withId(R.id.heroSection)).check(matches(isDisplayed()))
        onView(withId(R.id.cardDeviceInformation)).check(matches(isDisplayed()))
        onView(withId(R.id.containerStore)).check(matches(not(isDisplayed())))
    }

    // ---------------------------------------------------------------
    // Programmatic tab headers
    // ---------------------------------------------------------------

    @Test
    fun appsTab_showsItsHeader() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_applications)).perform(click())

        onView(withText(R.string.tab_apps_title)).check(matches(isDisplayed()))
        onView(withText(R.string.tab_apps_subtitle)).check(matches(isDisplayed()))
    }

    @Test
    fun storeTab_showsItsHeader() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_store)).perform(click())

        onView(withText(R.string.tab_store_title)).check(matches(isDisplayed()))
        onView(withText(R.string.tab_store_subtitle)).check(matches(isDisplayed()))
    }

    @Test
    fun managementTab_showsItsHeader() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_management)).perform(click())

        onView(withText(R.string.tab_management_title)).check(matches(isDisplayed()))
        onView(withText(R.string.tab_management_subtitle)).check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Live counts on cards
    // ---------------------------------------------------------------

    /**
     * The Passkeys card subtitle is rendered from the live fido2 key count, so
     * the expectation is derived from Room rather than hard-coded.
     */
    @Test
    fun passkeysCard_showsLivePasskeyCount() {
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = testKeyId,
                    keyType = "fido2",
                    algorithm = "ES256",
                    label = "UI Test Main Passkey",
                    keySizeBits = 256,
                    rpId = "ui-test-main.example.com",
                    rpName = "UI Test Main",
                    userName = "ui-test-main-user",
                    source = "local"
                )
            )
        }
        val context = ApplicationProvider.getApplicationContext<Context>()
        val count = runBlocking { keyDao.countByType("fido2") }
        val expected = when (count) {
            0 -> context.getString(R.string.passkeys_card_description)
            1 -> context.getString(R.string.passkeys_count_one)
            else -> context.getString(R.string.passkeys_count, count)
        }

        val scenario = ActivityScenario.launch(MainActivity::class.java)
        onView(withId(R.id.nav_applications)).perform(click())

        awaitText(scenario, expected)
        onView(withId(R.id.textPasskeysCount)).check(matches(withText(expected)))
    }

    /** The Authenticator card subtitle is rendered from the live OATH count. */
    @Test
    fun authenticatorCard_showsLiveCredentialCount() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val count = runBlocking {
            XKeyDatabase.getInstance(context).oathCredentialDao().count()
        }
        val expected = when (count) {
            0 -> context.getString(R.string.oath_card_description)
            1 -> context.getString(R.string.oath_count_one)
            else -> context.getString(R.string.oath_count, count)
        }

        val scenario = ActivityScenario.launch(MainActivity::class.java)
        onView(withId(R.id.nav_applications)).perform(click())

        awaitText(scenario, expected)
        onView(withId(R.id.textOathCount)).check(matches(withText(expected)))
    }

    // ---------------------------------------------------------------
    // Card presence
    // ---------------------------------------------------------------

    @Test
    fun pairedDevicesCard_isDisplayedInManageTab() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_management)).perform(click())

        onView(withId(R.id.cardPairedDevices))
            .perform(scrollToView())
            .check(matches(isDisplayed()))
            .check(matches(isClickable()))
    }

    // ---------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------

    @Test
    fun settingsCard_opensSettingsActivity() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_management)).perform(click())
        onView(withId(R.id.cardSettings)).perform(scrollToView(), click())

        Intents.intended(hasComponent(SettingsActivity::class.java.name))
    }

    @Test
    fun authenticatorCard_opensOathActivity() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_applications)).perform(click())
        onView(withId(R.id.cardAuthenticator)).perform(scrollToView(), click())

        Intents.intended(hasComponent(OathActivity::class.java.name))
    }

    @Test
    fun passkeysCard_opensPasskeysActivity() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_applications)).perform(click())
        onView(withId(R.id.cardPasskeys)).perform(scrollToView(), click())

        Intents.intended(hasComponent(PasskeysActivity::class.java.name))
    }

    @Test
    fun keyManagementCard_opensKeyManagementActivity() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_store)).perform(click())
        onView(withId(R.id.cardKeyManagement)).perform(scrollToView(), click())

        Intents.intended(hasComponent(KeyManagementActivity::class.java.name))
    }

    @Test
    fun passwordsCard_opensPasswordManagementActivity() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_store)).perform(click())
        onView(withId(R.id.cardPasswords)).perform(scrollToView(), click())

        Intents.intended(hasComponent(PasswordManagementActivity::class.java.name))
    }

    @Test
    fun auditLogCard_opensAuditLogActivity() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_management)).perform(click())
        onView(withId(R.id.cardAuditLog)).perform(scrollToView(), click())

        Intents.intended(hasComponent(AuditLogActivity::class.java.name))
    }

    @Test
    fun pinManagementCard_opensPinManagementActivity() {
        ActivityScenario.launch(MainActivity::class.java)

        onView(withId(R.id.nav_management)).perform(click())
        onView(withId(R.id.cardPinManagement)).perform(scrollToView(), click())

        Intents.intended(hasComponent(PinManagementActivity::class.java.name))
    }

    // ---------------------------------------------------------------
    // Sync card behaviour
    // ---------------------------------------------------------------

    @Test
    fun syncNowCard_whenNotConnected_showsSnackbar() {
        ActivityScenario.launch(MainActivity::class.java)

        // Navigate to Management tab, then tap the Sync with Desktop card.
        // No BLE permissions are granted in the test, so the service is never
        // bound and the tap takes the "not connected" branch.
        onView(withId(R.id.nav_management)).perform(click())
        onView(withText(R.string.sync_now_title)).check(matches(isDisplayed()))
        onView(withId(R.id.cardSyncNow)).perform(click())

        onView(withText(R.string.sync_not_connected))
            .check(matches(isDisplayed()))
    }
}
