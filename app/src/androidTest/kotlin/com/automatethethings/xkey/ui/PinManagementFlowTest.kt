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
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.closeSoftKeyboard
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.pin.PinHasher
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The full PIN lifecycle driven through [PinManagementActivity].
 *
 * `PinManagementActivityUiTest` deliberately never provisions a PIN: it only
 * exercises the mismatch guard, which returns before
 * [com.automatethethings.xkey.pin.PinManager] is reached. This suite does the
 * opposite -- it provisions, changes, mis-authenticates, locks out and recovers
 * for real, which is the only way to reach the screen's success handlers, its
 * five distinct failure messages, the lockout card and its countdown, and the
 * state-dependent rebuild of the action cards.
 *
 * PIN state is global, persisted in DataStore and shared with the BLE/USB/TCP
 * request handler, so every test here would otherwise leak into the rest of the
 * device's suites. The whole [PinSettingsData] snapshot is therefore captured
 * in @Before, replaced with a clean default, and written back verbatim in
 * @After -- including `maxPinAttempts`, which some tests lower so a lockout can
 * be reached in two attempts instead of five.
 *
 * Seeding a starting state goes through [PinManager] rather than through
 * hand-written hashes, so the stored Argon2id material is genuine and the
 * screen's verification paths behave exactly as they do in the field. PIN
 * operations therefore cost a real Argon2id hash each, which is why the waits
 * here are longer than the shared default.
 *
 * Tests cover:
 * - Setting the SO PIN, and its length and confirmation-mismatch refusals
 * - Setting the User PIN with the SO PIN, and refusal on a wrong SO PIN
 * - Changing each PIN, and refusal on a wrong current PIN
 * - Failed-attempt counting, lockout after the configured maximum, and the
 *   refusal to change a locked PIN
 * - Reset-lockout via the SO PIN, and its refusal on a wrong SO PIN
 * - The lockout card: attempt counter, countdown, expiry, and staying hidden
 *   when there is nothing to report
 */
@RunWith(AndroidJUnit4::class)
class PinManagementFlowTest {

    private lateinit var context: Context
    private lateinit var repository: PinSettingsRepository

    /** The device's PIN state before this suite ran; restored in @After. */
    private lateinit var original: PinSettingsData

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        repository = PinSettingsRepository(context)
        runBlocking {
            original = repository.getSettings()
            repository.updateSettings(PinSettingsData())
        }
    }

    @After
    fun tearDown() {
        runBlocking { repository.updateSettings(original) }
    }

    // ---------------------------------------------------------------
    // SO PIN provisioning
    // ---------------------------------------------------------------

    /**
     * Setting the SO PIN persists it, flips the hero badges, and rebuilds the
     * action cards into their "initialized" arrangement.
     */
    @Test
    fun setSoPin_provisionsTheSecurityOfficerPin() {
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_set_so_title))

        openCard(scenario, R.string.pin_action_set_so_title)
        typeDialogField(0, SO_PIN)
        typeDialogField(1, SO_PIN)
        clickDialogButton(R.string.pin_button_set)

        awaitPinText(scenario, title(R.string.pin_success_so_set))
        assertTrue("The SO PIN should be persisted", settings().soPinSet)
        assertBadge(scenario, R.string.pin_label_so, R.string.pin_badge_set)
        assertBadge(scenario, R.string.pin_label_initialized, R.string.pin_badge_set)
        awaitText(scenario, title(R.string.pin_action_change_so_title))
        awaitText(scenario, title(R.string.pin_action_set_user_title))
        awaitTextAbsent(scenario, title(R.string.pin_action_set_so_title))
    }

    /** A PIN shorter than the minimum is refused with the hasher's own message. */
    @Test
    fun setSoPin_rejectsAPinBelowTheMinimumLength() {
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_set_so_title))

        openCard(scenario, R.string.pin_action_set_so_title)
        typeDialogField(0, TOO_SHORT_PIN)
        typeDialogField(1, TOO_SHORT_PIN)
        clickDialogButton(R.string.pin_button_set)

        awaitPinText(
            scenario,
            "PIN must be ${PinHasher.MIN_PIN_LENGTH}-${PinHasher.MAX_PIN_LENGTH} UTF-8 bytes"
        )
        assertTrue("A refused PIN must not be persisted", !settings().soPinSet)
    }

    // ---------------------------------------------------------------
    // User PIN provisioning
    // ---------------------------------------------------------------

    /** The SO PIN authorizes provisioning of the User PIN. */
    @Test
    fun setUserPin_withTheCorrectSoPin_provisionsTheUserPin() {
        provisionSoPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_set_user_title))

        openCard(scenario, R.string.pin_action_set_user_title)
        typeDialogField(0, SO_PIN)
        typeDialogField(1, USER_PIN)
        typeDialogField(2, USER_PIN)
        clickDialogButton(R.string.pin_button_set)

        awaitPinText(scenario, title(R.string.pin_success_user_set))
        assertTrue("The User PIN should be persisted", settings().userPinSet)
        assertBadge(scenario, R.string.pin_label_user, R.string.pin_badge_set)
        awaitText(scenario, title(R.string.pin_action_change_user_title))
        awaitTextAbsent(scenario, title(R.string.pin_action_set_user_title))
    }

    /**
     * A wrong SO PIN is refused, leaves the User PIN unprovisioned, and burns
     * one SO attempt -- which the lockout card immediately reports.
     */
    @Test
    fun setUserPin_withTheWrongSoPin_isRejectedAndCountsAFailedSoAttempt() {
        provisionSoPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_set_user_title))

        openCard(scenario, R.string.pin_action_set_user_title)
        typeDialogField(0, WRONG_PIN)
        typeDialogField(1, USER_PIN)
        typeDialogField(2, USER_PIN)
        clickDialogButton(R.string.pin_button_set)

        awaitPinText(scenario, INCORRECT_PIN)
        val after = settings()
        assertTrue("A wrong SO PIN must not provision a User PIN", !after.userPinSet)
        assertEquals("The failed SO attempt should be counted", 1, after.failedSoPinAttempts)
        awaitText(
            scenario,
            context.getString(
                R.string.pin_lockout_so_attempts,
                1,
                after.maxPinAttempts
            )
        )
    }

    /** A confirmation that differs is refused before the PIN manager is called. */
    @Test
    fun setUserPin_mismatchedConfirmation_showsTheMismatchError() {
        provisionSoPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_set_user_title))

        openCard(scenario, R.string.pin_action_set_user_title)
        typeDialogField(0, SO_PIN)
        typeDialogField(1, USER_PIN)
        typeDialogField(2, OTHER_PIN)
        clickDialogButton(R.string.pin_button_set)

        awaitText(scenario, title(R.string.pin_error_mismatch))
        val after = settings()
        assertTrue("A mismatch must not provision a User PIN", !after.userPinSet)
        assertEquals(
            "A mismatch must not reach the PIN manager, so no attempt is spent",
            0,
            after.failedSoPinAttempts
        )
    }

    /** Cancelling the User PIN dialog leaves the device unprovisioned. */
    @Test
    fun setUserPinDialog_cancel_provisionsNothing() {
        provisionSoPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_set_user_title))

        openCard(scenario, R.string.pin_action_set_user_title)
        typeDialogField(0, SO_PIN)
        typeDialogField(1, USER_PIN)
        typeDialogField(2, USER_PIN)
        clickDialogButton(R.string.button_cancel)

        waitForIdle()
        assertTrue("Cancelling must not provision a User PIN", !settings().userPinSet)
        awaitText(scenario, title(R.string.pin_action_set_user_title))
    }

    // ---------------------------------------------------------------
    // Changing PINs
    // ---------------------------------------------------------------

    /** Changing the SO PIN with the current one replaces the stored material. */
    @Test
    fun changeSoPin_withTheCurrentPin_replacesIt() {
        provisionSoPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_so_title))

        openCard(scenario, R.string.pin_action_change_so_title)
        typeDialogField(0, SO_PIN)
        typeDialogField(1, OTHER_PIN)
        typeDialogField(2, OTHER_PIN)
        clickDialogButton(R.string.pin_button_change)

        awaitPinText(scenario, title(R.string.pin_success_so_changed))
        assertTrue(
            "The new SO PIN should verify after the change",
            runBlocking { PinManager(repository).verifySOPIN(OTHER_PIN) }
        )
    }

    /** A wrong current SO PIN is refused and leaves the stored PIN untouched. */
    @Test
    fun changeSoPin_withTheWrongCurrentPin_leavesThePinInPlace() {
        provisionSoPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_so_title))

        openCard(scenario, R.string.pin_action_change_so_title)
        typeDialogField(0, WRONG_PIN)
        typeDialogField(1, OTHER_PIN)
        typeDialogField(2, OTHER_PIN)
        clickDialogButton(R.string.pin_button_change)

        awaitPinText(scenario, INCORRECT_PIN)
        assertEquals(
            "The failed SO attempt should be counted",
            1,
            settings().failedSoPinAttempts
        )
        assertTrue(
            "The original SO PIN should still verify",
            runBlocking { PinManager(repository).verifySOPIN(SO_PIN) }
        )
    }

    /** A mismatched confirmation on the change dialog never reaches the manager. */
    @Test
    fun changeSoPin_mismatchedConfirmation_showsTheMismatchError() {
        provisionSoPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_so_title))

        openCard(scenario, R.string.pin_action_change_so_title)
        typeDialogField(0, SO_PIN)
        typeDialogField(1, OTHER_PIN)
        typeDialogField(2, USER_PIN)
        clickDialogButton(R.string.pin_button_change)

        awaitText(scenario, title(R.string.pin_error_mismatch))
        assertEquals(
            "A mismatch must not spend an attempt",
            0,
            settings().failedSoPinAttempts
        )
    }

    /** Changing the User PIN needs the current User PIN, not the SO PIN. */
    @Test
    fun changeUserPin_withTheCurrentPin_replacesIt() {
        provisionSoPin()
        provisionUserPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_user_title))

        openCard(scenario, R.string.pin_action_change_user_title)
        typeDialogField(0, USER_PIN)
        typeDialogField(1, OTHER_PIN)
        typeDialogField(2, OTHER_PIN)
        clickDialogButton(R.string.pin_button_change)

        awaitPinText(scenario, title(R.string.pin_success_user_changed))
        assertTrue(
            "The new User PIN should verify after the change",
            runBlocking { PinManager(repository).verifyUserPIN(OTHER_PIN) }
        )
    }

    /** A wrong current User PIN is refused and burns one User attempt. */
    @Test
    fun changeUserPin_withTheWrongCurrentPin_isRejectedAndCountsAFailedUserAttempt() {
        provisionSoPin()
        provisionUserPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_user_title))

        changeUserPinWith(scenario, WRONG_PIN)

        awaitPinText(scenario, INCORRECT_PIN)
        val after = settings()
        assertEquals("The failed User attempt should be counted", 1, after.failedUserPinAttempts)
        awaitText(
            scenario,
            context.getString(R.string.pin_lockout_user_attempts, 1, after.maxPinAttempts)
        )
    }

    // ---------------------------------------------------------------
    // Lockout
    // ---------------------------------------------------------------

    /**
     * Exhausting the attempt budget locks the User PIN, which surfaces the
     * "Reset Lockout" action card the screen otherwise never shows.
     *
     * `maxPinAttempts` is lowered to two so this costs two Argon2id hashes
     * rather than five; the value is part of the restored snapshot.
     */
    @Test
    fun repeatedWrongUserPins_lockTheUserPinAndOfferTheResetCard() {
        seedMaxAttempts(SHORT_MAX_ATTEMPTS)
        provisionSoPin()
        provisionUserPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_user_title))

        // The refusal snackbar lingers for several seconds, so each attempt is
        // sequenced on the persisted counter rather than on the message: a
        // second snackbar assertion would happily match the first one's view.
        repeat(SHORT_MAX_ATTEMPTS) { attempt ->
            changeUserPinWith(scenario, WRONG_PIN)
            awaitFailedUserAttempts(attempt + 1)
        }

        val after = settings()
        assertEquals(
            "Every wrong attempt should have been counted",
            SHORT_MAX_ATTEMPTS,
            after.failedUserPinAttempts
        )
        assertTrue(
            "The User PIN should be locked once the maximum is reached",
            after.userPinLockedUntil > System.currentTimeMillis()
        )
        awaitText(scenario, title(R.string.pin_action_reset_lockout_title))
        awaitText(
            scenario,
            context.getString(
                R.string.pin_lockout_user_attempts,
                SHORT_MAX_ATTEMPTS,
                SHORT_MAX_ATTEMPTS
            ) + title(R.string.pin_lockout_locked_suffix)
        )
    }

    /** A locked User PIN cannot be changed, and the refusal names the lockout. */
    @Test
    fun changingTheUserPinWhileLocked_reportsTheLockout() {
        provisionSoPin()
        provisionUserPin()
        seedUserLockout(LONG_LOCKOUT_MS)
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_user_title))

        changeUserPinWith(scenario, USER_PIN)

        awaitPinText(scenario, lockedPrefix(R.string.pin_error_user_locked))
    }

    /** The SO PIN clears a User PIN lockout without knowing the User PIN. */
    @Test
    fun resetLockout_withTheSoPin_clearsTheLockout() {
        provisionSoPin()
        provisionUserPin()
        seedUserLockout(LONG_LOCKOUT_MS)
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_reset_lockout_title))

        openCard(scenario, R.string.pin_action_reset_lockout_title)
        typeDialogField(0, SO_PIN)
        clickDialogButton(R.string.pin_button_reset)

        awaitPinText(scenario, title(R.string.pin_success_lockout_reset))
        val after = settings()
        assertEquals("The lockout deadline should be cleared", 0L, after.userPinLockedUntil)
        assertEquals("The attempt counter should be cleared", 0, after.failedUserPinAttempts)
        awaitTextAbsent(scenario, title(R.string.pin_action_reset_lockout_title))
    }

    /** A wrong SO PIN cannot clear the lockout. */
    @Test
    fun resetLockout_withTheWrongSoPin_leavesTheLockoutInPlace() {
        provisionSoPin()
        provisionUserPin()
        seedUserLockout(LONG_LOCKOUT_MS)
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_reset_lockout_title))

        openCard(scenario, R.string.pin_action_reset_lockout_title)
        typeDialogField(0, WRONG_PIN)
        clickDialogButton(R.string.pin_button_reset)

        awaitPinText(scenario, INCORRECT_PIN)
        assertTrue(
            "A wrong SO PIN must leave the User PIN locked",
            settings().userPinLockedUntil > System.currentTimeMillis()
        )
    }

    // ---------------------------------------------------------------
    // Lockout card
    // ---------------------------------------------------------------

    /** While locked, the card counts the remaining time down. */
    @Test
    fun lockoutCard_countsDownWhileLocked() {
        provisionSoPin()
        provisionUserPin()
        seedUserLockout(LONG_LOCKOUT_MS)

        val scenario = launch()

        awaitText(scenario, context.getString(R.string.pin_lockout_time_remaining, "").trim())
        awaitText(scenario, title(R.string.pin_lockout_badge))
    }

    /**
     * When the deadline passes, the countdown reports the expiry in place.
     *
     * The lockout is seeded *after* the screen is up: seeding it beforehand
     * would race activity start-up against a deadline only seconds away, and a
     * slow launch would leave nothing for the countdown to count.
     */
    @Test
    fun lockoutCard_reportsExpiryWhenTheCountdownFinishes() {
        provisionSoPin()
        provisionUserPin()
        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_user_title))

        seedUserLockout(BRIEF_LOCKOUT_MS)

        awaitText(scenario, title(R.string.pin_lockout_expired), COUNTDOWN_AWAIT_MS)
    }

    /**
     * Failed attempts that have not yet reached the maximum show the counter
     * but not the LOCKED badge.
     */
    @Test
    fun failedAttemptsWithoutLockout_showTheCounterWithoutTheLockedBadge() {
        provisionSoPin()
        provisionUserPin()
        seedSettings(settings().copy(failedUserPinAttempts = 1, userPinLockedUntil = 0))

        val scenario = launch()

        awaitText(
            scenario,
            context.getString(R.string.pin_lockout_user_attempts, 1, settings().maxPinAttempts)
        )
        awaitTextAbsent(scenario, title(R.string.pin_lockout_badge))
        awaitTextAbsent(scenario, title(R.string.pin_action_reset_lockout_title))
    }

    /** With no failures and no lockout, the whole card stays hidden. */
    @Test
    fun lockoutCard_isHiddenWhenThereIsNothingToReport() {
        provisionSoPin()
        provisionUserPin()

        val scenario = launch()
        awaitText(scenario, title(R.string.pin_action_change_user_title))

        awaitTextAbsent(scenario, title(R.string.pin_lockout_title))
        awaitTextAbsent(scenario, title(R.string.pin_lockout_badge))
    }

    // ---------------------------------------------------------------
    // Helpers: activity and dialogs
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<PinManagementActivity> =
        ActivityScenario.launch(PinManagementActivity::class.java)

    private fun title(resId: Int): String = context.getString(resId)

    /** Taps the action card whose title is [titleRes]. */
    private fun openCard(scenario: ActivityScenario<PinManagementActivity>, titleRes: Int) {
        clickTextInTree(scenario, title(titleRes))
    }

    /**
     * Replaces the text of the dialog's [index]-th field.
     *
     * PIN dialogs wrap their fields in `TextInputLayout`s whose hints Espresso
     * cannot match, so fields are addressed by the order they were built in.
     */
    private fun typeDialogField(index: Int, text: String) {
        onView(
            nthMatch(allOf(isAssignableFrom(EditText::class.java), isDisplayed()), index)
        )
            .inRoot(isDialog())
            .perform(replaceText(text))
        closeSoftKeyboard()
    }

    /**
     * Clicks the dialog button labelled [buttonRes].
     *
     * `pin_button_set` and `pin_badge_set` are both "Set", so the interaction is
     * scoped to the dialog root; within it, the exact-text match pins the click
     * to the button rather than the dialog title.
     */
    private fun clickDialogButton(buttonRes: Int) {
        onView(withText(buttonRes)).inRoot(isDialog()).perform(click())
    }

    /**
     * Drives the "Change User PIN" dialog with [currentPin] as the current PIN
     * and a fixed, valid replacement.
     */
    private fun changeUserPinWith(
        scenario: ActivityScenario<PinManagementActivity>,
        currentPin: String
    ) {
        openCard(scenario, R.string.pin_action_change_user_title)
        typeDialogField(0, currentPin)
        typeDialogField(1, OTHER_PIN)
        typeDialogField(2, OTHER_PIN)
        clickDialogButton(R.string.pin_button_change)
    }

    // ---------------------------------------------------------------
    // Helpers: waiting
    // ---------------------------------------------------------------

    /**
     * Waits for [text] with a budget that allows for a real Argon2id hash.
     *
     * Every PIN operation hashes with 64 MiB / 3 iterations -- once to verify
     * and once more to store -- and the snackbar only appears afterwards, so
     * the shared five-second default is not enough headroom on an emulator.
     */
    private fun awaitPinText(scenario: ActivityScenario<PinManagementActivity>, text: String) {
        awaitText(scenario, text, PIN_AWAIT_MS)
    }

    /**
     * Asserts the badge beside the hero row labelled [labelRes] reads
     * [badgeRes].
     *
     * Rows are built as `[label][badge]`, so the badge is the label's sibling;
     * the text is written by the settings-flow collector, hence the poll.
     */
    private fun assertBadge(
        scenario: ActivityScenario<PinManagementActivity>,
        labelRes: Int,
        badgeRes: Int
    ) {
        val label = title(labelRes)
        val badge = title(badgeRes)
        awaitCondition("Badge next to '$label' should read '$badge'", PIN_AWAIT_MS) {
            withActivity(scenario) { activity ->
                val labelView = collectViews(activity.window.decorView) {
                    it is TextView && it.text?.toString() == label
                }.firstOrNull()
                val row = labelView?.parent as? ViewGroup
                row != null && collectViews(row) {
                    it is TextView && it !== labelView && it.text?.toString() == badge
                }.isNotEmpty()
            }
        }
    }

    // ---------------------------------------------------------------
    // Helpers: state seeding
    // ---------------------------------------------------------------

    private fun settings(): PinSettingsData = runBlocking { repository.getSettings() }

    private fun seedSettings(data: PinSettingsData) {
        runBlocking { repository.updateSettings(data) }
    }

    /** Lowers the attempt budget before any PIN is provisioned. */
    private fun seedMaxAttempts(max: Int) {
        seedSettings(settings().copy(maxPinAttempts = max))
    }

    /** Provisions the SO PIN through the real manager, hash and all. */
    private fun provisionSoPin() {
        runBlocking { PinManager(repository).setSOPIN(currentSOPIN = null, newSOPIN = SO_PIN) }
    }

    /** Provisions the User PIN through the real manager, hash and all. */
    private fun provisionUserPin() {
        runBlocking { PinManager(repository).setUserPIN(soPIN = SO_PIN, newUserPIN = USER_PIN) }
    }

    /** Puts the User PIN into a lockout that expires [durationMs] from now. */
    private fun seedUserLockout(durationMs: Long) {
        val current = settings()
        seedSettings(
            current.copy(
                failedUserPinAttempts = current.maxPinAttempts,
                userPinLockedUntil = System.currentTimeMillis() + durationMs
            )
        )
    }

    /** Polls the persisted counter until it reaches [expected]. */
    private fun awaitFailedUserAttempts(expected: Int) {
        awaitCondition(
            "Expected $expected failed User PIN attempts to be persisted",
            PIN_AWAIT_MS
        ) {
            settings().failedUserPinAttempts == expected
        }
    }

    /**
     * The fixed part of a "PIN is locked" message.
     *
     * The message embeds a remaining-seconds count that ticks down between the
     * refusal and the assertion, so only the text before the colon is stable.
     */
    private fun lockedPrefix(resId: Int): String =
        context.getString(resId, 0).substringBefore(':') + ":"

    private companion object {

        const val SO_PIN = "so-pin-123456"
        const val USER_PIN = "user-pin-123456"
        const val OTHER_PIN = "other-pin-123456"
        const val WRONG_PIN = "wrong-pin-123456"

        /** One byte under [PinHasher.MIN_PIN_LENGTH]. */
        const val TOO_SHORT_PIN = "12345"

        /** Message [com.automatethethings.xkey.pin.PinException] carries verbatim. */
        const val INCORRECT_PIN = "Incorrect PIN"

        /** Attempt budget used by the lockout test, restored with the snapshot. */
        const val SHORT_MAX_ATTEMPTS = 2

        /** Long enough that the lockout cannot expire mid-test. */
        const val LONG_LOCKOUT_MS = 300_000L

        /** Short enough that the countdown's onFinish runs during the test. */
        const val BRIEF_LOCKOUT_MS = 2_500L

        /** Budget covering a real Argon2id hash plus the snackbar. */
        const val PIN_AWAIT_MS = 20_000L

        /** Budget covering [BRIEF_LOCKOUT_MS] plus the final countdown tick. */
        const val COUNTDOWN_AWAIT_MS = 15_000L
    }
}
