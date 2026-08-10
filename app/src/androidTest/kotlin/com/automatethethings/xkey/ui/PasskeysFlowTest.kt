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
import android.app.Instrumentation
import android.content.Context
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.espresso.matcher.RootMatchers.isDialog
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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for the [PasskeysActivity] list variants the basic suite
 * does not produce.
 *
 * `PasskeysActivityUiTest` seeds one fully-populated passkey — relying-party
 * name, username, discoverable, biometric — which leaves every fallback in
 * [PasskeyAdapter] unbound: the title's two-step fallback, the hidden account
 * row, the security badges a software credential does not earn, and the
 * relative last-used stamp. It also stops short of the context menu's first
 * entry, which is the only path from the list to the detail screen besides a
 * plain tap.
 *
 * Rows are read as a whole ([rowTexts]) rather than by scanning the screen: the
 * same badge labels appear on every row and in the hero card, so an assertion
 * has to be scoped to the row under test.
 *
 * Tests cover:
 * - Context menu "View Details" navigating with the row's key id
 * - Title falling back from relying-party name to id to the stored label
 * - Account row hidden with no user name, and the display-name fallback
 * - All three security badges, and a credential that earns none
 * - A used passkey showing a relative time instead of "Never"
 *
 * Every seeded row is deleted in @After.
 */
@RunWith(AndroidJUnit4::class)
class PasskeysFlowTest {

    private val runId = System.nanoTime()
    private val seededKeyIds = mutableListOf<String>()

    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        Intents.init()
        // Keep navigation from actually launching the detail screen.
        intending(hasComponent(PasskeyDetailActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, null)
        )

        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
    }

    @After
    fun tearDown() {
        runBlocking { seededKeyIds.forEach { keyDao.deleteByKeyId(it) } }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------

    @Test
    fun contextMenuViewDetails_opensTheDetailScreenWithThatKeyId() {
        val keyId = seed(rpName = "Flow Context Site $runId")

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        assertShownTextInList(scenario, "Flow Context Site $runId")

        RowFlowInteractions.longClickText(scenario, "Flow Context Site $runId")
        onView(withText(R.string.passkey_context_view_details))
            .inRoot(isDialog())
            .perform(click())

        intended(
            allOf(
                hasComponent(PasskeyDetailActivity::class.java.name),
                hasExtra(PasskeyDetailActivity.EXTRA_KEY_ID, keyId)
            )
        )
    }

    // ---------------------------------------------------------------
    // Title fallbacks
    // ---------------------------------------------------------------

    /** With no relying-party name the row is titled with the relying-party id. */
    @Test
    fun passkeyWithoutARelyingPartyName_showsTheRelyingPartyId() {
        val rpId = "flow-no-name-$runId.example.com"
        seed(rpName = null, rpId = rpId, label = "unused label $runId")

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)

        assertShownTextInList(scenario, rpId)
    }

    /** With neither name nor id the stored label is the last resort. */
    @Test
    fun passkeyWithoutNameOrId_showsTheStoredLabel() {
        val label = "Flow Label Only $runId"
        seed(rpName = null, rpId = null, label = label)

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)

        assertShownTextInList(scenario, label)
    }

    // ---------------------------------------------------------------
    // Account row
    // ---------------------------------------------------------------

    @Test
    fun passkeyWithoutAUserName_hidesTheAccountRow() {
        val rpName = "Flow No User $runId"
        seed(rpName = rpName, userName = null, userDisplayName = null)

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        assertShownTextInList(scenario, rpName)

        assertEquals(
            "The account row must be hidden when there is no user to show",
            View.GONE,
            rowView(scenario, rpName, "userName").visibility
        )
    }

    /** The display name stands in when the credential carries no user name. */
    @Test
    fun passkeyWithOnlyADisplayName_usesItForTheAccountRow() {
        val rpName = "Flow Display Name $runId"
        val displayName = "Flow Display Person $runId"
        seed(rpName = rpName, userName = null, userDisplayName = displayName)

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        assertShownTextInList(scenario, rpName)

        val account = rowView(scenario, rpName, "userName") as TextView
        assertEquals(displayName, account.text.toString())
        assertEquals(View.VISIBLE, account.visibility)
    }

    // ---------------------------------------------------------------
    // Security badges
    // ---------------------------------------------------------------

    @Test
    fun hardwareBackedPasskey_showsEverySecurityBadge() {
        val rpName = "Flow Hardened Site $runId"
        seed(
            rpName = rpName,
            isDiscoverable = true,
            biometricRequired = true,
            strongBoxBacked = true
        )

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        assertShownTextInList(scenario, rpName)

        val texts = rowTexts(scenario, rpName)
        val biometric = withActivity(scenario) { it.getString(R.string.key_badge_biometric) }
        val strongBox = withActivity(scenario) { it.getString(R.string.key_badge_strongbox) }
        assertTrue("Expected a Discoverable badge, found $texts", texts.contains("Discoverable"))
        assertTrue("Expected a $biometric badge, found $texts", texts.contains(biometric))
        assertTrue("Expected a $strongBox badge, found $texts", texts.contains(strongBox))
    }

    /** A software, non-discoverable credential earns no badges at all. */
    @Test
    fun softwarePasskey_showsNoSecurityBadges() {
        val rpName = "Flow Plain Site $runId"
        seed(
            rpName = rpName,
            isDiscoverable = false,
            biometricRequired = false,
            strongBoxBacked = false
        )

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        assertShownTextInList(scenario, rpName)

        val badgeRow = rowView(scenario, rpName, "badgeRow") as android.view.ViewGroup
        assertEquals("No badge should be added to this row", 0, badgeRow.childCount)
    }

    // ---------------------------------------------------------------
    // Last used
    // ---------------------------------------------------------------

    /**
     * A used credential renders a relative timestamp. The exact wording is
     * locale- and clock-dependent, so the assertion is that it is no longer the
     * "never used" marker.
     */
    @Test
    fun usedPasskey_showsARelativeTimeInsteadOfNever() {
        val rpName = "Flow Used Site $runId"
        seed(rpName = rpName, lastUsedAt = System.currentTimeMillis() - TWO_HOURS_MS)

        val scenario = ActivityScenario.launch(PasskeysActivity::class.java)
        assertShownTextInList(scenario, rpName)

        val never = withActivity(scenario) { it.getString(R.string.passkey_never_used) }
        val lastUsed = (rowView(scenario, rpName, "lastUsed") as TextView).text.toString()
        assertNotEquals("A used passkey must not report 'never'", never, lastUsed)
        assertTrue("A relative timestamp should be rendered", lastUsed.isNotBlank())
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /** Inserts a fido2 row and registers it for teardown. */
    private fun seed(
        rpName: String?,
        rpId: String? = "flow-passkeys-$runId.example.com",
        label: String = "Flow Passkey $runId",
        userName: String? = "flow-user-$runId",
        userDisplayName: String? = null,
        isDiscoverable: Boolean = true,
        biometricRequired: Boolean = true,
        strongBoxBacked: Boolean = false,
        lastUsedAt: Long = 0
    ): String {
        val keyId = "ui-test-passkeys-flow-${System.nanoTime()}-$runId"
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = "fido2",
                    algorithm = "ES256",
                    label = label,
                    keySizeBits = 256,
                    strongBoxBacked = strongBoxBacked,
                    biometricRequired = biometricRequired,
                    rpId = rpId,
                    rpName = rpName,
                    userName = userName,
                    userDisplayName = userDisplayName,
                    isDiscoverable = isDiscoverable,
                    lastUsedAt = lastUsedAt,
                    source = "local"
                )
            )
        }
        seededKeyIds.add(keyId)
        return keyId
    }

    /**
     * Returns the view tagged [tag] on the row titled [rpName].
     *
     * The adapter tags each part of its card, so the row is located by its
     * (unique) title and the tagged child is read from that card alone.
     */
    private fun rowView(
        scenario: ActivityScenario<PasskeysActivity>,
        rpName: String,
        tag: String
    ): View = withActivity(scenario) { activity ->
        collectViews(rowCard(activity.window.decorView, rpName)) { it.tag == tag }
            .firstOrNull() ?: throw AssertionError("No view tagged '$tag' on the '$rpName' row")
    }

    private fun rowTexts(
        scenario: ActivityScenario<PasskeysActivity>,
        rpName: String
    ): List<String> = withActivity(scenario) { activity ->
        collectViews(rowCard(activity.window.decorView, rpName)) { it is TextView }
            .map { (it as TextView).text?.toString().orEmpty() }
    }

    private fun rowCard(root: View, rpName: String): View {
        val title = collectViews(root) {
            it is TextView && it.tag == "rpName" && it.text?.toString() == rpName
        }.firstOrNull() ?: throw AssertionError("No bound row titled '$rpName'")
        return generateSequence(title.parent as? View) { it.parent as? View }
            .first { it.isClickable }
    }

    private companion object {
        const val TWO_HOURS_MS = 2L * 60L * 60L * 1000L
    }
}
