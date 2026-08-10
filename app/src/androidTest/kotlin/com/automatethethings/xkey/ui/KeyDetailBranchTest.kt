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
import android.content.Intent
import android.view.MenuItem
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.widget.PopupMenu
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withSubstring
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The remaining state-dependent branches of [KeyDetailActivity].
 *
 * `KeyDetailActivityVariantsTest` covers the display tables for the key types
 * and sources the app creates itself, and `KeyDetailActivityFlowTest` covers
 * delete and attestation for a local key with real Keystore material. What
 * neither reaches is the tail of both `when` tables (the key types and sources
 * that only ever arrive from a desktop or a future release), the two `deleteKey`
 * paths that skip the Keystore, the remote-attestation sheet's missing-backend
 * copy, and `onOptionsItemSelected`, which is 0% covered because every existing
 * back-navigation test presses the system back button instead.
 *
 * Menu items are built with a throwaway [PopupMenu] rather than by tapping the
 * collapsing toolbar: the activity declares no menu resource, so `home` is the
 * only item that exists, and an unrecognised id has no affordance at all. A
 * synthesised item is the only way to drive the fall-through arm, and using the
 * same technique for both keeps the two assertions symmetrical.
 *
 * Every seeded row carries a per-run id and is deleted in `@After`; none of
 * these tests writes to the Android Keystore.
 */
@RunWith(AndroidJUnit4::class)
class KeyDetailBranchTest {

    private val runId = System.nanoTime()

    private val context: Context get() = keyTestContext()

    private val seededKeyIds = mutableListOf<String>()

    @After
    fun tearDown() {
        deleteKeyRows(*seededKeyIds.toTypedArray())
        seededKeyIds.clear()
    }

    // ---------------------------------------------------------------
    // Display tables
    // ---------------------------------------------------------------

    /**
     * The key types that only ever arrive from a paired desktop still resolve to
     * a human display name rather than falling through to the capitalise arm.
     *
     * "Attestation" is also the title of a section on this screen, so the
     * assertion is scoped to the General card's Type row rather than to the
     * whole tree.
     */
    @Test
    fun everyRemainingKeyType_resolvesToItsDisplayName() {
        val expectations = mapOf(
            "tls" to "TLS",
            "ssh" to "SSH",
            "encryption" to context.getString(R.string.key_filter_encryption),
            "ca" to context.getString(R.string.key_filter_ca),
            "attestation" to context.getString(R.string.key_filter_attestation)
        )

        expectations.forEach { (keyType, expected) ->
            val keyId = seed(key("type-$keyType", keyType = keyType))
            val scenario = ActivityScenario.launch<KeyDetailActivity>(detailIntent(keyId))
            try {
                awaitText(scenario, context.getString(R.string.key_detail_type))
                assertRowValue(scenario, context.getString(R.string.key_detail_type), expected)
            } finally {
                scenario.close()
            }
        }
    }

    /**
     * A USB-attached remote key names its transport, and a source the table does
     * not know is capitalised rather than dropped.
     */
    @Test
    fun remainingSources_resolveThroughTheTableAndTheCapitaliseFallback() {
        val expectations = mapOf(
            "remote_usb" to context.getString(R.string.key_source_remote_usb),
            "cloud" to "Cloud"
        )

        expectations.forEach { (source, expected) ->
            val keyId = seed(key("source-$source", source = source))
            val scenario = ActivityScenario.launch<KeyDetailActivity>(detailIntent(keyId))
            try {
                awaitText(scenario, context.getString(R.string.key_detail_source))
                assertRowValue(scenario, context.getString(R.string.key_detail_source), expected)
            } finally {
                scenario.close()
            }
        }
    }

    // ---------------------------------------------------------------
    // Delete paths that never touch the Keystore
    // ---------------------------------------------------------------

    /**
     * Confirming the delete of a remotely-managed key removes only the local
     * cache row: the activity skips the Keystore lookup entirely for `xkmsd`
     * keys, because there is no local material to remove.
     */
    @Test
    fun deletingAnXkmsdKey_removesTheRowWithoutTouchingTheKeystore() {
        val keyId = seed(key("delete-xkmsd", source = "xkmsd"))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_action_delete))

        clickTextInTree(scenario, context.getString(R.string.key_action_delete))
        onView(withText(R.string.key_delete_confirm)).inRoot(isDialog()).perform(click())

        awaitCondition("The cached key row should be deleted") {
            runBlocking { keyTestDao().getByKeyId(keyId) } == null
        }
        assertActivityDestroyed(scenario)
    }

    /**
     * A local key whose Keystore material has never existed still deletes: the
     * alias lookup returns null and the row removal proceeds regardless.
     */
    @Test
    fun deletingALocalKeyWithNoMaterial_stillRemovesTheRow() {
        val keyId = seed(key("delete-orphan"))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_action_delete))

        clickTextInTree(scenario, context.getString(R.string.key_action_delete))
        onView(withText(R.string.key_delete_confirm)).inRoot(isDialog()).perform(click())

        awaitCondition("The orphaned key row should be deleted") {
            runBlocking { keyTestDao().getByKeyId(keyId) } == null
        }
        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Remote attestation copy
    // ---------------------------------------------------------------

    /**
     * A remote key with no recorded backend still explains how to attest it, and
     * names the backend as unknown rather than rendering an empty parenthesis.
     */
    @Test
    fun remoteAttestationSheet_namesAnAbsentBackendAsUnknown() {
        val keyId = seed(key("attest-nobackend", source = "xkmsd", remoteBackend = null))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.attest_button_remote))

        clickTextInTree(scenario, context.getString(R.string.attest_button_remote))

        onView(withText(R.string.attest_title)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withSubstring("(unknown backend)")).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withText(R.string.button_ok)).inRoot(isDialog()).perform(click())
        waitForIdle()

        // With no backend recorded the General card must not offer the row either.
        assertTextNotInTree(scenario, context.getString(R.string.key_detail_remote_backend))
    }

    // ---------------------------------------------------------------
    // Options menu
    // ---------------------------------------------------------------

    /** The `home` item routes through the back dispatcher and closes the screen. */
    @Test
    fun homeMenuItem_finishesTheActivity() {
        val keyId = seed(key("menu-home"))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_detail_type))

        val handled = selectMenuItem(scenario, android.R.id.home)

        assertTrue("The home item should be handled by the activity", handled)
        assertActivityDestroyed(scenario)
    }

    /** Any other item falls through to the superclass and is left unhandled. */
    @Test
    fun anUnrecognisedMenuItem_isNotHandled() {
        val keyId = seed(key("menu-other"))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_detail_type))

        val handled = selectMenuItem(scenario, UNRECOGNISED_ITEM_ID)

        assertFalse("An unknown menu item must not be claimed", handled)
        assertFalse(
            "An unhandled menu item must not close the screen",
            withActivity(scenario) { it.isFinishing }
        )
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Passes a synthesised [MenuItem] with [itemId] to the activity's handler.
     *
     * A [PopupMenu] is the cheapest source of a real `MenuItem` — the screen
     * inflates no menu resource of its own, so there is nothing to look one up
     * in.
     */
    private fun selectMenuItem(
        scenario: ActivityScenario<KeyDetailActivity>,
        itemId: Int
    ): Boolean {
        val handled = withActivity(scenario) { activity ->
            val item: MenuItem = PopupMenu(activity, activity.window.decorView)
                .menu
                .add(0, itemId, 0, "synthetic")
            activity.onOptionsItemSelected(item)
        }
        waitForIdle()
        return handled
    }

    /**
     * Asserts that some detail row labelled [label] carries [value].
     *
     * Every matching label is considered rather than only the first: several of
     * these labels are repeated across the screen's cards.
     */
    private fun assertRowValue(
        scenario: ActivityScenario<KeyDetailActivity>,
        label: String,
        value: String
    ) {
        assertTrue(
            "Expected some '$label' row to read '$value'",
            awaitActivity(scenario) { activity ->
                collectViews(activity.window.decorView) {
                    it is TextView && it.text?.toString() == label
                }.any { labelView ->
                    val row = labelView.parent as? ViewGroup ?: return@any false
                    collectViews(row) {
                        it is TextView && it.text?.toString() == value
                    }.isNotEmpty()
                }
            }
        )
    }

    private fun detailIntent(keyId: String) =
        Intent(context, KeyDetailActivity::class.java).apply {
            putExtra(KeyDetailActivity.EXTRA_KEY_ID, keyId)
        }

    private fun seed(key: KeyEntity): String {
        seedKeyRow(key)
        seededKeyIds.add(key.keyId)
        return key.keyId
    }

    private fun key(
        name: String,
        keyType: String = "signing",
        source: String = "local",
        remoteBackend: String? = null
    ) = KeyEntity(
        keyId = "$name-$runId",
        keyType = keyType,
        algorithm = "ES256",
        label = "Branch $name $runId",
        keySizeBits = 256,
        source = source,
        remoteBackend = remoteBackend
    )

    private companion object {

        /** An id no resource in this app can collide with. */
        const val UNRECOGNISED_ITEM_ID = 0x7EEE0001
    }
}
