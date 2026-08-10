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

import android.content.ClipboardManager
import android.content.Context
import androidx.lifecycle.Lifecycle
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * Instrumented tests for the actions [KeyDetailActivity] performs, as opposed to
 * the values it merely displays.
 *
 * These are the flows that write to Room, to the Android Keystore or to the
 * clipboard, plus the two bottom sheets the screen owns. The existing happy-path
 * suite stops at "the control is on screen" and at the *cancel* half of the
 * delete sheet, so everything here is the other half: confirming a delete,
 * exporting with and without key material, running attestation to completion,
 * and the sharing card re-reading its policy when the screen resumes.
 *
 * Flows covered:
 * - Unknown key id finishing the screen after the asynchronous lookup
 * - Delete confirmed: Keystore entry and Room row both removed, screen finishes
 * - Export public key: PEM on the clipboard, and the unavailable branch
 * - Local attestation: report replaces the placeholder, button re-enabled
 * - Remote attestation: information sheet opens and dismisses
 * - Sharing card: every policy badge branch, and the refresh on resume
 *
 * Keys and Keystore aliases seeded here are removed in @After.
 */
@RunWith(AndroidJUnit4::class)
class KeyDetailActivityFlowTest {

    private val runId = System.nanoTime()
    private val seededKeyIds = mutableListOf<String>()
    private val seededAliases = mutableListOf<String>()

    private val context: Context get() = keyTestContext()

    @After
    fun tearDown() {
        deleteKeyRows(*seededKeyIds.toTypedArray())
        seededKeyIds.clear()
        for (alias in seededAliases) {
            TestCertificates.deleteAlias(alias)
        }
        seededAliases.clear()
        clearClipboard()
    }

    // -----------------------------------------------------------------
    // Launch behaviour
    // -----------------------------------------------------------------

    /**
     * An id that is not in the database finishes the screen, but only after the
     * coroutine-backed lookup completes -- unlike the missing-extra case, the
     * activity is briefly resumed first.
     */
    @Test
    fun unknownKeyId_finishesAfterLookup() {
        val scenario = launchKeyDetail("flow-missing-$runId")

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Delete
    // -----------------------------------------------------------------

    /**
     * Confirming the delete sheet removes the Android Keystore entry as well as
     * the metadata row, then finishes the screen. The Keystore half only runs
     * for non-xkmsd keys, so the fixture has real key material.
     */
    @Test
    fun deleteConfirmed_removesKeystoreEntryAndRowThenFinishes() {
        val keyId = seedKeyWithMaterial("flow-delete")
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_action_delete))

        clickTextInTree(scenario, context.getString(R.string.key_action_delete))
        onView(withText(R.string.key_delete_confirm)).inRoot(isDialog()).perform(click())

        awaitCondition("The key row should be deleted") {
            runBlocking { keyTestDao().getByKeyId(keyId) } == null
        }
        awaitCondition("The Keystore entry should be deleted") { !keystoreContains(keyId) }
        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Export public key
    // -----------------------------------------------------------------

    /**
     * Exporting a key that has Keystore material puts a PEM block on the
     * clipboard and confirms with a snackbar.
     */
    @Test
    fun exportPublicKey_withMaterial_copiesPemToClipboard() {
        val keyId = seedKeyWithMaterial("flow-export")
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_action_export_public_key))

        clickTextInTree(scenario, context.getString(R.string.key_action_export_public_key))

        awaitText(scenario, context.getString(R.string.key_public_key_copied))
        val clip = withActivity(scenario) { activity ->
            val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.primaryClip?.getItemAt(0)?.text?.toString()
        }
        assertNotNull("Export should place the PEM on the clipboard", clip)
        assertTrue(
            "Clipboard should hold a PEM public key but held: $clip",
            clip!!.startsWith(PEM_HEADER) && clip.trimEnd().endsWith(PEM_FOOTER)
        )
    }

    /**
     * A metadata row whose Keystore entry is gone (or was never local) reports
     * the failure instead of copying an empty clipboard entry.
     */
    @Test
    fun exportPublicKey_withoutMaterial_reportsUnavailable() {
        val keyId = seed(key("flow-export-missing"))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_action_export_public_key))

        clickTextInTree(scenario, context.getString(R.string.key_action_export_public_key))

        awaitText(scenario, context.getString(R.string.key_public_key_unavailable))
    }

    // -----------------------------------------------------------------
    // Attestation
    // -----------------------------------------------------------------

    /**
     * Running local attestation replaces the "not attested yet" placeholder with
     * a report and re-enables the button.
     *
     * Whether the report is a success or a failure depends on the device:
     * attestation generates a fresh ephemeral Keystore key with the challenge
     * bound to it, which some emulator images refuse. Both outcomes are real
     * branches of `performLocalAttestation`, so the test asserts the invariants
     * that hold either way and then the details of whichever branch ran.
     */
    @Test
    fun localAttestation_replacesPlaceholderWithReport() {
        val keyId = seed(key("flow-attest"))
        val scenario = launchKeyDetail(keyId)
        val buttonLabel = context.getString(R.string.attest_button)
        awaitText(scenario, buttonLabel)
        assertShownTextInTree(scenario, context.getString(R.string.attest_description_local))

        clickTextInTree(scenario, buttonLabel)

        awaitTextAbsent(
            scenario,
            context.getString(R.string.attest_no_attestation_yet),
            ATTESTATION_TIMEOUT_MS
        )
        if (pollForText(scenario, context.getString(R.string.attest_verified), ATTESTATION_TIMEOUT_MS)) {
            assertShownTextInTree(scenario, context.getString(R.string.attest_security_level))
            assertShownTextInTree(scenario, context.getString(R.string.attest_chain_length))
            assertShownTextInTree(scenario, ATTESTATION_OVERVIEW_SECTION)
        } else {
            assertShownTextInTree(scenario, context.getString(R.string.attest_failed))
        }
        awaitCondition("The attestation button should be re-enabled") {
            withActivity(scenario) { activity ->
                val buttons = collectViews(activity.window.decorView) {
                    it is MaterialButton && it.text?.toString() == buttonLabel
                }
                buttons.isNotEmpty() && buttons.all { it.isEnabled }
            }
        }
    }

    /**
     * Remotely managed keys cannot be attested locally; the button opens an
     * explanatory sheet naming the backend, and OK dismisses it.
     */
    @Test
    fun remoteAttestation_opensInformationSheetAndDismisses() {
        val keyId = seed(key("flow-attest-remote", source = "xkmsd", remoteBackend = "tpm2"))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.attest_button_remote))

        clickTextInTree(scenario, context.getString(R.string.attest_button_remote))

        onView(withText(R.string.attest_title)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withText(R.string.button_ok)).inRoot(isDialog()).perform(click())

        waitForIdle()
        onView(withText(R.string.attest_title)).check(doesNotExist())
        assertTrue(
            "Dismissing the sheet should leave the detail screen open",
            scenario.state != Lifecycle.State.DESTROYED
        )
    }

    // -----------------------------------------------------------------
    // Sharing card
    // -----------------------------------------------------------------

    /** A private key is badged private and explains that no peer can use it. */
    @Test
    fun sharingCard_privatePolicy_showsPrivateBadge() {
        val keyId = seed(fido2Key("flow-share-private", SharingPolicyType.PRIVATE))
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.sharing_settings_title))
        assertExactTextShown(scenario, context.getString(R.string.sharing_badge_private))
        assertShownTextInTree(scenario, context.getString(R.string.sharing_policy_private_desc))
    }

    /** An all-peers key is badged shared. */
    @Test
    fun sharingCard_allPeersPolicy_showsSharedBadge() {
        val keyId = seed(fido2Key("flow-share-all", SharingPolicyType.ALL_PEERS))
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.sharing_settings_title))
        assertExactTextShown(scenario, context.getString(R.string.sharing_badge_shared))
        assertShownTextInTree(scenario, context.getString(R.string.sharing_policy_all_peers_desc))
    }

    /**
     * Selecting specific peers but choosing none is its own state: the badge
     * counts zero and the description says so rather than claiming the key is
     * shared.
     */
    @Test
    fun sharingCard_selectedPeersWithoutPeers_showsNoDevicesSelected() {
        val keyId = seed(fido2Key("flow-share-none", SharingPolicyType.SELECTED_PEERS))
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.sharing_settings_title))
        assertExactTextShown(
            scenario,
            context.getString(R.string.sharing_badge_selected, allowedPeerCount(keyId))
        )
        assertShownTextInTree(scenario, context.getString(R.string.sharing_no_devices_selected))
    }

    /**
     * With peers selected, both the badge and the description report the count.
     * The expected count is read back from the DAO rather than assumed.
     */
    @Test
    fun sharingCard_selectedPeersWithPeers_showsPeerCount() {
        val keyId = seed(fido2Key("flow-share-selected", SharingPolicyType.SELECTED_PEERS))
        grantPeer(keyId, PEER_A_HEX)
        grantPeer(keyId, PEER_B_HEX)
        val peerCount = allowedPeerCount(keyId)

        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.sharing_settings_title))
        assertExactTextShown(
            scenario,
            context.getString(R.string.sharing_badge_selected, peerCount)
        )
        assertExactTextShown(
            scenario,
            context.getString(R.string.sharing_selected_count_desc, peerCount)
        )
    }

    /**
     * The screen re-reads the key in onResume, so a policy changed while it was
     * stopped is reflected when the user comes back.
     */
    @Test
    fun sharingCard_reflectsPolicyChangedWhileStopped() {
        val keyId = seed(fido2Key("flow-share-refresh", SharingPolicyType.PRIVATE))
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.sharing_policy_private_desc))

        runBlocking {
            keyTestDao().updateSharingPolicy(keyId, SharingPolicyType.ALL_PEERS)
        }
        scenario.moveToState(Lifecycle.State.CREATED)
        scenario.moveToState(Lifecycle.State.RESUMED)

        awaitText(scenario, context.getString(R.string.sharing_policy_all_peers_desc))
        assertExactTextShown(scenario, context.getString(R.string.sharing_badge_shared))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun seed(key: KeyEntity): String {
        seedKeyRow(key)
        seededKeyIds.add(key.keyId)
        return key.keyId
    }

    /**
     * Seeds a metadata row together with a real Android Keystore entry under the
     * same alias, which is what `resolveKeystoreAlias` falls back to.
     */
    private fun seedKeyWithMaterial(prefix: String): String {
        val keyId = seed(key(prefix))
        TestCertificates.selfSigned(alias = keyId, commonName = "xKey Key Detail Flow Test")
        seededAliases.add(keyId)
        return keyId
    }

    private fun key(
        keyId: String,
        keyType: String = "signing",
        source: String = "local",
        remoteBackend: String? = null
    ) = KeyEntity(
        keyId = "$keyId-$runId",
        keyType = keyType,
        algorithm = "ES256",
        label = "Flow $keyId",
        keySizeBits = 256,
        source = source,
        remoteBackend = remoteBackend
    )

    /** A FIDO2 key, the only type for which the Sharing card is built. */
    private fun fido2Key(keyId: String, policy: SharingPolicyType) = KeyEntity(
        keyId = "$keyId-$runId",
        keyType = "fido2",
        algorithm = "ES256",
        label = "Flow $keyId",
        keySizeBits = 256,
        shareable = policy != SharingPolicyType.PRIVATE,
        sharingPolicy = policy,
        rpId = "flow-$keyId.example.com",
        source = "local"
    )

    private fun grantPeer(keyId: String, peerPublicKeyHex: String) {
        runBlocking {
            keySharingTestDao().setPolicy(
                KeySharingPolicy(
                    keyId = keyId,
                    peerPublicKeyHex = peerPublicKeyHex,
                    allowed = true
                )
            )
        }
    }

    private fun allowedPeerCount(keyId: String): Int =
        runBlocking { keySharingTestDao().getAllowedPeersForKey(keyId).size }

    private fun keystoreContains(alias: String): Boolean =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.containsAlias(alias)

    private fun clearClipboard() {
        runCatching {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.clearPrimaryClip()
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val PEM_HEADER = "-----BEGIN PUBLIC KEY-----"
        const val PEM_FOOTER = "-----END PUBLIC KEY-----"

        /** Section header rendered only for a successful attestation report. */
        const val ATTESTATION_OVERVIEW_SECTION = "Attestation Overview"

        /** Generating an attestation key on a cold emulator is not instant. */
        const val ATTESTATION_TIMEOUT_MS = 30_000L

        const val PEER_A_HEX = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899"
        const val PEER_B_HEX = "bb22cc33dd44ee55ff6600778899aabbccddeeff001122334455667788990011"
    }
}
