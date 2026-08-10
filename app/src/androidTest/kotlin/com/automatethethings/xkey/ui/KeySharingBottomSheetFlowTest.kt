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
import android.view.View
import android.widget.CheckBox
import android.widget.RadioButton
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [KeySharingBottomSheet], the per-key access control
 * sheet reached from the Sharing card of [KeyDetailActivity].
 *
 * The sheet is the only place in the app where a key's [SharingPolicyType] can
 * be changed by hand, so every assertion here ends at the two production
 * surfaces that decide whether a peer may use a key: the `sharing_policy` column
 * on the key row, and `KeySharingPolicyDao.isKeySharedWithPeer` -- the query the
 * protocol layer actually calls. Asserting through that query means the tests
 * cover the whole policy matrix rather than just the radio button that was
 * clicked.
 *
 * The sheet is a [com.google.android.material.bottomsheet.BottomSheetDialogFragment],
 * so its content lives in a dialog window that the activity's decor view does
 * not contain. Assertions therefore run against the fragment's own view via
 * [onSheet], on the main thread.
 *
 * Flows covered:
 * - Opening from the Sharing card, with the key label as subtitle
 * - Preselection for each of the three policies, including the peer list only
 *   appearing for "Selected Devices"
 * - Choosing each policy, and what it persists (ALL_PEERS also clears per-peer
 *   entries)
 * - Clicking an option's description selects that option
 * - The peer list matching the paired-device store, its empty state, the
 *   truncated fingerprint and the connection history line
 * - Granting and revoking one peer, by checkbox and by card tap, and the
 *   resulting allow/refuse answers for both a granted and a non-granted peer
 * - An unknown key id dismissing the sheet instead of rendering an empty one
 *
 * Two paired devices are added for the duration of the suite and removed in
 * @After; devices the user already had are left alone, and every expectation
 * about the peer list is derived from the live repository contents.
 */
@RunWith(AndroidJUnit4::class)
class KeySharingBottomSheetFlowTest {

    private val runId = System.nanoTime()
    private val seededKeyIds = mutableListOf<String>()

    private lateinit var repository: PairedDeviceRepository

    private val context: Context get() = keyTestContext()

    @Before
    fun setUp() {
        repository = PairedDeviceRepository(context)
        repository.removeDevice(PEER_A_HEX)
        repository.removeDevice(PEER_B_HEX)
        repository.addDevice(publicKeyHex = PEER_A_HEX, deviceName = PEER_A_NAME)
        repository.addDevice(publicKeyHex = PEER_B_HEX, deviceName = PEER_B_NAME)
        // Only one of the two has ever connected, so the card that renders a
        // connection history can be told apart from the one that must not.
        repository.recordConnection(PEER_A_HEX)
    }

    @After
    fun tearDown() {
        deleteKeyRows(*seededKeyIds.toTypedArray())
        seededKeyIds.clear()
        repository.removeDevice(PEER_A_HEX)
        repository.removeDevice(PEER_B_HEX)
    }

    // -----------------------------------------------------------------
    // Opening the sheet
    // -----------------------------------------------------------------

    /** The Sharing card's button opens a sheet offering all three policies. */
    @Test
    fun manageSharing_opensSheetWithEveryPolicyOption() {
        val scenario = openSheetFor(seedKey("open", SharingPolicyType.PRIVATE))

        assertSheetShows(scenario, context.getString(R.string.sharing_settings_title))
        assertSheetShows(scenario, context.getString(R.string.sharing_policy_private))
        assertSheetShows(scenario, context.getString(R.string.sharing_policy_private_desc))
        assertSheetShows(scenario, context.getString(R.string.sharing_policy_all_peers))
        assertSheetShows(scenario, context.getString(R.string.sharing_policy_all_peers_desc))
        assertSheetShows(scenario, context.getString(R.string.sharing_policy_selected_peers))
        assertSheetShows(scenario, context.getString(R.string.sharing_policy_selected_peers_desc))
    }

    /** The subtitle names the key being configured. */
    @Test
    fun sheet_showsKeyLabelAsSubtitle() {
        val keyId = seedKey("subtitle", SharingPolicyType.PRIVATE)
        val label = runBlocking { keyTestDao().getByKeyId(keyId) }!!.label

        val scenario = openSheetFor(keyId)

        assertSheetShows(scenario, label)
    }

    // -----------------------------------------------------------------
    // Preselection
    // -----------------------------------------------------------------

    /** A private key preselects Private and keeps the peer list hidden. */
    @Test
    fun privateKey_preselectsPrivateAndHidesPeerList() {
        val scenario = openSheetFor(seedKey("preselect-private", SharingPolicyType.PRIVATE))

        assertEquals(
            context.getString(R.string.sharing_policy_private),
            checkedPolicy(scenario)
        )
        assertFalse(
            "The peer picker belongs to the Selected Devices policy only",
            sheetShows(scenario, context.getString(R.string.sharing_select_devices))
        )
    }

    /** A shareable key with no per-peer entries preselects All Paired Devices. */
    @Test
    fun shareableKeyWithoutPeerPolicies_preselectsAllPairedDevices() {
        val scenario = openSheetFor(seedKey("preselect-all", SharingPolicyType.ALL_PEERS))

        assertEquals(
            context.getString(R.string.sharing_policy_all_peers),
            checkedPolicy(scenario)
        )
    }

    /** Per-peer entries make the key a Selected Devices key, peer list shown. */
    @Test
    fun shareableKeyWithPeerPolicies_preselectsSelectedDevices() {
        val keyId = seedKey("preselect-selected", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)

        val scenario = openSheetFor(keyId)

        assertEquals(
            context.getString(R.string.sharing_policy_selected_peers),
            checkedPolicy(scenario)
        )
        assertSheetShows(scenario, context.getString(R.string.sharing_select_devices))
        assertSheetShows(scenario, PEER_A_NAME)
        // The list is populated once from the policy change and again when the
        // allowed-peer set arrives, so the checked state settles asynchronously.
        awaitPeerChecked(scenario, PEER_A_NAME, checked = true)
        awaitPeerChecked(scenario, PEER_B_NAME, checked = false)
    }

    // -----------------------------------------------------------------
    // Choosing a policy
    // -----------------------------------------------------------------

    /**
     * Widening a key from selected peers to all peers persists the new policy
     * and drops the now-meaningless per-peer entries, so they cannot come back
     * silently if the key is narrowed again later.
     */
    @Test
    fun choosingAllPairedDevices_persistsPolicyAndClearsPeerEntries() {
        val keyId = seedKey("choose-all", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_all_peers))

        awaitPolicy(keyId, SharingPolicyType.ALL_PEERS)
        awaitCondition("Per-peer entries should be cleared for an all-peers key") {
            runBlocking { keySharingTestDao().getPoliciesForKeySync(keyId) }.isEmpty()
        }
    }

    /** Narrowing a key back to private persists the private policy. */
    @Test
    fun choosingPrivate_persistsPrivatePolicy() {
        val keyId = seedKey("choose-private", SharingPolicyType.ALL_PEERS)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_private))

        awaitPolicy(keyId, SharingPolicyType.PRIVATE)
    }

    /** Choosing Selected Devices reveals a card for every paired device. */
    @Test
    fun choosingSelectedDevices_revealsPeerListForEveryPairedDevice() {
        val keyId = seedKey("choose-selected", SharingPolicyType.PRIVATE)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_selected_peers))

        awaitPolicy(keyId, SharingPolicyType.SELECTED_PEERS)
        assertSheetShows(scenario, context.getString(R.string.sharing_select_devices))
        assertSheetShows(scenario, PEER_A_NAME)
        assertSheetShows(scenario, PEER_B_NAME)
    }

    /** Clicking an option's description selects the option it describes. */
    @Test
    fun policyDescription_selectsItsOption() {
        val keyId = seedKey("description-click", SharingPolicyType.PRIVATE)
        val scenario = openSheetFor(keyId)

        clickInSheet(scenario, "the all-peers description") { view ->
            view is TextView &&
                view !is RadioButton &&
                view.text?.toString() == context.getString(R.string.sharing_policy_all_peers_desc)
        }

        assertEquals(
            context.getString(R.string.sharing_policy_all_peers),
            checkedPolicy(scenario)
        )
        awaitPolicy(keyId, SharingPolicyType.ALL_PEERS)
    }

    // -----------------------------------------------------------------
    // The peer list
    // -----------------------------------------------------------------

    /**
     * The peer list mirrors the paired-device store exactly, and the empty state
     * is shown precisely when that store is empty.
     */
    @Test
    fun peerList_matchesPairedDeviceStore() {
        val keyId = seedKey("peer-list", SharingPolicyType.PRIVATE)
        val scenario = openSheetFor(keyId)
        clickPolicy(scenario, context.getString(R.string.sharing_policy_selected_peers))
        assertSheetShows(scenario, context.getString(R.string.sharing_select_devices))

        val devices = repository.getAllDevices()
        awaitCondition("One card should be rendered per paired device") {
            onSheet(scenario) { root -> peerCards(root).size } == devices.size
        }
        assertEquals(
            "The empty state belongs to an empty device store only",
            devices.isEmpty(),
            sheetShows(scenario, context.getString(R.string.sharing_no_paired_devices))
        )
    }

    /**
     * Each card identifies its device by the truncated fingerprint, and only
     * devices that have actually connected get a connection history line.
     */
    @Test
    fun peerCards_showTruncatedFingerprintAndConnectionHistory() {
        val keyId = seedKey("peer-cards", SharingPolicyType.PRIVATE)
        val scenario = openSheetFor(keyId)
        clickPolicy(scenario, context.getString(R.string.sharing_policy_selected_peers))
        assertSheetShows(scenario, PEER_B_NAME)

        assertSheetShows(scenario, PEER_A_HEX.take(FINGERPRINT_LENGTH))
        assertSheetShows(scenario, PEER_B_HEX.take(FINGERPRINT_LENGTH))

        val expected = repository.getAllDevices().count { (it.lastConnectedAt ?: 0L) != 0L }
        val rendered = onSheet(scenario) { root ->
            collectViews(root) {
                it is TextView && it.text?.toString()?.startsWith(LAST_CONNECTED_PREFIX) == true
            }.size
        }
        assertEquals(
            "A connection history line belongs to connected devices only",
            expected,
            rendered
        )
    }

    // -----------------------------------------------------------------
    // Granting and revoking individual peers
    // -----------------------------------------------------------------

    /**
     * Checking one device grants that device and only that device, as answered
     * by the access-control query the protocol layer uses.
     */
    @Test
    fun checkingPeer_grantsAccessToThatPeerOnly() {
        val keyId = seedKey("grant-one", SharingPolicyType.PRIVATE)
        val scenario = openSheetFor(keyId)
        clickPolicy(scenario, context.getString(R.string.sharing_policy_selected_peers))
        assertSheetShows(scenario, PEER_A_NAME)
        awaitPeerChecked(scenario, PEER_A_NAME, checked = false)

        clickPeerCheckbox(scenario, PEER_A_NAME)

        awaitPeerAccess(keyId, PEER_A_HEX, allowed = true)
        assertFalse(
            "An unchecked peer must not gain access",
            peerHasAccess(keyId, PEER_B_HEX)
        )
    }

    /** Unchecking a granted device revokes it again. */
    @Test
    fun uncheckingPeer_revokesAccess() {
        val keyId = seedKey("revoke-one", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)
        val scenario = openSheetFor(keyId)
        assertSheetShows(scenario, PEER_A_NAME)
        awaitPeerChecked(scenario, PEER_A_NAME, checked = true)

        clickPeerCheckbox(scenario, PEER_A_NAME)

        awaitPeerAccess(keyId, PEER_A_HEX, allowed = false)
        awaitCondition("The per-peer entry should be removed, not just denied") {
            runBlocking { keySharingTestDao().getPolicy(keyId, PEER_A_HEX) } == null
        }
    }

    /** The whole card is a hit target for its checkbox. */
    @Test
    fun tappingPeerCard_togglesItsCheckbox() {
        val keyId = seedKey("card-tap", SharingPolicyType.PRIVATE)
        val scenario = openSheetFor(keyId)
        clickPolicy(scenario, context.getString(R.string.sharing_policy_selected_peers))
        assertSheetShows(scenario, PEER_B_NAME)
        awaitPeerChecked(scenario, PEER_B_NAME, checked = false)

        clickInSheet(scenario, "the card for $PEER_B_NAME") { view ->
            view is MaterialCardView && findTextView(view, PEER_B_NAME) != null
        }

        awaitPeerAccess(keyId, PEER_B_HEX, allowed = true)
    }

    // -----------------------------------------------------------------
    // Policy matrix
    // -----------------------------------------------------------------

    /** All Paired Devices grants every paired peer without per-peer entries. */
    @Test
    fun choosingAllPairedDevices_grantsEveryPairedPeer() {
        val keyId = seedKey("matrix-all", SharingPolicyType.PRIVATE)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_all_peers))

        awaitPeerAccess(keyId, PEER_A_HEX, allowed = true)
        awaitPeerAccess(keyId, PEER_B_HEX, allowed = true)
    }

    /** Private refuses every peer, including one that was explicitly granted. */
    @Test
    fun choosingPrivate_refusesEveryPairedPeer() {
        val keyId = seedKey("matrix-private", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_private))

        awaitPeerAccess(keyId, PEER_A_HEX, allowed = false)
        awaitPeerAccess(keyId, PEER_B_HEX, allowed = false)
    }

    // -----------------------------------------------------------------
    // Missing key
    // -----------------------------------------------------------------

    /**
     * A key that disappeared between opening the detail screen and opening the
     * sheet must dismiss the sheet rather than present an unlabelled form whose
     * radio buttons write to nothing.
     */
    @Test
    fun unknownKey_dismissesSheetImmediately() {
        val scenario = launchKeyDetail(seedKey("missing-host", SharingPolicyType.PRIVATE))
        awaitText(scenario, context.getString(R.string.sharing_manage_button))

        // The attachment has to be observed inside the same main-thread block
        // that shows the sheet: the key lookup runs on the main dispatcher and
        // dismisses the sheet at the very next chance the looper gets, so a
        // second onActivity() would routinely find it already gone.
        val attached = withActivity(scenario) { activity ->
            KeySharingBottomSheet.show(activity.supportFragmentManager, "sharing-missing-$runId")
            activity.supportFragmentManager.executePendingTransactions()
            activity.supportFragmentManager.fragments
                .filterIsInstance<KeySharingBottomSheet>()
                .any { it.isAdded }
        }
        assertTrue("Precondition: the sheet attached", attached)

        awaitCondition("The sheet should dismiss itself when the key is gone") {
            onSheet(scenario) { it == null }
        }
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    /**
     * Seeds a FIDO2 key -- the only type whose detail screen offers the Sharing
     * card -- with [policy] and the legacy `shareable` flag kept in agreement
     * with it, as [KeyEntity] requires.
     */
    private fun seedKey(name: String, policy: SharingPolicyType): String {
        val key = KeyEntity(
            keyId = "sharing-$name-$runId",
            keyType = "fido2",
            algorithm = "ES256",
            label = "Sharing $name key",
            keySizeBits = 256,
            shareable = policy != SharingPolicyType.PRIVATE,
            sharingPolicy = policy,
            rpId = "sharing-$name.example.com",
            source = "local"
        )
        seedKeyRow(key)
        seededKeyIds.add(key.keyId)
        return key.keyId
    }

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

    // -----------------------------------------------------------------
    // Sheet helpers
    // -----------------------------------------------------------------

    /**
     * Opens the detail screen for [keyId] and taps through to the sharing sheet,
     * returning once the sheet has loaded the key and preselected a policy.
     */
    private fun openSheetFor(keyId: String): ActivityScenario<KeyDetailActivity> {
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.sharing_manage_button))
        clickTextInTree(scenario, context.getString(R.string.sharing_manage_button))

        awaitCondition("The sharing sheet should attach") { onSheet(scenario) { it != null } }
        awaitCondition("The sharing sheet should preselect a policy") {
            checkedPolicy(scenario) != null
        }
        return scenario
    }

    /** Runs [block] against the sheet's root view on the main thread. */
    private fun <T> onSheet(
        scenario: ActivityScenario<KeyDetailActivity>,
        block: (View?) -> T
    ): T = withActivity(scenario) { activity ->
        block(
            activity.supportFragmentManager.fragments
                .filterIsInstance<KeySharingBottomSheet>()
                .firstOrNull { it.isAdded }
                ?.view
        )
    }

    /** Returns whether a visible view in the sheet contains [text]. */
    private fun sheetShows(scenario: ActivityScenario<KeyDetailActivity>, text: String): Boolean =
        onSheet(scenario) { findShownTextView(it, text) != null }

    /** Polls until [text] is visible in the sheet, failing if it never is. */
    private fun assertSheetShows(scenario: ActivityScenario<KeyDetailActivity>, text: String) {
        awaitCondition("Expected '$text' in the sharing sheet") { sheetShows(scenario, text) }
    }

    /** Polls until the card for [deviceName] reports [checked]. */
    private fun awaitPeerChecked(
        scenario: ActivityScenario<KeyDetailActivity>,
        deviceName: String,
        checked: Boolean
    ) {
        awaitCondition("The card for $deviceName should be checked=$checked") {
            peerChecked(scenario, deviceName) == checked
        }
    }

    /** The title of the currently selected policy, or null before the key loads. */
    private fun checkedPolicy(scenario: ActivityScenario<KeyDetailActivity>): String? =
        onSheet(scenario) { root ->
            collectViews(root) { it is RadioButton && it.isChecked }
                .firstOrNull()
                ?.let { (it as RadioButton).text?.toString() }
        }

    /** Selects the policy option titled [title]. */
    private fun clickPolicy(scenario: ActivityScenario<KeyDetailActivity>, title: String) {
        clickInSheet(scenario, "the '$title' option") { view ->
            view is RadioButton && view.text?.toString() == title
        }
    }

    /** All peer cards currently rendered in the sheet. */
    private fun peerCards(root: View?): List<View> =
        collectViews(root) { it is MaterialCardView }

    private fun peerCheckbox(root: View?, deviceName: String): CheckBox? {
        val card = peerCards(root).firstOrNull { findTextView(it, deviceName) != null }
        return collectViews(card) { it is CheckBox }.firstOrNull() as CheckBox?
    }

    /** Whether the card for [deviceName] is checked, or null when absent. */
    private fun peerChecked(
        scenario: ActivityScenario<KeyDetailActivity>,
        deviceName: String
    ): Boolean? = onSheet(scenario) { peerCheckbox(it, deviceName)?.isChecked }

    /**
     * Clicks the checkbox belonging to [deviceName].
     *
     * Scoped to that device's card: every peer card carries a checkbox, so a
     * bare "first CheckBox" search would toggle whichever device happens to sort
     * first in the store.
     */
    private fun clickPeerCheckbox(
        scenario: ActivityScenario<KeyDetailActivity>,
        deviceName: String
    ) {
        val clicked = onSheet(scenario) { root ->
            val checkbox = peerCheckbox(root, deviceName)
            if (checkbox == null) {
                false
            } else {
                checkbox.performClick()
                true
            }
        }
        waitForIdle()
        assertTrue("Expected a checkbox for $deviceName in the sharing sheet", clicked)
    }

    /**
     * Clicks the first view in the sheet matching [predicate], failing with
     * [description] when there is none.
     *
     * The click is performed directly on the main thread: the sheet lives in a
     * dialog window whose content is frequently taller than the screen, so
     * injecting motion events would fight the bottom sheet's own drag handling.
     */
    private fun clickInSheet(
        scenario: ActivityScenario<KeyDetailActivity>,
        description: String,
        predicate: (View) -> Boolean
    ) {
        val clicked = onSheet(scenario) { root ->
            val target = collectViews(root) { predicate(it) }.firstOrNull()
            if (target == null) {
                false
            } else {
                target.performClick()
                true
            }
        }
        waitForIdle()
        assertTrue("Expected to find $description in the sharing sheet", clicked)
    }

    // -----------------------------------------------------------------
    // Persistence assertions
    // -----------------------------------------------------------------

    private fun awaitPolicy(keyId: String, expected: SharingPolicyType) {
        awaitCondition("The key's sharing policy should become $expected") {
            runBlocking { keyTestDao().getByKeyId(keyId) }?.sharingPolicy == expected
        }
    }

    private fun peerHasAccess(keyId: String, peerPublicKeyHex: String): Boolean =
        runBlocking { keySharingTestDao().isKeySharedWithPeer(keyId, peerPublicKeyHex) }

    private fun awaitPeerAccess(keyId: String, peerPublicKeyHex: String, allowed: Boolean) {
        awaitCondition(
            "Peer ${peerPublicKeyHex.take(FINGERPRINT_LENGTH)} should " +
                (if (allowed) "be allowed" else "be refused") + " for $keyId"
        ) {
            peerHasAccess(keyId, peerPublicKeyHex) == allowed
        }
    }

    private companion object {
        /** Characters of the public key the peer card renders as a fingerprint. */
        const val FINGERPRINT_LENGTH = 16

        const val LAST_CONNECTED_PREFIX = "Last connected:"

        const val PEER_A_HEX = "5ba71a2f0c9d4e6f8a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f607"
        const val PEER_B_HEX = "6cb82b3f1dae5f7a9b1c2d3e4f506172839405b6c7d8e9f0a1b2c3d4e5f60718"
        const val PEER_A_NAME = "xKey Sharing Sheet Peer A"
        const val PEER_B_NAME = "xKey Sharing Sheet Peer B"
    }
}
