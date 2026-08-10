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
 * Instrumented tests for what [KeySharingBottomSheet] does to the *per-peer*
 * grants when a key leaves the Selected Devices policy.
 *
 * Switching to All Paired Devices already cleared them. Switching to Private did
 * not, so the rows outlived the decision that revoked them: setting the key back
 * to Selected Devices silently resumed sharing with whoever had been granted
 * access before, with no prompt and nothing on screen to say so. Private is the
 * revoking choice — it has to leave nothing behind.
 *
 * Assertions end at `KeySharingPolicyDao`, which is what the protocol layer
 * consults, rather than at the checkbox that was clicked.
 *
 * Two peers are paired for the duration of each test and removed in @After;
 * seeded keys are deleted with them.
 */
@RunWith(AndroidJUnit4::class)
class KeySharingRevocationFlowTest {

    private val runId = System.nanoTime()
    private val seededKeyIds = mutableListOf<String>()

    private lateinit var repository: PairedDeviceRepository

    private var scenario: ActivityScenario<KeyDetailActivity>? = null

    private val context: Context get() = keyTestContext()

    @Before
    fun setUp() {
        repository = PairedDeviceRepository(context)
        repository.removeDevice(PEER_A_HEX)
        repository.removeDevice(PEER_B_HEX)
        repository.addDevice(publicKeyHex = PEER_A_HEX, deviceName = PEER_A_NAME)
        repository.addDevice(publicKeyHex = PEER_B_HEX, deviceName = PEER_B_NAME)
    }

    @After
    fun tearDown() {
        scenario?.close()
        scenario = null
        deleteKeyRows(*seededKeyIds.toTypedArray())
        seededKeyIds.clear()
        repository.removeDevice(PEER_A_HEX)
        repository.removeDevice(PEER_B_HEX)
    }

    /** Private revokes the grants rather than parking them. */
    @Test
    fun choosingPrivate_clearsThePerPeerGrants() {
        val keyId = seedKey("private-clears", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_private))

        awaitCondition("Choosing Private should clear the per-peer grants") {
            storedGrants(keyId).isEmpty()
        }
    }

    /**
     * The regression itself: selecting peers again must start from nothing, not
     * from a grant the user revoked when they chose Private.
     */
    @Test
    fun returningToSelectedPeers_doesNotResurrectARevokedGrant() {
        val keyId = seedKey("no-resurrection", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_private))
        awaitCondition("Precondition: Private cleared the grants") {
            storedGrants(keyId).isEmpty()
        }

        clickPolicy(scenario, context.getString(R.string.sharing_policy_selected_peers))
        awaitCondition("Precondition: the peer list came back") {
            peerChecked(scenario, PEER_A_NAME) != null
        }

        assertFalse(
            "A grant revoked by choosing Private must not come back",
            peerHasAccess(keyId, PEER_A_HEX)
        )
        assertEquals(
            "The peer card must not show a revoked grant as granted",
            false,
            peerChecked(scenario, PEER_A_NAME)
        )
    }

    /**
     * All Paired Devices keeps clearing them: it supersedes per-peer rows, which
     * could only contradict it later.
     */
    @Test
    fun choosingAllPeers_stillClearsThePerPeerGrants() {
        val keyId = seedKey("all-clears", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_all_peers))

        awaitCondition("Choosing All Paired Devices should clear the per-peer grants") {
            storedGrants(keyId).isEmpty()
        }
    }

    /**
     * Revoking is not a one-way door: after Private the user can select the same
     * peer again, and it is granted afresh rather than restored.
     */
    @Test
    fun aPeerCanBeGrantedAgainAfterRevocation() {
        val keyId = seedKey("regrant", SharingPolicyType.SELECTED_PEERS)
        grantPeer(keyId, PEER_A_HEX)
        val scenario = openSheetFor(keyId)

        clickPolicy(scenario, context.getString(R.string.sharing_policy_private))
        awaitCondition("Precondition: Private cleared the grants") {
            storedGrants(keyId).isEmpty()
        }

        clickPolicy(scenario, context.getString(R.string.sharing_policy_selected_peers))
        awaitCondition("Precondition: the peer list came back") {
            peerChecked(scenario, PEER_A_NAME) != null
        }
        clickPeerCheckbox(scenario, PEER_A_NAME)

        awaitCondition("The peer should be granted access again") {
            peerHasAccess(keyId, PEER_A_HEX)
        }
    }

    // ---------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------

    /**
     * Seeds a FIDO2 key — the only type whose detail screen offers the Sharing
     * card — with [policy] and the legacy `shareable` flag in agreement with it,
     * as [KeyEntity] requires.
     */
    private fun seedKey(name: String, policy: SharingPolicyType): String {
        val key = KeyEntity(
            keyId = "revoke-$name-$runId",
            keyType = "fido2",
            algorithm = "ES256",
            label = "Revocation $name key",
            keySizeBits = 256,
            shareable = policy != SharingPolicyType.PRIVATE,
            sharingPolicy = policy,
            rpId = "revoke-$name.example.com",
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

    private fun storedGrants(keyId: String) =
        runBlocking { keySharingTestDao().getPoliciesForKeySync(keyId) }

    private fun peerHasAccess(keyId: String, peerPublicKeyHex: String): Boolean =
        runBlocking { keySharingTestDao().isKeySharedWithPeer(keyId, peerPublicKeyHex) }

    // ---------------------------------------------------------------
    // Sheet helpers
    // ---------------------------------------------------------------

    /** Opens the detail screen for [keyId] and taps through to the sheet. */
    private fun openSheetFor(keyId: String): ActivityScenario<KeyDetailActivity> {
        val launched = launchKeyDetail(keyId)
        scenario = launched
        awaitText(launched, context.getString(R.string.sharing_manage_button))
        clickTextInTree(launched, context.getString(R.string.sharing_manage_button))

        awaitCondition("The sharing sheet should attach") { onSheet(launched) { it != null } }
        awaitCondition("The sharing sheet should preselect a policy") {
            onSheet(launched) { root ->
                collectViews(root) { it is RadioButton && it.isChecked }.isNotEmpty()
            }
        }
        return launched
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

    /** Selects the policy option titled [title]. */
    private fun clickPolicy(scenario: ActivityScenario<KeyDetailActivity>, title: String) {
        val clicked = onSheet(scenario) { root ->
            val target = collectViews(root) {
                it is RadioButton && it.text?.toString() == title
            }.firstOrNull()
            if (target == null) false else { target.performClick(); true }
        }
        waitForIdle()
        assertTrue("Expected the '$title' option in the sharing sheet", clicked)
    }

    /** Whether the card for [deviceName] is checked, or null when absent. */
    private fun peerChecked(
        scenario: ActivityScenario<KeyDetailActivity>,
        deviceName: String
    ): Boolean? = onSheet(scenario) { root -> peerCheckbox(root, deviceName)?.isChecked }

    /**
     * The checkbox on [deviceName]'s card.
     *
     * Scoped to that card: every peer card carries a checkbox, so a bare "first
     * CheckBox" search would answer for whichever device sorts first.
     */
    private fun peerCheckbox(root: View?, deviceName: String): CheckBox? {
        val card = collectViews(root) { it is MaterialCardView }
            .firstOrNull { findTextView(it, deviceName) != null }
        return collectViews(card) { it is CheckBox }.firstOrNull() as CheckBox?
    }

    private fun clickPeerCheckbox(
        scenario: ActivityScenario<KeyDetailActivity>,
        deviceName: String
    ) {
        val clicked = onSheet(scenario) { root ->
            val checkbox = peerCheckbox(root, deviceName)
            if (checkbox == null) false else { checkbox.performClick(); true }
        }
        waitForIdle()
        assertTrue("Expected a checkbox for $deviceName in the sharing sheet", clicked)
    }

    private companion object {
        const val PEER_A_HEX = "7dc93c401ebf608aac2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071829"
        const val PEER_B_HEX = "8eda4d512fc0719bbd3e4f50617283940516273849a0b1c2d3e4f5a6b7c8d9e0"
        const val PEER_A_NAME = "xKey Revocation Peer A"
        const val PEER_B_NAME = "xKey Revocation Peer B"
    }
}
