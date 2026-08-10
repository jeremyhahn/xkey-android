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
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Instrumented tests for the [PasskeyDetailActivity] rows whose value depends on
 * the credential.
 *
 * `PasskeyDetailActivityUiTest` seeds one discoverable, biometric, locally-held
 * passkey, which pins every ternary on the screen to a single side: the security
 * card always reads "Yes", the source is always "Local", the sharing policy
 * always "Private" and the usage card always "Never". This suite seeds the other
 * side of each, plus the placeholder rendering for a credential that carries no
 * relying-party or account metadata at all.
 *
 * Rows are read by label ([detailValue]) rather than by scanning for a value:
 * "Yes" and "No" repeat across the card, so only the label disambiguates them.
 *
 * Tests cover:
 * - Security card reporting "No" for StrongBox, biometric and discoverability
 * - Every source token mapped to its display name, including an unknown one
 * - Every sharing policy mapped to its display name
 * - "-" placeholders for missing relying-party and account details
 * - A used credential's formatted timestamp and use count
 *
 * Every seeded row is deleted in @After.
 */
@RunWith(AndroidJUnit4::class)
class PasskeyDetailFlowTest {

    private val runId = System.nanoTime()
    private val seededKeyIds = mutableListOf<String>()

    private lateinit var keyDao: KeyDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
    }

    @After
    fun tearDown() {
        runBlocking { seededKeyIds.forEach { keyDao.deleteByKeyId(it) } }
    }

    // ---------------------------------------------------------------
    // Security card
    // ---------------------------------------------------------------

    @Test
    fun softwarePasskey_reportsNoForEverySecurityFlag() {
        val keyId = seed(
            strongBoxBacked = false,
            biometricRequired = false,
            isDiscoverable = false
        )

        val scenario = launch(keyId)
        val no = withString(scenario, R.string.key_detail_no)

        assertEquals(no, detailValue(scenario, withString(scenario, R.string.passkey_strongbox)))
        assertEquals(no, detailValue(scenario, withString(scenario, R.string.passkey_biometric)))
        assertEquals(no, detailValue(scenario, withString(scenario, R.string.passkey_discoverable)))
    }

    // ---------------------------------------------------------------
    // Source and sharing
    // ---------------------------------------------------------------

    /**
     * Each stored source token has a display name; anything unrecognised is
     * echoed rather than dropped, so a new backend never renders as blank.
     */
    @Test
    fun sourceRow_namesEveryKnownBackendAndEchoesUnknownOnes() {
        val expectations = mapOf(
            "local" to R.string.key_source_local,
            "remote_ble" to R.string.key_source_remote_ble,
            "remote_usb" to R.string.key_source_remote_usb,
            "xkmsd" to R.string.key_source_xkmsd
        )

        expectations.forEach { (token, resId) ->
            val scenario = launch(seed(source = token))
            assertEquals(
                "source '$token' should render as its display name",
                withString(scenario, resId),
                detailValue(scenario, withString(scenario, R.string.passkey_source))
            )
            scenario.close()
        }

        val scenario = launch(seed(source = UNKNOWN_SOURCE))
        assertEquals(
            UNKNOWN_SOURCE,
            detailValue(scenario, withString(scenario, R.string.passkey_source))
        )
    }

    @Test
    fun sharingRow_namesEverySharingPolicy() {
        val expectations = mapOf(
            SharingPolicyType.PRIVATE to R.string.sharing_policy_private,
            SharingPolicyType.ALL_PEERS to R.string.sharing_policy_all_peers,
            SharingPolicyType.SELECTED_PEERS to R.string.sharing_policy_selected_peers
        )

        expectations.forEach { (policy, resId) ->
            val scenario = launch(
                seed(sharingPolicy = policy, shareable = policy != SharingPolicyType.PRIVATE)
            )
            assertEquals(
                "policy $policy should render as its display name",
                withString(scenario, resId),
                detailValue(scenario, withString(scenario, R.string.passkey_sharing))
            )
            scenario.close()
        }
    }

    // ---------------------------------------------------------------
    // Placeholders
    // ---------------------------------------------------------------

    /** A credential with no site or account metadata renders "-" rather than "null". */
    @Test
    fun passkeyWithoutSiteOrAccountDetails_showsPlaceholders() {
        val keyId = seed(
            rpId = null,
            rpName = null,
            userName = null,
            userDisplayName = null
        )

        val scenario = launch(keyId)

        assertEquals("-", detailValue(scenario, withString(scenario, R.string.passkey_rp_name)))
        assertEquals("-", detailValue(scenario, withString(scenario, R.string.passkey_rp_id)))
        assertEquals("-", detailValue(scenario, withString(scenario, R.string.passkey_user_name)))
        assertEquals(
            "-",
            detailValue(scenario, withString(scenario, R.string.passkey_user_display_name))
        )
    }

    // ---------------------------------------------------------------
    // Usage card
    // ---------------------------------------------------------------

    @Test
    fun usedPasskey_showsTheLastUsedTimestampAndUseCount() {
        val lastUsed = System.currentTimeMillis() - TWO_HOURS_MS
        val keyId = seed(lastUsedAt = lastUsed, useCount = USE_COUNT)

        val scenario = launch(keyId)

        val expected = SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault())
            .format(Date(lastUsed))
        assertEquals(
            expected,
            detailValue(scenario, withString(scenario, R.string.passkey_last_used))
        )
        assertEquals(
            withString(scenario, R.string.passkey_times_used, USE_COUNT.toInt()),
            detailValue(scenario, withString(scenario, R.string.passkey_use_count))
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun seed(
        rpId: String? = "flow-detail-$runId.example.com",
        rpName: String? = "Flow Detail Site $runId",
        userName: String? = "flow-detail-user-$runId",
        userDisplayName: String? = "Flow Detail User $runId",
        source: String = "local",
        sharingPolicy: SharingPolicyType = SharingPolicyType.PRIVATE,
        shareable: Boolean = false,
        strongBoxBacked: Boolean = false,
        biometricRequired: Boolean = true,
        isDiscoverable: Boolean = true,
        lastUsedAt: Long = 0,
        useCount: Long = 0
    ): String {
        val keyId = "ui-test-passkey-detail-flow-${System.nanoTime()}-$runId"
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = "fido2",
                    algorithm = "ES256",
                    label = "Flow Detail Passkey $runId",
                    keySizeBits = 256,
                    strongBoxBacked = strongBoxBacked,
                    biometricRequired = biometricRequired,
                    shareable = shareable,
                    sharingPolicy = sharingPolicy,
                    source = source,
                    rpId = rpId,
                    rpName = rpName,
                    userName = userName,
                    userDisplayName = userDisplayName,
                    isDiscoverable = isDiscoverable,
                    lastUsedAt = lastUsedAt,
                    useCount = useCount
                )
            )
        }
        seededKeyIds.add(keyId)
        return keyId
    }

    private fun launch(keyId: String): ActivityScenario<PasskeyDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            PasskeyDetailActivity::class.java
        ).apply {
            putExtra(PasskeyDetailActivity.EXTRA_KEY_ID, keyId)
        }
        val scenario = ActivityScenario.launch<PasskeyDetailActivity>(intent)
        // The cards are added only once the row has been read from Room.
        assertTextInTree(scenario, ApplicationProvider.getApplicationContext<Context>()
            .getString(R.string.passkey_section_security))
        return scenario
    }

    /**
     * Returns the value rendered beside the detail row labelled [label].
     *
     * Rows are built as `[label][value]`, so the value is the second TextView of
     * the label's parent. Matching on the value alone would be ambiguous: "Yes",
     * "No" and "-" each appear on several rows.
     */
    private fun detailValue(
        scenario: ActivityScenario<PasskeyDetailActivity>,
        label: String
    ): String = withActivity(scenario) { activity ->
        val labelView = collectViews(activity.window.decorView) {
            it is TextView && it.text?.toString() == label
        }.firstOrNull() ?: throw AssertionError("No detail row labelled '$label'")
        val row = labelView.parent as View
        val cells = collectViews(row) { it is TextView }
        require(cells.size >= 2) { "Row '$label' has no value cell" }
        (cells[1] as TextView).text.toString()
    }

    private fun withString(
        scenario: ActivityScenario<PasskeyDetailActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    private companion object {
        const val UNKNOWN_SOURCE = "flow-unknown-backend"
        const val USE_COUNT = 3L
        const val TWO_HOURS_MS = 2L * 60L * 60L * 1000L
    }
}
