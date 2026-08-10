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
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.entity.KeyEntity
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Instrumented tests for the rendering branches of [KeyDetailActivity].
 *
 * The screen renders a different set of cards, indicators and actions for every
 * combination of key type, origin and security flags, and every one of those
 * decisions is a branch that the happy-path suite
 * ([KeyDetailActivityUiTest], which drives a single local signing key) never
 * reaches. Each test here seeds exactly one key shaped to isolate one decision
 * and asserts both the branch that should render and the one that should not.
 *
 * Branches covered:
 * - Attestation card suppressed for symmetric (`secret`) and `hmac` keys
 * - `xkmsd` keys: remote backend row, remote attestation copy, no export action,
 *   and the "remove from local cache" delete wording
 * - System keys: explanation note instead of a delete action
 * - Security indicators: StrongBox vs TEE vs none, and the biometric badge
 * - Usage card: never-used vs used, with a real formatted timestamp
 * - FIDO2 metadata: discoverable vs non-discoverable, and null metadata
 *   rendering as a placeholder
 * - Unknown key types falling back to a capitalised display name
 *
 * Every seeded row is removed in @After; other suites assert on live key counts.
 */
@RunWith(AndroidJUnit4::class)
class KeyDetailActivityVariantsTest {

    private val runId = System.nanoTime()
    private val seededKeyIds = mutableListOf<String>()

    private val context: Context get() = keyTestContext()

    @After
    fun tearDown() {
        deleteKeyRows(*seededKeyIds.toTypedArray())
        seededKeyIds.clear()
    }

    // -----------------------------------------------------------------
    // Key types without attestation or export
    // -----------------------------------------------------------------

    /**
     * Symmetric keys cannot be attested and have no public half, so the
     * Attestation card and the export action are both suppressed. The Actions
     * card still offers a delete.
     */
    @Test
    fun secretKey_omitsAttestationCardAndExportAction() {
        val keyId = seed(
            key(keyId = "variant-secret", keyType = "secret", algorithm = "AES256", keySizeBits = 256)
        )
        val scenario = launchKeyDetail(keyId)

        // The Actions card is built last, so its presence proves the
        // attestation decision has already been made.
        awaitText(scenario, context.getString(R.string.key_action_delete))
        assertTextNotInTree(scenario, context.getString(R.string.key_section_attestation))
        assertTextNotInTree(scenario, context.getString(R.string.key_action_export_public_key))
        assertShownTextInTree(scenario, context.getString(R.string.key_filter_secret))
    }

    /** HMAC keys take the same suppression path as secret keys. */
    @Test
    fun hmacKey_omitsAttestationCard() {
        val keyId = seed(
            key(
                keyId = "variant-hmac",
                keyType = "hmac",
                algorithm = "HMAC-SHA256",
                keySizeBits = 256
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_action_delete))
        assertTextNotInTree(scenario, context.getString(R.string.key_section_attestation))
    }

    // -----------------------------------------------------------------
    // Remotely managed (xkmsd) keys
    // -----------------------------------------------------------------

    /**
     * A key held by the desktop daemon shows its backend, uses the remote
     * attestation copy, and hides the export action because there is no local
     * Keystore entry to export.
     */
    @Test
    fun xkmsdKey_showsRemoteBackendAndRemoteAttestationCopy() {
        val keyId = seed(
            key(keyId = "variant-xkmsd", source = "xkmsd", remoteBackend = REMOTE_BACKEND)
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_action_delete))
        assertShownTextInTree(scenario, context.getString(R.string.key_detail_remote_backend))
        assertShownTextInTree(scenario, REMOTE_BACKEND)
        assertShownTextInTree(scenario, context.getString(R.string.key_source_xkmsd))
        assertShownTextInTree(scenario, context.getString(R.string.attest_description_remote))
        assertShownTextInTree(scenario, context.getString(R.string.attest_button_remote))
        assertTextNotInTree(scenario, context.getString(R.string.key_action_export_public_key))
    }

    /**
     * Deleting a remotely managed key only drops the local cache entry, and the
     * confirmation wording has to say so.
     */
    @Test
    fun xkmsdKey_deleteSheet_usesRemoveFromCacheWording() {
        val label = "Variant xKMS Key $runId"
        val keyId = seed(
            key(
                keyId = "variant-xkmsd-delete",
                label = label,
                source = "xkmsd",
                remoteBackend = REMOTE_BACKEND
            )
        )
        val scenario = launchKeyDetail(keyId)
        awaitText(scenario, context.getString(R.string.key_action_delete))

        clickTextInTree(scenario, context.getString(R.string.key_action_delete))

        onView(withText(context.getString(R.string.remote_key_delete_message, label)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    // -----------------------------------------------------------------
    // System keys
    // -----------------------------------------------------------------

    /** System keys must not be deletable; the card explains why instead. */
    @Test
    fun systemKey_showsExplanationInsteadOfDeleteAction() {
        val keyId = seed(key(keyId = "variant-system", isSystemKey = true))
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_system_explanation))
        assertTextNotInTree(scenario, context.getString(R.string.key_action_delete))
    }

    // -----------------------------------------------------------------
    // Security indicators
    // -----------------------------------------------------------------

    /**
     * A StrongBox-backed key gets the StrongBox badge and, because the TEE badge
     * is the fallback for keys *without* StrongBox, must not also claim TEE.
     *
     * `exportable` and `biometricRequired` are both false here so that the only
     * "Yes" on screen is the StrongBox row.
     */
    @Test
    fun strongBoxKey_showsStrongBoxBadgeWithoutTee() {
        val keyId = seed(
            key(
                keyId = "variant-strongbox",
                strongBoxBacked = true,
                biometricRequired = false,
                exportable = false
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_detail_strongbox))
        assertExactTextShown(scenario, context.getString(R.string.key_detail_yes))
        assertExactTextShown(scenario, context.getString(R.string.key_detail_not_required))
        assertTextNotInTree(scenario, TEE_BADGE)
    }

    /**
     * A local key without StrongBox falls back to the TEE badge, and a key that
     * requires user verification also gets the biometric badge.
     *
     * `exportable` is the only "Yes" here, which pins the exportable row.
     */
    @Test
    fun localTeeKey_showsTeeAndBiometricBadges() {
        val keyId = seed(
            key(
                keyId = "variant-tee",
                strongBoxBacked = false,
                biometricRequired = true,
                authDurationSeconds = 30,
                exportable = true
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, TEE_BADGE)
        assertShownTextInTree(scenario, context.getString(R.string.key_detail_biometric))
        assertExactTextShown(scenario, context.getString(R.string.key_detail_required))
        assertExactTextShown(scenario, "30s")
        assertExactTextShown(scenario, context.getString(R.string.key_detail_yes))
    }

    /**
     * The TEE badge is claimed only for locally generated keys. A key that
     * arrived over BLE with no StrongBox backing gets no security badge at all,
     * and its origin is reported as remote.
     */
    @Test
    fun remoteBleKey_claimsNoHardwareBadge() {
        val keyId = seed(
            key(
                keyId = "variant-remote-ble",
                source = "remote_ble",
                strongBoxBacked = false,
                biometricRequired = false,
                exportable = false
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_source_remote_ble))
        assertExactTextShown(scenario, context.getString(R.string.key_detail_no))
        assertTextNotInTree(scenario, TEE_BADGE)
    }

    // -----------------------------------------------------------------
    // Usage statistics
    // -----------------------------------------------------------------

    /** A key that has never been used reports "Never" and a zero use count. */
    @Test
    fun neverUsedKey_showsNeverAndZeroCount() {
        val keyId = seed(key(keyId = "variant-unused", useCount = 0, lastUsedAt = 0))
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_section_usage))
        assertExactTextShown(scenario, context.getString(R.string.key_detail_never))
        assertExactTextShown(scenario, "0")
    }

    /**
     * A used key reports its counter and renders the last-used timestamp with
     * the screen's own format, so the expectation is derived rather than
     * hard-coded.
     */
    @Test
    fun usedKey_showsUseCountAndFormattedTimestamp() {
        val keyId = seed(
            key(
                keyId = "variant-used",
                useCount = 42,
                createdAt = CREATED_AT,
                lastUsedAt = LAST_USED_AT
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_section_usage))
        assertExactTextShown(scenario, "42")
        assertExactTextShown(scenario, formatTimestamp(LAST_USED_AT))
        assertExactTextShown(scenario, formatTimestamp(CREATED_AT))
        assertTextNotInTree(scenario, context.getString(R.string.key_detail_never))
    }

    // -----------------------------------------------------------------
    // FIDO2 metadata card
    // -----------------------------------------------------------------

    /** A resident credential is badged as discoverable and shows its counter. */
    @Test
    fun discoverableFido2Key_showsDiscoverableBadgeAndSignCount() {
        val keyId = seed(
            key(
                keyId = "variant-fido2-discoverable",
                keyType = "fido2",
                rpId = "variant-discoverable.example.com",
                rpName = "Variant RP",
                userName = "variant-user",
                userDisplayName = "Variant User",
                isDiscoverable = true,
                signCount = 9
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_section_fido2))
        assertExactTextShown(scenario, DISCOVERABLE_BADGE)
        assertExactTextShown(scenario, "variant-user")
        assertExactTextShown(scenario, "Variant User")
        assertExactTextShown(scenario, "9")
    }

    /** A non-resident credential takes the other badge branch. */
    @Test
    fun nonDiscoverableFido2Key_showsNonDiscoverableBadge() {
        val keyId = seed(
            key(
                keyId = "variant-fido2-server-side",
                keyType = "fido2",
                rpId = "variant-server-side.example.com",
                isDiscoverable = false
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_section_fido2))
        assertExactTextShown(scenario, NON_DISCOVERABLE_BADGE)
    }

    /**
     * FIDO2 metadata is optional in the schema. Missing values must render as a
     * placeholder rather than "null" or an empty row.
     */
    @Test
    fun fido2KeyWithoutOptionalMetadata_showsPlaceholders() {
        val keyId = seed(
            key(
                keyId = "variant-fido2-sparse",
                keyType = "fido2",
                rpId = null,
                rpName = null,
                userName = null,
                userDisplayName = null
            )
        )
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_section_fido2))
        assertShownTextInTree(scenario, context.getString(R.string.key_detail_rp_id))
        assertShownTextInTree(scenario, context.getString(R.string.key_detail_rp_name))
        assertShownTextInTree(scenario, context.getString(R.string.key_detail_user_name))
        assertShownTextInTree(scenario, context.getString(R.string.key_detail_user_display_name))
        assertExactTextShown(scenario, METADATA_PLACEHOLDER)
    }

    // -----------------------------------------------------------------
    // Unknown key types
    // -----------------------------------------------------------------

    /**
     * A key type the screen has no mapping for still renders: the display name
     * falls back to the capitalised raw type and the icon/gradient fall back to
     * the FIDO2 defaults.
     */
    @Test
    fun unknownKeyType_fallsBackToCapitalisedDisplayName() {
        val keyId = seed(key(keyId = "variant-unknown-type", keyType = "vault"))
        val scenario = launchKeyDetail(keyId)

        awaitText(scenario, context.getString(R.string.key_section_general))
        assertExactTextShown(scenario, "Vault")
        // Unknown types are still asymmetric as far as the screen is concerned.
        assertShownTextInTree(scenario, context.getString(R.string.key_section_attestation))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Inserts [key] and registers its id for teardown. Returns the key id. */
    private fun seed(key: KeyEntity): String {
        seedKeyRow(key)
        seededKeyIds.add(key.keyId)
        return key.keyId
    }

    /**
     * Builds a key fixture with a run-unique id.
     *
     * Only the properties a test actually asserts on are ever passed; the rest
     * keep [KeyEntity]'s own defaults so a fixture never silently depends on a
     * value it does not name.
     */
    private fun key(
        keyId: String,
        keyType: String = "signing",
        algorithm: String = "ES256",
        label: String = "Variant $keyId",
        keySizeBits: Int = 256,
        source: String = "local",
        strongBoxBacked: Boolean = false,
        biometricRequired: Boolean = false,
        authDurationSeconds: Int = 5,
        exportable: Boolean = false,
        remoteBackend: String? = null,
        useCount: Long = 0,
        createdAt: Long = System.currentTimeMillis(),
        lastUsedAt: Long = 0,
        rpId: String? = null,
        rpName: String? = null,
        userName: String? = null,
        userDisplayName: String? = null,
        isDiscoverable: Boolean = false,
        signCount: Long = 0,
        isSystemKey: Boolean = false
    ) = KeyEntity(
        keyId = "$keyId-$runId",
        keyType = keyType,
        algorithm = algorithm,
        label = label,
        keySizeBits = keySizeBits,
        strongBoxBacked = strongBoxBacked,
        biometricRequired = biometricRequired,
        authDurationSeconds = authDurationSeconds,
        exportable = exportable,
        source = source,
        remoteBackend = remoteBackend,
        useCount = useCount,
        createdAt = createdAt,
        lastUsedAt = lastUsedAt,
        rpId = rpId,
        rpName = rpName,
        userName = userName,
        userDisplayName = userDisplayName,
        isDiscoverable = isDiscoverable,
        signCount = signCount,
        isSystemKey = isSystemKey
    )

    /** Formats [timestamp] exactly as the Usage card does. */
    private fun formatTimestamp(timestamp: Long): String =
        SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault()).format(Date(timestamp))

    private companion object {
        /** Label of the fallback hardware badge for non-StrongBox local keys. */
        const val TEE_BADGE = "TEE"

        /** Backend name reported for keys held by the desktop daemon. */
        const val REMOTE_BACKEND = "tpm2"

        const val DISCOVERABLE_BADGE = "Discoverable"
        const val NON_DISCOVERABLE_BADGE = "Non-discoverable"
        const val METADATA_PLACEHOLDER = "-"

        /** Fixed instants so the rendered timestamps are reproducible. */
        const val CREATED_AT = 1_600_000_000_000L
        const val LAST_USED_AT = 1_700_000_000_000L
    }
}
