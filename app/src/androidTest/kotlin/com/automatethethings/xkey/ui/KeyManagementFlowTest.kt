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
import android.os.Build
import android.view.View
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.Spinner
import androidx.recyclerview.widget.ListAdapter
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.UiController
import androidx.test.espresso.ViewAction
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.closeSoftKeyboard
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.RootMatchers.isPlatformPopup
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matcher
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end flow tests for [KeyManagementActivity].
 *
 * `KeyManagementActivityUiTest` covers the static chrome: the toolbar, the hero
 * card, one filter chip and the fact that the FAB opens a dialog. This suite
 * drives the flows behind it — actually generating keys for every purpose and a
 * non-default algorithm, the long-press context menu and its per-key item set,
 * the delete confirmation in both directions, exporting a public key, and the
 * two empty states the filter bar can produce.
 *
 * Three properties of the screen shape everything here:
 * - `KeyStoreSyncManager.syncAll()` runs on start and deletes any non-"xkmsd"
 *   row whose Android Keystore alias is missing, so rows seeded straight into
 *   Room must use `source = "xkmsd"`. Conversely it *discovers* stray aliases
 *   and re-creates rows for them, so a test that generates a real key has to
 *   delete the alias as well as the row or the row comes back.
 * - Key generation is asynchronous (`lifecycleScope` + a suspending Keystore
 *   call), so creations are awaited against the DAO rather than the view tree.
 * - The emulator has no enrolled biometric, so the dialog's "Require biometric"
 *   switch (which defaults to on) is turned off before every creation; an
 *   auth-bound key cannot be generated there and the screen would only report
 *   "Failed to create key".
 *
 * Every key this suite creates is registered in [createdKeyIds] and removed —
 * row *and* Keystore alias — in @After, because other suites assert on live key
 * counts.
 */
@RunWith(AndroidJUnit4::class)
class KeyManagementFlowTest {

    private val runId = System.nanoTime()
    private val seededKeyId = "ui-flow-vault-seed-$runId"
    private val seededLabel = "UI Flow Seeded Signing Key $runId"

    private lateinit var keyDao: KeyDao

    /** Key ids created through the UI during a test; cleaned up in @After. */
    private val createdKeyIds = mutableListOf<String>()

    /** Extra rows seeded straight into Room during a test. */
    private val seededKeyIds = mutableListOf<String>()

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
        runBlocking {
            keyDao.insert(remoteKey(seededKeyId, seededLabel, "signing", "ES256"))
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            for (keyId in createdKeyIds) {
                // The alias has to go first: a surviving alias is rediscovered by
                // KeyStoreSyncManager on the next launch and the row reappears.
                TestCertificates.deleteAlias(GENERAL_ALIAS_PREFIX + keyId)
                keyDao.deleteByKeyId(keyId)
            }
            for (keyId in seededKeyIds) {
                keyDao.deleteByKeyId(keyId)
            }
            keyDao.deleteByKeyId(seededKeyId)
        }
        createdKeyIds.clear()
        seededKeyIds.clear()
    }

    // ---------------------------------------------------------------
    // Create dialog: option sets
    // ---------------------------------------------------------------

    /** Every purpose the screen claims to support must be selectable. */
    @Test
    fun createKeyDialog_offersEverySupportedPurpose() {
        launch()
        openCreateDialog()

        assertEquals(
            listOf(
                string(R.string.key_create_purpose_signing),
                string(R.string.key_create_purpose_tls),
                string(R.string.key_create_purpose_ssh),
                string(R.string.key_create_purpose_encryption),
                string(R.string.key_create_purpose_secret),
                string(R.string.key_create_purpose_hmac)
            ),
            spinnerEntries(PURPOSE_SPINNER)
        )
        dismissDialog()
    }

    /**
     * The algorithm list is rebuilt from the selected purpose, so a purpose
     * whose listener never fires would silently offer the wrong algorithms.
     *
     * This is the same class of defect as the PIV generate-key dialog, where the
     * option list was built but never attached and index 0 was always used.
     */
    @Test
    fun createKeyDialog_algorithmsFollowTheSelectedPurpose() {
        launch()
        openCreateDialog()

        assertEquals(
            listOf("ECDSA P-256", "ECDSA P-384", "RSA 2048"),
            selectPurposeAndReadAlgorithms(PURPOSE_SIGNING)
        )
        assertEquals(asymmetricAlgorithms(), selectPurposeAndReadAlgorithms(PURPOSE_TLS))
        assertEquals(asymmetricAlgorithms(), selectPurposeAndReadAlgorithms(PURPOSE_SSH))
        assertEquals(
            listOf("RSA-OAEP 2048", "RSA-OAEP 4096"),
            selectPurposeAndReadAlgorithms(PURPOSE_ENCRYPTION)
        )
        assertEquals(
            listOf("AES-128", "AES-256"),
            selectPurposeAndReadAlgorithms(PURPOSE_SECRET)
        )
        assertEquals(
            listOf("HMAC-SHA256", "HMAC-SHA512"),
            selectPurposeAndReadAlgorithms(PURPOSE_HMAC)
        )

        dismissDialog()
    }

    // ---------------------------------------------------------------
    // Create dialog: generation
    // ---------------------------------------------------------------

    /**
     * Picking the *second* algorithm must reach the store. A dialog that builds
     * its option list without attaching it silently generates the default.
     */
    @Test
    fun createSigningKey_honoursANonDefaultAlgorithm() {
        launch()

        val label = "UI Flow Signing ES384 $runId"
        val key = createKey(label, PURPOSE_SIGNING, algorithmIndex = 1)

        assertEquals("ES384", key.algorithm)
        assertEquals("signing", key.keyType)
        assertEquals(384, key.keySizeBits)
        assertEquals(label, key.label)
        assertNotNull("A signing key must record its public key", key.publicKeyDer)
    }

    /** A key created here must be resolvable under the general alias namespace. */
    @Test
    fun createdKey_isBackedByAnAndroidKeystoreAlias() {
        launch()

        val key = createKey(
            "UI Flow Keystore Backing $runId",
            PURPOSE_SIGNING,
            algorithmIndex = 0
        )

        assertTrue(
            "A generated key must exist in the Android Keystore under " +
                "$GENERAL_ALIAS_PREFIX${key.keyId}",
            keystoreContainsAlias(GENERAL_ALIAS_PREFIX + key.keyId)
        )
    }

    @Test
    fun createTlsKey_withRsaRecordsTheRsaKeySize() {
        launch()

        val key = createKey(
            "UI Flow TLS RSA $runId",
            PURPOSE_TLS,
            algorithmIndex = 2,
            timeoutMs = RSA_TIMEOUT_MS
        )

        assertEquals("RS256", key.algorithm)
        assertEquals("tls", key.keyType)
        assertEquals(2048, key.keySizeBits)
    }

    @Test
    fun createSshKey_recordsTheSshKeyType() {
        launch()

        val key = createKey("UI Flow SSH $runId", PURPOSE_SSH, algorithmIndex = 0)

        assertEquals("ssh", key.keyType)
        assertEquals("ES256", key.algorithm)
    }

    /** AES keys are symmetric: no public key is recorded for them. */
    @Test
    fun createSecretKey_storesASymmetricKeyWithoutAPublicKey() {
        launch()

        val key = createKey("UI Flow Secret $runId", PURPOSE_SECRET, algorithmIndex = 1)

        assertEquals("secret", key.keyType)
        assertEquals("AES-256", key.algorithm)
        assertEquals(256, key.keySizeBits)
        assertNull("A symmetric key has no public key", key.publicKeyDer)
    }

    @Test
    fun createHmacKey_honoursTheSha512Variant() {
        launch()

        val key = createKey("UI Flow HMAC $runId", PURPOSE_HMAC, algorithmIndex = 1)

        assertEquals("hmac", key.keyType)
        assertEquals("HMAC-SHA512", key.algorithm)
        assertEquals(512, key.keySizeBits)
        assertNull("An HMAC key has no public key", key.publicKeyDer)
    }

    @Test
    fun createEncryptionKey_recordsTheSelectedOaepAlgorithm() {
        launch()

        val key = createKey(
            "UI Flow Encryption $runId",
            PURPOSE_ENCRYPTION,
            algorithmIndex = 1,
            timeoutMs = RSA_TIMEOUT_MS
        )

        assertEquals("encryption", key.keyType)
        assertEquals("RSA-OAEP-4096", key.algorithm)
    }

    /** An empty label falls back to "<purpose> Key". */
    @Test
    fun createKey_withoutALabel_fallsBackToThePurposeName() {
        launch()

        val key = createKey(label = null, purposeIndex = PURPOSE_SIGNING, algorithmIndex = 0)

        assertEquals("${string(R.string.key_create_purpose_signing)} Key", key.label)
    }

    /** A freshly created key must reach the list and the hero count. */
    @Test
    fun createdKey_appearsInTheListAndTheLiveHeroCount() {
        val scenario = launch()
        val label = "UI Flow Listed Key $runId"

        createKey(label, PURPOSE_SIGNING, algorithmIndex = 0)

        assertShownTextInList(scenario, label)
        assertExactTextShown(scenario, runBlocking { keyDao.countAll() }.toString())
    }

    /** The creation path reports success through a snackbar. */
    @Test
    fun createKey_confirmsWithASnackbar() {
        val scenario = launch()

        createKey("UI Flow Snackbar $runId", PURPOSE_SIGNING, algorithmIndex = 0)

        assertShownTextInTree(scenario, string(R.string.key_create_success))
    }

    // ---------------------------------------------------------------
    // Context menu
    // ---------------------------------------------------------------

    /** A user-owned key with a public key offers all four actions. */
    @Test
    fun contextMenu_forAnOrdinaryKey_offersEveryAction() {
        val scenario = launch()

        openContextMenu(scenario, seededKeyId)

        assertMenuItemShown(R.string.key_menu_share_settings)
        assertMenuItemShown(R.string.key_menu_view_details)
        assertMenuItemShown(R.string.key_menu_export_public)
        assertMenuItemShown(R.string.key_menu_delete)
    }

    /** Without a public key there is nothing to export, so the item is hidden. */
    @Test
    fun contextMenu_hidesExportWhenThereIsNoPublicKey() {
        val scenario = launch()
        val keyId = seedRemoteKey("UI Flow No Public Key $runId", "secret", "AES-256")

        openContextMenu(scenario, keyId)

        assertMenuItemShown(R.string.key_menu_view_details)
        assertMenuItemAbsent(R.string.key_menu_export_public)
    }

    /** System keys are read-only: neither sharing nor deletion is offered. */
    @Test
    fun contextMenu_forASystemKey_offersOnlyViewDetails() {
        val scenario = launch()
        val keyId = seedRemoteKey(
            "UI Flow System Key $runId",
            "ca",
            "ES256",
            isSystemKey = true
        )

        openContextMenu(scenario, keyId)

        assertMenuItemShown(R.string.key_menu_view_details)
        assertMenuItemAbsent(R.string.key_menu_share_settings)
        assertMenuItemAbsent(R.string.key_menu_delete)
    }

    // ---------------------------------------------------------------
    // Export
    // ---------------------------------------------------------------

    /** Exporting a public key wraps it in PEM and confirms with a snackbar. */
    @Test
    fun exportPublicKey_confirmsTheCopy() {
        val scenario = launch()
        val key = createKey(
            "UI Flow Export $runId",
            PURPOSE_SIGNING,
            algorithmIndex = 0
        )

        openContextMenu(scenario, key.keyId)
        clickMenuItem(R.string.key_menu_export_public)

        assertShownTextInTree(scenario, string(R.string.key_public_key_copied))
    }

    // ---------------------------------------------------------------
    // Delete
    // ---------------------------------------------------------------

    @Test
    fun deleteCancelled_keepsTheKeyAndItsAlias() {
        val scenario = launch()
        val key = createKey(
            "UI Flow Delete Cancel $runId",
            PURPOSE_SIGNING,
            algorithmIndex = 0
        )

        openContextMenu(scenario, key.keyId)
        clickMenuItem(R.string.key_menu_delete)
        onView(withText(string(R.string.key_delete_message, key.label)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withId(android.R.id.button2)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertNotNull(
            "Cancelling must keep the key row",
            runBlocking { keyDao.getByKeyId(key.keyId) }
        )
        assertTrue(
            "Cancelling must keep the Keystore alias",
            keystoreContainsAlias(GENERAL_ALIAS_PREFIX + key.keyId)
        )
    }

    /** Confirming removes both the Room row and the Android Keystore entry. */
    @Test
    fun deleteConfirmed_removesTheKeyAndItsAlias() {
        val scenario = launch()
        val key = createKey(
            "UI Flow Delete Confirm $runId",
            PURPOSE_SIGNING,
            algorithmIndex = 0
        )

        openContextMenu(scenario, key.keyId)
        clickMenuItem(R.string.key_menu_delete)
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())

        awaitCondition("The key row should be deleted") {
            runBlocking { keyDao.getByKeyId(key.keyId) } == null
        }
        awaitCondition("The Keystore alias should be deleted") {
            !keystoreContainsAlias(GENERAL_ALIAS_PREFIX + key.keyId)
        }
        awaitTextAbsent(scenario, key.label)
    }

    /**
     * A remote key lives on the paired desktop; deleting it only drops the local
     * cache entry, and the dialog has to say so.
     */
    @Test
    fun deletingARemoteKey_warnsThatOnlyTheCacheIsCleared() {
        val scenario = launch()

        openContextMenu(scenario, seededKeyId)
        clickMenuItem(R.string.key_menu_delete)

        onView(withText(string(R.string.remote_key_delete_message, seededLabel)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())

        awaitCondition("The remote key row should be deleted") {
            runBlocking { keyDao.getByKeyId(seededKeyId) } == null
        }
    }

    // ---------------------------------------------------------------
    // Filtering and empty states
    // ---------------------------------------------------------------

    /**
     * A filter that matches nothing offers a shortcut to create that key type
     * plus a way back to the unfiltered list.
     */
    @Test
    fun filterWithNoMatches_offersCreateAndClearActions() {
        val scenario = launch()
        assertShownTextInList(scenario, seededLabel)

        clickFilterChip(scenario, R.string.key_filter_ssh)

        assertShownTextInTree(scenario, string(R.string.no_keys_for_filter, "SSH"))
        assertShownTextInTree(scenario, string(R.string.create_key_of_type, "SSH"))
        assertShownTextInTree(scenario, string(R.string.clear_filter))
    }

    @Test
    fun clearFilter_restoresTheUnfilteredList() {
        val scenario = launch()
        assertShownTextInList(scenario, seededLabel)

        clickFilterChip(scenario, R.string.key_filter_ssh)
        awaitTextAbsent(scenario, seededLabel)

        clickTextInTree(scenario, string(R.string.clear_filter))

        assertShownTextInList(scenario, seededLabel)
    }

    /** The empty-filter shortcut opens the same create dialog as the FAB. */
    @Test
    fun createFromTheEmptyFilterState_opensTheCreateDialog() {
        val scenario = launch()
        assertShownTextInList(scenario, seededLabel)

        clickFilterChip(scenario, R.string.key_filter_ssh)
        clickTextInTree(scenario, string(R.string.create_key_of_type, "SSH"))

        onView(withText(R.string.key_create_purpose))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        dismissDialog()
    }

    /**
     * Attestation keys are produced by the platform, never by the user, so the
     * empty state must not offer to create one.
     */
    @Test
    fun nonCreatableFilter_omitsTheCreateShortcut() {
        val scenario = launch()
        assertShownTextInList(scenario, seededLabel)

        clickFilterChip(scenario, R.string.key_filter_attestation)

        val filterName = string(R.string.key_filter_attestation)
        assertShownTextInTree(scenario, string(R.string.no_keys_for_filter, filterName))
        assertTextNotInTree(scenario, string(R.string.create_key_of_type, filterName))
        assertShownTextInTree(scenario, string(R.string.clear_filter))
    }

    /** The Remote chip filters on the key's source, not its type. */
    @Test
    fun remoteFilter_showsOnlyKeysBackedByAPairedDevice() {
        val scenario = launch()
        val localLabel = "UI Flow Local Signing $runId"
        createKey(localLabel, PURPOSE_SIGNING, algorithmIndex = 0)

        clickFilterChip(scenario, R.string.key_filter_remote)

        assertShownTextInList(scenario, seededLabel)
        awaitTextAbsent(scenario, localLabel)
    }

    // ---------------------------------------------------------------
    // Scroll-aware FAB
    // ---------------------------------------------------------------

    /**
     * The FAB gets out of the way while the user scrolls down the list and comes
     * back on the way up.
     */
    @Test
    fun scrollingTheList_hidesAndRestoresTheFab() {
        repeat(FILLER_ROW_COUNT) { index ->
            seedRemoteKey("UI Flow Filler $index $runId", "signing", "ES256")
        }
        val scenario = launch()
        assertTrue(
            "The seeded filler rows should reach the list",
            awaitRecyclerItemCount(scenario, FILLER_ROW_COUNT)
        )

        scrollList(scenario, dy = 1_200)
        awaitCondition("Scrolling down should hide the FAB") { fabAlpha(scenario) == 0f }

        scrollList(scenario, dy = -1_200)
        awaitCondition("Scrolling up should restore the FAB") { fabAlpha(scenario) == 1f }
    }

    // ---------------------------------------------------------------
    // Helpers: launching and seeding
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<KeyManagementActivity> =
        ActivityScenario.launch(KeyManagementActivity::class.java)

    private fun string(resId: Int, vararg args: Any): String {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return if (args.isEmpty()) context.getString(resId) else context.getString(resId, *args)
    }

    /**
     * Matches the first displayed view carrying [stringRes].
     *
     * Chip labels are repeated by the key cards' type text and by the create
     * dialog, so an unqualified matcher raises `AmbiguousViewMatcherException`.
     * The filter bar is built before the list, so index 0 is the chip.
     */
    private fun firstDisplayed(stringRes: Int): Matcher<View> =
        nthMatch(allOf(withText(stringRes), isDisplayed()), 0)

    /**
     * Clicks the filter chip labelled [stringRes].
     *
     * The eleven chips are laid out in a [android.widget.HorizontalScrollView]
     * more than twice the width of the screen, so everything from "TLS" rightward
     * starts scrolled off. Espresso's `isDisplayed()` rejects those outright, and
     * an unqualified `withText` matcher instead lands on the same word rendered
     * as a badge on a key card — which taps the card and opens the detail screen.
     * Clicking the chip itself, by exact text on a view that is *itself*
     * clickable, is both unambiguous and immune to the horizontal scroll offset.
     */
    private fun clickFilterChip(
        scenario: ActivityScenario<KeyManagementActivity>,
        stringRes: Int
    ) {
        clickClickableWithExactText(scenario, string(stringRes))
    }

    /**
     * Builds a row that survives the activity's start-up
     * `KeyStoreSyncManager.syncAll()`: only non-"xkmsd" rows are pruned when
     * their Keystore alias is missing.
     */
    private fun remoteKey(
        keyId: String,
        label: String,
        keyType: String,
        algorithm: String,
        isSystemKey: Boolean = false,
        publicKeyDer: ByteArray? = FAKE_PUBLIC_KEY
    ) = KeyEntity(
        keyId = keyId,
        keyType = keyType,
        algorithm = algorithm,
        label = label,
        publicKeyDer = publicKeyDer,
        keySizeBits = 256,
        biometricRequired = false,
        source = "xkmsd",
        remoteBackend = "software",
        isSystemKey = isSystemKey
    )

    /** Seeds an extra remote row and registers it for teardown. */
    private fun seedRemoteKey(
        label: String,
        keyType: String,
        algorithm: String,
        isSystemKey: Boolean = false
    ): String {
        val keyId = "ui-flow-seed-${seededKeyIds.size}-$runId"
        val publicKeyDer = if (keyType == "secret" || keyType == "hmac") null else FAKE_PUBLIC_KEY
        runBlocking {
            keyDao.insert(remoteKey(keyId, label, keyType, algorithm, isSystemKey, publicKeyDer))
        }
        seededKeyIds.add(keyId)
        return keyId
    }

    // ---------------------------------------------------------------
    // Helpers: the create dialog
    // ---------------------------------------------------------------

    private fun openCreateDialog() {
        onView(firstDisplayed(R.string.key_create_title)).perform(click())
        waitForIdle()
    }

    private fun dismissDialog() {
        onView(withId(android.R.id.button2)).inRoot(isDialog()).perform(click())
        waitForIdle()
    }

    /**
     * Runs the whole creation flow and returns the row it produced.
     *
     * The new row is identified by diffing the store rather than by label, so a
     * blank label (which the screen fills in itself) is still resolvable.
     */
    private fun createKey(
        label: String?,
        purposeIndex: Int,
        algorithmIndex: Int,
        timeoutMs: Long = CREATE_TIMEOUT_MS
    ): KeyEntity {
        val before = runBlocking { keyDao.getAll() }.map { it.keyId }.toSet()

        openCreateDialog()
        if (label != null) {
            onView(isAssignableFrom(EditText::class.java))
                .inRoot(isDialog())
                .perform(replaceText(label), closeSoftKeyboard())
        }
        selectSpinnerItem(PURPOSE_SPINNER, purposeIndex)
        selectSpinnerItem(ALGORITHM_SPINNER, algorithmIndex)
        // The emulator has no enrolled biometric, so an auth-bound key cannot be
        // generated there; the switch defaults to on and has to be cleared.
        onView(isAssignableFrom(MaterialSwitch::class.java))
            .inRoot(isDialog())
            .perform(setChecked(false))
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())

        var created: KeyEntity? = null
        awaitCondition("A new key row should be created", timeoutMs) {
            created = runBlocking { keyDao.getAll() }.firstOrNull { it.keyId !in before }
            created != null
        }
        val key = created ?: throw AssertionError("No key row was created")
        createdKeyIds.add(key.keyId)
        return key
    }

    /** Selects [purposeIndex] and returns the algorithms it produces. */
    private fun selectPurposeAndReadAlgorithms(purposeIndex: Int): List<String> {
        selectSpinnerItem(PURPOSE_SPINNER, purposeIndex)
        return spinnerEntries(ALGORITHM_SPINNER)
    }

    /** The algorithm set shared by the TLS and SSH purposes. */
    private fun asymmetricAlgorithms(): List<String> = buildList {
        add("ECDSA P-256")
        add("ECDSA P-384")
        add("RSA 2048")
        add("RSA 4096")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) add("Ed25519")
    }

    private fun spinnerEntries(spinnerIndex: Int): List<String> {
        val entries = mutableListOf<String>()
        onView(dialogSpinner(spinnerIndex)).inRoot(isDialog()).perform(
            object : ViewAction {
                override fun getConstraints(): Matcher<View> =
                    isAssignableFrom(Spinner::class.java)

                override fun getDescription(): String = "read the spinner's entries"

                override fun perform(uiController: UiController, view: View) {
                    val adapter = (view as Spinner).adapter
                    for (i in 0 until adapter.count) {
                        entries.add(adapter.getItem(i).toString())
                    }
                }
            }
        )
        return entries
    }

    private fun selectSpinnerItem(spinnerIndex: Int, itemIndex: Int) {
        onView(dialogSpinner(spinnerIndex)).inRoot(isDialog()).perform(
            object : ViewAction {
                override fun getConstraints(): Matcher<View> =
                    isAssignableFrom(Spinner::class.java)

                override fun getDescription(): String = "select spinner item $itemIndex"

                override fun perform(uiController: UiController, view: View) {
                    (view as Spinner).setSelection(itemIndex)
                    uiController.loopMainThreadUntilIdle()
                }
            }
        )
        waitForIdle()
    }

    /**
     * The dialog's spinners carry no ids; they are built purpose-first, so index
     * 0 is the purpose spinner and index 1 the algorithm spinner.
     */
    private fun dialogSpinner(index: Int): Matcher<View> =
        nthMatch(isAssignableFrom(Spinner::class.java), index)

    /**
     * Sets a compound button's state without injecting a tap.
     *
     * The switch sits at the bottom of a dialog whose height depends on the
     * device, and Espresso refuses to click a partially obscured view.
     */
    private fun setChecked(checked: Boolean): ViewAction = object : ViewAction {
        override fun getConstraints(): Matcher<View> =
            isAssignableFrom(CompoundButton::class.java)

        override fun getDescription(): String = "set checked to $checked"

        override fun perform(uiController: UiController, view: View) {
            (view as CompoundButton).isChecked = checked
            uiController.loopMainThreadUntilIdle()
        }
    }

    // ---------------------------------------------------------------
    // Helpers: the long-press context menu
    // ---------------------------------------------------------------

    /**
     * Long-presses the row bound to [keyId].
     *
     * The row's position is read from the adapter's current list rather than
     * assumed, because the vault also holds whatever keys the device already
     * had.
     */
    private fun openContextMenu(
        scenario: ActivityScenario<KeyManagementActivity>,
        keyId: String
    ) {
        var position = -1
        awaitCondition("Row for '$keyId' should be bound to the list") {
            position = positionOf(scenario, keyId)
            position >= 0
        }
        longClickRecyclerItem(scenario, position)
    }

    private fun positionOf(
        scenario: ActivityScenario<KeyManagementActivity>,
        keyId: String
    ): Int = withActivity(scenario) { activity ->
        val recycler = findFirstRecyclerView(activity.window.decorView)
        val adapter = recycler?.adapter as? ListAdapter<*, *> ?: return@withActivity -1
        adapter.currentList.indexOfFirst { (it as KeyEntity).keyId == keyId }
    }

    /**
     * A [android.widget.PopupMenu] lives in its own window, so its items are not
     * in the activity's view tree and have to be matched through the popup root.
     */
    private fun assertMenuItemShown(stringRes: Int) {
        onView(withText(stringRes)).inRoot(isPlatformPopup()).check(matches(isDisplayed()))
    }

    private fun assertMenuItemAbsent(stringRes: Int) {
        onView(withText(stringRes)).inRoot(isPlatformPopup()).check(doesNotExist())
    }

    private fun clickMenuItem(stringRes: Int) {
        onView(withText(stringRes)).inRoot(isPlatformPopup()).perform(click())
        waitForIdle()
    }

    // ---------------------------------------------------------------
    // Helpers: list scrolling and the FAB
    // ---------------------------------------------------------------

    private fun scrollList(scenario: ActivityScenario<KeyManagementActivity>, dy: Int) {
        scenario.onActivity { activity ->
            findFirstRecyclerView(activity.window.decorView)?.scrollBy(0, dy)
        }
        waitForIdle()
    }

    private fun fabAlpha(scenario: ActivityScenario<KeyManagementActivity>): Float =
        withActivity(scenario) { activity ->
            collectViews(activity.window.decorView) { it is ExtendedFloatingActionButton }
                .firstOrNull()?.alpha ?: -1f
        }

    // ---------------------------------------------------------------
    // Helpers: Android Keystore
    // ---------------------------------------------------------------

    private fun keystoreContainsAlias(alias: String): Boolean = runCatching {
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.containsAlias(alias)
    }.getOrDefault(false)

    private companion object {
        /** Alias prefix used by `KeystoreManager` for general-purpose keys. */
        const val GENERAL_ALIAS_PREFIX = "xkey_key_"

        const val PURPOSE_SPINNER = 0
        const val ALGORITHM_SPINNER = 1

        const val PURPOSE_SIGNING = 0
        const val PURPOSE_TLS = 1
        const val PURPOSE_SSH = 2
        const val PURPOSE_ENCRYPTION = 3
        const val PURPOSE_SECRET = 4
        const val PURPOSE_HMAC = 5

        /** EC key generation is quick; RSA on an emulator is not. */
        const val CREATE_TIMEOUT_MS = 20_000L
        const val RSA_TIMEOUT_MS = 90_000L

        /** Enough rows to make the list scrollable on any test device. */
        const val FILLER_ROW_COUNT = 18

        /**
         * Placeholder DER for seeded rows. Only its presence matters: the card
         * and the context menu branch on `publicKeyDer != null`, and nothing on
         * this screen parses it.
         */
        val FAKE_PUBLIC_KEY = ByteArray(64) { it.toByte() }
    }
}
