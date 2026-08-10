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
import android.content.Intent
import android.net.Uri
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onData
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.openActionBarOverflowOrOptionsMenu
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.closeSoftKeyboard
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.RootMatchers.isPlatformPopup
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withSubstring
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.R
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.hasToString
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec

/**
 * End-to-end import and export flows for [ContactManagementActivity].
 *
 * `ContactManagementActivityUiTest` stops at the entry points: it opens the
 * import bottom sheet and cancels the paste dialog. Everything past the first
 * dialog button -- parsing the key material, the name prompt, the insert, the
 * duplicate and malformed-input error paths, importing through the file picker
 * and rendering this device's own public key as a QR code -- is only reached
 * from here.
 *
 * Key material is generated in software wherever the screen only needs a public
 * key: an X.509 SubjectPublicKeyInfo is all `parsePublicKey` consumes, and a
 * software key leaves no Keystore alias behind. The one exception is the export
 * flow, which resolves the public half of a key from the Keystore by alias and
 * therefore needs a real entry.
 *
 * Every contact this class may create is registered *before* the import is
 * triggered and deleted in @After, so a half-completed flow still gets cleaned
 * up. Counts are always read back from the DAO because other suites and the app
 * itself share the `contacts` table.
 *
 * The QR *scan* path is deliberately untouched: it needs the camera and is being
 * reworked. Only the stable entry points around it are asserted.
 *
 * Tests cover:
 * - Paste import of an EC and an RSA key, including the detected algorithm
 * - The name prompt: its fingerprint preview, a custom name, the default name,
 *   and cancelling it
 * - Duplicate keys rejected by the unique fingerprint index
 * - Malformed and empty paste input
 * - File import via a stubbed `ACTION_OPEN_DOCUMENT` result, in PEM and DER form
 * - Exporting an own public key as a QR code
 * - The detail dialog's dismiss (OK) path
 * - The FAB retracting on scroll and returning on scroll back
 */
@RunWith(AndroidJUnit4::class)
class ContactManagementFlowTest {

    private lateinit var context: Context
    private lateinit var dao: ContactDao
    private lateinit var keyDao: KeyDao

    /**
     * Every fingerprint this run may have written, registered before the import
     * is triggered so that a half-completed flow still gets cleaned up.
     */
    private val createdFingerprints = mutableSetOf<String>()

    private val runId = System.nanoTime()
    private val ownKeyId = "uitest-contact-export-$runId"
    private val ownKeyAlias = "xkey_key_$ownKeyId"
    private var ownKeySeeded = false
    private var seedCounter = 0

    private val scratchFiles = mutableListOf<File>()

    /** Generated lazily: RSA key generation is far slower than EC. */
    private val ecKey: KeyPair by lazy {
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
    }

    private val rsaKey: KeyPair by lazy {
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    @Before
    fun setUp() {
        Intents.init()
        context = ApplicationProvider.getApplicationContext()
        dao = XKeyDatabase.getInstance(context).contactDao()
        keyDao = XKeyDatabase.getInstance(context).keyDao()
    }

    @After
    fun tearDown() {
        runBlocking {
            createdFingerprints.forEach { dao.deleteByFingerprint(it) }
            if (ownKeySeeded) keyDao.deleteByKeyId(ownKeyId)
        }
        TestCertificates.deleteAlias(ownKeyAlias)
        scratchFiles.forEach { it.delete() }
        Intents.release()
    }

    // -----------------------------------------------------------------
    // Paste import
    // -----------------------------------------------------------------

    /**
     * The whole paste path: PEM in, name prompt, row in the database and on
     * screen. The prompt's fingerprint preview is asserted too, because it is
     * the only place the user can compare the key against the sender's copy.
     */
    @Test
    fun pasteImport_ofAnEcKey_promptsWithTheFingerprintAndStoresTheContact() {
        val fingerprint = fingerprintOf(ecKey)
        createdFingerprints += fingerprint
        val scenario = launch()
        val before = contactCount()

        openPasteDialog(scenario)
        onView(withHint(R.string.contact_paste_hint))
            .inRoot(isDialog())
            .perform(replaceText(pemOf(ecKey)), closeSoftKeyboard())
        clickPositiveButton()

        // The prompt shows only the leading 23 characters of the formatted
        // fingerprint, followed by an ellipsis.
        val preview = formatFingerprint(fingerprint).take(23) + "..."
        onView(withText(string(scenario, R.string.contact_fingerprint, preview)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(string(scenario, R.string.contact_algorithm, "ES256")))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))

        onView(withHint(R.string.contact_name_hint))
            .inRoot(isDialog())
            .perform(replaceText(PASTED_NAME), closeSoftKeyboard())
        clickPositiveButton()

        awaitCondition("The pasted key should have been inserted") {
            runBlocking { dao.getByFingerprint(fingerprint) } != null
        }
        val stored = runBlocking { dao.getByFingerprint(fingerprint) }!!
        assertEquals(PASTED_NAME, stored.name)
        assertEquals("ES256", stored.algorithm)
        assertEquals("paste", stored.source)
        assertEquals(before + 1, contactCount())
        assertShownTextInList(scenario, PASTED_NAME)
    }

    /** RSA key material must be detected as RS256 rather than rejected. */
    @Test
    fun pasteImport_ofAnRsaKey_recordsTheRsaAlgorithm() {
        val fingerprint = fingerprintOf(rsaKey)
        createdFingerprints += fingerprint
        val scenario = launch()

        importByPaste(scenario, pemOf(rsaKey), RSA_NAME)

        awaitCondition("The pasted RSA key should have been inserted") {
            runBlocking { dao.getByFingerprint(fingerprint) } != null
        }
        assertEquals("RS256", runBlocking { dao.getByFingerprint(fingerprint) }!!.algorithm)
    }

    /** An empty name falls back to the generic contact label. */
    @Test
    fun pasteImport_withNoNameEntered_usesTheDefaultContactName() {
        val fingerprint = fingerprintOf(ecKey)
        createdFingerprints += fingerprint
        val scenario = launch()

        openPasteDialog(scenario)
        onView(withHint(R.string.contact_paste_hint))
            .inRoot(isDialog())
            .perform(replaceText(pemOf(ecKey)), closeSoftKeyboard())
        clickPositiveButton()
        // Leave the name field untouched.
        clickPositiveButton()

        awaitCondition("The contact should have been inserted with a default name") {
            runBlocking { dao.getByFingerprint(fingerprint) } != null
        }
        assertEquals(
            string(scenario, R.string.contact_default_name),
            runBlocking { dao.getByFingerprint(fingerprint) }!!.name
        )
    }

    @Test
    fun namePromptCancelled_leavesTheContactListUnchanged() {
        val fingerprint = fingerprintOf(ecKey)
        createdFingerprints += fingerprint
        val scenario = launch()
        val before = contactCount()

        openPasteDialog(scenario)
        onView(withHint(R.string.contact_paste_hint))
            .inRoot(isDialog())
            .perform(replaceText(pemOf(ecKey)), closeSoftKeyboard())
        clickPositiveButton()
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertNull(
            "Cancelling the name prompt must not insert a contact",
            runBlocking { dao.getByFingerprint(fingerprint) }
        )
        assertEquals(before, contactCount())
    }

    /**
     * `public_key_fingerprint` carries a unique index, so re-importing a key
     * already held must be reported rather than duplicated or left to crash the
     * insert.
     */
    @Test
    fun pasteImport_ofAKeyAlreadyHeld_keepsExactlyOneRow() {
        val fingerprint = fingerprintOf(ecKey)
        createdFingerprints += fingerprint
        runBlocking {
            dao.insert(
                ContactEntity(
                    name = EXISTING_NAME,
                    publicKeyDer = ecKey.public.encoded,
                    publicKeyFingerprint = fingerprint,
                    algorithm = "ES256",
                    source = "paste"
                )
            )
        }
        val scenario = launch()
        val before = contactCount()

        importByPaste(scenario, pemOf(ecKey), "Duplicate Attempt")

        assertShownTextInTree(scenario, string(scenario, R.string.contact_import_duplicate))
        assertEquals("The duplicate must not add a row", before, contactCount())
        assertEquals(
            "The original contact must survive the rejected import",
            EXISTING_NAME,
            runBlocking { dao.getByFingerprint(fingerprint) }!!.name
        )
    }

    /** Unparseable input must surface an error and add nothing. */
    @Test
    fun pasteImport_ofMalformedInput_reportsAnErrorAndAddsNoContact() {
        val scenario = launch()
        val before = contactCount()

        openPasteDialog(scenario)
        onView(withHint(R.string.contact_paste_hint))
            .inRoot(isDialog())
            .perform(replaceText("this is not a public key"), closeSoftKeyboard())
        clickPositiveButton()

        // Both rejection routes (undecodable Base64, and decodable bytes that
        // are not a key) surface through the same error snackbar prefix.
        assertShownTextInTree(scenario, errorPrefix(scenario))
        assertEquals(before, contactCount())
    }

    /** Submitting an empty paste dialog is a no-op, not an error. */
    @Test
    fun pasteDialogSubmittedEmpty_doesNothing() {
        val scenario = launch()
        val before = contactCount()

        openPasteDialog(scenario)
        clickPositiveButton()

        assertEquals(before, contactCount())
        // Espresso resolves against the topmost focused window, so this fails if
        // the name prompt opened at all.
        onView(withText(R.string.contact_name_prompt)).check(doesNotExist())
    }

    // -----------------------------------------------------------------
    // File import
    // -----------------------------------------------------------------

    /**
     * The file picker result is stubbed rather than driven, so the assertion is
     * about what the activity does with the bytes it is handed. PEM text is not
     * DER, so this also covers the PEM fallback inside `importPublicKeyBytes`.
     */
    @Test
    fun fileImport_ofAPemPublicKey_storesTheContactWithTheFileSource() {
        val fingerprint = fingerprintOf(ecKey)
        createdFingerprints += fingerprint
        stubOpenDocumentWith(scratchFile("contact-$runId.pem", pemOf(ecKey).toByteArray()))

        val scenario = launch()
        openImportBottomSheet(scenario)
        onView(withText(R.string.contact_import_file)).inRoot(isDialog()).perform(click())

        onView(withHint(R.string.contact_name_hint))
            .inRoot(isDialog())
            .perform(replaceText(FILE_NAME), closeSoftKeyboard())
        clickPositiveButton()

        awaitCondition("The key read from the file should have been inserted") {
            runBlocking { dao.getByFingerprint(fingerprint) } != null
        }
        val stored = runBlocking { dao.getByFingerprint(fingerprint) }!!
        assertEquals(FILE_NAME, stored.name)
        assertEquals("file", stored.source)
    }

    /** A file holding raw DER goes down the direct parse branch. */
    @Test
    fun fileImport_ofADerPublicKey_storesTheContact() {
        val fingerprint = fingerprintOf(ecKey)
        createdFingerprints += fingerprint
        stubOpenDocumentWith(scratchFile("contact-$runId.der", ecKey.public.encoded))

        val scenario = launch()
        openImportBottomSheet(scenario)
        onView(withText(R.string.contact_import_file)).inRoot(isDialog()).perform(click())

        onView(withHint(R.string.contact_name_hint))
            .inRoot(isDialog())
            .perform(replaceText(DER_NAME), closeSoftKeyboard())
        clickPositiveButton()

        awaitCondition("The DER key should have been inserted") {
            runBlocking { dao.getByFingerprint(fingerprint) } != null
        }
        assertEquals(DER_NAME, runBlocking { dao.getByFingerprint(fingerprint) }!!.name)
    }

    @Test
    fun fileImport_ofAFileWithoutAKey_reportsAnErrorAndAddsNoContact() {
        stubOpenDocumentWith(scratchFile("garbage-$runId.bin", ByteArray(64) { it.toByte() }))

        val scenario = launch()
        val before = contactCount()
        openImportBottomSheet(scenario)
        onView(withText(R.string.contact_import_file)).inRoot(isDialog()).perform(click())

        assertShownTextInTree(scenario, errorPrefix(scenario))
        assertEquals(before, contactCount())
    }

    // -----------------------------------------------------------------
    // Export
    // -----------------------------------------------------------------

    /**
     * The export menu offers every key whose public half the Keystore can
     * produce, so whether a picker appears first depends on what else is stored
     * on the device. The same predicate the activity uses is evaluated here
     * rather than assuming a count.
     */
    @Test
    fun exportMenu_rendersTheQrCodeForAnOwnPublicKey() {
        seedOwnKey()
        val scenario = launch()

        openActionBarOverflowOrOptionsMenu(context)
        onView(withText(R.string.contact_export_qr))
            .inRoot(isPlatformPopup())
            .perform(click())

        if (exportableKeyCount() > 1) {
            val entry = string(
                scenario,
                R.string.contact_export_key_entry,
                OWN_KEY_LABEL,
                OWN_KEY_ALGORITHM
            )
            onData(hasToString(entry)).inRoot(isDialog()).perform(click())
        }

        onView(withText(OWN_KEY_LABEL)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withText(string(scenario, R.string.contact_algorithm, OWN_KEY_ALGORITHM)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.contact_export_qr_instruction))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    // -----------------------------------------------------------------
    // Detail dialog
    // -----------------------------------------------------------------

    /** Dismissing the detail dialog with OK must not touch the contact. */
    @Test
    fun contactDetailDialogDismissed_keepsTheContact() {
        val fingerprint = seedContact(DETAIL_NAME)
        val scenario = launch()
        assertShownTextInList(scenario, DETAIL_NAME)

        clickTextInTree(scenario, DETAIL_NAME)
        onView(withSubstring(string(scenario, R.string.contact_imported_date, "").trim()))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())

        assertNotNull(
            "Dismissing the detail dialog must keep the contact",
            runBlocking { dao.getByFingerprint(fingerprint) }
        )
        assertShownTextInList(scenario, DETAIL_NAME)
    }

    // -----------------------------------------------------------------
    // FAB behaviour
    // -----------------------------------------------------------------

    /**
     * The FAB retracts while the list scrolls down so it stops covering rows,
     * and comes back on the way up. Enough contacts are seeded to make the list
     * scrollable regardless of what else is stored.
     */
    @Test
    fun scrollingTheList_retractsAndRestoresTheFab() {
        repeat(FAB_SCROLL_ROWS) { seedContact("$SCROLL_NAME_PREFIX $it") }
        val scenario = launch()
        assertTrue(
            "The seeded contacts should be bound before scrolling",
            awaitRecyclerItemCount(scenario, FAB_SCROLL_ROWS)
        )

        scrollListBy(scenario, SCROLL_DISTANCE_PX)
        awaitCondition("Scrolling down should push the FAB off screen") {
            fabTranslationY(scenario) > 0f
        }

        scrollListBy(scenario, -SCROLL_DISTANCE_PX)
        awaitCondition("Scrolling back up should bring the FAB back") {
            fabTranslationY(scenario) == 0f
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<ContactManagementActivity> =
        ActivityScenario.launch(ContactManagementActivity::class.java)

    private fun string(
        scenario: ActivityScenario<ContactManagementActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    /** The invariant leading text of every import failure snackbar. */
    private fun errorPrefix(scenario: ActivityScenario<ContactManagementActivity>): String =
        string(scenario, R.string.contact_import_error, "").trim()

    private fun contactCount(): Int = runBlocking { dao.getAll().size }

    /** Opens the import bottom sheet from whichever entry point is on screen. */
    private fun openImportBottomSheet(scenario: ActivityScenario<ContactManagementActivity>) {
        clickClickableWithExactText(scenario, string(scenario, R.string.contact_import_file))
    }

    private fun openPasteDialog(scenario: ActivityScenario<ContactManagementActivity>) {
        openImportBottomSheet(scenario)
        onView(withText(R.string.contact_import_paste)).inRoot(isDialog()).perform(click())
    }

    /** Runs the paste dialog and the name prompt end to end. */
    private fun importByPaste(
        scenario: ActivityScenario<ContactManagementActivity>,
        pem: String,
        name: String
    ) {
        openPasteDialog(scenario)
        onView(withHint(R.string.contact_paste_hint))
            .inRoot(isDialog())
            .perform(replaceText(pem), closeSoftKeyboard())
        clickPositiveButton()
        onView(withHint(R.string.contact_name_hint))
            .inRoot(isDialog())
            .perform(replaceText(name), closeSoftKeyboard())
        clickPositiveButton()
    }

    /**
     * Clicks the dialog's positive button by id.
     *
     * Several of these dialogs give the positive button the same label as their
     * own title -- the paste dialog is titled "Paste Public Key" and confirms
     * with "Paste Public Key" -- which makes a text matcher ambiguous.
     *
     * The click is dispatched on the main thread rather than as an injected tap:
     * every caller here types into a field first, and a tap that lands while the
     * soft keyboard is still animating away is swallowed by the departing IME
     * window, leaving the dialog up and the action reporting success. See
     * [DialogFlowSupport.clickButton].
     */
    private fun clickPositiveButton() {
        DialogFlowSupport.clickButton(android.R.id.button1)
    }

    private fun stubOpenDocumentWith(file: File) {
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT)).respondWith(
            Instrumentation.ActivityResult(
                Activity.RESULT_OK,
                Intent().setData(Uri.fromFile(file))
            )
        )
    }

    private fun scratchFile(name: String, bytes: ByteArray): File =
        File(context.cacheDir, name).apply {
            writeBytes(bytes)
            scratchFiles += this
        }

    /** Inserts a contact with a run-unique fingerprint and registers it for cleanup. */
    private fun seedContact(name: String): String {
        val fingerprint = "%016x%016x%016x%016x".format(
            runId,
            System.nanoTime(),
            seedCounter++.toLong(),
            name.hashCode().toLong()
        )
        createdFingerprints += fingerprint
        runBlocking {
            dao.insert(
                ContactEntity(
                    name = name,
                    publicKeyDer = ByteArray(32) { it.toByte() },
                    publicKeyFingerprint = fingerprint,
                    algorithm = "ES256",
                    source = "paste"
                )
            )
        }
        return fingerprint
    }

    /**
     * Creates a Keystore key plus its `keys` row so the export flow has
     * something to offer. The alias mirrors the general-key naming that
     * [KeystoreManager] resolves.
     */
    private fun seedOwnKey() {
        val certificate = TestCertificates.selfSigned(ownKeyAlias, "xKey UI Export Key")
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = ownKeyId,
                    keyType = "signing",
                    algorithm = OWN_KEY_ALGORITHM,
                    label = OWN_KEY_LABEL,
                    publicKeyDer = certificate.publicKey.encoded,
                    keySizeBits = 256,
                    biometricRequired = false,
                    source = "local"
                )
            )
        }
        ownKeySeeded = true
    }

    /** Number of stored keys whose public half the Keystore can produce. */
    private fun exportableKeyCount(): Int {
        val keystore = KeystoreManager(context)
        return runBlocking { keyDao.getAll() }.count { keystore.getPublicKeyPEM(it.keyId) != null }
    }

    private fun scrollListBy(
        scenario: ActivityScenario<ContactManagementActivity>,
        deltaY: Int
    ) {
        scenario.onActivity { activity ->
            findFirstRecyclerView(activity.window.decorView)?.scrollBy(0, deltaY)
        }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    private fun fabTranslationY(scenario: ActivityScenario<ContactManagementActivity>): Float =
        withActivity(scenario) { activity ->
            collectViews(activity.window.decorView) { it is ExtendedFloatingActionButton }
                .firstOrNull()
                ?.translationY
                ?: 0f
        }

    private fun pemOf(keyPair: KeyPair): String {
        val body = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
            .chunked(64)
            .joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----\n"
    }

    private fun fingerprintOf(keyPair: KeyPair): String =
        MessageDigest.getInstance("SHA-256")
            .digest(keyPair.public.encoded)
            .joinToString("") { "%02x".format(it) }

    private fun formatFingerprint(fingerprint: String): String =
        fingerprint.uppercase().chunked(2).joinToString(":")

    private companion object {
        const val PASTED_NAME = "UI Flow Pasted EC"
        const val RSA_NAME = "UI Flow Pasted RSA"
        const val EXISTING_NAME = "UI Flow Existing"
        const val FILE_NAME = "UI Flow From File"
        const val DER_NAME = "UI Flow From DER"
        const val DETAIL_NAME = "UI Flow Detail"
        const val SCROLL_NAME_PREFIX = "UI Flow Scroll"
        const val OWN_KEY_LABEL = "UI Flow Own Key"
        const val OWN_KEY_ALGORITHM = "ES256"

        /** Enough rows to guarantee the list scrolls on any test device. */
        const val FAB_SCROLL_ROWS = 24

        /** Comfortably more than one row height, in pixels. */
        const val SCROLL_DISTANCE_PX = 600
    }
}
