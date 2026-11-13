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

import android.Manifest
import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.BitmapDrawable
import android.widget.ImageView
import android.widget.Spinner
import androidx.core.content.FileProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.CoSignRequest
import com.automatethethings.xkey.media.CoSignResponse
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.SignerRole
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.containsString
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream

/**
 * The co-signing request and response flows of [CoSignActivity].
 *
 * `CoSignActivityUiTest` covers the screen's chrome, its section switching and
 * the two guard clauses that fire before anything is signed. Everything past
 * those guards needs three things the other suite deliberately avoids: a real
 * media file coming back from the system picker, a real signing key, and the
 * signature metadata reader. This suite supplies all three, so it reaches the
 * media-selection handler, the signature list rendering (empty and populated),
 * the initiator QR payload, and the witness signing round trip including its
 * failure branch.
 *
 * The picker is stubbed with Espresso-Intents rather than driven: the real
 * document picker is a separate app, and its UI is not part of this contract.
 * The stubbed result carries a `FileProvider` URI over a JPEG this suite wrote
 * into the app cache, because the activity reads the signature through
 * `ContentResolver.getType`, which reports nothing at all for a `file://` URI.
 *
 * A genuine Android Keystore EC key backs the signing tests -- with no
 * authentication requirement and no StrongBox, since the emulator offers
 * neither -- and the spinner selection is pinned to it, so the flow does not
 * depend on whatever keys other suites happen to have left behind.
 *
 * The Keystore alias, the key row, the key's audit rows and every file are
 * removed in @After. The two co-sign audit rows the flow itself writes carry no
 * key id and the DAO offers no way to delete a single row, so they are left in
 * place; every assertion here is scoped to this run's unique content hash.
 */
@RunWith(AndroidJUnit4::class)
class CoSignFlowTest {

    /** The recreation tests open the real scanner; every other test stubs it. */
    @get:Rule
    val cameraPermission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.CAMERA)

    private val runId = System.nanoTime()

    private val keyId = "ui-test-cosign-$runId"
    private val keyLabel = "UITestCoSign$runId"
    private val signerName = "UITestSigner$runId"

    /**
     * Even-length, all-hex, and unique to this run.
     *
     * The run id leads so the 16-character preview the signature card renders
     * is distinctive too; the padding only fills the tail out to a SHA-256
     * sized string.
     */
    private val contentHash = runId.toString(16).padEnd(64, '0')

    private lateinit var context: Context
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var keyDao: KeyDao
    private lateinit var auditLogDao: AuditLogDao

    private lateinit var plainJpeg: File
    private lateinit var signedJpeg: File

    @Before
    fun setUp() {
        Intents.init()
        context = ApplicationProvider.getApplicationContext()
        keystoreManager = KeystoreManager(context)
        val database = XKeyDatabase.getInstance(context)
        keyDao = database.keyDao()
        auditLogDao = database.auditLogDao()

        runBlocking {
            keystoreManager.generateKeyForAlgorithm(
                keyId = keyId,
                algorithm = KEY_ALGORITHM,
                authDurationSeconds = -1,
                preferStrongBox = false
            )
            keyDao.insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = "signing",
                    algorithm = KEY_ALGORITHM,
                    label = keyLabel,
                    keySizeBits = 256,
                    biometricRequired = false,
                    authDurationSeconds = -1,
                    source = "local"
                )
            )
        }

        plainJpeg = writeJpeg("plain")
        signedJpeg = writeJpeg("signed").also { file ->
            XmpMetadataHelper.writeSignature(
                file.path,
                ContentAuthenticityData(
                    contentHash = contentHash,
                    signatures = listOf(
                        SignatureEntry(
                            keyFingerprint = "fingerprint-$runId",
                            signerName = signerName,
                            algorithm = KEY_ALGORITHM,
                            value = "c2lnbmF0dXJl",
                            timestamp = "2026-01-01T00:00:00Z",
                            role = SignerRole.CREATOR
                        )
                    )
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking { keyDao.deleteByKeyId(keyId) }
        // Deleting the Keystore alias itself audit-logs, so the audit rows are
        // dropped afterwards to catch both the creation and the deletion row.
        keystoreManager.deleteGeneralKey(keyId)
        runBlocking { auditLogDao.deleteByKeyId(keyId) }

        listOf(plainJpeg, signedJpeg).forEach { file ->
            File(XmpMetadataHelper.getSidecarPath(file.path)).delete()
            file.delete()
        }
        Intents.release()
    }

    // -----------------------------------------------------------------
    // Media selection
    // -----------------------------------------------------------------

    /**
     * Picking an image with no embedded signature names the file and replaces
     * the "pick something" placeholder with the empty-signature message.
     */
    @Test
    fun selectingAnUnsignedImage_reportsThatItCarriesNoSignatures() {
        val scenario = launch()

        pickMedia(scenario, plainJpeg)

        assertShownTextInTree(scenario, plainJpeg.name)
        assertShownTextInTree(scenario, context.getString(R.string.verify_no_signatures))
        awaitTextAbsent(scenario, SIGNATURE_PLACEHOLDER)
    }

    /** A signed image lists its content hash and one line per signature. */
    @Test
    fun selectingASignedImage_listsItsExistingSignatures() {
        val scenario = launch()

        pickMedia(scenario, signedJpeg)

        assertShownTextInTree(scenario, "Hash: ${contentHash.take(HASH_PREVIEW_LENGTH)}...")
        assertShownTextInTree(
            scenario,
            "${SignerRole.CREATOR.name}: $signerName... ($KEY_ALGORITHM)"
        )
    }

    /** Picking a second file replaces the first file's signature rows. */
    @Test
    fun pickingASecondFile_replacesTheDisplayedSignatures() {
        val scenario = launch()
        pickMedia(scenario, signedJpeg)
        assertShownTextInTree(scenario, "Hash: ${contentHash.take(HASH_PREVIEW_LENGTH)}...")

        pickMedia(scenario, plainJpeg)

        assertShownTextInTree(scenario, context.getString(R.string.verify_no_signatures))
        awaitTextAbsent(scenario, "Hash: ${contentHash.take(HASH_PREVIEW_LENGTH)}...")
    }

    // -----------------------------------------------------------------
    // Key selection
    // -----------------------------------------------------------------

    /** The signing-key spinner offers the seeded key with its algorithm. */
    @Test
    fun keySpinner_offersTheSeededSigningKey() {
        val scenario = launch()

        selectSeededKey(scenario)

        assertShownTextInTree(scenario, spinnerLabel())
    }

    // -----------------------------------------------------------------
    // Initiator
    // -----------------------------------------------------------------

    /**
     * With signed media and a key selected, the initiator renders a QR code and
     * records the request in the audit log.
     */
    @Test
    fun generatingTheInitiatorQr_forSignedMedia_rendersTheQrAndLogsIt() {
        val scenario = launch()
        selectSeededKey(scenario)
        pickMedia(scenario, signedJpeg)

        clickClickableWithExactText(scenario, GENERATE_QR)

        assertQrRendered(scenario)
        awaitAuditEntry(AuditOperationType.COSIGN_INITIATED)
    }

    // -----------------------------------------------------------------
    // Witness
    // -----------------------------------------------------------------

    /**
     * A witness scans the owner's request QR, approves the prompt and gets a
     * response QR plus an audit record naming the same content hash.
     */
    @Test
    fun witnessScan_ofARequest_approved_producesAResponseQrAndLogsIt() {
        val scenario = launch()
        selectSeededKey(scenario)
        openWitnessSection(scenario)
        stubScanner(request(contentHash))

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_request))
        assertCoSignScannerLaunched()
        approveInDialog()

        assertShownTextInTree(scenario, context.getString(R.string.cosign_success))
        assertWitnessQrRendered(scenario)
        awaitAuditEntry(AuditOperationType.COSIGN_RECEIVED)
    }

    /**
     * A request whose hash is not hexadecimal is refused before any prompt,
     * and nothing is signed or logged.
     */
    @Test
    fun witnessScan_ofAMalformedRequest_isRefused() {
        val scenario = launch()
        selectSeededKey(scenario)
        openWitnessSection(scenario)
        stubScanner(request(MALFORMED_HASH))

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_request))

        assertShownTextInTree(
            scenario,
            context.getString(R.string.cosign_request_refused, context.getString(R.string.cosign_error_hash))
        )
        assertTrue(
            "A refused co-sign request must not be recorded in the audit log",
            runBlocking {
                auditLogDao.getByOperationType(AuditOperationType.COSIGN_RECEIVED)
                    .none { it.details?.contains(MALFORMED_HASH) == true }
            }
        )
    }

    // -----------------------------------------------------------------
    // Owner: the witness's response
    // -----------------------------------------------------------------

    /** A scanned response is appended to the picked media as an ATTESTOR entry. */
    @Test
    fun ownerScan_ofAResponse_appendsTheAttestorToTheSavedMedia() {
        val scenario = launch()
        pickMedia(scenario, signedJpeg)
        assertShownTextInTree(scenario, "Hash: ${contentHash.take(HASH_PREVIEW_LENGTH)}...")
        stubScanner(response(witnessFingerprint))

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_response))
        assertCoSignScannerLaunched()

        assertShownTextInTree(scenario, context.getString(R.string.cosign_appended, witnessName))
        assertAttestorSaved()
        assertShownTextInTree(scenario, "${SignerRole.ATTESTOR.name}: $witnessName... ($KEY_ALGORITHM)")
    }

    /** A response from a key that already signed is refused; the file is untouched. */
    @Test
    fun ownerScan_ofADuplicateSigner_isRefusedAndTheMediaIsUnchanged() {
        val scenario = launch()
        pickMedia(scenario, signedJpeg)
        assertShownTextInTree(scenario, "Hash: ${contentHash.take(HASH_PREVIEW_LENGTH)}...")
        val before = signedJpeg.readBytes()
        stubScanner(response(creatorFingerprint))

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_response))

        assertShownTextInTree(
            scenario,
            context.getString(R.string.cosign_duplicate_signer, creatorFingerprint.take(16))
        )
        assertTrue("A refused duplicate must leave the media unchanged", before.contentEquals(signedJpeg.readBytes()))
        assertEquals(1, XmpMetadataHelper.readSignature(signedJpeg.path)?.signatures?.size)
    }

    // -----------------------------------------------------------------
    // Camera permission denied in the scanner
    // -----------------------------------------------------------------

    /** Both scan buttons report a camera denial rather than doing nothing. */
    @Test
    fun aCameraDenial_onEitherScan_isReported() {
        val scenario = launch()
        val denied = context.getString(R.string.qr_camera_denied)
        intending(hasComponent(QrScannerActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(QrScannerActivity.RESULT_CAMERA_DENIED, null)
        )

        openWitnessSection(scenario)
        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_request))
        assertShownTextInTree(scenario, denied)

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_initiator_title))
        pickMedia(scenario, signedJpeg)
        assertShownTextInTree(scenario, "Hash: ${contentHash.take(HASH_PREVIEW_LENGTH)}...")
        awaitTextAbsent(scenario, denied)
        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_response))
        assertShownTextInTree(scenario, denied)
    }

    // -----------------------------------------------------------------
    // Recreation while the scanner is open
    // -----------------------------------------------------------------

    /**
     * The activity is recreated while the real scanner is in front; the
     * response then reaches the new instance, which still knows the media.
     */
    @Test
    fun aResponseScan_survivesRecreationWhileTheScannerIsOpen() {
        val scenario = launch()
        pickMedia(scenario, signedJpeg)
        assertShownTextInTree(scenario, "Hash: ${contentHash.take(HASH_PREVIEW_LENGTH)}...")

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_response))
        val scanner = awaitResumedScanner()
        recreateBehindTheScanner(scenario)
        finishScanner(scanner, response(witnessFingerprint))

        assertAttestorSaved()
        assertShownTextInTree(scenario, context.getString(R.string.cosign_appended, witnessName))
    }

    /**
     * The witness side: after recreation behind the scanner, the request still
     * opens the prompt in witness mode with the selected key, and signs.
     */
    @Test
    fun aRequestScan_survivesRecreationWithWitnessModeAndKey() {
        val scenario = launch()
        selectSeededKey(scenario)
        openWitnessSection(scenario)

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_scan_request))
        val scanner = awaitResumedScanner()
        recreateBehindTheScanner(scenario)
        finishScanner(scanner, request(contentHash))

        onView(withText(containsString(spinnerLabel()))).inRoot(isDialog()).check(matches(isDisplayed()))
        approveInDialog()
        assertShownTextInTree(scenario, WITNESS_DESCRIPTION)
        assertShownTextInTree(scenario, context.getString(R.string.cosign_success))
        assertWitnessQrRendered(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers: scanner
    // -----------------------------------------------------------------

    private val creatorFingerprint get() = "fingerprint-$runId"
    private val witnessFingerprint get() = "witness-fingerprint-$runId"
    private val witnessName get() = "UITestWitness$runId"

    private fun request(hash: String): String =
        CoSignRequest(hash, "SHA-256", "owner-fingerprint-$runId").toJsonString()

    private fun response(fingerprint: String): String =
        CoSignResponse(
            signature = "c2lnbmF0dXJl",
            fingerprint = fingerprint,
            signerName = witnessName,
            algorithm = KEY_ALGORITHM
        ).toJsonString()

    /** Stubs [QrScannerActivity] to return [value] as a scan. */
    private fun stubScanner(value: String) {
        intending(hasComponent(QrScannerActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(
                Activity.RESULT_OK,
                Intent().putExtra(QrScannerActivity.EXTRA_SCANNED_URI, value)
            )
        )
    }

    private fun assertCoSignScannerLaunched() {
        intended(
            allOf(
                hasComponent(QrScannerActivity::class.java.name),
                hasExtra(QrScannerActivity.EXTRA_PAYLOAD_KIND, QrPayloadKind.COSIGN.name)
            )
        )
    }

    private fun approveInDialog() {
        onView(withText(R.string.cosign_approve)).inRoot(isDialog()).perform(click())
        waitForIdle()
    }

    /** Polls until the media file itself carries the witness's ATTESTOR entry. */
    private fun assertAttestorSaved() {
        awaitCondition("Expected the saved media to carry the witness's ATTESTOR entry") {
            val saved = XmpMetadataHelper.readSignature(signedJpeg.path)?.signatures.orEmpty()
            saved.size == 2 && saved.any {
                it.role == SignerRole.ATTESTOR && it.keyFingerprint == witnessFingerprint &&
                    it.signerName == witnessName
            }
        }
    }

    /** The real scanner, once it is in front (CAMERA is granted by the rule). */
    private fun awaitResumedScanner(): QrScannerActivity {
        var scanner: QrScannerActivity? = null
        awaitCondition("Expected the QR scanner to come to the front") {
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                scanner = ActivityLifecycleMonitorRegistry.getInstance()
                    .getActivitiesInStage(Stage.RESUMED)
                    .filterIsInstance<QrScannerActivity>()
                    .firstOrNull()
            }
            scanner != null
        }
        return scanner!!
    }

    /**
     * Recreates the stopped [CoSignActivity] behind the scanner, as a
     * configuration change or process-state restore would, and waits for the
     * new instance.
     */
    private fun recreateBehindTheScanner(scenario: ActivityScenario<CoSignActivity>) {
        val old = withActivity(scenario) { it }
        InstrumentationRegistry.getInstrumentation().runOnMainSync { old.recreate() }
        awaitCondition("Expected a new CoSignActivity instance after recreation") {
            var recreated = false
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                val monitor = ActivityLifecycleMonitorRegistry.getInstance()
                recreated = listOf(Stage.CREATED, Stage.STARTED, Stage.STOPPED).any { stage ->
                    monitor.getActivitiesInStage(stage).any { it is CoSignActivity && it !== old }
                }
            }
            recreated
        }
    }

    private fun finishScanner(scanner: QrScannerActivity, value: String) {
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            scanner.setResult(Activity.RESULT_OK, Intent().putExtra(QrScannerActivity.EXTRA_SCANNED_URI, value))
            scanner.finish()
        }
        waitForIdle()
    }

    // -----------------------------------------------------------------
    // Helpers: launching and picking
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<CoSignActivity> =
        ActivityScenario.launch(CoSignActivity::class.java)

    /**
     * Stubs the system picker to return [file] and taps "Select Signed Media".
     *
     * The URI is a `FileProvider` one so the activity's
     * `ContentResolver.getType` call resolves `image/jpeg`; a `file://` URI
     * resolves to null there, which would silently route every image down the
     * "unsigned" path.
     */
    private fun pickMedia(scenario: ActivityScenario<CoSignActivity>, file: File) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(uri))
        )

        clickClickableWithExactText(scenario, context.getString(R.string.cosign_select_media))
        waitForIdle()
    }

    private fun openWitnessSection(scenario: ActivityScenario<CoSignActivity>) {
        clickClickableWithExactText(scenario, context.getString(R.string.cosign_witness_title))
        assertShownTextInTree(scenario, WITNESS_DESCRIPTION)
    }


    // -----------------------------------------------------------------
    // Helpers: key selection
    // -----------------------------------------------------------------

    private fun spinnerLabel(): String = "$keyLabel ($KEY_ALGORITHM)"

    /**
     * Pins the key spinner to the seeded key.
     *
     * The spinner is loaded asynchronously from Room and other suites may leave
     * signing keys behind, so the default selection cannot be assumed to be
     * this suite's key -- and signing with someone else's key would fail for a
     * reason that has nothing to do with the screen.
     */
    private fun selectSeededKey(scenario: ActivityScenario<CoSignActivity>) {
        val label = spinnerLabel()
        awaitCondition("The key spinner should offer and select '$label'") {
            withActivity(scenario) { activity ->
                val spinner = collectViews(activity.window.decorView) { it is Spinner }
                    .firstOrNull() as? Spinner ?: return@withActivity false
                val adapter = spinner.adapter ?: return@withActivity false
                val index = (0 until adapter.count).firstOrNull {
                    adapter.getItem(it)?.toString() == label
                } ?: return@withActivity false
                spinner.setSelection(index)
                spinner.selectedItemPosition == index
            }
        }
    }

    // -----------------------------------------------------------------
    // Helpers: assertions
    // -----------------------------------------------------------------

    /** Asserts some shown [ImageView] now carries a generated bitmap. */
    private fun assertQrRendered(scenario: ActivityScenario<CoSignActivity>) {
        assertTrue(
            "Expected a rendered QR bitmap to be shown",
            awaitActivity(scenario) { activity ->
                collectViews(activity.window.decorView) {
                    it is ImageView && it.isShown && it.drawable is BitmapDrawable
                }.isNotEmpty()
            }
        )
    }

    /** Asserts the witness section's own QR view carries a generated bitmap. */
    private fun assertWitnessQrRendered(scenario: ActivityScenario<CoSignActivity>) {
        assertTrue(
            "Expected the witness response QR to be shown",
            awaitActivity(scenario) { activity ->
                val view = collectViews(activity.window.decorView) {
                    it is ImageView && it.tag == WITNESS_QR_TAG
                }.firstOrNull() as? ImageView
                view != null && view.isShown && view.drawable is BitmapDrawable
            }
        )
    }

    /**
     * Polls for an audit row of [operationType] naming this run's content hash.
     *
     * `AuditLogger` writes on its own IO scope, so the row lands after the UI
     * has already updated.
     */
    private fun awaitAuditEntry(operationType: AuditOperationType) {
        awaitCondition("Expected an audit row of type $operationType for this run's hash") {
            runBlocking {
                auditLogDao.getByOperationType(operationType)
                    .any { it.details?.contains(contentHash) == true }
            }
        }
    }

    // -----------------------------------------------------------------
    // Helpers: fixtures
    // -----------------------------------------------------------------

    /** Writes a small real JPEG so `ExifInterface` has something it can edit. */
    private fun writeJpeg(suffix: String): File {
        val file = File(context.cacheDir, "ui-test-cosign-$suffix-$runId.jpg")
        val bitmap = Bitmap.createBitmap(16, 16, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(Color.rgb(0x11, 0x55, 0x99))
        FileOutputStream(file).use { bitmap.compress(Bitmap.CompressFormat.JPEG, 90, it) }
        bitmap.recycle()
        return file
    }

    private companion object {

        const val KEY_ALGORITHM = "ES256"

        /** Characters of the content hash the signature card previews. */
        const val HASH_PREVIEW_LENGTH = 16

        /** Hardcoded in [CoSignActivity]; not a string resource. */
        const val GENERATE_QR = "Generate Co-Sign QR"
        const val SIGNATURE_PLACEHOLDER = "Select a signed media file to view signatures"
        const val WITNESS_DESCRIPTION =
            "As a witness, you sign someone else's content hash to attest your presence."
        const val WITNESS_QR_TAG = "witnessQr"

        /** 64 characters, none of them hexadecimal digits. */
        const val MALFORMED_HASH = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    }
}
