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
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.widget.ImageButton
import android.widget.Spinner
import androidx.appcompat.widget.Toolbar
import androidx.core.content.FileProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.crypto.FileEncryptor
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.JpegFillBytes
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.SignatureVerifier
import com.automatethethings.xkey.media.SignerRole
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant

/**
 * End-to-end instrumented tests for the four operations [FileOperationActivity]
 * actually performs, as opposed to the form it renders.
 *
 * `FileOperationActivityUiTest` covers launch behaviour, the file-info card and
 * which selector card each operation reveals. This suite drives the buttons:
 * every test shares a real file the test itself creates, picks a real key or
 * contact out of the spinner and presses **Process**, then asserts on the bytes
 * that came out the other end rather than on the toast-like result text alone.
 *
 * The fixtures are genuine:
 * - a P-256 signing key in the Android Keystore, so `performSign` produces a
 *   signature that this test verifies against the exported public key;
 * - a contact whose public key is that same key, so a file encrypted for the
 *   contact can be decrypted again by the key in a single round trip.
 *
 * Three of the four operations hand off to the Storage Access Framework for the
 * output location. Espresso-Intents stubs `ACTION_CREATE_DOCUMENT` and
 * `ACTION_OPEN_DOCUMENT` with a URI for a file in the app's own cache, so the
 * document picker never opens and the test owns the result.
 *
 * Everything created here — Keystore aliases (including the ephemeral ones
 * [FileEncryptor] leaks), `keys`/`contacts` rows, `audit_logs` rows and cache
 * files — is removed in `@After`.
 */
@RunWith(AndroidJUnit4::class)
class FileOperationFlowTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val suffix = System.nanoTime()
    private val signingKeyId = "fileop-flow-$suffix"
    private val signingKeyLabel = "FileOp Flow Key $suffix"
    private val orphanKeyId = "fileop-orphan-$suffix"
    private val orphanKeyLabel = "FileOp Orphan Key $suffix"
    private val contactName = "FileOp Flow Contact $suffix"
    private val contactFingerprint = "fileopflow$suffix"

    /** Only audit rows written after this instant are cleaned up. */
    private val startedAt = System.currentTimeMillis()

    private lateinit var keyDao: KeyDao
    private lateinit var contactDao: ContactDao
    private lateinit var auditLogDao: AuditLogDao
    private lateinit var keystoreManager: KeystoreManager

    private lateinit var publicKeyDer: ByteArray
    private lateinit var jpegFile: File
    private lateinit var textFile: File

    /** Files the tests create, deleted in teardown. */
    private val scratch = mutableListOf<File>()

    /** Ephemeral aliases that already existed, so teardown only removes ours. */
    private var preExistingEphemerals: Set<String> = emptySet()

    @Before
    fun setUp() {
        val db = XKeyDatabase.getInstance(context)
        keyDao = db.keyDao()
        contactDao = db.contactDao()
        auditLogDao = db.auditLogDao()
        keystoreManager = KeystoreManager(context)
        preExistingEphemerals = ephemeralAliases()

        runBlocking {
            publicKeyDer = keystoreManager.generateKeyForAlgorithm(
                keyId = signingKeyId,
                algorithm = "ES256",
                authDurationSeconds = -1,
                preferStrongBox = false
            )
            keyDao.insert(
                KeyEntity(
                    keyId = signingKeyId,
                    keyType = "signing",
                    algorithm = "ES256",
                    label = signingKeyLabel,
                    publicKeyDer = publicKeyDer,
                    keySizeBits = 256,
                    biometricRequired = false,
                    source = "local"
                )
            )
            // The contact holds the very same public key, which is what makes
            // the encrypt -> decrypt round trip in this suite possible.
            contactDao.insert(
                ContactEntity(
                    name = contactName,
                    publicKeyDer = publicKeyDer,
                    publicKeyFingerprint = contactFingerprint,
                    algorithm = CONTACT_ALGORITHM,
                    source = "test"
                )
            )
        }

        jpegFile = jpeg("xkey-fileop-$suffix.jpg")
        textFile = scratchFile("xkey-fileop-$suffix.txt").apply { writeText(TEXT_CONTENT) }

        // Stubs the document picker; must be initialised before any launch.
        Intents.init()
    }

    @After
    fun tearDown() {
        Intents.release()

        // Keystore first: deleting a key is itself audited, so the audit sweep
        // below has to run after it.
        keystoreManager.deleteGeneralKey(signingKeyId)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ephemeralAliases() - preExistingEphemerals).forEach { keyStore.deleteEntry(it) }

        runBlocking {
            keyDao.deleteByKeyId(signingKeyId)
            keyDao.deleteByKeyId(orphanKeyId)
            contactDao.deleteByFingerprint(contactFingerprint)
            auditLogDao.deleteByKeyId(signingKeyId)
            auditLogDao.deleteByKeyId(orphanKeyId)
        }
        sweepAuditRows()

        scratch.forEach { file ->
            File(XmpMetadataHelper.getSidecarPath(file.path)).delete()
            file.delete()
        }
        scratch.clear()
    }

    // -----------------------------------------------------------------
    // Sign
    // -----------------------------------------------------------------

    /**
     * A JPEG can carry its signature in-band, so the sign path writes the
     * signature into the file's EXIF and never asks for an output location.
     */
    @Test
    fun signOperation_embedsTheSignatureInASharedJpeg() {
        val scenario = launch(jpegFile)
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_sign_success))
        val embedded = XmpMetadataHelper.readSignature(jpegFile.path)
        assertNotNull("the signed jpeg should carry embedded signature metadata", embedded)
        val entry = embedded!!.signatures.single()
        assertEquals(signingKeyLabel, entry.signerName)
        assertEquals("ES256", entry.algorithm)
        assertEquals(MediaHasher.hashBytes(publicKeyDer), entry.keyFingerprint)
        assertEquals(SignerRole.CREATOR, entry.role)
    }

    /**
     * The point of the screen: the bytes it produced must verify against the
     * public half of the Keystore key the user picked.
     */
    @Test
    fun signOperation_producesASignatureThatVerifiesAgainstThePublicKey() {
        assertSignOperationVerifies()
    }

    /**
     * #47, Codex review 6661: the same flow on [jpegFile] given `0xFF` fill
     * bytes before an added EXIF APP1 (or before the encoder's first marker)
     * and before a kept table. The written file must still hash to what was
     * signed and the signature must verify. Device only: CI runs no
     * androidTest stage; `XmpMetadataHelperExifFillByteTest` runs the same
     * fixtures through the real ExifInterface 1.4.2 writer in the JVM.
     */
    @Test
    fun signOperation_onAJpegWithFillBytesBeforeApp1AndDqt_verifies() {
        jpegFile.writeBytes(
            JpegFillBytes.fixture(
                JpegFillBytes.withExifApp1(jpegFile.readBytes()), JpegFillBytes.APP1, JpegFillBytes.DQT
            )
        )

        assertSignOperationVerifies()
        JpegFillBytes.assertWellFormed(jpegFile.readBytes())
    }

    /** As above, for a JPEG with no APP1: fill bytes before its first marker and before DHT. */
    @Test
    fun signOperation_onAJpegWithFillBytesBeforeFirstMarkerAndDht_verifies() {
        jpegFile.writeBytes(JpegFillBytes.fixture(jpegFile.readBytes(), null, JpegFillBytes.DHT))

        assertSignOperationVerifies()
        JpegFillBytes.assertWellFormed(jpegFile.readBytes())
    }

    /** Signs [jpegFile] through the screen and checks the result against the public key. */
    private fun assertSignOperationVerifies() {
        // Canonical, not whole-file: signing embeds the signature into the JPEG,
        // so a hash over every byte could never match afterwards. The canonical
        // form excludes the APPn/COM segments that carry the signature.
        val originalHash = MediaHasher.hashCanonical(jpegFile.readBytes(), "image/jpeg")
        val scenario = launch(jpegFile)
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_sign_success))
        val entry = XmpMetadataHelper.readSignature(jpegFile.path)!!.signatures.single()
        assertEquals(
            "the signature must cover the hash of the file as it was shared",
            originalHash,
            XmpMetadataHelper.readSignature(jpegFile.path)!!.contentHash
        )
        // #47: the file as written must still hash to what was signed, or the
        // verify screens reject their own signature. Device only: CI runs no
        // androidTest stage; MediaHasherCanonicalTest carries the JVM proof.
        assertEquals(
            "embedding the signature must not change the canonical hash",
            originalHash,
            MediaHasher.hashCanonical(jpegFile.readBytes(), "image/jpeg")
        )
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(
                KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyDer))
            )
            update(hexToBytes(originalHash))
        }
        assertTrue(
            "the embedded signature must verify against the signing key",
            verifier.verify(android.util.Base64.decode(entry.value, android.util.Base64.NO_WRAP))
        )
    }

    @Test
    fun signOperation_recordsKeyUsageAndWritesAnAuditEntry() {
        val before = runBlocking { keyDao.getByKeyId(signingKeyId)!!.useCount }
        val scenario = launch(jpegFile)
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_sign_success))
        awaitCondition("signing should increment the key's use count") {
            runBlocking { keyDao.getByKeyId(signingKeyId)!!.useCount } == before + 1
        }
        awaitCondition("signing should write a FILE_SIGNED audit entry") {
            runBlocking { auditLogDao.getByKeyId(signingKeyId) }
                .any { it.operationType == AuditOperationType.FILE_SIGNED }
        }
    }

    /**
     * A file that cannot hold embedded metadata falls back to a `.xkeysig`
     * sidecar, which the user is asked to place via the document picker.
     */
    @Test
    fun signOperation_writesASidecarForAFileThatCannotEmbedMetadata() {
        val sidecar = scratchFile("xkey-fileop-sidecar-$suffix.xkeysig")
        stubDocumentPicker(Intent.ACTION_CREATE_DOCUMENT, uriFor(sidecar))
        val scenario = launch(textFile)
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_sign_success))
        awaitCondition("the sidecar should have been written") { sidecar.length() > 0 }
        val cad = ContentAuthenticityData.fromJsonString(sidecar.readText())
        assertEquals(MediaHasher.hashBytes(TEXT_CONTENT.toByteArray()), cad.contentHash)
        assertEquals(signingKeyLabel, cad.signatures.single().signerName)
        assertEquals(
            "the shared file must be left untouched when a sidecar is used",
            TEXT_CONTENT,
            textFile.readText()
        )
    }

    /**
     * The database row survives its Keystore key, so signing has to report the
     * failure instead of crashing the share sheet.
     */
    @Test
    fun signOperation_reportsAnErrorWhenTheKeystoreHasNoSuchKey() {
        insertOrphanKey()
        val scenario = launch(jpegFile)
        selectSpinnerEntry(scenario, orphanEntry)

        process(scenario)

        assertShownTextInTree(scenario, errorPrefix(scenario))
        assertNull(
            "a failed signature must not be embedded",
            XmpMetadataHelper.readSignature(jpegFile.path)
        )
    }

    /** ACTION_SEND_MULTIPLE is accepted, and the operation runs on the first file. */
    @Test
    fun signOperation_operatesOnTheFirstFileOfAMultipleShare() {
        val scenario = launchMultiple(jpegFile, textFile)
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_sign_success))
        assertNotNull(
            "the first shared file should be the one signed",
            XmpMetadataHelper.readSignature(jpegFile.path)
        )
    }

    /** Switching operations clears the previous outcome from the screen. */
    @Test
    fun switchingOperationsHidesThePreviousResult() {
        val scenario = launch(jpegFile)
        selectSpinnerEntry(scenario, keyEntry)
        process(scenario)
        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_sign_success))

        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_encrypt))

        awaitTextAbsent(scenario, string(scenario, R.string.file_operation_sign_success))
    }

    // -----------------------------------------------------------------
    // Verify
    // -----------------------------------------------------------------

    @Test
    fun verifyOperation_reportsAnEmbeddedSignatureFromAKnownContactAsVerified() {
        embedSignature(jpegFile, contactFingerprint, contactName)
        val scenario = launch(jpegFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_verify_success))
        assertShownTextInTree(scenario, "$contactName: Verified")
    }

    /**
     * A signer nobody knows is neither trusted nor a failure: the screen says
     * so explicitly instead of claiming the file is verified.
     */
    @Test
    fun verifyOperation_reportsAnUnrecognisedSignerAsUnknown() {
        val strangerFingerprint = "ff".repeat(32)
        embedSignature(jpegFile, strangerFingerprint, signerName = null)
        val scenario = launch(jpegFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, "Verification complete")
        assertShownTextInTree(scenario, "${strangerFingerprint.take(16)}...: Unknown signer")
    }

    /** A signature made by one of the device's own keys resolves to its label. */
    @Test
    fun verifyOperation_resolvesALocalKeyByItsPublicKeyFingerprint() {
        embedSignature(jpegFile, MediaHasher.hashBytes(publicKeyDer), signerName = null)
        val scenario = launch(jpegFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_verify_success))
        assertShownTextInTree(scenario, "$signingKeyLabel: Verified")
    }

    /**
     * The in-band content hash is checked before any signature: the block a
     * genuine signer put on one image, copied onto different image content,
     * fails even though the signature over the stored hash is valid.
     */
    @Test
    fun verifyOperation_rejectsAnEmbeddedSignatureCopiedOntoDifferentContent() {
        embedSignature(jpegFile, contactFingerprint, contactName)
        val original = launch(jpegFile)
        clickClickableWithExactText(original, string(original, R.string.file_operation_verify))
        process(original)
        assertShownTextInTree(original, string(original, R.string.file_operation_verify_success))
        assertShownTextInTree(original, "$contactName: Verified")
        original.close()

        val other = jpeg("xkey-fileop-copied-$suffix.jpg", Color.rgb(0xCC, 0x22, 0x44))
        XmpMetadataHelper.writeSignature(other.path, XmpMetadataHelper.readSignature(jpegFile.path)!!)
        val scenario = launch(other)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_verify_failed))
        assertShownTextInTree(scenario, "Content hash mismatch: Failed")
        assertShownTextInTree(scenario, "$contactName: Failed")
    }

    /**
     * A copied block from a signer nobody knows fails too: the mismatch is
     * decided before the signer lookup, never shown as an unknown signer.
     */
    @Test
    fun verifyOperation_rejectsACopiedBlockFromAnUnknownSigner() {
        val strangerFingerprint = "ee".repeat(32)
        embedSignature(jpegFile, strangerFingerprint, signerName = null)
        val other = jpeg("xkey-fileop-copied-unknown-$suffix.jpg", Color.rgb(0xCC, 0x22, 0x44))
        XmpMetadataHelper.writeSignature(other.path, XmpMetadataHelper.readSignature(jpegFile.path)!!)
        val scenario = launch(other)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_verify_failed))
        assertShownTextInTree(scenario, "${strangerFingerprint.take(16)}...: Failed")
    }

    /**
     * With nothing embedded, verification asks for the `.xkeysig` sidecar and
     * checks the file's hash against the one the sidecar recorded.
     */
    @Test
    fun verifyOperation_acceptsASidecarWhoseContentHashMatches() {
        val sidecar = writeSidecar(
            "xkey-fileop-good-$suffix.xkeysig",
            contentHash = MediaHasher.hashBytes(TEXT_CONTENT.toByteArray()),
            fingerprint = contactFingerprint,
            signerName = contactName
        )
        stubDocumentPicker(Intent.ACTION_OPEN_DOCUMENT, uriFor(sidecar))
        val scenario = launch(textFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_verify_success))
        assertShownTextInTree(scenario, "$contactName: Verified")
    }

    /** A sidecar written for different content means the file was altered. */
    @Test
    fun verifyOperation_rejectsASidecarWhoseContentHashDoesNotMatch() {
        val sidecar = writeSidecar(
            "xkey-fileop-stale-$suffix.xkeysig",
            contentHash = "00".repeat(32),
            fingerprint = contactFingerprint,
            signerName = contactName
        )
        stubDocumentPicker(Intent.ACTION_OPEN_DOCUMENT, uriFor(sidecar))
        val scenario = launch(textFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_verify_failed))
        assertShownTextInTree(scenario, "Content hash mismatch: Failed")
    }

    @Test
    fun verifyOperation_reportsAnErrorForAnUnreadableSidecar() {
        val sidecar = scratchFile("xkey-fileop-garbage-$suffix.xkeysig")
            .apply { writeText("this is not json") }
        stubDocumentPicker(Intent.ACTION_OPEN_DOCUMENT, uriFor(sidecar))
        val scenario = launch(textFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_verify))

        process(scenario)

        assertShownTextInTree(scenario, errorPrefix(scenario))
    }

    // -----------------------------------------------------------------
    // Encrypt and decrypt
    // -----------------------------------------------------------------

    @Test
    fun encryptOperation_writesAnXkeyencFileForTheSelectedRecipient() {
        val encrypted = scratchFile("xkey-fileop-out-$suffix.xkeyenc")
        stubDocumentPicker(Intent.ACTION_CREATE_DOCUMENT, uriFor(encrypted))
        val scenario = launch(textFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_encrypt))
        selectSpinnerEntry(scenario, contactEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_encrypt_success))
        awaitCondition("the encrypted file should have been written") { encrypted.length() > 0 }
        val bytes = encrypted.readBytes()
        assertEquals("xkeyenc version byte", 0x01.toByte(), bytes[0])
        assertFalse(
            "the plaintext must not survive into the output",
            String(bytes, Charsets.ISO_8859_1).contains(TEXT_CONTENT)
        )
    }

    @Test
    fun encryptOperation_auditsTheRecipientFingerprint() {
        val encrypted = scratchFile("xkey-fileop-audit-$suffix.xkeyenc")
        stubDocumentPicker(Intent.ACTION_CREATE_DOCUMENT, uriFor(encrypted))
        val scenario = launch(textFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_encrypt))
        selectSpinnerEntry(scenario, contactEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_encrypt_success))
        awaitCondition("encryption should be audited against the recipient") {
            runBlocking { auditLogDao.getByOperationType(AuditOperationType.FILE_ENCRYPTED) }
                .any { it.details?.contains(contactFingerprint) == true }
        }
    }

    /**
     * The whole round trip: a file encrypted to the contact's public key is
     * recovered by the Keystore key that owns it, through the UI both ways.
     */
    @Test
    fun decryptOperation_recoversAFileEncryptedForTheSelectedKey() {
        val encrypted = scratchFile("xkey-fileop-round-$suffix.xkeyenc")
        runBlocking {
            FileOutputStream(encrypted).use { output ->
                FileEncryptor(keystoreManager).encryptForRecipient(
                    publicKeyDer,
                    ByteArrayInputStream(TEXT_CONTENT.toByteArray()),
                    output
                )
            }
        }
        val recovered = scratchFile("xkey-fileop-round-$suffix.out")
        stubDocumentPicker(Intent.ACTION_CREATE_DOCUMENT, uriFor(recovered))

        val scenario = launch(encrypted)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_decrypt))
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_decrypt_success))
        awaitCondition("the decrypted file should have been written") { recovered.length() > 0 }
        assertEquals(TEXT_CONTENT, recovered.readText())
    }

    @Test
    fun decryptOperation_recordsKeyUsageAndWritesAnAuditEntry() {
        val encrypted = scratchFile("xkey-fileop-used-$suffix.xkeyenc")
        runBlocking {
            FileOutputStream(encrypted).use { output ->
                FileEncryptor(keystoreManager).encryptForRecipient(
                    publicKeyDer,
                    ByteArrayInputStream(TEXT_CONTENT.toByteArray()),
                    output
                )
            }
        }
        val before = runBlocking { keyDao.getByKeyId(signingKeyId)!!.useCount }
        stubDocumentPicker(
            Intent.ACTION_CREATE_DOCUMENT,
            uriFor(scratchFile("xkey-fileop-used-$suffix.out"))
        )

        val scenario = launch(encrypted)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_decrypt))
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_decrypt_success))
        awaitCondition("decrypting should increment the key's use count") {
            runBlocking { keyDao.getByKeyId(signingKeyId)!!.useCount } == before + 1
        }
        awaitCondition("decrypting should write a FILE_DECRYPTED audit entry") {
            runBlocking { auditLogDao.getByKeyId(signingKeyId) }
                .any { it.operationType == AuditOperationType.FILE_DECRYPTED }
        }
    }

    /** A file that was never encrypted must be refused, not silently copied. */
    @Test
    fun decryptOperation_reportsAnErrorForAFileThatIsNotEncrypted() {
        val scenario = launch(textFile)
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_decrypt))
        selectSpinnerEntry(scenario, keyEntry)

        process(scenario)

        assertShownTextInTree(scenario, errorPrefix(scenario))
    }

    // -----------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------

    /** The toolbar's up affordance dismisses the share target. */
    @Test
    fun upNavigation_finishesTheScreen() {
        val scenario = launch(jpegFile)
        assertShownTextInTree(scenario, string(scenario, R.string.file_operation_title))

        clickToolbarNavigation(scenario)

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    private val keyEntry: String get() = "$signingKeyLabel (ES256)"
    private val orphanEntry: String get() = "$orphanKeyLabel (ES256)"
    private val contactEntry: String get() = "$contactName ($CONTACT_ALGORITHM)"

    private fun insertOrphanKey() {
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = orphanKeyId,
                    keyType = "signing",
                    algorithm = "ES256",
                    label = orphanKeyLabel,
                    keySizeBits = 256,
                    biometricRequired = false,
                    source = "local"
                )
            )
        }
    }

    /** Writes a small real JPEG so `ExifInterface` has something it can edit. */
    private fun jpeg(name: String, color: Int = Color.rgb(0x11, 0x55, 0x99)): File {
        val file = scratchFile(name)
        val bitmap = Bitmap.createBitmap(24, 24, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(color)
        FileOutputStream(file).use { bitmap.compress(Bitmap.CompressFormat.JPEG, 90, it) }
        bitmap.recycle()
        return file
    }

    private fun scratchFile(name: String): File =
        File(context.cacheDir, name).also { scratch.add(it) }

    /**
     * Embeds signature metadata into [file] the way a signed photo carries it:
     * an in-band block records the canonical hash, the only one Verify accepts.
     */
    private fun embedSignature(file: File, fingerprint: String, signerName: String?) {
        val contentHash = MediaHasher.hashCanonical(file.readBytes(), "image/jpeg")
        XmpMetadataHelper.writeSignature(
            file.path,
            ContentAuthenticityData(
                contentHash = contentHash,
                signatures = listOf(signatureEntry(fingerprint, signerName, contentHash))
            )
        )
    }

    private fun writeSidecar(
        name: String,
        contentHash: String,
        fingerprint: String,
        signerName: String?
    ): File = scratchFile(name).apply {
        writeText(
            ContentAuthenticityData(
                contentHash = contentHash,
                signatures = listOf(signatureEntry(fingerprint, signerName, contentHash))
            ).toJsonString()
        )
    }

    /**
     * A genuine signature over [contentHash], produced by the same Keystore key
     * whose public half backs both the seeded contact and the local key row.
     * A placeholder would now be rejected: the screen verifies the bytes.
     */
    private fun signatureEntry(
        fingerprint: String,
        signerName: String?,
        contentHash: String
    ): SignatureEntry {
        val signature = runBlocking {
            keystoreManager.signWithoutBiometric(
                signingKeyId,
                SignatureVerifier.hexToBytes(contentHash)
            )
        }
        return SignatureEntry(
            keyFingerprint = fingerprint,
            signerName = signerName,
            algorithm = "ES256",
            value = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
            timestamp = Instant.now().toString(),
            role = SignerRole.CREATOR
        )
    }

    // -----------------------------------------------------------------
    // Launching and driving
    // -----------------------------------------------------------------

    private fun launch(file: File): ActivityScenario<FileOperationActivity> {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "*/*"
            putExtra(Intent.EXTRA_STREAM, uriFor(file))
            setClass(context, FileOperationActivity::class.java)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return ActivityScenario.launch(intent)
    }

    private fun launchMultiple(vararg files: File): ActivityScenario<FileOperationActivity> {
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = "*/*"
            putParcelableArrayListExtra(
                Intent.EXTRA_STREAM,
                ArrayList(files.map { uriFor(it) })
            )
            setClass(context, FileOperationActivity::class.java)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return ActivityScenario.launch(intent)
    }

    private fun uriFor(file: File): Uri =
        FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)

    /**
     * Answers the Storage Access Framework request [action] with [uri].
     *
     * Sign (sidecar), encrypt and decrypt all end in a document picker; stubbing
     * it keeps the test hermetic and gives the assertions a file they can read.
     */
    private fun stubDocumentPicker(action: String, uri: Uri) {
        Intents.intending(hasAction(action)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(uri))
        )
    }

    private fun process(scenario: ActivityScenario<FileOperationActivity>) {
        clickClickableWithExactText(scenario, string(scenario, R.string.file_operation_process))
    }

    /**
     * Selects the spinner entry reading exactly [entry].
     *
     * The spinners have no ids and the adapter is filled from a Room query, so
     * this polls until the entry exists (which also proves the load finished),
     * then selects it and checks the selection stuck. Always switch operation
     * first: changing operation rebuilds the key adapter and resets it to 0.
     */
    private fun selectSpinnerEntry(
        scenario: ActivityScenario<FileOperationActivity>,
        entry: String
    ) {
        val selected = awaitActivity(scenario) { activity ->
            val spinners = collectViews(activity.window.decorView) { it is Spinner }
            spinners.any { view ->
                val spinner = view as Spinner
                val adapter = spinner.adapter ?: return@any false
                val position = (0 until adapter.count).firstOrNull { adapter.getItem(it) == entry }
                    ?: return@any false
                if (spinner.selectedItemPosition != position) spinner.setSelection(position)
                spinner.selectedItem == entry
            }
        }
        assertTrue("Expected '$entry' to be selectable in a spinner", selected)
        waitForIdle()
    }

    /**
     * Clicks the toolbar's navigation button.
     *
     * `setSupportActionBar` installs the up affordance as the toolbar's only
     * [ImageButton]; clicking it dispatches `android.R.id.home` to
     * `onOptionsItemSelected`.
     */
    private fun clickToolbarNavigation(scenario: ActivityScenario<FileOperationActivity>) {
        scenario.onActivity { activity ->
            val toolbar = collectViews(activity.window.decorView) { it is Toolbar }.firstOrNull()
            val navigation = collectViews(toolbar) { it is ImageButton }.firstOrNull()
            assertNotNull("the toolbar should expose an up button", navigation)
            navigation!!.performClick()
        }
        waitForIdle()
    }

    private fun string(
        scenario: ActivityScenario<FileOperationActivity>,
        resId: Int
    ): String = withActivity(scenario) { it.getString(resId) }

    /** The invariant part of the error result, without the exception text. */
    private fun errorPrefix(scenario: ActivityScenario<FileOperationActivity>): String =
        withActivity(scenario) { it.getString(R.string.file_operation_error, "") }.trim()

    private fun hexToBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ephemeralAliases(): Set<String> =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            .aliases().toList()
            .filter { it.startsWith("xkey_key_ephemeral_") }
            .toSet()

    /**
     * Removes every audit row this test method produced.
     *
     * `AuditLogDao` can only delete by key id, and encryption and verification
     * are logged without one, so the sweep goes through the support database and
     * is bounded by the time the test started. Key rows are included because
     * encrypting mints (and leaks) an ephemeral key under an id nothing here
     * knows in advance.
     *
     * [AuditLogger][com.automatethethings.xkey.audit.AuditLogger] writes on a
     * background dispatcher, so the sweep runs twice with a short gap to catch
     * a row that lands while teardown is running.
     */
    private fun sweepAuditRows() {
        repeat(2) { attempt ->
            if (attempt > 0) Thread.sleep(AUDIT_SETTLE_MS)
            XKeyDatabase.getInstance(context).openHelper.writableDatabase.execSQL(
                "DELETE FROM audit_logs WHERE timestamp >= ? AND operation_type IN " +
                    "('FILE_SIGNED', 'FILE_VERIFIED', 'FILE_ENCRYPTED', 'FILE_DECRYPTED', " +
                    "'KEY_CREATED', 'KEY_DELETED')",
                arrayOf<Any>(startedAt)
            )
        }
    }

    private companion object {
        const val TEXT_CONTENT = "xkey file operation flow payload"
        const val CONTACT_ALGORITHM = "EC P-256"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** Gap between the two audit sweeps in teardown. */
        const val AUDIT_SETTLE_MS = 150L
    }
}
