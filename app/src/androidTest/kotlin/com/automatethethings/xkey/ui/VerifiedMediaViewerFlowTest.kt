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
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.util.Base64
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import androidx.core.content.FileProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.SignatureEntry
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Instrumented tests for the verification overlay of [VerifiedMediaViewerActivity].
 *
 * `VerifiedMediaViewerActivityUiTest` covers launch behaviour and the unsigned
 * path, where the screen settles on the "no signatures" placeholder. Everything
 * interesting happens on the other branch: this suite feeds the screen media
 * that *does* carry signature metadata and asserts the badge each signer gets —
 * green/verified, yellow/unknown, red/failed — plus the signer count, the
 * timestamp formatting and the video branch.
 *
 * Signatures are real. The suite generates a P-256 key pair with plain JCA (the
 * emulator has no biometric, so nothing here may touch an auth-bound Keystore
 * key), stores its public half as a contact, and signs the media's content hash
 * with the private half so the activity's cryptographic check has something
 * genuine to succeed against.
 *
 * Two fixture details follow production behaviour that is arguably wrong; both
 * are called out on the tests that rely on them:
 * - sidecar metadata is read next to the activity's own temp copy, so the
 *   fixture is planted at `cacheDir/verify_temp.<ext>.xkeysig`;
 * - embedding a signature changes the file, so a file signed the way
 *   `FileOperationActivity` signs it can never satisfy the hash check here.
 *
 * All rows, keys and files are per-run and removed in `@After`.
 */
@RunWith(AndroidJUnit4::class)
class VerifiedMediaViewerFlowTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val suffix = System.nanoTime()
    private val contactName = "Media Flow Signer $suffix"
    private val contactFingerprint = "mediaflow$suffix"
    private val associatedKeyId = "media-flow-assoc-$suffix"
    private val associatedKeyLabel = "Media Flow Assoc Key $suffix"

    /** Only audit rows written after this instant are cleaned up. */
    private val startedAt = System.currentTimeMillis()

    private lateinit var contactDao: ContactDao
    private lateinit var keyDao: KeyDao
    private lateinit var auditLogDao: AuditLogDao
    private lateinit var signerKeyPair: KeyPair

    private lateinit var pngFile: File
    private lateinit var jpegFile: File

    /** Files the tests create, deleted in teardown. */
    private val scratch = mutableListOf<File>()

    @Before
    fun setUp() {
        val db = XKeyDatabase.getInstance(context)
        contactDao = db.contactDao()
        keyDao = db.keyDao()
        auditLogDao = db.auditLogDao()

        signerKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        runBlocking {
            contactDao.insert(
                ContactEntity(
                    name = contactName,
                    publicKeyDer = signerKeyPair.public.encoded,
                    publicKeyFingerprint = contactFingerprint,
                    algorithm = "EC P-256",
                    source = "test"
                )
            )
        }

        clearPlantedSidecars()
        pngFile = png("xkey-media-flow-$suffix.png")
        jpegFile = jpeg("xkey-media-flow-$suffix.jpg")
    }

    @After
    fun tearDown() {
        runBlocking {
            contactDao.deleteByFingerprint(contactFingerprint)
            keyDao.deleteByKeyId(associatedKeyId)
        }
        deleteVerificationAuditRows()

        clearPlantedSidecars()
        scratch.forEach { file ->
            File(XmpMetadataHelper.getSidecarPath(file.path)).delete()
            file.delete()
        }
        scratch.clear()
    }

    // -----------------------------------------------------------------
    // Verified
    // -----------------------------------------------------------------

    /**
     * A signature made by a known contact over the file's real content hash is
     * cryptographically checked and reported as verified.
     *
     * The metadata is planted at the temp path the activity actually reads:
     * `readSignatureViaTempFile` copies the media to `cacheDir/verify_temp.png`
     * and looks for the sidecar beside *that*, not beside the source file.
     */
    @Test
    fun aValidSignatureFromAKnownContactIsShownAsVerified() {
        plantSidecar(pngFile, PNG_EXTENSION, signedEntry(pngFile))

        val scenario = launchView(pngFile, "image/png")

        assertSignerCount(scenario, 1)
        assertSignerRow(scenario, contactName, VERIFIED_GLYPH)
        assertShownTextInTree(scenario, SignerRole.CREATOR.name)
        awaitCondition("opening signed media should be audited as a verification") {
            runBlocking { auditLogDao.getByOperationType(AuditOperationType.FILE_VERIFIED) }
                .any { it.timestamp >= startedAt && it.success }
        }
    }

    /**
     * A key the device owns but has no public key material for cannot be
     * checked cryptographically, so it is trusted by association.
     */
    @Test
    fun aLocalKeyWithoutPublicKeyMaterialIsTrustedByAssociation() {
        runBlocking {
            keyDao.insert(
                KeyEntity(
                    keyId = associatedKeyId,
                    keyType = "signing",
                    algorithm = "ES256",
                    label = associatedKeyLabel,
                    publicKeyDer = null,
                    keySizeBits = 256,
                    biometricRequired = false,
                    source = "local"
                )
            )
        }
        embedSignature(jpegFile, entry(fingerprint = associatedKeyId, signerName = null))

        val scenario = launchView(jpegFile, "image/jpeg")

        assertSignerCount(scenario, 1)
        assertSignerRow(scenario, associatedKeyLabel, VERIFIED_GLYPH)
    }

    // -----------------------------------------------------------------
    // Unknown
    // -----------------------------------------------------------------

    /** A signer in neither the contacts nor the key store is flagged, not trusted. */
    @Test
    fun anUnrecognisedSignerIsShownAsUnknown() {
        val stranger = "ab".repeat(32)
        embedSignature(jpegFile, entry(fingerprint = stranger, signerName = null))

        val scenario = launchView(jpegFile, "image/jpeg")

        assertSignerCount(scenario, 1)
        assertSignerRow(scenario, "${stranger.take(16)}...", UNKNOWN_GLYPH)
    }

    // -----------------------------------------------------------------
    // Failed
    // -----------------------------------------------------------------

    /** Signature bytes that are not even Base64 cannot verify. */
    @Test
    fun anUndecodableSignatureIsShownAsFailed() {
        plantSidecar(
            pngFile,
            PNG_EXTENSION,
            entry(
                fingerprint = contactFingerprint,
                signerName = contactName,
                value = "!!! not base64 !!!"
            ),
            contentHash = MediaHasher.hashBytes(pngFile.readBytes())
        )

        val scenario = launchView(pngFile, "image/png")

        assertSignerRow(scenario, contactName, FAILED_GLYPH)
    }

    /** An algorithm the verifier does not implement is a failure, not a pass. */
    @Test
    fun anUnsupportedSignatureAlgorithmIsShownAsFailed() {
        plantSidecar(
            pngFile,
            PNG_EXTENSION,
            signedEntry(pngFile).copy(algorithm = "Ed25519"),
            contentHash = MediaHasher.hashBytes(pngFile.readBytes())
        )

        val scenario = launchView(pngFile, "image/png")

        assertSignerRow(scenario, contactName, FAILED_GLYPH)
    }

    /**
     * Content that changed after it was signed must not verify.
     *
     * This is also what a file signed by `FileOperationActivity` looks like:
     * that screen hashes the file, then embeds the signature into it, which
     * changes the very bytes the hash covered. Anything signed in-band by xKey
     * therefore lands on this branch when it is opened here.
     */
    @Test
    fun contentThatChangedAfterSigningIsShownAsFailed() {
        val hashBeforeEmbedding = MediaHasher.hashBytes(jpegFile.readBytes())
        embedSignature(
            jpegFile,
            signedEntry(jpegFile),
            contentHash = hashBeforeEmbedding
        )

        val scenario = launchView(jpegFile, "image/jpeg")

        assertSignerRow(scenario, contactName, FAILED_GLYPH)
    }

    // -----------------------------------------------------------------
    // Multiple signers and timestamps
    // -----------------------------------------------------------------

    @Test
    fun everySignerGetsItsOwnRow() {
        val stranger = "cd".repeat(32)
        plantSidecar(
            pngFile,
            PNG_EXTENSION,
            listOf(
                signedEntry(pngFile),
                entry(fingerprint = stranger, signerName = "Second Signer $suffix")
            ),
            contentHash = MediaHasher.hashBytes(pngFile.readBytes())
        )

        val scenario = launchView(pngFile, "image/png")

        assertSignerCount(scenario, 2)
        assertSignerRow(scenario, contactName, VERIFIED_GLYPH)
        assertSignerRow(scenario, "Second Signer $suffix", UNKNOWN_GLYPH)
    }

    /** Timestamps recorded as epoch milliseconds are rendered as a date. */
    @Test
    fun anEpochMillisTimestampIsRenderedAsADate() {
        val millis = 1_767_225_600_000L
        plantSidecar(
            pngFile,
            PNG_EXTENSION,
            signedEntry(pngFile).copy(timestamp = millis.toString()),
            contentHash = MediaHasher.hashBytes(pngFile.readBytes())
        )

        val scenario = launchView(pngFile, "image/png")

        val expected = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
            .format(Date(millis))
        assertSignerRow(scenario, contactName, VERIFIED_GLYPH)
        assertShownTextInTree(scenario, expected)
    }

    /** A timestamp in no recognised format is shown verbatim rather than dropped. */
    @Test
    fun anUnparseableTimestampIsShownVerbatim() {
        val stamp = "whenever-$suffix"
        plantSidecar(
            pngFile,
            PNG_EXTENSION,
            signedEntry(pngFile).copy(timestamp = stamp),
            contentHash = MediaHasher.hashBytes(pngFile.readBytes())
        )

        val scenario = launchView(pngFile, "image/png")

        assertSignerRow(scenario, contactName, VERIFIED_GLYPH)
        assertShownTextInTree(scenario, stamp)
    }

    // -----------------------------------------------------------------
    // Media branches
    // -----------------------------------------------------------------

    /**
     * Video swaps the still image for the Media3 player.
     *
     * The fixture is not decodable, so this covers the player's setup and
     * teardown rather than playback; ExoPlayer reports decode failures to its
     * listeners instead of throwing, so the screen stays up either way.
     */
    @Test
    fun videoMedia_showsThePlayerAndHidesTheImage() {
        val video = scratchFile("xkey-media-flow-$suffix.mp4").apply {
            writeBytes(ByteArray(64) { it.toByte() })
        }

        val scenario = launchView(video, "video/mp4")

        assertTrue(
            "the player should become visible for video media",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.playerView).visibility == View.VISIBLE
            }
        )
        assertEquals(
            View.GONE,
            withActivity(scenario) { it.findViewById<View>(R.id.imageView).visibility }
        )
    }

    /** Video signatures come from a sidecar, since no EXIF can carry them. */
    @Test
    fun videoMedia_readsItsSignatureFromTheSidecar() {
        val video = scratchFile("xkey-media-flow-sig-$suffix.mp4").apply {
            writeBytes(ByteArray(64) { (it * 3).toByte() })
        }
        plantSidecar(video, MP4_EXTENSION, signedEntry(video))

        val scenario = launchView(video, "video/mp4")

        assertSignerCount(scenario, 1)
        assertSignerRow(scenario, contactName, VERIFIED_GLYPH)
    }

    /**
     * Anything that is not video takes the image branch, even when it cannot be
     * decoded: the view is shown empty rather than the screen being torn down.
     */
    @Test
    fun undecodableMedia_showsAnEmptyImageViewAndNoSignatures() {
        val binary = scratchFile("xkey-media-flow-$suffix.bin").apply {
            writeText("definitely not an image")
        }

        val scenario = launchView(binary, "application/octet-stream")

        assertTrue(
            "the image branch should still be selected",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.imageView).visibility == View.VISIBLE
            }
        )
        assertTrue(
            "unsigned media should reveal the placeholder",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.textNoSignatures).visibility == View.VISIBLE
            }
        )
        assertNull(
            "no bitmap can be decoded from a text file",
            withActivity(scenario) { it.findViewById<ImageView>(R.id.imageView).drawable }
        )
    }

    // -----------------------------------------------------------------
    // Assertions
    // -----------------------------------------------------------------

    private fun assertSignerCount(
        scenario: ActivityScenario<VerifiedMediaViewerActivity>,
        count: Int
    ) {
        val expected = withActivity(scenario) {
            it.getString(R.string.verified_viewer_signers, count)
        }
        assertShownTextInTree(scenario, expected)
        assertEquals(
            "the signer list should be showing",
            View.VISIBLE,
            withActivity(scenario) { it.findViewById<View>(R.id.signerListContainer).visibility }
        )
    }

    /**
     * Asserts that one row of the signer list carries both [signerName] and the
     * status [glyph].
     *
     * Matching per row matters: the status glyph is a separate `TextView` from
     * the name, so a tree-wide search could pair a name from one row with a
     * glyph from another.
     */
    private fun assertSignerRow(
        scenario: ActivityScenario<VerifiedMediaViewerActivity>,
        signerName: String,
        glyph: String
    ) {
        assertTrue(
            "Expected a signer row reading '$signerName' with status '$glyph'",
            awaitActivity(scenario) { activity ->
                val container = activity.findViewById<ViewGroup>(R.id.signerListContainer)
                container.visibility == View.VISIBLE &&
                    (0 until container.childCount).any { index ->
                        val row = container.getChildAt(index)
                        findShownTextView(row, signerName) != null &&
                            findShownTextView(row, glyph) != null
                    }
            }
        )
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    private fun entry(
        fingerprint: String,
        signerName: String?,
        value: String = "c2lnbmF0dXJl",
        algorithm: String = "ES256"
    ) = SignatureEntry(
        keyFingerprint = fingerprint,
        signerName = signerName,
        algorithm = algorithm,
        value = value,
        timestamp = "2026-01-01T00:00:00Z",
        role = SignerRole.CREATOR
    )

    /** A signature entry genuinely produced over [file]'s current content hash. */
    private fun signedEntry(file: File): SignatureEntry {
        val contentHash = MediaHasher.hashBytes(file.readBytes())
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(signerKeyPair.private)
            update(hexToBytes(contentHash))
        }.sign()
        return entry(
            fingerprint = contactFingerprint,
            signerName = contactName,
            value = Base64.encodeToString(signature, Base64.NO_WRAP)
        )
    }

    /** Embeds signature metadata in a JPEG's EXIF, the way a signed photo carries it. */
    private fun embedSignature(
        file: File,
        entry: SignatureEntry,
        contentHash: String = MediaHasher.hashBytes(file.readBytes())
    ) {
        XmpMetadataHelper.writeSignature(
            file.path,
            ContentAuthenticityData(contentHash = contentHash, signatures = listOf(entry))
        )
    }

    /**
     * Writes sidecar metadata where the activity looks for it.
     *
     * `readSignatureViaTempFile` copies the media to a fixed `verify_temp`
     * name in the cache directory and resolves the sidecar next to the copy, so
     * the sidecar belonging to the real file is never consulted.
     */
    private fun plantSidecar(
        file: File,
        extension: String,
        entry: SignatureEntry,
        contentHash: String = MediaHasher.hashBytes(file.readBytes())
    ) {
        plantSidecar(file, extension, listOf(entry), contentHash)
    }

    private fun plantSidecar(
        file: File,
        extension: String,
        entries: List<SignatureEntry>,
        contentHash: String = MediaHasher.hashBytes(file.readBytes())
    ) {
        File(context.cacheDir, "$TEMP_BASE$extension.xkeysig").writeText(
            ContentAuthenticityData(contentHash = contentHash, signatures = entries).toJsonString()
        )
    }

    private fun clearPlantedSidecars() {
        context.cacheDir.listFiles()
            ?.filter { it.name.startsWith(TEMP_BASE) }
            ?.forEach { it.delete() }
    }

    private fun png(name: String): File {
        val file = scratchFile(name)
        val bitmap = Bitmap.createBitmap(24, 24, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(Color.rgb(0x22, 0x44, 0x88))
        FileOutputStream(file).use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
        return file
    }

    private fun jpeg(name: String): File {
        val file = scratchFile(name)
        val bitmap = Bitmap.createBitmap(24, 24, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(Color.rgb(0x99, 0x33, 0x11))
        FileOutputStream(file).use { bitmap.compress(Bitmap.CompressFormat.JPEG, 90, it) }
        bitmap.recycle()
        return file
    }

    private fun scratchFile(name: String): File =
        File(context.cacheDir, name).also { scratch.add(it) }

    private fun launchView(
        file: File,
        mimeType: String
    ): ActivityScenario<VerifiedMediaViewerActivity> {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uriFor(file), mimeType)
            setClass(context, VerifiedMediaViewerActivity::class.java)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return ActivityScenario.launch(intent)
    }

    private fun uriFor(file: File): Uri =
        FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)

    private fun hexToBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /**
     * Removes the verification audit rows this test method produced.
     *
     * `logFileVerified` records no key id, so `AuditLogDao.deleteByKeyId` cannot
     * reach these rows and the sweep goes through the support database, bounded
     * by the time the test started. The logger writes on a background
     * dispatcher, so the sweep runs twice with a short gap to catch a row that
     * lands while teardown is running.
     */
    private fun deleteVerificationAuditRows() {
        repeat(2) { attempt ->
            if (attempt > 0) Thread.sleep(AUDIT_SETTLE_MS)
            XKeyDatabase.getInstance(context).openHelper.writableDatabase.execSQL(
                "DELETE FROM audit_logs WHERE timestamp >= ? AND operation_type = 'FILE_VERIFIED'",
                arrayOf<Any>(startedAt)
            )
        }
    }

    private companion object {
        /** Fixed name the activity gives its temp copy while reading a sidecar. */
        const val TEMP_BASE = "verify_temp"
        const val PNG_EXTENSION = ".png"
        const val MP4_EXTENSION = ".mp4"

        const val VERIFIED_GLYPH = "✓"
        const val UNKNOWN_GLYPH = "?"
        const val FAILED_GLYPH = "✗"

        /** Gap between the two audit sweeps in teardown. */
        const val AUDIT_SETTLE_MS = 150L
    }
}
