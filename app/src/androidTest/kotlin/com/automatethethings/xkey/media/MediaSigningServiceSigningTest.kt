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
package com.automatethethings.xkey.media

import android.Manifest
import android.app.NotificationManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.SystemClock
import android.provider.MediaStore
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.MediaSigningSettingsData
import com.automatethethings.xkey.settings.MediaSigningSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.ui.MainActivity
import java.io.File
import java.io.RandomAccessFile
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * [MediaSigningService] actually signing something.
 *
 * The existing suite proves every way the service *declines* a capture and
 * stops there on purpose: the success path needs a real MediaStore row, a real
 * Keystore key and a file the app may rewrite. That leaves the entire signing
 * job — hash, sign, fingerprint, resolve the file path, write the metadata,
 * audit — with no coverage at all, which is the half a user would actually
 * notice being broken.
 *
 * So this suite provides all three. The capture is a genuine JPEG inserted into
 * MediaStore by the test process, which makes the app its owner and therefore
 * allowed to rewrite it in place; the signing key is a real non-authenticating
 * ES256 Keystore key with the Room row the service looks up.
 *
 * The assertion is deliberately end to end and cryptographic: the signature
 * left in the photo's own EXIF is verified against the key's public DER over
 * the content hash recorded beside it. Anything less — an audit row, a
 * non-empty field — would pass just as happily if the service signed the wrong
 * bytes with the wrong key.
 *
 * Cleanup: the MediaStore row and its file, the Keystore alias, the Room key
 * row, every audit row naming that key, and the media-signing settings are all
 * restored. The notification channel is left in place; it is app-owned and
 * permanent by design.
 */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = Build.VERSION_CODES.Q)
class MediaSigningServiceSigningTest {

    @get:Rule
    val permissions: GrantPermissionRule = GrantPermissionRule.grant(
        Manifest.permission.POST_NOTIFICATIONS,
        Manifest.permission.READ_MEDIA_IMAGES
    )

    private lateinit var context: Context
    private lateinit var notificationManager: NotificationManager
    private lateinit var settings: MediaSigningSettingsRepository
    private lateinit var keystoreManager: KeystoreManager

    private lateinit var keyId: String
    private lateinit var keyLabel: String
    private lateinit var publicKeyDer: ByteArray

    private var mediaUri: Uri? = null
    private var mediaPath: String? = null
    private var originalSettings: MediaSigningSettingsData? = null
    private var activity: ActivityScenario<MainActivity>? = null

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        notificationManager = context.getSystemService(NotificationManager::class.java)
        settings = MediaSigningSettingsRepository(context)
        keystoreManager = KeystoreManager(context)

        val stamp = System.nanoTime()
        keyId = "media-autosign-$stamp"
        keyLabel = "Media Auto Sign $stamp"

        runBlocking {
            originalSettings = settings.getSettings()
            settings.updateSettings(MediaSigningSettingsData())

            publicKeyDer = keystoreManager.generateKeyForAlgorithm(
                keyId = keyId,
                algorithm = ALGORITHM,
                authDurationSeconds = -1,
                preferStrongBox = false
            )
            XKeyDatabase.getInstance(context).keyDao().insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = "signing",
                    algorithm = ALGORITHM,
                    label = keyLabel,
                    publicKeyDer = publicKeyDer,
                    keySizeBits = 256,
                    biometricRequired = false,
                    source = "local"
                )
            )
        }

        insertCapture(stamp)

        // A foreground-service start is only permitted while the app is visible.
        activity = ActivityScenario.launch(MainActivity::class.java)
    }

    @After
    fun tearDown() {
        context.stopService(Intent(context, MediaSigningService::class.java))
        awaitNotificationGone()

        mediaUri?.let { uri -> runCatching { context.contentResolver.delete(uri, null, null) } }
        mediaPath?.let { path ->
            runCatching { File(XmpMetadataHelper.getSidecarPath(path)).delete() }
            runCatching { File(path).delete() }
        }
        mediaUri = null
        mediaPath = null

        // The Keystore delete is itself audited, so it has to happen before the
        // audit sweep below.
        runCatching { keystoreManager.deleteGeneralKey(keyId) }
        runBlocking {
            XKeyDatabase.getInstance(context).keyDao().deleteByKeyId(keyId)
            XKeyDatabase.getInstance(context).auditLogDao().deleteByKeyId(keyId)
            settings.updateSettings(originalSettings ?: MediaSigningSettingsData())
        }
        originalSettings = null

        activity?.close()
        activity = null
    }

    // -------------------------------------------------------------------------
    // The signing path
    // -------------------------------------------------------------------------

    /**
     * A capture is hashed, signed with the configured key and the signature
     * written into the photo's own metadata — verifiably so.
     */
    @Test
    fun aNewPhotoIsSignedIntoItsOwnMetadata() {
        val uri = mediaUri!!
        val path = mediaPath!!
        configure(autoSignEnabled = true, signPhotos = true)
        startService()

        context.contentResolver.notifyChange(uri, null)

        val signed = awaitSignature(path)
        assertEquals("one signature per capture", 1, signed.signatures.size)

        val entry = signed.signatures.single()
        assertEquals(ALGORITHM, entry.algorithm)
        assertEquals(keyLabel, entry.signerName)
        assertEquals(SignerRole.CREATOR, entry.role)
        assertEquals(
            "the signer is identified by the hash of its public key",
            MediaHasher.hashBytes(publicKeyDer),
            entry.keyFingerprint
        )
        assertEquals("SHA-256", signed.hashAlgorithm)
        assertEquals(64, signed.contentHash.length)
        assertTrue("the timestamp must be recorded", entry.timestamp.isNotEmpty())

        assertTrue(
            "the signature must verify against the configured key over the recorded hash",
            SignatureVerifier.verifyEntry(publicKeyDer, entry, signed.contentHash)
        )
    }

    /** And the capture is recorded in the audit log under the signing key. */
    @Test
    fun aSignedPhotoIsAudited() {
        val uri = mediaUri!!
        configure(autoSignEnabled = true, signPhotos = true)
        startService()

        context.contentResolver.notifyChange(uri, null)

        awaitSignature(mediaPath!!)
        val row = awaitAuditRow(uri)
        assertEquals(keyId, row)
    }

    /**
     * MediaStore delivers the same change more than once for a single capture —
     * on insert, on write, on scan. Signing twice would append a second
     * signature to a photo that had one creator, so a URI already handled is
     * skipped outright.
     */
    @Test
    fun aRepeatedNotificationForTheSameCaptureIsIgnored() {
        val uri = mediaUri!!
        val path = mediaPath!!
        configure(autoSignEnabled = true, signPhotos = true)
        startService()

        context.contentResolver.notifyChange(uri, null)
        val first = awaitSignature(path)

        repeat(3) { context.contentResolver.notifyChange(uri, null) }
        SystemClock.sleep(SETTLE_MS)

        val after = XmpMetadataHelper.readSignature(path)
        assertNotNull(after)
        assertEquals("no second signature may be appended", 1, after!!.signatures.size)
        assertEquals(first.signatures.single().value, after.signatures.single().value)
        assertEquals(
            "exactly one audit record per capture",
            1,
            auditRowsFor(uri).size
        )
    }

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    /**
     * Inserts a real JPEG into MediaStore from the test process, so the app owns
     * the row and may rewrite the file through its path — which is what
     * `getFilePathFromUri` hands the metadata writer.
     */
    private fun insertCapture(stamp: Long) {
        val resolver = context.contentResolver
        val pending = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "xkey-autosign-$stamp.jpg")
            put(MediaStore.MediaColumns.MIME_TYPE, "image/jpeg")
            put(
                MediaStore.MediaColumns.RELATIVE_PATH,
                "${Environment.DIRECTORY_PICTURES}/$ALBUM"
            )
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }

        val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, pending)
        assumeTrue("this device has no writable image collection", uri != null)
        mediaUri = uri

        val bitmap = Bitmap.createBitmap(32, 32, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(Color.rgb(0x22, 0x44, 0x88))
        resolver.openOutputStream(uri!!)!!.use {
            bitmap.compress(Bitmap.CompressFormat.JPEG, 90, it)
        }
        bitmap.recycle()

        resolver.update(
            uri,
            ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) },
            null,
            null
        )

        @Suppress("DEPRECATION")
        val path = resolver.query(uri, arrayOf(MediaStore.MediaColumns.DATA), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATA))
                } else null
            }
        assumeTrue("this device's MediaStore exposes no file path", path != null)
        // The service writes the signature through the raw path, and the EXIF
        // writer stages it through a sibling temp file. A sandbox that allows
        // neither is the environment deciding the outcome, not the service.
        assumeTrue(
            "the MediaStore file is not writable through its path",
            runCatching {
                RandomAccessFile(path!!, "rw").use { }
                val staging = File("$path.probe")
                staging.writeBytes(byteArrayOf(0x01))
                staging.delete()
            }.isSuccess
        )
        mediaPath = path
    }

    private fun configure(autoSignEnabled: Boolean, signPhotos: Boolean) {
        runBlocking {
            settings.updateSettings(
                MediaSigningSettingsData(
                    autoSignEnabled = autoSignEnabled,
                    signingKeyId = keyId,
                    signPhotos = signPhotos,
                    signVideos = true
                )
            )
        }
    }

    private fun startService() {
        context.startService(Intent(context, MediaSigningService::class.java))
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (SystemClock.uptimeMillis() < deadline) {
            if (notificationManager.activeNotifications.any { it.id == NOTIFICATION_ID }) return
            SystemClock.sleep(POLL_MS)
        }
        fail("the media signing notification was never posted")
    }

    private fun awaitNotificationGone() {
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (SystemClock.uptimeMillis() < deadline) {
            if (notificationManager.activeNotifications.none { it.id == NOTIFICATION_ID }) return
            SystemClock.sleep(POLL_MS)
        }
    }

    /** Polls the photo's metadata until the service has written a signature. */
    private fun awaitSignature(path: String): ContentAuthenticityData {
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (SystemClock.uptimeMillis() < deadline) {
            val signature = runCatching { XmpMetadataHelper.readSignature(path) }.getOrNull()
            if (signature != null) return signature
            SystemClock.sleep(POLL_MS)
        }
        throw AssertionError("the capture was never signed")
    }

    /** Polls for the audit record naming this capture; returns its key id. */
    private fun awaitAuditRow(uri: Uri): String {
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (SystemClock.uptimeMillis() < deadline) {
            auditRowsFor(uri).firstOrNull()?.let { return it }
            SystemClock.sleep(POLL_MS)
        }
        throw AssertionError("no MEDIA_AUTO_SIGNED record names $uri")
    }

    private fun auditRowsFor(uri: Uri): List<String> = runBlocking {
        XKeyDatabase.getInstance(context).auditLogDao()
            .getByOperationType(AuditOperationType.MEDIA_AUTO_SIGNED)
            .filter { it.details?.contains(uri.toString()) == true }
            .mapNotNull { it.keyId }
    }

    private companion object {
        const val ALGORITHM = "ES256"
        const val ALBUM = "xkey-tests"

        /** Mirrors the private constant in [MediaSigningService]. */
        const val NOTIFICATION_ID = 2002

        /**
         * Comfortably past the ~10s the system may defer a foreground-service
         * notification by.
         */
        const val TIMEOUT_MS = 20_000L
        const val POLL_MS = 100L

        /** Comfortably past the service's 500 ms write-settling delay. */
        const val SETTLE_MS = 3_000L
    }
}
