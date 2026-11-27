/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.media

import android.content.ContentProvider
import android.content.ContentResolver
import android.content.ContentUris
import android.content.ContentValues
import android.database.ContentObserver
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.MediaSigningSettingsData
import com.automatethethings.xkey.settings.MediaSigningSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.robolectric.Robolectric
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ServiceController
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.InputStream
import java.security.KeyStore
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Drives [MediaSigningService] on the JVM through its Android surfaces only:
 * the service is started with Robolectric, a fake `media` provider answers
 * the type, bytes and DATA path of each capture, and events are delivered by
 * calling the two ContentObservers the service registered.
 *
 * The AndroidKeyStore, the settings DataStore, the database and the audit
 * log are mocked as `AssertionSignCountTest` mocks them. Captures are real
 * files under [dir], so the signature the service writes (embedded or in a
 * `.xkeysig` sidecar) is read back with [XmpMetadataHelper].
 *
 * Call [setUp] in `@Before` and [tearDown] in `@After`.
 */
class MediaSigningServiceFixture(private val dir: File) {

    /** One capture the fake provider serves. */
    class Capture(
        val uri: Uri,
        val file: File,
        val mimeType: String?,
        /** The capture's bytes when it was added. */
        val original: ByteArray,
        /** The DATA column; null models a row without a file path. */
        @Volatile var path: String?,
        /** False makes the provider refuse to open the capture. */
        @Volatile var readable: Boolean = true
    ) {
        val sidecar: File get() = File(XmpMetadataHelper.getSidecarPath(file.path))
    }

    /** The arguments of one `signApproved` call. */
    class SignCall(val alias: String, val publicKeyDer: ByteArray, val data: ByteArray, val jcaAlgorithm: String)

    /**
     * A stand-in for the MediaStore provider under authority `media`. A query
     * of an item returns its DATA path; a query of a collection URI returns
     * every capture under it, as MediaStore does.
     */
    class MediaProvider : ContentProvider() {
        override fun onCreate(): Boolean = true

        override fun getType(uri: Uri): String? = captures[uri]?.mimeType

        override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
            val capture = captures[uri] ?: throw FileNotFoundException("No capture at $uri")
            if (!capture.readable) throw FileNotFoundException("Cannot open $uri")
            return ParcelFileDescriptor.open(capture.file, ParcelFileDescriptor.MODE_READ_ONLY)
        }

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            selectionArgs: Array<out String>?,
            sortOrder: String?
        ): Cursor {
            queries.merge(uri, 1, Int::plus)
            @Suppress("DEPRECATION")
            val cursor = MatrixCursor(arrayOf(MediaStore.MediaColumns.DATA))
            val item = captures[uri]
            if (item != null) {
                item.path?.let { cursor.addRow(arrayOf<Any?>(it)) }
            } else {
                captures.values
                    .filter { it.uri.toString().startsWith("$uri/") }
                    .forEach { capture -> capture.path?.let { cursor.addRow(arrayOf<Any?>(it)) } }
            }
            return cursor
        }

        override fun insert(uri: Uri, values: ContentValues?): Uri? = null

        override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            selectionArgs: Array<out String>?
        ): Int = 0
    }

    companion object {
        const val KEY_ID = "camera-key"
        const val KEY_LABEL = "Camera key"
        const val KEY_TYPE = "signing"
        const val KEY_ALGORITHM = "ES256"

        val PUBLIC_KEY_DER: ByteArray = ByteArray(91) { (it * 7 + 3).toByte() }
        val SIGNATURE: ByteArray = ByteArray(70) { (it * 11 + 5).toByte() }

        val IMAGES: Uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        val VIDEOS: Uri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI

        /** How long [awaitSigning] waits: the service's 500 ms delay plus the work. */
        private const val MAX_WAIT_MS = 5_000L

        /** What the fake provider serves, by item URI. */
        internal val captures = ConcurrentHashMap<Uri, Capture>()

        /** DATA queries the provider answered, by URI. */
        internal val queries = ConcurrentHashMap<Uri, Int>()

        fun key(keyId: String = KEY_ID) = KeyEntity(
            keyId = keyId,
            keyType = KEY_TYPE,
            algorithm = KEY_ALGORITHM,
            label = KEY_LABEL,
            keySizeBits = 256,
            source = "local"
        )

        private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

        private fun segment(marker: Int, body: ByteArray): ByteArray {
            val length = body.size + 2
            return bytes(0xFF, marker, length shr 8, length and 0xFF) + body
        }

        /**
         * A complete 8x8 greyscale baseline JPEG as a camera leaves it: JFIF
         * APP0 and an EXIF APP1 (big-endian TIFF header, empty IFD0), then
         * the tables, one scan and EOI.
         */
        fun jpeg(): ByteArray = ByteArrayOutputStream().apply {
            write(bytes(0xFF, 0xD8))
            write(segment(0xE0, bytes(0x4A, 0x46, 0x49, 0x46, 0x00, 1, 1, 0, 0, 1, 0, 1, 0, 0)))
            write(segment(0xE1, bytes(0x45, 0x78, 0x69, 0x66, 0, 0, 0x4D, 0x4D, 0x00, 0x2A, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0)))
            write(segment(0xDB, bytes(0x00) + ByteArray(64) { 1 }))
            write(segment(0xC0, bytes(8, 0, 8, 0, 8, 1, 1, 0x11, 0)))
            write(segment(0xC4, bytes(0x00, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00)))
            write(segment(0xC4, bytes(0x10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00)))
            write(segment(0xDA, bytes(1, 1, 0x00, 0, 63, 0)))
            write(bytes(0x3F, 0xFF, 0xD9))
        }.toByteArray()

        /** Bytes standing in for a video container; the service never parses them. */
        fun video(seed: Int = 1): ByteArray = ByteArray(20_000) { ((it * 31 + seed) % 251).toByte() }

        /** A PNG signature followed by bytes the service never parses. */
        fun png(seed: Int = 1): ByteArray =
            bytes(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) + ByteArray(4_000) { ((it + seed) % 253).toByte() }
    }

    /** The settings `getSettings` returns, read at each event. */
    @Volatile
    var settings = MediaSigningSettingsData(autoSignEnabled = true, signingKeyId = KEY_ID)

    /** Key rows the database holds, by key id. */
    val keys = ConcurrentHashMap<String, KeyEntity>()

    /** What `publicKeyDERAt` returns; null models a missing key. */
    @Volatile
    var publicKeyDer: ByteArray? = PUBLIC_KEY_DER

    /** Thrown by `signApproved` when set. */
    @Volatile
    var signFailure: Throwable? = null

    /** Every `signApproved` call, in order. */
    val signCalls: MutableList<SignCall> = Collections.synchronizedList(mutableListOf())

    private val nextId = AtomicLong(1000)
    private var controller: ServiceController<MediaSigningService>? = null
    private var startId = 0
    private var destroyed = false

    val service: MediaSigningService get() = checkNotNull(controller) { "start() first" }.get()

    /** The resolver the service reads captures through. */
    val resolver: ContentResolver get() = service.contentResolver

    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        captures.clear()
        queries.clear()
        keys[KEY_ID] = key()
        Robolectric.setupContentProvider(MediaProvider::class.java, MediaStore.AUTHORITY)

        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(KeystoreManager::class)
        every { anyConstructed<KeystoreManager>().publicKeyDERAt(any()) } answers { publicKeyDer }
        coEvery { anyConstructed<KeystoreManager>().signApproved(any(), any(), any(), any()) } answers {
            signFailure?.let { throw it }
            signCalls += SignCall(firstArg(), secondArg(), thirdArg(), arg(3))
            SIGNATURE.copyOf()
        }

        mockkConstructor(MediaSigningSettingsRepository::class)
        coEvery { anyConstructed<MediaSigningSettingsRepository>().getSettings() } answers { settings }

        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } answers { keys[firstArg<String>()] }
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        // The signing key is a general key with no delete under way and no stored policy.
        val keyPolicyDao = mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true)
        coEvery { keyPolicyDao.deletion(any()) } returns null
        coEvery { keyPolicyDao.policyRow(any()) } returns null
        every { database.keyPolicyDao() } returns keyPolicyDao
        every { anyConstructed<KeystoreManager>().exportKind(any()) } returns com.automatethethings.xkey.crypto.UserKeyKind.GENERAL
        every { anyConstructed<KeystoreManager>().rowKeyKind(any(), any(), any(), any()) } returns
            com.automatethethings.xkey.crypto.UserKeyKind.GENERAL
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkObject(AuditLogger)
        every { AuditLogger.logMediaAutoSigned(any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyUsed(any(), any(), any(), any(), any(), any(), any()) } returns Unit
    }

    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        try {
            if (controller != null && !destroyed) controller!!.destroy()
            // A job a destroyed service left behind must not outlive the test.
            if (controller != null) awaitSigning()
        } finally {
            unmockkAll()
            captures.clear()
            queries.clear()
        }
    }

    /** Creates the service on the first call; every call delivers a start command. */
    fun start(): MediaSigningService {
        val c = controller ?: Robolectric.buildService(MediaSigningService::class.java).create()
            .also { controller = it }
        c.startCommand(0, ++startId)
        return c.get()
    }

    /** Destroys the service as the system does when it is stopped. */
    fun destroy() {
        checkNotNull(controller).destroy()
        destroyed = true
    }

    /** The observers registered for [collection], as the resolver holds them. */
    fun observers(collection: Uri): Collection<ContentObserver> =
        shadowOf(service.contentResolver).getContentObservers(collection)

    /** Adds a file [name] holding [bytes] as a new item of [collection]. */
    fun addCapture(
        collection: Uri,
        name: String,
        bytes: ByteArray,
        mimeType: String?,
        withPath: Boolean = true
    ): Capture {
        val file = File(dir, name).apply { writeBytes(bytes) }
        val uri = ContentUris.withAppendedId(collection, nextId.incrementAndGet())
        return Capture(uri, file, mimeType, bytes.copyOf(), if (withPath) file.path else null)
            .also { captures[uri] = it }
    }

    /** Makes the resolver hand out [stream] for [uri] instead of the provider's file. */
    fun registerStream(uri: Uri, stream: InputStream) =
        shadowOf(service.contentResolver).registerInputStream(uri, stream)

    /**
     * Delivers a MediaStore change for [uri] to the one observer of its
     * collection (videos for a video URI, images otherwise) and waits until
     * the signing job it started has finished.
     */
    fun deliver(uri: Uri) {
        val collection = if (uri.toString().startsWith(VIDEOS.toString())) VIDEOS else IMAGES
        val registered = observers(collection)
        check(registered.size == 1) { "expected one observer for $collection, found ${registered.size}" }
        fire(registered.single(), uri)
    }

    /** Calls [observer] for [uri], registered or not, and waits for its job. */
    fun fire(observer: ContentObserver, uri: Uri) {
        observer.onChange(false, uri)
        awaitSigning()
    }

    /**
     * Waits until the service has no signing job in flight. This is the one
     * place that knows how the service tracks its work (its private
     * `signingJobs` set); change it here when the service is restructured.
     */
    fun awaitSigning() {
        val field = MediaSigningService::class.java.getDeclaredField("signingJobs").apply { isAccessible = true }
        val jobs = field.get(service) as Set<*>
        val deadline = System.currentTimeMillis() + MAX_WAIT_MS
        while (jobs.isNotEmpty()) {
            if (System.currentTimeMillis() > deadline) {
                throw AssertionError("signing did not finish within $MAX_WAIT_MS ms")
            }
            Thread.sleep(10)
        }
    }

    /** [capture] has no signature: no sidecar, no embedded one, its bytes unchanged. */
    fun assertUnsigned(capture: Capture) {
        assertFalse("no sidecar for ${capture.file.name}", capture.sidecar.exists())
        assertArrayEquals("${capture.file.name} must be unchanged", capture.original, capture.file.readBytes())
        assertNull("no signature for ${capture.file.name}", XmpMetadataHelper.readSignature(capture.file.path))
    }
}
