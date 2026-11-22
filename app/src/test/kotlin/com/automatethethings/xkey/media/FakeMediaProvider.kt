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

import android.content.ContentProvider
import android.content.ContentValues
import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OperationCanceledException
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Stands in for MediaStore's "media" provider: every content URI is backed
 * by [media], opened as MediaStore opens it, so a "wt" open truncates the
 * capture at once. With [failWrites] a write open still truncates for "t"
 * but hands back a descriptor that refuses every write, as a write that
 * fails mid-copy (storage full, the provider gone) leaves things.
 */
class FakeMediaProvider : ContentProvider() {

    lateinit var media: File
    var mimeType = "image/png"
    var failWrites = false
    val openModes = mutableListOf<String>()

    /** Each URI opened, in order: a read of the original carries `requireOriginal=1`. */
    val openUris = mutableListOf<Uri>()

    /** Runs as each open begins, with its mode: a test edits [media] here as another app would. */
    var onOpen: (String) -> Unit = {}

    /**
     * When set, a read of a URI that does not ask for the original
     * (`MediaStore.setRequireOriginal`) gets these bytes instead of [media]'s:
     * the redacted view MediaStore gives an app without ACCESS_MEDIA_LOCATION.
     */
    var redact: ((ByteArray) -> ByteArray)? = null

    /**
     * When set, a read stalls, as a slow or hostile provider's does, until
     * [release]. Robolectric's pipe reaches end of file as soon as it is
     * drained, write end open or not, so the read blocks on a latch in the
     * open instead; an interrupt ends the wait, as a cancelled call does.
     */
    var stall = false

    private val stalled = CountDownLatch(1)

    /** Ends every stalled read: each goes on to read [media]. */
    fun release() = stalled.countDown()

    /** Stalled reads whose thread was interrupted, which left the stall. */
    val stallInterrupted = AtomicInteger()

    /** Reads inside the stall now. */
    val inStall = AtomicInteger()

    /**
     * With [stall], the stall stands for an open blocked in the provider's
     * own process: the calling thread's interrupt does not reach it, so it
     * ends only by [release] or by the open's [CancellationSignal] being
     * cancelled, which counts [stallCancelled] and throws
     * [OperationCanceledException].
     */
    var stallAcrossProcess = false

    /** Stalled reads ended by their open's cancel signal. */
    val stallCancelled = AtomicInteger()

    /** For each read open, in order: whether it was handed a cancel signal. */
    val readSignals: MutableList<Boolean> = java.util.Collections.synchronizedList(mutableListOf())

    override fun onCreate() = true

    override fun getType(uri: Uri): String = mimeType

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor = openFile(uri, mode, null)

    /**
     * As MediaStore does: the open's signal reaches [openFile]. A read
     * through `ContentResolver.openFileDescriptor` arrives here (the
     * framework's defaults drop the signal).
     */
    override fun openAssetFile(uri: Uri, mode: String, signal: CancellationSignal?): AssetFileDescriptor =
        AssetFileDescriptor(openFile(uri, mode, signal), 0, AssetFileDescriptor.UNKNOWN_LENGTH)

    override fun openTypedAssetFile(
        uri: Uri,
        mimeTypeFilter: String,
        opts: Bundle?,
        signal: CancellationSignal?
    ): AssetFileDescriptor = openAssetFile(uri, "r", signal)

    override fun openFile(uri: Uri, mode: String, signal: CancellationSignal?): ParcelFileDescriptor {
        openModes += mode
        openUris += uri
        onOpen(mode)
        val writes = 'w' in mode
        if (!writes) readSignals += signal != null
        if (stall && !writes) {
            inStall.incrementAndGet()
            try {
                if (stallAcrossProcess) stallAcrossProcess(signal) else stalled.await()
            } catch (e: InterruptedException) {
                stallInterrupted.incrementAndGet()
                throw e
            } finally {
                inStall.decrementAndGet()
            }
        }
        val redacted = redact
        if (!writes && redacted != null && uri.getQueryParameter("requireOriginal") != "1") {
            // MediaStore's redacted view of a foreign capture: location left out.
            val view = File.createTempFile("redacted-", ".view", media.parentFile)
            view.writeBytes(redacted(media.readBytes()))
            view.deleteOnExit()
            return ParcelFileDescriptor.open(view, ParcelFileDescriptor.MODE_READ_ONLY)
        }
        if (writes && 't' in mode) media.writeBytes(ByteArray(0))
        if (writes && failWrites) return ParcelFileDescriptor.open(media, ParcelFileDescriptor.MODE_READ_ONLY)
        return ParcelFileDescriptor.open(media, ParcelFileDescriptor.parseMode(mode))
    }

    /** Waits out the stall deaf to interrupts, as another process's open is, until [release] or [signal]'s cancel. */
    private fun stallAcrossProcess(signal: CancellationSignal?) {
        var interrupted = false
        try {
            while (true) {
                if (signal?.isCanceled == true) {
                    stallCancelled.incrementAndGet()
                    throw OperationCanceledException("the open was cancelled")
                }
                try {
                    if (stalled.await(10, TimeUnit.MILLISECONDS)) return
                } catch (e: InterruptedException) {
                    interrupted = true
                }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    /** The file MediaStore names for every item (`_data`), or null for none: then a query finds nothing. */
    var dataPath: String? = null

    override fun query(uri: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? {
        val path = dataPath ?: return null
        val columns = p ?: arrayOf(MediaStore.MediaColumns.DATA)
        return MatrixCursor(columns).apply {
            addRow(columns.map { if (it == MediaStore.MediaColumns.DATA) path else null }.toTypedArray())
        }
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, a: Array<out String>?) = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<out String>?) = 0
}
