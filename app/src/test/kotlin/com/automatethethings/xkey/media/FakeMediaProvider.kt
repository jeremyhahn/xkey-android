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
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File

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

    override fun onCreate() = true

    override fun getType(uri: Uri): String = mimeType

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        openModes += mode
        val writes = 'w' in mode
        if (writes && 't' in mode) media.writeBytes(ByteArray(0))
        if (writes && failWrites) return ParcelFileDescriptor.open(media, ParcelFileDescriptor.MODE_READ_ONLY)
        return ParcelFileDescriptor.open(media, ParcelFileDescriptor.parseMode(mode))
    }

    override fun query(uri: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, a: Array<out String>?) = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<out String>?) = 0
}
