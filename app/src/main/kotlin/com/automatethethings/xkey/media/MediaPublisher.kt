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

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream

/**
 * Writing the bytes it was publishing failed, or closing the destination
 * did; they are kept, whole, at [kept] for recovery, and the media the user
 * already had is untouched.
 */
class MediaPublishException(val kept: File, cause: Throwable) :
    IOException("the signed media could not be written; it is kept at ${kept.path}", cause)

/**
 * The one place xKey writes media bytes where the user keeps them: signing,
 * co-signing and every XMP, EXIF or sidecar write go through it, and no
 * other code opens a content URI for writing (a test scans for one).
 *
 * Media the user already has is never truncated. It is replaced atomically
 * where its provider allows that, a file reached by path: the new bytes are
 * written beside it and renamed over it, so it holds the old bytes or the
 * new, never half ([replaceFile], [replace]). Any other provider offers no
 * atomic replace, so the caller writes a separate copy to a document the
 * user creates through a save picker ([writeCopy], [openCreated]).
 *
 * The bytes being published stay on disk until the write and the close of
 * the destination have both succeeded; a failure keeps them for recovery
 * and throws [MediaPublishException], which names them.
 */
object MediaPublisher {

    const val RECOVERY_DIRECTORY = "media-recovery"

    /**
     * Where a caller stages what it publishes, so a failure keeps it: under
     * the app's files, which the system does not clear as it does the cache.
     */
    fun recoveryDirectory(context: Context): File =
        File(context.filesDir, RECOVERY_DIRECTORY).apply { mkdirs() }

    /**
     * Replace [target] with the file [write] fills. [write] gets a new,
     * exclusively created file beside [target] (on its filesystem, so the
     * rename is atomic); only when it returns true is that file synced and
     * renamed over [target]. False, with [target] untouched, when [write]
     * declines. The new file never outlives the call: [target] is either
     * replaced or left as it was.
     */
    fun replaceFile(target: File, write: (File) -> Boolean): Boolean {
        val directory = target.absoluteFile.parentFile ?: throw IOException("no directory holds ${target.path}")
        val temp = File.createTempFile(".${target.name}.", ".xkeytmp", directory)
        try {
            if (!write(temp)) return false
            FileOutputStream(temp, true).use { it.fd.sync() }
            if (!temp.renameTo(target)) throw IOException("cannot replace ${target.path}")
            return true
        } finally {
            temp.delete()
        }
    }

    /** The file [target] names when its provider allows an atomic replace (a file URI), else null. */
    fun replaceableFile(target: Uri): File? =
        if (target.scheme == ContentResolver.SCHEME_FILE) target.path?.let(::File) else null

    /**
     * Put [staged] in place of the user's media at [target] when its provider
     * allows an atomic replace ([replaceableFile]), then delete [staged].
     * False, with nothing written and [staged] left to the caller, when it
     * does not: the caller writes a separate copy ([writeCopy]). A failed
     * replace leaves [target] whole, keeps [staged] and throws
     * [MediaPublishException].
     */
    fun replace(target: Uri, staged: File): Boolean {
        val file = replaceableFile(target) ?: return false
        try {
            replaceFile(file) { temp -> staged.copyTo(temp, overwrite = true); true }
        } catch (e: Throwable) {
            throw MediaPublishException(staged, e)
        }
        staged.delete()
        return true
    }

    /**
     * Copy [staged] to the stream [openOutput] opens, a document the user
     * created for it, never media they already had, and close it. [staged]
     * is deleted only once the write and the close both succeeded; otherwise
     * it is kept and [MediaPublishException] names it.
     */
    fun writeCopy(staged: File, openOutput: () -> OutputStream) {
        try {
            openOutput().use { output -> staged.inputStream().use { it.copyTo(output) } }
        } catch (e: Throwable) {
            throw MediaPublishException(staged, e)
        }
        staged.delete()
    }

    /**
     * Open [target], a document the user just created through a save picker,
     * for writing from its start: the only content URI xKey opens for
     * writing. Media the user already has is never passed here; it is
     * replaced ([replace]) or copied ([writeCopy]).
     */
    fun openCreated(resolver: ContentResolver, target: Uri): OutputStream =
        resolver.openOutputStream(target, "wt") ?: throw IOException("cannot write $target")
}
