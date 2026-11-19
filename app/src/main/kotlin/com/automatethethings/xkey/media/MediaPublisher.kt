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

import android.app.PendingIntent
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Process
import android.provider.MediaStore
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
 * Media another app owns, a camera capture, is not xKey's to rename over:
 * the user grants write access through a MediaStore write request
 * ([writeAccess], [writeRequest]) and the new bytes go through its content
 * URI ([writeGranted]), the one write MediaStore allows there.
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

    /** How xKey may write the MediaStore item at a content URI. */
    enum class MediaWriteAccess {
        /** xKey created it (or storage is not scoped): its file is replaced by path. */
        OWNED,

        /** Another app owns it and the user granted xKey write access to it. */
        GRANTED,

        /** Another app owns it (a camera capture): the user must grant write access first. */
        NEEDS_GRANT
    }

    /** The MediaStore facts [writeAccess] reads; settable so tests can stand in for the platform. */
    interface MediaStoreAccess {
        /** The package that owns [uri] (`OWNER_PACKAGE_NAME`), or null when MediaStore names none. */
        fun ownerPackage(context: Context, uri: Uri): String?

        /** Whether this process holds write access to [uri] (a granted write request). */
        fun hasWriteGrant(context: Context, uri: Uri): Boolean

        /** The user-approved write request for [uris] (`MediaStore.createWriteRequest`). */
        fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent
    }

    /** The platform's MediaStore. */
    object PlatformMediaStore : MediaStoreAccess {
        override fun ownerPackage(context: Context, uri: Uri): String? {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
            return context.contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.OWNER_PACKAGE_NAME), null, null, null)
                ?.use { cursor -> if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getString(0) else null }
        }

        override fun hasWriteGrant(context: Context, uri: Uri): Boolean =
            context.checkUriPermission(uri, Process.myPid(), Process.myUid(), Intent.FLAG_GRANT_WRITE_URI_PERMISSION) ==
                PackageManager.PERMISSION_GRANTED

        override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent {
            check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) { "write requests need Android 11" }
            return MediaStore.createWriteRequest(context.contentResolver, uris)
        }
    }

    @Volatile
    var mediaStore: MediaStoreAccess = PlatformMediaStore

    /**
     * How xKey may write the media at [target]. Before scoped storage
     * (Android 10 and earlier) the file is xKey's to replace by path. From
     * Android 11 only media whose owner is xKey is: anything else, a camera
     * capture above all, needs the user's grant, and READ_MEDIA_* gives none.
     */
    fun writeAccess(context: Context, target: Uri): MediaWriteAccess {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return MediaWriteAccess.OWNED
        if (target.scheme != ContentResolver.SCHEME_CONTENT) return MediaWriteAccess.OWNED
        if (mediaStore.ownerPackage(context, target) == context.packageName) return MediaWriteAccess.OWNED
        return if (mediaStore.hasWriteGrant(context, target)) MediaWriteAccess.GRANTED else MediaWriteAccess.NEEDS_GRANT
    }

    /** The request the user approves to let xKey write [targets]; an activity launches its intent sender. */
    fun writeRequest(context: Context, targets: List<Uri>): PendingIntent = mediaStore.createWriteRequest(context, targets)

    /** Writing [target] needs a write grant the user has not given. */
    class WriteAuthorizationRequiredException(val target: Uri) :
        IOException("writing $target needs the user's write access")

    /**
     * Write [staged] over the media at [target] through its content URI: the
     * one path for media another app owns, which xKey may write only with
     * the user's grant ([writeAccess] GRANTED) and never by renaming over its
     * file. Without the grant it throws [WriteAuthorizationRequiredException]
     * and writes nothing. [staged] is deleted only once the write and the
     * close both succeeded; a failure keeps it and throws
     * [MediaPublishException], which names it.
     */
    fun writeGranted(context: Context, target: Uri, staged: File) {
        if (writeAccess(context, target) == MediaWriteAccess.NEEDS_GRANT) throw WriteAuthorizationRequiredException(target)
        try {
            val output = context.contentResolver.openOutputStream(target, "wt") ?: throw IOException("cannot write $target")
            output.use { out -> staged.inputStream().use { it.copyTo(out) } }
        } catch (e: Throwable) {
            throw MediaPublishException(staged, e)
        }
        staged.delete()
    }
}
