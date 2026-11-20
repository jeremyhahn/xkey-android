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
import android.app.PendingIntent
import android.app.RecoverableSecurityException
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.provider.MediaStore
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Writing the bytes it was publishing failed, or closing the destination
 * did; they are kept, whole, at [kept] for recovery, and the media the user
 * already had is untouched, unless [original] is set: a granted write that
 * failed part-way and could not put the media back, whose prior bytes are
 * kept there.
 */
class MediaPublishException(val kept: File, cause: Throwable, val original: File? = null) :
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
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) throw IllegalStateException("write requests need Android 11")
            return MediaStore.createWriteRequest(context.contentResolver, uris)
        }
    }

    @Volatile
    var mediaStore: MediaStoreAccess = PlatformMediaStore

    /**
     * How xKey may write the media at [target]. Before scoped storage
     * (Android 9 and earlier) the file is xKey's to replace by path. From
     * Android 10 only media whose owner is xKey is: anything else, a camera
     * capture above all, is written only through its content URI. Android 11
     * asks the user first, in a write request (NEEDS_GRANT until granted);
     * Android 10 has none and asks at the write itself, so it is GRANTED and
     * the write throws [UserActionRequiredException] until the user allows it.
     */
    fun writeAccess(context: Context, target: Uri): MediaWriteAccess {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return MediaWriteAccess.OWNED
        if (target.scheme != ContentResolver.SCHEME_CONTENT) return MediaWriteAccess.OWNED
        if (mediaStore.ownerPackage(context, target) == context.packageName) return MediaWriteAccess.OWNED
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return MediaWriteAccess.GRANTED
        return if (mediaStore.hasWriteGrant(context, target)) MediaWriteAccess.GRANTED else MediaWriteAccess.NEEDS_GRANT
    }

    /** The request the user approves to let xKey write [targets]; an activity launches its intent sender. */
    fun writeRequest(context: Context, targets: List<Uri>): PendingIntent = mediaStore.createWriteRequest(context, targets)

    /**
     * [target] can be read only as MediaStore's redacted view, its location
     * left out, because xKey lacks ACCESS_MEDIA_LOCATION: writing that view
     * back, or keeping it as the backup, would erase the location for good,
     * so nothing is staged, backed up or written.
     */
    class OriginalUnavailableException(val target: Uri) :
        IOException("$target can be read only without its location; rewriting it needs location access")

    /**
     * The URI that reads [target] whole, its location metadata included: a
     * content URI's original ([MediaStore.setRequireOriginal]) from Android
     * 10, which needs ACCESS_MEDIA_LOCATION, or [target] itself where nothing
     * is redacted (another scheme or provider, earlier Android, or an item
     * that carries no location: see [carriesLocation]). Only MediaStore
     * redacts, and only images and videos: its own URIs and the media
     * documents it backs, which serve the original to a caller holding the
     * permission. Null when that permission is missing for one of them.
     */
    fun originalUri(context: Context, target: Uri): Uri? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return target
        if (target.scheme != ContentResolver.SCHEME_CONTENT) return target
        val authority = target.authority
        if (authority != MediaStore.AUTHORITY && authority != MEDIA_DOCUMENTS_AUTHORITY) return target
        if (!carriesLocation(context, target)) return target
        if (context.checkSelfPermission(Manifest.permission.ACCESS_MEDIA_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            return null
        }
        return if (authority == MediaStore.AUTHORITY) MediaStore.setRequireOriginal(target) else target
    }

    /**
     * Whether MediaStore redacts [target]'s location: an image or a video,
     * by the type the provider serves. Audio, PDFs and other documents read
     * whole without location access. With no type served, the collection the
     * URI names decides, and an unknown one is taken as one that may.
     */
    private fun carriesLocation(context: Context, target: Uri): Boolean {
        val type = try {
            context.contentResolver.getType(target)
        } catch (_: Exception) {
            null
        }
        if (type != null) return type.startsWith("image/") || type.startsWith("video/")
        val segments = target.pathSegments
        if (target.authority == MEDIA_DOCUMENTS_AUTHORITY) {
            val id = segments.lastOrNull().orEmpty()
            return !(id.startsWith("audio:") || id.startsWith("document:"))
        }
        return "audio" !in segments
    }

    /**
     * Whether [target] is readable only as MediaStore's redacted view until
     * xKey holds ACCESS_MEDIA_LOCATION ([originalUri] null): what
     * [MediaLocationAccess] asks the user for.
     */
    fun needsLocationAccess(context: Context, target: Uri): Boolean = originalUri(context, target) == null

    /** The documents provider MediaStore backs (the system picker's Images, Videos and Audio roots). */
    private const val MEDIA_DOCUMENTS_AUTHORITY = "com.android.providers.media.documents"

    /**
     * The one read of a capture xKey stages, backs up or checks before and
     * after writing it in place: its original bytes ([originalUri]), never
     * the redacted view. Throws [OriginalUnavailableException] when only
     * that view is readable.
     */
    fun openOriginal(context: Context, target: Uri): InputStream {
        val original = originalUri(context, target) ?: throw OriginalUnavailableException(target)
        return context.contentResolver.openInputStream(original) ?: throw IOException("cannot read $target")
    }

    /**
     * A granted write of [target] an earlier call or process was interrupted
     * in could not be put back yet (no write grant now, or the restore
     * failed): the capture may be part-written, so nothing stages or writes
     * it until a later recovery restores [backup].
     */
    class RecoveryPendingException(val target: Uri, val backup: File) :
        IOException("$target is not restored yet; its prior bytes are kept at ${backup.path}")

    /** Whether [target] has a granted write recorded that is not yet put back. */
    fun recoveryPending(context: Context, target: Uri): Boolean =
        GrantedWriteJournal(recoveryDirectory(context), target).recorded()

    /** Writing [target] needs a write grant the user has not given. */
    class WriteAuthorizationRequiredException(val target: Uri) :
        IOException("writing $target needs the user's write access")

    /**
     * Android 10 refused the write of [target], media another app owns,
     * until the user allows it (a RecoverableSecurityException): nothing was
     * written. An activity launches [intentSender], MediaStore's question,
     * and writes again once the user allows it.
     */
    class UserActionRequiredException(val target: Uri, val intentSender: IntentSender) :
        IOException("writing $target needs the user to allow it")

    /**
     * What a capture held when it was staged, before anything was embedded:
     * the canonical hash of what was signed ([contentHash], typed by
     * [mimeType]) and a SHA-256 of the whole snapshot ([digest]). The
     * canonical hash leaves out metadata (a JPEG's APP and COM segments), so
     * only the whole-file digest shows an edit of the location or
     * orientation alone. The one check that a capture has not changed since
     * staging: [of] at staging, [requireUnchanged] before it is overwritten.
     */
    class StagedSource internal constructor(val mimeType: String, val contentHash: String, val digest: String) {
        /** Throws [XmpMetadataHelper.SourceChangedException] unless [current] is the staged snapshot, byte for byte. */
        fun requireUnchanged(current: File) {
            if (AutoSignHash.contentHashFile(current, mimeType) != contentHash) throw XmpMetadataHelper.SourceChangedException()
            if (digestOf(current) != digest) throw XmpMetadataHelper.SourceChangedException()
        }

        companion object {
            /**
             * [snapshot], the capture as just staged, which must still hold
             * what was signed ([contentHash]), else
             * [XmpMetadataHelper.SourceChangedException].
             */
            fun of(snapshot: File, mimeType: String, contentHash: String): StagedSource {
                if (AutoSignHash.contentHashFile(snapshot, mimeType) != contentHash) throw XmpMetadataHelper.SourceChangedException()
                return StagedSource(mimeType, contentHash, digestOf(snapshot))
            }

            private fun digestOf(file: File): String {
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                file.inputStream().use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        digest.update(buffer, 0, n)
                    }
                }
                return digest.digest().joinToString("") { "%02x".format(it) }
            }
        }
    }

    /**
     * Write [staged] over the media at [target] through its content URI: the
     * one path for media another app owns, which xKey may write only with
     * the user's grant ([writeAccess] GRANTED) and never by renaming over its
     * file. Without the grant it throws [WriteAuthorizationRequiredException]
     * and writes nothing.
     *
     * A content URI offers no atomic replace, so the capture is never
     * truncated up front. Its current bytes are first copied whole and
     * synced to the recovery directory and checked against [source], what the
     * capture held when it was staged ([StagedSource.requireUnchanged]): any
     * edit saved since staging, its metadata alone included, throws [XmpMetadataHelper.SourceChangedException] and nothing
     * is written. Then a synced record naming the capture and that backup is
     * written ([GrantedWriteJournal]), and only then is the capture
     * overwritten in place ([overwrite]) and cut to length once every new
     * byte is in. A write that fails or is interrupted part-way puts the
     * backup back ([restore]) and checks it byte for byte; one the process
     * dies in, or whose restore fails, keeps its record, and the next start
     * or retry puts the backup back ([recoverInterruptedWrites]), unless the
     * capture was edited since: then both versions are kept ([recover]).
     * [MediaPublishException.original] names the backup while it is needed.
     * [staged] is deleted only once the write and the close both succeeded.
     */
    fun writeGranted(context: Context, target: Uri, staged: File, source: StagedSource) = synchronized(grantedWrites) {
        if (writeAccess(context, target) == MediaWriteAccess.NEEDS_GRANT) throw WriteAuthorizationRequiredException(target)
        // The backup must be the capture whole, location included, or the
        // write would leave nothing to put the location back from.
        if (originalUri(context, target) == null) throw OriginalUnavailableException(target)
        val resolver = context.contentResolver
        // A write of this capture an earlier process died in is put back
        // first; one that cannot be yet throws RecoveryPendingException.
        recoverInterruptedWrite(context, target)
        val journal = GrantedWriteJournal(recoveryDirectory(context), target)
        val partial = File.createTempFile(GrantedWriteJournal.PREFIX, ".part", recoveryDirectory(context))
        try {
            openOriginal(context, target).use { input ->
                FileOutputStream(partial).use { out ->
                    input.copyTo(out)
                    out.fd.sync()
                }
            }
            // What is about to be overwritten must still be what was staged: an
            // edit saved since, metadata alone included, is kept, not replaced
            // by the older snapshot.
            source.requireUnchanged(partial)
            journal.commit(partial, staged)
        } catch (e: XmpMetadataHelper.SourceChangedException) {
            partial.delete()
            throw e
        } catch (e: Throwable) {
            partial.delete()
            journal.clear()
            throw MediaPublishException(staged, e)
        }
        var touched = false
        try {
            overwrite(resolver, target, staged) { touched = true }
        } catch (e: UserActionRequiredException) {
            // Refused before a byte changed: the capture is whole, and the
            // caller asks the user and writes again.
            journal.clear()
            throw e
        } catch (e: Throwable) {
            val intact = !touched || restore(context, target, journal)
            // One that could not be put back keeps its record: the next start or retry restores it.
            if (intact) journal.clear()
            throw MediaPublishException(staged, e, original = if (intact) null else journal.backup)
        }
        journal.clear()
        staged.delete()
    }

    /**
     * Held across every granted write and every recovery, so a recovery
     * never puts a backup back under a write in progress. [grantedSection]
     * lets a caller hold it from staging the capture to writing it.
     */
    @PublishedApi
    internal val grantedWrites = Any()

    /**
     * Run [block] holding the granted-write lock, once any write of
     * [target] an earlier process died in has been put back: what [block]
     * stages is then the capture as it was, never one half-written. When it
     * cannot be put back yet, [block] does not run: [RecoveryPendingException].
     */
    inline fun <T> grantedSection(context: Context, target: Uri, block: () -> T): T = synchronized(grantedWrites) {
        recoverInterruptedWrite(context, target)
        block()
    }

    /**
     * Put back every capture a granted write was interrupted in, by an
     * exception, a cancellation or the process dying: each left a record
     * naming the capture and its backup ([GrantedWriteJournal]). Called at
     * start and before a retry; a capture xKey cannot write yet (no grant)
     * keeps its record for a later call.
     */
    fun recoverInterruptedWrites(context: Context) = synchronized(grantedWrites) {
        GrantedWriteJournal.all(recoveryDirectory(context)).forEach { recover(context, it) }
    }

    /**
     * [recoverInterruptedWrites] for [target] alone, which must succeed
     * before anything stages or writes it: a capture left part-written
     * that cannot be put back yet throws [RecoveryPendingException], and its
     * record and backup stay for a later call.
     */
    fun recoverInterruptedWrite(context: Context, target: Uri) = synchronized(grantedWrites) {
        val journal = GrantedWriteJournal(recoveryDirectory(context), target)
        if (journal.recorded() && !recover(context, journal)) throw RecoveryPendingException(target, journal.backup)
    }

    /**
     * Put back what [journal] records; true once nothing is left to put back.
     * A record that cannot be read leaves the recovery pending (false), its
     * record and backup kept: only a restore that succeeded clears them.
     *
     * A capture edited since the write (in a gallery, after the process
     * died) is never restored over: its content is not one the interrupted
     * write, or a restore of it the process died in, can leave
     * ([GrantedWriteJournal.explains]). A part-restored capture is put back. Its edit stays, the
     * backup is set aside ([GrantedWriteJournal.keepBackup]) so both
     * versions remain, and the record is cleared; signing it then meets the
     * changed-source check and is refused. A record from before [written]
     * was journalled cannot tell the two apart and is restored as before.
     */
    private fun recover(context: Context, journal: GrantedWriteJournal): Boolean {
        val target = try {
            journal.target()
        } catch (_: IOException) {
            return false
        }
        if (!journal.backup.isFile) {
            journal.clear()
            return true
        }
        if (journal.written.isFile) {
            val explained = try {
                openOriginal(context, target).buffered().use { content -> journal.explains(content) }
            } catch (_: Exception) {
                // Not readable as it is now: nothing shows it unedited, so nothing is written.
                return false
            }
            if (!explained) {
                val kept = journal.keepBackup() ?: return false
                Log.w(TAG, "$target was edited after an interrupted write; its earlier version is kept in ${kept.name}")
                journal.clear()
                return true
            }
        }
        if (writeAccess(context, target) == MediaWriteAccess.NEEDS_GRANT) return false
        if (!restore(context, target, journal)) return false
        journal.clear()
        return true
    }

    /**
     * Whether [content] is a state an interrupted granted write, and any
     * restore of [backup] after it, can leave: the one test that tells a
     * capture to put back from one edited since. An in-place write of
     * [written] ([overwrite]) leaves [written]'s bytes up to where it stopped,
     * then [backup]'s from there, ending where [backup] ends or, past it,
     * where the write stopped; or [written] whole once it was cut to length.
     * Once a restore has begun ([restoring]), each try writes [backup] from
     * the start over that, so [backup]'s bytes come first, up to where the
     * furthest try stopped, then what the write left. [backup] itself is
     * such a state. Anything else was saved since.
     */
    internal fun interruptedWriteExplains(content: java.io.InputStream, written: File, backup: File, restoring: Boolean): Boolean {
        val writtenLength = written.length()
        val backupLength = backup.length()
        written.inputStream().buffered().use { w ->
            backup.inputStream().buffered().use { b ->
                // Which part of a layout the bytes so far can end in: the backup's
                // bytes a restore put back ([restored], only once one began), the
                // written bytes after them ([writing]), or the backup's bytes the
                // write never reached ([untouched]). Each part may be empty.
                var restored = restoring
                var writing = true
                var untouched = true
                var n = 0L
                while (true) {
                    val c = content.read()
                    if (c < 0) break
                    val nw = w.read()
                    val nb = b.read()
                    val nextRestored = restored && c == nb
                    val nextWriting = (restored || writing) && c == nw
                    untouched = (restored || writing || untouched) && c == nb
                    restored = nextRestored
                    writing = nextWriting
                    if (!restored && !writing && !untouched) return false
                    n++
                }
                // Where each layout can end: a restore that put the backup back
                // past where a written-whole capture ended stops anywhere from
                // there; written bytes end where the write stopped (past the
                // backup's end) or where a truncate cut the written file; the
                // backup's own bytes end where the backup ends.
                return (restored && (n == backupLength || n >= writtenLength)) ||
                    (writing && (n >= backupLength || n == writtenLength)) ||
                    (untouched && n == backupLength)
            }
        }
    }

    /**
     * The durable record of one granted write: the capture's prior bytes
     * ([backup]), the bytes written over them ([written], a link to the
     * staged file) and, written and synced only once both are whole, a record
     * naming the capture's URI. A record present means the capture may be
     * part-written and [backup] is what it must hold; [written], with the
     * phase ([restoring], once a restore began), tells a part-written or
     * part-restored capture from one edited since ([explains]).
     */
    class GrantedWriteJournal(private val directory: File, private val uri: Uri) {
        private val key = java.security.MessageDigest.getInstance("SHA-256")
            .digest(uri.toString().toByteArray()).joinToString("") { "%02x".format(it) }

        val backup = File(directory, "$PREFIX$key.bak")
        val written = File(directory, "$PREFIX$key.new")
        private val record = File(directory, "$PREFIX$key$RECORD")

        /** Present once a restore of [backup] may have begun writing: the restore phase. */
        val restoring = File(directory, "$PREFIX$key.restoring")

        fun recorded() = record.isFile

        /**
         * Record, synced, that a restore of [backup] begins: from here the
         * capture may hold the backup's bytes before what the write left.
         * Throws when it cannot be recorded, so nothing is restored unrecorded.
         */
        fun markRestoring() {
            if (restoring.isFile) return
            FileOutputStream(restoring).use { out -> out.fd.sync() }
        }

        /**
         * Whether [content], the capture as it reads now, is a state this
         * write or a restore of it can leave ([interruptedWriteExplains], in
         * the phase recorded): the one check every recovery makes before it
         * puts [backup] back.
         */
        fun explains(content: InputStream): Boolean =
            interruptedWriteExplains(content, written, backup, restoring = restoring.isFile)

        /**
         * The capture the record names. A read that fails throws: it has not
         * shown the record gone, so the record and backup must stay.
         */
        fun target(): Uri = Uri.parse(readRecord(record))

        /**
         * [whole] (synced) becomes the backup, [staged] is linked (or copied
         * and synced) as [written], then the record is written and synced.
         */
        fun commit(whole: File, staged: File) {
            // A new write starts in the write phase: no restore of it has begun.
            restoring.delete()
            if (!whole.renameTo(backup)) throw IOException("cannot keep the capture's backup")
            written.delete()
            try {
                java.nio.file.Files.createLink(written.toPath(), staged.toPath())
            } catch (_: Exception) {
                FileOutputStream(written).use { out ->
                    staged.inputStream().use { it.copyTo(out) }
                    out.fd.sync()
                }
            }
            val temp = File(directory, "$PREFIX$key.tmp")
            FileOutputStream(temp).use { out ->
                out.write(uri.toString().toByteArray())
                out.fd.sync()
            }
            if (!temp.renameTo(record)) throw IOException("cannot record the granted write")
        }

        /**
         * Set the backup aside under a name no recovery reads, so a capture
         * edited since the write keeps its edit and the version before the
         * write stays too. Null when it cannot be moved.
         */
        fun keepBackup(): File? {
            val kept = File(directory, "$KEPT_PREFIX$key-${System.currentTimeMillis()}.bak")
            return if (backup.renameTo(kept)) kept else null
        }

        /** The record goes first: a backup with no record is only a leftover. */
        fun clear() {
            record.delete()
            backup.delete()
            written.delete()
            restoring.delete()
        }

        companion object {
            const val PREFIX = "granted-"
            /** A backup set aside for a capture edited after an interrupted write. */
            const val KEPT_PREFIX = "kept-"
            private const val RECORD = ".uri"

            /** The one read of a record's text; tests make it fail. */
            @Volatile
            internal var readRecord: (File) -> String = { it.readText() }

            /**
             * Every recorded write. A record that cannot be read is skipped,
             * never cleared: it and its backup stay for a later recovery.
             */
            fun all(directory: File): List<GrantedWriteJournal> =
                directory.listFiles { f -> f.name.startsWith(PREFIX) && f.name.endsWith(RECORD) }.orEmpty()
                    .mapNotNull { f ->
                        try {
                            GrantedWriteJournal(directory, Uri.parse(readRecord(f)))
                        } catch (_: IOException) {
                            null
                        }
                    }
        }
    }

    /**
     * Put [journal]'s backup back over [target] after a write that failed
     * part-way, and confirm it byte for byte: the one path that restores. The
     * journal records the restore phase first ([GrantedWriteJournal.markRestoring]),
     * so a restore the process dies in is recognised by the next recovery
     * ([GrantedWriteJournal.explains]) and finished; when that record cannot
     * be written, nothing is. An interrupt closes a file channel at
     * once and would refuse the restore too, so the restore runs with the
     * thread's interrupt held back (a few tries, should another arrive) and
     * re-asserts it after. True only when [target] reads back as [backup].
     */
    private fun restore(context: Context, target: Uri, journal: GrantedWriteJournal): Boolean {
        val backup = journal.backup
        try {
            journal.markRestoring()
        } catch (e: IOException) {
            Log.w(TAG, "Cannot record the restore of $target", e)
            return false
        }
        var interrupted = false
        try {
            repeat(RESTORE_ATTEMPTS) {
                if (Thread.interrupted()) interrupted = true
                val restored = runCatching {
                    overwrite(context.contentResolver, target, backup) {}
                    sameBytes(context, target, backup)
                }.getOrDefault(false)
                if (restored) return true
            }
            return false
        } finally {
            if (Thread.interrupted()) interrupted = true
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    /** Whether the content at [target] is exactly [file]'s bytes. */
    private fun sameBytes(context: Context, target: Uri, file: File): Boolean {
        // The original, as the backup was read: a redacted view never matches it.
        return openOriginal(context, target).buffered().use { content ->
            file.inputStream().buffered().use { expected ->
                var a: Int
                do {
                    a = content.read()
                    if (a != expected.read()) return false
                } while (a >= 0)
                true
            }
        }
    }

    private const val RESTORE_ATTEMPTS = 3
    private const val TAG = "MediaPublisher"

    /** Runs at each named step of an in-place write; tests interrupt a write there. */
    @Volatile
    internal var overwriteStep: (String) -> Unit = {}

    /**
     * Write [source] over the content at [target] in place: opened "rw",
     * which never truncates on open, and cut to [source]'s length only after
     * every byte is written. [beforeWrite] runs before the first byte changes.
     * Android 10's refusal of media another app owns, before the user allows
     * it, throws [UserActionRequiredException] with nothing written.
     */
    private fun overwrite(resolver: ContentResolver, target: Uri, source: File, beforeWrite: () -> Unit) {
        val descriptor = try {
            resolver.openFileDescriptor(target, "rw")
        } catch (e: SecurityException) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || e !is RecoverableSecurityException) throw e
            throw UserActionRequiredException(target, e.userAction.actionIntent.intentSender)
        } ?: throw IOException("cannot write $target")
        ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { output ->
            val channel = output.channel
            channel.position(0)
            source.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    beforeWrite()
                    output.write(buffer, 0, n)
                }
            }
            overwriteStep("truncate")
            channel.truncate(source.length())
            output.fd.sync()
        }
    }
}
