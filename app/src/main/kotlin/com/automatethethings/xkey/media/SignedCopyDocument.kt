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
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.result.contract.ActivityResultContract
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.withResumed
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import java.util.concurrent.ConcurrentHashMap

/**
 * The document a signed or co-signed copy is created as: [name] keeps the
 * source's media suffix and [mimeType] is the source's own type, so the
 * picker offers a location for that type and the copy reads back as the
 * same container.
 */
data class SignedCopyDocument(val name: String, val mimeType: String) {

    companion object {
        private const val FALLBACK_MIME = "application/octet-stream"

        /**
         * The copy of [source] tagged [tag]: "clip.mp4" becomes
         * "clip-[tag].mp4". The name is the provider's display name
         * ([OpenableColumns.DISPLAY_NAME]), else the Uri's last segment, so
         * an opaque document id ("image:123") still names the copy; when the
         * name has no media suffix one is derived from the source's type.
         */
        fun of(resolver: ContentResolver, source: Uri, tag: String): SignedCopyDocument {
            val mimeType = resolver.getType(source)?.substringBefore(';')?.trim()?.ifBlank { null }
            return named(displayName(resolver, source), mimeType, tag)
        }

        /** [of] for a source already named [fileName] and typed [mimeType]. */
        fun named(fileName: String?, mimeType: String?, tag: String): SignedCopyDocument {
            val name = fileName?.substringAfterLast('/')?.substringAfterLast(':')?.trim()?.ifBlank { null } ?: "media"
            val dot = name.lastIndexOf('.')
            val (base, suffix) = if (dot > 0 && dot < name.length - 1) {
                name.substring(0, dot) to name.substring(dot)
            } else {
                name to mimeType?.let(XmpMetadataHelper::stagingSuffix)?.takeIf { it != ".bin" }.orEmpty()
            }
            return SignedCopyDocument("$base-$tag$suffix", mimeType ?: FALLBACK_MIME)
        }

        private fun displayName(resolver: ContentResolver, source: Uri): String? {
            val queried = try {
                resolver.query(source, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                    val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
                }
            } catch (_: Exception) {
                // A provider that refuses the query still names the copy by its Uri.
                null
            }
            return queried?.ifBlank { null } ?: source.lastPathSegment
        }
    }

    /**
     * Creates the [SignedCopyDocument] through the system's save picker
     * (ACTION_CREATE_DOCUMENT), typed per launch, unlike
     * [androidx.activity.result.contract.ActivityResultContracts.CreateDocument],
     * whose type is fixed when it is registered.
     */
    class Create : ActivityResultContract<SignedCopyDocument, Uri?>() {
        override fun createIntent(context: Context, input: SignedCopyDocument): Intent =
            Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType(input.mimeType)
                .putExtra(Intent.EXTRA_TITLE, input.name)

        override fun parseResult(resultCode: Int, intent: Intent?): Uri? =
            intent.takeIf { resultCode == android.app.Activity.RESULT_OK }?.data
    }
}

/**
 * The media saves running in this process, by id. A save's write runs here,
 * not in an activity's scope, so the instance after a recreation waits on
 * the same write and shows its end; the id is kept in the saved state.
 */
object MediaSaveRuns {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val runs = ConcurrentHashMap<String, Deferred<*>>()

    /** The run of [id], started with [write] unless it already runs; its result is [write]'s. */
    @Suppress("UNCHECKED_CAST")
    fun <T> attach(id: String, write: () -> T): Deferred<T> =
        runs.computeIfAbsent(id) { scope.async { write() } } as Deferred<T>

    /**
     * Hands what [run] ended with (its result, or the failure it ended with)
     * to [use], once [screen] is resumed, and returns what [use] returns. The
     * one way a screen reads a run:
     *
     * - A waiter that is itself cancelled (its screen went away) throws, even
     *   when [run] has already ended, so the run and its result stay here for
     *   the next instance; awaiting [run] directly would take that
     *   cancellation for the run's failure.
     * - [use] runs only while [screen] is resumed, so never after its state
     *   was saved: an outcome taken then would be missing from that state,
     *   and the instance restored from it would lose it. A screen that goes
     *   away first leaves the outcome to the next instance; one that comes
     *   back takes it then.
     *
     * A failure is always an [Exception]; an [Error] is thrown.
     */
    suspend fun <T, R> outcome(run: Deferred<T>, screen: Lifecycle, use: (Result<T>) -> R): R {
        // Throws only on the waiter's own cancellation, never on the run's failure.
        run.join()
        val result = try {
            Result.success(run.await())
        } catch (e: Exception) {
            Result.failure(e)
        }
        return screen.withResumed { use(result) }
    }

    /**
     * Forget [id] once the instance showing it has taken its outcome. A saved
     * state still naming [id] can only be older than a process death, which
     * took the run with it: such a state runs it again.
     */
    fun finished(id: String) {
        runs.remove(id)
    }
}
