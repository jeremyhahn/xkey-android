/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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

import java.io.File
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException

/**
 * Staging files for [FileOperationActivity]'s sign, encrypt and decrypt.
 *
 * Every staged file lives in [directory] (`<cacheDir>/file-ops-staging/`)
 * under a generated name: the shared file's display name only lends its
 * extension, and only when it is short and alphanumeric, so a `../` in it
 * can never move the file and two operations never share a path. A staged
 * file goes when its write step throws, when it is delivered (copied to
 * the target, whether the copy succeeds or not), when the save is cancelled
 * ([release]), when the activity goes ([shutdown]), and at a later start
 * ([sweep]) if the process died first.
 *
 * Each instance is a session: its files are named `stage-<session>-*`, and
 * the session stays live from construction to [shutdown]. [sweep] removes
 * only what no live session owns, so one activity never deletes another's
 * output. After [shutdown] the instance stages nothing, and a write step
 * still running then (blocked in its input, say) deletes its file when it
 * returns, so a writer cannot leave plaintext behind its teardown.
 *
 * Plain Kotlin over a [File] cache directory, so it runs in JVM tests.
 */
class FileOperationStaging(cacheDir: File) {

    val directory: File = File(cacheDir, DIRECTORY_NAME)

    private val session: String = UUID.randomUUID().toString().replace("-", "").take(SESSION_LENGTH)

    private val lock = Any()
    private val owned = mutableSetOf<File>()
    private var closed = false

    init {
        synchronized(liveSessions) { liveSessions.add(session) }
    }

    /**
     * Create a staging file, run [write] on it and return it. The file is
     * deleted, and the exception rethrown, when [write] throws. When
     * [shutdown] ran while [write] did, the file is deleted and this throws
     * [CancellationException].
     */
    inline fun stage(displayName: String?, write: (File) -> Unit): File {
        val file = create(displayName)
        try {
            write(file)
        } catch (e: Throwable) {
            release(file)
            throw e
        }
        keepWritten(file)
        return file
    }

    /** Run [copy] on a staged file, then delete it whether [copy] throws or not. */
    inline fun deliver(file: File, copy: (File) -> Unit) {
        try {
            copy(file)
        } finally {
            release(file)
        }
    }

    /** Create an empty staging file under a generated name and own it; refused after [shutdown]. */
    @PublishedApi
    internal fun create(displayName: String?): File = synchronized(lock) {
        if (closed) throw CancellationException(CLOSED)
        directory.mkdirs()
        File.createTempFile("$PREFIX$session-", safeExtension(displayName), directory).also { owned.add(it) }
    }

    /** The write step returned: keep [file], unless [shutdown] ran meanwhile, then delete it and cancel. */
    @PublishedApi
    internal fun keepWritten(file: File) {
        if (synchronized(lock) { !closed }) return
        file.delete()
        throw CancellationException(CLOSED)
    }

    /** Delete a staged file, e.g. when the user cancels the save. */
    fun release(file: File) {
        synchronized(lock) { owned.remove(file) }
        file.delete()
    }

    /** Delete every file this instance staged and has not released. */
    fun releaseAll() {
        val files = synchronized(lock) { owned.toList().also { owned.clear() } }
        files.forEach { it.delete() }
    }

    /**
     * End this instance: refuse further staging, delete what it owns and
     * drop its session, so a later [sweep] may take any file a writer still
     * running recreates (the writer deletes it too, see [stage]).
     */
    fun shutdown() {
        synchronized(lock) { closed = true }
        releaseAll()
        synchronized(liveSessions) { liveSessions.remove(session) }
    }

    /** Delete whatever no live session owns in [directory], and nothing outside it. */
    fun sweep() {
        // List before reading the live sessions: a session registers before
        // it creates a file, so every listed file of a live one is seen live.
        val entries = directory.listFiles() ?: return
        val live = synchronized(liveSessions) { liveSessions.toSet() }
        entries.filterNot { it.isFile && sessionOf(it.name) in live }.forEach { it.deleteRecursively() }
    }

    companion object {
        const val DIRECTORY_NAME = "file-ops-staging"
        private const val PREFIX = "stage-"
        private const val SESSION_LENGTH = 16
        private const val CLOSED = "file operation staging is shut down"
        private val EXTENSION = Regex("[A-Za-z0-9]{1,10}")

        /** Sessions of the instances in this process not yet [shutdown]. */
        private val liveSessions = mutableSetOf<String>()

        /** The session tag of a staged file's name, or null when it has none. */
        private fun sessionOf(name: String): String? =
            if (name.startsWith(PREFIX)) name.removePrefix(PREFIX).substringBefore('-', "").ifEmpty { null } else null

        /** `.ext` of [displayName] when it is short and alphanumeric, else null (`.tmp`). */
        internal fun safeExtension(displayName: String?): String? {
            val ext = displayName?.substringAfterLast('/')?.substringAfterLast('.', "") ?: return null
            return if (EXTENSION.matches(ext)) ".$ext" else null
        }
    }
}
