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

/**
 * Staging files for [FileOperationActivity]'s sign, encrypt and decrypt.
 *
 * Every staged file lives in [directory] (`<cacheDir>/file-ops-staging/`)
 * under a generated name: the shared file's display name only lends its
 * extension, and only when it is short and alphanumeric, so a `../` in it
 * can never move the file and two operations never share a path. A staged
 * file goes when its write step throws, when it is delivered (copied to
 * the target, whether the copy succeeds or not), when the save is cancelled
 * ([release]), when the activity finishes ([releaseAll]), and at the next
 * start ([sweep]) if the process died first.
 *
 * Plain Kotlin over a [File] cache directory, so it runs in JVM tests.
 */
class FileOperationStaging(cacheDir: File) {

    val directory: File = File(cacheDir, DIRECTORY_NAME)

    private val owned = mutableSetOf<File>()

    /**
     * Create a staging file, run [write] on it and return it. The file is
     * deleted, and the exception rethrown, when [write] throws.
     */
    inline fun stage(displayName: String?, write: (File) -> Unit): File {
        val file = create(displayName)
        try {
            write(file)
        } catch (e: Throwable) {
            release(file)
            throw e
        }
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

    /** Create an empty staging file under a generated name and own it. */
    @PublishedApi
    internal fun create(displayName: String?): File {
        directory.mkdirs()
        val file = File.createTempFile(PREFIX, safeExtension(displayName), directory)
        synchronized(owned) { owned.add(file) }
        return file
    }

    /** Delete a staged file, e.g. when the user cancels the save. */
    fun release(file: File) {
        synchronized(owned) { owned.remove(file) }
        file.delete()
    }

    /** Delete every file this instance staged and has not released. */
    fun releaseAll() {
        val files = synchronized(owned) { owned.toList().also { owned.clear() } }
        files.forEach { it.delete() }
    }

    /** Stub: replaced by the writer fence. */
    fun shutdown() = releaseAll()

    /** Delete whatever an earlier run left in [directory], and nothing outside it. */
    fun sweep() {
        directory.listFiles()?.forEach { it.deleteRecursively() }
    }

    companion object {
        const val DIRECTORY_NAME = "file-ops-staging"
        private const val PREFIX = "stage-"
        private val EXTENSION = Regex("[A-Za-z0-9]{1,10}")

        /** `.ext` of [displayName] when it is short and alphanumeric, else null (`.tmp`). */
        internal fun safeExtension(displayName: String?): String? {
            val ext = displayName?.substringAfterLast('/')?.substringAfterLast('.', "") ?: return null
            return if (EXTENSION.matches(ext)) ".$ext" else null
        }
    }
}
