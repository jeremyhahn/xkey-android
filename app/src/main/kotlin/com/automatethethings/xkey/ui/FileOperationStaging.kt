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

/** Staging files for [FileOperationActivity]. Not yet implemented. */
class FileOperationStaging(cacheDir: File) {

    val directory: File = File(cacheDir, DIRECTORY_NAME)

    fun stage(displayName: String?, write: (File) -> Unit): File = TODO()

    fun deliver(file: File, copy: (File) -> Unit): Unit = TODO()

    fun release(file: File): Unit = TODO()

    fun releaseAll(): Unit = TODO()

    fun sweep(): Unit = TODO()

    companion object {
        const val DIRECTORY_NAME = "file-ops-staging"
    }
}
