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
package com.automatethethings.xkey.storage

import com.automatethethings.xkey.crypto.KeyPresence
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.BasicFileAttributes

/**
 * Whether [file] is there, three-way (#255 review r8): the one presence probe
 * of the key stores' files. Not File.exists() or File.isFile(), which answer
 * false when the lookup fails as well as when the file is missing, so a
 * store directory that can be listed but not searched would report a stored
 * key as absent. Only a lookup that finds no such file
 * ([NoSuchFileException]) is [KeyPresence.ABSENT]; any other I/O or access
 * failure is [KeyPresence.UNREADABLE].
 */
fun filePresence(file: File): KeyPresence =
    try {
        Files.readAttributes(file.toPath(), BasicFileAttributes::class.java)
        KeyPresence.PRESENT
    } catch (e: NoSuchFileException) {
        KeyPresence.ABSENT
    } catch (e: IOException) {
        KeyPresence.UNREADABLE
    } catch (e: SecurityException) {
        KeyPresence.UNREADABLE
    } catch (e: java.nio.file.InvalidPathException) {
        KeyPresence.UNREADABLE
    }
