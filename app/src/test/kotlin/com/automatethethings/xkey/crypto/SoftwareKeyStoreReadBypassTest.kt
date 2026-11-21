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
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * #255 verify r2z (ruling 554): every read of a software key record's file
 * goes through the store's one read, [SoftwareKeyStore]'s readRecordFile,
 * which turns a failed read into [KeyPresenceUnreadableException]. A direct
 * readText or readBytes elsewhere in the store is the bypass that read an
 * unreadable record as a present key and crashed a delete with an
 * IOException.
 */
class SoftwareKeyStoreReadBypassTest {

    private val source: String by lazy {
        val main = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        stripComments(File(main, "com/automatethethings/xkey/crypto/SoftwareKeyStore.kt").readText())
    }

    @Test
    fun noRecordFileIsReadOutsideTheStoresOneRead() {
        val helper = Regex("""private fun readRecordFile\(""").find(source)
        assertTrue("the store's one record read is gone", helper != null)
        val start = helper!!.range.first
        val end = source.indexOf("\n    }", start).let { if (it < 0) source.length else it }
        val reads = Regex("""\.(readText|readBytes|readLines|bufferedReader|reader|inputStream|forEachLine|useLines)\(""")
            .findAll(source).map { it.range.first }.toList()
        val outside = reads.filter { it !in start..end }
        assertEquals("record reads outside readRecordFile: ${outside.map { lineOf(it) }}", emptyList<Int>(), outside)
        assertEquals("readRecordFile reads the file once", 1, reads.size)
    }

    private fun lineOf(offset: Int): Int = source.substring(0, offset).count { it == '\n' } + 1

    private fun stripComments(text: String): String =
        text.replace(Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)) { m -> m.value.filter { it == '\n' } }
            .replace(Regex("""//[^\n]*"""), "")
}
