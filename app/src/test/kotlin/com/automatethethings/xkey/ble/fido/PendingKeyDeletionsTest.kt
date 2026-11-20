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

package com.automatethethings.xkey.ble.fido

import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** The record of Keystore deletions still to retry outlives the object that wrote it. */
class PendingKeyDeletionsTest {

    @get:Rule
    val folder = TemporaryFolder()

    private fun file() = File(folder.root, "pending")

    @Test
    fun `recorded deletions survive a new instance and go once forgotten`() {
        val ids = listOf("AQI", "padded==", "not base64\nat all")
        FilePendingKeyDeletions(file()).add(ids)

        val reopened = FilePendingKeyDeletions(file())
        assertEquals(ids.toSet(), reopened.all())

        reopened.remove("padded==")
        assertEquals(setOf("AQI", "not base64\nat all"), FilePendingKeyDeletions(file()).all())
    }

    @Test
    fun `no record file is an empty record, and forgetting an unknown id writes nothing`() {
        val pending = FilePendingKeyDeletions(file())
        assertEquals(emptySet<String>(), pending.all())

        pending.remove("AQI")
        assertEquals(false, file().exists())
    }
}
