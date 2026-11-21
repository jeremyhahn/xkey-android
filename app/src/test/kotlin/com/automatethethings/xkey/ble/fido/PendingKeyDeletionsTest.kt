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

import com.automatethethings.xkey.crypto.UserKeyKind
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
        val keys = listOf(
            PendingKey("AQI", UserKeyKind.CREDENTIAL),
            PendingKey("padded==", UserKeyKind.GENERAL),
            PendingKey("not base64\nat all", UserKeyKind.CREDENTIAL),
            PendingKey("either", null)
        )
        FilePendingKeyDeletions(file()).add(keys)

        val reopened = FilePendingKeyDeletions(file())
        assertEquals(keys.toSet(), reopened.all())

        reopened.remove("padded==")
        assertEquals(setOf(keys[0], keys[2], keys[3]), FilePendingKeyDeletions(file()).all())
    }

    @Test
    fun `a deleted key is forgotten in its own namespace only`() {
        val credential = PendingKey("AQI", UserKeyKind.CREDENTIAL)
        val general = PendingKey("AQI", UserKeyKind.GENERAL)
        val pending = FilePendingKeyDeletions(file())
        pending.add(listOf(credential, general))
        pending.addRegistration("AQI")

        pending.remove(general)
        assertEquals(setOf(credential), FilePendingKeyDeletions(file()).all())
        assertEquals(setOf("AQI"), pending.registrations())

        pending.remove(credential)
        assertEquals(emptySet<PendingKey>(), pending.all())
        assertEquals("a registration's key is its credential key", emptySet<String>(), pending.registrations())
    }

    @Test
    fun `a record written before namespaces were recorded names either namespace`() {
        file().writeText("QVFJ\nr QlFJ\n", Charsets.US_ASCII)

        val pending = FilePendingKeyDeletions(file())
        assertEquals(setOf(PendingKey("AQI", null)), pending.all())
        assertEquals(UserKeyKind.entries, pending.all().single().candidates)
        assertEquals(setOf("BQI"), pending.registrations())
    }

    @Test
    fun `no record file is an empty record, and forgetting an unknown id writes nothing`() {
        val pending = FilePendingKeyDeletions(file())
        assertEquals(emptySet<PendingKey>(), pending.all())

        pending.remove("AQI")
        assertEquals(false, file().exists())
    }
}
